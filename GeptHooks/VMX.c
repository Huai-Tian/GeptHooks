#include"VMX.h"
#include"CPU.h"
#include"reg.h"
#include"common.h"
#include"GeptMsr.h"
#include"GeptApi.h"
#include<intrin.h>

//运行模式开关GEPT_PROBE_EXIT/GEPT_LAUNCH_CPU_LIMIT/BASE在common.h,
//勿在此重复#define。
//
//关键设计:
//  - 中断直投: pin期望=0+无ack-on-exit——中断在non-root直接经guest
//    IDT交付, EOI直写真LAPIC, VMM零参与(开ack-on-exit+注入状态机
//    会导致EOI债/ISR位永不清→整机冻结)
//  - ctls2指令许可位(rdtscp/xsaves/invpcid): 未开许可位→non-root执行
//    即#UD蓝屏
//  - vmx_off回真机三件套: 恢复非易失GPR+还原GDTR/IDTR limit+写回
//    GUEST_CR3(HOST_CR3残留会传播错误页表)
//  - 逃生机制(VmxExitStormEscape): 不可解exit=vmx_off回真机重执行,
//    绝不停核(停核=IPI永不处理=全机冻结)

VCPU g_vcpu[128];

PVCPU VmxGetCurrentVcpu(ULONG cpuNumber)
{
	return &g_vcpu[cpuNumber];
}
//PASSIVE_LEVEL预分配(DriverEntry调用): 不能在DPC里做连续内存分配
//(IRQL限制+碎片化后全核DPC自旋=整机冻结)
int VMXInitCpuAlloc(ULONG cpuNumber)
{
	PHYSICAL_ADDRESS phys = { 0 };
	phys.QuadPart = MAXULONG64;
	PVMX_VMCS pvmxon = (PVMX_VMCS)MmAllocateContiguousMemory(sizeof(VMX_VMCS), phys);
	PVMX_VMCS pvmcs = (PVMX_VMCS)MmAllocateContiguousMemory(sizeof(VMX_VMCS), phys);
	PVOID MsrBitMap = MmAllocateContiguousMemory(PAGE_SIZE, phys);
	PVOID pvmmStack = MmAllocateContiguousMemory(PAGE_SIZE * 6, phys);
	//EPTP-list页(VMFUNC EPTP switching, 4KB对齐+物理连续)。
	//VmxSetupVmcs里填: list[0]=clean/list[1]=hooked
	PVOID pEptpList = MmAllocateContiguousMemory(PAGE_SIZE, phys);
	if (pvmmStack == NULL || MsrBitMap == NULL || pvmxon == NULL || pvmcs == NULL
		|| pEptpList == NULL)
	{
		//释放已成功的部分, 调用方负责清理
		if (pEptpList) MmFreeContiguousMemory(pEptpList);
		if (pvmmStack) MmFreeContiguousMemory(pvmmStack);
		if (MsrBitMap) MmFreeContiguousMemory(MsrBitMap);
		if (pvmxon) MmFreeContiguousMemory(pvmxon);
		if (pvmcs) MmFreeContiguousMemory(pvmcs);
		return 1;
	}
	RtlZeroMemory(pvmxon, sizeof(VMX_VMCS));
	RtlZeroMemory(pvmcs, sizeof(VMX_VMCS));
	RtlZeroMemory(pvmmStack, PAGE_SIZE * 6);
	//MSR位图必须清零: 全零=不拦截任何MSR直通(垃圾位=随机exit+
	//EOI被吞→APIC中断卡死)
	RtlZeroMemory(MsrBitMap, PAGE_SIZE);
	//EPTP-list清零: 未用项(2-511)全0, guest误切→VMFUNC失败exit(59)
	RtlZeroMemory(pEptpList, PAGE_SIZE);
	pvmxon->RevisionId = (ULONG)__readmsr(MSR_IA32_VMX_BASIC);
	pvmcs->RevisionId = (ULONG)__readmsr(MSR_IA32_VMX_BASIC);
	g_vcpu[cpuNumber].VMXON = pvmxon;
	g_vcpu[cpuNumber].VMMStack = pvmmStack;
	g_vcpu[cpuNumber].VMCS = pvmcs;
	g_vcpu[cpuNumber].MsrBitMap = MsrBitMap;
	g_vcpu[cpuNumber].VmfuncEptpList = pEptpList;
	g_vcpu[cpuNumber].bInGuest = 0;
	g_vcpu[cpuNumber].bLaunchFailed = 0;
	g_vcpu[cpuNumber].bVmfuncOn = 0;
	return 0;
}

//串行模式(亲和性已切换到目标核, PASSIVE_LEVEL):
//vmxon → vmclear/vmptrld → 填VMCS → vmlaunch, 每步落盘
int VMXInitCpuStart()
{
	ULONG cpuNumber = KeGetCurrentProcessorNumber();
	PHYSICAL_ADDRESS physvmon = { 0 };
	PHYSICAL_ADDRESS physvmcs = { 0 };
	if (g_vcpu[cpuNumber].VMXON == NULL || g_vcpu[cpuNumber].VMCS == NULL)
	{
		FlLog("cpu%u 无预分配资源, 跳过", cpuNumber);
		return 1;
	}
	FlLog("cpu%u: vmxon...", cpuNumber);
	ULONG64 mycr4 = __readcr4();
	mycr4 |= __readmsr(MSR_IA32_VMX_CR4_FIXED0);
	mycr4 &= __readmsr(MSR_IA32_VMX_CR4_FIXED1);
	ULONG64 mycr0 = __readcr0();
	mycr0 |= __readmsr(MSR_IA32_VMX_CR0_FIXED0);
	mycr0 &= __readmsr(MSR_IA32_VMX_CR0_FIXED1);
	__writecr0(mycr0);
	__writecr4(mycr4);
	physvmon = MmGetPhysicalAddress(g_vcpu[cpuNumber].VMXON);
	physvmcs = MmGetPhysicalAddress(g_vcpu[cpuNumber].VMCS);
	//__vmx_on加SEH: 覆盖宿主hypervisor在场注入#GP/裸机0x3A锁定#GP两种
	//失败, 异常不逃逸(内核态未处理异常=蓝屏)
	UCHAR vmonResult = 0;
	__try
	{
		vmonResult = __vmx_on(&physvmon);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		vmonResult = 2;    //与__vmx_on的VMfailInvalid返回值同语义
	}
	if (vmonResult)
	{
		FlLog("cpu%u vmxon失败=%d (Hyper-V/VBS占用? 或宿主hypervisor仲裁#GP/VMfail)",
			cpuNumber, vmonResult);
		g_vcpu[cpuNumber].bLaunchFailed = 1;
		return vmonResult;
	}
	g_vcpu[cpuNumber].bVmxOn = 1;
	FlLog("cpu%u: vmxon OK, 填充VMCS...", cpuNumber);

	FlLog("cpu%u: vmclear/vmptrld...", cpuNumber);
	__vmx_vmclear(&physvmcs);
	__vmx_vmptrld(&physvmcs);
	FlLog("cpu%u: 进CmGuestRsp填充VMCS...", cpuNumber);
	//填充VMCS区域(vmlaunch在其中)
	CmGuestRsp();
	//关写盘护卫(CmGuestRsp返回=所有路径汇合点), T1补写积压行
	g_flWriteGuard = 0;
	if (!g_vcpu[cpuNumber].bLaunchFailed)
	{
		g_vcpu[cpuNumber].bInGuest = 1;
		//'Q'环事件=guest回到VMXInitCpuStart续跑的标记(此刻IF=0)
		FlRingPush('Q', cpuNumber, 0, 0, 0, 0);
		//KEEP检查点(sti之前, IF=0自旋安全): 强制T1落盘探针事件。
		//cli窗内到达的中断留在LAPIC IRR, sti后硬件自行投递
		FlLogSpin("cpu%u KEEP检查点(中断直投): pin=0无队列无注入, 即将sti——IRR积压中断由硬件直投guest ISR",
			cpuNumber);
	}
	//恢复IF(必须在任何FlLog之前——IF=0下其等待会永久睡眠)
	_enable();
	if (!g_vcpu[cpuNumber].bLaunchFailed)
	{
		//此行在non-root下打印: 本行之后本核OS执行全部在EPT之下
		FlLog("cpu%u vmlaunch成功, 已进入guest(接管: 此后本核OS运行于EPT之下)", cpuNumber);
	}
	else
	{
		//bLaunchFailed来源: vmlaunch VMfail/EPT自检失败/probe-exit完成
		FlLog("cpu%u vmlaunch失败或probe-exit完成(判读: [W][K]标记=自测通过; 错误码行=VMfail), 本核已回真机", cpuNumber);
	}
	//'f'环事件=launch窗口完成标记(与'F'配对); 同时熄灭T1热轮询
	FlRingPush('f', cpuNumber, 0, 0, 0, 0);
	g_flLaunchHot = 0;
	return 0;
}

//串行逐核退出VT。主卸载路径=VmxStopAllIpi(IPI原子退出); 本函数仅供
//DriverEntry全败清理路径防御性使用
void VmxStopCpu()
{
	ULONG cpuNumber = KeGetCurrentProcessorNumber();
	if (g_vcpu[cpuNumber].bInGuest)
	{
		FlLogSpin("cpu%u: vmcall退出VT...", cpuNumber);
		//成功进入guest的核: vmcall退出(handler内vmx_off后跳回此处)
		CmVmCall(1, 0, 0, 0);
		FlLogSpin("cpu%u: 已退出guest", cpuNumber);
	}
	else if (g_vcpu[cpuNumber].bVmxOn)
	{
		//vmlaunch失败但vmxon成功的核: 仍在root, 直接off
		FlLogSpin("cpu%u: root模式直接vmx_off...", cpuNumber);
		__vmx_off();
	}
	if (g_vcpu[cpuNumber].bVmxOn)
	{
		//清CR4.VMXE, 恢复干净状态
		ULONG64 cr4 = __readcr4();
		cr4 &= ~0x2000;
		__writecr4(cr4);
		g_vcpu[cpuNumber].bVmxOn = 0;
		FlLogSpin("cpu%u: VMXE已清, VT完全停止", cpuNumber);
	}
	else
	{
		FlLogSpin("cpu%u: 未启用VT, 无需停止", cpuNumber);
	}
}

//全核IPI原子退出(KeIpiGenericCall广播, 每核执行一次; DriverUload调用)。
//IPI_LEVEL高于DISPATCH, 处理程序内零调度: 每核原子完成vmcall(1)退出
//+清VMXE+PGE冲刷, IPI返回后各核TLB从零重建。IPI上下文内绝不
//FlLog/睡眠, 只FlRingPush(无锁环)
ULONG64 VmxStopAllIpi(ULONG_PTR Argument)
{
	UNREFERENCED_PARAMETER(Argument);
	ULONG cpu = KeGetCurrentProcessorNumber();
	ULONG64 wasInGuest = g_vcpu[cpu].bInGuest ? 1 : 0;
	if (g_vcpu[cpu].bInGuest)
	{
		//本核退出: vmcall(1)→exit handler(vmx_off+CR3写回+'r'取证环
		//+冲刷A)→VmxJumGuestRegs跳回此处(IPI上下文原样继续)
		CmVmCall(1, 0, 0, 0);
	}
	else if (g_vcpu[cpu].bVmxOn)
	{
		//vmlaunch失败但vmxon成功的核: root直接off(从未激活EPT翻译)
		__vmx_off();
	}
	if (g_vcpu[cpu].bVmxOn)
	{
		//清CR4.VMXE
		ULONG64 cr4 = __readcr4();
		cr4 &= ~0x2000;
		__writecr4(cr4);
		g_vcpu[cpu].bVmxOn = 0;
	}
	//PGE翻转冲空本核全部翻译(含EPT派生条目), 与exit handler内的
	//冲刷双保险
	{
		ULONG64 cr4Full = __readcr4();
		__writecr4(cr4Full & ~0x80ULL);   //PGE=0(冲含全局页)
		__writecr4(cr4Full);              //PGE=1(恢复, 再冲)
	}
	//环'v'留痕: a=本核是否曾in-guest, b=bVmxOn终值(应0)
	FlRingPush('v', cpu, 0, wasInGuest, g_vcpu[cpu].bVmxOn, 0);
	return 0;
}

//控制字段计算: (MSR低32|期望)&高32。
//低32=必须为1的位, 高32=允许为1的位(SDM Appendix A.3); 对新旧MSR
//均正确。勿用补码公式(会把不允许的位全开→VM-entry一致性检查失败)
ULONG VmxMsrAdjuest(ULONG64 msrNum, ULONG controlValue)
{
	LARGE_INTEGER msrValue;
	msrValue.QuadPart = __readmsr(msrNum);
	return (msrValue.LowPart | controlValue) & msrValue.HighPart;
}

//PASSIVE_LEVEL释放指定CPU的全部VT资源(DriverUload调用)
void VmxFreeCpuResources(ULONG cpuNumber)
{
	if (g_vcpu[cpuNumber].VMCS)
	{
		MmFreeContiguousMemory(g_vcpu[cpuNumber].VMCS);
		g_vcpu[cpuNumber].VMCS = NULL;
	}
	if (g_vcpu[cpuNumber].VMXON)
	{
		MmFreeContiguousMemory(g_vcpu[cpuNumber].VMXON);
		g_vcpu[cpuNumber].VMXON = NULL;
	}
	if (g_vcpu[cpuNumber].VMMStack)
	{
		MmFreeContiguousMemory(g_vcpu[cpuNumber].VMMStack);
		g_vcpu[cpuNumber].VMMStack = NULL;
	}
	if (g_vcpu[cpuNumber].MsrBitMap)
	{
		MmFreeContiguousMemory(g_vcpu[cpuNumber].MsrBitMap);
		g_vcpu[cpuNumber].MsrBitMap = NULL;
	}
	if (g_vcpu[cpuNumber].PeptData)
	{
		MmFreeContiguousMemory(g_vcpu[cpuNumber].PeptData);
		g_vcpu[cpuNumber].PeptData = NULL;
	}
	//hooked视图EPT(内含的拆分pte页不单独跟踪, 随整机生命周期释放)
	if (g_vcpu[cpuNumber].PeptDataHooked)
	{
		MmFreeContiguousMemory(g_vcpu[cpuNumber].PeptDataHooked);
		g_vcpu[cpuNumber].PeptDataHooked = NULL;
	}
	//EPTP-list页(VMFUNC)
	if (g_vcpu[cpuNumber].VmfuncEptpList)
	{
		MmFreeContiguousMemory(g_vcpu[cpuNumber].VmfuncEptpList);
		g_vcpu[cpuNumber].VmfuncEptpList = NULL;
	}
	//释放>512GB动态建立的pdpt页(必须用raw指针: HighPdptVa是4KB对齐后的
	//地址, 不在pool块起始处, 直接ExFreePool会池损坏)
	for (ULONG i = 0; i < 512; i++)
	{
		if (g_vcpu[cpuNumber].HighPdptRawVa[i])
		{
			ExFreePool(g_vcpu[cpuNumber].HighPdptRawVa[i]);
			g_vcpu[cpuNumber].HighPdptRawVa[i] = NULL;
			g_vcpu[cpuNumber].HighPdptVa[i] = NULL;
		}
	}
	g_vcpu[cpuNumber].bInGuest = 0;
	g_vcpu[cpuNumber].bLaunchFailed = 0;
	g_vcpu[cpuNumber].bVmxOn = 0;
}

//==================== 框架生命周期(使用者只经VMX.h调这两个) ====================

//0x3A(IA32_FEATURE_CONTROL)读伪造: 恒返1(锁定+VMX禁用形态)——与
//vmxon注入#GP(0)构成一致的"BIOS锁VT"读/行为互证, 并让后到实例的
//CommCheckBios第一层即退出。exit上下文回调: 只返回值零副作用
static ULONG64 VmxFeatCtlOnRead(PVOID Context, ULONG32 Msr)
{
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(Msr);
	return 1;
}

//全核接管入口(PASSIVE_LEVEL): 资源分配→串行逐核启动VT→互斥仲裁→常驻。
//失败路径已自清理资源, 调用方直接返回即可
NTSTATUS VmxStartAllCpus(PDRIVER_OBJECT DriverObject)
{
	//文件日志最先初始化(此后任何一步卡死都有现场); Release构建为空操作
	FlInit();

	//预分配必须在PASSIVE_LEVEL: 每核VMXON/VMCS/VMM栈/MSR位图/EPT_DATA
	//绝不能推迟到DPC(DISPATCH_LEVEL)里分配
	ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
	FlLog("==== GeptHooks build %s | cpu数=%d ====",
		GEPT_BUILD_TAG, cpuCount);
	FlLog("黑匣子: BB=%p 魔数=GEPTBB01 看门狗v2(自旋+rdtsc, 30s不动)→蓝屏0xDEADC0DE→DMP",
		(PVOID)&g_flBlackBox);
	//蓝屏判读锚点: bugcheck参数2落在[base,base+size)内=驱动内代码
	FlLog("驱动映像: base=%p size=0x%X", DriverObject->DriverStart, DriverObject->DriverSize);
	//模块清单: 遍历InLoadOrderLinks, 蓝屏时对照bugcheck参数2定位崩溃模块
	{
		typedef struct _GEPT_KLDR_ENTRY {
			LIST_ENTRY InLoadOrderLinks;          //+0x00
			LIST_ENTRY InMemoryOrderLinks;        //+0x10
			LIST_ENTRY InInitializationOrderLinks;//+0x20
			PVOID DllBase;                        //+0x30
			PVOID EntryPoint;                     //+0x38
			ULONG SizeOfImage;                    //+0x40
			UNICODE_STRING FullDllName;           //+0x48
			UNICODE_STRING BaseDllName;           //+0x58
		} GEPT_KLDR_ENTRY;
		GEPT_KLDR_ENTRY* start = (GEPT_KLDR_ENTRY*)DriverObject->DriverSection;
		if (start != NULL)
		{
			FlLog("=== 模块清单(蓝屏参数2判读: 看落在哪个模块的[base,base+size)内) ===");
			GEPT_KLDR_ENTRY* mod = start;
			ULONG cnt = 0;
			do
			{
				char name[24];
				ULONG n = mod->BaseDllName.Length / sizeof(WCHAR);
				if (n > 23)
				{
					n = 23;
				}
				for (ULONG c = 0; c < n; c++)
				{
					WCHAR wch = mod->BaseDllName.Buffer
						? mod->BaseDllName.Buffer[c] : L'?';
					name[c] = (wch < 128) ? (char)wch : '?';
				}
				name[n] = 0;
				FlLog("MOD %p +%06X %s", mod->DllBase, mod->SizeOfImage, name);
				mod = (GEPT_KLDR_ENTRY*)mod->InLoadOrderLinks.Flink;
				cnt++;
			} while (mod != start && cnt < 400);
		}
	}
	for (ULONG i = 0; i < cpuCount; i++)
	{
		//面包屑: 每步都落盘, 卡死时最后一行即精确卡点
		FlLog("cpu%u/%u: VMX资源分配(4块连续内存)...", i, cpuCount);
		if (VMXInitCpuAlloc(i) != 0)
		{
			FlLog("cpu%u VMX资源分配失败! 回滚返回(此时sc start应报错而非挂起)", i);
			for (ULONG j = 0; j <= i; j++)
			{
				VmxFreeCpuResources(j);
			}
			EptShutdownHighMappings();   //共享高区页(幂等)
			FlShutdown();
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		FlLog("cpu%u: EPT_DATA分配(2MB连续)+建表...", i);
		if (!NT_SUCCESS(EptInitEptData(i)))
		{
			FlLog("cpu%u EPT初始化失败! 回滚返回(此时sc start应报错而非挂起)", i);
			for (ULONG j = 0; j <= i; j++)
			{
				VmxFreeCpuResources(j);
			}
			EptShutdownHighMappings();   //共享高区页(幂等)
			FlShutdown();
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		FlLog("cpu%u: 预分配OK", i);
	}
	FlLog("预分配完成, 串行逐核启动VT(每步落盘, 冻结时最后一行=精确卡点)");

	//串行逐核启动(PASSIVE级+亲和性切换), 不用KeGenericCallDpc
	//(DPC全核进DISPATCH级, 线程不可调度)
#if GEPT_LAUNCH_CPU_BASE >= 0
	ULONG launchBase = GEPT_LAUNCH_CPU_BASE;
#else
	ULONG launchBase = cpuCount - 1;    //-1=最后一核(安静核)
#endif
	FlLog("启动模式: launchBase=cpu%u LIMIT=%d(0=不限制), 目标=全部%u核接管",
		launchBase, GEPT_LAUNCH_CPU_LIMIT, cpuCount);
	KAFFINITY allCpus = KeQueryActiveProcessors();
	for (ULONG i = 0; i < cpuCount; i++)
	{
		//只虚拟化[launchBase, launchBase+LIMIT)区间的核, 其余真机
		if (GEPT_LAUNCH_CPU_LIMIT != 0 &&
			(i < launchBase || i >= launchBase + GEPT_LAUNCH_CPU_LIMIT))
		{
			FlLog("cpu%u 跳过启动(目标区间外的核保持真机)", i);
			continue;
		}
		if (g_vcpu[i].VMXON == NULL || g_vcpu[i].VMCS == NULL)
		{
			FlLog("cpu%u 无资源, 跳过", i);
			continue;
		}
		FlLog("cpu%u: 切换亲和性, VT环境检查+启动...", i);
		KeSetSystemAffinityThread((KAFFINITY)1 << i);
		//记录虚拟化目标核(日志心跳读它)
		g_geptVcpuCpu = (LONG)i;
		if (CommCheckBios() && CommCheckCpuid() && CommCheckCr4())
		{
			VMXInitCpuStart();
		}
		else
		{
			FlLog("cpu%u VT环境检查未通过, 跳过", i);
		}
		KeSetSystemAffinityThread(allCpus);
	}

	//各核启动结果落盘
	FlLog("全部核心启动流程完成, 各核状态:");
	{
		ULONG inGuestTotal = 0;
		for (ULONG i = 0; i < cpuCount; i++)
		{
			FlLog("cpu%d inGuest=%d launchFailed=%d vmxon=%d",
				i, g_vcpu[i].bInGuest, g_vcpu[i].bLaunchFailed, g_vcpu[i].bVmxOn);
			if (g_vcpu[i].bInGuest)
			{
				inGuestTotal++;
			}
		}
		//零核in-guest=VT启动全败(Hyper-V/VBS占用 或 同框架宿主已在场,
		//VT-x原生互斥仲裁生效)。调用方失败返回不会触发DriverUnload,
		//必须在此自清资源+返回失败干净退出
		if (inGuestTotal == 0)
		{
			FlLog("VmxStartAllCpus: **零核in-guest——VT启动全败**。成因: "
				"Hyper-V/VBS占用 或 同框架宿主hypervisor已在场。"
				"释放全部资源后干净退出, 系统不受影响");
			for (ULONG i = 0; i < cpuCount; i++)
			{
				if (g_vcpu[i].bVmxOn)
				{
					//防御性: vmxon成功但未进guest的核做标准停核
					KeSetSystemAffinityThread((KAFFINITY)1 << i);
					VmxStopCpu();
					KeSetSystemAffinityThread(allCpus);
				}
			}
			for (ULONG i = 0; i < cpuCount; i++)
			{
				VmxFreeCpuResources(i);
			}
			EptShutdownHighMappings();
			FlShutdown();
			return STATUS_UNSUCCESSFUL;
		}
	}
	//框架内置MSR hook: 0x3A读伪造恒返1——框架语义非demo, 勿剥离。
	//双重作用: ①互斥第一层(后到实例CommCheckBios读1→干净退出)
	//②隐藏层(0x3A=1+CR4.VMXE影子0+vmxon #GP(0)三层自洽)
	{
		GEPT_MSR_HOOK featCtlHook = { 0 };
		featCtlHook.Msr = MSR_IA32_FEATURE_CONTROL;   //0x3A
		featCtlHook.OnRead = VmxFeatCtlOnRead;
		NTSTATUS msrSt = GeptMsrHookInstall(&featCtlHook);
		FlLog("框架内置0x3A读伪造(恒返1): %s——互斥第一层+vmxon #GP(0)读/行为互证",
			NT_SUCCESS(msrSt) ? "安装OK" : "安装失败(不影响VT运行, 详见[MSR]行)");
	}
	//放行Desktop镜像(加载窗口期结束)
	FlMarkEntryDone();
	return STATUS_SUCCESS;
}

//全核关停(PASSIVE_LEVEL): 移除全部hook→全核IPI原子退出VT→释放全部资源
VOID VmxShutdownAllCpus(VOID)
{
	//park守卫: park核的VMM栈/代码页仍被占用, 卸载=延迟崩溃。
	//拒绝卸载, 收集日志后重启清理
	if (g_geptParkedMask != 0)
	{
		FlLog("Unload: 拒绝卸载! cpu掩码%X在三重故障park中(代码页/VMM栈被park核占用, 机器应存活)——请收集日志后重启系统", g_geptParkedMask);
		return;
	}
	FlLog("Unload: 开始关闭VT(全核IPI原子退出)");
	//先移除全部hook再关VT: 在途回调此刻VT仍开=安全执行完毕;
	//2s宽限让被抢占的回调跑完(GeptViewSwitch的bInGuest检查兜底)
	GeptApiRemoveAll();
	{
		LARGE_INTEGER tick;
		tick.QuadPart = -2000000LL;    //2秒宽限
		KeDelayExecutionThread(KernelMode, FALSE, &tick);
	}
	ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
	//全核IPI原子退出(实现: VmxStopAllIpi): IPI_LEVEL高于DISPATCH,
	//处理程序内零调度——每核原子完成vmcall(1)+清VMXE+PGE冲刷, 各核
	//退出间无线程切换窗口。不能用逐核亲和性退出(DISPATCH级线程不
	//迁移, 只会退1核)
	KeIpiGenericCall(VmxStopAllIpi, 0);
	FlLog("Unload: 全核IPI退出完成(每核原子vmcall(1)+清VMXE+双PGE冲刷, 环'v'×%u核留痕, 零调度零窗口)", cpuCount);
	//CPUID exit计数终值: >0=透传修改路径在跑; =0=native直通
	FlLog("Unload: CPUID exit计数终值=%lld (r10; >0=handler活跃 /=0=直通, 均裸机一致)",
		(LONGLONG)g_flExitCounts[EXIT_REASON_CPUID]);
	FlLog("Unload: VT已关闭, 释放资源");
	//PASSIVE_LEVEL释放全部资源(含EPT_DATA与动态页表)
	for (ULONG i = 0; i < cpuCount; i++)
	{
		VmxFreeCpuResources(i);
	}
	//释放共享高区页表(全部核EPT共用的pdpt, 幂等)
	EptShutdownHighMappings();
	//API内存(纯pool释放; 此刻hook已移除+VT已关, 无在途引用)
	GeptApiFreeMemory();
	FlLog("Unload: 完成, 关闭文件日志");
	FlShutdown();
}

//vmx_off回真机前还原GDTR/IDTR limit: VM-exit无条件把两limit压成
//0xFFFF(host-state区只有base无limit), 残留=真机sgdt/sidt读到异常值。
//必须在vmx_off之前调用(此后vmread非法)。描述符: WORD limit@+0,
//QWORD base@+2(10字节)
static void VmxRestoreDtrLimits(void)
{
	UCHAR dtr[10];
	ULONG64 lim = 0;
	//GDTR
	__vmx_vmread(GUEST_GDTR_LIMIT, &lim);
	*(USHORT*)dtr = (USHORT)lim;
	*(ULONG64*)(dtr + 2) = GetGdtBase();
	VmxLoadGdtr(dtr);
	//IDTR
	__vmx_vmread(GUEST_IDTR_LIMIT, &lim);
	*(USHORT*)dtr = (USHORT)lim;
	*(ULONG64*)(dtr + 2) = GetIdtBase();
	VmxLoadIdtr(dtr);
}

void VmxCpuidHandler(PGUEST_REGS GuestRegs)
{
	//所有leaf先透传真实硬件结果
	int cpuinfo[4] = {0};
	__cpuidex(cpuinfo, (int)GuestRegs->rax, (int)GuestRegs->rcx);
	//CPUID输入leaf取低32位(EAX语义; 高位垃圾不参与匹配)
	ULONG leaf = (ULONG)GuestRegs->rax;
	if (leaf == 1)
	{
		//只清ECX bit31(hypervisor present)。绝不能全零返回CPUID.1
		//(特性位全丢=系统行为未定义)
		cpuinfo[2] &= ~(1 << 31);
	}
	//hypervisor专用leaf(0x40000000-0x4000000F)归零(无签名泄漏;
	//嵌套场景下层签名不穿透)
	else if (leaf >= 0x40000000 && leaf <= 0x4000000F)
	{
		cpuinfo[0] = 0;
		cpuinfo[1] = 0;
		cpuinfo[2] = 0;
		cpuinfo[3] = 0;
	}
	//leaf0 maxleaf收敛到0x1F(嵌套场景下层可能抬高maxleaf; 不做更低
	//收敛——比裸机真实值小=检测特征)
	else if (leaf == 0 && (ULONG)cpuinfo[0] > 0x1F)
	{
		cpuinfo[0] = 0x1F;
	}
	GuestRegs->rax = cpuinfo[0];
	GuestRegs->rbx = cpuinfo[1];
	GuestRegs->rcx = cpuinfo[2];
	GuestRegs->rdx = cpuinfo[3];
}

//TSC补偿: 每次exit的root驻留时间经TSC_OFFSET从guest可读TSC中扣除
//(procCtl bit3开启后RDTSC/RDTSCP/RDMSR(0x10)硬件自动加offset;
//IA32_TSC_DEADLINE不受影响)。测算两端各欠~百cycle=安全方向(TSC
//绝不倒退)。仅VMX root上下文可调
void VmxTscCompensate(ULONG64 entryTsc, ULONG64 exitTsc)
{
	if (exitTsc <= entryTsc)
	{
		return;    //rdtsc同值/乱序(理论不可能, 防御)
	}
	ULONG64 offset = 0;
	__vmx_vmread(TSC_OFFSET, &offset);
	offset -= (exitTsc - entryTsc);
	__vmx_vmwrite(TSC_OFFSET, offset);
}

void VmxMsrReadHandler(PGUEST_REGS GuestRegs)
{
	//MSR hook分发: 命中回调返回伪造值, 未hook=直通。exit上下文绝不DbgPrint
	ULONG64 forged = 0;
	if (GeptMsrDispatchRead((ULONG32)GuestRegs->rcx, &forged))
	{
		GuestRegs->rax = forged & 0xFFFFFFFF;
		GuestRegs->rdx = (forged >> 32) & 0xFFFFFFFF;
		return;
	}
	ULONG64 msrValue = __readmsr(GuestRegs->rcx);
	GuestRegs->rax = msrValue&0xFFFFFFFF;
	GuestRegs->rdx= (msrValue>>32) & 0xFFFFFFFF;
}

//向guest注入#UD——VMX指令族exit的裸机语义("not in VMX operation→#UD")。
//编码(SDM Table 24-13): bit31=valid|bits10:8=3(硬件异常)|bit11=0
//(无错误码)|vector 6 → 0x80000306。
//调用方: 绝不推进RIP(异常在本指令派发), return早退绕过尾部RIP推进
static VOID VmxInjectUd(ULONG cpu, ULONG reason, ULONG64 rip)
{
	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0x80000306);
	//采样环事件(首次+每4096次, 防狂喷刷爆环)
	static volatile LONG s_udCnt[64] = { 0 };
	LONG n = InterlockedIncrement(&s_udCnt[cpu & 63]);
	if (n == 1 || (n & 0xFFF) == 0)
	{
		FlRingPush('B', cpu, reason, rip, (ULONG64)(ULONG)n, 0);
	}
}

//向guest注入#GP(0)——VMXON exit用(见case EXIT_REASON_VMXON)。
//编码: bit31=valid|bit11=1(带错误码)|bits10:8=3|vector 13 → 0x80000B0D,
//错误码0写VM_ENTRY_EXCEPTION_ERROR_CODE。调用方纪律同VmxInjectUd
static VOID VmxInjectGp(ULONG cpu, ULONG reason, ULONG64 rip)
{
	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0x80000B0D);
	__vmx_vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, 0);
	static volatile LONG s_gpCnt[64] = { 0 };
	LONG n = InterlockedIncrement(&s_gpCnt[cpu & 63]);
	if (n == 1 || (n & 0xFFF) == 0)
	{
		FlRingPush('B', cpu, reason, rip, (ULONG64)(ULONG)n, 0);
	}
}

void VmxExitHandler(PGUEST_REGS GuestRegs)
{
	
	ULONG vmexitReason = 0;
	ULONG64 exitCodeLen = 0;
	ULONG64 guestRip = 0;
	ULONG64 guestRsp = 0;
	ULONG64 exitQual = 0;
	__vmx_vmread(VM_EXIT_REASON,&vmexitReason);
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN,&exitCodeLen);
	__vmx_vmread(GUEST_RIP, &guestRip);
	__vmx_vmread(GUEST_RSP, &guestRsp);
	__vmx_vmread(EXIT_QUALIFICATION, &exitQual);
	vmexitReason = vmexitReason & 0xFFFF;
	//清残留注入事件(SDM §24.8.3: VM-exit自清valid位, 此为运行时保险)
	{
		ULONG64 staleIntr = 0;
		__vmx_vmread(VM_ENTRY_INTR_INFO_FIELD, &staleIntr);
		if (staleIntr & 0x80000000ULL)
		{
			__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);
		}
	}
	//环路检测: 同一(reason,rip)连续>500次=不可解exit循环→逃生。
	//豁免(合法高频同RIP形态): 48(violation, ept.c有专属检测)
	//10/1/7(CPUID自旋/中断风暴/开窗排空) 16/14/12/36(已模拟指令exit)
	//18-27+INVEPT/INVVPID(VMX指令族, 每次exit都有guest可见进展)
	//28(CR访问, 写落地+RIP推进)
	{
		static volatile LONG s_sameCnt[64] = { 0 };
		static volatile ULONG s_lastReason[64] = { 0 };
		static volatile ULONG64 s_lastRip[64] = { 0 };
		ULONG cpuD = KeGetCurrentProcessorNumber();
		if (cpuD < 64)
		{
			if (vmexitReason == s_lastReason[cpuD] && guestRip == s_lastRip[cpuD])
			{
				if (vmexitReason != EXIT_REASON_EPT_VIOLATION &&
					vmexitReason != EXIT_REASON_CPUID &&
					vmexitReason != EXIT_REASON_EXTERNAL_INTERRUPT &&
					vmexitReason != EXIT_REASON_PENDING_INTERRUPT &&
					//已模拟指令exit豁免(计时自旋/同调用点INVLPG/HLT空闲)
				vmexitReason != EXIT_REASON_RDTSC &&
				vmexitReason != EXIT_REASON_RDTSCP &&
				vmexitReason != EXIT_REASON_INVLPG &&
				vmexitReason != EXIT_REASON_HLT &&
				vmexitReason != EXIT_REASON_MWAIT_INSTRUCTION &&
				//VMX指令族(18-27+INVEPT/INVVPID)整体豁免(确定性处置, 见上)
				!(vmexitReason >= EXIT_REASON_VMCALL &&
					vmexitReason <= EXIT_REASON_VMXON) &&
				vmexitReason != EXIT_REASON_INVEPT &&
				vmexitReason != EXIT_REASON_INVVPID &&
				//CR访问(28)豁免: 写落地+RIP推进=有guest可见进展
				vmexitReason != EXIT_REASON_CR_ACCESS &&
				InterlockedIncrement(&s_sameCnt[cpuD]) > 500)
				{
					VmxExitStormEscape('D', vmexitReason, guestRip, exitQual,
						GuestRegs);
				}
			}
			else
			{
				s_lastReason[cpuD] = vmexitReason;
				s_lastRip[cpuD] = guestRip;
				s_sameCnt[cpuD] = 1;
			}
		}
	}
	//exit计数+采样(EPT violation在EptExitHandler单独入环)
	if (vmexitReason == EXIT_REASON_EPT_VIOLATION)
	{
		InterlockedIncrement64(&g_flExitCounts[EXIT_REASON_EPT_VIOLATION]);
	}
	else
	{
		FlRingExit(KeGetCurrentProcessorNumber(), vmexitReason, guestRip, exitQual);
	}
	switch (vmexitReason)
	{
		case EXIT_REASON_CPUID:
		{
			VmxCpuidHandler(GuestRegs);
		}
		break;
		case EXIT_REASON_VMCALL:
	{
		//VMCALL签名门: 内部vmcall在r10/r11携带128位签名(common.h),
		//进case先校验(防外来vmcall穷举功能码: 退VT/可控拆页/任意写)。
		//不符→'u'环留痕(采样)+#UD注入(裸机语义)。
		//CPL检查: x64内核CS恒RPL0; 用户态vmcall裸机=#UD
		{
			ULONG64 vmcallCsSel = 0;
			__vmx_vmread(GUEST_CS_SELECTOR, &vmcallCsSel);
			if ((vmcallCsSel & 3) != 0 ||
				GuestRegs->r10 != GEPT_VMCALL_SIG0 ||
				GuestRegs->r11 != GEPT_VMCALL_SIG1)
			{
				static volatile LONG s_sigCnt[64] = { 0 };
				ULONG sigCpu = KeGetCurrentProcessorNumber();
				LONG sn = InterlockedIncrement(&s_sigCnt[sigCpu & 63]);
				if (sn == 1 || (sn & 0xFFF) == 0)
				{
					FlRingPush('u', sigCpu, 18, guestRip,
						GuestRegs->rcx, vmcallCsSel);
				}
				VmxInjectUd(sigCpu, 18, guestRip);
				//异常在本指令派发: RIP原样写回+早退(绝不推进)
				__vmx_vmwrite(GUEST_RIP, guestRip);
				return;
			}
		}
		if (GuestRegs->rcx==1)//表示要退出vt
			{
				//exit上下文禁止DbgPrint(同核重入死锁)——日志只FlRingPush
			FlRingPush('V', KeGetCurrentProcessorNumber(), 18,
				guestRip, exitCodeLen, 0);
			//vmx_off后按guest原RFLAGS恢复IF(不恢复=睡眠永不唤醒)
			ULONG64 vmcallFlags = 0;
			__vmx_vmread(GUEST_RFLAGS, &vmcallFlags);
			//vmx_off前invept全上下文(EPT派生TLB零残留)
			EptInveptBothViews();
			//记录最终TSC_OFFSET('t'环事件); vmread须在vmx_off前
			{
				ULONG64 tscOffFinal = 0;
				__vmx_vmread(TSC_OFFSET, &tscOffFinal);
				FlRingPush('t', KeGetCurrentProcessorNumber(), 0,
					tscOffFinal, 0, 0);
			}
			//状态一致性——bInGuest清零
			g_vcpu[KeGetCurrentProcessorNumber()].bInGuest = 0;
			//vmx_off前还原GDTR/IDTR limit(见VmxRestoreDtrLimits注释;
			//vmread必须在vmx_off之前)
			VmxRestoreDtrLimits();
			//CR3恢复: VM-exit加载的HOST_CR3(System进程DTB)在vmx_off
			//后残留, 会经同进程线程切换传播错误页表→用户VA访问蓝屏。
			//vmx_off后立即写回GUEST_CR3(vmread须在vmx_off前)
			ULONG64 unloadCr3 = 0;
			ULONG64 hostCr3Snap = 0;
			__vmx_vmread(GUEST_CR3, &unloadCr3);
			//'r'环事件: a=GUEST_CR3 b=回读 c=HOST_CR3快照
			__vmx_vmread(HOST_CR3, &hostCr3Snap);
			__vmx_off();
			__writecr3(unloadCr3);
			//CR3回读校验+取证环事件
			FlRingPush('r', KeGetCurrentProcessorNumber(), 0,
				unloadCr3, __readcr3(), hostCr3Snap);
			//PGE翻转全量TLB冲刷(与invept+CR3重载构成三重防线)
			{
				ULONG64 cr4Full = __readcr4();
				__writecr4(cr4Full & ~0x80ULL);   //PGE=0(冲全局页)
				__writecr4(cr4Full);              //PGE=1(恢复, 再冲)
			}
			if (vmcallFlags & 0x200)
			{
				_enable();
			}
				//VmxJumGuestRegs恢复非易失GPR后切栈跳回(易失寄存器
				//不恢复——vmcall=调用边界)
				VmxJumGuestRegs(GuestRegs, guestRsp, guestRip+ exitCodeLen);
			}
			//EPT hook
		else if (GuestRegs->rcx == 2)
		{
			EptSetHook(GuestRegs->rdx, GuestRegs->r8);
		}
		//还原字节原语(GeptApi.c的DPC广播): rdx=还原目标, r8=源(原页),
		//r9=长度。每核执行(memcpy幂等, invept按核生效)
		else if (GuestRegs->rcx == 7)
		{
			if (GuestRegs->r9 > 0 && GuestRegs->r9 <= 128)
			{
				RtlCopyMemory((PVOID)GuestRegs->rdx, (PVOID)GuestRegs->r8,
					(SIZE_T)GuestRegs->r9);
			}
			//双视图invept(旧翻译残留=Remove延迟生效)
			EptInveptBothViews();
			FlRingPush('m', KeGetCurrentProcessorNumber(), 7,
				GuestRegs->rdx, GuestRegs->r8, GuestRegs->r9);
		}
			//落地探针首段: 'W'环留痕(VM-entry+EPT取指+exit+RIP推进+
			//vmresume全链路自证), 走通用RIP推进
			else if (GuestRegs->rcx == GEPT_PROBE_MAGIC)
			{
				FlRingPush('W', KeGetCurrentProcessorNumber(), 18,
					guestRip, exitQual, exitCodeLen);
			}
			//探针第二段: GEPT_PROBE_EXIT=1时vmx_off回真机(自测模式);
			//=0(接管)时为空, 落到通用RIP推进, 探针恢复栈回non-root继续
			else if (GuestRegs->rcx == 3)
			{
#if GEPT_PROBE_EXIT
				FlRingPush('K', KeGetCurrentProcessorNumber(), 18,
					guestRip, exitQual, exitCodeLen);
				ULONG64 probeFlags = 0;
				__vmx_vmread(GUEST_RFLAGS, &probeFlags);
				//vmx_off前invept全上下文
				EptInveptBothViews();
				//清in-service中断债(x2APIC用WRMSR 0x80B), 否则真机中断屏蔽
				{
					ULONG probeCpuX = KeGetCurrentProcessorNumber();
					if (g_vcpu[probeCpuX].PendingIntrCount > 0)
					{
						ULONG64 apicBaseX = __readmsr(0x1B);
						if ((apicBaseX & 0xC00) == 0xC00)
						{
							for (LONG pk = 0; pk < g_vcpu[probeCpuX].PendingIntrCount; pk++)
							{
								__writemsr(0x80B, 0);
							}
						}
						g_vcpu[probeCpuX].PendingIntrCount = 0;
					}
				}
				//vmx_off前还原GDTR/IDTR limit(同rcx==1路径)
				VmxRestoreDtrLimits();
				//CR3恢复(同rcx==1路径; vmread须在vmx_off前)
				ULONG64 probeExitCr3 = 0;
				__vmx_vmread(GUEST_CR3, &probeExitCr3);
				__vmx_off();
				__writecr3(probeExitCr3);
				ULONG64 probeCr4 = __readcr4();
				probeCr4 &= ~0x2000;              //清CR4.VMXE, 干净回真机
				__writecr4(probeCr4);
				ULONG probeCpu = KeGetCurrentProcessorNumber();
				g_vcpu[probeCpu].bVmxOn = 0;
				g_vcpu[probeCpu].bLaunchFailed = 1;
				//IF=0时跳过sti(真机IF由VMXInitCpuStart统一恢复)
				if (probeFlags & 0x200)
				{
					_enable();
				}
				//跳回vmcall下一条(探针jmp): ret回VMXInitCpuStart走失败分支
				VmxJumGuestRegs(GuestRegs, guestRsp, guestRip + exitCodeLen);
#endif
				//GEPT_PROBE_EXIT=0: 落到通用RIP推进, guest接管OS执行
			}
			//压测循环进度: 每1024次采样1条'L'(a=rbx剩余值)
			else if (GuestRegs->rcx == 4)
			{
				if ((GuestRegs->rbx & 0x3FF) == 0)
				{
					FlRingPush('L', KeGetCurrentProcessorNumber(), 18,
						GuestRegs->rbx, 0, 0);
				}
			}
			//循环完成标记'Y'
			else if (GuestRegs->rcx == 6)
			{
				FlRingPush('Y', KeGetCurrentProcessorNumber(), 18,
					GuestRegs->rbx, 0, 0);
			}
			//未知vmcall功能码=外来者: 注入#UD(裸机VMCALL不在VMX
			//operation=#UD; 静默放行=hypervisor泄漏)
			else
			{
				VmxInjectUd(KeGetCurrentProcessorNumber(), 18, guestRip);
				__vmx_vmwrite(GUEST_RIP, guestRip);
				return;
			}
		}
		break;
		//=============== VMX指令族exit ===============
		//注入#UD(裸机"not in VMX operation"语义)。若走default逃生:
		//真机重执行VMXOFF=#UD蓝屏, VMXON可能真成功=抢占VMX root;
		//同框架后到实例的vmxon被注入#GP→全核失败→干净退出(互斥仲裁)
		case EXIT_REASON_VMCLEAR:
		case EXIT_REASON_VMLAUNCH:
		case EXIT_REASON_VMPTRLD:
		case EXIT_REASON_VMPTRST:
		case EXIT_REASON_VMREAD:
		case EXIT_REASON_VMRESUME:
		case EXIT_REASON_VMWRITE:
		case EXIT_REASON_VMXOFF:
		case EXIT_REASON_INVEPT:
		case EXIT_REASON_INVVPID:
		{
			VmxInjectUd(KeGetCurrentProcessorNumber(), vmexitReason, guestRip);
			//异常在本指令派发: RIP原样写回+早退
			__vmx_vmwrite(GUEST_RIP, guestRip);
			return;
		}
		case EXIT_REASON_VMXON:
	{
		//按guest可见CR4.VMXE(=CR4_READ_SHADOW bit13)分流(裸机一致):
		//  shadow.VMXE=1→#GP(0): 配套0x3A读伪造=1(锁+VMX禁用形态),
		//    读/行为互证
		//  shadow.VMXE=0→#UD: 裸机"CR4.VMXE=0时VMXON"=#UD
		//(若0x3A真值5可读, "读到5却vmxon失败"=矛盾泄漏, 故两层配套)
		ULONG64 cr4ShadowForVmxon = 0;
		__vmx_vmread(CR4_READ_SHADOW, &cr4ShadowForVmxon);
		if (cr4ShadowForVmxon & 0x2000)
		{
			VmxInjectGp(KeGetCurrentProcessorNumber(), 27, guestRip);
		}
		else
		{
			VmxInjectUd(KeGetCurrentProcessorNumber(), 27, guestRip);
		}
		//异常在本指令派发: RIP原样写回+早退
		__vmx_vmwrite(GUEST_RIP, guestRip);
		return;
	}
	case EXIT_REASON_CR_ACCESS:   //28
	{
		//CR4.VMXE影子化(SDM 28.1.3/28.3): mask=bit13, shadow=真值清bit13。
		//读: masked位喂shadow(=0), 其余真值(硬件直读零exit);
		//写: masked位≠shadow→exit到本case
		//exitQualification(Table 30-3): bits3:0=CR号 bits5:4=访问类型
		//(0=MOV to/1=from/2=CLTS/3=LMSW) bits11:8=GPR号(帧偏移=寄存器号×8)
		ULONG crNum   = (ULONG)(exitQual & 0xF);
		ULONG accType = (ULONG)((exitQual >> 4) & 3);
		ULONG gprIdx  = (ULONG)((exitQual >> 8) & 0xF);
		//源操作数: MOV to CR的GPR读值; 目的GPR=RSP时帧上rsp槽是asm
		//压栈占位值(非真RSP)——改用硬件保存的GUEST_RSP
		ULONG64 srcVal = (gprIdx == 4)
			? guestRsp
			: *(PULONG64)((PUCHAR)GuestRegs + gprIdx * 8);
		//'c'环留痕(采样): rsn=28, a=rip, b=exitQual, c=源操作数
		static volatile LONG s_crCnt[64] = { 0 };
		ULONG crCpu = KeGetCurrentProcessorNumber();
		LONG crn = InterlockedIncrement(&s_crCnt[crCpu & 63]);
		if (crn == 1 || (crn & 0xFFF) == 0)
		{
			FlRingPush('c', crCpu, 28, guestRip, exitQual, srcVal);
		}
		if (crNum == 4)
		{
			ULONG64 cr4Mask = 0, curCr4 = 0, cr4Shd = 0;
			__vmx_vmread(CR4_GUEST_HOST_MASK, &cr4Mask);
			__vmx_vmread(GUEST_CR4, &curCr4);
			if (accType == 0)      //MOV to CR4: 唯一理论可达形态
			{
				//host-owned位(mask)保持GUEST_CR4(VMXE恒1), 其余位=写值;
				//shadow=写值原样
				__vmx_vmwrite(GUEST_CR4,
					(srcVal & ~cr4Mask) | (curCr4 & cr4Mask));
				__vmx_vmwrite(CR4_READ_SHADOW, srcVal);
			}
			else if (accType == 1) //MOV from CR4: 硬件直喂shadow零exit
			{
				//防御性模拟(SDM §28.3): dst=(真值&~mask)|(shadow&mask)
				__vmx_vmread(CR4_READ_SHADOW, &cr4Shd);
				ULONG64 cr4ReadVal = (curCr4 & ~cr4Mask) | (cr4Shd & cr4Mask);
				if (gprIdx == 4)
				{
					__vmx_vmwrite(GUEST_RSP, cr4ReadVal);
				}
				else
				{
					*(PULONG64)((PUCHAR)GuestRegs + gprIdx * 8) = cr4ReadVal;
				}
			}
		}
		else if (crNum == 0)
		{
			//CR0(mask=0本不exit)——防御性同公式处理
			ULONG64 cr0Mask = 0, curCr0 = 0;
			__vmx_vmread(CR0_GUEST_HOST_MASK, &cr0Mask);
			__vmx_vmread(GUEST_CR0, &curCr0);
			if (accType == 0)
			{
				__vmx_vmwrite(GUEST_CR0,
					(srcVal & ~cr0Mask) | (curCr0 & cr0Mask));
				__vmx_vmwrite(CR0_READ_SHADOW, srcVal);
			}
			else if (accType == 1)
			{
				ULONG64 cr0Shd = 0;
				__vmx_vmread(CR0_READ_SHADOW, &cr0Shd);
				ULONG64 cr0ReadVal = (curCr0 & ~cr0Mask) | (cr0Shd & cr0Mask);
				if (gprIdx == 4)
				{
					__vmx_vmwrite(GUEST_RSP, cr0ReadVal);
				}
				else
				{
					*(PULONG64)((PUCHAR)GuestRegs + gprIdx * 8) = cr0ReadVal;
				}
			}
		}
		//其余形态理论不可达(CLTS/LMSW不exit; CR3/CR8无exiting控制):
		//'c'留痕已够, 只推进RIP
	}
	break;
		case EXIT_REASON_INVD:
		{

			VmxInvd();
		}
		break;
		case EXIT_REASON_WBINVD:
		{
			//INVD/WBINVD无条件exit, 必须VMM代执行(缺case=跳过指令=数据损坏)
			__wbinvd();
		}
		break;
		//=============== 指令exit模拟 ===============
		//本机must-1集使这些指令exiting全部关闭, 以下case大概率不触发;
		//换CPU布局即需要(保留)
		case EXIT_REASON_RDTSC:
	{
		//回填必须加TSC_OFFSET(回填裸TSC=时间线前跳)
		ULONG64 tscOff = 0;
		__vmx_vmread(TSC_OFFSET, &tscOff);
		ULONG64 tsc = __rdtsc() + tscOff;
		GuestRegs->rax = tsc & 0xFFFFFFFF;
		GuestRegs->rdx = tsc >> 32;
	}
	break;
	case EXIT_REASON_RDTSCP:   //51
	{
		//SDM 28.3: EAX:EDX=TSC+TSC_OFFSET; ECX=IA32_TSC_AUX bits31:0
		ULONG64 tscOffP = 0;
		__vmx_vmread(TSC_OFFSET, &tscOffP);
		ULONG64 tscP = __rdtsc() + tscOffP;
		GuestRegs->rax = tscP & 0xFFFFFFFF;
		GuestRegs->rdx = tscP >> 32;
		GuestRegs->rcx = __readmsr(MSR_IA32_TSC_AUX) & 0xFFFFFFFF;
	}
	break;
		case EXIT_REASON_INVLPG:
		{
			//INVLPG代执行: EXIT_QUALIFICATION=操作的线性地址。
			//root与guest共用CR3(恒等虚拟化), root执行invlpg语义一致
			__invlpg((void*)(ULONG_PTR)exitQual);
		}
		break;
		case EXIT_REASON_HLT:
		{
			//跳过hlt(空闲线程会高频exit, 已豁免环检+限流)
		}
		break;
		case EXIT_REASON_MWAIT_INSTRUCTION:
		{
			//MWAIT同HLT跳过; MONITOR无副作用同跳过
		}
		break;
		case EXIT_REASON_MONITOR_INSTRUCTION:   //39
		{
			//MONITOR: 建立监控地址, 无架构可见副作用, 跳过即可
		}
		break;
		case EXIT_REASON_MSR_READ:
		{
			VmxMsrReadHandler(GuestRegs);
		}
		break;
		case EXIT_REASON_MSR_WRITE:
	{
		//WRMSR代执行: rdx:rax=值, rcx=MSR号。回调TRUE=放行代写,
	//FALSE=静默丢弃; 未hook=直通
	ULONG64 msrVal = ((ULONG64)GuestRegs->rdx << 32)
			| (GuestRegs->rax & 0xFFFFFFFF);
		if (GeptMsrDispatchWrite((ULONG32)GuestRegs->rcx, msrVal))
		{
			__writemsr(GuestRegs->rcx, msrVal);
		}
	}
	break;
	case EXIT_REASON_XSETBV:   //55
	{
		//XSETBV无条件exit(SDM 25.1.3), VMM代执行: rcx=XCR索引, rdx:rax=值
		_xsetbv((unsigned int)GuestRegs->rcx,
			((ULONG64)GuestRegs->rdx << 32) | (GuestRegs->rax & 0xFFFFFFFF));
	}
	break;
	case EXIT_REASON_VMFUNC:   //59
	{
		//VMFUNC失败exit(EPTP-list项非法/ECX>=512): 视图未切换,
		//推RIP跳过后guest继续旧视图(绝不走'U'逃生——真机重执行
		//vmfunc=#UD蓝屏)。length异常时按定长3跳过(0F01D4)
		if (exitCodeLen == 0 || exitCodeLen > 15)
		{
			exitCodeLen = 3;
		}
		FlRingPush('u', KeGetCurrentProcessorNumber(), 59,
			guestRip, exitQual, exitCodeLen);
	}
	break;
		case EXIT_REASON_TRIPLE_FAULT:
		{
			//三重故障不可恢复(重执行=真机重启): park(vmx_off+sti/hlt
			//自旋继续服务中断), 切断级联冻结, 'T'环留痕
			VmxTripleFaultPark();    //noreturn
		}
		break;
		case EXIT_REASON_INVALID_GUEST_STATE:
		{
			//VM-entry failure(guest状态非法)。launch期(guestRip在探针区间,
		//GUEST_RSP=启动栈): 改写RIP到CmGeustRip纯栈恢复后逃生, 主线程
		//从CmGuestRsp()返回走失败分支; 运行期(OS线程栈): 不改写, 直接
		//逃回被中断上下文(在OS栈上执行栈恢复代码=栈粉碎)
			if (guestRip >= (ULONG64)(ULONG_PTR)CmGuestProbe &&
				guestRip < (ULONG64)(ULONG_PTR)CmVmCall)
			{
				__vmx_vmwrite(GUEST_RIP, CmGeustRip);
			}
			VmxExitStormEscape('G', 33, guestRip, exitQual, GuestRegs);    //noreturn
		}
		break;
		case EXIT_REASON_EXTERNAL_INTERRUPT:
		{
			//pin=0直投下理论不可达; 防御: 'I'留痕, 同核>100次逃生'J'
			ULONG64 intrInfo = 0;
			__vmx_vmread(VM_EXIT_INTR_INFO, &intrInfo);
			ULONG cpuX = KeGetCurrentProcessorNumber();
			FlRingPush('I', cpuX, 1, intrInfo & 0xFF, intrInfo, 0);
			static volatile LONG s_iCnt[64] = { 0 };
			if (InterlockedIncrement(&s_iCnt[cpuX & 63]) > 100)
			{
				VmxExitStormEscape('J', 1, intrInfo, guestRip, GuestRegs);    //noreturn
			}
			//非指令性exit: RIP原样写回。中断仍在LAPIC IRR, resume后投递
			__vmx_vmwrite(GUEST_RIP, guestRip);
			return;
		}
		break;
		case EXIT_REASON_PENDING_INTERRUPT:   //7: interrupt-window exiting=guest可中断了
		{
			//理论不可达; 防御: 'J'留痕后放行
			FlRingPush('J', KeGetCurrentProcessorNumber(), 7, guestRip, 0, 0);
			//非指令性exit: 原样写回RIP, 绝不能推进
			__vmx_vmwrite(GUEST_RIP, guestRip);
			return;
		}
		break;
		case EXIT_REASON_EPT_VIOLATION:
		{
			EptExitHandler(GuestRegs);
			return;
		}
		break;
		case EXIT_REASON_EPT_CONFIG:
		{
			//EPT misconfig(PTE格式非法, 非指令性exit): 留痕, >1000次逃生
			static volatile LONG eptCfgCount = 0;
			ULONG64 cfgGpa = 0;
			__vmx_vmread(GUEST_PHYSICAL_ADDRESS, &cfgGpa);
			if (InterlockedIncrement(&eptCfgCount) == 1)
			{
				FlRingPush('C', KeGetCurrentProcessorNumber(), 49,
					cfgGpa, guestRip, 0);
			}
			if (eptCfgCount > 1000)
			{
				VmxExitStormEscape('X', 49, cfgGpa, guestRip, GuestRegs);    //noreturn
			}
		}
		return;
		default:
		{
			//未知exit: 绝不能推进RIP(跳过指令=副作用丢失; len=0推进=
		//无限循环), 也不能原地重试。逃生: vmx_off回真机重执行
			VmxExitStormEscape(exitCodeLen == 0 ? 'Z' : 'U',
				vmexitReason, guestRip, exitQual, GuestRegs);    //noreturn
		}
		break;
	}
	__vmx_vmwrite(GUEST_RIP, guestRip+ exitCodeLen);
}




//vmresume失败处理(asm跳入, 永不返回): GUEST状态仍可从VMCS读出,
//'R'标记入环后逃生
void VmxResumeFailedEntry(void)
{
	//GPR已被asm pop链恢复, 无帧可传
	VmxExitStormEscape('R', 0, 0, 0, NULL);
}

//风暴逃生(永不返回): 标记入环后vmx_off脱离VT, 跳回guest触发点重执行。
//逃生场景指令均未成功执行, RIP一律不推进; 唯一例外reason=18(VMCALL)
//必须推进(真机重执行vmcall=#UD蓝屏)。
//逃生而非停核: 停核=级联冻结(日志线程死=死因零落盘); 逃生后本核回
//真机, 系统与其余核无感。
//IF按GUEST_RFLAGS原值恢复(强制sti会破坏guest临界区)。
//tag: 'X'=violation/misconfig风暴 'A'=动态建表失败 'P'=低地址环路
//     'D'=同(reason,rip)环路 'Z'=len0未知exit 'U'=len>0未知exit
//     'R'=vmresume失败 'G'=VM-entry failure
void VmxExitStormEscape(char tag, ULONG reason, ULONG64 a, ULONG64 b,
	PVOID guestRegs)
{
	ULONG cpu = KeGetCurrentProcessorNumber();
	FlRingPush(tag, cpu, reason, a, b, 0);
	//vmread必须在vmx_off之前(退出VMX operation后vmread非法)
	ULONG64 guestRsp = 0, guestRip = 0, guestRflags = 0;
	__vmx_vmread(GUEST_RSP, &guestRsp);
	__vmx_vmread(GUEST_RIP, &guestRip);
	__vmx_vmread(GUEST_RFLAGS, &guestRflags);
	//vmcall必须推RIP再跳(见函数头); 'R'/'G'路径reason不匹配, 不触发
	if (reason == EXIT_REASON_VMCALL)
	{
		ULONG64 vmcallLen = 0;
		__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &vmcallLen);
		if (vmcallLen > 0 && vmcallLen <= 15)
		{
			guestRip += vmcallLen;
		}
	}
	//vmx_off前invept全上下文
	EptInveptBothViews();
	//vmx_off前还原GDTR/IDTR limit(见VmxRestoreDtrLimits)
	VmxRestoreDtrLimits();
	//CR3恢复(同卸载路径): 逃逸线程带HOST_CR3残留会蓝屏; vmread须在vmx_off前
	ULONG64 escapeCr3 = 0;
	__vmx_vmread(GUEST_CR3, &escapeCr3);
	__vmx_off();
	__writecr3(escapeCr3);
	ULONG64 cr4 = __readcr4();
	cr4 &= ~0x2000;              //清CR4.VMXE, 干净回真机
	__writecr4(cr4);
	g_vcpu[cpu].bVmxOn = 0;
	g_vcpu[cpu].bInGuest = 0;
	g_vcpu[cpu].bLaunchFailed = 1;   //主线程判此标志走失败分支(不再冻结)
	//清in-service中断债(x2APIC的EOI=MSR 0x80B; xAPIC略过)
	if (g_vcpu[cpu].PendingIntrCount > 0)
	{
		ULONG64 apicBase = __readmsr(0x1B);       //IA32_APICBASE
		if ((apicBase & 0xC00) == 0xC00)          //bits11:10=10: x2APIC使能
		{
			for (LONG pe = 0; pe < g_vcpu[cpu].PendingIntrCount; pe++)
			{
				__writemsr(0x80B, 0);             //EOI: 清一条in-service
			}
		}
		g_vcpu[cpu].PendingIntrCount = 0;         //xAPIC时只能弃(计数清零防重复)
	}
	if (guestRflags & 0x200)
	{
		_enable();               //已脱离VMX, 恢复guest原始IF
	}
	//guestRegs非NULL: 恢复非易失GPR后跳; NULL: 寄存器已被asm恢复, 直接跳
	if (guestRegs != NULL)
	{
		VmxJumGuestRegs(guestRegs, guestRsp, guestRip);
	}
	VmxJumGuest(guestRsp, guestRip); //重执行触发指令(真机无VMCS拦截, 必然通过)
}

//三重故障park(永不返回): 重执行=真机三重故障=重启, 停核=级联冻结,
//故vmx_off+sti/hlt自旋继续服务中断(机器存活, 'T'+环尾由T1落盘)。
//本核永久park, 驱动不得卸载(g_geptParkedMask守卫)。
//不调FlLog(IRQL未知), 只FlRingPush
void VmxTripleFaultPark(void)
{
	ULONG cpu = KeGetCurrentProcessorNumber();
	FlRingPush('T', cpu, 2, 0, 0, 0);
	//清in-service中断债
	if (g_vcpu[cpu].PendingIntrCount > 0)
	{
		ULONG64 apicBase = __readmsr(0x1B);
		if ((apicBase & 0xC00) == 0xC00)          //x2APIC
		{
			for (LONG pe = 0; pe < g_vcpu[cpu].PendingIntrCount; pe++)
			{
				__writemsr(0x80B, 0);             //EOI: 清一条in-service
			}
		}
		g_vcpu[cpu].PendingIntrCount = 0;
	}
	//脱离VMX(exit上下文, host状态合法)
	EptInveptBothViews();
	__vmx_off();
	ULONG64 cr4 = __readcr4();
	cr4 &= ~0x2000;                               //清CR4.VMXE, 干净回真机
	__writecr4(cr4);
	g_vcpu[cpu].bVmxOn = 0;
	g_vcpu[cpu].bInGuest = 0;
	g_vcpu[cpu].bLaunchFailed = 1;                //卸载路径跳过本核vmcall
	//park位掩码(VmxShutdownAllCpus卸载守卫): park核的VMM栈/park代码页不能释放
	InterlockedOr(&g_geptParkedMask, (LONG)(1UL << (cpu & 31)));
	//park本体(asm, 永不返回): sti+hlt自旋持续服务中断, 切断级联冻结
	CmTripleFaultPark();
}

int VmxSetupVmcs(PVOID GuestRsp)
{
	ULONG cpuNumber = KeGetCurrentProcessorNumber();
	//VCPU约8.4KB, 必须指针访问(值拷贝=内核栈溢出)
	PVCPU currentCpu = &g_vcpu[cpuNumber];
	//DbgBreakPoint();
	FlLog("cpu%u VMCS[1/6]: 段寄存器...", cpuNumber);
	VmxFillSelectorData(RegGetEs(),0);
	VmxFillSelectorData(RegGetCs(), 1);
	VmxFillSelectorData(RegGetSs(), 2);
	VmxFillSelectorData(RegGetDs(), 3);
	VmxFillSelectorData(RegGetFs(), 4);
	VmxFillSelectorData(RegGetGs(), 5);
	VmxFillSelectorData(GetLdtr(),6);

	__vmx_vmwrite(HOST_ES_SELECTOR, RegGetEs() & 0XFFF8);
	__vmx_vmwrite(HOST_CS_SELECTOR, RegGetCs() & 0XFFF8);
	__vmx_vmwrite(HOST_SS_SELECTOR, RegGetSs() & 0XFFF8);
	__vmx_vmwrite(HOST_DS_SELECTOR, RegGetDs() & 0XFFF8);
	__vmx_vmwrite(HOST_FS_SELECTOR, RegGetFs() & 0XFFF8);
	__vmx_vmwrite(HOST_GS_SELECTOR, RegGetGs() & 0XFFF8);
	//填充TR寄存器
	FlLog("cpu%u VMCS[2/6]: TR+FS/GS base...", cpuNumber);
	USHORT trSelector=GetTrSelector();
	trSelector = trSelector &= 0xFFF8;
	ULONG trLimit = __segmentlimit(trSelector);
	ULONG64 gdtBase = GetGdtBase();
	LARGE_INTEGER trSegement = { 0 };
	PULONG trContext=(PULONG)(gdtBase + trSelector);
	trSegement.LowPart = ((trContext[0] >> 16) & 0xFFFF) | ((trContext[1] & 0xFF) << 16) | ((trContext[1] & 0xFF000000));
	trSegement.HighPart = trContext[2];
	ULONG trAttr = (trContext[1] & 0x00F0FF00) >> 8;
	__vmx_vmwrite(GUEST_TR_BASE, trSegement.QuadPart);
	__vmx_vmwrite(GUEST_TR_LIMIT, trLimit);
	__vmx_vmwrite(GUEST_TR_AR_BYTES, trAttr);
	__vmx_vmwrite(GUEST_TR_SELECTOR, trSelector);
	__vmx_vmwrite(HOST_TR_BASE, trSegement.QuadPart);
	__vmx_vmwrite(HOST_TR_SELECTOR, trSelector);

	__vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));
	__vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));
	__vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
	__vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));
	//CR
	FlLog("cpu%u VMCS[3/6]: CR/DR7/MSR状态...", cpuNumber);
	__vmx_vmwrite(GUEST_CR0,__readcr0());
	__vmx_vmwrite(GUEST_CR3,__readcr3());
	__vmx_vmwrite(GUEST_CR4,__readcr4());
	//CR4.VMXE影子化: mask=bit13, shadow=真值清bit13(读CR4见VMXE=0,
	//写VMXE→exit28); GUEST_CR4保持真值(VMXE=1, VMXON持续有效)
	__vmx_vmwrite(CR4_GUEST_HOST_MASK, 0x2000);
	__vmx_vmwrite(CR4_READ_SHADOW, __readcr4() & ~0x2000ULL);
	__vmx_vmwrite(GUEST_DR7, __readdr(7));
	__vmx_vmwrite(HOST_CR0, __readcr0());
	__vmx_vmwrite(HOST_CR3, __readcr3());
	__vmx_vmwrite(HOST_CR4, __readcr4());
	//IA_32
	__vmx_vmwrite(VMCS_LINK_POINTER, -1);
	__vmx_vmwrite(VMCS_LINK_POINTER_HIGH, -1);
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL));
	__vmx_vmwrite(GUEST_IA32_PAT, __readmsr(MSR_IA32_PAT));
	__vmx_vmwrite(GUEST_IA32_EFER, __readmsr(MSR_IA32_EFER));
	//host PAT/EFER: 不填=vmlaunch error 8(64位host一致性检查)
	__vmx_vmwrite(HOST_IA32_PAT, __readmsr(MSR_IA32_PAT));
	__vmx_vmwrite(HOST_IA32_EFER, __readmsr(MSR_IA32_EFER));

	//sysenter
	__vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	__vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	__vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	__vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));

	//GDT
	FlLog("cpu%u VMCS[4/6]: GDTR/IDTR/RSP/RIP...", cpuNumber);
	__vmx_vmwrite(GUEST_GDTR_BASE,GetGdtBase());
	__vmx_vmwrite(GUEST_GDTR_LIMIT, GetGdtLimit());
	__vmx_vmwrite(HOST_GDTR_BASE, GetGdtBase());
	//IDT
	__vmx_vmwrite(GUEST_IDTR_BASE, GetIdtBase());
	__vmx_vmwrite(GUEST_IDTR_LIMIT, GetIdtLimit());
	__vmx_vmwrite(HOST_IDTR_BASE, GetIdtBase());
	//guest rsp rip
	__vmx_vmwrite(GUEST_RSP, GuestRsp);
	//GUEST_RIP指向落地探针(自证VM-entry+EPT取指+exit+RIP推进+vmresume
	//全链路), 探针不触碰RSP/不依赖GPR(栈恢复见common-asm.asm)
	__vmx_vmwrite(GUEST_RIP, CmGuestProbe);
	__vmx_vmwrite(GUEST_RFLAGS, __readeflags());
	__vmx_vmwrite(HOST_RSP, (ULONG64)currentCpu->VMMStack+PAGE_SIZE*5);
	__vmx_vmwrite(HOST_RIP, VmxVmexitHandler);
	ULONG64 basicMsr = __readmsr(MSR_IA32_VMX_BASIC);
	//VMX_BASIC bit55=TRUE能力MSR存在: 存在则用TRUE MSR(0x48D-0x490),
	//否则旧式(0x481-0x484); 公式对两者都正确(见VmxMsrAdjuest)
	BOOLEAN useTrueCtl = ((basicMsr >> 55) & 1) != 0;
	ULONG64 result = 0;
	ULONG64 entryMsrNum = MSR_IA32_VMX_ENTRY_CTLS;
	ULONG64 exitMsrNum = MSR_IA32_VMX_EXIT_CTLS;
	ULONG64 pinMsr = MSR_IA32_VMX_PINBASED_CTLS;
	ULONG64	procMsr = MSR_IA32_VMX_PROCBASED_CTLS;
	if (useTrueCtl)
	{
		entryMsrNum = MSR_IA32_VMX_TRUE_ENTRY_CTLS;
		exitMsrNum= MSR_IA32_VMX_TRUE_EXIT_CTLS;

		pinMsr = MSR_IA32_VMX_TRUE_PINBASED_CTLS;
		procMsr= MSR_IA32_VMX_TRUE_PROCBASED_CTLS;
	}
	FlLog("cpu%u VMCS[5/6]: 控制字段+MSR位图 (bit55=%d)...", cpuNumber, (int)useTrueCtl);
	//能力MSR原值一次性落盘(高32=允许1掩码, 低32=必须1位)
	{
		static volatile LONG s_msrLogged = 0;
		if (InterlockedCompareExchange(&s_msrLogged, 1, 0) == 0)
		{
			FlLog("MSR原值: PIN=%llX PROC=%llX EXIT=%llX ENTRY=%llX (实际读取的%s)",
				(unsigned long long)__readmsr(pinMsr),
				(unsigned long long)__readmsr(procMsr),
				(unsigned long long)__readmsr(exitMsrNum),
				(unsigned long long)__readmsr(entryMsrNum),
				useTrueCtl ? "TRUE MSR" : "旧式MSR");
			FlLog("MSR原值: SEC(48Bh)=%llX EPT_VPID_CAP(48Ch)=%llX",
				(unsigned long long)__readmsr(MSR_IA32_VMX_PROCBASED_CTLS2),
				(unsigned long long)__readmsr(MSR_IA32_VMX_EPT_VPID_CAP));
		}
	}
	//pin期望=0(外部中断直投guest)
	ULONG pinCtl   = VmxMsrAdjuest(pinMsr, 0);
	//proc: bit3=TSC offsetting(补偿硬件基础), bit12保持0(RDTSC直通),
	//bit28(MSR位图)/bit31(secondary)必需
	ULONG procCtl  = VmxMsrAdjuest(procMsr, 0X8 | 0X10000000 | 0X80000000);
	//exitCtl只留bit9(host address-space size); 绝不开bit15
	//(ack-on-exit, 直投纪律)
	ULONG exitCtl  = VmxMsrAdjuest(exitMsrNum, 0x200);
	ULONG entryCtl = VmxMsrAdjuest(entryMsrNum, 0x200);
	//控制字段留痕(proc的bit3=0=极老CPU, TSC补偿自动降级)
	FlLog("cpu%u 控制字段(直投+TSCoff): pin=%08X proc=%08X exit=%08X entry=%08X",
		cpuNumber, pinCtl, procCtl, exitCtl, entryCtl);
	__vmx_vmwrite(VM_ENTRY_CONTROLS, entryCtl);
	__vmx_vmwrite(VM_EXIT_CONTROLS, exitCtl);
	__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, pinCtl);
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, procCtl);
	//TSC_OFFSET初始0, 此后VmxTscCompensate单调向负推
	__vmx_vmwrite(TSC_OFFSET, 0);
	PHYSICAL_ADDRESS msrPhyAddr = MmGetPhysicalAddress(currentCpu->MsrBitMap);
	__vmx_vmwrite(MSR_BITMAP, msrPhyAddr.QuadPart);
	__vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
	__vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);
	__vmx_vmwrite(GUEST_ACTIVITY_STATE, 0);   // 处于正常执行指令状态
	//MSR位图在此接线(恒零=全直通); GeptMsr.c按核置位实现RDMSR/WRMSR拦截
	FlLog("cpu%u VMCS[6/6]: 填充完成, 启用EPT", cpuNumber);
	//EPT数据已在DriverEntry(PASSIVE_LEVEL)预分配, 此处只写入VMCS
	if (g_vcpu[cpuNumber].PeptData != NULL)
	{
		//不用VPID: 恒等虚拟化无需(它是vcpu切换优化), invept即可完整冲刷
		//ctls2: bit1(secondary) bit3(rdtscp) bit12(invpcid) bit20(xsaves)
		//bit13(VMFUNC)。位布局须与SDM核对(公式无法拦截允许域内的错误期望)
		ULONG64 ctls2Value = VmxMsrAdjuest(MSR_IA32_VMX_PROCBASED_CTLS2,
			0x2 | 0x8 | 0x2000 | 0x1000 | 0x100000);
		__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, ctls2Value);
		__vmx_vmwrite(EPT_POINTER, g_vcpu[cpuNumber].Eptp.ALL);
		FlLog("cpu%u ctls2=%llX (期望0010300A=EPT+rdtscp+invpcid+xsaves+VMFUNC, 无VPID)",
			cpuNumber, (unsigned long long)ctls2Value);
		//VMFUNC EPTP switching(零VM-Exit hook基石)。VMFUNC无CPUID
		//枚举位, 判据=ctls2 bit13实际置位+EPTP-list页就绪; 不满足=
		//bVmfuncOn=0, hook走violation方案(fallback)
		if ((ctls2Value & 0x2000) && g_vcpu[cpuNumber].VmfuncEptpList != NULL)
		{
			//EPTP-list: [0]=clean, [1]=hooked(guest内vmfunc(0,idx)零
			//VM-Exit切换, SDM §28.5.7.3)。无hooked EPT时双项同值(no-op)。
			//未用项(2-511)全0: 误切→exit 59(非#UD)
			PULONG64 eptpList = (PULONG64)g_vcpu[cpuNumber].VmfuncEptpList;
			eptpList[0] = g_vcpu[cpuNumber].Eptp.ALL;
			eptpList[1] = (g_vcpu[cpuNumber].PeptDataHooked != NULL)
				? g_vcpu[cpuNumber].EptpHooked.ALL
				: g_vcpu[cpuNumber].Eptp.ALL;
			PHYSICAL_ADDRESS eptpListPhys =
				MmGetPhysicalAddress(g_vcpu[cpuNumber].VmfuncEptpList);
			//bit0=EPTP switching; EPTP-list须4KB对齐
			__vmx_vmwrite(VMFUNC_CONTROL, 1);
			__vmx_vmwrite(EPTP_LIST_ADDRESS, eptpListPhys.QuadPart);
			g_vcpu[cpuNumber].bVmfuncOn = 1;
			FlLog("cpu%u VMFUNC已启用: EPTP-list=%p(phys=%llX) [0]=%llX(clean) [1]=%llX(%s)",
				cpuNumber, g_vcpu[cpuNumber].VmfuncEptpList,
				(unsigned long long)eptpListPhys.QuadPart,
				(unsigned long long)eptpList[0], (unsigned long long)eptpList[1],
				(g_vcpu[cpuNumber].PeptDataHooked != NULL)
				? "hooked双EPT" : "同值no-op(hooked分配失败)");
		}
		else
		{
			g_vcpu[cpuNumber].bVmfuncOn = 0;
			FlLog("cpu%u VMFUNC未启用(ctls2.bit13=%d list=%p, MSR 0x48B无VMFUNC控制=CPU不支持)——hook走violation方案",
				cpuNumber, (int)((ctls2Value >> 13) & 1),
				g_vcpu[cpuNumber].VmfuncEptpList);
		}
	}
	else
	{
		//EPT未就绪: 仍可虚拟化运行(无hook能力), 指令许可位仍必须开
		FlLog("cpu%u 无EPT数据(预分配失败?), ctls2仅指令许可位", cpuNumber);
		ULONG64 ctls2Value = VmxMsrAdjuest(MSR_IA32_VMX_PROCBASED_CTLS2,
			0x8 | 0x1000 | 0x100000);
		__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, ctls2Value);
	}

	//EPT软件自检(ept.c): launch前软件走查复演硬件翻译, 失败=放弃
	//本核vmlaunch(留在root模式)
	if (g_vcpu[cpuNumber].PeptData != NULL)
	{
		ULONG eptFails = EptVerifyTables(cpuNumber, (ULONG64)(ULONG_PTR)GuestRsp);
		if (eptFails > 0)
		{
			g_vcpu[cpuNumber].bLaunchFailed = 1;
			FlLog("cpu%u EPT自检失败(%u组), 放弃vmlaunch(本核留在root模式)",
				cpuNumber, eptFails);
			return 1;
		}
	}
	FlLog("cpu%u vmlaunch前自检: EPT=PASS EPTP=%llX 探针VA=%llX 模式=%s",
		cpuNumber,
		(unsigned long long)g_vcpu[cpuNumber].Eptp.ALL,
		(unsigned long long)(ULONG_PTR)CmGuestProbe,
#if GEPT_PROBE_EXIT
		"EXIT(自测)"
#else
		"KEEP(接管)"
#endif
	);
	FlLog("cpu%u vmlaunch...(护卫开: T1停写盘至probe返回)", cpuNumber);
	//观测预热(见FlArmLaunchWatch)
	FlArmLaunchWatch();
	//开写盘护卫
	g_flWriteGuard = 1;
	//武装看门狗(30s写盘零推进→黑匣子蓝屏, 见FlWdArm)
	FlWdArm();
	//IF0探针窗口(必须在FlArmLaunchWatch之后, 其睡眠依赖IF1):
	//中断留IRR不投递, sti后硬件直投
	_disable();
	//重写GUEST_RFLAGS(探针全程IF=0, 真机IF由VMXInitCpuStart统一恢复)
	__vmx_vmwrite(GUEST_RFLAGS, __readeflags());
	//'F'环事件=launch窗口开启标记(与'f'配对)
	FlRingPush('F', cpuNumber, 0, 0, 0, 0);
	result=__vmx_vmlaunch();

	if (result)
	{
		ULONG vmerr = 0;
		__vmx_vmread(VM_INSTRUCTION_ERROR, &vmerr);
		g_vcpu[cpuNumber].bLaunchFailed = 1;
		//先清护卫再FlLog
		g_flWriteGuard = 0;
		//恢复IF(FlLog的等待依赖时钟中断)
		_enable();
		FlLog("cpu%u vmlaunch失败! 错误码=%d (7=控制字段非法 8=host状态非法, SDM Table 33-1)", cpuNumber, vmerr);
		g_flLaunchHot = 0;
	}
	return (int)result;
}

void VmxFillSelectorData(USHORT selector,USHORT index)
{
	SEGMENT_SELECTOR segMentSelector = { 0 };
	segMentSelector.sel = selector;
	segMentSelector.limit = __segmentlimit(segMentSelector.sel);
	segMentSelector.base = 0;
	//获取Gdt表
	ULONG64 gdtBase = GetGdtBase();
	//获取段描述符 0x23 10 0000 *
	PSEGMENT_DESCRIPTOR segmentDes =
		(PSEGMENT_DESCRIPTOR)(gdtBase + (ULONG64)(segMentSelector.sel & 0xFFF8));//等价与 gdtBase+index*8
	//segmentDes->BaseLow| segmentDes->BaseMid
	segMentSelector.base =
		segmentDes->BaseHigh << 24 | segmentDes->BaseMid << 16 | segmentDes->BaseLow;
	segMentSelector.attributes = segmentDes->AttributesHigh << 8 | segmentDes->AttributesLow;
	//AR字段布局(SDM 24.4.1): Type[3:0] S[4] DPL[6:5] P[7] AVL[12]
	//L[13] D/B[14] G[15] Unusable[16], 即 byte0 | byte1<<12
	ULONG attr = ((PUCHAR)&segMentSelector.attributes)[0]
		| ((PUCHAR)&segMentSelector.attributes)[1] << 12;
	if (selector==0)
	{
		attr |= 0x10000;   //unusable(空选择子DS/ES/LDTR)
	}
	__vmx_vmwrite(GUEST_ES_SELECTOR+index*2, segMentSelector.sel);
	__vmx_vmwrite(GUEST_ES_LIMIT + index * 2, segMentSelector.limit);
	__vmx_vmwrite(GUEST_ES_BASE + index * 2, segMentSelector.base);
	__vmx_vmwrite(GUEST_ES_AR_BYTES + index * 2, attr);
}

