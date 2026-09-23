#include"VMX.h"
#include"CPU.h"
#include"reg.h"
#include"common.h"
#include"GeptMsr.h"
#include"GeptApi.h"
#include"Clock.h"
#include"Cr3.h"
#include<intrin.h>

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
	//框架页恒限低区512GB内(EPT恒等区=WB快路径; 超限=自检[5]拒绝vmlaunch)
	phys.QuadPart = 0x7FFFFFFFFF;
	PVMX_VMCS pvmxon = (PVMX_VMCS)MmAllocateContiguousMemory(sizeof(VMX_VMCS), phys);
	PVMX_VMCS pvmcs = (PVMX_VMCS)MmAllocateContiguousMemory(sizeof(VMX_VMCS), phys);
	PVOID MsrBitMap = MmAllocateContiguousMemory(PAGE_SIZE, phys);
	PVOID pvmmStack = MmAllocateContiguousMemory(PAGE_SIZE * 6, phys);
	//I/O位图8KB连续块(A@+0, B@+4K; 全零=全端口直通)
	PVOID pIoBitmaps = MmAllocateContiguousMemory(PAGE_SIZE * 2, phys);
	//私有Host IDT页(v1.11a: 256门×16B, root异常/NMI劫持面封堵)
	PVOID pRootIdt = MmAllocateContiguousMemory(PAGE_SIZE, phys);
	if (pvmmStack == NULL || MsrBitMap == NULL || pvmxon == NULL || pvmcs == NULL
		|| pIoBitmaps == NULL || pRootIdt == NULL)
	{
		//释放已成功的部分, 调用方负责清理
		if (pRootIdt) MmFreeContiguousMemory(pRootIdt);
		if (pIoBitmaps) MmFreeContiguousMemory(pIoBitmaps);
		if (pvmmStack) MmFreeContiguousMemory(pvmmStack);
		if (MsrBitMap) MmFreeContiguousMemory(MsrBitMap);
		if (pvmxon) MmFreeContiguousMemory(pvmxon);
		if (pvmcs) MmFreeContiguousMemory(pvmcs);
		return 1;
	}
	//I/O位图清零(全零=不拦截任何端口直通)
	RtlZeroMemory(pIoBitmaps, PAGE_SIZE * 2);
	RtlZeroMemory(pRootIdt, PAGE_SIZE);
	RtlZeroMemory(pvmxon, sizeof(VMX_VMCS));
	RtlZeroMemory(pvmcs, sizeof(VMX_VMCS));
	RtlZeroMemory(pvmmStack, PAGE_SIZE * 6);
	//MSR位图必须清零: 全零=不拦截任何MSR直通(垃圾位=随机exit+
	//EOI被吞→APIC中断卡死)
	RtlZeroMemory(MsrBitMap, PAGE_SIZE);
	pvmxon->RevisionId = (ULONG)__readmsr(MSR_IA32_VMX_BASIC);
	pvmcs->RevisionId = (ULONG)__readmsr(MSR_IA32_VMX_BASIC);
	g_vcpu[cpuNumber].VMXON = pvmxon;
	g_vcpu[cpuNumber].VMMStack = pvmmStack;
	g_vcpu[cpuNumber].VMCS = pvmcs;
	g_vcpu[cpuNumber].MsrBitMap = MsrBitMap;
	g_vcpu[cpuNumber].IoBitmaps = pIoBitmaps;
	g_vcpu[cpuNumber].RootIdt = pRootIdt;
	g_vcpu[cpuNumber].bInGuest = 0;
	g_vcpu[cpuNumber].bLaunchFailed = 0;
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
	msrValue.QuadPart = __readmsr((ULONG)msrNum);
	return (msrValue.LowPart | controlValue) & msrValue.HighPart;
}

//释放前清零(取证反制): 池释放不改写内容, VMCS revision id/VMXON
//签名/位图布局/EPT表结构在物理内存长存=卸载后可被翻出"曾运行过
//hypervisor"的证据。park守卫已保证无核再用; IPI退出后硬件walker
//也不再访问
static VOID VmxFreeZero(PVOID va, SIZE_T bytes)
{
	if (va != NULL)
	{
		RtlZeroMemory(va, bytes);
	}
}

//PASSIVE_LEVEL释放指定CPU的全部VT资源(DriverUload调用)
void VmxFreeCpuResources(ULONG cpuNumber)
{
	if (g_vcpu[cpuNumber].VMCS)
	{
		VmxFreeZero(g_vcpu[cpuNumber].VMCS, sizeof(VMX_VMCS));
		MmFreeContiguousMemory(g_vcpu[cpuNumber].VMCS);
		g_vcpu[cpuNumber].VMCS = NULL;
	}
	if (g_vcpu[cpuNumber].VMXON)
	{
		VmxFreeZero(g_vcpu[cpuNumber].VMXON, sizeof(VMX_VMCS));
		MmFreeContiguousMemory(g_vcpu[cpuNumber].VMXON);
		g_vcpu[cpuNumber].VMXON = NULL;
	}
	if (g_vcpu[cpuNumber].VMMStack)
	{
		VmxFreeZero(g_vcpu[cpuNumber].VMMStack, PAGE_SIZE * 6);
		MmFreeContiguousMemory(g_vcpu[cpuNumber].VMMStack);
		g_vcpu[cpuNumber].VMMStack = NULL;
	}
	if (g_vcpu[cpuNumber].MsrBitMap)
	{
		VmxFreeZero(g_vcpu[cpuNumber].MsrBitMap, PAGE_SIZE);
		MmFreeContiguousMemory(g_vcpu[cpuNumber].MsrBitMap);
		g_vcpu[cpuNumber].MsrBitMap = NULL;
	}
	if (g_vcpu[cpuNumber].PeptData)
	{
		VmxFreeZero(g_vcpu[cpuNumber].PeptData, sizeof(EPT_DATA));
		MmFreeContiguousMemory(g_vcpu[cpuNumber].PeptData);
		g_vcpu[cpuNumber].PeptData = NULL;
	}
	//hooked视图EPT(内含的拆分pte页不单独跟踪, 随整机生命周期释放)
	if (g_vcpu[cpuNumber].PeptDataHooked)
	{
		VmxFreeZero(g_vcpu[cpuNumber].PeptDataHooked, sizeof(EPT_DATA));
		MmFreeContiguousMemory(g_vcpu[cpuNumber].PeptDataHooked);
		g_vcpu[cpuNumber].PeptDataHooked = NULL;
	}
	//I/O位图8KB块
	if (g_vcpu[cpuNumber].IoBitmaps)
	{
		VmxFreeZero(g_vcpu[cpuNumber].IoBitmaps, PAGE_SIZE * 2);
		MmFreeContiguousMemory(g_vcpu[cpuNumber].IoBitmaps);
		g_vcpu[cpuNumber].IoBitmaps = NULL;
	}
	//私有Host IDT页(v1.11a; 清零后释放=取证反制)
	if (g_vcpu[cpuNumber].RootIdt)
	{
		VmxFreeZero(g_vcpu[cpuNumber].RootIdt, PAGE_SIZE);
		MmFreeContiguousMemory(g_vcpu[cpuNumber].RootIdt);
		g_vcpu[cpuNumber].RootIdt = NULL;
	}
	//释放>512GB动态建立的pdpt页(必须用raw指针: HighPdptVa是4KB对齐后的
	//地址, 不在pool块起始处, 直接ExFreePool会池损坏)
	for (ULONG i = 0; i < 512; i++)
	{
		if (g_vcpu[cpuNumber].HighPdptRawVa[i])
		{
			VmxFreeZero(g_vcpu[cpuNumber].HighPdptRawVa[i], PAGE_SIZE);
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

//0x6E0(TSC_DEADLINE)时间轴换算回调: guest的RDTSC=裸TSC+TSC_OFFSET,
//硬件按裸TSC比较——不换算则定时时刻漂移|offset|且读回值泄漏累计
//驻留时长。读+offset(回读=OS写入值)/写-offset(0=取消, 直通)
static ULONG64 VmxDeadlineOnRead(PVOID Context, ULONG32 Msr)
{
	UNREFERENCED_PARAMETER(Context);
	ULONG64 real = GeptMsrReadReal(Msr);
	if (real == 0)
	{
		return 0;
	}
	ULONG64 off = 0;
	__vmx_vmread(TSC_OFFSET, &off);
	return real + off;
}

static BOOLEAN VmxDeadlineOnWrite(PVOID Context, ULONG32 Msr, ULONG64 Value)
{
	UNREFERENCED_PARAMETER(Context);
	if (Value != 0)
	{
		ULONG64 off = 0;
		__vmx_vmread(TSC_OFFSET, &off);
		Value -= off;    //guest时间轴→裸TSC轴
	}
	__writemsr(Msr, Value);
	return FALSE;   //已代写, 静默(勿再写原值)
}

//PERF_GLOBAL_CTRL guest写同步标志(1=sec-exit bit30缺, 需WRMSR拦截)
static volatile LONG g_perfWrSync = 0;

//hook读透明MTF窗口标记(每核): ept.c切clean+开MTF时置位, MTF exit
//认领后才切回hooked——未被认领的MTF绝不碰EPT_POINTER(视图是核级
//状态, 凭空切=其他上下文执行流错位)
volatile LONG g_hookMtfPending[64] = { 0 };

//0x38F写回调(sec-exit bit30不支持时的兜底): 代写真MSR+同步本核GUEST
//字段(entry恢复的数据源)。PMU配置时才触发=冷路径
static BOOLEAN VmxPerfCtrlOnWrite(PVOID Context, ULONG32 Msr, ULONG64 Value)
{
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(Msr);
	__writemsr(MSR_IA32_PERF_GLOBAL_CTRL, Value);
	__vmx_vmwrite(GUEST_IA32_PERF_GLOBAL_CTRL, Value);
	return FALSE;   //已代写, 静默
}

//全核接管入口(PASSIVE_LEVEL): 资源分配→串行逐核启动VT→互斥仲裁→常驻。
//失败路径已自清理资源, 调用方直接返回即可
NTSTATUS VmxStartAllCpus(_In_ PDRIVER_OBJECT DriverObject)
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

	//v1.12私有Host CR3树构建(全部资源已分配=boot快照集完整, 首个
	//vmlaunch前=Ophion约束)。失败=回退launch CR3(可用性优先), 不致命
	Cr3Init(DriverObject->DriverStart, DriverObject->DriverSize);

	//串行逐核启动(PASSIVE级+亲和性切换), 不用KeGenericCallDpc
	//(DPC全核进DISPATCH级, 线程不可调度)
	FlLog("启动模式: 目标=全部%u核接管", cpuCount);
	KAFFINITY allCpus = KeQueryActiveProcessors();
	for (ULONG i = 0; i < cpuCount; i++)
	{
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
			Cr3Shutdown();      //v1.12私有树(零exit发生=零私有CR3残留)
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
	//框架内置0x6E0时间轴换算: TSC offsetting的伴生自洽(定时时刻不漂移
	//+读回值不泄漏累计驻留)。代价=每核每次定时器编程1次MSR exit
	{
		GEPT_MSR_HOOK dlHook = { 0 };
		dlHook.Msr = MSR_IA32_TSC_DEADLINE;
		dlHook.OnRead = VmxDeadlineOnRead;
		dlHook.OnWrite = VmxDeadlineOnWrite;
		NTSTATUS dlSt = GeptMsrHookInstall(&dlHook);
		FlLog("框架内置0x6E0时间轴换算: %s(读+TSC_OFFSET/写-TSC_OFFSET, 0直通)",
			NT_SUCCESS(dlSt) ? "安装OK" : "安装失败(不影响VT运行, 详见[MSR]行)");
	}
	//TSC校准(全核in-guest确认后, 0x6E0 hook安装前——校准vmcall是
	//空exit, 定时器流量不干扰)
	VmxTscCalibrateAll();
	//PERF_GLOBAL_CTRL写同步兜底(sec-exit bit30缺时): PMU配置是冷路径
	if (g_perfWrSync)
	{
		GEPT_MSR_HOOK perfHook = { 0 };
		perfHook.Msr = MSR_IA32_PERF_GLOBAL_CTRL;
		perfHook.OnWrite = VmxPerfCtrlOnWrite;
		NTSTATUS pfSt = GeptMsrHookInstall(&perfHook);
		FlLog("框架内置0x38F写同步(sec bit30缺, 拦截同步GUEST字段): %s",
			NT_SUCCESS(pfSt) ? "安装OK" : "安装失败(见[MSR]行)");
	}
	//MMIO时钟封堵(v1.8): ACPI发现→校准→逐核布防。TSC轴封堵的伴生
	//自洽——交叉时钟(HPET/PM_TMR)不再泄漏时间轴空洞
	ClkInitAll();
	//放行Desktop镜像(加载窗口期结束)
	FlMarkEntryDone();
	return STATUS_SUCCESS;
}

//TSC校准: guest侧rdtsc(已含TSC_OFFSET)夹逼vmcall(10), 测得值=
//真实往返-asm采样窗口(补偿已生效)=采样点外净泄漏K(硬件VM-exit/
//VM-entry+rdtsc/vmcall指令开销)。K并入每次补偿后guest时延均值≈裸机。
//K偏保守(含指令开销, 非exit场景不产生)——过补风险受控
VOID VmxTscCalibrateAll(VOID)
{
	ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
	KAFFINITY allCpus = KeQueryActiveProcessors();
	for (ULONG i = 0; i < cpuCount; i++)
	{
		if (!g_vcpu[i].bInGuest)
		{
			continue;
		}
		KeSetSystemAffinityThread((KAFFINITY)1 << i);
		//rdtsc对自身开销R(校准循环的固定成本)
		ULONG64 rAcc = 0;
		for (ULONG n = 0; n < 256; n++)
		{
			ULONG64 a = __rdtsc();
			ULONG64 b = __rdtsc();
			rAcc += b - a;
		}
		ULONG64 r = rAcc / 256;
		//vmcall往返均值(K初值0, 测得即纯泄漏)
		ULONG64 acc = 0;
		const ULONG N = 1024;
		for (ULONG n = 0; n < N; n++)
		{
			ULONG64 t0 = __rdtsc();
			CmVmCall(GEPT_VMCALL_TSCCAL, 0, 0, 0);
			ULONG64 t1 = __rdtsc();
			acc += t1 - t0;
		}
		ULONG64 avg = acc / N;
		LONG64 k = (LONG64)(avg > r ? avg - r : 0);
		g_vcpu[i].TscCalibK = k;
		FlLog("cpu%u TSC校准: K=%lld cycles(每exit采样外泄漏, 已并入补偿)",
			i, k);
		FlRingPush('j', i, 0, (ULONG64)k, r, avg);
	}
	KeSetSystemAffinityThread(allCpus);
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
	//2s宽限让被抢占的回调跑完(CallOriginal不碰视图, 只剩replay
	//执行=普通内存访问, 宽限纯为保守)
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
	//驻留偏差量化(偏置信号裁决依据): 累计驻留≈单核exit数×K均值,
	//离线除以(时长×TSC频率)得ppm, 与±20-50ppm晶体容差地板对比——
	//低于地板=与晶体失配不可区分(无归因), 高于=时间轴空洞可积累
	{
		ULONG64 totalExits = 0;
		for (ULONG r = 0; r < GEPT_EXIT_REASON_MAX; r++)
		{
			totalExits += (ULONG64)g_flExitCounts[r];
		}
		LONG64 kAvg = 0;
		ULONG kCores = 0;
		for (ULONG i = 0; i < cpuCount; i++)
		{
			if (g_vcpu[i].TscCalibK > 0)
			{
				kAvg += g_vcpu[i].TscCalibK;
				kCores++;
			}
		}
		if (kCores > 0)
		{
			kAvg /= (LONG64)kCores;
			//单核exit数无分核统计, 用总量/核数上界近似
			ULONG64 perCpu = totalExits / kCores;
			ULONG64 dwellCycles = perCpu * (ULONG64)kAvg;
			FlLog("Unload: 驻留量化(裁决用): 总exit=%llu K均值=%lld cycles/exit "
				"单核估算exit≈%llu 累计驻留≈%llu cycles(离线除以时长×TSC频率得ppm, 地板=±20-50ppm)",
				(unsigned long long)totalExits, kAvg,
				(unsigned long long)perCpu,
				(unsigned long long)dwellCycles);
			FlRingPush('z', KeGetCurrentProcessorNumber(), 0,
				totalExits, (ULONG64)kAvg, dwellCycles);
		}
	}
	FlLog("Unload: VT已关闭, 释放资源");
	//PASSIVE_LEVEL释放全部资源(含EPT_DATA与动态页表)
	for (ULONG i = 0; i < cpuCount; i++)
	{
		VmxFreeCpuResources(i);
	}
	//v1.12私有CR3树(全核vmx_off+GUEST_CR3写回后=root零引用, 释放安全)
	Cr3Shutdown();
	//释放共享高区页表(全部核EPT共用的pdpt, 幂等)
	EptShutdownHighMappings();
	//时钟页IoSpace映射解除(VT已关, 无访存)
	ClkShutdown();
	//API内存(纯pool释放; 此刻hook已移除+VT已关, 无在途引用)
	GeptApiFreeMemory();
	FlLog("Unload: 完成, 关闭文件日志");
	FlShutdown();
}

//park/vmx_off前恢复OS IDT(v1.11b判例修复): exit上下文当前IDTR=
//HOST_IDTR_BASE(私有页)——sidt式GetIdtBase()读到的是私有页而非OS IDT
//(v1.10前host==OS巧合成立, 私有化后broken)。OS基址/limit必须取GUEST_*
//字段(guest=OS本身)。必须在vmx_off之前调用(此后vmread非法)
static void VmxRestoreOsIdtr(void)
{
	UCHAR dtr[10];
	ULONG64 lim = 0, base = 0;
	__vmx_vmread(GUEST_IDTR_LIMIT, &lim);
	__vmx_vmread(GUEST_IDTR_BASE, &base);
	*(USHORT*)dtr = (USHORT)lim;
	*(ULONG64*)(dtr + 2) = base;
	VmxLoadIdtr(dtr);
}

//vmx_off回真机前还原GDTR/IDTR: VM-exit无条件把两limit压成0xFFFF
//(host-state区只有base无limit), 残留=真机sgdt/sidt读到异常值+IDTR
//指私有页。基址/limit全取GUEST_*字段(判例见VmxRestoreOsIdtr注释)。
//必须在vmx_off之前调用(此后vmread非法)
static void VmxRestoreDtrLimits(void)
{
	UCHAR dtr[10];
	ULONG64 lim = 0, base = 0;
	//GDTR
	__vmx_vmread(GUEST_GDTR_LIMIT, &lim);
	__vmx_vmread(GUEST_GDTR_BASE, &base);
	*(USHORT*)dtr = (USHORT)lim;
	*(ULONG64*)(dtr + 2) = base;
	VmxLoadGdtr(dtr);
	//IDTR
	VmxRestoreOsIdtr();
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
//IA32_TSC_DEADLINE不受影响)。仅VMX root上下文可调
void VmxTscCompensate(ULONG64 entryTsc, ULONG64 exitTsc)
{
	if (exitTsc <= entryTsc)
	{
		return;    //rdtsc同值/乱序(理论不可能, 防御)
	}
	ULONG64 offset = 0;
	__vmx_vmread(TSC_OFFSET, &offset);
	//+K: 采样点外的硬件exit/entry净泄漏(VmxTscCalibrateAll, 0=未校准)
	offset -= (exitTsc - entryTsc) +
		(ULONG64)g_vcpu[KeGetCurrentProcessorNumber()].TscCalibK;
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
	ULONG64 msrValue = __readmsr((ULONG)GuestRegs->rcx);
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

//==== RDRAND/RDSEED/INVPCID代执行(v1.10d防御case族) ====
//三个exit在当前控制配置下不可达(RDRAND/RDSEED exiting=0,
//INVPCID exit需INVLPG exiting=1), 此处是must-1位异变的保险:
//落default='U'逃生=vmx_off"诱导后消失"向量。代执行=裸机语义
//(root与guest共CR3共真实硬件, 直接执行等价)。FALSE=解码异常
//(调用方走'U'逃生, 真机重执行=裸机)

//RDRAND/RDSEED(0F C7 /6,/7; 寄存器操作数唯一形态): 解码目标GPR+
//操作数宽, root代执行(asm助手)回填。RFLAGS: CF=成败, 清OF/SF/ZF/AF/PF
static BOOLEAN VmxEmuRdRandFamily(PGUEST_REGS regs, ULONG64 rip,
	ULONG len, BOOLEAN isRdseed)
{
	if (len < 3 || len > 15)
	{
		return FALSE;
	}
	UCHAR code[15];
	RtlCopyMemory(code, (PVOID)rip, len);
	UCHAR* p = code;
	UCHAR* end = code + len;
	BOOLEAN op66 = FALSE;
	UCHAR rex = 0;
	while (p + 3 <= end && (*p == 0x66 || (*p & 0xF0) == 0x40))
	{
		if (*p == 0x66) { op66 = TRUE; }
		else { rex = *p; }
		p++;
	}
	if (p + 3 > end || p[0] != 0x0F || p[1] != 0xC7 || (p[2] >> 6) != 3)
	{
		return FALSE;    //非0F C7 /6-/7寄存器形态
	}
	UCHAR rm = p[2] & 7;
	if (rex & 1)
	{
		rm |= 8;         //REX.B(REX.0100WRXB的bit0)
	}
	ULONG64 val = 0;
	unsigned char ok = isRdseed ? VmxRdSeed64Step(&val)
		: VmxRdRand64Step(&val);
	//回填: REX.W=8字节全宽/默认4字节清高32/66=2字节清高48
	ULONG64 slot = *(PULONG64)((PUCHAR)regs + rm * 8);
	if (rex & 8)          //REX.W(bit3)
	{
		slot = val;
	}
	else if (op66)
	{
		slot = (slot & ~0xFFFFULL) | (val & 0xFFFF);
	}
	else
	{
		slot = (slot & ~0xFFFFFFFFULL) | (val & 0xFFFFFFFF);
	}
	*(PULONG64)((PUCHAR)regs + rm * 8) = slot;
	//RFLAGS: CF/PF/AF/ZF/SF/OF = 0x1|0x4|0x10|0x40|0x80|0x800
	ULONG64 rflags = 0;
	__vmx_vmread(GUEST_RFLAGS, &rflags);
	rflags &= ~0x8D5ULL;
	if (ok)
	{
		rflags |= 1;    //CF=1(熵就绪)
	}
	__vmx_vmwrite(GUEST_RFLAGS, rflags);
	return TRUE;
}

//INVPCID(66 0F 38 82 /r): type=reg源, descriptor=内存操作数。仅支持
//mod=00简单[r]形态(编译器标准输出); 复杂寻址FALSE走'U'逃生。
//root代执行作用真实TLB(无PCID虚拟化)=裸机语义
static BOOLEAN VmxEmuInvpcid(PGUEST_REGS regs, ULONG64 rip, ULONG len)
{
	if (len < 4 || len > 15)
	{
		return FALSE;
	}
	UCHAR code[15];
	RtlCopyMemory(code, (PVOID)rip, len);
	UCHAR* p = code;
	UCHAR* end = code + len;
	while (p + 4 <= end && (*p == 0x66 || (*p & 0xF0) == 0x40))
	{
		p++;
	}
	if (p + 4 > end || p[0] != 0x0F || p[1] != 0x38 || p[2] != 0x82)
	{
		return FALSE;
	}
	UCHAR modrm = p[3];
	UCHAR mod = modrm >> 6;
	UCHAR rm = modrm & 7;
	if (mod != 0 || rm == 4 || rm == 5)
	{
		return FALSE;    //SIB/rip-relative/disp形态不支持(防御路径)
	}
	ULONG64 type = *(PULONG64)((PUCHAR)regs + ((modrm >> 3) & 7) * 8);
	ULONG64 desc = *(PULONG64)((PUCHAR)regs + rm * 8);
	VmxInvpcid(type, (PVOID)desc);
	return TRUE;
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
				//I/O指令(30)豁免: 时钟端口串flicker逐迭代重入(有进展)
				vmexitReason != EXIT_REASON_IO_INSTRUCTION &&
				//MTF(37)豁免: 读透明单步边界事件(HideRead页访问风暴)
				vmexitReason != EXIT_REASON_MTF &&
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
			//EPT hook布防: rdx=原页PFN, r8=CodePagePFN, r9=HideRead
		else if (GuestRegs->rcx == 2)
		{
			EptSetHook(GuestRegs->rdx, GuestRegs->r8, GuestRegs->r9);
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
		//MSR位图原语(GeptMsr安装/移除): rdx=MSR号, r8=bit1:0操作
		//(0=仅读/1=置位/2=清位)+bit8=写位图区。rax=核位掩码(bit i=
		//cpu i该位操作后现值)。位图页已自我隐蔽(改译零页), guest态
		//直写=静默失效; root模式不走EPT直写真页
		else if (GuestRegs->rcx == GEPT_VMCALL_MSRBIT)
		{
			GuestRegs->rax = GeptMsrBitmapOpRoot((ULONG32)GuestRegs->rdx,
				(UCHAR)((GuestRegs->r8 >> 8) & 1),
				(UCHAR)(GuestRegs->r8 & 3));
			FlRingPush('b', KeGetCurrentProcessorNumber(), GEPT_VMCALL_MSRBIT,
				GuestRegs->rdx, GuestRegs->r8, GuestRegs->rax);
		}
			//落地探针首段: 'W'环留痕(VM-entry+EPT取指+exit+RIP推进+
			//vmresume全链路自证), 走通用RIP推进
			else if (GuestRegs->rcx == GEPT_PROBE_MAGIC)
			{
				FlRingPush('W', KeGetCurrentProcessorNumber(), 18,
					guestRip, exitQual, exitCodeLen);
			}
			//TSC校准探针(VmxTscCalibrateAll的往返样本): 空handler走通用
		//RIP推进——asm层TSC补偿照常执行, guest侧夹逼差值即净泄漏
		else if (GuestRegs->rcx == GEPT_VMCALL_TSCCAL)
		{
		}
		//MMIO时钟页布防(ClkInitAll逐核调用): root在当前核两套视图
		//拆页+清RWX+invept(exit上下文arena切槽安全)
		else if (GuestRegs->rcx == GEPT_VMCALL_CLKARM)
		{
			ClkArmCpu();
		}
		//CodePage物理隐蔽(GeptHookInstall/Remove的DPC广播):
		//rdx=CodePage GPA, r8=1隐蔽/0恢复。两套视图都改(扫描可能
		//在任一视图下进行); 仅双EPT核(fallback取指走clean恒等
		//PTE); invept本核生效
		else if (GuestRegs->rcx == GEPT_VMCALL_CPHIDE)
		{
			BOOLEAN cpOk = FALSE;
			ULONG cpuC = KeGetCurrentProcessorNumber();
			if (g_vcpu[cpuC].PeptDataHooked != NULL)
			{
				ULONG64 gpa = GuestRegs->rdx;
				BOOLEAN hide = (GuestRegs->r8 != 0);
				ULONG64 curEptp = 0;
				__vmx_vmread(EPT_POINTER, &curEptp);
				//当前视图(可能是clean或hooked)
				cpOk = EptHideCodePageGpa(gpa, hide);
				//另一视图: 临时切换EPTP做完再切回
				ULONG64 other = (curEptp == g_vcpu[cpuC].Eptp.ALL)
					? g_vcpu[cpuC].EptpHooked.ALL : g_vcpu[cpuC].Eptp.ALL;
				__vmx_vmwrite(EPT_POINTER, other);
				if (!EptHideCodePageGpa(gpa, hide))
				{
					cpOk = FALSE;
				}
				__vmx_vmwrite(EPT_POINTER, curEptp);
				EptInveptCurrent();
			}
			GuestRegs->rax = cpOk ? 1 : 0;
			FlRingPush('c', cpuC, GEPT_VMCALL_CPHIDE,
				GuestRegs->rdx, GuestRegs->r8, cpOk ? 1 : 0);
		}
		//私有CR3树protect(v1.12, root执行): rdx=VA r8=len。深拷贝该
		//区间页表路径+sync-on-alloc(新分配在私有区可见); 池耗尽→
		//fallback共享(区不保护但可用)。树全局单份, 单核执行即可,
		//其余核下次exit的PCID0全刷自愈
		else if (GuestRegs->rcx == GEPT_VMCALL_PTPROT)
		{
			BOOLEAN ptOk = Cr3ProtectRoot(GuestRegs->rdx, GuestRegs->r8);
			GuestRegs->rax = ptOk ? 1 : 0;
			FlRingPush('K', KeGetCurrentProcessorNumber(),
				GEPT_VMCALL_PTPROT, GuestRegs->rdx, GuestRegs->r8,
				ptOk ? 1 : 0);
		}
		//探针末段: KEEP(接管)放行, 通用RIP推进, 探针恢复栈回non-root
		else if (GuestRegs->rcx == 3)
		{
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
	//=============== 防御case族(56-81; v1.10d审计) ===============
	//当前控制配置下不可达, 纯must-1位异变保险; 落default='U'逃生=
	//vmx_off"诱导后消失"向量。语义按裸机(详见VMX.h逐条注释)
	case EXIT_REASON_RDRAND:   //57
	{
		if (!VmxEmuRdRandFamily(GuestRegs, guestRip, (ULONG)exitCodeLen, FALSE))
		{
			VmxExitStormEscape('U', vmexitReason, guestRip, exitQual, GuestRegs);
		}
	}
	break;
	case EXIT_REASON_RDSEED:   //61
	{
		if (!VmxEmuRdRandFamily(GuestRegs, guestRip, (ULONG)exitCodeLen, TRUE))
		{
			VmxExitStormEscape('U', vmexitReason, guestRip, exitQual, GuestRegs);
		}
	}
	break;
	case EXIT_REASON_INVPCID:   //58
	{
		if (!VmxEmuInvpcid(GuestRegs, guestRip, (ULONG)exitCodeLen))
		{
			VmxExitStormEscape('U', vmexitReason, guestRip, exitQual, GuestRegs);
		}
	}
	break;
	case EXIT_REASON_UMWAIT:   //67
	case EXIT_REASON_TPAUSE:   //68
	{
		//"已到deadline立即返回"形态: CF=1, 清AF/PF/SF/ZF/OF(bit26
		//修复后不可达, 纯防御; root代等待会占核, 不做)
		ULONG64 wflags = 0;
		__vmx_vmread(GUEST_RFLAGS, &wflags);
		wflags &= ~0x8D4ULL;
		wflags |= 1;              //CF=1
		__vmx_vmwrite(GUEST_RFLAGS, wflags);
	}
	break;
	case EXIT_REASON_RDMSRLIST:   //78
	case EXIT_REASON_WRMSRLIST:   //79
	{
		//跳过整条(SDM: 单MSR exit时对应RCX位不清=该项未读——跳过=
		//全list未处理的保守忠实形态; 纯防御路径)
	}
	break;
	case EXIT_REASON_ENCLS:   //60: ENCLS exiting=0+bitmap全0双保险不可达
	case EXIT_REASON_SEAMCALL:   //76: 非TDX平台裸机语义
	case EXIT_REASON_TDCALL:   //77: 同上
	{
		VmxInjectUd(KeGetCurrentProcessorNumber(), vmexitReason, guestRip);
		__vmx_vmwrite(GUEST_RIP, guestRip);
		return;
	}
	case EXIT_REASON_URDMSR:   //80: OS默认禁user-MSR的裸机形态
	case EXIT_REASON_UWRMSR:   //81: 同上
	{
		VmxInjectGp(KeGetCurrentProcessorNumber(), vmexitReason, guestRip);
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
	case EXIT_REASON_IO_INSTRUCTION:   //30
	{
		//端口时钟(Clock.c, I/O位图仅时钟位置位): 标量IN=真值+
		//TSC_OFFSET/Ratio补偿/OUT直写; 串INS/OUTS=flicker(清位放行
		//单迭代+MTF回捕重置位), 不推进RIP重执行
		if (ClkIoTryEmulate(GuestRegs, exitQual))
		{
			break;    //已仿真: 走尾部通用RIP推进
		}
		__vmx_vmwrite(GUEST_RIP, guestRip);
		return;
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
			__writemsr((ULONG)GuestRegs->rcx, msrVal);
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
		//ctls2 bit13=0下guest执行vmfunc按SDM应#UD(硬件), 本case为
		//兜底(若CPU语义为exit则注入#UD)——与裸机逐位一致。异常在
		//本指令派发, 不推RIP(return早退绕过尾部通用推进)
		VmxInjectUd(KeGetCurrentProcessorNumber(), 59, guestRip);
		FlRingPush('u', KeGetCurrentProcessorNumber(), 59,
			guestRip, exitQual, exitCodeLen);
		return;
	}
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
		case EXIT_REASON_MTF:
	{
		//时钟flicker回捕(优先): 指令已执行完, 重封堵+关MTF——
		//无视图切换(时钟陷阱与hook视图正交, 两套视图都已布防)
		if (ClkMtfFinish())
		{
			__vmx_vmwrite(GUEST_RIP, guestRip);
			return;
		}
		//hook读透明回捕(认领制): ept.c置位方才切回hooked。非本路径
		//的MTF只关标志不动视图——凭空切EPT_POINTER=视图错乱源
		ULONG cpuM = KeGetCurrentProcessorNumber();
		if (InterlockedExchange(&g_hookMtfPending[cpuM & 63], 0))
		{
			if (g_vcpu[cpuM].PeptDataHooked != NULL)
			{
				__vmx_vmwrite(EPT_POINTER, g_vcpu[cpuM].EptpHooked.ALL);
			}
		}
		//关MTF。RIP已是下一条指令; MTF exit的指令长字段无效, 显式
		//重写绕过尾部通用推进(exitCodeLen残留值=执行流错位)
		ULONG64 mtfCtl = 0;
		__vmx_vmread(CPU_BASED_VM_EXEC_CONTROL, &mtfCtl);
		__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, mtfCtl & ~0x08000000ULL);
		__vmx_vmwrite(GUEST_RIP, guestRip);
		return;
	}
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
	//恢复OS IDT(v1.11b判例: exit上下文IDTR=私有页——vmx_off后的
	//sti+hlt窗口要正常服务中断, 必须先指回OS IDT)
	VmxRestoreOsIdtr();
	//CR3恢复(v1.12, 判例同卸载路径/风暴逃生): exit上下文CR3=HOST_CR3
	//(私有PML4)——park的sti+hlt窗口要跑OS ISR, 必须先回OS页表;
	//vmread须在vmx_off前(此后非法)
	ULONG64 parkCr3 = 0;
	__vmx_vmread(GUEST_CR3, &parkCr3);
	//脱离VMX(exit上下文, host状态合法)
	EptInveptBothViews();
	__vmx_off();
	ULONG64 cr4 = __readcr4();
	cr4 &= ~0x2000;                               //清CR4.VMXE, 干净回真机
	__writecr4(cr4);
	__writecr3(parkCr3);                          //回OS页表(裸机等价)
	g_vcpu[cpu].bVmxOn = 0;
	g_vcpu[cpu].bInGuest = 0;
	g_vcpu[cpu].bLaunchFailed = 1;                //卸载路径跳过本核vmcall
	//park位掩码(VmxShutdownAllCpus卸载守卫): park核的VMM栈/park代码页不能释放
	InterlockedOr(&g_geptParkedMask, (LONG)(1UL << (cpu & 31)));
	//park本体(asm, 永不返回): sti+hlt自旋持续服务中断, 切断级联冻结
	CmTripleFaultPark();
}

//root异常/NMI park(v1.11a私有Host IDT, 永不返回): 256门全指VmxRootExceptStub
//→此函数。语义=可用性换安全: root窗口内异常/NMI不再跑OS处理程序
//(guest可改的门向量=root特权劫持向量, SDM 30.5.2: exit加载HOST_IDTR_
//BASE且limit压0xFFFF), 改为park本核+黑匣子留痕——每次到达都是该修的
//bug或一次攻击, 都该被看见。清债序复用VmxTripleFaultPark骨架
//(rsn=0x1000=异常标记; b=GUEST_REGS帧首地址即r15, a=errcode, c=故障RIP)
void VmxRootFaultPark(ULONG64 rsn, ULONG64 errcode, ULONG64 faultRip,
	ULONG64 faultCs)
{
	ULONG cpu = KeGetCurrentProcessorNumber();
	FlRingPush('I', cpu, 0x1000, errcode, faultRip, faultCs);
	//恢复OS IDT(v1.11b判例: exit上下文GetIdtBase()=私有页, 须vmread
	//GUEST_IDTR_BASE; vmx_off后的sti+hlt窗口要正常服务中断)
	VmxRestoreOsIdtr();
	//清in-service中断债(同VmxTripleFaultPark)
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
	//CR3恢复(v1.12, 同VmxTripleFaultPark): park的sti+hlt窗口要跑OS
	//ISR, vmx_off前vmread GUEST_CR3、vmx_off后写回
	ULONG64 parkCr3 = 0;
	__vmx_vmread(GUEST_CR3, &parkCr3);
	//脱离VMX(exit上下文, host状态合法)
	EptInveptBothViews();
	__vmx_off();
	ULONG64 cr4 = __readcr4();
	cr4 &= ~0x2000;                               //清CR4.VMXE, 干净回真机
	__writecr4(cr4);
	__writecr3(parkCr3);                          //回OS页表(裸机等价)
	g_vcpu[cpu].bVmxOn = 0;
	g_vcpu[cpu].bInGuest = 0;
	g_vcpu[cpu].bLaunchFailed = 1;                //卸载路径跳过本核vmcall
	//park位掩码(卸载守卫): park核的VMM栈/park代码页/私有IDT页不能释放
	InterlockedOr(&g_geptParkedMask, (LONG)(1UL << (cpu & 31)));
	//park本体(asm, 永不返回)
	CmTripleFaultPark();
}

//构建私有Host IDT(v1.11a): 256门×16B=4KB整页, 全指VmxRootExceptStub。
//64位中断门格式: offLo16|sel16|IST5|type14(0x8E=中断门DPL0)|offHi32。
//IST=0(不读TSS.IST=链B顺带封堵), DPL=0(root态CPL0可入)。门2=NMI
//(pin bit3=0下root窗口内NMI经HOST IDT向量, Table 27-5)。页在
//VMXInitCpuAlloc分配(连续物理, EPT隐蔽/自检[5]样本接入)
static BOOLEAN VmxRootIdtBuild(ULONG cpuNumber)
{
	PVOID idt = g_vcpu[cpuNumber].RootIdt;
	if (idt == NULL)
	{
		return FALSE;
	}
	USHORT cs = RegGetCs() & 0xFFF8;
	for (ULONG v = 0; v < 256; v++)
	{
		PULONG64 gate = (PULONG64)((PUCHAR)idt + v * 16);
		ULONG64 off = (ULONG64)(ULONG_PTR)VmxRootExceptStub;
		gate[0] = (off & 0xFFFFULL)
			| ((ULONG64)cs << 16)
			| ((ULONG64)0x8E << 40);          //type=1110 DPL=0 P=1 IST=0
		gate[1] = off >> 16;
	}
	return TRUE;
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
	//v1.12私有Host CR3(链D封堵): root运行于私有PML4——VMM区深拷贝
	//(隔离)+guest世界浅拷贝(裸机等价)+用户半区清零。树未就绪→
	//回退launch线程CR3(可用性优先, 同RootIdt回退模式)。PCID位=0
	//(4K对齐, SDM 29.2.2合法; exit加载bit63被忽略=每次全刷, 与
	//现状同成本——'z'驻留判据不回归)
	if (Cr3PrivatePa() != 0)
	{
		__vmx_vmwrite(HOST_CR3, Cr3PrivatePa());
		ULONG64 cr3Back = 0;
		__vmx_vmread(HOST_CR3, &cr3Back);
		FlLog("cpu%u 私有Host CR3: PML4=%llX(回读=%llX%s) 深拷贝PT=%u区 "
			"大页区=%u——root页表隔离生效",
			cpuNumber, (unsigned long long)Cr3PrivatePa(),
			(unsigned long long)cr3Back,
			cr3Back == Cr3PrivatePa() ? "" : " !回读不一致!",
			Cr3DeepPtCount(), Cr3LargePdCount());
	}
	else
	{
		__vmx_vmwrite(HOST_CR3, __readcr3());
		FlLog("cpu%u 私有Host CR3未就绪, 回退launch CR3=%llX(链D未封)",
			cpuNumber, (unsigned long long)__readcr3());
	}
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
	//v1.11a私有Host IDT: HOST_IDTR_BASE指私有页(256门全指VmxRootExceptStub),
	//root窗口内异常/NMI不再经guest可改的OS IDT门向量(劫持链A封堵;
	//IST=0不读TSS=链B顺带封堵)。门构建失败回退OS IDT(可用性优先)
	if (VmxRootIdtBuild(cpuNumber))
	{
		__vmx_vmwrite(HOST_IDTR_BASE, currentCpu->RootIdt);
		ULONG64 idtrBack = 0;
		__vmx_vmread(HOST_IDTR_BASE, &idtrBack);
		FlLog("cpu%u 私有Host IDT: VA=%llX 门=256→stub(回读=%llX%s)",
			cpuNumber, (ULONG64)(ULONG_PTR)currentCpu->RootIdt, idtrBack,
			idtrBack == (ULONG64)(ULONG_PTR)currentCpu->RootIdt
				? "" : " !回读不一致!");
	}
	else
	{
		__vmx_vmwrite(HOST_IDTR_BASE, GetIdtBase());
		FlLog("cpu%u 私有Host IDT构建失败, 回退OS IDT(劫持面未封)", cpuNumber);
	}
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
				(unsigned long long)__readmsr((ULONG)pinMsr),
				(unsigned long long)__readmsr((ULONG)procMsr),
				(unsigned long long)__readmsr((ULONG)exitMsrNum),
				(unsigned long long)__readmsr((ULONG)entryMsrNum),
				useTrueCtl ? "TRUE MSR" : "旧式MSR");
			FlLog("MSR原值: SEC(48Bh)=%llX EPT_VPID_CAP(48Ch)=%llX",
				(unsigned long long)__readmsr(MSR_IA32_VMX_PROCBASED_CTLS2),
				(unsigned long long)__readmsr(MSR_IA32_VMX_EPT_VPID_CAP));
		}
	}
	//pin期望=0(外部中断直投guest)
	ULONG pinCtl   = VmxMsrAdjuest(pinMsr, 0);
	//proc: bit3=TSC offsetting(补偿硬件基础), bit12保持0(RDTSC直通),
	//bit25(I/O位图)/bit28(MSR位图)/bit31(secondary)必需——位图全零=
	//全端口直通, 零行为差; 时钟端口位由ClkArmCpu(vmcall 11 root侧)置位
	ULONG procCtl  = VmxMsrAdjuest(procMsr,
		0X8 | 0X10000000 | 0X80000000 | 0X02000000);
	//entryCtl: bit9(IA-32e)+bit2(load debug: DR7/DEBUGCTL重载=写读一致)
	//+bit13(load PERF_GLOBAL_CTRL: exit停表后guest恢复)+bit17/18(conceal
	//PT/load RTIT: 与sec-exit配对)。老CPU不允许的位被能力MSR自动清
	ULONG entryCtl = VmxMsrAdjuest(entryMsrNum,
		0x200 | 0x4 | 0x2000 | 0x20000 | 0x40000);
	//exitCtl: bit9+bit2(save debug)+bit12(load PERF_GLOBAL_CTRL: HOST
	//字段=0→root期间全局停表, guest的PMC不再计入root指令)+bit31
	//(activate secondary exit)。bit12与entry bit13成对(只开exit侧=
	//guest的PMU被exit吃掉=更强暴露)
	ULONG exitCtl  = VmxMsrAdjuest(exitMsrNum, 0x200 | 0x4 | 0x1000
		| ((entryCtl & 0x2000) ? 0x80000000 : 0));
	if (!(entryCtl & 0x2000))
	{
		exitCtl &= ~0x1000;    //entry恢复不支持=停表侧一并退(成对原则)
	}
	//secondary exit(0x493能力, 老CPU无此MSR→bit31被清→全退化):
	//bit25 clear IA32_RTIT_CTL(root分支不进PT数据流)+bit24 conceal
	//VMX from PT(exit不产PIP包)+bit30 save PERF_GLOBAL_CTL(exit自动
	//存guest值→免WRMSR拦截同步)
	ULONG secExitCtl = 0;
	if (exitCtl & 0x80000000)
	{
		secExitCtl = VmxMsrAdjuest(MSR_IA32_VMX_EXIT_CTLS2,
			0x40000000 | 0x2000000 | 0x1000000);
		//sec bit30缺=PERF guest字段需WRMSR拦截同步(冷路径, 见
		//VmxPerfCtrlOnWrite); 任一核缺即全局装(标志)
		if ((entryCtl & 0x2000) && !(secExitCtl & 0x40000000))
		{
			g_perfWrSync = 1;
		}
	}
	//控制字段留痕(proc的bit3=0=极老CPU, TSC补偿自动降级)
	FlLog("cpu%u 控制字段(直投+TSCoff+调试/PMU透明): pin=%08X proc=%08X exit=%08X entry=%08X secExit=%08X",
		cpuNumber, pinCtl, procCtl, exitCtl, entryCtl, secExitCtl);
	__vmx_vmwrite(VM_ENTRY_CONTROLS, entryCtl);
	__vmx_vmwrite(VM_EXIT_CONTROLS, exitCtl);
	if (exitCtl & 0x80000000)
	{
		__vmx_vmwrite(SECONDARY_VM_EXIT_CONTROLS, secExitCtl);
	}
	__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, pinCtl);
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, procCtl);
	//PMU/PT封堵字段(存在性按控制位动态判, 不存在而写=VMfail):
	//HOST PERF=0(root停表)/GUEST PERF=真值(entry恢复)/GUEST RTIT=真值
	if (exitCtl & 0x1000)
	{
		__vmx_vmwrite(HOST_IA32_PERF_GLOBAL_CTRL, 0);
	}
	if (entryCtl & 0x2000)
	{
		ULONG64 perfInit = 0;
		__try { perfInit = __readmsr(MSR_IA32_PERF_GLOBAL_CTRL); }
		__except (EXCEPTION_EXECUTE_HANDLER) { }
		__vmx_vmwrite(GUEST_IA32_PERF_GLOBAL_CTRL, perfInit);
	}
	if ((entryCtl & 0x40000) || (secExitCtl & 0x2000000))
	{
		ULONG64 rtitInit = 0;
		__try { rtitInit = __readmsr(MSR_IA32_RTIT_CTL); }
		__except (EXCEPTION_EXECUTE_HANDLER) { }
		__vmx_vmwrite(GUEST_IA32_RTIT_CTL, rtitInit);
	}
	//TSC_OFFSET初始0, 此后VmxTscCompensate单调向负推
	__vmx_vmwrite(TSC_OFFSET, 0);
	PHYSICAL_ADDRESS msrPhyAddr = MmGetPhysicalAddress(currentCpu->MsrBitMap);
	__vmx_vmwrite(MSR_BITMAP, msrPhyAddr.QuadPart);
	//I/O位图接线(A@+0/B@+4K; procCtl bit25置位后生效, 全零=全直通)
	if (currentCpu->IoBitmaps != NULL)
	{
		PHYSICAL_ADDRESS ioPhyA = MmGetPhysicalAddress(currentCpu->IoBitmaps);
		__vmx_vmwrite(IO_BITMAP_A, ioPhyA.QuadPart);
		__vmx_vmwrite(IO_BITMAP_B, ioPhyA.QuadPart + PAGE_SIZE);
	}
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
		//bit26(user wait and pause) bit27(PCONFIG)——后两个是"=0则#UD"型
		//(SDM Table 27-7): 不开则WAITPKG CPU(12代+)上guest的UMWAIT/
		//UMONITOR/TPAUSE/PCONFIG被硬件#UD(CPUID透传真值→OS真用)——内核
		//意外#UD蓝屏+裸机行为差双重暴露; 开=原生执行零exit(裸机一致)。
		//老CPU能力MSR自动清位零影响。VMFUNC(bit13)不开——guest执行
		//vmfunc=#UD与裸机一致(探测面封堵: 裸机必#UD的指令成功零exit=
		//hypervisor铁证+可篡改双视图)。视图切换全走root侧vmwrite
		//EPT_POINTER, 双EPT引擎不依赖VMFUNC
		ULONG64 ctls2Value = VmxMsrAdjuest(MSR_IA32_VMX_PROCBASED_CTLS2,
			0x2 | 0x8 | 0x1000 | 0x100000 | 0x4000000 | 0x8000000);
		__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, ctls2Value);
		__vmx_vmwrite(EPT_POINTER, g_vcpu[cpuNumber].Eptp.ALL);
		FlLog("cpu%u ctls2=%llX (期望0C10100A=EPT+rdtscp+invpcid+xsaves+userwait+pconfig, 无VPID/VMFUNC)",
			cpuNumber, (unsigned long long)ctls2Value);
		if (g_vcpu[cpuNumber].PeptDataHooked != NULL)
		{
			FlLog("cpu%u 双EPT引擎: hooked EPTP=%llX(切换=root vmwrite, VMFUNC指令已禁用)",
				cpuNumber, (unsigned long long)g_vcpu[cpuNumber].EptpHooked.ALL);
		}
		else
		{
			FlLog("cpu%u hooked EPT未就绪(深拷贝失败)——hook走violation方案",
				cpuNumber);
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
	//EPT自我隐蔽(须在verify后: 拆2M破坏verify[4]全2M恒等走查;
	//此刻全部核资源已分配, 本核两视图把框架私有页改译零页)
	EptHideFrameworkPages(cpuNumber);
	FlLog("cpu%u vmlaunch前自检: EPT=PASS EPTP=%llX 探针VA=%llX 模式=KEEP(接管)",
		cpuNumber,
		(unsigned long long)g_vcpu[cpuNumber].Eptp.ALL,
		(unsigned long long)(ULONG_PTR)CmGuestProbe);
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

