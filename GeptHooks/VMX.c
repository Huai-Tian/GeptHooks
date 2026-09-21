#include"VMX.h"
#include"CPU.h"
#include"reg.h"
#include"common.h"
#include"GeptMsr.h"
#include<intrin.h>

//注意: 运行模式开关GEPT_PROBE_EXIT/GEPT_LAUNCH_CPU_LIMIT/BASE在common.h
//(main.c启动循环也要用)——勿在此重复#define(会覆盖其值)!
//
//本文件的关键设计裁决(全文索引, 详见各处注释):
//  - 中断直投: pin期望=0+无ack-on-exit——中断在non-root直接经guest IDT
//    交付ISR, EOI直写真LAPIC, VMM零参与。绝不开启"ext-int exiting+
//    ack-on-exit+注入状态机": ack-on-exit把中断从IRR移进物理LAPIC ISR,
//    注入回guest的只是VM-entry事件, guest ISR的EOI管不到物理LAPIC→
//    ISR位永不清→时钟中断永久阻塞→整机静默冻结; 且该状态机=重写半个
//    虚拟APIC(EOI债/窗口位/优先级/多核竞争), 漏一项=间歇性冻结
//    (HyperPlatform/hvpp/SimpleVisor/HyperDbg/TinyVT五项目全部直投)
//  - ctls2指令许可位(rdtscp/xsaves/invpcid): 内核启动时CPUID检出指令
//    可用→选定路径; non-root下未开许可位→执行即#UD→蓝屏/静默冻结
//  - vmx_off回真机三件套: 恢复非易失GPR(VmxJumGuestRegs)+还原GDTR/
//    IDTR limit(VM-exit强制0xFFFF)+写回GUEST_CR3(HOST_CR3=System DTB
//    残留→同进程线程继承错误页表→用户VA访问蓝屏0x50)
//  - 逃生机制(VmxExitStormEscape): 不可解exit=vmx_off回真机重执行,
//    绝不停核(IF=0停核=IPI永不处理=全机级联冻结)

VCPU g_vcpu[128];
//段AR指纹(CS/TR最终写入VMCS的值), 供vmlaunch前指纹日志行——
//每次测试先看指纹行确认跑的是新编译的sys
static volatile ULONG g_dbgCsAr = 0;
static volatile ULONG g_dbgTrAr = 0;

PVCPU VmxGetCurrentVcpu(ULONG cpuNumber)
{
	return &g_vcpu[cpuNumber];
}
//PASSIVE_LEVEL预分配: DriverEntry里调用.
//绝不能在DPC(DISPATCH_LEVEL)里做MmAllocateContiguousMemory:
//文档要求IRQL<=APC_LEVEL, 且每核2MB连续内存搜索在系统碎片化后
//会让所有核的DPC同时自旋等待 -> 整机冻结(无蓝屏)
int VMXInitCpuAlloc(ULONG cpuNumber)
{
	PHYSICAL_ADDRESS phys = { 0 };
	phys.QuadPart = MAXULONG64;
	PVMX_VMCS pvmxon = (PVMX_VMCS)MmAllocateContiguousMemory(sizeof(VMX_VMCS), phys);
	PVMX_VMCS pvmcs = (PVMX_VMCS)MmAllocateContiguousMemory(sizeof(VMX_VMCS), phys);
	PVOID MsrBitMap = MmAllocateContiguousMemory(PAGE_SIZE, phys);
	PVOID pvmmStack = MmAllocateContiguousMemory(PAGE_SIZE * 6, phys);
	//EPTP-list页(VMFUNC EPTP switching用)。SDM要求4KB对齐
	//(MmAllocateContiguousMemory天然满足)+物理连续。内容在VmxSetupVmcs
	//里填(Eptp此刻尚未就绪): list[0]=clean/list[1]=hooked
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
	//MSR位图必须清零! CPU_BASED启用了"use MSR bitmaps"(bit28), 垃圾位图
	//=随机MSR触发exit; 且exit handler缺WRMSR case会静默丢弃写——
	//x2APIC系统的EOI(WRMSR 0x80B)被吞 → APIC中断卡死 → 整机冻结无蓝屏。
	//全零位图=不拦截任何MSR, guest直接访问, 零exit零风险
	RtlZeroMemory(MsrBitMap, PAGE_SIZE);
	//EPTP-list清零: 未用项(idx2-511)保持全0, guest误切到无效索引时VMFUNC
	//按SDM语义VMfail(#UD)而非静默翻译到物理0——预留安全失败模式
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

//串行模式(亲和性切换到目标核, PASSIVE_LEVEL): vmxon -> vmclear/vmptrld -> 填VMCS -> vmlaunch
//每步FlLog面包屑同步落盘Temp: 冻结时文件最后一行即精确卡点
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
	//__vmx_on加SEH——三种#GP来源全覆盖:
	//  ①同框架宿主已在场: 我们的vmxon在宿主guest内→宿主case27注入
	//    #GP(0)(BIOS锁VT故事)→SEH捕获→干净失败→main.c全败汇总
	//    =VT-x原生互斥仲裁闭环
	//  ②裸机0x3A锁定(锁+VMX禁用)机器: 真vmxon本就#GP(0)(SDM),
	//    CommCheckBios正常会先拦截, 此为防御纵深
	//  ③异常绝不逃逸(内核态未处理异常=蓝屏0x7E)
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
	//关写盘护卫——CmGuestRsp()返回=所有路径的汇合点: KEEP续跑/'K'退出/
	//'G'逃生/VMfail。T1在≤1ms内补写护卫期间积压的全部行
	g_flWriteGuard = 0;
	if (!g_vcpu[cpuNumber].bLaunchFailed)
	{
		g_vcpu[cpuNumber].bInGuest = 1;
		//'Q'环事件=guest回到VMXInitCpuStart续跑的精确标记
		//(探针四段+栈恢复+ret全链路通过, 且此刻IF=0)
		FlRingPush('Q', cpuNumber, 0, 0, 0, 0);
		//KEEP检查点(**sti之前, IF=0下自旋等待安全**)——强制T1把探针
		//事件全部落盘, 然后才进入直投世界。cli窗口内到达的中断安然
		//留在LAPIC IRR(不被ack), sti后硬件自行投递, 零丢失零状态机
		FlLogSpin("cpu%u KEEP检查点(中断直投): pin=0无队列无注入, 即将sti——IRR积压中断由硬件直投guest ISR",
			cpuNumber);
	}
	//恢复IF: 'K'/'G'路径guest原IF=0跳过了自己的sti, 全靠这一行恢复;
	//cli窗内到达的中断在LAPIC IRR排队, sti后硬件直接投递guest ISR。
	//必须在任何FlLog之前(IF=0下其等待会永久睡眠)
	_enable();
	if (!g_vcpu[cpuNumber].bLaunchFailed)
	{
		//此日志在non-root下打印(EPT翻译, 对OS透明)。看到它=该核
		//vmlaunch+探针+栈恢复全通过, 且**本行之后的OS执行全部发生在
		//EPT之下**——本行是接管边界的精确标记
		FlLog("cpu%u vmlaunch成功, 已进入guest(接管: 此后本核OS运行于EPT之下)", cpuNumber);
	}
	else
	{
		//bLaunchFailed有三来源——①vmlaunch直接VMfail(错误码见上一条)
		//②EPT自检失败放弃 ③探针probe-exit完成(自测模式正常路径:
		//guest两段vmcall后vmx_off回真机, 本核已干净脱离VT)
		FlLog("cpu%u vmlaunch失败或probe-exit完成(判读: [W][K]标记=自测通过; 错误码行=VMfail), 本核已回真机", cpuNumber);
	}
	//'f'环事件=launch窗口完成标记(与'F'配对); 同时熄灭T1热轮询
	FlRingPush('f', cpuNumber, 0, 0, 0, 0);
	g_flLaunchHot = 0;
	return 0;
}

//串行模式(亲和性切换到目标核, PASSIVE_LEVEL)逐核退出VT。
//**主卸载路径已退役**(改KeIpiGenericCall全核原子退出, 见
//VmxStopAllIpi——DISPATCH_LEVEL下KeSetSystemAffinityThread不迁移
//运行中的线程, 串行迁移方案在该IRQL下结构性失效)。本函数仅剩
//调用方=DriverEntry全败汇总路径(junior形态: 全核vmxon失败bVmxOn=0,
//空转打印"未启用VT"——防御性保留)
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

//全核IPI原子退出(KeIpiGenericCall广播处理程序, 每核各执行一次含
//发起核; DriverUload在PASSIVE调用)。
//为什么必须是IPI: IPI_LEVEL(高于DISPATCH)处理程序内**零调度零线程**,
//每核原子完成"vmcall(1)退出(exit handler: invept+CR3写回+'r'环+冲A)
//→清VMXE→PGE冲B"——IPI返回后各核VT已关死+TLB已冲空, 被打断线程
//与后续一切进程切换基于空TLB从零重建=调度暴露窗构造性为0(不依赖
//冲刷时机的运气, 不依赖线程迁移)。串行逐核方案在此有两个已实证的
//死法: ①FlLog睡眠窗内调度器切入其他进程线程→TLB跨进程污染蓝屏
//0x50 ②DISPATCH级下线程不迁移→只退1核→释放其余核正在用的
//VMCS/EPT=双重故障0x7F
//IPI上下文纪律: 绝不FlLog/FlLogSpin(T1也被IPI打断, 任何等待=死锁)
//绝不睡眠——只FlRingPush(无锁环, 任意IRQL安全, T1稍后落盘)
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
	//冲刷B(每核, VMXE清后, IPI收尾前): PGE翻转冲空本核一切翻译——
	//EPT运行期间的EPTP-tagged条目+普通条目+IPI处理期间积累条目全部
	//作废(SDM: 改PGE的MOV CR4冲全部TLB条目含全局页)。与exit handler
	//内冲A双保险: A护vmx_off瞬间, B护IPI结束瞬间(两者间无任何调度,
	//B覆盖一切); IPI返回后被打断线程/后续任何切换从零重建=零污染
	{
		ULONG64 cr4Full = __readcr4();
		__writecr4(cr4Full & ~0x80ULL);   //PGE=0(冲含全局页)
		__writecr4(cr4Full);              //PGE=1(恢复, 再冲)
	}
	//环'v'留痕: a=本核是否曾in-guest, b=bVmxOn终值(应0)
	FlRingPush('v', cpu, 0, wasInGuest, g_vcpu[cpu].bVmxOn, 0);
	return 0;
}

//控制字段计算。SDM Appendix A.3原文语义:
//  "Bits 31:0 indicate the allowed 0-settings ... VM entry allows control X
//   to be 0 if bit X in the MSR is CLEARED to 0; if bit X in the MSR is
//   SET to 1, VM entry fails if control X is 0."
//即: 能力MSR低32位**置1的位=控制位必须为1**, 清零的位才允许为0; 高32位=
//允许为1的位。新旧MSR位语义相同(旧式0x481-0x484对default1类位恒读1,
//TRUE MSR 0x48D-0x490如实上报——两者唯一区别), 经典公式
//(低32|期望) & 高32 对新旧MSR都正确。
//**勿用补码公式**(~低32=把允许掩码全开): TPR shadow/I/O位图/
//NMI-window等控制位会因一致性检查失败→VM-entry错误码7
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

//vmx_off回真机前还原GDTR/IDTR limit(卸载vmcall/逃生两处共用)。
//VM-exit无条件把两个limit压成0xFFFF(SDM 27.5: host-state区只有base
//无limit字段), KEEP期间root模式带0xFFFF跑无害(guest向量全在0xFFF内),
//但vmx_off跳回真机后残留=后续内核/驱动sgdt/sidt读到异常limit。
//base不用动(host-state=launch时写的原值)。**必须在vmx_off之前调用**
//(退出VMX operation后vmread非法)。limit来源=GUEST_GDTR/IDTR_LIMIT
//(guest状态在KEEP期间未被改动, 恒等于launch时快照=真机正确值)。
//描述符布局: WORD limit@+0, QWORD base@+2(reg.asm sgdt读侧同款,
//WDK DESCRIPTOR64 pack(2)格式, 10字节)
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
	int cpuinfo[4] = { 0 };
	__cpuidex(cpuinfo, (int)GuestRegs->rax, (int)GuestRegs->rcx);
	//CPUID输入leaf取低32位(EAX语义; 高位垃圾不参与匹配)
	ULONG leaf = (ULONG)GuestRegs->rax;
	if (leaf == 1)
	{
		//只清ECX bit31(hypervisor present), 隐藏"运行在VT之上"这一事实。
		//注意: 绝不能把CPUID.1全零返回——它携带FPU/SSE2/XSAVE/APIC-ID等
		//特性位, 全零=整颗CPU"退化"成无FPU无APIC的史前芯片, 系统行为
		//未定义→整机卡死
		cpuinfo[2] &= ~(1 << 31);
	}
	//hypervisor专用leaf(0x40000000-0x4000000F)全部归零——EAX=0即
	//"无hypervisor leaf", EBX/ECX/EDX=0即无vendor签名(Hyper-V/
	//"Microsoft Hv"/KVM/"KVMKVMKVM"/VMware...全不泄漏)。裸金属上该
	//区间本就返回0, 归零是纯防御: 嵌套在下层hypervisor之下运行时
	//其签名不会穿透
	else if (leaf >= 0x40000000 && leaf <= 0x4000000F)
	{
		cpuinfo[0] = 0;
		cpuinfo[1] = 0;
		cpuinfo[2] = 0;
		cpuinfo[3] = 0;
	}
	//leaf0 maxleaf防御收敛: 真实硬件max leaf恒<0x40000000(该区间保留给
	//hypervisor), 但嵌套场景下层hypervisor可能把maxleaf抬到0x40000000+;
	//>0x1F时收敛到0x1F(纯防御)。不做过低收敛: 比开机时(未虚拟化)读到的
	//真实值还小=另一种检测特征(内核启动时已缓存过原始maxleaf)
	else if (leaf == 0 && (ULONG)cpuinfo[0] > 0x1F)
	{
		cpuinfo[0] = 0x1F;
	}
	GuestRegs->rax = cpuinfo[0];
	GuestRegs->rbx = cpuinfo[1];
	GuestRegs->rcx = cpuinfo[2];
	GuestRegs->rdx = cpuinfo[3];
}

//TSC补偿(隐藏)——每次VM-exit的root驻留时间从guest可读TSC中永久扣除
//(TSC_OFFSET累计向负)。开启use TSC offsetting(procCtl bit3, SDM
//Table 27-6)后, guest内RDTSC/RDTSCP/RDMSR(0x10)硬件自动返回
//真TSC+TSC_OFFSET(SDM §28.3)——offset越来越负=exit从未发生的时间伪装。
//**IA32_TSC_DEADLINE(0x6E0)不受offset影响**(SDM §28.3原文)=LAPIC
//定时器/时钟中断零扰动。
//测算边界: 入口rdtsc在HVM_SAVE之后/出口rdtsc在vmresume之前——两端各漏
//~百cycle级(硬件exit转换+16push/16pop+vmresume转换), 欠补偿是**安全方向**:
//guest只会看到略多于真实的时间(正常), 绝不会倒退; 过补偿才有风险(紧邻
//两次RDTSC之间TSC倒退=可检测特征)
//仅VMX root+VMCS已加载上下文可调(vmx-asm.asm VmxVmexitHandler专用;
//vmread/vmwrite均作用于当前VMCS)。若bit3未存活(极老CPU), offset写入
//无害只是不被硬件使用(直通RDTSC本就读裸TSC)
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
	//MSR hook分发(GeptMsr.c)——位图命中的MSR读进回调, 返回值=伪造值
	//(rax:rdx)。未hook=直通(位图全零时本case根本不会触发)。
	//纪律: 绝不DbgPrint(exit上下文重入死锁)
	ULONG64 forged = 0;
	if (GeptMsrDispatchRead((ULONG32)GuestRegs->rcx, &forged))
	{
		GuestRegs->rax = forged & 0xFFFFFFFF;
		GuestRegs->rdx = (forged >> 32) & 0xFFFFFFFF;
		return;
	}
	ULONG64 msrValue = __readmsr(GuestRegs->rcx);
	GuestRegs->rax = msrValue & 0xFFFFFFFF;
	GuestRegs->rdx = (msrValue >> 32) & 0xFFFFFFFF;
}

//向guest注入#UD(非法指令)——VMX指令族exit的裸机精确仿真。
//SDM裁决(VMCALL/VMXOFF/VMCLEAR/INVEPT四指令页Operation节原文一致,
//覆盖三种指令形态): "IF not in VMX operation THEN #UD"——guest视角它
//从未成功进入VMX operation(它的VMXON被注入#GP拒绝), 裸机上这些指令
//=#UD, 注入#UD=行为逐位一致, 病毒探针零泄漏。
//字段编码(SDM Vol3C Table 24-13, 双权威=KVM vmx.h INTR_TYPE族):
//  bit31=valid | bits10:8=**3(硬件异常——0是外部中断! 写0=注入成
//  外部中断=完全不同事件)** | bit11=0(#UD无错误码: SDM错误码向量表
//  8/10-14/17不含6) | bits7:0=vector 6 → 0x80000306。
//硬件保证: "VM exits clear the valid bit"(§24.8.3, 每次VM-exit自清
//valid位=注入永不重复; handler顶部的清valid是保险)
//调用方纪律: ①绝不推进RIP(异常必须在本指令派发, 推进=异常地址错位
//=病毒#UD处理器的返回点异常=可观测泄漏) ②return早退绕过尾部推进
static VOID VmxInjectUd(ULONG cpu, ULONG reason, ULONG64 rip)
{
	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0x80000306);
	//采样环事件(首次+每4096次——病毒狂喷时MHz级, 不采样=刷爆环
	//挤掉别人的死因证据; 采样由T1异步落盘)
	static volatile LONG s_udCnt[64] = { 0 };
	LONG n = InterlockedIncrement(&s_udCnt[cpu & 63]);
	if (n == 1 || (n & 0xFFF) == 0)
	{
		FlRingPush('B', cpu, reason, rip, (ULONG64)(ULONG)n, 0);
	}
}

//向guest注入#GP(0)——VMXON exit的"BIOS锁VT"故事行为面(见
//case EXIT_REASON_VMXON注释)。编码(SDM Vol3C Table 24-13/24-15,
//双权威=KVM vmx.h INTR_TYPE族+VECTOR_HAS_ERROR_CODE):
//  bit31=valid | bit11=**1(携带错误码——#GP属错误码向量族
//  8/10-14/17, SDM §6.15; 不置位=VM-entry一致性检查拒绝)**
//  | bits10:8=3(硬件异常) | bits7:0=13(#GP) → 0x80000B0D;
//  错误码=0写入VM_ENTRY_EXCEPTION_ERROR_CODE(注入#GP时硬件从该
//  字段取错误码压入guest异常栈)
//调用方纪律与VmxInjectUd同: ①绝不推进RIP(#GP在指令处派发)
//②return早退绕过尾部推进
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
	__vmx_vmread(VM_EXIT_REASON, &vmexitReason);
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &exitCodeLen);
	__vmx_vmread(GUEST_RIP, &guestRip);
	__vmx_vmread(GUEST_RSP, &guestRsp);
	__vmx_vmread(EXIT_QUALIFICATION, &exitQual);
	vmexitReason = vmexitReason & 0xFFFF;
	//事件注入保险腰带——SDM Vol3C §24.8.3: "VM exits clear the valid
	//bit (bit 31)", 即每次VM-exit硬件**自清**valid位=注入永不重复。
	//保留为对该裁决的运行时保险: 若某构建行为与SDM不符(残留valid),
	//不清=此后每次vmresume重复注入#UD=无限异常环。代价: 每exit一次
	//vmread(~30cyc, exit本身~1000cyc且VMFUNC hook零exit, 可忽略)
	{
		ULONG64 staleIntr = 0;
		__vmx_vmread(VM_ENTRY_INTR_INFO_FIELD, &staleIntr);
		if (staleIntr & 0x80000000ULL)
		{
			__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);
		}
	}
	//通用环路检测: 同一(reason,rip)连续重复>500次=不可解exit循环
	//(修不好的violation/推进不了的fault无限重入)。500次在微秒级完成,
	//先于持锁线程的锁级联冻结触发——走逃生(vmx_off回真机)而非停核,
	//其余核与T1继续记录, 主线程也能继续启动后续核。
	//豁免(合法高频同RIP重复形态):
	//  48 EPT violation(ept.c有专属风暴检测且hook期同RIP交替属正常)
	//  10 CPUID(用户态cpuid自旋)  1 外部中断(中断风暴)  7 开窗排空
	//  16/14/12/36 已模拟指令exit(RDTSC计时自旋/INVLPG同调用点/HLT空闲)
	//  18-27+INVEPT/INVVPID VMX指令族(该族全部确定性处置: 已知vmcall码
	//  做实工/未知码注入#UD/VMXON注入#GP, 每次exit都有guest可见进展,
	//  病毒同RIP狂喷属合法形态——裸机上同样狂喷同样吃异常)
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
					//已模拟的指令exit豁免——RDTSC计时自旋/INVLPG
					//同指令高重复(上下文切换同一invlpg调用点)/HLT空闲自旋
					//都是合法同(reason,rip)高频形态
					vmexitReason != EXIT_REASON_RDTSC &&
					vmexitReason != EXIT_REASON_INVLPG &&
					vmexitReason != EXIT_REASON_HLT &&
					vmexitReason != EXIT_REASON_MWAIT_INSTRUCTION &&
					//VMX指令族(18-27+INVEPT/INVVPID)整体豁免——
					//该族全部确定性处置(见上), 每次exit都有guest可见进展
					//(异常派发经guest自身IDT), 绝非"不可解环路"
					!(vmexitReason >= EXIT_REASON_VMCALL &&
						vmexitReason <= EXIT_REASON_VMXON) &&
					vmexitReason != EXIT_REASON_INVEPT &&
					vmexitReason != EXIT_REASON_INVVPID &&
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
	//文件日志: 所有exit按reason计数; EPT violation在EptExitHandler里
	//单独入环(需要gpa), 其余在此采样, 心跳线程每秒落盘到Desktop日志
	if (vmexitReason == EXIT_REASON_EPT_VIOLATION)
	{
		InterlockedIncrement64(&g_flExitCounts[EXIT_REASON_EPT_VIOLATION]);
	}
	else
	{
		FlRingExit(KeGetCurrentProcessorNumber(), vmexitReason, guestRip, exitQual);
	}
	//DbgPrint("code:%d", vmexitReason);
	switch (vmexitReason)
	{
	case EXIT_REASON_CPUID:
	{
		VmxCpuidHandler(GuestRegs);
	}
	break;
	case EXIT_REASON_VMCALL:
	{
		if (GuestRegs->rcx == 1)//表示要退出vt
		{
			//exit上下文禁止DbgPrint(同核重入死锁)——日志只FlRingPush
			FlRingPush('V', KeGetCurrentProcessorNumber(), 18,
				guestRip, exitCodeLen, 0);
			//vmx_off后按guest原RFLAGS恢复IF——VM-exit时IF被硬件
			//清0, 跳回后FlLog的KeDelayExecutionThread睡眠依赖时钟
			//中断, IF=0=本核时钟被屏蔽=睡眠永不唤醒=卸载死锁
			ULONG64 vmcallFlags = 0;
			__vmx_vmread(GUEST_RFLAGS, &vmcallFlags);
			//vmx_off前invept全上下文——guest期间缓存的EPT派生
			//TLB表项(EPTP标签组合翻译)全部作废, 卸载后真机翻译零残留
			//(sc start/stop循环测试时, 上一轮残留+下一轮同物理页重用
			//=静默错译的经典源)
			EptInveptBothViews();
			//卸载前记录最终TSC_OFFSET('t'环事件)——本核整个生命周期
			//累计隐藏的exit驻留总时长(负值)。offset显著非0=补偿循环
			//全程在跑的直接证据; 恒0=补偿未生效(bit3未开/asm改动回归)。
			//vmread必须在vmx_off前(退出VMX operation后vmread非法)
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
			//卸载路径CR3恢复(根因级)——VM-exit硬件加载HOST_CR3
			//(=vmlaunch时System进程的页表基址, launch后永不更新)。
			//vmresume路径每次都会重载GUEST_CR3, 但vmx_off路径没有
			//vmresume: 跳回后本线程带着System页表继续跑——内核半区全
			//进程共享所以FlLog/CR4/亲和切换全部正常("干净退出"的假象
			//来源), 但同进程线程切换(KiSwapContext只在进程变化时重载
			//CR3)会把错误页表传播给本核后续调度的同进程线程; 其系统
			//调用写用户缓冲(LPC应答)时用户VA在System页表下零映射→#PF
			//→MmAccessFault判"内核态访问用户VA不允许"(p4=0xF)→蓝屏0x50
			//(此臂是概率性的: 多次退出可能都赌赢, 某一次赌输)。
			//修复=vmx_off后立即写回触发线程自己的CR3(=GUEST_CR3快照,
			//即vmcall时该线程所属进程的DTB)。vmread必须在vmx_off前。
			ULONG64 unloadCr3 = 0;
			ULONG64 hostCr3Snap = 0;
			__vmx_vmread(GUEST_CR3, &unloadCr3);
			//HOST_CR3取证快照——'r'三元组(a=卸载线程DTB b=回读 c=宿主
			//DTB快照)落环。若0x50复发, DMP里bugcheck CR3与各核'r'事件
			//直接比对: 等于c=宿主DTB残留臂实锤; 等于a且仍崩=第三方
			//指针损坏臂
			__vmx_vmread(HOST_CR3, &hostCr3Snap);
			__vmx_off();
			__writecr3(unloadCr3);
			//CR3回读校验+取证环事件(回读≠a=硬件级异常, 留痕供DMP判读)
			FlRingPush('r', KeGetCurrentProcessorNumber(), 0,
				unloadCr3, __readcr3(), hostCr3Snap);
			//主动全量TLB冲刷(CR4.PGE翻转, SDM: 改变PGE位的MOV CR4冲刷
			//全部翻译含全局页)——invept(EPT臂)+CR3重载(进程臂)+本冲刷
			//(残余一切翻译)=三重防线; IF=0窗口内执行, 两次CR4写~百cycle级
			{
				ULONG64 cr4Full = __readcr4();
				__writecr4(cr4Full & ~0x80ULL);   //PGE=0(冲全局页)
				__writecr4(cr4Full);              //PGE=1(恢复, 再冲)
			}
			if (vmcallFlags & 0x200)
			{
				_enable();
			}
			//返回到正确的位置——用VmxJumGuestRegs从GuestRegs帧恢复全部
			//非易失GPR(rbx/rbp/rsi/rdi/r12-r15)后再切栈跳转。只切
			//RSP+JMP的旧写法会拿本handler C代码残留的垃圾寄存器继续
			//跑(访问g_vcpu→访问违例蓝屏)。易失寄存器(rax/rcx/rdx/
			//r8-r11)不恢复: vmcall=x64调用边界, 调用者本就不跨调用
			//持有(ABI合法)
			VmxJumGuestRegs(GuestRegs, guestRsp, guestRip + exitCodeLen);
		}
		//EPT hook
		else if (GuestRegs->rcx == 2)
		{
			EptSetHook(GuestRegs->rdx, GuestRegs->r8);
		}
		//GeptHookRemove原语(GeptApi.c的DPC广播调用)——
		//rdx=CodePage+偏移(还原目标), r8=原页+偏移(权威副本, 原页从未被
		//修改), r9=还原长度(hookLen)。每核DPC各执行一次: memcpy幂等无害,
		//invept按核生效(TLB每核独立)故每核必做。还原后hooked视图≡clean
		//视图=hook死透; 在途回调(已过跳板)安全完成(其vmfunc此刻VT仍开)
		else if (GuestRegs->rcx == 7)
		{
			if (GuestRegs->r9 > 0 && GuestRegs->r9 <= 128)
			{
				RtlCopyMemory((PVOID)GuestRegs->rdx, (PVOID)GuestRegs->r8,
					(SIZE_T)GuestRegs->r9);
			}
			//双视图invept: hooked视图的CodePage执行缓存必须失效, 否则
			//旧翻译(跳转字节)存活到TLB自然逐出=Remove延迟生效
			EptInveptBothViews();
			FlRingPush('m', KeGetCurrentProcessorNumber(), 7,
				GuestRegs->rdx, GuestRegs->r8, GuestRegs->r9);
		}
		//落地探针(唯一合法来源=CmGuestProbe首条vmcall, 探针页已过
		//launch前EptVerifyTables样本走查): 看到它=全链路自证通过
		//"VM-entry转换+EPT取指翻译+vmcall exit+本handler+RIP推进+
		//vmresume"。'W'入环由T1落盘。放行走函数末尾通用RIP推进,
		//探针jmp CmGeustRip
		else if (GuestRegs->rcx == GEPT_PROBE_MAGIC)
		{
			FlRingPush('W', KeGetCurrentProcessorNumber(), 18,
				guestRip, exitQual, exitCodeLen);
		}
		//探针第二段(能执行到此=vmresume已成功过):
		//GEPT_PROBE_EXIT=1自测模式——vmx_off立即回真机, guest不
		//接管任何OS执行。GEPT_PROBE_EXIT=0(接管模式): 本分支编译
		//为空, 落到函数末尾通用RIP推进——探针jmp CmGeustRip恢复栈,
		//ret回VMXInitCpuStart在non-root继续, 该核从此运行在EPT之下
		else if (GuestRegs->rcx == 3)
		{
#if GEPT_PROBE_EXIT
			FlRingPush('K', KeGetCurrentProcessorNumber(), 18,
				guestRip, exitQual, exitCodeLen);
			ULONG64 probeFlags = 0;
			__vmx_vmread(GUEST_RFLAGS, &probeFlags);
			//vmx_off前invept全上下文——guest窗口期间缓存的EPT派生
			//TLB表项全部作废(sc start/stop循环时下轮重用同物理页=
			//静默错译的经典源)
			EptInveptBothViews();
			//vmx_off前排空积压in-service债——被ack进LAPIC ISR的
			//vector, 'K'直接vmx_off=永无ISR运行=永不EOI=真机上
			//中断屏蔽。x2APIC用WRMSR 0x80B清
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
			//CR3恢复(同rcx==1卸载路径, 见其注释; vmread必须在
			//vmx_off前)
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
			//IF0窗下probeFlags.IF=0→跳过sti(真机IF由
			//VMXInitCpuStart的CmGuestRsp后_enable()统一恢复)
			if (probeFlags & 0x200)
			{
				_enable();
			}
			//跳回vmcall下一条(=探针的jmp CmGeustRip): 真机执行纯栈恢复,
			//ret回VMXInitCpuStart后走bLaunchFailed分支, 串行启动下一核
			//(VmxJumGuestRegs恢复非易失GPR——落点是探针的纯jmp+pop链
			//虽会重恢复, 但统一出口零成本更稳妥)
			VmxJumGuestRegs(GuestRegs, guestRsp, guestRip + exitCodeLen);
#endif
			//GEPT_PROBE_EXIT=0(接管模式): 不做任何事, 落到函数末尾通用
			//RIP推进, 探针jmp CmGeustRip后guest正式接管OS执行
		}
		//持续执行压测循环(探针②段)——每1024次采样1条'L'(a=rbx剩余值)。
		//若冻结发生在循环中, 最后落盘的'L'的a值=死亡迭代号。
		//注意: 本分支不推'E'(FlRingExit已把r18环采样限到64条,
		//否则数千事件刷爆环把[W][F]等标记挤出去)
		else if (GuestRegs->rcx == 4)
		{
			if ((GuestRegs->rbx & 0x3FF) == 0)
			{
				FlRingPush('L', KeGetCurrentProcessorNumber(), 18,
					GuestRegs->rbx, 0, 0);
			}
		}
		//探针③段——循环完成(rbx=0), 即将进入rcx=3分流。
		//'Y'落盘后死亡=[rcx=3的exit→vmresume→jmp CmGeustRip→
		//add/pop/ret→_enable→FlLog]窗口; 无'Y'=死在循环内
		//(用'Y'不用'X': 'X'已被violation风暴逃生占用)
		else if (GuestRegs->rcx == 6)
		{
			FlRingPush('Y', KeGetCurrentProcessorNumber(), 18,
				GuestRegs->rbx, 0, 0);
		}
		//未知vmcall功能码——内部功能码穷举可复核(grep CmVmCall(:
		//1=停核/2=EptSetHook/7=还原字节, +探针3/4/6/0x5ABE全在链上),
		//能走到这的=外来者(病毒探针/第三方驱动)。裸机故事: VMCALL
		//不在VMX operation=**#UD**(SDM VMCALL指令页Operation节首行),
		//静默放行(跳过+推进RIP)=病毒观察到"VMCALL没#UD"=hypervisor
		//在场信号泄漏
		else
		{
			VmxInjectUd(KeGetCurrentProcessorNumber(), 18, guestRip);
			__vmx_vmwrite(GUEST_RIP, guestRip);
			return;
		}
	}
	break;
	//=============== VMX指令族exit(安全修复+互斥仲裁) ===============
	//双重身份: ①安全修复——该族若落default 'U'逃生(vmx_off回真机
	//重执行): 内核态病毒狂喷VMXOFF=真机重执行#UD=蓝屏, 狂喷VMXON
	//更糟=逃生后真机重执行可能真的成功=病毒抢走VMX root=脑裂
	//②互斥仲裁——同框架junior实例的__vmx_on被注入#GP=全核失败→
	//main.c汇总干净退出; 零签名/零共享对象/零新增可扫描物(仲裁者
	//是VT-x硬件本身, 对抗场景无单点失效)
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
		//异常在本指令派发: RIP原样写回+早退(绝不推进——见VmxInjectUd
		//调用方纪律①)
		__vmx_vmwrite(GUEST_RIP, guestRip);
		return;
	}
	case EXIT_REASON_VMXON:
	{
		//注入#GP(0)——"BIOS锁VT"故事的行为面:
		//  泄漏机理: 本机FEATURE_CONTROL(0x3A)真值=5(锁+VMX启用)对
		//guest可读——病毒"读0x3A=5→vmxon应成功"与宿主的失败处置
		//矛盾=hypervisor在场信号。裸机行为权威(SDM VMXON指令页
		//Protected Mode Exceptions: "If IA32_FEATURE_CONTROL MSR does
		//not indicate VMX operation enabled, #GP(0)"):
		//  a) 0x3A=1(锁+VMX禁用)的裸机: vmxon=**#GP(0)**
		//  b) 0x3A=5(锁+VMX启用)的裸机: vmxon(合法操作数)=成功
		//两针合壁(配套MSR hook伪造0x3A读=1): ①读面=0x3A读回1
		//("BIOS锁VT"标准形态) ②行为面=vmxon→#GP(0)(=a的裸机行为
		//逐位一致)——读/行为互相印证, 双探针病毒零泄漏。
		//互斥仲裁: 同框架junior的__vmx_on在宿主guest内→本case注入
		//#GP→junior侧SEH捕获→干净失败→main.c全败汇总路径不变
		VmxInjectGp(KeGetCurrentProcessorNumber(), 27, guestRip);
		//异常在本指令派发: RIP原样写回+早退(绝不推进——异常
		//派发经guest自身IDT, 推进=异常地址错位)
		__vmx_vmwrite(GUEST_RIP, guestRip);
		return;
	}
	case EXIT_REASON_INVD:
	{

		VmxInvd();
	}
	break;
	case EXIT_REASON_WBINVD:
	{
		//INVD/WBINVD在guest内无条件VM-exit, 必须由VMM代执行
		//缺此case会落进default被"推进RIP跳过", 缓存写回丢失->隐蔽的数据损坏
		__wbinvd();
	}
	break;
	//=============== must-1强制exit的指令模拟 ===============
	//注意: 本机PROC低32位的must-1集{1,4,5,6,8,13,14,26}全部落在
	//非控制位空洞(SDM Table 27-6: 本世代表布局bit7=HLT/bit9=INVLPG/
	//bit10=MWAIT/bit12=RDTSC; must-1集是保留位)——即本机这些指令
	//exiting全部关闭, 以下case大概率永不触发(保留无害; 若日志见
	//r16/r14计数>0则证明该CPU布局成立, 这些模拟就是必需的)
	case EXIT_REASON_RDTSC:
	{
		//TSC直通: root读真实TSC回填rax/rdx。不碰ecx(RDTSC本就不写
		//ecx; RDTSCP才写——罕见, 暂不管)。每次exit走完整handler,
		//计数留痕(r16)
		ULONG64 tsc = __rdtsc();
		GuestRegs->rax = tsc & 0xFFFFFFFF;
		GuestRegs->rdx = tsc >> 32;
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
		//空转模拟(跳过hlt指令)。空闲线程会自旋+每次循环exit一次
		//(exit风暴~1M/s, 已豁免'D'环检+环采样限流, 可承受)。
		//什么都不做, 落到函数尾通用RIP推进=跳过hlt
	}
	break;
	case EXIT_REASON_MWAIT_INSTRUCTION:
	{
		//MWAIT v1同HLT: 跳过(空转)。MONITOR(39)无副作用, 同跳过
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
		//WRMSR代执行: rdx:rax=64位值, rcx=MSR号(SDM 25.1.2寄存器映射)。
	//缺此case: 落default被"推进RIP"=写被静默丢弃(x2APIC EOI被吞=
	//中断卡死=整机冻结)。
	//hook分派(GeptMsr.c)——回调TRUE=放行代写(监控), FALSE=静默丢弃
	//(guest认为写成功); 未hook=直通(原逻辑)
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
		//XSETBV在non-root**无条件**VM-exit(SDM 25.1.3), 与ctls2许可位
		//无关, 必须由VMM代执行。缺此case=落default走'U'未知exit逃生
		//(vmx_off静默脱离VT, EPT hook全失效且无人知晓)。
		//rcx=XCR索引, rdx:rax=64位值(寄存器映射同WRMSR)
		_xsetbv((unsigned int)GuestRegs->rcx,
			((ULONG64)GuestRegs->rdx << 32) | (GuestRegs->rax & 0xFFFFFFFF));
	}
	break;
	case EXIT_REASON_VMFUNC:   //59
	{
		//VMFUNC失败exit(SDM §28.5.7.2/28.5.7.3)——到达本case的只有
		//EPTP switching失败: EPTP-list项非法/ECX>=512/函数位未开
		//(EAX>63或控制位0是#UD不走这里)。**视图未切换**(tent_EPTP被拒):
		//正确处置=推RIP跳过vmfunc, guest继续在旧视图跑。
		//绝不走'U'逃生: vmx_off回真机后重执行vmfunc=非non-root=#UD蓝屏。
		//SDM §30.2.5: VMFUNC失败exit的VM-exit instruction length字段
		//有效→函数尾通用RIP推进=安全跳过(防御: length异常时按vmfunc
		//裸指令定长3跳过——CmVmfuncSwitch的vmfunc无前缀, 机器码恰为
		//3字节0F01D4)
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
		//三重故障: guest状态已不可恢复(异常级联), 不能重执行(真机
		//三重故障=重启)。停核→park——vmx_off+sti/hlt自旋继续服务
		//中断, 切断"IF=0停核→IPI发送核自旋→全机冻结"的级联,
		//机器存活, 'T'+环尾由T1落盘
		VmxTripleFaultPark();    //noreturn
	}
	break;
	case EXIT_REASON_INVALID_GUEST_STATE:
	{
		//VM-entry failure(vmlaunch时guest状态非法, 如CR0/CR4固定位
		//不符/EFER不一致/段AR保留位非0)。控制流已跳到HOST_RIP而非
		//vmlaunch下一条——主线程此刻停在vmlaunch调用点, GUEST_RSP=
		//启动栈。逃生跳回入口: 恢复栈+ret后主线程从CmGuestRsp()调用
		//返回, 判bLaunchFailed走失败分支, 继续启动后续核(系统不冻结)
		//两类场景必须区分——launch期(vmlaunch入口失败: guestRip=
		//探针区间, GUEST_RSP=启动栈)才做CmGeustRip改写(逃生落点必须是
		//纯栈恢复代码, 真机可安全执行; 若跳回探针, 其vmcall在真机
		//模式=#UD蓝屏); 运行期(注入vmresume入口失败: guestRip=被
		//中断的OS上下文, GUEST_RSP=OS线程栈)若仍改写=在OS栈上执行
		//add rsp,28h+pop×16+ret=栈粉碎蓝屏! 直接逃回被中断上下文
		//(真机续跑该指令)
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
		//pin期望=0(外部中断直投guest), 本case**理论不可达**。
		//防御: 万一到达(pin配置未生效)='I'标记留痕, 同核超100次=
		//配置异常风暴, 逃生'J'留死因, 不拖全机
		ULONG64 intrInfo = 0;
		__vmx_vmread(VM_EXIT_INTR_INFO, &intrInfo);
		ULONG cpuX = KeGetCurrentProcessorNumber();
		FlRingPush('I', cpuX, 1, intrInfo & 0xFF, intrInfo, 0);
		static volatile LONG s_iCnt[64] = { 0 };
		if (InterlockedIncrement(&s_iCnt[cpuX & 63]) > 100)
		{
			VmxExitStormEscape('J', 1, intrInfo, guestRip, GuestRegs);    //noreturn
		}
		//非指令性exit: 原样写回RIP, 绝不能推进。无ack-on-exit时中断
		//仍在LAPIC IRR, resume后guest IF=1时硬件自行投递(零丢失)
		__vmx_vmwrite(GUEST_RIP, guestRip);
		return;
	}
	break;
	case EXIT_REASON_PENDING_INTERRUPT:   //7: interrupt-window exiting=guest可中断了
	{
		//窗口从未开启(proc期望无bit2), 本case**理论不可达**。
		//防御: 'J'标记留痕后放行
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
		//EPT misconfiguration: PTE格式非法(非指令性exit, 不能推进RIP)
		//出现说明EPT页表有结构性bug(如页表页未4KB对齐)。计数留痕,
		//超1000次=修复无效, 走逃生(vmx_off回真机重执行)而非停核
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
		//未知exit reason——指令未模拟执行, **绝不能推进RIP**:
		//  len>0推进 = 静默跳过指令(CR3-load被丢=地址空间错乱,
		//             WRMSR被丢=APIC EOI吞掉=中断卡死)
		//  len=0推进 = 原地重执行 = 无限循环
		//也不能原地vmresume重试(同因exit必然再来)。正确动作=逃生:
		//vmx_off回真机模式重执行该指令(真机无VMCS控制位拦截, 必然
		//正常执行), 'U'(len>0)/'Z'(len=0)标记由T1落盘, 系统继续跑
		VmxExitStormEscape(exitCodeLen == 0 ? 'Z' : 'U',
			vmexitReason, guestRip, exitQual, GuestRegs);    //noreturn
	}
	break;
	}
	__vmx_vmwrite(GUEST_RIP, guestRip + exitCodeLen);
}




//vmresume失败处理(asm VmxResumeFailed跳入, 永不返回)
//vmresume的VMfail(VMCS状态坏)不影响vmx_off逃生: GUEST_RIP/RSP/RFLAGS
//仍可从VMCS读出, 跳回guest重执行;'R'标记入环留死因
void VmxResumeFailedEntry(void)
{
	//guestRegs=NULL——本路径的GPR已被asm的pop链恢复(vmresume
	//失败点在HVM_RESTORE_ALL_NOSEGREGS之后), 无帧可传也无需恢复
	VmxExitStormEscape('R', 0, 0, 0, NULL);
}

//风暴逃生(永不返回): 标记入环后vmx_off脱离VT, 跳回guest触发点
//重执行。**所有逃生场景的指令都未成功执行, RIP一律不推进**(推进=静默
//丢弃指令效果: CR3-load被跳过=地址空间错乱, len=0推进=原地死循环)。
//唯一例外: reason=18(VMCALL)必须推进RIP——vmcall在真机模式=非法指令
//(#UD), 不推RIP跳回=真机重执行vmcall=必然蓝屏。reason=18的exit唯一
//来源就是vmcall指令本身, len恒=3, 推进=跳过它, 安全。
//为什么逃生而不是停核: 停核有级联冻结(该核的磁盘/时钟中断永不完成
//→日志线程的ZwWriteFile挂死→死因标记困在内存环=零信息冻结)。逃生后
//本核回真机模式: 中断正常、主线程从CmGuestRsp()返回继续启动后续核
//(bLaunchFailed=1防误判成功)、系统与其余核无感、日志线程必活→死因
//必然落盘。
//IF恢复: VM-exit时RFLAGS.IF被硬件清0; 跳回前按GUEST_RFLAGS原值恢复——
//guest原IF=0(其临界区)时强制sti会破坏其临界区, 必须按原值还原。
//tag: 'X'=violation/misconfig风暴 'A'=动态建表失败 'P'=低地址环路
//     'D'=同(reason,rip)通用环路 'Z'=len0未知exit 'U'=len>0未知exit
//     'R'=vmresume失败 'G'=VM-entry failure(guest状态非法)
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
	//触发指令=vmcall时必须推RIP再跳(见函数头注释)。
	//len需vmread(在vmx_off前); 'R'路径reason=0不触发; 'G'路径GUEST_RIP
	//已被改写为CmGeustRip且reason=33不触发——互不干扰
	if (reason == EXIT_REASON_VMCALL)
	{
		ULONG64 vmcallLen = 0;
		__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &vmcallLen);
		if (vmcallLen > 0 && vmcallLen <= 15)
		{
			guestRip += vmcallLen;
		}
	}
	//vmx_off前invept全上下文(EPT派生TLB零残留, 同[K]路径理由)
	EptInveptBothViews();
	//vmx_off前还原GDTR/IDTR limit(VM-exit强制0xFFFF, 见
	//VmxRestoreDtrLimits注释; 同样必须前置=vmread依赖VMX operation)
	VmxRestoreDtrLimits();
	//CR3恢复(同rcx==1卸载路径, 见其注释)——逃生=随机guest线程
	//执行中vmx_off回真机, VM-exit加载的HOST_CR3(System进程DTB)同样
	//残留; 逃逸线程带着System页表继续跑OS代码, 其任何用户VA访问
	//(系统调用写用户缓冲)都会蓝屏0x50/0xF。vmread必须在vmx_off前。
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
	//逃生前清积压中断的in-service债——被ack进LAPIC ISR的vector,
	//逃生后真机永不跑其ISR=永不EOI, 不清则≤其优先级的全部中断在
	//本核被永久屏蔽。x2APIC的EOI=MSR 0x80B; xAPIC(MMIO 0xFEE000B0)
	//需映射, 现代Windows默认x2APIC, 略过
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
	//跳回出口分流——guestRegs非NULL(exit handler的C上下文调用):
	//先从帧恢复全部非易失GPR再切栈跳(同rcx==1卸载路径, 防"垃圾
	//寄存器回真机"蓝屏, 见VmxJumGuestRegs注释); NULL(VmxResumeFailed
	//Entry): 寄存器已被asm的pop链恢复, 直接切栈跳(旧VmxJumGuest语义)
	if (guestRegs != NULL)
	{
		VmxJumGuestRegs(guestRegs, guestRsp, guestRip);
	}
	VmxJumGuest(guestRsp, guestRip); //重执行触发指令(真机无VMCS拦截, 必然通过)
}

//三重故障专用park(永不返回): guest已异常级联不可恢复, 逃生**重执行**
//=真机三重故障=重启。也不能停核: IF=0停核=本核IPI永不处理=各核的
//TLB-flush广播发送核自旋等待(持锁, DISPATCH级)=全机级联冻结→日志线程
//死+看门狗死=观测全盲。park方案: 'T'入环+清EOI债+vmx_off脱离VT+
//**sti+hlt自旋**(见common-asm.asm)——本核继续服务一切中断, 发送核
//等待解除, 机器存活, T1把'T'+环尾(最后exit的RIP/vector!)全部落盘。
//代价: 本核线程永久park(sc start不返回, 可接受), 驱动不得卸载
//(main.c守卫拒绝, park代码页/VMM栈仍被占用)。
//注意: 此处不调FlLog(IRQL未知, 其睡眠等待非法), 只FlRingPush(任意
//IRQL安全)
void VmxTripleFaultPark(void)
{
	ULONG cpu = KeGetCurrentProcessorNumber();
	FlRingPush('T', cpu, 2, 0, 0, 0);
	//EOI债: 被ack进LAPIC in-service但未投递的vector——不清则真机上
	//这些vector永久屏蔽中断
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
	//脱离VMX(此刻仍在exit上下文/VMM栈, host状态合法)——
	//EPT派生TLB残留全作废
	EptInveptBothViews();
	__vmx_off();
	ULONG64 cr4 = __readcr4();
	cr4 &= ~0x2000;                               //清CR4.VMXE, 干净回真机
	__writecr4(cr4);
	g_vcpu[cpu].bVmxOn = 0;
	g_vcpu[cpu].bInGuest = 0;
	g_vcpu[cpu].bLaunchFailed = 1;                //卸载路径跳过本核vmcall
	//park位掩码(main.c卸载守卫): park核的VMM栈/park代码页不能释放
	InterlockedOr(&g_geptParkedMask, (LONG)(1UL << (cpu & 31)));
	//park本体(asm, 永不返回): sti+hlt自旋持续服务中断, 切断级联冻结
	CmTripleFaultPark();
}

int VmxSetupVmcs(PVOID GuestRsp)
{
	ULONG cpuNumber = KeGetCurrentProcessorNumber();
	//注意: VCPU约8.4KB, 必须用指针访问——值拷贝会把整个结构体压进
	//内核栈(仅12-24KB, 深路径下栈溢出=蓝屏, 极其隐蔽)
	PVCPU currentCpu = &g_vcpu[cpuNumber];
	//DbgBreakPoint();
	//分段面包屑[1/6]: 每段FlLog同步落盘后才前进——蓝屏时最后一行=崩溃段
	FlLog("cpu%u VMCS[1/6]: 段寄存器...", cpuNumber);
	VmxFillSelectorData(RegGetEs(), 0);
	VmxFillSelectorData(RegGetCs(), 1);
	VmxFillSelectorData(RegGetSs(), 2);
	VmxFillSelectorData(RegGetDs(), 3);
	VmxFillSelectorData(RegGetFs(), 4);
	VmxFillSelectorData(RegGetGs(), 5);
	VmxFillSelectorData(GetLdtr(), 6);

	__vmx_vmwrite(HOST_ES_SELECTOR, RegGetEs() & 0XFFF8);
	__vmx_vmwrite(HOST_CS_SELECTOR, RegGetCs() & 0XFFF8);
	__vmx_vmwrite(HOST_SS_SELECTOR, RegGetSs() & 0XFFF8);
	__vmx_vmwrite(HOST_DS_SELECTOR, RegGetDs() & 0XFFF8);
	__vmx_vmwrite(HOST_FS_SELECTOR, RegGetFs() & 0XFFF8);
	__vmx_vmwrite(HOST_GS_SELECTOR, RegGetGs() & 0XFFF8);
	//填充TR寄存器
	FlLog("cpu%u VMCS[2/6]: TR+FS/GS base...", cpuNumber);
	USHORT trSelector = GetTrSelector();
	trSelector = trSelector &= 0xFFF8;
	ULONG trLimit = __segmentlimit(trSelector);
	ULONG64 gdtBase = GetGdtBase();
	LARGE_INTEGER trSegement = { 0 };
	PULONG trContext = (PULONG)(gdtBase + trSelector);
	trSegement.LowPart = ((trContext[0] >> 16) & 0xFFFF) | ((trContext[1] & 0xFF) << 16) | ((trContext[1] & 0xFF000000));
	trSegement.HighPart = trContext[2];
	ULONG trAttr = (trContext[1] & 0x00F0FF00) >> 8;
	g_dbgTrAr = trAttr;   //指纹留痕
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
	__vmx_vmwrite(GUEST_CR0, __readcr0());
	__vmx_vmwrite(GUEST_CR3, __readcr3());
	__vmx_vmwrite(GUEST_CR4, __readcr4());
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
	//host PAT/EFER: VMexit时host按此加载IA32_PAT/EFER——VMclear后为0,
	//而VM_EXIT_CONTROLS含"host address-space size"=64位host → 不填必vmlaunch error 8
	//(遗漏此填充会在修好其他崩溃后必然触发vmlaunch error 8)
	__vmx_vmwrite(HOST_IA32_PAT, __readmsr(MSR_IA32_PAT));
	__vmx_vmwrite(HOST_IA32_EFER, __readmsr(MSR_IA32_EFER));

	//sysenter
	__vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	__vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	__vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	__vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	//__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));

	//GDT
	FlLog("cpu%u VMCS[4/6]: GDTR/IDTR/RSP/RIP...", cpuNumber);
	__vmx_vmwrite(GUEST_GDTR_BASE, GetGdtBase());
	__vmx_vmwrite(GUEST_GDTR_LIMIT, GetGdtLimit());
	__vmx_vmwrite(HOST_GDTR_BASE, GetGdtBase());
	//IDT
	__vmx_vmwrite(GUEST_IDTR_BASE, GetIdtBase());
	__vmx_vmwrite(GUEST_IDTR_LIMIT, GetIdtLimit());
	__vmx_vmwrite(HOST_IDTR_BASE, GetIdtBase());
	//guest rsp rip
	__vmx_vmwrite(GUEST_RSP, GuestRsp);
	//GUEST_RIP指向落地探针(不直接CmGeustRip)。探针首条vmcall自证
	//"VM-entry转换+EPT取指翻译+VM-exit+RIP推进+vmresume"全链路,
	//handler推'W'环标记后放行, 探针jmp CmGeustRip恢复栈正常落地。
	//探针不触碰RSP(GUEST_RSP仍=CmGuestRsp保存值, 供CmGeustRip的
	//add/pop/ret恢复), 也不依赖GPR(VMCS不保存GPR, 落地时GPR是launch
	//现场垃圾值, CmGeustRip的pop会从栈恢复全部寄存器), 见common-asm.asm
	__vmx_vmwrite(GUEST_RIP, CmGuestProbe);
	__vmx_vmwrite(GUEST_RFLAGS, __readeflags());
	__vmx_vmwrite(HOST_RSP, (ULONG64)currentCpu->VMMStack + PAGE_SIZE * 5);
	__vmx_vmwrite(HOST_RIP, VmxVmexitHandler);
	ULONG64 basicMsr = __readmsr(MSR_IA32_VMX_BASIC);
	//VMX_BASIC bit55: TRUE能力MSR存在标志。存在则用TRUE MSR(0x48D-0x490,
	//如实上报必须为1的位), 否则用旧式MSR(0x481-0x484, default1类位恒读1)。
	//两种MSR位语义相同(见VmxMsrAdjuest注释), 经典公式通吃, 此标志只
	//决定读哪组MSR
	BOOLEAN useTrueCtl = ((basicMsr >> 55) & 1) != 0;
	ULONG64 result = 0;
	ULONG64 entryMsrNum = MSR_IA32_VMX_ENTRY_CTLS;
	ULONG64 exitMsrNum = MSR_IA32_VMX_EXIT_CTLS;
	ULONG64 pinMsr = MSR_IA32_VMX_PINBASED_CTLS;
	ULONG64	procMsr = MSR_IA32_VMX_PROCBASED_CTLS;
	if (useTrueCtl)
	{
		entryMsrNum = MSR_IA32_VMX_TRUE_ENTRY_CTLS;
		exitMsrNum = MSR_IA32_VMX_TRUE_EXIT_CTLS;

		pinMsr = MSR_IA32_VMX_TRUE_PINBASED_CTLS;
		procMsr = MSR_IA32_VMX_TRUE_PROCBASED_CTLS;
	}
	FlLog("cpu%u VMCS[5/6]: 控制字段+MSR位图 (bit55=%d)...", cpuNumber, (int)useTrueCtl);
	//能力MSR原值一次性落盘(全部后续判读的最终依据)。高32=允许为1
	//掩码, 低32=必须为1位, 结合控制字段行可反解每个位的来源
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
	//经典公式(低32|期望)&高32对新旧MSR都正确(见VmxMsrAdjuest注释);
	//secondary(0x48B)本就无TRUE变体, 亦同公式。
	//pin期望=**0**(外部中断直投guest, 不exit不注入——机理见本文件
	//头部"中断直投"裁决)
	ULONG pinCtl = VmxMsrAdjuest(pinMsr, 0);
	//proc期望+0x8(**bit3=use TSC offsetting**, SDM Table 27-6: RDTSC/
	//RDTSCP/RDMSR(0x10)返回值自动加TSC offset字段)——TSC补偿的硬件
	//基础。RDTSC exiting(bit12)保持0: 指令直通+硬件自动加offset
	//=零exit成本的读TSC。bit28(use MSR bitmaps)/bit31(activate
	//secondary controls)为必需位
	ULONG procCtl = VmxMsrAdjuest(procMsr, 0X8 | 0X10000000 | 0X80000000);
	//exitCtl期望只留bit9(0x200=host address-space size, 64位host必须),
	//**绝不开bit15(acknowledge interrupt on exit)**——直投纪律
	ULONG exitCtl = VmxMsrAdjuest(exitMsrNum, 0x200);
	ULONG entryCtl = VmxMsrAdjuest(entryMsrNum, 0x200);
	//控制字段留痕: 偏离期望=公式/MSR被误改; proc的bit3=0=极老CPU无
	//TSC offsetting, 补偿自动无效(直通RDTSC读裸TSC, 无害降级)
	FlLog("cpu%u 控制字段(直投+TSCoff): pin=%08X proc=%08X exit=%08X entry=%08X",
		cpuNumber, pinCtl, procCtl, exitCtl, entryCtl);
	__vmx_vmwrite(VM_ENTRY_CONTROLS, entryCtl);
	__vmx_vmwrite(VM_EXIT_CONTROLS, exitCtl);
	__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, pinCtl);
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, procCtl);
	//TSC_OFFSET初始化为0(累计负偏移的起点)。bit3未存活时该字段不被
	//硬件咨询(vmwrite无害)。此后VmxTscCompensate(每次exit, vmx-asm.asm
	//调用)把它单调向负推——guest的TSC时间线=真TSC减去全部已发生exit
	//的驻留时长
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
		//弃VPID: 真机同场PCID与guest VPID共用TLB资源的混叠疑点无法从
		//软件侧排除, 且恒等虚拟化无需VPID(它是vcpu切换免TLB冲刷的
		//优化)。翻译退化为EP4TA+CR3标签, invept全上下文即可完整冲刷
		//ctls2指令许可位(rdtscp/xsaves/invpcid)+EPT+VMFUNC:
		//  bit1(activate secondary) bit3(rdtscp) bit12(invpcid)
		//  bit20(xsaves) bit13(enable VM functions)。
		//注意位布局(TinyVT ia32.h/SimpleVisor vmx.h/hvpp/KVM四源一致):
		//  bit3=rdtscp bit4=virtualize_x2apic_mode bit10=pause_loop_
		//  exiting bit12=invpcid bit20=xsaves——**勿凭记忆写**(曾误写
		//  bit4=xsaves/bit10=invpcid, 实际开了x2APIC虚拟化+PLE→
		//  VM-entry要求PLE_Gap/PLE_Window非全零→控制字段检查失败
		//  错误码7)。VmxMsrAdjuest公式无法拦截"允许域内的错误期望"
		ULONG64 ctls2Value = VmxMsrAdjuest(MSR_IA32_VMX_PROCBASED_CTLS2,
			0x2 | 0x8 | 0x2000 | 0x1000 | 0x100000);
		__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, ctls2Value);
		__vmx_vmwrite(EPT_POINTER, g_vcpu[cpuNumber].Eptp.ALL);
		FlLog("cpu%u ctls2=%llX (期望0010300A=EPT+rdtscp+invpcid+xsaves+VMFUNC, 无VPID)",
			cpuNumber, (unsigned long long)ctls2Value);
		//VMFUNC EPTP switching上电(零VM-Exit hook的基石)。
		//能力探测: **VMFUNC没有任何CPUID枚举位**(SDM VMFUNC指令页:
		//#UD仅当非non-root/控制位0/EAX>=64)——切勿用CPUID.7.EBX[16]
		//探测(该位实为AVX512F, 无AVX-512的CPU读0, 会被误判"无VMFUNC")。
		//权威判据只有两个: ①ctls2 bit13(enable VM functions)经
		//VmxMsrAdjuest按MSR 0x48B允许域掩码后实际置位=硬件支持
		//②EPTP-list页就绪(Alloc阶段已分配)。vmlaunch成功即硬件已
		//验证整个VMFUNC配置。任一不满足=本核bVmfuncOn=0: hook走
		//violation方案(fallback)
		if ((ctls2Value & 0x2000) && g_vcpu[cpuNumber].VmfuncEptpList != NULL)
		{
			//EPTP-list双项: [0]=clean视图EPTP(恒等原始), [1]=hooked视图
			//EPTP(hook页→CodePage的hook世界)——SDM §28.5.7.3: guest内
			//vmfunc(0,idx)零VM-Exit切换; EptSetHook在root侧用
			//vmwrite(EPT_POINTER)走同一字段切视图。无hooked EPT(分配
			//失败)时退回双项同值(切换no-op, hook走violation方案)。
			//未用项(idx2-511)保持全0: guest误切=无效项→VM-exit
			//reason 59(case 59推RIP跳过, 绝非#UD——SDM裁决)
			PULONG64 eptpList = (PULONG64)g_vcpu[cpuNumber].VmfuncEptpList;
			eptpList[0] = g_vcpu[cpuNumber].Eptp.ALL;
			eptpList[1] = (g_vcpu[cpuNumber].PeptDataHooked != NULL)
				? g_vcpu[cpuNumber].EptpHooked.ALL
				: g_vcpu[cpuNumber].Eptp.ALL;
			PHYSICAL_ADDRESS eptpListPhys =
				MmGetPhysicalAddress(g_vcpu[cpuNumber].VmfuncEptpList);
			//VMFUNC control bit0=EPTP switching(唯一function); EPTP-list
			//地址须4KB对齐(物理连续页天然满足)
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
		//EPT未就绪: 无EPT无VPID(仍可虚拟化运行, 无hook能力), 但
		//指令许可位(rdtscp/xsaves/invpcid)仍必须开——它们与EPT正交,
		//缺了照样#UD蓝屏/冻结
		FlLog("cpu%u 无EPT数据(预分配失败?), ctls2仅指令许可位", cpuNumber);
		ULONG64 ctls2Value = VmxMsrAdjuest(MSR_IA32_VMX_PROCBASED_CTLS2,
			0x8 | 0x1000 | 0x100000);
		__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, ctls2Value);
	}

	//EPT软件自检门(见ept.c EptVerifyTables)——launch前用软件走查
	//复演硬件EPT翻译(EPTP链/pdpte链/2M叶全扫/探针页等关键样本页)。
	//失败=放弃本核vmlaunch(留在root模式, 系统存活, T1继续记录)=
	//"launch前精确报错+安全放弃"而非"死在黑盒"。无EPT数据时EPT未
	//启用(硬件直接翻译, 无黑盒), 跳过自检
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
	//指纹行(每次测试必核对!): 缺此行=测试机加载的是旧编译的sys。
	//CS.AR期望值=209B: x64 Windows内核CS(0x10)的真实GDT值就是L=1/
	//D=0/G=0/limit=0xFFFFF(长模式CS取指只查canonical不查limit,
	//G=0+20位limit自洽; "期望A09B"是32位/Linux时代的想当然)。
	//TR.AR=008B(IA-32e的TSS仍用32位busy type=0xB)。CS.AR若bit13(L)=0
	//(如009B)=AR填充回归旧bug
	FlLog("cpu%u 指纹(中断直投): CS.AR=%04lX TR.AR=%04lX (期望209B/008B) EPT自检=PASS EPTP=%llX 探针VA=%llX 模式=%s+pin0直投+无ack-on-exit+写盘护卫+KEEP检查点+512压测循环+D豁免+热观测+TFpark",
		cpuNumber, g_dbgCsAr, g_dbgTrAr,
		(unsigned long long)g_vcpu[cpuNumber].Eptp.ALL,
		(unsigned long long)(ULONG_PTR)CmGuestProbe,
#if GEPT_PROBE_EXIT
		"EXIT(自测)"
#else
		"KEEP(接管)"
#endif
	);
	//这条落盘后下一步就是vmlaunch。判读: 冻结/蓝屏时最后一行是它
	//=死在vmlaunch指令本身或探针两段vmcall前后; [W][K][F][f]环标记
	//与"probe-exit完成"行把死亡点二分到指令级。
	//本行也是护卫判读锚点——护卫期间T1零落盘, 若冻结且这是最后落盘行
	//=T1磁盘I/O被构造性排除(凶手在guest执行/中断直递); 存活则护卫
	//解除后此行下面紧跟[F][W][E]..[Y][K]补写=guest窗口无辜
	FlLog("cpu%u vmlaunch...(护卫开: T1停写盘至probe返回)", cpuNumber);
	//观测预热——置hot+踢T1+睡5ms, T1醒来进入1ms热节奏,
	//launch窗口(vmlaunch+探针循环+接管初期)全程毫秒级观测
	FlArmLaunchWatch();
	//开写盘护卫(此时"护卫开"行已由FlLog同步落盘)
	g_flWriteGuard = 1;
	//武装蓝屏黑匣子看门狗——此后行环游标30s不动(=T1循环死=冻结级联)
	//→自旋看门狗线程快照黑匣子+KeBugCheckEx(0xDEADC0DE)→MEMORY.DMP
	//保留死亡现场(T1磁盘日志通道在级联爆炸半径内结构性失效, bugcheck
	//的crash dump栈是唯一为死锁设计的低层通道)
	FlWdArm();
	//IF0探针窗口: _disable必须在FlArmLaunchWatch之后(其5ms睡眠依赖
	//IF1)。IF0下(pin=0)中断到达但不投递(留IRR), 探针窗内零ISR执行;
	//KEEP的sti后硬件直投guest ISR。'K'退出回真机→sti→IRR中断在真机
	//投递(安全)
	_disable();
	//重写GUEST_RFLAGS(此刻IF=0)——探针全程IF=0, [K]处理器的
	//"按guest原IF恢复"分支自然跳过, 真机IF由VMXInitCpuStart统一恢复
	__vmx_vmwrite(GUEST_RFLAGS, __readeflags());
	//'F'环事件=launch窗口开启标记(与'f'配对)
	FlRingPush('F', cpuNumber, 0, 0, 0, 0);
	result = __vmx_vmlaunch();

	if (result)
	{
		ULONG vmerr = 0;
		__vmx_vmread(VM_INSTRUCTION_ERROR, &vmerr);
		g_vcpu[cpuNumber].bLaunchFailed = 1;
		//先清护卫再FlLog(否则失败行要等500ms超时)
		g_flWriteGuard = 0;
		//恢复IF0窗→vmlaunch失败路径也要sti(IF=0下FlLog的等待依赖
		//时钟中断, 不恢复=永久睡眠)
		_enable();
		FlLog("cpu%u vmlaunch失败! 错误码=%d (7=控制字段非法 8=host状态非法, SDM Table 33-1)", cpuNumber, vmerr);
		g_flLaunchHot = 0;
	}
	return (int)result;
}

void VmxFillSelectorData(USHORT selector, USHORT index)
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
	//AR字段位布局(SDM 24.4.1, 已用SDM PDF+KVM/Xen/HyperPlatform三方
	//实现交叉验证): Type[3:0] S[4] DPL[6:5] P[7] AVL[12] L[13] D/B[14]
	//G[15] Unusable[16]——AttrHigh的AVL/L/D-B/G恰好左移12位就位,
	//即 byte0 | byte1<<12。**此公式正确, 勿"修复"**(改写成错误布局会把
	//L=1的内核CS标成32位兼容段→内核取指non-canonical→#GP风暴三重故障)
	ULONG attr = ((PUCHAR)&segMentSelector.attributes)[0]
		| ((PUCHAR)&segMentSelector.attributes)[1] << 12;
	if (selector == 0)
	{
		attr |= 0x10000;   //unusable(空选择子DS/ES/LDTR)
	}
	if (index == 1)
	{
		g_dbgCsAr = attr;  //指纹留痕(见VmxSetupVmcs末尾指纹行)
	}
	__vmx_vmwrite(GUEST_ES_SELECTOR + index * 2, segMentSelector.sel);
	__vmx_vmwrite(GUEST_ES_LIMIT + index * 2, segMentSelector.limit);
	__vmx_vmwrite(GUEST_ES_BASE + index * 2, segMentSelector.base);
	__vmx_vmwrite(GUEST_ES_AR_BYTES + index * 2, attr);
	//RIP RSP
	//1检测环境
	//2申请内存cpu vmxON vmcx
	//3 vmxon 进入 vt root host
	//4填充vmcs区域 RSP RIP
	//5 vmlaunch 从host层回到 guest  类似从r0回到r3
}

