#include"VMX.h"
#include"CPU.h"
#include"reg.h"
#include"common.h"
#include<intrin.h>
VCPU g_vcpu[128];
//v3.10: 段AR指纹(CS/TR最终写入VMCS的值), 供vmlaunch前指纹日志行——
//每次测试先看指纹行确认跑的是新编译的sys(本次v3.9教训: 测试机加载的
//旧二进制让全部修复"看似无效", 日志形态与v3.8一模一样)
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
	if (pvmmStack == NULL || MsrBitMap == NULL || pvmxon == NULL || pvmcs == NULL)
	{
		//释放已成功的部分, 调用方负责清理
		if (pvmmStack) MmFreeContiguousMemory(pvmmStack);
		if (MsrBitMap) MmFreeContiguousMemory(MsrBitMap);
		if (pvmxon) MmFreeContiguousMemory(pvmxon);
		if (pvmcs) MmFreeContiguousMemory(pvmcs);
		return 1;
	}
	RtlZeroMemory(pvmxon, sizeof(VMX_VMCS));
	RtlZeroMemory(pvmcs, sizeof(VMX_VMCS));
	RtlZeroMemory(pvmmStack, PAGE_SIZE * 6);
	//MSR位图必须清零!(myVt原版同样缺失) CPU_BASED启用了"use MSR bitmaps"(bit28),
	//垃圾位图=随机MSR触发exit; 且exit handler缺WRMSR case会静默丢弃写——
	//x2APIC系统的EOI(WRMSR 0x80B)被吞 → APIC中断卡死 → 整机冻结无蓝屏(vmlaunch成功后秒冻)
	//全零位图=不拦截任何MSR, guest直接访问, 零exit零风险
	RtlZeroMemory(MsrBitMap, PAGE_SIZE);
	pvmxon->RevisionId = (ULONG)__readmsr(MSR_IA32_VMX_BASIC);
	pvmcs->RevisionId = (ULONG)__readmsr(MSR_IA32_VMX_BASIC);
	g_vcpu[cpuNumber].VMXON = pvmxon;
	g_vcpu[cpuNumber].VMMStack = pvmmStack;
	g_vcpu[cpuNumber].VMCS = pvmcs;
	g_vcpu[cpuNumber].MsrBitMap = MsrBitMap;
	g_vcpu[cpuNumber].bInGuest = 0;
	g_vcpu[cpuNumber].bLaunchFailed = 0;
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
	UCHAR vmonResult = __vmx_on(&physvmon);
	if (vmonResult)
	{
		FlLog("cpu%u vmxon失败=%d (Hyper-V/VBS占用?)", cpuNumber, vmonResult);
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
	//vmlaunch成功: guest从CmGeustRip续跑后返回到这里(已处于non-root)
	//vmlaunch失败: fall-through恢复栈后返回到这里(仍在root)
	if (!g_vcpu[cpuNumber].bLaunchFailed)
	{
		g_vcpu[cpuNumber].bInGuest = 1;
		//此日志在non-root下打印(EPT翻译, 对OS透明)
		//看到它=该核vmlaunch成功; 之后若卡死即运行期问题而非启动问题
		FlLog("cpu%u vmlaunch成功, 已进入guest", cpuNumber);
	}
	else
	{
		FlLog("cpu%u vmlaunch失败(错误码见上一条), 该核留在root模式", cpuNumber);
	}
	return 0;
}

//串行模式(亲和性切换到目标核, PASSIVE_LEVEL)逐核退出VT(DriverUnload调用)
//取代原CommVtShutDown DPC: 卸载路径同样需要每步落盘可观测
void VmxStopCpu()
{
	ULONG cpuNumber = KeGetCurrentProcessorNumber();
	if (g_vcpu[cpuNumber].bInGuest)
	{
		FlLog("cpu%u: vmcall退出VT...", cpuNumber);
		//成功进入guest的核: vmcall退出(handler内vmx_off后跳回此处)
		CmVmCall(1, 0, 0, 0);
		FlLog("cpu%u: 已退出guest", cpuNumber);
	}
	else if (g_vcpu[cpuNumber].bVmxOn)
	{
		//vmlaunch失败但vmxon成功的核: 仍在root, 直接off
		FlLog("cpu%u: root模式直接vmx_off...", cpuNumber);
		__vmx_off();
	}
	if (g_vcpu[cpuNumber].bVmxOn)
	{
		//清CR4.VMXE, 恢复干净状态
		ULONG64 cr4 = __readcr4();
		cr4 &= ~0x2000;
		__writecr4(cr4);
		g_vcpu[cpuNumber].bVmxOn = 0;
		FlLog("cpu%u: VMXE已清, VT完全停止", cpuNumber);
	}
	else
	{
		FlLog("cpu%u: 未启用VT, 无需停止", cpuNumber);
	}
}

//控制字段计算。两种能力MSR的位语义**相反**, 必须区分(SDM Appendix A):
//  旧式MSR(0x481-0x484/0x48B): 低32位=必须为1的位
//  TRUE MSR(0x48D-0x490, VMX_BASIC bit55=1时启用, 现代CPU均有):
//        低32位=允许为0的位 -> 必须为1的位 = ~低32位
//v3.9根因修复: 原版(含myVt参考项目)对TRUE MSR套用旧式公式(低32位|期望值),
//等于把所有"允许为0"的控制位全部强制置1:
//  pin控位: external-interrupt exiting=1(每个中断都VM-exit) + preemption timer=1
//  proc控位: HLT/INVLPG/MWAIT/RDPMC/RDTSC/CR3载入/CR3存储/CR8/MOV-DR/IO exiting全=1
//vmlaunch照常成功(被误开的位都是allowed-1), 但进入guest后第一个时钟中断
//-> exit reason 1 -> handler无case -> default -> len=0 -> 'Z'自毁停核cpu0;
//而CR3/RDTSC exiting落default被"推进RIP跳过" = CR3永远不加载/QPC读数冻结。
//设备MSI(AHCI/USB/GPU)普遍落在cpu0 -> 中断永不完成 -> T1的ZwWriteFile挂死
//-> 日志停在"cpu0 vmlaunch..."、整机I/O冻结零蓝屏(v3.7/v3.8两次实测形态)。
//myVt在作者机器"能用": 老CPU bit55=0走旧式MSR, 旧式公式恰好正确。
ULONG VmxMsrAdjuest(ULONG64 msrNum, ULONG controlValue, BOOLEAN trueCtl)
{
	LARGE_INTEGER msrValue;
	msrValue.QuadPart = __readmsr(msrNum);
	if (trueCtl)
	{
		//TRUE MSR: 低32位=允许为0 -> 必须为1=~低32位
		controlValue = ((ULONG)~msrValue.LowPart | controlValue) & msrValue.HighPart;
	}
	else
	{
		//旧式MSR(含0x48B secondary, 无TRUE变体): 低32位=必须为1
		controlValue = (msrValue.LowPart | controlValue) & msrValue.HighPart;
	}
	return controlValue;
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

void VmxSetMsrRw(ULONG64 msrNum, UCHAR rw, BOOLEAN flag)
{
	ULONG cpuNumber = KeGetCurrentProcessorNumber();
	//v3.8: 值拷贝->指针(避免8.4KB压栈, 同VmxSetupVmcs)
	PVCPU currentCpu = &g_vcpu[cpuNumber];
	PUCHAR msrBitMapAddr = currentCpu->MsrBitMap;
	ULONG64 msrByteOffset = 0;
	ULONG msrBitOffset = 0;
	if (rw == 1)
	{
		msrBitMapAddr += 1024 * 2;
	}
	if (msrNum >= 0xC0000000)
	{
		msrBitMapAddr += 1024;
		msrNum -= 0xC0000000;
	}
	msrByteOffset = msrNum / 8;
	msrBitOffset = msrNum % 8;
	msrBitMapAddr += msrByteOffset;
	if (flag)
	{
		(*msrBitMapAddr) |= 1 << msrBitOffset;

	}
	else
	{
		(*msrBitMapAddr) &= ~(1 << msrBitOffset);
	}
}

void VmxCpuidHandler(PGUEST_REGS GuestRegs)
{
	//所有leaf先透传真实硬件结果
	int cpuinfo[4] = { 0 };
	__cpuidex(cpuinfo, (int)GuestRegs->rax, (int)GuestRegs->rcx);
	if (GuestRegs->rax == 1)
	{
		//只清ECX bit31(hypervisor present), 隐藏"运行在VT之上"这一事实
		//原版直接返回全零是致命的: CPUID.1携带FPU/SSE2/XSAVE/APIC-ID(EBX 31:24)等
		//特性位, 全零=整颗CPU"退化"成无FPU无APIC的史前芯片, DWM/Defender/
		//新进程特性探测/多线程库的核映射全部行为未定义 -> 运行期整机卡死
		cpuinfo[2] &= ~(1 << 31);
	}
	GuestRegs->rax = cpuinfo[0];
	GuestRegs->rbx = cpuinfo[1];
	GuestRegs->rcx = cpuinfo[2];
	GuestRegs->rdx = cpuinfo[3];
}
void VmxMsrReadHandler(PGUEST_REGS GuestRegs)
{
	//v3.8: 移除DbgPrint——本函数在VM-exit上下文执行, DbgPrint内部锁与被中断
	//线程可能同核重入死锁(位图全零时本case实际不会触发, 属残留地雷)
	ULONG64 msrValue = __readmsr(GuestRegs->rcx);
	GuestRegs->rax = msrValue & 0xFFFFFFFF;
	GuestRegs->rdx = (msrValue >> 32) & 0xFFFFFFFF;
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
	//v3.7通用环路检测: 同一(reason,rip)连续重复>500次=不可解exit循环
	//(修不好的violation/推进不了的fault无限重入)。500次在微秒级完成,
	//先于持锁线程的锁级联冻结触发——v3.10起走逃生(vmx_off回真机)而非
	//停核, 其余核与T1继续记录, 主线程也能继续启动后续核。
	//豁免: 48(EPT violation, ept.c有专属风暴检测且hook期同RIP交替属正常)
	//      10(CPUID, 用户态cpuid自旋属合法高频同RIP重复)
	//      1(外部中断, 中断风暴属合法高频同RIP重复)
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
					InterlockedIncrement(&s_sameCnt[cpuD]) > 500)
				{
					VmxExitStormEscape('D', vmexitReason, guestRip, exitQual);
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
			//v3.8: Log->FlRingPush(exit上下文禁止DbgPrint, 同核重入死锁)
			FlRingPush('V', KeGetCurrentProcessorNumber(), 18,
				guestRip, exitCodeLen, 0);
			//v3.10: vmx_off后按guest原RFLAGS恢复IF——VM-exit时IF被硬件
			//清0, 跳回后VmxStopCpu的FlLog->KeDelayExecutionThread睡眠
			//依赖时钟中断, IF=0=本核时钟被屏蔽=睡眠永不唤醒=卸载死锁
			ULONG64 vmcallFlags = 0;
			__vmx_vmread(GUEST_RFLAGS, &vmcallFlags);
			__vmx_off();
			if (vmcallFlags & 0x200)
			{
				_enable();
			}
			//返回到正确的位置
			VmxJumGuest(guestRsp, guestRip + exitCodeLen);
		}
		//EPT hook
		else if (GuestRegs->rcx == 2)
		{
			EptSetHook(GuestRegs->rdx, GuestRegs->r8);
		}

	}
	break;
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
	case EXIT_REASON_MSR_READ:
	{
		VmxMsrReadHandler(GuestRegs);
	}
	break;
	case EXIT_REASON_MSR_WRITE:
	{
		//WRMSR代执行: rdx:rax=64位值, rcx=MSR号(SDM 25.1.2寄存器映射)
		//此前缺此case: 落default被"推进RIP"=写被静默丢弃 —— 整机冻结根因C
		__writemsr(GuestRegs->rcx,
			((ULONG64)GuestRegs->rdx << 32) | (GuestRegs->rax & 0xFFFFFFFF));
	}
	break;
	case EXIT_REASON_TRIPLE_FAULT:
	{
		//三重故障: guest状态已不可恢复(异常级联), 唯一保留停核的场景
		//(逃生重执行=真机三重故障=直接重启且丢内存环日志, 见VmxTripleFaultHalt)
		VmxTripleFaultHalt();    //noreturn
	}
	break;
	case EXIT_REASON_INVALID_GUEST_STATE:
	{
		//v3.10关键case: VM-entry failure(vmlaunch时guest状态非法, 如
		//CR0/CR4固定位不符/EFER不一致/段AR保留位非0)。控制流已跳到
		//HOST_RIP而非vmlaunch下一条——主线程此刻停在vmlaunch调用点,
		//GUEST_RIP=CmGeustRip/GUEST_RSP=启动栈。逃生跳回入口:
		//恢复栈+ret后主线程从CmGuestRsp()调用返回, 判bLaunchFailed
		//走失败分支, 继续启动后续核(系统不冻结, 死因'G'由T1落盘)。
		//v3.9及以前缺此case: 落default len=0 -> 'Z'停核cpu0 -> loader锁
		//挂死+磁盘中断级联 -> "vmlaunch后零心跳冻结"
		VmxExitStormEscape('G', 33, guestRip, exitQual);    //noreturn
	}
	break;
	case EXIT_REASON_EXTERNAL_INTERRUPT:
	{
		//v3.9防御: 修复TRUE MSR公式后pin.bit0=0, 本case正常不触发。
		//若控制字段回归误开ext-int exiting: exit控制含"acknowledge
		//interrupt on exit"(bit15), 中断在exit时已被EOI——必须重新注入
		//guest, 否则时钟/设备中断永久丢失; 若落default则len=0走'Z'自毁
		//=v3.8冻结形态复发。非指令性exit: 原样写回RIP, 绝不能推进
		ULONG64 intrInfo = 0;
		__vmx_vmread(VM_EXIT_INTR_INFO, &intrInfo);
		if (intrInfo & 0x80000000)    //bit31=valid才注入
		{
			__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, intrInfo);
			__vmx_vmwrite(GUEST_INTERRUPTIBILITY_STATE, 0);
		}
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
		//超1000次=修复无效, v3.10走逃生(vmx_off回真机重执行)而非停核
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
			VmxExitStormEscape('X', 49, cfgGpa, guestRip);    //noreturn
		}
	}
	return;
	default:
	{
		//v3.10: 未知exit reason——指令未模拟执行, **绝不能推进RIP**:
		//  len>0推进 = 静默跳过指令(CR3-load被丢=地址空间错乱,
		//             WRMSR被丢=APIC EOI吞掉=中断卡死, v3.8的教训)
		//  len=0推进 = 原地重执行 = 无限循环
		//也不能原地vmresume重试(同因exit必然再来)。正确动作=逃生:
		//vmx_off回真机模式重执行该指令(真机无VMCS控制位拦截, 必然
		//正常执行), 'U'(len>0)/'Z'(len=0)标记由T1落盘, 系统继续跑
		VmxExitStormEscape(exitCodeLen == 0 ? 'Z' : 'U',
			vmexitReason, guestRip, exitQual);    //noreturn
	}
	break;
	}
	__vmx_vmwrite(GUEST_RIP, guestRip + exitCodeLen);
}




//vmresume失败处理(asm VmxResumeFailed跳入, 永不返回)
//v3.10: 停核->逃生。vmresume的VMfail(VMCS状态坏)不影响vmx_off逃生:
//GUEST_RIP/RSP/RFLAGS仍可从VMCS读出, 跳回guest重执行;'R'标记入环留死因
void VmxResumeFailedEntry(void)
{
	VmxExitStormEscape('R', 0, 0, 0);
}

//风暴逃生(v3.10, 永不返回): 标记入环后vmx_off脱离VT, 跳回guest触发点
//重执行。**所有逃生场景的指令都未成功执行, RIP一律不推进**(推进=静默
//丢弃指令效果: CR3-load被跳过=地址空间错乱, len=0推进=原地死循环)。
//v3.7-v3.9的"停核"方案实测有级联冻结: cpu0停核后落在该核的磁盘/时钟
//中断永不完成 -> T1的ZwWriteFile挂死 -> 死因标记困在内存环+心跳全停
//= "停在cpu0 vmlaunch+零[HB]"的零信息冻结(三次实测同一形态)。
//逃生后本核回真机模式: 中断正常、主线程从CmGuestRsp()返回继续启动
//后续核(bLaunchFailed=1防误判成功)、系统与其余核无感、T1必活->死因必然落盘。
//IF恢复: VM-exit时RFLAGS.IF被硬件清0; 跳回前按GUEST_RFLAGS原值恢复——
//guest原IF=0(其临界区)时强制sti会破坏其临界区, 必须按原值还原。
//tag: 'X'=violation/misconfig风暴 'A'=动态建表失败 'P'=低地址环路
//     'D'=同(reason,rip)通用环路 'Z'=len0未知exit 'U'=len>0未知exit
//     'R'=vmresume失败 'G'=VM-entry failure(guest状态非法)
void VmxExitStormEscape(char tag, ULONG reason, ULONG64 a, ULONG64 b)
{
	ULONG cpu = KeGetCurrentProcessorNumber();
	FlRingPush(tag, cpu, reason, a, b, 0);
	//vmread必须在vmx_off之前(退出VMX operation后vmread非法)
	ULONG64 guestRsp = 0, guestRip = 0, guestRflags = 0;
	__vmx_vmread(GUEST_RSP, &guestRsp);
	__vmx_vmread(GUEST_RIP, &guestRip);
	__vmx_vmread(GUEST_RFLAGS, &guestRflags);
	__vmx_off();
	ULONG64 cr4 = __readcr4();
	cr4 &= ~0x2000;              //清CR4.VMXE, 干净回真机
	__writecr4(cr4);
	g_vcpu[cpu].bVmxOn = 0;
	g_vcpu[cpu].bInGuest = 0;
	g_vcpu[cpu].bLaunchFailed = 1;   //主线程判此标志走失败分支(不再冻结)
	if (guestRflags & 0x200)
	{
		_enable();               //已脱离VMX, 恢复guest原始IF
	}
	VmxJumGuest(guestRsp, guestRip); //重执行触发指令(真机无VMCS拦截, 必然通过)
}

//三重故障专用停核(v3.10, 永不返回): 唯一不能逃生的场景——guest已异常
//级联不可恢复, 逃生重执行=真机三重故障=直接重启且连内存环日志都丢。
//停核+留'T'标记, 其余核与T1继续(三重故障时guest通常已持有破坏性状态,
//继续放行风险大于收益; 若T1的磁盘I/O完成中断不在本核, 标记将落盘)
void VmxTripleFaultHalt(void)
{
	FlRingPush('T', KeGetCurrentProcessorNumber(), 2, 0, 0, 0);
	_disable();
	__halt();
}

int VmxSetupVmcs(PVOID GuestRsp)
{
	ULONG cpuNumber = KeGetCurrentProcessorNumber();
	//v3.8: 值拷贝->指针。VCPU含HighPdptVa[512]+HighPdptRawVa[512]约8.4KB,
	//原写法每次调用把整个结构体压进内核栈(内核栈仅12-24KB, 深路径下
	//栈溢出=蓝屏0x1E/栈损坏, 极其隐蔽)
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
	g_dbgTrAr = trAttr;   //指纹留痕(v3.10)
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
	//(myVt原版遗漏; 此前vmlaunch没走到这一步就先在别处蓝屏, 修好当前崩溃后必踩)
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
	__vmx_vmwrite(GUEST_RIP, CmGeustRip);
	__vmx_vmwrite(GUEST_RFLAGS, __readeflags());
	__vmx_vmwrite(HOST_RSP, (ULONG64)currentCpu->VMMStack + PAGE_SIZE * 5);
	__vmx_vmwrite(HOST_RIP, VmxVmexitHandler);
	ULONG64 basicMsr = __readmsr(MSR_IA32_VMX_BASIC);
	//v3.9: TRUE能力MSR存在标志(VMX_BASIC bit55)。它决定VmxMsrAdjuest用哪套
	//位语义——误用旧式公式=所有灵活控制位被强制置1(vmlaunch成功但进guest
	//即冻结, 见VmxMsrAdjuest注释), 即v3.7/v3.8两次实测"cpu0 vmlaunch...后
	//整机冻结零日志"的根因。现代CPU该位恒为1, myVt作者的旧CPU为0故恰好没炸
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
	//v3.9: TRUE MSR必须传TRUE标志走补码公式; 0x48B secondary无TRUE变体恒FALSE
	ULONG pinCtl = VmxMsrAdjuest(pinMsr, 0, useTrueCtl);
	ULONG procCtl = VmxMsrAdjuest(procMsr, 0X10000000 | 0X80000000, useTrueCtl);
	ULONG exitCtl = VmxMsrAdjuest(exitMsrNum, 0x8200, useTrueCtl);
	ULONG entryCtl = VmxMsrAdjuest(entryMsrNum, 0x200, useTrueCtl);
	//控制字段原值留痕(冻结时对照NOTES.md v3.9判读表直接定位误开的位):
	//pin:  bit0(ext-int exiting)/bit5(preemption timer)/bit6(posted int)必须=0
	//proc: 应仅剩bit28(MSR位图)+bit31(secondary)+个别保留must-1位,
	//      bit2(int-window)/bit7(HLT)/bit12(RDTSC)/bit15,16(CR3)/bit21(CPUID)等必须=0
	FlLog("cpu%u 控制字段: pin=%08X proc=%08X exit=%08X entry=%08X",
		cpuNumber, pinCtl, procCtl, exitCtl, entryCtl);
	__vmx_vmwrite(VM_ENTRY_CONTROLS, entryCtl);
	__vmx_vmwrite(VM_EXIT_CONTROLS, exitCtl);
	__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, pinCtl);
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, procCtl);
	PHYSICAL_ADDRESS msrPhyAddr = MmGetPhysicalAddress(currentCpu->MsrBitMap);
	__vmx_vmwrite(MSR_BITMAP, msrPhyAddr.QuadPart);
	__vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
	__vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);
	__vmx_vmwrite(GUEST_ACTIVITY_STATE, 0);   // 处于正常执行指令状态
	//0xC0000082
	//VmxSetMsrRw(0xC0000082,0,TRUE);
	FlLog("cpu%u VMCS[6/6]: 填充完成, 启用EPT", cpuNumber);
	//EPT数据已在DriverEntry(PASSIVE_LEVEL)预分配, 此处只写入VMCS
	if (g_vcpu[cpuNumber].PeptData != NULL)
	{
		ULONG64 ctls2Value = VmxMsrAdjuest(MSR_IA32_VMX_PROCBASED_CTLS2, 2 | 0X20, FALSE);
		__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, ctls2Value);
		__vmx_vmwrite(EPT_POINTER, g_vcpu[cpuNumber].Eptp.ALL);
		__vmx_vmwrite(0, cpuNumber + 1);	//field 0 = VPID, 必须非0
	}
	else
	{
		//EPT未就绪: 只启用VPID, 不启用EPT(仍可虚拟化运行, 无hook能力)
		FlLog("cpu%u 无EPT数据(预分配失败?), 仅启用VPID", cpuNumber);
		ULONG64 ctls2Value = VmxMsrAdjuest(MSR_IA32_VMX_PROCBASED_CTLS2, 0X20, FALSE);
		__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, ctls2Value);
		__vmx_vmwrite(0, cpuNumber + 1);
	}

	//v3.10指纹行(每次测试必核对!): 缺此行=测试机加载的是旧编译的sys
	//(本次v3.9实测教训: 全部修复"看似无效", 日志形态与v3.8一模一样,
	//实际测试机根本没跑新代码)。期望值: CS.AR=A09B(x64内核CS: L=1 G=1
	//DPL=0 S=1 P=1 Type=B), TR.AR=008B(32位busy TSS)。
	//CS.AR若bit13/bit15为0(如20DB)=段AR填充回归旧bug
	FlLog("cpu%u v3.10指纹: CS.AR=%04lX TR.AR=%04lX (期望A09B/008B) EPTP=%llX",
		cpuNumber, g_dbgCsAr, g_dbgTrAr,
		(unsigned long long)g_vcpu[cpuNumber].Eptp.ALL);
	//这条落盘后下一步就是vmlaunch: 若冻结时它是最后一行,
	//=卡死在vmlaunch指令本身或guest刚启动的头几条指令
	FlLog("cpu%u vmlaunch...", cpuNumber);
	result = __vmx_vmlaunch();

	if (result)
	{
		ULONG vmerr = 0;
		__vmx_vmread(VM_INSTRUCTION_ERROR, &vmerr);
		g_vcpu[cpuNumber].bLaunchFailed = 1;
		FlLog("cpu%u vmlaunch失败! 错误码=%d (7=控制字段非法 8=host状态非法, SDM Table 33-1)", cpuNumber, vmerr);
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
	//AR字段位布局(SDM 24.4.1, 本项目已用SDM PDF裁决+KVM/Xen/HyperPlatform
	//三方实现交叉验证): Type[3:0] S[4] DPL[6:5] P[7] AVL[12] L[13] D/B[14]
	//G[15] Unusable[16]——AttrHigh的AVL/L/D-B/G恰好左移12位就位,
	//即 byte0 | byte1<<12。**myVt原版公式正确, 勿"修复"**(v3.10曾险些
	//按错误布局改写成AVL→10/L→12/D-B→13/G→14, 会把L=1的内核CS标成
	//32位兼容段→内核取指non-canonical→#GP风暴三重故障)
	ULONG attr = ((PUCHAR)&segMentSelector.attributes)[0]
		| ((PUCHAR)&segMentSelector.attributes)[1] << 12;
	if (selector == 0)
	{
		attr |= 0x10000;   //unusable(空选择子DS/ES/LDTR)
	}
	if (index == 1)
	{
		g_dbgCsAr = attr;  //指纹留痕(v3.10, 见VmxSetupVmcs末尾指纹行)
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

