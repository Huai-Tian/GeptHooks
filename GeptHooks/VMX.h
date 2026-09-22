#pragma once
#ifndef VMX_H
#define VMX_H
#include<ntifs.h>
#include"ept.h"
#define EXIT_REASON_EXCEPTION_NMI       0
#define EXIT_REASON_EXTERNAL_INTERRUPT  1
#define EXIT_REASON_TRIPLE_FAULT        2
#define EXIT_REASON_INIT                3
#define EXIT_REASON_SIPI                4
#define EXIT_REASON_IO_SMI              5
#define EXIT_REASON_OTHER_SMI           6
#define EXIT_REASON_PENDING_INTERRUPT   7
#define EXIT_REASON_TASK_SWITCH         9
#define EXIT_REASON_CPUID               10
#define EXIT_REASON_HLT                 12
#define EXIT_REASON_INVD                13
#define EXIT_REASON_INVLPG              14
#define EXIT_REASON_RDPMC               15
#define EXIT_REASON_RDTSC               16
#define EXIT_REASON_RSM                 17
#define EXIT_REASON_VMCALL              18
#define EXIT_REASON_VMCLEAR             19
#define EXIT_REASON_VMLAUNCH            20
#define EXIT_REASON_VMPTRLD             21
#define EXIT_REASON_VMPTRST             22
#define EXIT_REASON_VMREAD              23
#define EXIT_REASON_VMRESUME            24
#define EXIT_REASON_VMWRITE             25
#define EXIT_REASON_VMXOFF              26
#define EXIT_REASON_VMXON               27
#define EXIT_REASON_CR_ACCESS           28
#define EXIT_REASON_DR_ACCESS           29
#define EXIT_REASON_IO_INSTRUCTION      30
#define EXIT_REASON_MSR_READ            31
#define EXIT_REASON_MSR_WRITE           32
#define EXIT_REASON_INVALID_GUEST_STATE 33
#define EXIT_REASON_MSR_LOADING         34
#define EXIT_REASON_MWAIT_INSTRUCTION   36
#define EXIT_REASON_MONITOR_INSTRUCTION 39
#define EXIT_REASON_PAUSE_INSTRUCTION   40
#define EXIT_REASON_MACHINE_CHECK       41
#define EXIT_REASON_TPR_BELOW_THRESHOLD 43
#define EXIT_REASON_EPT_VIOLATION       48
#define EXIT_REASON_EPT_CONFIG          49
//INVEPT: non-root无条件exit(与VMXOFF同族, 需case处置)
#define EXIT_REASON_INVEPT              50
//RDTSCP: 仅特定控制位布局下exit(保留case防御)
#define EXIT_REASON_RDTSCP              51
#define EXIT_REASON_INVVPID             53
#define EXIT_REASON_WBINVD              54
#define EXIT_REASON_XSETBV              55
//VMFUNC失败exit(reason 59, 非#UD)
#define EXIT_REASON_VMFUNC              59
#define VMX_MAX_GUEST_VMEXIT	EXIT_REASON_VMFUNC

//vmresume失败处理(asm调用, noreturn): 'R'标记入环后逃生(vmx_off+跳回guest)
void VmxResumeFailedEntry(void);
//风暴逃生(noreturn): 标记入环后vmx_off脱离VT, 跳回guest触发点重执行
//(RIP不推进; 唯一例外reason=18须推进)。
//tag: 'X'=violation/misconfig风暴 'A'=动态建表失败 'P'=低地址环路
//     'D'=同(reason,rip)环路 'Z'=len0未知exit 'U'=len>0未知exit
//     'R'=vmresume失败 'G'=VM-entry failure 'J'=ext-int意外到达风暴
//guestRegs: 非NULL=exit handler C上下文(跳回前恢复非易失GPR);
//NULL=寄存器已被asm pop链恢复
void VmxExitStormEscape(char tag, ULONG reason, ULONG64 a, ULONG64 b,
	PVOID guestRegs);
//vmx_off跳回guest的出口: 从GuestRegs帧恢复非易失GPR后切RSP/JMP
void VmxJumGuestRegs(PVOID guestRegs, ULONG64 targetRsp, ULONG64 targetRip);
//lgdt/lidt——rcx=10字节描述符(WORD limit@+0, QWORD base@+2)
void VmxLoadGdtr(PVOID descriptor);
void VmxLoadIdtr(PVOID descriptor);
//三重故障park(noreturn): vmx_off+sti/hlt自旋继续服务中断, 切断
//级联冻结; 本核永久park, 驱动不得卸载(g_geptParkedMask守卫)
void VmxTripleFaultPark(void);
typedef struct _VMX_VMCS
{
    ULONG RevisionId;
    ULONG AbortIndicator;
    UCHAR Data[PAGE_SIZE - 2 * sizeof(ULONG)];
} VMX_VMCS, * PVMX_VMCS;
typedef struct _VCPU
{
    PVMX_VMCS VMXON;
    PVMX_VMCS VMCS;
    PVOID VMMStack;
    PVOID MsrBitMap;
    PEPT_DATA PeptData;
    EPT_EPTP Eptp;
    //hooked视图EPT: hook页PTE→CodePage(X=1,R=1,W=0)=执行零VM-Exit;
    //clean视图下原页字节完好。EptSetHook在root侧vmwrite(EPT_POINTER)
    //切视图(与VMFUNC切换同字段)
    PEPT_DATA PeptDataHooked;
    EPT_EPTP EptpHooked;
    //EPTP-list页(4KB对齐): [0]=clean EPTP, [1]=hooked EPTP。
    //VMFUNC(0,idx)在guest内零VM-Exit切换
    PVOID VmfuncEptpList;
    PVOID HighPdptVa[512];      //动态建立的pml4[i>0]对应pdpt页的虚拟地址(>512GB MMIO区)
    PVOID HighPdptRawVa[512];   //上述pdpt的原始pool指针(4KB对齐后无法反推raw, 卸载时用它ExFreePool)
    volatile LONG bInGuest;     //该CPU已成功进入VMX non-root(卸载时用于判断能否vmcall)
    volatile LONG bLaunchFailed;//vmlaunch失败标志(区分fall-through路径)
    volatile LONG bVmxOn;       //该CPU的__vmx_on已成功(卸载时需vmx_off+清CR4.VMXE)
    volatile LONG bVmfuncOn;    //该核VMFUNC已启用(ctls2 bit13实际写入成功); guest内执行vmfunc的前提, 否则#UD蓝屏
    //已ack未投递的中断计数(直投模式下恒0, EOI清债路径用)
    volatile LONG PendingIntrCount;
    UCHAR PendingIntrVec[256];
} VCPU, * PVCPU;
extern VCPU g_vcpu[128];      //定义于VMX.c, 每CPU一个虚拟CPU实例
typedef enum _INV_TYPE
{
    //TLB
    INV_INDIV_ADDR = 0,  // Invalidate a specific page
    INV_SINGLE_CONTEXT = 1,  //   Invalidate one context (specific VPID)
    INV_ALL_CONTEXTS = 2,  // Invalidate all contexts (all VPIDs)
    INV_SINGLE_CONTEXT_RETAIN_GLOBALS = 3   // Invalidate a single VPID context retaining global mappings
} IVVPID_TYPE, INVEPT_TYPE;
typedef struct _EPT_CTX
{
    ULONG64 PEPT;
    ULONG64 High;
} EPT_CTX, * PEPT_CTX;
PVCPU VmxGetCurrentVcpu(ULONG cpuNumber);
int VMXInitCpuAlloc(ULONG cpuNumber);   //PASSIVE_LEVEL: 预分配VMXON/VMCS/VMM栈/MSR位图
int VMXInitCpuStart();                  //串行模式(亲和性已切换到目标核, PASSIVE): vmxon+vmptrld+vmlaunch
void VmxStopCpu();                      //串行逐核退出VT(仅DriverEntry全败清理用; 主卸载路径=VmxStopAllIpi)
//全核IPI原子退出(KeIpiGenericCall广播): 每核原子完成VT退出+清VMXE
//+PGE冲刷; IPI内只FlRingPush('v')
ULONG64 VmxStopAllIpi(ULONG_PTR Argument);
//框架生命周期入口(main.c只调这两个, 实现见VMX.c):
//启动: 资源预分配→串行逐核VT接管→内置0x3A互斥hook→放行日志镜像。
//失败时已自清理资源, 调用方直接返回即可
NTSTATUS VmxStartAllCpus(_In_ PDRIVER_OBJECT DriverObject);
//关停: 移除全部hook→全核IPI原子退出VT→释放全部资源
//(park核在场时拒绝关停, 直接返回)
VOID VmxShutdownAllCpus(VOID);
int VmxSetupVmcs();
void VmxFillSelectorData();
//控制字段计算: (MSR低32|期望)&高32(低32=必须1位, 高32=允许1位)
ULONG VmxMsrAdjuest(ULONG64 msrNum, ULONG controlValue);
//TSC补偿(每exit调用): TSC_OFFSET -= exit驻留时长
void VmxTscCompensate(ULONG64 entryTsc, ULONG64 exitTsc);
void VmxVmexitHandler();
void VmxExitHandler();
void VmxJumGuest(ULONG64 targetRsp,ULONG64 targetRip);
void VmxFreeCpuResources(ULONG cpuNumber);  //PASSIVE_LEVEL: 释放指定CPU的全部VT资源
void VmxInvd();
BOOLEAN VmxInvept(INVEPT_TYPE type, PEPT_CTX ctx);  //返回TRUE=VMfail(失败)

#endif // VMX_H
