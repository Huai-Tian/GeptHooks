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
//INVEPT/INVVPID编码(权威源: Linux asm/vmx.h, 与SDM一致)。
//INVEPT指令页(SDM原文): "not in VMX operation→#UD"且non-root无条件
//VMexit——与VMXOFF同族, 缺case=落default'U'逃生(病毒DoS面)
#define EXIT_REASON_INVEPT              50
#define EXIT_REASON_INVVPID             53
#define EXIT_REASON_WBINVD              54
#define EXIT_REASON_XSETBV              55
//VMFUNC失败exit(SDM §28.5.7.2/28.5.7.3: 函数未启用/EAX无效/EPTP-list
//项非法/ECX>=512 → VM-exit reason 59, **绝非#UD**)
#define EXIT_REASON_VMFUNC              59
#define VMX_MAX_GUEST_VMEXIT	EXIT_REASON_VMFUNC

//vmresume失败处理(asm调用, noreturn): 'R'标记入环后逃生(vmx_off+跳回guest)
void VmxResumeFailedEntry(void);
//EPT事件风暴逃生(noreturn): 标记入环后vmx_off脱离VT, 跳回guest
//触发点重执行(RIP不推进——逃生场景指令均未成功执行)。
//停核方案被否决: 停核会级联冻结日志通道(磁盘中断落停核永不完成→
//ZwWriteFile挂死→死因困在内存环=零信息冻结)。
//tag: 'X'=violation/misconfig风暴 'A'=动态建表失败 'P'=低地址环路
//     'D'=同(reason,rip)通用环路 'Z'=len0未知exit 'U'=len>0未知exit
//     'R'=vmresume失败 'G'=VM-entry failure(guest状态非法, 主线程走失败分支)
//     'J'=ext-int exit意外到达风暴(pin=0直投下理论不可达, 到达=
//         配置未生效, case1防御>100次触发)
//guestRegs参数: 非NULL=从exit handler的C上下文调用(帧上保存着guest
//全部GPR), 跳回前用VmxJumGuestRegs恢复非易失GPR——不恢复则调用者拿
//handler残留垃圾寄存器继续跑(卸载蓝屏0x7E根因, 见vmx-asm.asm
//VmxJumGuestRegs注释); NULL=寄存器已被asm pop链恢复的路径
//(VmxResumeFailedEntry), 直接切栈跳
void VmxExitStormEscape(char tag, ULONG reason, ULONG64 a, ULONG64 b,
    PVOID guestRegs);
//C上下文vmx_off跳回guest的出口——从GuestRegs帧恢复全部非易失
//GPR(rbx/rbp/rsi/rdi/r12-r15)后再切RSP/JMP(见vmx-asm.asm详注)
void VmxJumGuestRegs(PVOID guestRegs, ULONG64 targetRsp, ULONG64 targetRip);
//lgdt/lidt——rcx=10字节描述符(WORD limit@+0, QWORD base@+2)。
//VM-exit把GDTR/IDTR limit强制0xFFFF(host-state无limit字段), vmx_off
//回真机前须还原guest原limit
void VmxLoadGdtr(PVOID descriptor);
void VmxLoadIdtr(PVOID descriptor);
//三重故障专用park(noreturn): guest不可恢复(重执行=真机三重故障
//=重启)。vmx_off+清EOI债+sti/hlt自旋——本核继续服务中断(IPI等待者
//解除, 级联冻结被切断), 'T'标记+环尾由T1落盘; 本核永久park, 驱动
//不得卸载(g_geptParkedMask守卫)
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
    //hooked视图EPT(clean=PeptData, violation方案兼容/兜底)。guest默认
    //在clean视图; hook安装时VMM在exit上下文vmwrite(EPT_POINTER,
    //EptpHooked)切入hooked视图(SDM §28.5.7.3: VMFUNC切换会写回
    //EPT_POINTER字段=两通道同义), hook页在hooked EPT里PTE→CodePage
    //(X=1,R=1,W=0)=执行零VM-Exit; clean视图下原页字节完好(读/写看到
    //的都是原始字节, 隐蔽性根基)。深拷贝时pdpte/pde自指物理地址全部
    //重指hooked自己的表(ept.c EptInitHookedEptData)
    PEPT_DATA PeptDataHooked;
    EPT_EPTP EptpHooked;
    //EPTP-list页(4KB物理连续+对齐, MmAllocateContiguousMemory保证)。
    //list[0]=clean EPTP, list[1]=hooked EPTP。VMFUNC(0,idx)在guest内
    //切换EPTP=零VM-Exit的视图切换(零VM-Exit hook的基石)
    PVOID VmfuncEptpList;
    PVOID HighPdptVa[512];      //动态建立的pml4[i>0]对应pdpt页的虚拟地址(>512GB MMIO区)
    PVOID HighPdptRawVa[512];   //上述pdpt的原始pool指针(4KB对齐后无法反推raw, 卸载时用它ExFreePool)
    volatile LONG bInGuest;     //该CPU已成功进入VMX non-root(卸载时用于判断能否vmcall)
    volatile LONG bLaunchFailed;//vmlaunch失败标志(区分fall-through路径)
    volatile LONG bVmxOn;       //该CPU的__vmx_on已成功(卸载时需vmx_off+清CR4.VMXE)
    volatile LONG bVmfuncOn;    //该核VMFUNC已启用(ctls2 bit13实际写入成功); guest内执行vmfunc的前提, 否则#UD蓝屏
    //已ack未投递的中断计数(历史遗留: interrupt-window模式用)。
    //当前直投模式下恒0, 保留给EOI清债路径判断
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
void VmxStopCpu();                      //串行模式(同上): 该核退出VT(vmcall/vmx_off+清VMXE); 主卸载路径已退役(仅全败路径防御性保留)
//全核IPI原子退出(KeIpiGenericCall广播处理程序, DriverUload在PASSIVE
//调用)——每核在IPI_LEVEL上下文原子完成自己的VT退出+清VMXE+双PGE
//冲刷, 零调度零窗口(机理见VMX.c实现注释); IPI内纪律=只FlRingPush('v')
ULONG64 VmxStopAllIpi(ULONG_PTR Argument);
int VmxSetupVmcs();
void VmxFillSelectorData();
//控制字段计算(经典公式, 对新旧MSR均正确): (MSR低32|期望)&高32。
//低32=必须为1的位, 高32=允许为1的位; TRUE MSR(0x48D-0x490)与旧式MSR
//(0x481-0x484)位语义相同(勿用补码公式, 见VMX.c实现注释)
ULONG VmxMsrAdjuest(ULONG64 msrNum, ULONG controlValue);
//TSC补偿(隐藏; vmx-asm.asm VmxVmexitHandler每exit调用)——
//TSC_OFFSET -= exit驻留时长, guest的RDTSC/RDTSCP读数扣掉exit时间
void VmxTscCompensate(ULONG64 entryTsc, ULONG64 exitTsc);
void VmxVmexitHandler();
void VmxExitHandler();
void VmxJumGuest(ULONG64 targetRsp, ULONG64 targetRip);
void VmxFreeCpuResources(ULONG cpuNumber);  //PASSIVE_LEVEL: 释放指定CPU的全部VT资源
void VmxInvd();
BOOLEAN VmxInvept(INVEPT_TYPE type, PEPT_CTX ctx);  //返回TRUE=VMfail(失败)

#endif // VMX_H
