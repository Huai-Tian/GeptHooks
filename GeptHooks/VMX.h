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
#define VMX_MAX_GUEST_VMEXIT	EXIT_REASON_TPR_BELOW_THRESHOLD
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
    PVOID HighPdptVa[512];      //动态建立的pml4[i>0]对应pdpt页的虚拟地址(>512GB MMIO区)
    volatile LONG bInGuest;     //该CPU已成功进入VMX non-root(卸载时用于判断能否vmcall)
    volatile LONG bLaunchFailed;//vmlaunch失败标志(区分fall-through路径)
    volatile LONG bVmxOn;       //该CPU的__vmx_on已成功(卸载时需vmx_off+清CR4.VMXE)
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
int VMXInitCpuStart();                  //DPC(目标核): vmxon+vmptrld+vmlaunch
int VmxSetupVmcs();
void VmxFillSelectorData();
ULONG VmxMsrAdjuest(ULONG64 msrNum, ULONG controlValue);
void VmxVmexitHandler();
void VmxExitHandler();
void VmxJumGuest(ULONG64 targetRsp, ULONG64 targetRip);
void VmxFreeCpuResources(ULONG cpuNumber);  //PASSIVE_LEVEL: 释放指定CPU的全部VT资源
void VmxInvd();
void VmxSetMsrRw(ULONG64 msrNum, UCHAR rw, BOOLEAN flag);
void VmxInvept(INVEPT_TYPE type, PEPT_CTX ctx);

#endif // VMX_H

