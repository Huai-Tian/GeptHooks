#pragma once
#ifndef EPT_H
#define EPT_H
#include<ntifs.h>
#include"common.h"
#include"PageHook.h"
#define EPT_PREALLOC_PAGES 512
typedef union _EPT_EPTP
{
	ULONG64 ALL;
	struct
	{
		ULONG64 memoryType : 3;    //bits 2:0   EPT页表内存类型(0=UC 6=WB)
		ULONG64 walkLen : 3;       //bits 5:3   页表级数-1, 4级EPT必须填3(SDM 29.2.1.1)
		ULONG64 dirty : 1;         //bit 6      accessed/dirty标志
		ULONG64	reseved1 : 5;      //bits 11:7  保留, 必须为0
		ULONG64 physicalAddr : 40; //bits 51:12 PML4表物理地址
		ULONG64	reseved2 : 12;
	}fileds;
}EPT_EPTP, * PEPT_EPTP;

typedef union _EPT_PML4
{
	ULONG64 ALL;
	struct
	{
		ULONG64 present : 1;
		ULONG64 write : 1;
		ULONG64	execute : 1;
		ULONG64 reseved1 : 5;
		ULONG64	accessd : 1;
		ULONG64 reseved2 : 3;
		ULONG64	physicalAddr : 40;
		ULONG64	reseved3 : 12;
	}fileds;
}EPT_PML4, * PEPT_PML4;

typedef union _EPT_PDPTE
{
	ULONG64 ALL;
	struct
	{
		ULONG64 present : 1;
		ULONG64 write : 1;
		ULONG64	execute : 1;
		ULONG64 reseved1 : 5;
		ULONG64	accessd : 1;
		ULONG64 reseved2 : 3;
		ULONG64	physicalAddr : 40;
		ULONG64	reseved3 : 12;
	}fileds;
}EPT_PDPTE, * PEPT_PDPTE;
typedef union _EPT_PDPTE_1G
{
	ULONG64 ALL;
	struct
	{
		ULONG64 present : 1;
		ULONG64 write : 1;
		ULONG64	execute : 1;
		ULONG64 memoryType : 3;
		ULONG64	pat : 1;
		ULONG64 largePage : 1;
		ULONG64	accessed : 1;
		ULONG64	dirty : 1;
		ULONG64	reseved2 : 20;
		ULONG64	physicalAddr : 18;
		ULONG64	reseved3 : 16;
	}fileds;
}EPT_PDPTE_1G, * PEPT_PDPTE_1G;


typedef union _EPT_PDE
{
	ULONG64 ALL;
	struct
	{
		ULONG64 read : 1;
		ULONG64 write : 1;
		ULONG64	execute : 1;
		ULONG64 reseved1 : 5;
		ULONG64	accessd : 1;
		ULONG64 reseved2 : 1;
		ULONG64 userModeExecute : 1;
		ULONG64	reseved3 : 1;
		ULONG64	physicalAddr : 36;
		ULONG64	reseved4 : 16;
	}fileds;
}EPT_PDE, * PEPT_PDE;

typedef union _EPT_PDE_2M
{
	ULONG64 ALL;
	struct
	{
		ULONG64 present : 1;
		ULONG64 write : 1;
		ULONG64	execute : 1;
		ULONG64 memoryType : 3;
		ULONG64	pat : 1;
		ULONG64 ps : 1;
		ULONG64	accessed : 1;
		ULONG64	dirty : 1;
		ULONG64	reseved2 : 11;
		ULONG64	physicalAddr : 27;
		ULONG64	reseved3 : 16;
	}fileds;
}EPT_PDE_2M, * PEPT_PDE_2M;

typedef union _EPT_PTE
{
	ULONG64 ALL;
	struct
	{
		ULONG64 present : 1;
		ULONG64 write : 1;
		ULONG64	execute : 1;
		ULONG64 memoryType : 3;
		ULONG64	pat : 1;
		ULONG64 reseved1 : 1;
		ULONG64	accessed : 1;
		ULONG64	dirty : 1;
		ULONG64	reseved2 : 2;
		ULONG64	physicalAddr : 40;
		ULONG64	reseved3 : 12;
	}fileds;
}EPT_PTE, * PEPT_PTE;

typedef struct _EPT_DATA
{
	EPT_PML4 pml4[EPT_PREALLOC_PAGES];
	EPT_PDPTE pdpte[EPT_PREALLOC_PAGES];
	EPT_PDE_2M pde[EPT_PREALLOC_PAGES][EPT_PREALLOC_PAGES];
}EPT_DATA, * PEPT_DATA;

typedef union _EPT_EXITDATA
{
	ULONG64 ALL;
	struct
	{
		ULONG64 read : 1;
		ULONG64 write : 1;
		ULONG64	execute : 1;
		ULONG64 readable : 1;
		ULONG64	writeable : 1;
		ULONG64	executeable : 1;
		ULONG64 reseved1 : 1;
		ULONG64	valid : 1;
		ULONG64	translation : 1;
		ULONG64	reseved2 : 3;
		ULONG64	NMIunblocking : 1;
		ULONG64	reseved3 : 51;
	}fileds;
}EPT_EXITDATA, * PEPT_EXITDATA;

NTSTATUS EptInitEptData(ULONG cpuNumber);
//释放共享高区页表+双EPT标记页(DriverUload/回滚调用, 幂等)
VOID EptShutdownHighMappings(VOID);
//vmlaunch前EPT软件自检: 返回失败项数(0=通过), 含hooked EPT的
//[7][8][9]项; VmxSetupVmcs据此决定是否放弃vmlaunch
ULONG EptVerifyTables(ULONG cpuNumber, ULONG64 guestRspVa);
void EptExitHandler(PGUEST_REGS GuestRegs);
//hideRead: 1=hooked视图hook页R=0(exec-only)——读/写violation→切clean+MTF
//单步透出原始字节(读透明)。需CPU exec-only支持(g_bEptExecOnly), 否则回退R=1
void EptSetHook(ULONG64 orginalPagePFN, ULONG64 codePagePFN, ULONG64 hideRead);
//walker带显式PEPT_DATA参数(须明确目标视图): clean=g_vcpu[n].PeptData,
//hooked=g_vcpu[n].PeptDataHooked, 当前视图=EptGetActiveData()
PEPT_PDE_2M EptGetPde2B(PEPT_DATA ept, ULONG64 PFN);
BOOLEAN EptPdeToPte(PEPT_PDE_2M pde2M);
PEPT_PTE EptGetPte(PEPT_DATA ept, ULONG64 PFN);
void EptUpdatePageAcess(PEPT_DATA ept, ULONG64 gpa, UCHAR acess, PPAGE_HOOK_ENTRY pageEntry);
//本核当前视图的EPT(vmread EPT_POINTER比对, 仅VMX root上下文可调)
PEPT_DATA EptGetActiveData(VOID);
VOID EptInveptCurrent(VOID);   //统一invept入口(能力探测+EPTP填充+VMfail留痕)
VOID EptInveptBothViews(VOID); //vmx_off前双视图invept(all-context短路; single-context型CPU逐视图失效)
BOOLEAN EptBuildHighMapping(ULONG64 gpa);
//EPT自我隐蔽: 每核vmlaunch前(须在EptVerifyTables后)把全部框架私有
//物理页(VMXON/VMCS/VMM栈/MSR位图/EPT表/EPTP-list/高区pdpt/标记页/
//拆分pte页)在两套视图统一改译零页——root与硬件walker按HPA直访
//不受影响, guest物理扫描只见零
VOID EptHideFrameworkPages(ULONG cpuNumber);
//CodePage物理隐蔽(vmcall(12)root侧, 每核调用): hide=1改译零页/
//0恢复恒等。仅VMFUNC核; Remove释放CodePage前必须恢复(PFN复用)
BOOLEAN EptHideCodePageGpa(ULONG64 gpa, BOOLEAN hide);
//释放全部拆分pte页(vmx_off后/回滚, EptShutdownHighMappings内调用)
VOID EptFreeSplitPtes(VOID);
extern BOOLEAN g_bEpt1GbPage;
//EPT_VPID_CAP(0x48C) bit0: exec-only页(X=1,R=0)支持——HideRead的前提
extern BOOLEAN g_bEptExecOnly;

//==== 双EPT标记页 ====
//hooked EPT把pageA改译到pageB: guest读同一VA, clean=GEPT_MARK_A /
//hooked=GEPT_MARK_B=双EPT独立翻译的软件验证。全核共用, 随高区释放
extern PVOID g_geptMarkVA;         //pageA虚拟地址(GPA=PA_A恒等, 自测读它)
extern ULONG64 g_geptMarkPaB;      //pageB物理地址(hooked视图翻译目标)
#define GEPT_MARK_A 0x5450454E41454C43ULL   //小端内存=ASCII "CLEANEPT"
#define GEPT_MARK_B 0x545044454B4F4F48ULL   //小端内存=ASCII "HOOKEDPT"

#endif // EPT_H