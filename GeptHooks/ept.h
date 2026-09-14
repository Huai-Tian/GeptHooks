#pragma once
#include<ntifs.h>
#include"common.h"
#include"PageHook.h"
#define EPT_PREALLOC_PAGES 512
typedef union _EPT_EPTP
{
	ULONG64 ALL;
	struct  
	{
		ULONG64 memoryType : 3;
		ULONG64 walkLen : 3;
		ULONG64 dirty : 1;
		ULONG64	reseved1 : 5;
		ULONG64 physicalAddr : 40;
		ULONG64 reseved2 : 12;
	}fileds;
}EPT_EPTP,*PEPT_EPTP;

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
}EPT_PML4,*PEPT_PML4;

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
}EPT_PDPTE,*PEPT_PDPTE;
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
}EPT_PDE,*PEPT_PDE;

typedef union _EPT_PDE_2M
{
	ULONG64 ALL;
	struct
	{
		ULONG64 present :1;
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
}EPT_PTE,*PEPT_PTE;

typedef struct _EPT_DATA
{
	EPT_PML4 pml4[EPT_PREALLOC_PAGES];
	EPT_PDPTE pdpte[EPT_PREALLOC_PAGES];
	EPT_PDE_2M pde[EPT_PREALLOC_PAGES][EPT_PREALLOC_PAGES];
}EPT_DATA,*PEPT_DATA;

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

NTSTATUS EptInitEptData();
void EptExitHandler(PGUEST_REGS GuestRegs);
void EptSetHook(ULONG64 orginalPagePFN,ULONG64 codePagePFN);
PEPT_PDE_2M EptGetPde2B(ULONG64 PFN);
BOOLEAN EptPdeToPte(PEPT_PDE_2M pde2M);
PEPT_PTE EptGetPte(ULONG64 PFN);
void EptUpdatePageAcess(ULONG64 gpa,UCHAR acess,PPAGE_HOOK_ENTRY pageEntry);