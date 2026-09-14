#pragma once
#ifndef PAGEHOOK_H
#define PAGEHOOK_H
#include<ntifs.h>

NTSTATUS PHHook(PVOID pFun, PVOID pHook);

#pragma pack(push,1)
typedef struct _JMP_OPCODE64
{
	UCHAR pushOp;
	ULONG jmpAddressLow;
	ULONG movOp;
	ULONG jmpAddressHigh;
	UCHAR retOp;
}JMP_OPCODE64, * PJMP_OPCODE64;
#pragma pack(pop)

typedef struct _PAGE_HOOK_ENTRY
{
	PVOID OriginalPtr;//原函数地址
	PVOID OriginalPageVA;//原函数所在页的起始地址
	PVOID OriginalPagePFN;//原函数所在页的物理地址
	PVOID CodePageVA;//copy函数所在页首地址
	LIST_ENTRY link;
	PVOID CodePagePFN;//copy函数所在页的物理地址
}PAGE_HOOK_ENTRY, * PPAGE_HOOK_ENTRY;

typedef struct _HOOK_CONTEXT
{
	ULONG64 OriginalPagePFN;
	ULONG64 CodePagePFN;
}HOOK_CONTEXT, * PHOOK_CONTEXT;

void PHInitJmpCode(PJMP_OPCODE64 jmpCode, ULONG64 jmpTo);
ULONG PHGetHookLen(ULONG64 codeAddr, ULONG codeSize, BOOLEAN is64);
PPAGE_HOOK_ENTRY PHGetHookEntryPage(PVOID funAddr);
PPAGE_HOOK_ENTRY PHGetHookEntryPageBy(ULONG64 gpa);
VOID PHHookCallBackDpc(_In_ struct _KDPC* Dpc, _In_opt_ PVOID DeferredContext, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2);

#endif // PAGEHOOK_H
