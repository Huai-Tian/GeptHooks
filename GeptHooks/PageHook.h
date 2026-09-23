#pragma once
#ifndef PAGEHOOK_H
#define PAGEHOOK_H
#include<ntifs.h>

NTSTATUS PHHook(PVOID pFun, PVOID pHook, ULONG hideRead);

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
	ULONG HideRead;//1=该页按读透明布防(EptExitHandler的MTF路径判据)
}PAGE_HOOK_ENTRY, * PPAGE_HOOK_ENTRY;

typedef struct _HOOK_CONTEXT
{
	ULONG64 OriginalPagePFN;
	ULONG64 CodePagePFN;
	ULONG64 HideRead;
}HOOK_CONTEXT, * PHOOK_CONTEXT;

void PHInitJmpCode(PJMP_OPCODE64 jmpCode, ULONG64 jmpTo);
ULONG PHGetHookLen(ULONG64 codeAddr, ULONG codeSize, BOOLEAN is64);
PPAGE_HOOK_ENTRY PHGetHookEntryPage(PVOID funAddr);
PPAGE_HOOK_ENTRY PHGetHookEntryPageBy(ULONG64 gpa);
VOID PHHookCallBackDpc(_In_ struct _KDPC* Dpc, _In_opt_ PVOID DeferredContext, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2);

//KeGenericCallDpc族=未文档化内核导出(WDK无声明, 签名源=ReactOS NDK),
//显式原型消除隐式声明警告
VOID KeGenericCallDpc(_In_ PKDEFERRED_ROUTINE Routine, _In_opt_ PVOID Context);
VOID KeSignalCallDpcDone(_In_ PVOID SystemArgument1);
LOGICAL KeSignalCallDpcSynchronize(_In_ PVOID SystemArgument2);

//LDE重定位生成器: 复制目标prologue≥MinLen字节到可执行缓冲并重定位
//RIP-relative, 尾接jmp回Target+Len(经典Detours语义, 版本无关)。
//失败返回NULL(相对分支/超±2GB/自检不符=拒绝)
PVOID PHBuildRelocTrampoline(ULONG64 Target, ULONG MinLen, PULONG OutLen);
//卸载终清理(VT已关后调用, 幂等): CodePage+hook条目清零释放
VOID PHFreeAllMemory(VOID);

#endif // PAGEHOOK_H
