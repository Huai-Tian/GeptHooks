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

//v3.50: KeGenericCallDpc族原型显式化——三个函数是**未文档化**内核导出
//(Microsoft Learn无页面, 2026-09-20实测404; NT5.2的"Generic DPC"全核
//DPC回调机制), **WDK公共wdm.h无声明**——权威签名源=ReactOS NDK
//(sdk/include/ndk/kefuncs.h, NDK专收未文档化API; ntoskrnl.lib导出)。
//此前v3.41起PageHook.c靠C隐式声明调用(每次构建产生C4013警告+
//6条转换警告, 但非错误: 链接期ntoskrnl.lib按导出符号解析, x64统一
//调用约定+全指针参数恰好正确, 故v3.41-v3.49全部构建与上机有效);
//v3.50 GeptApi.c同款调用令警告翻倍显眼——显式原型一次根除。
//签名与潜在的未来声明兼容(LOGICAL与BOOLEAN同为UCHAR, typedef名
//不参与C类型兼容性判定)
VOID KeGenericCallDpc(_In_ PKDEFERRED_ROUTINE Routine, _In_opt_ PVOID Context);
VOID KeSignalCallDpcDone(_In_ PVOID SystemArgument1);
LOGICAL KeSignalCallDpcSynchronize(_In_ PVOID SystemArgument2);

#endif // PAGEHOOK_H
