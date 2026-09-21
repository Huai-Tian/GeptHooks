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

//KeGenericCallDpc族原型显式化——三个函数是**未文档化**内核导出
//(Microsoft Learn无页面; NT5.2的"Generic DPC"全核DPC回调机制),
//**WDK公共wdm.h无声明**——权威签名源=ReactOS NDK
//(sdk/include/ndk/kefuncs.h, NDK专收未文档化API; ntoskrnl.lib导出)。
//不显式声明则靠C隐式声明调用(构建产生C4013等警告; 链接期按导出
//符号解析恰好正确, 但显式原型一次根除)。
//签名与潜在的未来声明兼容(LOGICAL与BOOLEAN同为UCHAR, typedef名
//不参与C类型兼容性判定)
VOID KeGenericCallDpc(_In_ PKDEFERRED_ROUTINE Routine, _In_opt_ PVOID Context);
VOID KeSignalCallDpcDone(_In_ PVOID SystemArgument1);
LOGICAL KeSignalCallDpcSynchronize(_In_ PVOID SystemArgument2);

//LDE重定位生成器——把目标函数前≥MinLen字节的prologue复制到可执行
//缓冲并重定位RIP-relative, 尾接jmp回Target+Len。
//violation方案"版本无关化"的核心(硬编码重放会绑定特定Windows构建)。
//失败返回NULL(保守策略: 相对分支/RIP-relative超±2GB/回扫自检不符
//=拒绝, 绝不带病上机)。调用它=执行原prologue后进入原函数体并正常
//返回(经典Detours语义)
PVOID PHBuildRelocTrampoline(ULONG64 Target, ULONG MinLen, PULONG OutLen);

#endif // PAGEHOOK_H
