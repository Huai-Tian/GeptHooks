#pragma once
#ifndef COMMON_H
#define COMMON_H
#include<ntifs.h>
#include<ntddk.h>
#include<intrin.h>
#define Log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[VT][%s]: " format "\n", __FUNCTION__, ##__VA_ARGS__)

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct _GUEST_REGS
	{
		ULONG64 rax;
		ULONG64 rcx;
		ULONG64 rdx;
		ULONG64 rbx;
		ULONG64 rsp;
		ULONG64 rbp;
		ULONG64 rsi;
		ULONG64 rdi;
		ULONG64 r8;
		ULONG64 r9;
		ULONG64 r10;
		ULONG64 r11;
		ULONG64 r12;
		ULONG64 r13;
		ULONG64 r14;
		ULONG64 r15;
	} GUEST_REGS, * PGUEST_REGS;

	typedef struct
	{
		USHORT sel;
		USHORT attributes;
		ULONG32 limit;
		ULONG64 base;
	} SEGMENT_SELECTOR;

#pragma warning(push)
#pragma warning(disable: 4201)
	typedef struct
	{
		USHORT LimitLow;
		USHORT BaseLow;
		UCHAR BaseMid;
		UCHAR AttributesLow;
		struct
		{
			UCHAR LimitHigh : 4;
			UCHAR AttributesHigh : 4;
		};
		UCHAR BaseHigh;
	} SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;
#pragma warning(pop)

	BOOLEAN CommCheckBios();
	BOOLEAN CommCheckCpuid();
	BOOLEAN CommCheckCr4();

	void CommVtStart(
		_In_ struct _KDPC* Dpc,
		_In_opt_ PVOID DeferredContext,
		_In_opt_ PVOID SystemArgument1,
		_In_opt_ PVOID SystemArgument2
	);

	void CommVtShutDown(
		_In_ struct _KDPC* Dpc,
		_In_opt_ PVOID DeferredContext,
		_In_opt_ PVOID SystemArgument1,
		_In_opt_ PVOID SystemArgument2
	);

	void CmGeustRip();
	void CmGuestRsp();
	void CmVmCall(ULONG opcode, ULONG64 arg2, ULONG64 arg3, ULONG64 arg4);

#ifdef __cplusplus
}
#endif

#endif // COMMON_H
