#pragma once
#include<ntifs.h>
#include<ntddk.h>
#include<intrin.h>
#define Log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[VT][%s]: " format "\n", __FUNCTION__, ##__VA_ARGS__)

#define MSR_IA32_FEATURE_CONTROL 0x3a

typedef struct {
	USHORT sel;
	USHORT attributes;
	ULONG32 limit;
	ULONG64 base;
} SEGMENT_SELECTOR;
#pragma warning(push)
#pragma warning(disable: 4201)
typedef struct {
    USHORT LimitLow;
    USHORT BaseLow;
    UCHAR BaseMid;
    UCHAR AttributesLow;
    struct {
        UCHAR LimitHigh : 4;
        UCHAR AttributesHigh : 4;
    };
    UCHAR BaseHigh;
} SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;
#pragma warning(pop)
BOOLEAN CommCheckBios();
BOOLEAN CommCheckCpuId();
BOOLEAN CommCheckCr4();
VOID CommVtStart(_In_ struct _KDPC* Dpc, _In_opt_ PVOID DeferredContext, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2);