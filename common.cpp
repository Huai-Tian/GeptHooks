#include"common.h"
#include"winApiDef.h"
BOOLEAN CommCheckBios()
{
	ULONG64 bios = __readmsr(MSR_IA32_FEATURE_CONTROL);
	ULONG64 result = bios & 5;
	return result == 5;
}

BOOLEAN CommCheckCpuId()
{
	int cpuInfo[4] = { 0 };
	__cpuidex(cpuInfo, 1, 0);
	return (cpuInfo[2] >> 5) & 1;
}

BOOLEAN CommCheckCr4()
{
	ULONG64 cr4 = __readcr4();
	cr4 = cr4 >> 13;
	return (cr4 & 1) == 0;
}

VOID CommVtStart(_In_ struct _KDPC* Dpc, _In_opt_ PVOID DeferredContext, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);
	BOOLEAN bios = CommCheckBios();
	BOOLEAN cpuId = CommCheckCpuId();
	BOOLEAN cr4 = CommCheckCr4();
	Log("current cpuNumber=%d, bios=%d, cpuid=%d, cr4=%d", 
		KeGetCurrentProcessorNumber(), bios, cpuId, cr4);
	KeSignalCallDpcDone(SystemArgument1);
	KeSignalCallDpcSynchronize(SystemArgument2);
}
