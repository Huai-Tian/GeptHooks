#include"common.h"
#include"winApiDef.h"
#include"CPU.h"
#include"VMX.h"
BOOLEAN CommCheckBios()
{
	ULONG64 bios=__readmsr(MSR_IA32_FEATURE_CONTROL);
	ULONG64 result = bios & 5;
	if (result==5)
	{
		return TRUE;
	}
	return FALSE;
}

BOOLEAN CommCheckCpuid()
{
	int cpuinfo[4] = {0};
	__cpuidex(cpuinfo,1,0);
	return (cpuinfo[2] >> 5) & 1;
}

BOOLEAN CommCheckCr4()
{
	ULONG64 cr4 = __readcr4();
	cr4 = cr4 >> 13;
	if ((cr4&1)==0)
	{
		return TRUE;
	}
	return FALSE;
}

void CommVtStart(
	_In_ struct _KDPC* Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
)
{
	//释放申请内存
	
	BOOLEAN bbios=CommCheckBios();
	BOOLEAN bcpuid = CommCheckCpuid();
	BOOLEAN bcr4 = CommCheckCr4();
	DbgPrint("current cpuNumber=%d,bbios=%d,bcpuid=%d,bcr4=%d",
		KeGetCurrentProcessorNumber(), bbios, bcpuid, bcr4);
	VMXInitCpu();
	KeSignalCallDpcDone(SystemArgument1);
	KeSignalCallDpcSynchronize(SystemArgument2);
}

void CommVtShutDown(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	//关闭VT
	CmVmCall(1,0,0,0);
	//释放内存
	VmxFreeMemery();
	KeSignalCallDpcDone(SystemArgument1);
	KeSignalCallDpcSynchronize(SystemArgument2);
}

