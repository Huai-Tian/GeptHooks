#include"common.h"
#include"winApiDef.h"
#include"CPU.h"
#include"VMX.h"
BOOLEAN CommCheckBios()
{
	ULONG64 bios = __readmsr(MSR_IA32_FEATURE_CONTROL);
	ULONG64 result = bios & 5;
	if (result == 5)
	{
		return TRUE;
	}
	return FALSE;
}

BOOLEAN CommCheckCpuid()
{
	int cpuinfo[4] = { 0 };
	__cpuidex(cpuinfo, 1, 0);
	return (cpuinfo[2] >> 5) & 1;
}

BOOLEAN CommCheckCr4()
{
	ULONG64 cr4 = __readcr4();
	cr4 = cr4 >> 13;
	if ((cr4 & 1) == 0)
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
	BOOLEAN bbios = CommCheckBios();
	BOOLEAN bcpuid = CommCheckCpuid();
	BOOLEAN bcr4 = CommCheckCr4();
	Log("cpu%d bbios=%d bcpuid=%d bcr4=%d",
		KeGetCurrentProcessorNumber(), bbios, bcpuid, bcr4);
	if (bbios && bcpuid && bcr4)
	{
		//内存已在DriverEntry(PASSIVE_LEVEL)预分配, 这里只做vmxon/vmlaunch
		VMXInitCpuStart();
	}
	else
	{
		Log("cpu%d VT环境检查未通过, 跳过启动", KeGetCurrentProcessorNumber());
	}
	//KeGenericCallDpc约定这两个参数非空, 判空仅为满足SAL静态分析
	if (SystemArgument1)
	{
		KeSignalCallDpcDone(SystemArgument1);
	}
	if (SystemArgument2)
	{
		KeSignalCallDpcSynchronize(SystemArgument2);
	}
}

void CommVtShutDown(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	ULONG cpuNumber = KeGetCurrentProcessorNumber();
	if (g_vcpu[cpuNumber].bInGuest)
	{
		//成功进入guest的核: vmcall退出(handler内vmx_off后跳回此处)
		CmVmCall(1, 0, 0, 0);
	}
	else if (g_vcpu[cpuNumber].bVmxOn)
	{
		//vmlaunch失败但vmxon成功的核: 仍在root, 直接off
		__vmx_off();
	}
	if (g_vcpu[cpuNumber].bVmxOn)
	{
		//清CR4.VMXE, 恢复干净状态
		ULONG64 cr4 = __readcr4();
		cr4 &= ~0x2000;
		__writecr4(cr4);
		g_vcpu[cpuNumber].bVmxOn = 0;
	}
	//KeGenericCallDpc约定这两个参数非空, 判空仅为满足SAL静态分析
	if (SystemArgument1)
	{
		KeSignalCallDpcDone(SystemArgument1);
	}
	if (SystemArgument2)
	{
		KeSignalCallDpcSynchronize(SystemArgument2);
	}
}

