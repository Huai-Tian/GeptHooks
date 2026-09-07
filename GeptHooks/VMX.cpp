#include"VMX.h"
#include"CPU.h"
#include<intrin.h>
VCPU g_vcpu[128];
int VMXInitCpu()
{
	ULONG cpuNumber = KeGetCurrentProcessorNumber();
	VCPU currentCpu = g_vcpu[cpuNumber];
	PHYSICAL_ADDRESS phys = { 0 };
	PHYSICAL_ADDRESS physVmon = { 0 };
	phys.QuadPart = MAXULONG64;
	PVMX_VMCS pvmxon = (PVMX_VMCS)MmAllocateContiguousMemory(sizeof(VMX_VMCS), phys);
	PVMX_VMCS pvmcs = (PVMX_VMCS)MmAllocateContiguousMemory(sizeof(VMX_VMCS), phys);
	if (pvmxon == NULL || pvmcs == NULL)
	{
		return 1;
	}
	RtlZeroMemory(pvmxon, sizeof(VMX_VMCS));
	RtlZeroMemory(pvmcs, sizeof(VMX_VMCS));
	pvmxon->RevisionId = (ULONG)__readmsr(MSR_IA32_VMX_BASIC);
	pvmcs->RevisionId = (ULONG)__readmsr(MSR_IA32_VMX_BASIC);
	currentCpu.VMXON = pvmxon;
	currentCpu.VMCS = pvmcs;
	ULONG64 cr4 = __readcr4();
	cr4 |= MSR_IA32_VMX_CR4_FIXED0;
	cr4 &= MSR_IA32_VMX_CR4_FIXED1;
	ULONG64 cr0 = __readcr0();
	cr0 |= MSR_IA32_VMX_CR0_FIXED0;
	cr0 &= MSR_IA32_VMX_CR0_FIXED1;
	physVmon = MmGetPhysicalAddress(pvmxon);
	return __vmx_on((unsigned __int64*)&physVmon);
}