#include"VMX.h"
#include"CPU.h"
#include"reg.h"
#include"common.h"
#include<intrin.h>
VCPU g_vcpu[128];
int VMXInitCpu()
{
	ULONG cpuNumber = KeGetCurrentProcessorNumber();
	VCPU currentCpu = g_vcpu[cpuNumber];
	PHYSICAL_ADDRESS phys = { 0 };
	PHYSICAL_ADDRESS physVmon = { 0 };
	PHYSICAL_ADDRESS physVmcs = { 0 };
	phys.QuadPart = MAXULONG64;
	PVMX_VMCS pvmxon = (PVMX_VMCS)MmAllocateContiguousMemory(sizeof(VMX_VMCS), phys);
	PVMX_VMCS pvmcs = (PVMX_VMCS)MmAllocateContiguousMemory(sizeof(VMX_VMCS), phys);
	if (pvmxon == NULL || pvmcs == NULL) return 1;
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
	physVmcs = MmGetPhysicalAddress(pvmcs);
	ULONG vmonResult = __vmx_on((unsigned __int64*)&physVmon);
	if (vmonResult)return vmonResult;
	__vmx_vmclear((unsigned __int64*)&physVmcs);
	__vmx_vmptrld((unsigned __int64*)&physVmcs);
	//Ìî³äVMCS
}

int VMXSetupVmcs()
{

	__vmx_vmlaunch();
	return 0;
}

void VMXFillSelectorData(USHORT selector, USHORT index)
{
	SEGMENT_SELECTOR segmentSelector = { 0 };
	segmentSelector.sel = selector;
	segmentSelector.limit = __segmentlimit(segmentSelector.sel);
	segmentSelector.base = 0;
	//Gdt±í
	ULONG64 gdtBase = GetGdtBase();
	//»ñÈ¡¶ÎÃèÊö·û
	PSEGMENT_DESCRIPTOR segmentDes = (PSEGMENT_DESCRIPTOR)(gdtBase + segmentSelector.sel & 0xFFF8);
	segmentSelector.base = segmentDes->BaseHigh << 24 | segmentDes->BaseMid << 16 | segmentDes->BaseLow;
	segmentSelector.attributes = segmentDes->BaseHigh << 8 | segmentDes->AttributesLow;
	if (segmentSelector.attributes & 0x800) {
		segmentSelector.limit = segmentSelector.limit << 12 + 0xFFF;
	}
	__vmx_vmwrite(GUEST_ES_SELECTOR + index * 2, segmentSelector.sel);
	__vmx_vmwrite(GUEST_ES_LIMIT + index * 2, segmentSelector.limit);
	__vmx_vmwrite(GUEST_ES_BASE + index * 2, segmentSelector.base);
	__vmx_vmwrite(GUEST_ES_AR_BYTES + index * 2, segmentSelector.attributes);
	//RIP RSP
}
