#include"VMX.h"
#include"CPU.h"
#include"reg.h"
#include"common.h"
#include<intrin.h>
VCPU g_vcpu[128];

PVCPU VmxGetCurrentVcpu(ULONG cpuNumber)
{
	return &g_vcpu[cpuNumber];
}
int VMXInitCpu()
{
	ULONG cpuNumber = KeGetCurrentProcessorNumber();
	VCPU currentCpu = g_vcpu[cpuNumber];
	PHYSICAL_ADDRESS phys = { 0 };
	PHYSICAL_ADDRESS physvmon = { 0 };
	PHYSICAL_ADDRESS physvmcs = { 0 };
	phys.QuadPart = MAXULONG64;
	PVMX_VMCS pvmxon = (PVMX_VMCS)MmAllocateContiguousMemory(sizeof(VMX_VMCS), phys);
	PVMX_VMCS pvmcs = (PVMX_VMCS)MmAllocateContiguousMemory(sizeof(VMX_VMCS), phys);
	PVOID MsrBitMap = MmAllocateContiguousMemory(PAGE_SIZE, phys);
	PVOID pvmmStack = MmAllocateContiguousMemory(PAGE_SIZE * 6, phys);
	if (pvmmStack == NULL || MsrBitMap == NULL)
	{
		return 1;
	}
	if (pvmxon == NULL || pvmcs == NULL)
	{
		return 1;
	}
	RtlZeroMemory(pvmxon, sizeof(VMX_VMCS));
	RtlZeroMemory(pvmcs, sizeof(VMX_VMCS));
	RtlZeroMemory(pvmmStack, PAGE_SIZE * 6);
	pvmxon->RevisionId = (ULONG)__readmsr(MSR_IA32_VMX_BASIC);
	pvmcs->RevisionId = (ULONG)__readmsr(MSR_IA32_VMX_BASIC);
	g_vcpu[cpuNumber].VMXON = pvmxon;
	g_vcpu[cpuNumber].VMMStack = pvmmStack;
	g_vcpu[cpuNumber].VMCS = pvmcs;
	g_vcpu[cpuNumber].MsrBitMap = MsrBitMap;
	ULONG64 mycr4 = __readcr4();
	mycr4 |= __readmsr(MSR_IA32_VMX_CR4_FIXED0);
	mycr4 &= __readmsr(MSR_IA32_VMX_CR4_FIXED1);
	ULONG64 mycr0 = __readcr0();
	mycr0 |= __readmsr(MSR_IA32_VMX_CR0_FIXED0);
	mycr0 &= __readmsr(MSR_IA32_VMX_CR0_FIXED1);
	__writecr0(mycr0);
	__writecr4(mycr4);
	physvmon = MmGetPhysicalAddress(pvmxon);
	physvmcs = MmGetPhysicalAddress(pvmcs);
	UCHAR vmonResult = __vmx_on(&physvmon);

	if (vmonResult)
	{
		return vmonResult;
	}

	__vmx_vmclear(&physvmcs);
	__vmx_vmptrld(&physvmcs);
	//填充VMCS区域
	CmGuestRsp();
	//xxx
	return 0;
}

ULONG VmxMsrAdjuest(ULONG64 msrNum, ULONG controlValue)
{
	LARGE_INTEGER msrValue;
	msrValue.QuadPart = __readmsr(msrNum);
	controlValue = (msrValue.LowPart | controlValue) & msrValue.HighPart;
	return controlValue;
}

void VmxFreeMemery()
{
	ULONG cpuNumber = KeGetCurrentProcessorNumber();
	VCPU currentCpu = g_vcpu[cpuNumber];
	if (g_vcpu[cpuNumber].VMCS)
	{
		MmFreeContiguousMemory(g_vcpu[cpuNumber].VMCS);
		g_vcpu[cpuNumber].VMCS = NULL;
	}
	if (g_vcpu[cpuNumber].VMXON)
	{
		MmFreeContiguousMemory(g_vcpu[cpuNumber].VMXON);
		g_vcpu[cpuNumber].VMXON = NULL;
	}
	if (g_vcpu[cpuNumber].VMMStack)
	{
		MmFreeContiguousMemory(g_vcpu[cpuNumber].VMMStack);
		g_vcpu[cpuNumber].VMMStack = NULL;
	}
	if (g_vcpu[cpuNumber].MsrBitMap)
	{
		MmFreeContiguousMemory(g_vcpu[cpuNumber].MsrBitMap);
		g_vcpu[cpuNumber].MsrBitMap = NULL;
	}
	ULONG64 myCr4 = __readcr4();
	myCr4 &= ~0X2000;
	__writecr4(myCr4);
}

void VmxSetMsrRw(ULONG64 msrNum, UCHAR rw, BOOLEAN flag)
{
	ULONG cpuNumber = KeGetCurrentProcessorNumber();
	VCPU currentCpu = g_vcpu[cpuNumber];
	PUCHAR msrBitMapAddr = currentCpu.MsrBitMap;
	ULONG64 msrByteOffset = 0;
	ULONG msrBitOffset = 0;
	if (rw == 1)
	{
		msrBitMapAddr += 1024 * 2;
	}
	if (msrNum >= 0xC0000000)
	{
		msrBitMapAddr += 1024;
		msrNum -= 0xC0000000;
	}
	msrByteOffset = msrNum / 8;
	msrBitOffset = msrNum % 8;
	msrBitMapAddr += msrByteOffset;
	if (flag)
	{
		(*msrBitMapAddr) |= 1 << msrBitOffset;

	}
	else
	{
		(*msrBitMapAddr) &= ~(1 << msrBitOffset);
	}
}

void VmxCpuidHandler(PGUEST_REGS GuestRegs)
{
	if (GuestRegs->rax == 1)
	{
		GuestRegs->rax = 0;
		GuestRegs->rbx = 0;
		GuestRegs->rcx = 0;
		GuestRegs->rdx = 0;
	}
	else
	{
		int cpuinfo[4] = { 0 };
		__cpuidex(cpuinfo, GuestRegs->rax, GuestRegs->rcx);
		GuestRegs->rax = cpuinfo[0];
		GuestRegs->rbx = cpuinfo[1];
		GuestRegs->rcx = cpuinfo[2];
		GuestRegs->rdx = cpuinfo[3];
	}
}
void VmxMsrReadHandler(PGUEST_REGS GuestRegs)
{
	if (GuestRegs->rcx == 0XC0000082)
	{
		DbgPrint("read msr 0XC0000082\n");
	}
	ULONG64 msrValue = __readmsr(GuestRegs->rcx);
	GuestRegs->rax = msrValue & 0xFFFFFFFF;
	GuestRegs->rdx = (msrValue >> 32) & 0xFFFFFFFF;
}

void VmxExitHandler(PGUEST_REGS GuestRegs)
{

	ULONG vmexitReason = 0;
	ULONG64 exitCodeLen = 0;
	ULONG64 guestRip = 0;
	ULONG64 guestRsp = 0;
	__vmx_vmread(VM_EXIT_REASON, &vmexitReason);
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &exitCodeLen);
	__vmx_vmread(GUEST_RIP, &guestRip);
	__vmx_vmread(GUEST_RSP, &guestRsp);
	vmexitReason = vmexitReason & 0xFFFF;
	//DbgPrint("code:%d", vmexitReason);
	switch (vmexitReason)
	{
	case EXIT_REASON_CPUID:
	{
		VmxCpuidHandler(GuestRegs);
	}
	break;
	case EXIT_REASON_VMCALL:
	{
		if (GuestRegs->rcx == 1)//表示要退出vt
		{
			DbgBreakPoint();
			__vmx_off();
			//返回到正确的位置
			VmxJumGuest(guestRsp, guestRip + exitCodeLen);
		}
		//EPT hook
		else if (GuestRegs->rcx == 2)
		{
			EptSetHook(GuestRegs->rdx, GuestRegs->r8, GuestRegs->r9);

		}

	}
	break;
	case EXIT_REASON_INVD:
	{

		VmxInvd();
	}
	break;
	case EXIT_REASON_MSR_READ:
	{
		VmxMsrReadHandler(GuestRegs);
	}
	break;
	case EXIT_REASON_EPT_VIOLATION:
	{
		EptExitHandler(GuestRegs);
		return;
	}
	break;
	default:
		break;
	}
	__vmx_vmwrite(GUEST_RIP, guestRip + exitCodeLen);
}




int VmxSetupVmcs(PVOID GuestRsp)
{
	ULONG cpuNumber = KeGetCurrentProcessorNumber();
	VCPU currentCpu = g_vcpu[cpuNumber];
	//DbgBreakPoint();
	VmxFillSelectorData(RegGetEs(), 0);
	VmxFillSelectorData(RegGetCs(), 1);
	VmxFillSelectorData(RegGetSs(), 2);
	VmxFillSelectorData(RegGetDs(), 3);
	VmxFillSelectorData(RegGetFs(), 4);
	VmxFillSelectorData(RegGetGs(), 5);
	VmxFillSelectorData(GetLdtr(), 6);

	__vmx_vmwrite(HOST_ES_SELECTOR, RegGetEs() & 0XFFF8);
	__vmx_vmwrite(HOST_CS_SELECTOR, RegGetCs() & 0XFFF8);
	__vmx_vmwrite(HOST_SS_SELECTOR, RegGetSs() & 0XFFF8);
	__vmx_vmwrite(HOST_DS_SELECTOR, RegGetDs() & 0XFFF8);
	__vmx_vmwrite(HOST_FS_SELECTOR, RegGetFs() & 0XFFF8);
	__vmx_vmwrite(HOST_GS_SELECTOR, RegGetGs() & 0XFFF8);
	//填充TR寄存器
	USHORT trSelector = GetTrSelector();
	trSelector = trSelector &= 0xFFF8;
	ULONG trLimit = __segmentlimit(trSelector);
	ULONG64 gdtBase = GetGdtBase();
	LARGE_INTEGER trSegement = { 0 };
	PULONG trContext = (PULONG)(gdtBase + trSelector);
	trSegement.LowPart = ((trContext[0] >> 16) & 0xFFFF) | ((trContext[1] & 0xFF) << 16) | ((trContext[1] & 0xFF000000));
	trSegement.HighPart = trContext[2];
	ULONG trAttr = (trContext[1] & 0x00F0FF00) >> 8;
	__vmx_vmwrite(GUEST_TR_BASE, trSegement.QuadPart);
	__vmx_vmwrite(GUEST_TR_LIMIT, trLimit);
	__vmx_vmwrite(GUEST_TR_AR_BYTES, trAttr);
	__vmx_vmwrite(GUEST_TR_SELECTOR, trSelector);
	__vmx_vmwrite(HOST_TR_BASE, trSegement.QuadPart);
	__vmx_vmwrite(HOST_TR_SELECTOR, trSelector);

	__vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));
	__vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));
	__vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
	__vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));
	//CR
	__vmx_vmwrite(GUEST_CR0, __readcr0());
	__vmx_vmwrite(GUEST_CR3, __readcr3());
	__vmx_vmwrite(GUEST_CR4, __readcr4());
	__vmx_vmwrite(GUEST_DR7, __readdr(7));
	__vmx_vmwrite(HOST_CR0, __readcr0());
	__vmx_vmwrite(HOST_CR3, __readcr3());
	__vmx_vmwrite(HOST_CR4, __readcr4());
	//IA_32
	__vmx_vmwrite(VMCS_LINK_POINTER, -1);
	__vmx_vmwrite(VMCS_LINK_POINTER_HIGH, -1);
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL));
	__vmx_vmwrite(GUEST_IA32_PAT, __readmsr(MSR_IA32_PAT));
	__vmx_vmwrite(GUEST_IA32_EFER, __readmsr(MSR_IA32_EFER));

	//sysenter
	__vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	__vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	__vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	__vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	//__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));

	//GDT
	__vmx_vmwrite(GUEST_GDTR_BASE, GetGdtBase());
	__vmx_vmwrite(GUEST_GDTR_LIMIT, GetGdtLimit());
	__vmx_vmwrite(HOST_GDTR_BASE, GetGdtBase());
	//IDT
	__vmx_vmwrite(GUEST_IDTR_BASE, GetIdtBase());
	__vmx_vmwrite(GUEST_IDTR_LIMIT, GetIdtLimit());
	__vmx_vmwrite(HOST_IDTR_BASE, GetIdtBase());
	//guest rsp rip
	__vmx_vmwrite(GUEST_RSP, GuestRsp);
	__vmx_vmwrite(GUEST_RIP, CmGeustRip);
	__vmx_vmwrite(GUEST_RFLAGS, __readeflags());
	__vmx_vmwrite(HOST_RSP, (ULONG64)currentCpu.VMMStack + PAGE_SIZE * 5);
	__vmx_vmwrite(HOST_RIP, VmxVmexitHandler);
	ULONG64 basicMsr = __readmsr(MSR_IA32_VMX_BASIC);
	ULONG64 result = (basicMsr >> 55) & 1;
	ULONG64 entryMsrNum = MSR_IA32_VMX_ENTRY_CTLS;
	ULONG64 exitMsrNum = MSR_IA32_VMX_EXIT_CTLS;
	ULONG64 pinMsr = MSR_IA32_VMX_PINBASED_CTLS;
	ULONG64	procMsr = MSR_IA32_VMX_PROCBASED_CTLS;
	if (result)
	{
		entryMsrNum = MSR_IA32_VMX_TRUE_ENTRY_CTLS;
		exitMsrNum = MSR_IA32_VMX_TRUE_EXIT_CTLS;

		pinMsr = MSR_IA32_VMX_TRUE_PINBASED_CTLS;
		procMsr = MSR_IA32_VMX_TRUE_PROCBASED_CTLS;
	}
	__vmx_vmwrite(VM_ENTRY_CONTROLS, VmxMsrAdjuest(entryMsrNum, 0x200));
	__vmx_vmwrite(VM_EXIT_CONTROLS, VmxMsrAdjuest(exitMsrNum, 0x8200));
	__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, VmxMsrAdjuest(pinMsr, 0));
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, VmxMsrAdjuest(procMsr, 0X10000000 | 0x80000000));
	PHYSICAL_ADDRESS msrPhyAddr = MmGetPhysicalAddress(currentCpu.MsrBitMap);
	__vmx_vmwrite(MSR_BITMAP, msrPhyAddr.QuadPart);
	__vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
	__vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);
	__vmx_vmwrite(GUEST_ACTIVITY_STATE, 0);   // 处于正常执行指令状态 
	//0xC0000082 
	//VmxSetMsrRw(0xC0000082,0,TRUE);
	DbgBreakPoint();
	if (NT_SUCCESS(EptInitEptData()))
	{
		ULONG64 ctls2Value = VmxMsrAdjuest(MSR_IA32_VMX_PROCBASED_CTLS2, 2 | 0X20);
		__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, ctls2Value);
		__vmx_vmwrite(EPT_POINTER, g_vcpu[cpuNumber].Eptp.ALL);
		__vmx_vmwrite(0, KeGetCurrentProcessorNumberEx(NULL) + 1);
	}

	result = __vmx_vmlaunch();

	if (result)
	{
		DbgBreakPoint();
	}
	return result;
}

void VmxFillSelectorData(USHORT selector, USHORT index)
{
	SEGMENT_SELECTOR segMentSelector = { 0 };
	segMentSelector.sel = selector;
	segMentSelector.limit = __segmentlimit(segMentSelector.sel);
	segMentSelector.base = 0;
	//获取Gdt表
	ULONG64 gdtBase = GetGdtBase();
	//获取段描述符 0x23 10 0000 *
	PSEGMENT_DESCRIPTOR segmentDes =
		(PSEGMENT_DESCRIPTOR)(gdtBase + (ULONG64)(segMentSelector.sel & 0xFFF8));//等价与 gdtBase+index*8
	//segmentDes->BaseLow| segmentDes->BaseMid
	segMentSelector.base =
		segmentDes->BaseHigh << 24 | segmentDes->BaseMid << 16 | segmentDes->BaseLow;
	segMentSelector.attributes = segmentDes->AttributesHigh << 8 | segmentDes->AttributesLow;
	ULONG attr = ((PUCHAR)&segMentSelector.attributes)[0] | (((PUCHAR)&segMentSelector.attributes)[1]) << 12;
	/*if (segMentSelector.attributes & 0x800)
	{
		segMentSelector.limit = segMentSelector.limit << 12 + 0xFFF;
	}*/

	if (selector == 0)
	{
		attr |= 0x10000;
	}
	__vmx_vmwrite(GUEST_ES_SELECTOR + index * 2, segMentSelector.sel);
	__vmx_vmwrite(GUEST_ES_LIMIT + index * 2, segMentSelector.limit);
	__vmx_vmwrite(GUEST_ES_BASE + index * 2, segMentSelector.base);
	__vmx_vmwrite(GUEST_ES_AR_BYTES + index * 2, attr);
	//RIP RSP
	//1检测环境
	//2申请内存cpu vmxON vmcx
	//3 vmxon 进入 vt root host
	//4填充vmcs区域 RSP RIP
	//5 vmlaunch 从host层回到 guest  类似从r0回到r3
}

