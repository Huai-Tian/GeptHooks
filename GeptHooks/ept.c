#pragma once
#include<intrin.h>
#include"ept.h"
#include"CPU.h"
#include"VMX.h"

BOOLEAN EptIsSupportEpt()
{

	ULONG64 msrCtls = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS);
	ULONG64 msrCtls2 = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
	ULONG64 msrCap = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
	if (((msrCtls >> 63) & 1) == 0)
	{
		return FALSE;
	}
	if (((msrCtls2>>33)&1)==0)
	{
		return FALSE;
	}
	if ((msrCap & 1) == 0)
	{
		return FALSE;
	}
	if (((msrCap >> 6) & 1) == 0)
	{
		return FALSE;
	}
	if (((msrCap >> 16) & 1) == 0)
	{
		return FALSE;
	}
	return TRUE;
}

NTSTATUS EptInitEptData()
{
	ULONG64 msrCap = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
	NTSTATUS status = STATUS_SUCCESS;
	PHYSICAL_ADDRESS phys = { 0 };
	phys.QuadPart = MAXULONG64;
	ULONG cpuNumber = KeGetCurrentProcessorNumber();
	PVCPU currentVcpu=VmxGetCurrentVcpu(cpuNumber);
	ULONG memtype = ((msrCap >> 14) & 1) ? 6 : 0;
	ULONG ifDirty= ((msrCap >> 21) & 1) ? 1 : 0;
	if (!EptIsSupportEpt())
	{
		return STATUS_UNSUCCESSFUL;
	}
	currentVcpu->PeptData = (PEPT_DATA)MmAllocateContiguousMemory(sizeof(EPT_DATA), phys);
	if (currentVcpu->PeptData ==NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	
	for (size_t i = 0; i < EPT_PREALLOC_PAGES; i++)
	{
		currentVcpu->PeptData->pdpte[i].fileds.present = 1;
		currentVcpu->PeptData->pdpte[i].fileds.execute = 1;
		currentVcpu->PeptData->pdpte[i].fileds.write = 1;
		currentVcpu->PeptData->pdpte[i].fileds.physicalAddr = MmGetPhysicalAddress(&(currentVcpu->PeptData->pde[i][0])).QuadPart/ PAGE_SIZE;
		for (size_t k = 0; k < EPT_PREALLOC_PAGES; k++)
		{
			currentVcpu->PeptData->pde[i][k].fileds.present = 1;
			currentVcpu->PeptData->pde[i][k].fileds.execute = 1;
			currentVcpu->PeptData->pde[i][k].fileds.write = 1;
			currentVcpu->PeptData->pde[i][k].fileds.memoryType = memtype;
			currentVcpu->PeptData->pde[i][k].fileds.ps = 1;
			currentVcpu->PeptData->pde[i][k].fileds.physicalAddr = i * EPT_PREALLOC_PAGES + k;
		}
	}
	currentVcpu->Eptp.fileds.memoryType = memtype;
	currentVcpu->Eptp.fileds.walkLen = 3;
	currentVcpu->Eptp.fileds.physicalAddr = MmGetPhysicalAddress(&(currentVcpu->PeptData->pml4)).QuadPart / PAGE_SIZE;
	currentVcpu->Eptp.fileds.dirty = ifDirty;
	currentVcpu->PeptData->pml4[0].fileds.present = 1;
	currentVcpu->PeptData->pml4[0].fileds.execute = 1;
	currentVcpu->PeptData->pml4[0].fileds.write = 1;
	currentVcpu->PeptData->pml4[0].fileds.physicalAddr = MmGetPhysicalAddress(&(currentVcpu->PeptData->pdpte)).QuadPart / PAGE_SIZE;
	return status;
}

void EptExitHandler(PGUEST_REGS GuestRegs)
{
	EPT_EXITDATA eptExit = {0};
	ULONG64 gpa = 0;
	ULONG64 guestRip = 0;
	ULONG64 guestRsp = 0;
	__vmx_vmread(GUEST_RIP,&guestRip);
	__vmx_vmread(GUEST_RSP, &guestRsp);
	__vmx_vmread(EXIT_QUALIFICATION,&eptExit);
	//获取哪个地址触发的exit事件
	__vmx_vmread(GUEST_PHYSICAL_ADDRESS,&gpa);
	//判断这个地址所在页是否被我们hook过
	ULONG64 pfn = gpa /PAGE_SIZE;
	PPAGE_HOOK_ENTRY pageEntry= PHGetHookEntryPageBy(pfn);
	if (pageEntry==NULL)
	{
		return;
	}
	if (eptExit.fileds.read)
	{
		EptUpdatePageAcess(gpa,1, pageEntry);
	}
	if (eptExit.fileds.write)
	{
		EptUpdatePageAcess(gpa, 2, pageEntry);
	}
	if (eptExit.fileds.execute)
	{
		EptUpdatePageAcess(gpa, 3, pageEntry);
	}
	//刷新页表缓存TLB
	EPT_CTX ctx = { 0 };
	VmxInvept(2, &ctx);

	__vmx_vmwrite(GUEST_RIP,guestRip);
	__vmx_vmwrite(GUEST_RSP,guestRsp);
}


void EptSetHook(ULONG64 orginalPagePFN, ULONG64 codePagePFN)
{
	//相当于有了GPA 要获取HPA
	ULONG64 oPFN = orginalPagePFN << 12;
	ULONG64 cPFN = codePagePFN <<12;
	//获取PDE/PTE
	PEPT_PDE_2M oPde2M=EptGetPde2B(oPFN);
	PEPT_PDE_2M cPed2M=EptGetPde2B(cPFN);
	if (oPde2M==NULL || cPed2M==NULL)
	{
		return;
	}
	//判断如果是2M页，就进行拆分
	if (oPde2M->fileds.ps)
	{
		//将当前的GPA所在的PDE 拆分成1个ptt 也就是512个pte
		BOOLEAN status = EptPdeToPte(oPde2M);
	}
	
	if (cPed2M->fileds.ps)
	{
		//将当前的GPA所在的PDE 拆分成1个ptt 也就是512个pte
		BOOLEAN status = EptPdeToPte(cPed2M);
	}
	//修改页属性，将执行权限去掉
	PEPT_PTE pte = EptGetPte(oPFN);//
	
	if (pte==NULL)
	{
		return;
	}
	pte->fileds.execute =0;
	//刷新页表缓存TLB
	EPT_CTX ctx = {0};
	VmxInvept(2,&ctx);

}

PEPT_PDE_2M EptGetPde2B(ULONG64 PFN)
{

	//PML4 9 9 9 9 12
	ULONG pml4Index = (PFN >> 39) & 0x1FF;
	if (pml4Index>0)
	{
		return NULL;
	}
	//pdpteINDEX
	ULONG pdpteIndex = (PFN >> 30) & 0x1FF;
	//PDE
	ULONG pdeindex= (PFN >> 21) & 0x1FF;
	ULONG cpuNumber = KeGetCurrentProcessorNumber();
	PVCPU currentVcpu = VmxGetCurrentVcpu(cpuNumber);
	//EPT_PDE_2M pde2M= currentVcpu->PeptData->pde[pdpteIndex][pdeindex];
	return &(currentVcpu->PeptData->pde[pdpteIndex][pdeindex]);
}

BOOLEAN EptPdeToPte(PEPT_PDE_2M pde2M)
{
	BOOLEAN status = TRUE;
	PEPT_PTE ppte=(PEPT_PTE)ExAllocatePool(NonPagedPool,sizeof(EPT_PTE)*512);
	if (ppte==NULL)
	{
		return FALSE;
	}
	RtlZeroMemory(ppte, sizeof(EPT_PTE) * 512);
	for (size_t i = 0; i < 512; i++)
	{
		ppte[i].fileds.present = 1;
		ppte[i].fileds.write = 1;
		ppte[i].fileds.execute = 1;
		ppte[i].fileds.physicalAddr = (pde2M->fileds.physicalAddr)*512+i;
	}

	EPT_PDE pde = {0};
	pde.fileds.read = 1;
	pde.fileds.write = 1;
	pde.fileds.execute = 1;
	pde.fileds.physicalAddr = (MmGetPhysicalAddress(ppte).QuadPart)/PAGE_SIZE;

	memcpy(pde2M,&pde,sizeof(pde));
	return status;
}

PEPT_PTE EptGetPte(ULONG64 PFN)
{
	PEPT_PDE_2M pde2M= EptGetPde2B(PFN);
	if (pde2M->fileds.ps)
	{
		return NULL;
	}
	PEPT_PDE pde = (PEPT_PDE)pde2M;
	//获取PTE 9 9 9 9 12
	//ptt[index]
	//PFN = PFN << 12;
	ULONG pteIndex=((PFN >> 12) & 0x1FF);
	//ptt[pteIndex]----》pte
	PHYSICAL_ADDRESS pttPhAddress = {0};
	pttPhAddress.QuadPart=(pde->fileds.physicalAddr)*PAGE_SIZE;
	PEPT_PTE ptt=(PEPT_PTE) MmGetVirtualForPhysical(pttPhAddress);
	return &ptt[pteIndex];
}

void EptUpdatePageAcess(ULONG64 gpa, UCHAR acess, PPAGE_HOOK_ENTRY pageEntry)
{
	//获取pte
	PEPT_PTE ppte= EptGetPte(gpa);
	if (ppte==NULL)
	{
		return;
	}
	//读
	if (acess==1)
	{
		ppte->fileds.physicalAddr = pageEntry->OriginalPagePFN;
		ppte->fileds.present = 1;
		ppte->fileds.execute = 0;
		ppte->fileds.write = 1;
	}
	//写
	else if (acess==2)
	{
		ppte->fileds.physicalAddr = pageEntry->OriginalPagePFN;
		ppte->fileds.present = 1;
		ppte->fileds.execute = 0;
		ppte->fileds.write = 1;
	}
	//执行
	else if (acess == 3)
	{
		ppte->fileds.physicalAddr = pageEntry->CodePagePFN;
		ppte->fileds.present = 0;
		ppte->fileds.execute = 1;
		ppte->fileds.write = 0;
	}
}






