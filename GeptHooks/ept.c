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
	if (((msrCtls2 >> 33) & 1) == 0)
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

//bit17: EPT 1GB大页支持(用于超512GB区域的动态映射)
BOOLEAN g_bEpt1GbPage = FALSE;

//必须在PASSIVE_LEVEL调用(DriverEntry预分配阶段), 不能在DPC里分配2MB连续内存
NTSTATUS EptInitEptData(ULONG cpuNumber)
{
	ULONG64 msrCap = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
	NTSTATUS status = STATUS_SUCCESS;
	PHYSICAL_ADDRESS phys = { 0 };
	phys.QuadPart = MAXULONG64;
	PVCPU currentVcpu = VmxGetCurrentVcpu(cpuNumber);
	ULONG memtype = ((msrCap >> 14) & 1) ? 6 : 0;
	ULONG ifDirty = ((msrCap >> 21) & 1) ? 1 : 0;
	g_bEpt1GbPage = (BOOLEAN)((msrCap >> 17) & 1);
	if (!EptIsSupportEpt())
	{
		return STATUS_UNSUCCESSFUL;
	}
	currentVcpu->PeptData = (PEPT_DATA)MmAllocateContiguousMemory(sizeof(EPT_DATA), phys);
	if (currentVcpu->PeptData == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	for (size_t i = 0; i < EPT_PREALLOC_PAGES; i++)
	{
		currentVcpu->PeptData->pdpte[i].fileds.present = 1;
		currentVcpu->PeptData->pdpte[i].fileds.execute = 1;
		currentVcpu->PeptData->pdpte[i].fileds.write = 1;
		currentVcpu->PeptData->pdpte[i].fileds.physicalAddr = MmGetPhysicalAddress(&(currentVcpu->PeptData->pde[i][0])).QuadPart / PAGE_SIZE;
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

//为超出512GB恒等映射的gpa(典型: PCIe高地址MMIO)动态建立EPT路径
//惰性策略: 只为命中的512GB区间建一个pdpt页, pdpte项用1GB大页(不支持时建pdt页+2M大页)
//内存类型一律UC: MMIO必须不可缓存; 即使是RAM也只是慢而不会错
BOOLEAN EptBuildHighMapping(ULONG64 gpa)
{
	ULONG pml4Idx = (ULONG)((gpa >> 39) & 0x1FF);
	ULONG pdpteIdx = (ULONG)((gpa >> 30) & 0x1FF);
	ULONG cpuNumber = KeGetCurrentProcessorNumber();
	PEPT_DATA eptData = g_vcpu[cpuNumber].PeptData;
	if (eptData == NULL)
	{
		return FALSE;
	}
	PEPT_PDPTE pdpt = (PEPT_PDPTE)g_vcpu[cpuNumber].HighPdptVa[pml4Idx];
	if (pdpt == NULL)
	{
		pdpt = (PEPT_PDPTE)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'tpeP');
		if (pdpt == NULL)
		{
			Log("EPT动态建表失败: pdpt分配失败 gpa=%p", (PVOID)gpa);
			return FALSE;
		}
		RtlZeroMemory(pdpt, PAGE_SIZE);
		g_vcpu[cpuNumber].HighPdptVa[pml4Idx] = pdpt;
		eptData->pml4[pml4Idx].ALL = 0;
		eptData->pml4[pml4Idx].fileds.present = 1;
		eptData->pml4[pml4Idx].fileds.write = 1;
		eptData->pml4[pml4Idx].fileds.execute = 1;
		eptData->pml4[pml4Idx].fileds.physicalAddr = MmGetPhysicalAddress(pdpt).QuadPart / PAGE_SIZE;
		Log("EPT动态建表: pml4[%d] -> pdpt (512GB区间 %d)", pml4Idx, pml4Idx);
	}
	if (pdpt[pdpteIdx].fileds.present)
	{
		//该1GB已建好(可能上次invept前残留的重复violation)
		return TRUE;
	}
	if (g_bEpt1GbPage)
	{
		//1GB大页恒等映射, UC
		EPT_PDPTE_1G e1g;
		e1g.ALL = 0;
		e1g.fileds.present = 1;
		e1g.fileds.write = 1;
		e1g.fileds.execute = 1;
		e1g.fileds.memoryType = 0;	//UC
		e1g.fileds.largePage = 1;
		e1g.fileds.physicalAddr = (ULONG64)pml4Idx * 512 + pdpteIdx;	//1GB页帧号(bits 47:30)
		pdpt[pdpteIdx].ALL = e1g.ALL;
	}
	else
	{
		//无1GB支持: 建pdt页, 512个2M大页恒等, UC
		PEPT_PDE_2M pdt = (PEPT_PDE_2M)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'tpeP');
		if (pdt == NULL)
		{
			Log("EPT动态建表失败: pdt分配失败 gpa=%p", (PVOID)gpa);
			return FALSE;
		}
		RtlZeroMemory(pdt, PAGE_SIZE);
		ULONG64 base2mPfn = ((ULONG64)pml4Idx * 512 + pdpteIdx) * 512;	//该1GB区间首个2M页帧号
		for (ULONG i = 0; i < 512; i++)
		{
			pdt[i].fileds.present = 1;
			pdt[i].fileds.write = 1;
			pdt[i].fileds.execute = 1;
			pdt[i].fileds.memoryType = 0;	//UC
			pdt[i].fileds.ps = 1;
			pdt[i].fileds.physicalAddr = base2mPfn + i;
		}
		pdpt[pdpteIdx].ALL = 0;
		pdpt[pdpteIdx].fileds.present = 1;
		pdpt[pdpteIdx].fileds.write = 1;
		pdpt[pdpteIdx].fileds.execute = 1;
		pdpt[pdpteIdx].fileds.physicalAddr = MmGetPhysicalAddress(pdt).QuadPart / PAGE_SIZE;
	}
	return TRUE;
}

void EptExitHandler(PGUEST_REGS GuestRegs)
{
	EPT_EXITDATA eptExit = { 0 };
	ULONG64 gpa = 0;
	ULONG64 guestRip = 0;
	ULONG64 guestRsp = 0;
	static volatile LONG g_eptLogCount = 0;
	__vmx_vmread(GUEST_RIP, &guestRip);
	__vmx_vmread(GUEST_RSP, &guestRsp);
	__vmx_vmread(EXIT_QUALIFICATION, &eptExit);
	//获取哪个地址触发的exit事件
	__vmx_vmread(GUEST_PHYSICAL_ADDRESS, &gpa);
	//限流日志: 只打印前20次EPT违规, 违规风暴时避免日志本身拖死系统
	if (InterlockedIncrement(&g_eptLogCount) <= 20)
	{
		Log("EPT violation gpa=%p rip=%p r=%d w=%d x=%d",
			(PVOID)gpa, (PVOID)guestRip,
			(int)eptExit.fileds.read, (int)eptExit.fileds.write, (int)eptExit.fileds.execute);
	}
	//判断这个地址所在页是否被我们hook过
	ULONG64 pfn = gpa / PAGE_SIZE;
	PPAGE_HOOK_ENTRY pageEntry = PHGetHookEntryPageBy(pfn);
	if (pageEntry == NULL)
	{
		//未被hook的页发生EPT违规(典型原因: 物理地址超出512GB恒等映射范围, 如PCIe高地址MMIO)
		//原版直接return -> 同一指令无限重试 -> 整机卡死
		PEPT_PDE_2M pde2M = EptGetPde2B(gpa);
		if (pde2M != NULL)
		{
			//512GB内但2M页尚未拆分等情形: 恢复该PTE全部权限让指令继续执行
			PEPT_PTE ppte = EptGetPte(gpa);
			if (ppte != NULL)
			{
				ppte->fileds.present = 1;
				ppte->fileds.write = 1;
				ppte->fileds.execute = 1;
			}
			else
			{
				//2M页尚未拆分为PTE: 直接恢复PDE全权限兜底
				pde2M->fileds.present = 1;
				pde2M->fileds.write = 1;
				pde2M->fileds.execute = 1;
			}
			//必须刷新EPT缓存, 否则旧翻译仍在, 同一指令继续violation
			EPT_CTX ctx = { 0 };
			VmxInvept(2, &ctx);
		}
		else
		{
			//超出512GB恒等映射: 动态建立EPT路径(惰性, UC内存类型对MMIO安全)
			if (EptBuildHighMapping(gpa))
			{
				//映射已建立, 刷新EPT缓存后重执行同一指令(此次能通过)
				EPT_CTX ctx = { 0 };
				VmxInvept(2, &ctx);
			}
			//分配失败则只能记录(极小概率, NonPagedPool耗尽)
		}
		return;
	}
	if (eptExit.fileds.read)
	{
		EptUpdatePageAcess(gpa, 1, pageEntry);
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

	__vmx_vmwrite(GUEST_RIP, guestRip);
	__vmx_vmwrite(GUEST_RSP, guestRsp);
}


void EptSetHook(ULONG64 orginalPagePFN, ULONG64 codePagePFN)
{
	//相当于有了GPA 要获取HPA
	ULONG64 oPFN = orginalPagePFN << 12;
	ULONG64 cPFN = codePagePFN << 12;
	//获取PDE/PTE
	PEPT_PDE_2M oPde2M = EptGetPde2B(oPFN);
	PEPT_PDE_2M cPed2M = EptGetPde2B(cPFN);
	if (oPde2M == NULL || cPed2M == NULL)
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

	if (pte == NULL)
	{
		return;
	}
	pte->fileds.execute = 0;
	//刷新页表缓存TLB
	EPT_CTX ctx = { 0 };
	VmxInvept(2, &ctx);

}

PEPT_PDE_2M EptGetPde2B(ULONG64 PFN)
{

	//PML4 9 9 9 9 12
	ULONG pml4Index = (PFN >> 39) & 0x1FF;
	if (pml4Index > 0)
	{
		return NULL;
	}
	//pdpteINDEX
	ULONG pdpteIndex = (PFN >> 30) & 0x1FF;
	//PDE
	ULONG pdeindex = (PFN >> 21) & 0x1FF;
	ULONG cpuNumber = KeGetCurrentProcessorNumber();
	PVCPU currentVcpu = VmxGetCurrentVcpu(cpuNumber);
	//EPT_PDE_2M pde2M= currentVcpu->PeptData->pde[pdpteIndex][pdeindex];
	return &(currentVcpu->PeptData->pde[pdpteIndex][pdeindex]);
}

BOOLEAN EptPdeToPte(PEPT_PDE_2M pde2M)
{
	BOOLEAN status = TRUE;
	PEPT_PTE ppte = (PEPT_PTE)ExAllocatePool(NonPagedPool, sizeof(EPT_PTE) * 512);
	if (ppte == NULL)
	{
		return FALSE;
	}
	RtlZeroMemory(ppte, sizeof(EPT_PTE) * 512);
	for (size_t i = 0; i < 512; i++)
	{
		ppte[i].fileds.present = 1;
		ppte[i].fileds.write = 1;
		ppte[i].fileds.execute = 1;
		//必须继承源2M页的内存类型! 原版漏设=0(UC不可缓存),
		//拆分后整个2MB内核代码区取指全部直通内存, 性能塌方表现为整机卡死
		ppte[i].fileds.memoryType = pde2M->fileds.memoryType;
		ppte[i].fileds.physicalAddr = (pde2M->fileds.physicalAddr) * 512 + i;
	}

	EPT_PDE pde = { 0 };
	pde.fileds.read = 1;
	pde.fileds.write = 1;
	pde.fileds.execute = 1;
	pde.fileds.physicalAddr = (MmGetPhysicalAddress(ppte).QuadPart) / PAGE_SIZE;

	memcpy(pde2M, &pde, sizeof(pde));
	return status;
}

PEPT_PTE EptGetPte(ULONG64 PFN)
{
	PEPT_PDE_2M pde2M = EptGetPde2B(PFN);
	if (pde2M->fileds.ps)
	{
		return NULL;
	}
	PEPT_PDE pde = (PEPT_PDE)pde2M;
	//获取PTE 9 9 9 9 12
	//ptt[index]
	//PFN = PFN << 12;
	ULONG pteIndex = ((PFN >> 12) & 0x1FF);
	//ptt[pteIndex]----》pte
	PHYSICAL_ADDRESS pttPhAddress = { 0 };
	pttPhAddress.QuadPart = (pde->fileds.physicalAddr) * PAGE_SIZE;
	PEPT_PTE ptt = (PEPT_PTE)MmGetVirtualForPhysical(pttPhAddress);
	return &ptt[pteIndex];
}

void EptUpdatePageAcess(ULONG64 gpa, UCHAR acess, PPAGE_HOOK_ENTRY pageEntry)
{
	//获取pte
	PEPT_PTE ppte = EptGetPte(gpa);
	if (ppte == NULL)
	{
		return;
	}
	//读
	if (acess == 1)
	{
		ppte->fileds.physicalAddr = pageEntry->OriginalPagePFN;
		ppte->fileds.present = 1;
		ppte->fileds.execute = 0;
		ppte->fileds.write = 1;
	}
	//写
	else if (acess == 2)
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
		//保持可读(原版为0=仅执行): "执行中读同页数据"的指令(如mov rax,[rip+X])
		//会在读视图/执行视图间无限互切, RIP永不前进=活锁卡死
		//代价: 读内存会看到跳板字节(对调试无影响, 隐蔽性以后用VMFUNC双EPT解决)
		ppte->fileds.present = 1;
		ppte->fileds.execute = 1;
		ppte->fileds.write = 0;
	}
}






