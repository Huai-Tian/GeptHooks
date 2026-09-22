#pragma once
#include<intrin.h>
#include"ept.h"
#include"CPU.h"
#include"VMX.h"
#include"reg.h"

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
//bit0: exec-only页(X=1,R=0)支持——HideRead读透明的前提
BOOLEAN g_bEptExecOnly = FALSE;

//==================== EPT内存类型按真实RAM布局 ====================
//MMIO洞(LAPIC/IOAPIC/HPET/低地址BAR)若标成WB会被错误缓存→中断
//pending/I/O永不完成=整机冻结。MmGetPhysicalMemoryRanges取真实布局:
//2M页完全落在RAM内才WB, 否则UC(UC只损失性能不损失正确性)。
//位图32KB, DriverEntry建一次, 全核共用
#define EPT_2M_FRAME_COUNT (EPT_PREALLOC_PAGES * EPT_PREALLOC_PAGES)   //262144
#define EPT_RAM_BITMAP_BYTES (EPT_2M_FRAME_COUNT / 8)                  //32KB
static UCHAR g_eptRamBitmap[EPT_RAM_BITMAP_BYTES];    //BSS自动清零: 1=该2MB页完全在RAM内
static BOOLEAN g_eptRamBitmapReady = FALSE;

//==================== 高区(512GB-256TB)EPT预建 ====================
//高地址MMIO(>512GB)走惰性建表会在VM-exit上下文做池分配——被中断者
//持池锁时=整机冻结。DriverEntry一次性预建511个pdpt页(512×1GB UC
//恒等, 全核共享), 高地址访问零exit零分配。惰性路径保留为兜底。
//pdpt页取自单块2MB连续(512×4KB槽): 散池511页各占独立2M帧=自我
//隐蔽级联火种, 单块仅跨~2帧
static PVOID g_eptHighPdptVa[512];     //共享高区pdpt页(块内槽; [0]未用)
static PVOID g_eptHighPdptBlock = NULL; //2MB连续块(统一释放)
static BOOLEAN g_eptHighReady = FALSE;

//拆分pte页arena(EptPdeToPte切槽): 2MB连续块×512槽, 页对齐免费。
//散池分配每页几乎独占一个2M帧→自我隐蔽拆该帧=级联放大(实测8核
//21K页/165MB池且打穿登记上限); arena聚簇后同帧第二页起零新
//拆分, 级联坍缩。PASSIVE预建, 耗尽→散池兜底
#define GEPT_SPLIT_ARENA_BLOCKS 8
static PVOID s_splitArenaBlock[GEPT_SPLIT_ARENA_BLOCKS];        //2MB连续块
static volatile LONG s_splitArenaUsed[GEPT_SPLIT_ARENA_BLOCKS]; //已切槽数(Interlocked)
static BOOLEAN EptPrebuildHighMappings(VOID);   //前置声明(定义在EptAllocAlignedPage后)

//PASSIVE_LEVEL(首个EptInitEptData调用时执行一次, 即DriverEntry预分配阶段)
static VOID EptBuildRamBitmap(VOID)
{
	if (g_eptRamBitmapReady)
	{
		return;
	}
	//返回真实物理RAM区间数组(以全零条目结尾), 调用方负责ExFreePool
	PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
	if (ranges == NULL)
	{
		//极小概率失败: 位图保持全0 = 全部UC(慢但正确), FlLog留痕
		FlLog("EPT: MmGetPhysicalMemoryRanges失败! EPT全程UC(性能降级, 正确性不变)");
		return;
	}
	ULONG wbPages = 0;
	ULONG rangeCnt = 0;
	for (PPHYSICAL_MEMORY_RANGE r = ranges;
		r->BaseAddress.QuadPart != 0 || r->NumberOfBytes.QuadPart != 0; r++)
	{
		ULONG64 base = (ULONG64)r->BaseAddress.QuadPart;
		ULONG64 end = base + (ULONG64)r->NumberOfBytes.QuadPart;
		//区间逐条落盘(WB总量与RAM真实布局的核对依据)
		if (rangeCnt < 32)
		{
			FlLog("RAM区间[%u]: %llX - %llX (%llu MB)",
				rangeCnt, (unsigned long long)base, (unsigned long long)end,
				(unsigned long long)((end - base) >> 20));
		}
		rangeCnt++;
		//只标记完整落在[base,end)内的2MB帧, 边界半页标UC
		ULONG64 first = (base + 0x1FFFFFULL) >> 21;
		ULONG64 last = end >> 21;
		for (ULONG64 f = first; f < last && f < EPT_2M_FRAME_COUNT; f++)
		{
			g_eptRamBitmap[f >> 3] |= (UCHAR)(1 << (f & 7));
			wbPages++;
		}
	}
	FlLog("EPT: RAM区间共%u条(超出32条未列)", rangeCnt);
	ExFreePool(ranges);
	g_eptRamBitmapReady = TRUE;
	FlLog("EPT: RAM位图就绪, WB=%u/%u个2M页(其余UC=MMIO洞/边界页)",
		wbPages, (ULONG)EPT_2M_FRAME_COUNT);
}

//2M帧号 -> 内存类型: 完全RAM=WB(6), 否则UC(0)
static ULONG EptMemTypeFor2MFrame(ULONG64 frame2m)
{
	if (g_eptRamBitmapReady &&
		(g_eptRamBitmap[frame2m >> 3] & (UCHAR)(1 << (frame2m & 7))))
	{
		return 6;
	}
	return 0;
}

//==================== 双EPT标记页 ====================
//hooked EPT里把pageA改译到pageB: guest读同一VA, clean视图见
//"CLEANEPT"/hooked视图见"HOOKEDPT"=双EPT独立翻译的功能验证。
//全核共用一对, EptShutdownHighMappings释放
PVOID g_geptMarkVA = NULL;      //pageA虚拟地址(GPA=PA_A, 恒等映射)
static PVOID s_geptMarkVB = NULL;   //pageB虚拟地址(写MAGIC/释放用)
ULONG64 g_geptMarkPaB = 0;      //pageB物理地址(hooked视图的翻译目标)

static BOOLEAN EptAllocMarkPages(VOID)
{
	if (g_geptMarkVA != NULL)
	{
		return TRUE;
	}
	PHYSICAL_ADDRESS phys = { 0 };
	phys.QuadPart = MAXULONG64;
	PVOID a = MmAllocateContiguousMemory(PAGE_SIZE, phys);
	PVOID b = MmAllocateContiguousMemory(PAGE_SIZE, phys);
	if (a == NULL || b == NULL)
	{
		if (a) MmFreeContiguousMemory(a);
		if (b) MmFreeContiguousMemory(b);
		FlLog("EPT: 双EPT标记页分配失败——标记自测跳过(VMFUNC核将判FAIL降级)");
		return FALSE;
	}
	*(volatile ULONG64*)a = GEPT_MARK_A;
	*(volatile ULONG64*)b = GEPT_MARK_B;
	g_geptMarkVA = a;
	s_geptMarkVB = b;
	g_geptMarkPaB = MmGetPhysicalAddress(b).QuadPart;
	FlLog("EPT: 双EPT标记页就绪: pageA=%p(PA=%llX) pageB(PA=%llX) MAGIC=\"%llX\"/\"%llX\"",
		a, (unsigned long long)MmGetPhysicalAddress(a).QuadPart,
		(unsigned long long)g_geptMarkPaB,
		(unsigned long long)GEPT_MARK_A, (unsigned long long)GEPT_MARK_B);
	return TRUE;
}

//在hooked EPT里建立标记remap: 拆pageA所在2M页→PTE改指pageB物理帧。
//launch前PASSIVE级调用(表未被硬件walk过)无需invept。返回FALSE=
//pageA超512GB/拆分失败
static BOOLEAN EptBuildMarkRemap(PEPT_DATA hooked)
{
	if (g_geptMarkVA == NULL)
	{
		return FALSE;
	}
	ULONG64 paA = MmGetPhysicalAddress(g_geptMarkVA).QuadPart;
	PEPT_PDE_2M pde2M = EptGetPde2B(hooked, paA);
	if (pde2M == NULL)
	{
		return FALSE;    //>512GB(8GB机器不可能, 防御)
	}
	if (pde2M->fileds.ps)
	{
		if (!EptPdeToPte(pde2M))
		{
			return FALSE;
		}
	}
	PEPT_PTE pte = EptGetPte(hooked, paA);
	if (pte == NULL)
	{
		return FALSE;
	}
	pte->fileds.physicalAddr = g_geptMarkPaB >> 12;
	pte->fileds.present = 1;
	pte->fileds.write = 1;
	pte->fileds.execute = 1;
	return TRUE;
}

//==================== vmlaunch前EPT软件自检 ====================
//软件走查复演硬件EPT翻译, 失败核放弃vmlaunch(留在root模式):
//  [1] EPTP  [2][3] 非叶物理链  [4] 2M叶恒等帧+权限位全扫
//  [5] 关键样本页(探针/栈/CR3/IDT/GDT/KPCR)
//返回失败组数(0=通过)
ULONG EptVerifyTables(ULONG cpuNumber, ULONG64 guestRspVa)
{
	ULONG fails = 0;
	PEPT_DATA e = g_vcpu[cpuNumber].PeptData;
	if (e == NULL)
	{
		FlLog("EPT自检: PeptData为空(异常), 按失败处理");
		return 1;
	}
	//[1] EPTP
	{
		ULONG64 eptp = g_vcpu[cpuNumber].Eptp.ALL;
		ULONG64 pml4Pa = MmGetPhysicalAddress(&e->pml4[0]).QuadPart;
		if ((eptp & 0xF80ULL) != 0 || (eptp >> 52) != 0)
		{
			FlLog("EPT自检[1] FAIL: EPTP保留位非0 (EPTP=%llX)",
				(unsigned long long)eptp);
			fails++;
		}
		if (g_vcpu[cpuNumber].Eptp.fileds.walkLen != 3)
		{
			FlLog("EPT自检[1] FAIL: walkLen=%u(必须3=四级)",
				(ULONG)g_vcpu[cpuNumber].Eptp.fileds.walkLen);
			fails++;
		}
		if (g_vcpu[cpuNumber].Eptp.fileds.physicalAddr * PAGE_SIZE != pml4Pa)
		{
			FlLog("EPT自检[1] FAIL: EPTP.PML4=%llX != pml4实际物理地址=%llX",
				(unsigned long long)(g_vcpu[cpuNumber].Eptp.fileds.physicalAddr * PAGE_SIZE),
				(unsigned long long)pml4Pa);
			fails++;
		}
		else
		{
			FlLog("EPT自检[1] EPTP->pml4链OK (EPTP=%llX PA=%llX mt=%u)",
				(unsigned long long)eptp, (unsigned long long)pml4Pa,
				(ULONG)g_vcpu[cpuNumber].Eptp.fileds.memoryType);
		}
	}
	//[2][3] 非叶物理链(硬件walk踩的就是这些指针)
	{
		ULONG64 pdptePa = MmGetPhysicalAddress(&e->pdpte[0]).QuadPart;
		if (!e->pml4[0].fileds.present ||
			e->pml4[0].fileds.physicalAddr != pdptePa / PAGE_SIZE)
		{
			FlLog("EPT自检[2] FAIL: pml4[0]指向%llX != pdpte实际%llX (present=%u)",
				(unsigned long long)(e->pml4[0].fileds.physicalAddr * PAGE_SIZE),
				(unsigned long long)pdptePa, (ULONG)e->pml4[0].fileds.present);
			fails++;
		}
		ULONG badPdpt = 0;
		ULONG firstBadPdpt = 0xFFFFFFFF;
		for (ULONG i = 0; i < EPT_PREALLOC_PAGES; i++)
		{
			ULONG64 expect = MmGetPhysicalAddress(&e->pde[i][0]).QuadPart / PAGE_SIZE;
			if (!e->pdpte[i].fileds.present ||
				e->pdpte[i].fileds.physicalAddr != expect)
			{
				badPdpt++;
				if (firstBadPdpt == 0xFFFFFFFF)
				{
					firstBadPdpt = i;
				}
			}
		}
		if (badPdpt != 0)
		{
			FlLog("EPT自检[3] FAIL: pdpte->pde链%u/512项错位(首个i=%u)",
				badPdpt, firstBadPdpt);
			fails++;
		}
		else
		{
			FlLog("EPT自检[2/3] pml4[0]->pdpte->512个pde页物理链全OK");
		}
	}
	//[4] 叶全扫: 恒等帧号+权限位
	{
		ULONG badLeaf = 0;
		ULONG64 firstBadGpa = 0;
		ULONG64 firstBadEntry = 0;
		for (ULONG i = 0; i < EPT_PREALLOC_PAGES; i++)
		{
			for (ULONG k = 0; k < EPT_PREALLOC_PAGES; k++)
			{
				PEPT_PDE_2M d = &e->pde[i][k];
				if (!d->fileds.present || !d->fileds.write || !d->fileds.execute ||
					!d->fileds.ps ||
					d->fileds.physicalAddr != (ULONG64)i * EPT_PREALLOC_PAGES + k)
				{
					if (badLeaf == 0)
					{
						firstBadGpa = ((ULONG64)i * EPT_PREALLOC_PAGES + k) << 21;
						firstBadEntry = d->ALL;
					}
					badLeaf++;
				}
			}
		}
		if (badLeaf != 0)
		{
			FlLog("EPT自检[4] FAIL: 2M叶%u/262144项异常, 首项GPA=%llX entry=%llX",
				badLeaf, (unsigned long long)firstBadGpa,
				(unsigned long long)firstBadEntry);
			fails++;
		}
		else
		{
			FlLog("EPT自检[4] 262144个2M叶恒等帧+P/W/X/ps全OK");
		}
	}
	//[5] 关键样本页: guest落地后头几条指令就会触碰的物理页
	{
		const char* names[8];
		ULONG64 gpas[8];
		ULONG n = 0;
		names[n] = "探针代码页";   gpas[n] = MmGetPhysicalAddress((PVOID)CmGuestProbe).QuadPart; n++;
		names[n] = "落地标签页";   gpas[n] = MmGetPhysicalAddress((PVOID)CmGeustRip).QuadPart; n++;
		if (guestRspVa != 0)
		{
			names[n] = "guest栈页"; gpas[n] = MmGetPhysicalAddress((PVOID)guestRspVa).QuadPart; n++;
		}
		names[n] = "CR3页表";      gpas[n] = __readcr3(); n++;
		names[n] = "IDT页";        gpas[n] = MmGetPhysicalAddress((PVOID)GetIdtBase()).QuadPart; n++;
		names[n] = "GDT页";        gpas[n] = MmGetPhysicalAddress((PVOID)GetGdtBase()).QuadPart; n++;
		names[n] = "KPCR页(GS基)"; gpas[n] = MmGetPhysicalAddress((PVOID)__readmsr(MSR_GS_BASE)).QuadPart; n++;
		for (ULONG s = 0; s < n; s++)
		{
			ULONG64 gpa2m = gpas[s] & ~0x1FFFFFULL;    //样本对齐到2M叶
			if ((gpa2m >> 39) != 0)
			{
				FlLog("EPT自检[5] FAIL: %s GPA=%llX 超出512GB恒等区(驱动数据不应在此!)",
					names[s], (unsigned long long)gpas[s]);
				fails++;
				continue;
			}
			ULONG pi = (ULONG)((gpa2m >> 30) & 0x1FF);
			ULONG di = (ULONG)((gpa2m >> 21) & 0x1FF);
			PEPT_PDE_2M d = &e->pde[pi][di];
			ULONG64 expectFrame = gpa2m >> 21;
			if (d->fileds.present && d->fileds.write && d->fileds.execute &&
				d->fileds.ps && d->fileds.physicalAddr == expectFrame)
			{
				FlLog("EPT自检[5] %s: GPA=%llX 帧=%llX 权限OK mt=%s",
					names[s], (unsigned long long)gpas[s],
					(unsigned long long)d->fileds.physicalAddr,
					d->fileds.memoryType == 6 ? "WB" : "UC");
			}
			else
			{
				FlLog("EPT自检[5] FAIL: %s GPA=%llX entry=%llX (期望帧=%llX)",
					names[s], (unsigned long long)gpas[s],
					(unsigned long long)d->ALL,
					(unsigned long long)expectFrame);
				fails++;
			}
		}
	}
	//[6] 高区链: 511个pml4[1..511]→共享pdpt页, 抽查首尾1GB UC叶
	{
		ULONG badHigh = 0;
		ULONG64 firstBadIdx = 0;
		for (ULONG i = 1; i < 512; i++)
		{
			if (g_eptHighPdptVa[i] == NULL ||
				!e->pml4[i].fileds.present ||
				e->pml4[i].fileds.physicalAddr !=
				MmGetPhysicalAddress(g_eptHighPdptVa[i]).QuadPart / PAGE_SIZE)
			{
				badHigh++;
				if (badHigh == 1)
				{
					firstBadIdx = i;
				}
			}
		}
		if (badHigh != 0)
		{
			FlLog("EPT自检[6] FAIL: pml4[1..511]高区链%u/511项异常(首个i=%llu)",
				badHigh, (unsigned long long)firstBadIdx);
			fails++;
		}
		else
		{
			PEPT_PDPTE_1G p1 = (PEPT_PDPTE_1G)g_eptHighPdptVa[1];
			PEPT_PDPTE_1G p511 = (PEPT_PDPTE_1G)g_eptHighPdptVa[511];
			if (p1[0].fileds.present && p1[0].fileds.write && p1[0].fileds.execute &&
				p1[0].fileds.largePage && p1[0].fileds.memoryType == 0 &&
				p1[0].fileds.physicalAddr == 512 &&
				p511[511].fileds.present && p511[511].fileds.largePage &&
				p511[511].fileds.memoryType == 0 &&
				p511[511].fileds.physicalAddr == 262143)
			{
				FlLog("EPT自检[6] 高区511×512×1GB UC恒等链全OK(512GB-256TB, 8核共享)");
			}
			else
			{
				FlLog("EPT自检[6] FAIL: 高区1GB叶抽查不符 (首=%llX 尾=%llX)",
					(unsigned long long)p1[0].ALL, (unsigned long long)p511[511].ALL);
				fails++;
			}
		}
	}
	//==================== hooked EPT自检 ====================
	//[7]深拷贝自指链 [8]叶全扫+标记remap [9]高区共享链。
	//任一FAIL=放弃vmlaunch(与clean自检同处置)
	if (g_vcpu[cpuNumber].PeptDataHooked != NULL)
	{
		PEPT_DATA h = g_vcpu[cpuNumber].PeptDataHooked;
		//[7] hooked EPTP + 深拷贝自指链(pml4[0]→hooked pdpte→512×hooked pde)
		{
			ULONG64 hPa = MmGetPhysicalAddress(&h->pml4[0]).QuadPart;
			if ((g_vcpu[cpuNumber].EptpHooked.ALL & 0xF80ULL) != 0 ||
				(g_vcpu[cpuNumber].EptpHooked.ALL >> 52) != 0 ||
				g_vcpu[cpuNumber].EptpHooked.fileds.walkLen != 3 ||
				g_vcpu[cpuNumber].EptpHooked.fileds.physicalAddr * PAGE_SIZE != hPa)
			{
				FlLog("EPT自检[7] FAIL: hooked EPTP=%llX非法(PML4期望PA=%llX)",
					(unsigned long long)g_vcpu[cpuNumber].EptpHooked.ALL,
					(unsigned long long)hPa);
				fails++;
			}
			else if (!h->pml4[0].fileds.present ||
				h->pml4[0].fileds.physicalAddr !=
				MmGetPhysicalAddress(&h->pdpte[0]).QuadPart / PAGE_SIZE)
			{
				FlLog("EPT自检[7] FAIL: hooked pml4[0]指向%llX != hooked pdpte实际%llX(深拷贝自指链断裂)",
					(unsigned long long)(h->pml4[0].fileds.physicalAddr * PAGE_SIZE),
					(unsigned long long)MmGetPhysicalAddress(&h->pdpte[0]).QuadPart);
				fails++;
			}
			else
			{
				ULONG badLink = 0;
				ULONG firstBad = 0xFFFFFFFF;
				for (ULONG i = 0; i < EPT_PREALLOC_PAGES; i++)
				{
					if (!h->pdpte[i].fileds.present ||
						h->pdpte[i].fileds.physicalAddr !=
						MmGetPhysicalAddress(&h->pde[i][0]).QuadPart / PAGE_SIZE)
					{
						badLink++;
						if (firstBad == 0xFFFFFFFF)
						{
							firstBad = i;
						}
					}
				}
				if (badLink != 0)
				{
					FlLog("EPT自检[7] FAIL: hooked pdpte→pde链%u/512项错位(首个i=%u, 深拷贝未重指?)",
						badLink, firstBad);
					fails++;
				}
				else
				{
					FlLog("EPT自检[7] hooked EPTP=%llX 自指链(pml4[0]→pdpte→512×pde)全OK",
						(unsigned long long)g_vcpu[cpuNumber].EptpHooked.ALL);
				}
			}
			//EPTP-list项有效性: mt/A-D须与clean一致(SDM §28.5.7.3)
			if (g_vcpu[cpuNumber].EptpHooked.fileds.memoryType !=
				g_vcpu[cpuNumber].Eptp.fileds.memoryType ||
				g_vcpu[cpuNumber].EptpHooked.fileds.dirty !=
				g_vcpu[cpuNumber].Eptp.fileds.dirty)
			{
				FlLog("EPT自检[7] FAIL: hooked EPTP的mt/A-D位与clean不一致(vmfunc切换会rsn59拒绝)");
				fails++;
			}
		}
		//[8] hooked叶全扫(除标记页所在2M区已拆4K)+标记remap PTE逐一验证
		{
			ULONG64 paA = (g_geptMarkVA != NULL)
				? MmGetPhysicalAddress(g_geptMarkVA).QuadPart : 0;
			ULONG mark1g = (ULONG)((paA >> 30) & 0x1FF);
			ULONG mark2m = (ULONG)((paA >> 21) & 0x1FF);
			ULONG badLeaf = 0;
			ULONG64 firstBadGpa = 0;
			for (ULONG i = 0; i < EPT_PREALLOC_PAGES; i++)
			{
				for (ULONG k = 0; k < EPT_PREALLOC_PAGES; k++)
				{
					if (paA != 0 && i == mark1g && k == mark2m)
					{
						continue;    //标记区已拆4K(PDE.ps=0), 下方PTE级补验
					}
					PEPT_PDE_2M d = &h->pde[i][k];
					if (!d->fileds.present || !d->fileds.write || !d->fileds.execute ||
						!d->fileds.ps ||
						d->fileds.physicalAddr != (ULONG64)i * EPT_PREALLOC_PAGES + k)
					{
						if (badLeaf == 0)
						{
							firstBadGpa = ((ULONG64)i * EPT_PREALLOC_PAGES + k) << 21;
						}
						badLeaf++;
					}
				}
			}
			if (badLeaf != 0)
			{
				FlLog("EPT自检[8] FAIL: hooked 2M叶%u/262144项异常(首项GPA=%llX, 深拷贝/marker拆页损坏)",
					badLeaf, (unsigned long long)firstBadGpa);
				fails++;
			}
			else
			{
				FlLog("EPT自检[8] hooked 262144个2M叶恒等全OK(标记区除外, 见下行)");
			}
			//标记区PTE级: 512项=511恒等+1项remap到pageB
			if (paA != 0)
			{
				PEPT_PDE pdePtr = (PEPT_PDE)&h->pde[mark1g][mark2m];
				PHYSICAL_ADDRESS pttPh = { 0 };
				pttPh.QuadPart = pdePtr->fileds.physicalAddr * PAGE_SIZE;
				PEPT_PTE ptt = (PEPT_PTE)MmGetVirtualForPhysical(pttPh);
				ULONG markPteIdx = (ULONG)((paA >> 12) & 0x1FF);
				ULONG64 base2mFrame = (paA & ~0x1FFFFFULL) >> 12;
				ULONG badPte = 0;
				if (ptt != NULL)
				{
					for (ULONG t = 0; t < 512; t++)
					{
						ULONG64 expect = (t == markPteIdx)
							? (g_geptMarkPaB >> 12) : (base2mFrame + t);
						PEPT_PTE p = &ptt[t];
						if (!p->fileds.present || !p->fileds.write ||
							!p->fileds.execute || p->fileds.physicalAddr != expect)
						{
							badPte++;
						}
					}
				}
				else
				{
					badPte = 1;    //ptt页VA映射失败(异常)
				}
				if (badPte != 0)
				{
					FlLog("EPT自检[8] FAIL: 标记区512 PTE中%u项异常(511恒等+1 remap→%llX 期望)",
						badPte, (unsigned long long)(g_geptMarkPaB >> 12));
					fails++;
				}
				else
				{
					FlLog("EPT自检[8] 标记区512 PTE全OK(511恒等+1 remap→PA %llX: 双视图真正分叉点)",
						(unsigned long long)g_geptMarkPaB);
				}
			}
		}
		//[9] hooked高区共享链(pml4[1..511]与clean指向同一批共享pdpt页)
		if (g_eptHighReady)
		{
			ULONG badHigh = 0;
			for (ULONG i = 1; i < 512; i++)
			{
				if (!h->pml4[i].fileds.present ||
					h->pml4[i].fileds.physicalAddr !=
					MmGetPhysicalAddress(g_eptHighPdptVa[i]).QuadPart / PAGE_SIZE)
				{
					badHigh++;
				}
			}
			if (badHigh != 0)
			{
				FlLog("EPT自检[9] FAIL: hooked高区链%u/511项异常(深拷贝时高区共享链损坏)",
					badHigh);
				fails++;
			}
			else
			{
				FlLog("EPT自检[9] hooked高区511链全OK(与clean共享同一批pdpt页)");
			}
		}
	}
	return fails;
}

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
	g_bEptExecOnly = (BOOLEAN)(msrCap & 1);
	if (!EptIsSupportEpt())
	{
		return STATUS_UNSUCCESSFUL;
	}
	currentVcpu->PeptData = (PEPT_DATA)MmAllocateContiguousMemory(sizeof(EPT_DATA), phys);
	if (currentVcpu->PeptData == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	//MmAllocateContiguousMemory不清零: 残留垃圾=保留位置1(misconfig
	//无限重试)或错译到随机物理页, 必须清零
	RtlZeroMemory(currentVcpu->PeptData, sizeof(EPT_DATA));

	//先建RAM位图(首次调用时), PDE内存类型由位图决定(见EptBuildRamBitmap)
	EptBuildRamBitmap();
	//双EPT标记页(全核共用一对, 首次调用时分配)
	EptAllocMarkPages();

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
			//完全RAM的2M页=WB, 其余UC
			currentVcpu->PeptData->pde[i][k].fileds.memoryType =
				EptMemTypeFor2MFrame(i * EPT_PREALLOC_PAGES + k);
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
	//预建+链接高区(全核共享, 见文件头注释)
	if (EptPrebuildHighMappings())
	{
		for (ULONG i = 1; i < 512; i++)
		{
			currentVcpu->PeptData->pml4[i].ALL = 0;
			currentVcpu->PeptData->pml4[i].fileds.present = 1;
			currentVcpu->PeptData->pml4[i].fileds.write = 1;
			currentVcpu->PeptData->pml4[i].fileds.execute = 1;
			currentVcpu->PeptData->pml4[i].fileds.physicalAddr =
				MmGetPhysicalAddress(g_eptHighPdptVa[i]).QuadPart / PAGE_SIZE;
			//惰性兜底路径识别已建好的页(不再进分配分支)
			currentVcpu->HighPdptVa[i] = g_eptHighPdptVa[i];
			//HighPdptRawVa保持NULL: 共享页由EptShutdownHighMappings统一释放
		}
	}
	//==== hooked视图EPT(每核一份深拷贝) ====
	//必须深拷贝+重指自指链(浅拷贝=两套EPT共享物理页表, 双视图失效)。
	//EptpHooked=clean EPTP仅换PML4地址(mt/walkLen/A-D一致=EPTP-list
	//有效性判据满足)。分配失败不致命(hook走violation方案)
	currentVcpu->PeptDataHooked =
		(PEPT_DATA)MmAllocateContiguousMemory(sizeof(EPT_DATA), phys);
	if (currentVcpu->PeptDataHooked != NULL)
	{
		PEPT_DATA h = currentVcpu->PeptDataHooked;
		RtlZeroMemory(h, sizeof(EPT_DATA));
		RtlCopyMemory(h, currentVcpu->PeptData, sizeof(EPT_DATA));
		h->pml4[0].ALL = 0;
		h->pml4[0].fileds.present = 1;
		h->pml4[0].fileds.write = 1;
		h->pml4[0].fileds.execute = 1;
		h->pml4[0].fileds.physicalAddr =
			MmGetPhysicalAddress(&h->pdpte[0]).QuadPart / PAGE_SIZE;
		for (ULONG i = 0; i < EPT_PREALLOC_PAGES; i++)
		{
			h->pdpte[i].fileds.physicalAddr =
				MmGetPhysicalAddress(&h->pde[i][0]).QuadPart / PAGE_SIZE;
		}
		currentVcpu->EptpHooked.ALL = currentVcpu->Eptp.ALL;
		currentVcpu->EptpHooked.fileds.physicalAddr =
			MmGetPhysicalAddress(&h->pml4[0]).QuadPart / PAGE_SIZE;
		//标记remap(hooked EPT独有, 两视图从此真正不同)
		if (EptBuildMarkRemap(h))
		{
			FlLog("cpu%u hooked EPT就绪(深拷贝): %p EPTP=%llX(仅PML4异于clean=%llX), 标记页remap=OK",
				cpuNumber, h,
				(unsigned long long)currentVcpu->EptpHooked.ALL,
				(unsigned long long)currentVcpu->Eptp.ALL);
		}
		else
		{
			FlLog("cpu%u hooked EPT就绪但标记remap失败(拆页/超512GB)——标记自测将判FAIL降级",
				cpuNumber);
		}
	}
	else
	{
		FlLog("cpu%u hooked EPT分配失败(2MB连续)——本核hook走violation方案(fallback)",
			cpuNumber);
	}
	return status;
}

//EPT页表页分配: 4KB对齐(ExAllocatePool只保证16字节对齐, 物理地址
//低12位被截断=硬件读错位页表→violation无限循环)。分配2页内部对齐。
//raw指针由调用方保存用于释放(对齐指针不能释放)
static PVOID EptAllocAlignedPage(PVOID* rawOut)
{
	PUCHAR raw = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * 2, 'Pool');
	if (raw == NULL)
	{
		return NULL;
	}
	PVOID aligned = (PVOID)(((ULONG64)raw + PAGE_SIZE - 1) & ~((ULONG64)PAGE_SIZE - 1));
	if (rawOut != NULL)
	{
		*rawOut = raw;
	}
	return aligned;
}

//预建全部高区pdpt页(首个EptInitEptData执行一次, 幂等):
//511×512个1GB UC恒等大页, 全核共享
static BOOLEAN EptPrebuildHighMappings(VOID)
{
	if (g_eptHighReady)
	{
		return TRUE;
	}
	//拆分pte页arena预建(PASSIVE一次; 部分失败照常, 耗尽走散池兜底)
	{
		PHYSICAL_ADDRESS arenaMax = { 0 };
		arenaMax.QuadPart = MAXULONG64;
		ULONG arenaOk = 0;
		for (ULONG b = 0; b < GEPT_SPLIT_ARENA_BLOCKS; b++)
		{
			if (s_splitArenaBlock[b] == NULL)
			{
				s_splitArenaBlock[b] =
					MmAllocateContiguousMemory(PAGE_SIZE * 512, arenaMax);
			}
			if (s_splitArenaBlock[b] != NULL)
			{
				arenaOk++;
			}
		}
		FlLog("EPT: 拆分pte页arena就绪: %u/%u块×2MB(耗尽后散池兜底)",
			arenaOk, (ULONG)GEPT_SPLIT_ARENA_BLOCKS);
	}
	if (!g_bEpt1GbPage)
	{
		//无1GB大页支持(罕见): 保持惰性路径
		FlLog("EPT: 本机无1GB大页支持, 高区保持惰性建表(罕见, 接管有冻结风险!)");
		return FALSE;
	}
	PHYSICAL_ADDRESS blockMax = { 0 };
	blockMax.QuadPart = MAXULONG64;
	g_eptHighPdptBlock = MmAllocateContiguousMemory(PAGE_SIZE * 512, blockMax);
	if (g_eptHighPdptBlock == NULL)
	{
		FlLog("EPT: 高区预建失败(2MB块分配失败)——放弃");
		EptShutdownHighMappings();
		return FALSE;
	}
	for (ULONG i = 1; i < 512; i++)
	{
		PEPT_PDPTE_1G pdpt = (PEPT_PDPTE_1G)
			((PUCHAR)g_eptHighPdptBlock + (ULONG)i * PAGE_SIZE);
		for (ULONG j = 0; j < 512; j++)
		{
			pdpt[j].ALL = 0;
			pdpt[j].fileds.present = 1;
			pdpt[j].fileds.write = 1;
			pdpt[j].fileds.execute = 1;
			pdpt[j].fileds.memoryType = 0;    //UC: 高区只有MMIO
			pdpt[j].fileds.largePage = 1;
			pdpt[j].fileds.physicalAddr = (ULONG64)i * 512 + j;   //1GB帧号(bits 47:30)
		}
		g_eptHighPdptVa[i] = pdpt;
	}
	g_eptHighReady = TRUE;
	FlLog("EPT: 高区预建完成: 511个pdpt(单块2MB)×512×1GB UC恒等(512GB-256TB全覆盖), 8核共享");
	return TRUE;
}

//释放共享高区页表+双EPT标记页(DriverUload/回滚调用, 幂等)
VOID EptShutdownHighMappings(VOID)
{
	if (g_eptHighPdptBlock != NULL)
	{
		MmFreeContiguousMemory(g_eptHighPdptBlock);
		g_eptHighPdptBlock = NULL;
		RtlZeroMemory(g_eptHighPdptVa, sizeof(g_eptHighPdptVa));
	}
	g_eptHighReady = FALSE;
	//标记页(全局一对)
	if (s_geptMarkVB != NULL)
	{
		MmFreeContiguousMemory(s_geptMarkVB);
		s_geptMarkVB = NULL;
		g_geptMarkPaB = 0;
	}
	if (g_geptMarkVA != NULL)
	{
		MmFreeContiguousMemory(g_geptMarkVA);
		g_geptMarkVA = NULL;
	}
	//拆分pte页(标记remap/自我隐蔽/hook产生的; 此刻VT已关或未启, 幂等)
	EptFreeSplitPtes();
}

//为超512GB的gpa动态建EPT路径(惰性兜底, 预建后理论不达):
//1GB大页(不支持时2M), 内存类型UC
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
		PVOID raw = NULL;
		pdpt = (PEPT_PDPTE)EptAllocAlignedPage(&raw);
		if (pdpt == NULL || raw == NULL)
		{
			//exit上下文不DbgPrint, 失败由调用方'A'留痕
			return FALSE;
		}
		RtlZeroMemory(pdpt, PAGE_SIZE);
		g_vcpu[cpuNumber].HighPdptVa[pml4Idx] = pdpt;
		g_vcpu[cpuNumber].HighPdptRawVa[pml4Idx] = raw;
		eptData->pml4[pml4Idx].ALL = 0;
		eptData->pml4[pml4Idx].fileds.present = 1;
		eptData->pml4[pml4Idx].fileds.write = 1;
		eptData->pml4[pml4Idx].fileds.execute = 1;
		eptData->pml4[pml4Idx].fileds.physicalAddr = MmGetPhysicalAddress(pdpt).QuadPart / PAGE_SIZE;
		//同一pdpt页同时链进hooked EPT(否则hooked视图的violation修不好)
		if (g_vcpu[cpuNumber].PeptDataHooked != NULL)
		{
			g_vcpu[cpuNumber].PeptDataHooked->pml4[pml4Idx].ALL = 0;
			g_vcpu[cpuNumber].PeptDataHooked->pml4[pml4Idx].fileds.present = 1;
			g_vcpu[cpuNumber].PeptDataHooked->pml4[pml4Idx].fileds.write = 1;
			g_vcpu[cpuNumber].PeptDataHooked->pml4[pml4Idx].fileds.execute = 1;
			g_vcpu[cpuNumber].PeptDataHooked->pml4[pml4Idx].fileds.physicalAddr =
				MmGetPhysicalAddress(pdpt).QuadPart / PAGE_SIZE;
		}
		//信息不落盘, 函数尾部FlRingPush('H')已记录
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
		//无1GB支持: 建pdt页, 512个2M大页UC(raw未跟踪, 泄漏量极小)
		PEPT_PDE_2M pdt = (PEPT_PDE_2M)EptAllocAlignedPage(NULL);
		if (pdt == NULL)
		{
			//exit上下文不DbgPrint, 失败由调用方'A'留痕
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
	//动态建表事件入环
	FlRingPush('H', KeGetCurrentProcessorNumber(), 0, gpa, pml4Idx, pdpteIdx);
	return TRUE;
}

//本核当前视图的EPT: vmread EPT_POINTER即真相(VMFUNC切换会写回该字段,
//SDM §28.5.7.3)。仅VMX root上下文可调; 失败/无hooked=返回clean兜底
PEPT_DATA EptGetActiveData(VOID)
{
	ULONG cpu = KeGetCurrentProcessorNumber();
	if (g_vcpu[cpu].PeptDataHooked != NULL && g_vcpu[cpu].bVmxOn)
	{
		ULONG64 cur = 0;
		if (__vmx_vmread(EPT_POINTER, &cur) == 0 &&
			cur == g_vcpu[cpu].EptpHooked.ALL)
		{
			return g_vcpu[cpu].PeptDataHooked;
		}
	}
	return g_vcpu[cpu].PeptData;
}

//==== REP串指令root仿真(HideRead读/写violation的MTF风暴消解) ====
//MTF路径下REP指令逐迭代violation(2N exit/串)。本仿真在root内一次
//exit完成整串: MOVS/STOS/LODS(纯数据移动, 无flags副作用); SCAS/INS/
//OUTS及0x67地址前缀回退MTF老路径。访问语义与clean视图单步一致:
//hook页内地址读写原物理页(读=原始字节, 写=透传), 其余GVA走
//GUEST_CR3四级页表翻译(EPT恒等区GPA=HPA)

//物理地址有效位(bits 51:12): 从PTE/CR3提取PA须剥离NX(bit63)/软件位
//(62:52)/标志位(11:0)——栈/数据页PTE恒NX=1, 不剥离→垃圾PA→
//MmGetVirtualForPhysical野指针→root态#PF落在VMM栈(非线程栈)→
//蓝屏0x139(4)
#define GEPT_PA_MASK 0x000FFFFFFFFFF000ULL

//四级页表walk: GVA→GPA(含1G/2M大页; 仅供框架自用, 权限位不校验)
static BOOLEAN EptGvaToGpa(ULONG64 cr3, ULONG64 gva, ULONG64* gpaOut)
{
	//canonical检查(bits 63:47须同符号)
	if ((((gva >> 47) ^ (gva >> 63)) & 1) != 0)
	{
		return FALSE;
	}
	ULONG64 pa = cr3 & GEPT_PA_MASK;
	for (ULONG level = 4; level > 0; level--)
	{
		ULONG shift = 12 + 9 * (level - 1);
		PHYSICAL_ADDRESS ptPa = { 0 };
		ptPa.QuadPart = (LONGLONG)pa;
		PULONG64 pt = (PULONG64)MmGetVirtualForPhysical(ptPa);
		if ((ULONG64)pt < 0xFFFF800000000000ULL)
		{
			return FALSE;    //NULL/KSEG查表垃圾(非canonical内核VA)
		}
		ULONG64 entry = pt[(gva >> shift) & 0x1FF];
		if ((entry & 1) == 0)
		{
			return FALSE;    //not present
		}
		//大页: PDPTE.PS=1G(页内偏移30位)/PDE.PS=2M(21位);
		//PML4E无PS位(bit7保留), 不判
		if (level == 3 && (entry & 0x80) != 0)
		{
			*gpaOut = (entry & GEPT_PA_MASK & ~0x3FFFFFFFULL) |
				(gva & 0x3FFFFFFFULL);
			return TRUE;
		}
		if (level == 2 && (entry & 0x80) != 0)
		{
			*gpaOut = (entry & GEPT_PA_MASK & ~0x1FFFFFULL) |
				(gva & 0x1FFFFFULL);
			return TRUE;
		}
		pa = entry & GEPT_PA_MASK;
	}
	*gpaOut = pa | (gva & 0xFFFULL);
	return TRUE;
}

//页指针缓存(串访问页内连续, 命中后零walk)
typedef struct _EPT_REP_CACHE
{
	ULONG64 pageBase;
	PUCHAR  ptrBase;
} EPT_REP_CACHE;

//GVA→内核可访问字节指针: hook页→原物理页VA(读原始字节/写透传);
//其余→GUEST_CR3页表walk(EPT恒等区GPA=HPA, present位即换页门槛)。
//walk别名必须canonical内核VA(MmGetVirtualForPhysical的KSEG查表对
//非常规PA可返回非canonical垃圾)。NULL=不可翻译(回退MTF)
static PUCHAR EptRepPtr(ULONG64 gva, ULONG64 cr3, PPAGE_HOOK_ENTRY entry,
	EPT_REP_CACHE* cache)
{
	ULONG64 page = gva & ~0xFFFULL;
	if (cache->ptrBase != NULL && page == cache->pageBase)
	{
		return cache->ptrBase + (gva & 0xFFFULL);
	}
	PUCHAR base = NULL;
	if (page == (ULONG64)entry->OriginalPageVA)
	{
		base = (PUCHAR)entry->OriginalPageVA;
	}
	else
	{
		//walk结果须落512GB恒等区RAM内(位图覆盖范围), 否则视为
		//不可翻译→回退MTF, 杜绝野指针直写
		ULONG64 gpa = 0;
		if (EptGvaToGpa(cr3, gva, &gpa) && gpa < 0x8000000000ULL &&
			EptMemTypeFor2MFrame(gpa >> 21) == 6)
		{
			PHYSICAL_ADDRESS pa = { 0 };
			pa.QuadPart = (LONGLONG)(gpa & GEPT_PA_MASK);
			base = (PUCHAR)MmGetVirtualForPhysical(pa);
			if ((ULONG64)base < 0xFFFF800000000000ULL)
			{
				base = NULL;    //KSEG查表垃圾防护(非canonical)
			}
		}
	}
	if (base == NULL)
	{
		return NULL;
	}
	cache->pageBase = page;
	cache->ptrBase = base;
	return base + (gva & 0xFFFULL);
}

//指令字节读取: root直读内核VA(host页表覆盖全内核空间; 取指页正在
//执行=恒present), 不走walk/MmGetVirtualForPhysical。窗口以页边界为限,
//页内未见opcode→返回短窗口由调用方回退MTF; 取指页=hook页时从CodePage
//读(hooked视图取指语义)。返回读到的字节数, 0=失败
static ULONG EptRepReadCode(ULONG64 rip, PPAGE_HOOK_ENTRY entry, UCHAR* buf)
{
	if ((rip >> 48) != 0xFFFF)
	{
		return 0;    //非canonical内核VA(防御)
	}
	ULONG64 rest = (rip | 0xFFFULL) + 1 - rip;
	ULONG len = rest < 15 ? (ULONG)rest : 15;
	PUCHAR src = (PUCHAR)rip;
	if ((rip & ~0xFFFULL) == (ULONG64)entry->OriginalPageVA)
	{
		src = (PUCHAR)entry->CodePageVA + (rip & 0xFFFULL);
	}
	RtlCopyMemory(buf, src, len);
	return len;
}

//REP串仿真: 成功=TRUE并完成全串(*OutLen=指令长度, 调用方推进RIP);
//中途不可翻译=FALSE(已完成元素的GPR已更新, 剩余交MTF老路径重执行,
//重复复制幂等无害)
static BOOLEAN EptRepEmulate(PGUEST_REGS regs, ULONG64 rip, ULONG64 cr3,
	PPAGE_HOOK_ENTRY entry, ULONG* OutLen)
{
	UCHAR code[15];
	ULONG codeLen = EptRepReadCode(rip, entry, code);
	if (codeLen == 0)
	{
		return FALSE;
	}
	//前缀解析: F2/F3=REP, 66=操作数宽, 67=地址宽(不支持→回退), REX
	UCHAR* p = code;
	UCHAR* end = code + codeLen;
	BOOLEAN rep = FALSE, op66 = FALSE, ad67 = FALSE, rexw = FALSE;
	while (p < end)
	{
		UCHAR c = *p;
		if (c == 0xF3 || c == 0xF2) { rep = TRUE; }
		else if (c == 0x66) { op66 = TRUE; }
		else if (c == 0x67) { ad67 = TRUE; }
		else if ((c & 0xF0) == 0x40) { rexw = (c & 0x08) != 0; }
		else if (c == 0x2E || c == 0x36 || c == 0x3E || c == 0x26 ||
			c == 0x64 || c == 0x65) {
			;
		}    //段前缀: 串指令忽略
		else { break; }
		p++;
	}
	*OutLen = (ULONG)(p - code) + 1;
	if (!rep || ad67 || p >= end)
	{
		return FALSE;
	}
	UCHAR op = *p;
	//仅MOVS/STOS/LODS(A4/A5/AA/AB/AC/AD); SCAS(flags语义)与INS/OUTS(IO)回退
	if (op != 0xA4 && op != 0xA5 && op != 0xAA && op != 0xAB &&
		op != 0xAC && op != 0xAD)
	{
		return FALSE;
	}
	ULONG esize = (op & 1) ? (rexw ? 8 : 4) : 1;
	if ((op & 1) && op66)
	{
		esize = 2;
	}
	ULONG64 rflags = 0;
	__vmx_vmread(GUEST_RFLAGS, &rflags);
	LONG64 step = (rflags & 0x400) ? -(LONG64)esize : (LONG64)esize;
	ULONG64 cnt = regs->rcx;
	if (cnt == 0)
	{
		return TRUE;    //count=0: 串指令为空操作, 仅推进RIP
	}
	EPT_REP_CACHE sc = { 0, NULL }, dc = { 0, NULL };
	for (ULONG64 i = 0; i < cnt; i++)
	{
		//元素内逐字节解析指针(元素可跨页)
		UCHAR tmp[8];
		for (ULONG o = 0; o < esize; o++)
		{
			BOOLEAN ok = TRUE;
			switch (op & ~1)
			{
			case 0xA4:    //MOVS: [RDI]=[RSI]
			{
				PUCHAR ps = EptRepPtr(regs->rsi + o, cr3, entry, &sc);
				PUCHAR pd = EptRepPtr(regs->rdi + o, cr3, entry, &dc);
				if (ps != NULL && pd != NULL)
				{
					*pd = *ps;
				}
				else
				{
					ok = FALSE;
				}
				break;
			}
			case 0xAA:    //STOS: [RDI]=AL/AX/EAX/RAX
			{
				PUCHAR pd = EptRepPtr(regs->rdi + o, cr3, entry, &dc);
				if (pd != NULL)
				{
					*pd = (UCHAR)(regs->rax >> (8 * o));
				}
				else
				{
					ok = FALSE;
				}
				break;
			}
			default:      //LODS: AL/AX/EAX/RAX=[RSI]
			{
				PUCHAR ps = EptRepPtr(regs->rsi + o, cr3, entry, &sc);
				if (ps != NULL)
				{
					tmp[o] = *ps;
				}
				else
				{
					ok = FALSE;
				}
				break;
			}
			}
			if (!ok)
			{
				//本元素不可翻译: 部分已复制字节与MTF重执行幂等
				regs->rcx = cnt - i;
				return FALSE;
			}
		}
		if (op == 0xAC || op == 0xAD)
		{
			ULONG64 v = 0;
			for (ULONG o = 0; o < esize; o++)
			{
				v |= (ULONG64)tmp[o] << (8 * o);
			}
			regs->rax = v;
			regs->rsi += step;
		}
		else if (op == 0xA4 || op == 0xA5)
		{
			regs->rsi += step;
			regs->rdi += step;
		}
		else
		{
			regs->rdi += step;
		}
	}
	regs->rcx = 0;
	return TRUE;
}


void EptExitHandler(PGUEST_REGS GuestRegs)
{
	EPT_EXITDATA eptExit = { 0 };
	ULONG64 gpa = 0;
	ULONG64 guestRip = 0;
	ULONG64 guestRsp = 0;
	__vmx_vmread(GUEST_RIP, &guestRip);
	__vmx_vmread(GUEST_RSP, &guestRsp);
	__vmx_vmread(EXIT_QUALIFICATION, &eptExit);
	//获取哪个地址触发的exit事件
	__vmx_vmread(GUEST_PHYSICAL_ADDRESS, &gpa);
	//violation四元组入环
	FlRingPush('V', KeGetCurrentProcessorNumber(), 48, gpa, guestRip, eptExit.ALL);
	//violation发生在当前视图的表上(vmread EPT_POINTER裁决act指向哪套)
	PEPT_DATA act = EptGetActiveData();
	//判断这个地址所在页是否被我们hook过
	ULONG64 pfn = gpa / PAGE_SIZE;
	PPAGE_HOOK_ENTRY pageEntry = PHGetHookEntryPageBy(pfn);
	if (pageEntry == NULL)
	{
		//未被hook的页violation: 直接return=同指令无限重试; 修复须作用在
		//ACTIVE视图的表上
		PEPT_PDE_2M pde2M = EptGetPde2B(act, gpa);
		if (pde2M != NULL)
		{
			//512GB内但2M页尚未拆分等情形: 恢复该PTE全部权限让指令继续执行
			PEPT_PTE ppte = EptGetPte(act, gpa);
			if (ppte != NULL)
			{
				//身份检查: 非恒等映射=自我隐蔽页(改译零页)。仍放开权限
				//让访问落零页(静默吸收, 裸机单页近似), 'O'留痕(采样)
				//——框架自身路径误写隐蔽页(=静默失效类bug)依赖此事件暴露
				if (ppte->fileds.physicalAddr != (gpa >> 12))
				{
					static volatile LONG s_oCnt[64] = { 0 };
					ULONG oCpu = KeGetCurrentProcessorNumber();
					LONG on = InterlockedIncrement(&s_oCnt[oCpu & 63]);
					if (on == 1 || (on & 0xFFF) == 0)
					{
						FlRingPush('O', oCpu, 48, gpa,
							(ULONG64)ppte->fileds.physicalAddr, 0);
					}
				}
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
			//刷新EPT缓存(否则旧翻译=继续violation)
			EptInveptCurrent();
			//'P'环路检测: 同一gpa>100次=结构性bug, 逃生'P'
			static volatile ULONG64 s_pGpa[128] = { 0 };
			static volatile LONG s_pCnt[128] = { 0 };
			ULONG cpuP = KeGetCurrentProcessorNumber();
			if (s_pGpa[cpuP] != gpa)
			{
				s_pGpa[cpuP] = gpa;
				s_pCnt[cpuP] = 0;
			}
			if (InterlockedIncrement(&s_pCnt[cpuP]) > 100)
			{
				VmxExitStormEscape('P', 48, gpa, guestRip, GuestRegs);    //noreturn
			}
		}
		else
		{
			//超出512GB恒等映射: 动态建立EPT路径(惰性, UC内存类型对MMIO安全)
			if (EptBuildHighMapping(gpa))
			{
				//映射已建立, 刷新后重执行
				EptInveptCurrent();
				//风暴检测: 同一gpa>1000次=页表结构性bug, 逃生'X'
				static volatile ULONG64 s_stormGpa[128] = { 0 };
				static volatile LONG s_stormCnt[128] = { 0 };
				ULONG cpu = KeGetCurrentProcessorNumber();
				if (s_stormGpa[cpu] != gpa)
				{
					s_stormGpa[cpu] = gpa;
					s_stormCnt[cpu] = 0;
				}
				if (InterlockedIncrement(&s_stormCnt[cpu]) > 1000)
				{
					VmxExitStormEscape('X', 48, gpa, guestRip, GuestRegs);    //noreturn
				}
			}
			else
			{
				//分配失败: 逃生'A'
				VmxExitStormEscape('A', 48, gpa, guestRip, GuestRegs);    //noreturn
			}
		}
		return;
	}
	//==== hooked视图hook页读/写violation(HideRead=1布防, VMFUNC核) ====
	//REP串优先root仿真(单exit吸收整串, 消解MTF逐迭代风暴); 非串指令
	//或不可翻译回退MTF读透明
	if ((eptExit.fileds.read || eptExit.fileds.write) && pageEntry->HideRead &&
		g_vcpu[KeGetCurrentProcessorNumber()].bVmfuncOn &&
		g_vcpu[KeGetCurrentProcessorNumber()].PeptDataHooked != NULL)
	{
		ULONG repLen = 0;
		ULONG64 guestCr3 = 0;
		__vmx_vmread(GUEST_CR3, &guestCr3);
		if (EptRepEmulate(GuestRegs, guestRip, guestCr3, pageEntry, &repLen))
		{
			//'q'留痕(采样: 首次+每4096次)
			static volatile LONG s_qCnt[128] = { 0 };
			ULONG cpuQ = KeGetCurrentProcessorNumber();
			LONG qn = InterlockedIncrement(&s_qCnt[cpuQ & 127]);
			if (qn == 1 || (qn & 0xFFF) == 0)
			{
				FlRingPush('q', cpuQ, 48, guestRip, GuestRegs->rcx, 0);
			}
			__vmx_vmwrite(GUEST_RIP, guestRip + repLen);
			__vmx_vmwrite(GUEST_RSP, guestRsp);
			return;
		}
		//MTF读透明: 切clean+开MTF→重执行该指令(读/写落原页)→MTF exit(37)
		//切回hooked+关MTF。读方(PG/扫描器)只见原始字节; 中断注入最坏多走
		//一轮本循环, 收敛
		ULONG cpuM = KeGetCurrentProcessorNumber();
		__vmx_vmwrite(EPT_POINTER, g_vcpu[cpuM].Eptp.ALL);
		ULONG64 mtfCtl = 0;
		__vmx_vmread(CPU_BASED_VM_EXEC_CONTROL, &mtfCtl);
		__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, mtfCtl | 0x08000000ULL);
		//'M'留痕(采样: 首次+每4096次, 防扫描风暴刷爆环)
		static volatile LONG s_mCnt[128] = { 0 };
		LONG mn = InterlockedIncrement(&s_mCnt[cpuM & 127]);
		if (mn == 1 || (mn & 0xFFF) == 0)
		{
			FlRingPush('M', cpuM, 48, gpa, guestRip, eptExit.ALL);
		}
		__vmx_vmwrite(GUEST_RIP, guestRip);
		__vmx_vmwrite(GUEST_RSP, guestRsp);
		return;
	}
	if (eptExit.fileds.read)
	{
		EptUpdatePageAcess(act, gpa, 1, pageEntry);
	}
	if (eptExit.fileds.write)
	{
		EptUpdatePageAcess(act, gpa, 2, pageEntry);
	}
	if (eptExit.fileds.execute)
	{
		EptUpdatePageAcess(act, gpa, 3, pageEntry);
	}
	//刷新EPT缓存(否则旧TLB条目=再次violation活锁)
	EptInveptCurrent();

	__vmx_vmwrite(GUEST_RIP, guestRip);
	__vmx_vmwrite(GUEST_RSP, guestRsp);
}


void EptSetHook(ULONG64 orginalPagePFN, ULONG64 codePagePFN, ULONG64 hideRead)
{
	ULONG cpuHook = KeGetCurrentProcessorNumber();
	//==== VMFUNC主路径(零VM-Exit hook) ====
	//hooked EPT里hook页PTE→CodePage(X=1,R=1,W=0)+切入hooked视图:
	//执行零VM-Exit, clean视图下原页字节完好。写hook页(W=0)→violation
	//→EptUpdatePageAcess在hooked表上互切(与violation方案同骨架)
	if (g_vcpu[cpuHook].bVmfuncOn && g_vcpu[cpuHook].PeptDataHooked != NULL)
	{
		//hideRead读透明: R=0(exec-only)——读/写violation走MTF路径
		//(EptExitHandler切clean单步透出原始字节); CPU不支持exec-only
		//时回退R=1(读hook页=CodePage副本字节, 可见)
		BOOLEAN bHide = (hideRead != 0 && g_bEptExecOnly);
		PEPT_DATA he = g_vcpu[cpuHook].PeptDataHooked;
		//相当于有了GPA 要获取HPA
		ULONG64 oPFN = orginalPagePFN << 12;
		PEPT_PDE_2M oPde2M = EptGetPde2B(he, oPFN);
		if (oPde2M == NULL)
		{
			FlRingPush('n', cpuHook, 2, orginalPagePFN, codePagePFN, 0);
			return;
		}
		//hook页所在2M若未拆分则在hooked表内拆(只影响hooked视图)
		if (oPde2M->fileds.ps)
		{
			if (!EptPdeToPte(oPde2M))
			{
				FlRingPush('n', cpuHook, 2, orginalPagePFN, 0, 0);
				return;
			}
			FlRingPush('S', cpuHook, 21, orginalPagePFN,
				((PEPT_PDE)oPde2M)->fileds.physicalAddr, 0);
		}
		PEPT_PTE pte = EptGetPte(he, oPFN);
		if (pte == NULL)
		{
			FlRingPush('n', cpuHook, 2, orginalPagePFN, 0, 0);
			return;
		}
		//hook页PTE→CodePage: X=1 R=1(执行中读同页数据不violation) W=0;
		//bHide时R=0: 读/写violation→EptExitHandler的MTF路径
		pte->fileds.physicalAddr = codePagePFN;
		pte->fileds.present = !bHide;
		pte->fileds.execute = 1;
		pte->fileds.write = 0;
		//切入hooked视图(先vmwrite再invept)
		__vmx_vmwrite(EPT_POINTER, g_vcpu[cpuHook].EptpHooked.ALL);
		//刷新TLB(all-context覆盖两套EPT; VMFUNC自带的失效不覆盖root侧)
		EptInveptCurrent();
		//布防标记: rsn=24=R=1形态 / rsn=25=读透明形态(R=0+MTF)
		FlRingPush('S', cpuHook, bHide ? 25 : 24, orginalPagePFN, codePagePFN,
			g_vcpu[cpuHook].EptpHooked.ALL);
		return;
	}
	//==== violation方案(fallback: 无VMFUNC/无hooked EPT/标记自测FAIL的核) ====
	//相当于有了GPA 要获取HPA
	ULONG64 oPFN = orginalPagePFN << 12;
	ULONG64 cPFN = codePagePFN << 12;
	//获取PDE/PTE
	PEPT_PDE_2M oPde2M = EptGetPde2B(g_vcpu[cpuHook].PeptData, oPFN);
	PEPT_PDE_2M cPed2M = EptGetPde2B(g_vcpu[cpuHook].PeptData, cPFN);
	if (oPde2M == NULL || cPed2M == NULL)
	{
		//中止留痕(>512GB或页表越界: hook静默未建立)
		FlRingPush('n', cpuHook, 2,
			orginalPagePFN, codePagePFN, 0);
		return;
	}
	//判断如果是2M页，就进行拆分
	if (oPde2M->fileds.ps)
	{
		//将当前的GPA所在的PDE 拆分成1个ptt 也就是512个pte
		BOOLEAN status = EptPdeToPte(oPde2M);
		if (!status)
		{
			FlRingPush('n', cpuHook, 2,
				orginalPagePFN, 0, 0);
			return;
		}
		//三步'S'之一(拆原页完成), b=新pte表物理帧号
		FlRingPush('S', cpuHook, 21,
			orginalPagePFN, ((PEPT_PDE)oPde2M)->fileds.physicalAddr, 0);
	}

	if (cPed2M->fileds.ps)
	{
		//将当前的GPA所在的PDE 拆分成1个ptt 也就是512个pte
		BOOLEAN status = EptPdeToPte(cPed2M);
		if (!status)
		{
			FlRingPush('n', cpuHook, 2,
				0, codePagePFN, 0);
			return;
		}
		//三步'S'之二(拆CodePage完成), b=新pte表帧号
		FlRingPush('S', cpuHook, 22,
			codePagePFN, ((PEPT_PDE)cPed2M)->fileds.physicalAddr, 0);
	}
	//修改页属性，将执行权限去掉
	PEPT_PTE pte = EptGetPte(g_vcpu[cpuHook].PeptData, oPFN);//

	if (pte == NULL)
	{
		FlRingPush('n', cpuHook, 2,
			orginalPagePFN, 0, 0);
		return;
	}
	pte->fileds.execute = 0;
	//刷新EPT缓存(否则旧exec条目存活=hook延迟生效)
	EptInveptCurrent();
	//布防完成标记: rsn=23(21/22/23=拆原页/拆Code页/清execute三步)
	FlRingPush('S', cpuHook, 23,
		orginalPagePFN, codePagePFN, 0);
}

PEPT_PDE_2M EptGetPde2B(PEPT_DATA ept, ULONG64 PFN)
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
	//显式EPT_DATA(双EPT)——恒等区(pml4[0])内直接索引目标表的pde数组
	return &(ept->pde[pdpteIndex][pdeindex]);
}

//==================== 拆分pte页登记+EPT自我隐蔽状态 ====================
//EptPdeToPte拆分2M页时登记: raw供EptFreeSplitPtes释放, 对齐VA供
//EptHideFrameworkPages改译零页(须定义在EptPdeToPte之前)。
//上限经验式≈585+783×(核数-1)(每核隐蔽须拆自有EPT表), 16384覆盖
//≤20核(BSS代价256KB); 溢出见EptPdeToPte的'O'环留痕
#define GEPT_SPLIT_PTE_MAX 16384
static PVOID s_splitRaw[GEPT_SPLIT_PTE_MAX];  //拆分pte页raw指针(释放用)
static PVOID s_splitVa[GEPT_SPLIT_PTE_MAX];   //对齐后VA(隐蔽对象)
static volatile LONG s_splitCount = 0;
static PVOID s_hideZeroPage = NULL;   //共享零页(改译目标)
static ULONG64 s_hideZeroPFN = 0;

BOOLEAN EptPdeToPte(PEPT_PDE_2M pde2M)
{
	BOOLEAN status = TRUE;
	//arena切槽(页对齐免费, Interlocked任意IRQL安全); 耗尽/未建→
	//散池兜底(raw登记, EptFreeSplitPtes释放)。VA统一登记(自我隐蔽)
	PVOID raw = NULL;
	PEPT_PTE ppte = NULL;
	for (ULONG b = 0; b < GEPT_SPLIT_ARENA_BLOCKS; b++)
	{
		if (s_splitArenaBlock[b] == NULL)
		{
			continue;
		}
		LONG slot = InterlockedIncrement(&s_splitArenaUsed[b]) - 1;
		if (slot < 512)
		{
			ppte = (PEPT_PTE)((PUCHAR)s_splitArenaBlock[b]
				+ (ULONG)slot * PAGE_SIZE);
			break;
		}
	}
	if (ppte == NULL)
	{
		ppte = (PEPT_PTE)EptAllocAlignedPage(&raw);
	}
	if (ppte == NULL)
	{
		return FALSE;
	}
	LONG idx = InterlockedIncrement(&s_splitCount) - 1;
	if (idx < GEPT_SPLIT_PTE_MAX)
	{
		s_splitRaw[idx] = raw;
		s_splitVa[idx] = ppte;
	}
	else if (idx == GEPT_SPLIT_PTE_MAX || (idx & 0xFFF) == 0)
	{
		//登记溢出: 该拆分页不自我隐蔽+卸载不释放。exit上下文禁FlLog
		//→'O'环留痕(首个+每4096个采样)
		FlRingPush('O', KeGetCurrentProcessorNumber(), 0,
			(ULONG64)(ULONG)idx, 0, 0);
	}
	RtlZeroMemory(ppte, sizeof(EPT_PTE) * 512);
	for (size_t i = 0; i < 512; i++)
	{
		ppte[i].fileds.present = 1;
		ppte[i].fileds.write = 1;
		ppte[i].fileds.execute = 1;
		//继承源2M页内存类型(漏设UC=取指性能塌方)
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

PEPT_PTE EptGetPte(PEPT_DATA ept, ULONG64 PFN)
{
	PEPT_PDE_2M pde2M = EptGetPde2B(ept, PFN);
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

//==================== EPT自我隐蔽(框架私有页→零页) ====================
//VMXON/VMCS/VMM栈/MSR位图/EPT表/EPTP-list/高区pdpt/标记页/拆分pte页
//只有root模式与硬件walker访问(VMCS类结构CPU按HPA直读不走EPT翻译),
//guest视野不需要; 两套视图统一改译共享零页=MmMapIoSpace类物理
//签名扫描只见零。DMA绕过EPT=残留

//单GPA在指定视图改译零页(P=1 W=0 X=0; 内存类型继承所在2M块)
static VOID EptHideOneGpa(PEPT_DATA ept, ULONG64 gpa)
{
	PEPT_PDE_2M pde = EptGetPde2B(ept, gpa);
	if (pde == NULL)
	{
		return;    //>512GB(框架页都在低区, 防御)
	}
	if (pde->fileds.ps && !EptPdeToPte(pde))
	{
		return;    //拆分失败: 该页保持可见(尽力而为)
	}
	PEPT_PTE pte = EptGetPte(ept, gpa);
	if (pte == NULL)
	{
		return;
	}
	pte->fileds.physicalAddr = s_hideZeroPFN;
	pte->fileds.present = 1;
	pte->fileds.write = 0;
	pte->fileds.execute = 0;
}

//连续VA区间逐页改译(两视图; NULL/零长安全)
static VOID EptHideVaRange(PEPT_DATA clean, PEPT_DATA hooked, PVOID va, ULONG64 bytes)
{
	if (va == NULL || bytes == 0)
	{
		return;
	}
	ULONG64 pa = MmGetPhysicalAddress(va).QuadPart;
	for (ULONG64 off = 0; off < bytes; off += PAGE_SIZE)
	{
		EptHideOneGpa(clean, pa + off);
		if (hooked != NULL)
		{
			EptHideOneGpa(hooked, pa + off);
		}
	}
}

//每核vmlaunch前调用: 此刻全部核资源已分配(串行启动), 本核两视图
//把全部框架私有页(含他核的——每核访客可扫全物理内存)改译零页
VOID EptHideFrameworkPages(ULONG cpuNumber)
{
	PEPT_DATA clean = g_vcpu[cpuNumber].PeptData;
	PEPT_DATA hooked = g_vcpu[cpuNumber].PeptDataHooked;
	if (clean == NULL)
	{
		return;
	}
	if (s_hideZeroPage == NULL)
	{
		s_hideZeroPage = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'Pool');
		if (s_hideZeroPage == NULL)
		{
			FlLog("EPT自我隐蔽: 零页分配失败, 本核跳过(其余核重试)");
			return;
		}
		RtlZeroMemory(s_hideZeroPage, PAGE_SIZE);
		s_hideZeroPFN = MmGetPhysicalAddress(s_hideZeroPage).QuadPart >> 12;
	}
	ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
	for (ULONG c = 0; c < cpuCount; c++)
	{
		EptHideVaRange(clean, hooked, g_vcpu[c].VMXON, PAGE_SIZE);
		EptHideVaRange(clean, hooked, g_vcpu[c].VMCS, PAGE_SIZE);
		EptHideVaRange(clean, hooked, g_vcpu[c].VMMStack, PAGE_SIZE * 6);
		EptHideVaRange(clean, hooked, g_vcpu[c].MsrBitMap, PAGE_SIZE);
		EptHideVaRange(clean, hooked, g_vcpu[c].VmfuncEptpList, PAGE_SIZE);
		EptHideVaRange(clean, hooked, g_vcpu[c].PeptData, sizeof(EPT_DATA));
		EptHideVaRange(clean, hooked, g_vcpu[c].PeptDataHooked, sizeof(EPT_DATA));
	}
	//共享高区pdpt([0]未用)+双EPT标记页(verify已过, 运行期无读者)
	for (ULONG i = 1; i < 512; i++)
	{
		EptHideVaRange(clean, hooked, g_eptHighPdptVa[i], PAGE_SIZE);
	}
	EptHideVaRange(clean, hooked, g_geptMarkVA, PAGE_SIZE);
	EptHideVaRange(clean, hooked, s_geptMarkVB, PAGE_SIZE);
	//拆分pte页迭代收敛: 藏一页可能拆出新pte页(其自身也要藏)
	LONG processed = 0;
	for (ULONG round = 0; round < 16 && processed < s_splitCount; round++)
	{
		LONG n = s_splitCount;
		for (; processed < n && processed < GEPT_SPLIT_PTE_MAX; processed++)
		{
			EptHideVaRange(clean, hooked, s_splitVa[processed], PAGE_SIZE);
		}
	}
	EptInveptBothViews();
	FlRingPush('H', cpuNumber, 0, s_hideZeroPFN, (ULONG64)(ULONG)s_splitCount, 0);
	FlLog("EPT自我隐蔽: cpu%u两视图改译零页(框架结构+高区pdpt+标记页+%u个拆分pte页)",
		cpuNumber, (ULONG)s_splitCount);
}

//释放全部拆分pte页(vmx_off后/回滚调用, 幂等)
VOID EptFreeSplitPtes(VOID)
{
	LONG n = s_splitCount;
	if (n > GEPT_SPLIT_PTE_MAX)
	{
		n = GEPT_SPLIT_PTE_MAX;
	}
	for (LONG i = 0; i < n; i++)
	{
		if (s_splitRaw[i] != NULL)
		{
			ExFreePool(s_splitRaw[i]);
			s_splitRaw[i] = NULL;
		}
	}
	s_splitCount = 0;
	//arena块统一释放(槽无独立raw)
	for (ULONG b = 0; b < GEPT_SPLIT_ARENA_BLOCKS; b++)
	{
		if (s_splitArenaBlock[b] != NULL)
		{
			MmFreeContiguousMemory(s_splitArenaBlock[b]);
			s_splitArenaBlock[b] = NULL;
		}
		s_splitArenaUsed[b] = 0;
	}
}

//统一invept入口: 能力探测+正确EPTP+VMfail留痕。
//invept类型(SDM): 1=single-context(desc的EPTP匹配失效), 2=all-context。
//single-context时desc必须填当前EPT_POINTER(全零=匹配不到=no-op)
VOID EptInveptCurrent(VOID)
{
	EPT_CTX ctx = { 0 };
	ULONG64 cap = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
	if (cap & (1ULL << 26))
	{
		if (!VmxInvept(2, &ctx))
		{
			return;    //all-context成功(最彻底)
		}
		//bit26在却VMfail(异常): 落到single-context重试
	}
	if (cap & (1ULL << 25))
	{
		//single-context: 填当前VMCS的EPT_POINTER
		__vmx_vmread(EPT_POINTER, &ctx.PEPT);
		if (!VmxInvept(1, &ctx))
		{
			return;
		}
	}
	//都VMfail(理论不可能): 'e'环留痕, hook退化为TLB自然逐出后生效
	FlRingPush('e', KeGetCurrentProcessorNumber(), 0, cap, 0, 0);
}

//vmx_off前双视图invept(EPT派生TLB零残留)。all-context一次覆盖两套;
//single-context型CPU逐视图失效(接受任意EPTP)
VOID EptInveptBothViews(VOID)
{
	ULONG64 cap = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
	if (cap & (1ULL << 26))
	{
		EPT_CTX allCtx = { 0 };
		if (!VmxInvept(2, &allCtx))
		{
			return;    //all-context成功=两套EPT一次覆盖
		}
	}
	ULONG cpu = KeGetCurrentProcessorNumber();
	EPT_CTX ctx = { 0 };
	if (g_vcpu[cpu].PeptDataHooked != NULL)
	{
		ctx.PEPT = g_vcpu[cpu].EptpHooked.ALL;
		VmxInvept(1, &ctx);
	}
	ctx.PEPT = g_vcpu[cpu].Eptp.ALL;
	VmxInvept(1, &ctx);
}

//互切发生在ACTIVE视图表上: 写→切原页(R/W, X=0)→写落原页→执行violation
//→切回CodePage(X=1,R=1,W=0)。CodePage副本写后stale=已知限制
void EptUpdatePageAcess(PEPT_DATA ept, ULONG64 gpa, UCHAR acess, PPAGE_HOOK_ENTRY pageEntry)
{
	//获取pte
	PEPT_PTE ppte = EptGetPte(ept, gpa);
	if (ppte == NULL)
	{
		return;
	}
	//视图切换留痕('x'): a=1读/2写/3执行, b=gpa, c=Code页PFN
	FlRingPush('x', KeGetCurrentProcessorNumber(), acess, gpa,
		pageEntry->CodePagePFN, pageEntry->OriginalPagePFN);
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
		//保持可读: "执行中读同页数据"的指令否则会在两视图间无限互切活锁
		ppte->fileds.present = 1;
		ppte->fileds.execute = 1;
		ppte->fileds.write = 0;
	}
}






