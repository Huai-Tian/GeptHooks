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

//==================== EPT内存类型按真实RAM布局 ====================
//根因: 若把0-512GB**全部**标成memoryType=6(WB可缓存), 物理空间里的
//MMIO洞(LAPIC 0xFEE00000 / IOAPIC 0xFEC00000 / HPET 0xFED00000 /
//AHCI/USB/GPU低地址BAR, 全部<4GB)会被错误缓存:
//  写MMIO寄存器(清中断原因) -> 写进CPU缓存行永不抵达设备 -> 中断永远
//  pending -> ISR风暴独占该核; 读MMIO寄存器 -> 拿到stale缓存值 ->
//  I/O永不完成。两者都表现为整机冻结(所有核等待磁盘/中断响应), 无bugcheck。
//修复: MmGetPhysicalMemoryRanges获取真实RAM布局, 2MB大页**完全**落在
//RAM内才WB, 否则(纯MMIO或RAM/MMIO边界页)UC。UC只损失性能, 绝不损失
//正确性。位图32KB(512GB/2MB/8), DriverEntry里建一次, 全部核共用。
#define EPT_2M_FRAME_COUNT (EPT_PREALLOC_PAGES * EPT_PREALLOC_PAGES)   //262144
#define EPT_RAM_BITMAP_BYTES (EPT_2M_FRAME_COUNT / 8)                  //32KB
static UCHAR g_eptRamBitmap[EPT_RAM_BITMAP_BYTES];    //BSS自动清零: 1=该2MB页完全在RAM内
static BOOLEAN g_eptRamBitmapReady = FALSE;

//==================== 高区(512GB-256TB)EPT预建 ====================
//根因: GPU ReBAR等高地址MMIO(>512GB)被线程/DPC/ISR触碰时, 若走惰性
//建表路径, EptBuildHighMapping会在**VM-exit上下文**执行
//ExAllocatePoolWithTag——若被中断者持池锁(DPC抢占线程)或处于DIRQL
//(ISR): 池锁自旋永不出来 → 该核楔死 → 全局池锁被卡 → 所有核的池
//分配全部自旋 → 整机冻结(含日志线程的ZwWriteFile→IRP分配), 画面卡死。
//修复: DriverEntry(PASSIVE级)一次性预建pml4[1..511]全部511个pdpt页
//(每页512个1GB UC恒等大页, 覆盖512GB-256TB全部物理地址空间), 全部核
//EPT共享同一批页表 → 任何高地址MMIO访问**直接翻译成功, 零exit零分配**。
//惰性路径保留为兜底: 预建后HighPdptVa非空+pdpte已present → 原路径
//退化为纯读+invept, 任意IRQL安全。内存代价: 511×8KB≈4MB NonPaged(共享)。
static PVOID g_eptHighPdptVa[512];     //共享高区pdpt页(4KB对齐后; [0]未用)
static PVOID g_eptHighPdptRaw[512];    //原始pool指针(统一释放用)
static BOOLEAN g_eptHighReady = FALSE;
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
		//只标记"完整"落在[base,end)内的2MB帧: 首帧=ceil(base/2M),
		//尾帧(不含)=floor(end/2M)。边界半页标UC(安全侧)
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
//功能: hooked EPT里把pageA的GPA改译到pageB物理页。guest内读同一VA:
//  clean视图(恒等)   → 读到 GEPT_MARK_A "CLEANEPT"
//  hooked视图(remap) → 读到 GEPT_MARK_B "HOOKEDPT"
//B值的出现=VMFUNC切换到的是**真实独立翻译的第二套EPT**(区别于
//no-op往返验证升级为功能验证)。分配在EptInitEptData首次调用(PASSIVE),
//释放走EptShutdownHighMappings(unload/回滚, 幂等)
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

//在hooked EPT里建立标记remap: 拆pageA所在2M页→PTE改指pageB物理帧
//(全权限, 内存类型继承源2M页)。launch前+PASSIVE级调用(表从未被硬件
//walk过)=无需invept。返回FALSE=pageA超512GB/拆分失败(标记自测判FAIL)
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

//==================== vmlaunch前EPT软件自检门 ====================
//动机: EPT若把落地代码页静默错译到别的物理帧(权限位全对、不触发
//violation/misconfig), guest执行的就是"别的内存的内容"=整机瞬间混乱
//冻结且零日志——"死在黑盒里"零信息。
//本函数在launch前用**软件走查**复演硬件EPT翻译, 把"死在黑盒里"变成
//"launch前精确报错+安全放弃"(失败核留在root模式, 系统存活, T1继续记录):
//  [1] EPTP: 保留位清零/walkLen=3/PML4物理地址==MmGetPhysicalAddress(pml4)
//  [2] pml4[0] -> pdpte 物理链
//  [3] pdpte[i] -> pde[i][0] 物理链(512项全查)
//  [4] pde[i][k] 恒等帧+P/W/X/ps位(262144项全扫, 顺序读2MB, 微秒级)
//  [5] 关键样本页走查: 探针代码页/落地标签页/guest栈页/CR3页表/IDT/GDT/KPCR
//返回失败组数(0=通过)。guestRspVa=GUEST_RSP(CmGuestRsp帧内栈指针)
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
	//[2][3] 非叶物理链: 硬件walk踩的就是这些指针, 错一项=后面全错位
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
	//[6] 高区链——511个pml4[1..511]全部指向共享pdpt页, 抽查
	//首(pml4[1]/pdpt[0]=512GB,帧512)尾(pml4[511]/pdpt[511]=256TB-1GB,帧262143)
	//两片1GB UC恒等叶。接管后GPU等高MMIO全靠这批页直接翻译(零exit零分配)
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
	//双视图的第二套表在launch前用软件走查复演(把"死在黑盒"变成launch前
	//精确报错): [7]深拷贝自指链 [8]叶全扫+标记remap [9]高区共享链。
	//任一FAIL=该核vmlaunch放弃(与clean自检同处置)——hooked表结构错的
	//核绝不让它进guest后切视图
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
			//SDM §28.5.7.3 EPTP-list项有效性: walkLen已验, 此处验mt/A-D与
			//clean一致(全位复制构造, 不一致=构造代码回归)
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
	if (!EptIsSupportEpt())
	{
		return STATUS_UNSUCCESSFUL;
	}
	currentVcpu->PeptData = (PEPT_DATA)MmAllocateContiguousMemory(sizeof(EPT_DATA), phys);
	if (currentVcpu->PeptData == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	//MmAllocateContiguousMemory不清零(文档明示)! 残留垃圾会让pml4[1..511]/pdpte/pde
	//的保留位随机置1: 轻则EPT misconfig无限重试(整机卡死), 重则翻译到随机物理页
	//(静默数据损坏)。原实现同样漏了这行, 碰巧拿到清零页才"能用"。
	//这是vmlaunch成功后仍卡死的头号根因。
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
			//完全RAM的2M页=WB, MMIO洞/边界页=UC(整机冻结根因修复)
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
	//预建+链接高区(512GB-256TB)——所有核共享同一批pdpt页, 任何
	//高地址MMIO(GPU ReBAR等)直接翻译, 彻底消除exit上下文的池分配死锁
	//(高地址MMIO走exit上下文建表=整机冻结根因, 见文件头注释)
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
	//==== hooked视图EPT(每核一份深拷贝)——hook的世界 ====
	//**必须深拷贝**: 浅memcpy会把clean表里的自指物理地址一起抄过来
	//(pml4[0]→clean pdpte / pdpte[i]→clean pde[i])=pml4以下两套EPT
	//共享同一批物理页表→任何一侧重拆2M页另一侧同步被改, 双视图名存实亡。
	//深拷贝三步:
	//  ①整块memcpy: 262144个2M恒等叶+高区pml4[1..511]共享链(值正确)
	//  ②重指自指链: hooked pml4[0]→hooked pdpte, hooked pdpte[i]→hooked pde[i]
	//  ③EptpHooked=clean EPTP全位复制后仅换PML4物理地址——内存类型/
	//    walkLen/A/D位天然一致=SDM §28.5.7.3 EPTP-list项有效性判据自动满足
	//分配失败不致命: bVmfuncOn核的hook自动走violation方案(fallback)
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
		//标记remap(hooked EPT独有; clean视图恒等, 两视图从此真正不同)
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

//EPT页表页专用分配: 保证4KB对齐且exit上下文安全(<=DISPATCH的NonPaged分配)
//根因: ExAllocatePoolWithTag只保证16字节对齐(pool header 0x10偏移),
//而写入页表项时 MmGetPhysicalAddress(p)/PAGE_SIZE 会截断物理地址低12位
//-> EPT硬件从截断后的(错误)物理地址读页表, 软件写的条目硬件永远看不见
//-> 该gpa永远violation/misconfig -> exit无限循环 -> 持锁线程拖死全系统(整机冻结)
//方案: 分配2页, 内部向上对齐到4KB边界(零出的4KB恰好完整落在自己的raw块内,
//不会越界清零相邻pool块)
//raw指针必须由调用方保存, 卸载时用它ExFreePool(对齐指针不能用于释放)
static PVOID EptAllocAlignedPage(PVOID* rawOut)
{
	PUCHAR raw = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * 2, 'tpeP');
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

//预建全部高区pdpt页(PASSIVE级, 首个EptInitEptData时执行一次, 幂等)
//511页×512个1GB UC恒等大页 = 512GB-256TB全覆盖。8核EPT共享同一批页。
static BOOLEAN EptPrebuildHighMappings(VOID)
{
	if (g_eptHighReady)
	{
		return TRUE;
	}
	if (!g_bEpt1GbPage)
	{
		//无1GB大页支持(现代Intel均有, 罕见): 保持惰性路径并留痕
		FlLog("EPT: 本机无1GB大页支持, 高区保持惰性建表(罕见, 接管有冻结风险!)");
		return FALSE;
	}
	for (ULONG i = 1; i < 512; i++)
	{
		PVOID raw = NULL;
		PEPT_PDPTE_1G pdpt = (PEPT_PDPTE_1G)EptAllocAlignedPage(&raw);
		if (pdpt == NULL || raw == NULL)
		{
			FlLog("EPT: 高区预建失败(pml4[%u]分配失败), 已建%u/511——放弃", i, i - 1);
			EptShutdownHighMappings();
			return FALSE;
		}
		for (ULONG j = 0; j < 512; j++)
		{
			pdpt[j].ALL = 0;
			pdpt[j].fileds.present = 1;
			pdpt[j].fileds.write = 1;
			pdpt[j].fileds.execute = 1;
			pdpt[j].fileds.memoryType = 0;    //UC: 高区只有MMIO(本机8GB RAM全在512GB内)
			pdpt[j].fileds.largePage = 1;
			pdpt[j].fileds.physicalAddr = (ULONG64)i * 512 + j;   //1GB帧号(bits 47:30)
		}
		g_eptHighPdptVa[i] = pdpt;
		g_eptHighPdptRaw[i] = raw;
	}
	g_eptHighReady = TRUE;
	FlLog("EPT: 高区预建完成: 511个pdpt×512×1GB UC恒等(512GB-256TB全覆盖), 8核共享");
	return TRUE;
}

//释放共享高区页表(DriverUload/DriverEntry回滚调用, 幂等)
//(兼释放双EPT标记页一对——此时已vmx_off/未launch, 无翻译引用)
VOID EptShutdownHighMappings(VOID)
{
	for (ULONG i = 1; i < 512; i++)
	{
		if (g_eptHighPdptRaw[i] != NULL)
		{
			ExFreePool(g_eptHighPdptRaw[i]);
			g_eptHighPdptRaw[i] = NULL;
			g_eptHighPdptVa[i] = NULL;
		}
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
		PVOID raw = NULL;
		pdpt = (PEPT_PDPTE)EptAllocAlignedPage(&raw);
		if (pdpt == NULL || raw == NULL)
		{
			//不DbgPrint(exit上下文重入风险), 失败由调用方'A'自毁留痕
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
		//同一pdpt页同时链进hooked EPT(共享, 与高区预建同语义)——
		//否则hooked视图下同一MMIO gpa的violation永远修不好(改的是clean表)
		//→'X'风暴。本机1GB大页+预建全覆盖, 此路径为dormant防御代码
		if (g_vcpu[cpuNumber].PeptDataHooked != NULL)
		{
			g_vcpu[cpuNumber].PeptDataHooked->pml4[pml4Idx].ALL = 0;
			g_vcpu[cpuNumber].PeptDataHooked->pml4[pml4Idx].fileds.present = 1;
			g_vcpu[cpuNumber].PeptDataHooked->pml4[pml4Idx].fileds.write = 1;
			g_vcpu[cpuNumber].PeptDataHooked->pml4[pml4Idx].fileds.execute = 1;
			g_vcpu[cpuNumber].PeptDataHooked->pml4[pml4Idx].fileds.physicalAddr =
				MmGetPhysicalAddress(pdpt).QuadPart / PAGE_SIZE;
		}
		//信息不DbgPrint(exit上下文重入风险), 函数尾部FlRingPush('H')已记录
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
		//(pdt的raw指针未跟踪不释放: 仅无1GB支持的旧CPU走此路径, 泄漏量极小)
		PEPT_PDE_2M pdt = (PEPT_PDE_2M)EptAllocAlignedPage(NULL);
		if (pdt == NULL)
		{
			//不DbgPrint(exit上下文重入风险), 失败由调用方'A'自毁留痕
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
	//文件日志: 动态建表事件入环(高地址MMIO首次访问), 心跳线程落盘
	FlRingPush('H', KeGetCurrentProcessorNumber(), 0, gpa, pml4Idx, pdpteIdx);
	return TRUE;
}

//本核**当前视图**的EPT。SDM §28.5.7.3裁决: VMFUNC切换会把
//新EPTP写回EPT_POINTER字段(切换跨exit/entry持久)——vmread该字段即真相。
//仅VMX root+VMCS已加载上下文可调(exit handler/EptSetHook); vmread失败或
//无hooked EPT=返回clean(兜底语义, fallback核恒返回clean=violation方案行为)
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
	//文件日志: violation完整四元组(gpa/rip/qual)入环形缓冲, 心跳线程落盘
	FlRingPush('V', KeGetCurrentProcessorNumber(), 48, gpa, guestRip, eptExit.ALL);
	//双EPT——violation发生在**当前视图**的表上。VMFUNC核hooked视图
	//(hook页W=0的写兜底/写后X=0的执行回切)与fallback核clean视图的violation
	//互切由同一逻辑处理, 区别只是act指向哪套表(vmread EPT_POINTER裁决)
	PEPT_DATA act = EptGetActiveData();
	//判断这个地址所在页是否被我们hook过
	ULONG64 pfn = gpa / PAGE_SIZE;
	PPAGE_HOOK_ENTRY pageEntry = PHGetHookEntryPageBy(pfn);
	if (pageEntry == NULL)
	{
		//未被hook的页发生EPT违规(典型原因: 物理地址超出512GB恒等映射范围, 如PCIe高地址MMIO)
		//直接return会令同一指令无限重试 -> 整机卡死
		//恢复路径同样作用于ACTIVE视图的表(改clean修不了hooked视图的violation)
		PEPT_PDE_2M pde2M = EptGetPde2B(act, gpa);
		if (pde2M != NULL)
		{
			//512GB内但2M页尚未拆分等情形: 恢复该PTE全部权限让指令继续执行
			PEPT_PTE ppte = EptGetPte(act, gpa);
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
			//统一入口(能力探测+VMfail留痕, 见EptInveptCurrent注释)
			EptInveptCurrent();
			//'P'环路检测: 无hook时该分支恢复的是本就全权限的PDE/PTE——若同一
			//gpa反复走到这里(>100), 说明violation根源不在权限(结构性bug:
			//如pdpte与pde数组不一致/硬件走的页表与软件写的不是同一份),
			//修复是无效no-op → 自毁留'P'死因, 不再拖全系统
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
				//映射已建立, 刷新EPT缓存后重执行同一指令(此次能通过)
				//统一入口(能力探测+VMfail留痕)
				EptInveptCurrent();
				//风暴检测: 同一gpa建好映射后仍反复violation=页表结构性bug
				//(如对齐错误/硬件读到错位页表)。正常流程建好一次后不再violation;
				//阈值1000次(~毫秒级)后停本核自毁, 避免持锁线程在exit循环里
				//拖死全系统(锁级联=整机冻结零日志)
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
				//分配失败(极小概率): 同样会无限重试, 逃生路径留痕
				VmxExitStormEscape('A', 48, gpa, guestRip, GuestRegs);    //noreturn
			}
		}
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
	//刷新页表缓存TLB
	//统一入口(能力探测+VMfail留痕)——视图切换后若invept无效,
	//vmresume重取指仍命中旧TLB条目=同一条指令再violation=本核活锁
	EptInveptCurrent();

	__vmx_vmwrite(GUEST_RIP, guestRip);
	__vmx_vmwrite(GUEST_RSP, guestRsp);
}


void EptSetHook(ULONG64 orginalPagePFN, ULONG64 codePagePFN)
{
	ULONG cpuHook = KeGetCurrentProcessorNumber();
	//==== VMFUNC主路径(零VM-Exit hook) ====
	//与violation方案的本质区别: 不在clean EPT清execute(=不再依赖violation触发)
	//而是hooked EPT里hook页PTE→CodePage(X=1,R=1,W=0)+本核整体切入hooked
	//视图——hook触发=纯翻译切换,**零VM-Exit**; clean视图下原页字节完好
	//(读/CRC校验看到的是原始字节, 隐蔽性根基)。
	//vmwrite(EPT_POINTER)切视图的合法性=SDM §28.5.7.3(VMFUNC切换的本质
	//就是写该字段)。
	//写hook页(W=0)→violation→EptUpdatePageAcess在hooked表上按violation方案语义
	//互切(切原页W=1/X=0→写落原页→下次执行violation→切回CodePage)——
	//读写兜底与fallback共用同一套骨架, 只是act=hooked表
	if (g_vcpu[cpuHook].bVmfuncOn && g_vcpu[cpuHook].PeptDataHooked != NULL)
	{
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
		//hook页PTE→CodePage: X=1(执行零VM-Exit) R=1(执行中读同页数据的
		//指令不violation, 活锁教训) W=0(写→violation兜底)
		pte->fileds.physicalAddr = codePagePFN;
		pte->fileds.present = 1;
		pte->fileds.execute = 1;
		pte->fileds.write = 0;
		//本核切入hooked视图(先vmwrite再invept: single-context型CPU上
		//EptInveptCurrent按当前EPT_POINTER填充desc, 切换后读到hooked)
		__vmx_vmwrite(EPT_POINTER, g_vcpu[cpuHook].EptpHooked.ALL);
		//刷新页表缓存TLB(all-context覆盖两套EPT的全部EP4TA缓存;
		//VMFUNC切换自带的VPID0组合映射失效不覆盖root侧vmwrite路径)
		EptInveptCurrent();
		//布防标记: rsn=24=VMFUNC路径专属(区别于violation方案的23)
		FlRingPush('S', cpuHook, 24, orginalPagePFN, codePagePFN,
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
		//三步'S'之一(拆原页完成)——b=新pte表物理帧号。
		//DMP环判读: 死在本步与'S'rsn=23之间=拆分/分配/取pte路径
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
		//三步'S'之二(拆CodePage的2M完成)——b=新pte表物理帧号
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
	//刷新页表缓存TLB
	//统一入口(能力探测+VMfail留痕)——布防后若invept无效, 热函数
	//的旧exec TLB条目继续存活=hook对TLB常驻函数(NtClose)数小时不触发
	//(曾经的蓝屏延迟根源); 留痕'e'事件可判读
	EptInveptCurrent();
	//**布防完成标记**(每核一条, DMP解析判别: 8×S rsn=23=全核armed,
	//<8=有核死在EptSetHook路径=拆页/分配问题; 与'n'互斥)
	//rsn从2改为23(21/22/23=拆原页/拆Code页/清execute三步)
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

BOOLEAN EptPdeToPte(PEPT_PDE_2M pde2M)
{
	BOOLEAN status = TRUE;
	//必须4KB对齐(ExAllocatePool只16字节对齐, physicalAddr截断低12位
	//=EPT硬件读错位页表)。raw指针未跟踪不释放(每次泄漏2页, 仅hook安装时发生)
	PEPT_PTE ppte = (PEPT_PTE)EptAllocAlignedPage(NULL);
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
		//必须继承源2M页的内存类型! 漏设=0(UC不可缓存),
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

//统一invept入口(替代裸VmxInvept(2,&ctx))——能力探测+正确EPTP
//+VMfail留痕。曾经的蓝屏**延迟根源**: 旧代码invept type2(all-context)
//不检查VMfail——CPU若不支持all-context(EPT_VPID_CAP bit26=0, 仅支持
//single-context bit25=1), invept静默VMfail=什么都没失效: 已布防hook
//对热函数(NtClose等TLB常驻函数)数小时不触发(旧exec条目存活), 直到
//TLB自然逐出才第一次走进跳板。冷函数(首次调用, 无TLB条目, 靠walk
//触发violation)从不暴露此问题。
//invept类型(SDM): 1=single-context(desc的EPTP字段匹配失效),
//2=all-context(全失效, desc忽略)
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
		//single-context: 必须填当前VMCS的EPTP(desc.EPTP匹配失效,
		//ctx全零=EPTP 0匹配不到任何缓存=静默no-op, 曾实测的同款陷阱)
		__vmx_vmread(EPT_POINTER, &ctx.PEPT);
		if (!VmxInvept(1, &ctx))
		{
			return;
		}
	}
	//两种类型都VMfail/都不支持(理论不可能: 支持INVEPT则至少其一)——
	//'e'环事件留痕(a=EPT_VPID_CAP): 此时EPT TLB无法软件失效, hook
	//生效时点退化为"TLB自然逐出后"(延迟形态), DMP可判读
	FlRingPush('e', KeGetCurrentProcessorNumber(), 0, cap, 0, 0);
}

//vmx_off前的双视图invept(rcx==1卸载/逃生/probe-exit路径)——
//vmx_off前invept防"EPT派生TLB残留→下轮sc start重用物理页静默
//错译"。双EPT下all-context型CPU一次覆盖两套(bit26, 本机形态, 短路);
//single-context-only型CPU的invept只失效desc.PEPT匹配的视图→必须逐
//视图失效(INVEPT single-context接受任意EPTP, 不要求=当前, SDM INVEPT)
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

//显式EPT_DATA(双EPT)——互切发生在violation所在的ACTIVE视图表上:
//  VMFUNC核hooked视图: 写hook页(W=0)→切原页(R/W/X=0)→写落原页→下次执行
//    violation(X=0)→切回CodePage(X=1,R=1,W=0)——hook页读永远直通,
//    只有写会短暂走原页(CodePage副本stale=已知限制, 同violation方案语义)
//  fallback核clean视图: violation方案原语义(执行<->读写互切)
void EptUpdatePageAcess(PEPT_DATA ept, ULONG64 gpa, UCHAR acess, PPAGE_HOOK_ENTRY pageEntry)
{
	//获取pte
	PEPT_PTE ppte = EptGetPte(ept, gpa);
	if (ppte == NULL)
	{
		return;
	}
	//视图切换留痕('x')——a=1读/2写/3执行, b=gpa, c=Code页PFN。
	//DMP环判读: hook触发后无'x'=violation根本没走到切视图(死在
	//EptExitHandler查表前); 有'x'3后死=死在vmresume后的guest执行
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
		//保持可读(勿设为仅执行): "执行中读同页数据"的指令(如mov rax,[rip+X])
		//会在读视图/执行视图间无限互切, RIP永不前进=活锁卡死
		//代价: 读内存会看到跳板字节(对调试无影响, 隐蔽性以后用VMFUNC双EPT解决)
		ppte->fileds.present = 1;
		ppte->fileds.execute = 1;
		ppte->fileds.write = 0;
	}
}






