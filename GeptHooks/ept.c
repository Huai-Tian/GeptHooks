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

//==================== v3.8根因修复: EPT内存类型按真实RAM布局 ====================
//v3.7实测冻结形态: 日志停在"cpu0 vmlaunch...", 之后零行零[HB]零蓝屏。
//根因: EptInitEptData把0-512GB**全部**标成memoryType=6(WB可缓存), 但物理
//空间里布满MMIO洞(LAPIC 0xFEE00000 / IOAPIC 0xFEC00000 / HPET 0xFED00000 /
//AHCI/USB/GPU低地址BAR, 全部<4GB)。被虚拟化核一旦运行设备ISR:
//  写MMIO寄存器(清中断原因) -> 写进CPU缓存行永不抵达设备 -> 中断永远pending
//  -> ISR风暴独占该核; 读MMIO寄存器 -> 拿到stale缓存值 -> I/O永不完成。
//两者都表现为整机冻结(所有核等待磁盘/中断响应), 无bugcheck。
//触发链=vmlaunch成功后T1的第一次落盘ZwWriteFile -> AHCI完成中断落在被虚拟化
//的cpu0上(设备IRQ普遍倾向cpu0) -> 秒级冻结。与"冻结点=最后日志是vmlaunch、
//成功日志永远写不出、零[HB]"完全吻合。
//修复: MmGetPhysicalMemoryRanges获取真实RAM布局, 2MB大页**完全**落在RAM内
//才WB, 否则(纯MMIO或RAM/MMIO边界页)UC。UC只损失性能, 绝不损失正确性。
//位图32KB(512GB/2MB/8), DriverEntry里建一次, 全部核共用。
#define EPT_2M_FRAME_COUNT (EPT_PREALLOC_PAGES * EPT_PREALLOC_PAGES)   //262144
#define EPT_RAM_BITMAP_BYTES (EPT_2M_FRAME_COUNT / 8)                  //32KB
static UCHAR g_eptRamBitmap[EPT_RAM_BITMAP_BYTES];    //BSS自动清零: 1=该2MB页完全在RAM内
static BOOLEAN g_eptRamBitmapReady = FALSE;

//==================== v3.18: 高区(512GB-256TB)EPT预建 ====================
//v3.17实测判读: 单核接管(cpu0)后<20ms全机冻结——L287"vmlaunch..."后连[F]
//环事件都没被T1排空(T1钉在真机核上也死了), 与v3.12/v3.13全核接管冻结
//完全同签名; 而探针自测模式(不运行OS)37次全过 => 凶手=OS在EPT下的某行为。
//头号嫌疑(证据链): GPU ReBAR高地址MMIO(>512GB, v3.5模块清单已证nvlddmkm/
//igdkmd64在跑)被cpu0上的线程/DPC/ISR触碰 → EPT violation →
//EptBuildHighMapping在**VM-exit上下文**执行ExAllocatePoolWithTag——
//若被中断者持池锁(DPC抢占线程)或处于DIRQL(ISR): 池锁自旋永不出来 →
//cpu0楔死 → 全局池锁被卡 → 所有核的池分配全部自旋 → 整机冻结(含T1的
//ZwWriteFile→IRP分配), 画面卡死。与"瞬杀全机+屏幕死+日志戛然而止"
//三特征完全吻合。
//修复: DriverEntry(PASSIVE级)一次性预建pml4[1..511]全部511个pdpt页
//(每页512个1GB UC恒等大页, 覆盖512GB-256TB全部物理地址空间), 8核EPT
//共享同一批页表 → 任何高地址MMIO访问**直接翻译成功, 零exit零分配**。
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
		//v3.14: 区间逐条落盘——v3.13实测WB=4023个2M页(约7.9GB), 但EPT_DATA
		//(物理0x277BFE000≈9.9GB)与驱动代码页(≈10.6GB)都存在且标了WB,
		//说明RAM延伸至少到10.6GB, 位图却只标了约一半——区间明细是裁决依据
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

//==================== v3.13: vmlaunch前EPT软件自检门 ====================
//v3.12实测: 控制字段修复后vmlaunch首次真正成功, 却在"cpu0 vmlaunch..."后
//250ms内整机冻结——T1(钉在未虚拟化核上, 250ms心跳)连一条[HB]都没来得及发,
//二进制环零标记(=零exit零逃逸零三重故障)。guest落地窗口的全部代码路径
//(CmGeustRip恢复栈/EPT硬件走查取指)从未被v3.11b执行过(8核全在entry检查
//阶段就fail返回), 属"黑盒死区"——EPT若把落地代码页静默错译到别的物理帧
//(权限位全对、不触发violation/misconfig), guest执行的就是"别的内存的内容",
//整机瞬间混乱冻结且零日志, 与实测形态完全吻合。
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
	//[6] v3.18: 高区链——511个pml4[1..511]全部指向共享pdpt页, 抽查
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
	//(静默数据损坏)。myVt原版同样漏了这行, 作者测试机碰巧拿到清零页才"能用"。
	//这是vmlaunch成功后仍卡死的头号根因。
	RtlZeroMemory(currentVcpu->PeptData, sizeof(EPT_DATA));

	//v3.8: 先建RAM位图(首次调用时), PDE内存类型由位图决定(见EptBuildRamBitmap)
	EptBuildRamBitmap();

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
			//v3.8: 完全RAM的2M页=WB, MMIO洞/边界页=UC(整机冻结根因修复)
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
	//v3.18: 预建+链接高区(512GB-256TB)——所有核共享同一批pdpt页, 任何
	//高地址MMIO(GPU ReBAR等)直接翻译, 彻底消除exit上下文的池分配死锁
	//(v3.17单核接管<20ms全机冻结的头号根因, 见文件头注释)
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
	return status;
}

//EPT页表页专用分配: 保证4KB对齐且exit上下文安全(<=DISPATCH的NonPaged分配)
//v3.6根因: ExAllocatePoolWithTag只保证16字节对齐(pool header 0x10偏移),
//而写入页表项时 MmGetPhysicalAddress(p)/PAGE_SIZE 会截断物理地址低12位
//-> EPT硬件从截断后的(错误)物理地址读页表, 软件写的条目硬件永远看不见
//-> 该gpa永远violation/misconfig -> exit无限循环 -> 持锁线程拖死全系统(整机冻结)
//方案: 分配2页, 内部向上对齐到4KB边界(零出的4KB恰好完整落在自己的raw块内,
//顺带修复原版RtlZeroMemory(pdpt,PAGE_SIZE)越界清零相邻pool块16字节的bug)
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

//v3.18: 预建全部高区pdpt页(PASSIVE级, 首个EptInitEptData时执行一次, 幂等)
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

//v3.18: 释放共享高区页表(DriverUload/DriverEntry回滚调用, 幂等)
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
			//v3.7: 不DbgPrint(exit上下文重入风险), 失败由调用方'A'自毁留痕
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
		//v3.7: 信息不DbgPrint(exit上下文重入风险), 函数尾部FlRingPush('H')已记录
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
		//(pdt的raw指针未跟踪: 该路径仅无1GB支持的旧CPU走, 现代Intel均有1GB;
		// 原版本就泄漏pdt不释放, 保持同粒度, 4KB对齐修复才是关键)
		PEPT_PDE_2M pdt = (PEPT_PDE_2M)EptAllocAlignedPage(NULL);
		if (pdt == NULL)
		{
			//v3.7: 不DbgPrint(exit上下文重入风险), 失败由调用方'A'自毁留痕
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
	//v3.7: 移除DbgPrint限流日志——被中断线程可能正持有DbgPrint内部锁,
	//exit上下文重入=同核死锁(整核冻结零日志的候选机理), 环形缓冲已记录全部
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
				EPT_CTX ctx = { 0 };
				VmxInvept(2, &ctx);
				//风暴检测: 同一gpa建好映射后仍反复violation=页表结构性bug
				//(如对齐错误/硬件读到错位页表)。正常流程建好一次后不再violation;
				//阈值1000次(~毫秒级)后停本核自毁, 避免持锁线程在exit循环里
				//拖死全系统(锁级联=整机冻结零日志, v3.5实测形态)
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
		//v3.42: 中止留痕(>512GB或页表越界: hook静默未建立, 原版完全无声)
		FlRingPush('n', KeGetCurrentProcessorNumber(), 2,
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
			FlRingPush('n', KeGetCurrentProcessorNumber(), 2,
				orginalPagePFN, 0, 0);
			return;
		}
		//v3.43: 三步'S'之一(拆原页完成)——b=新pte表物理帧号。
		//DMP环判读: 死在本步与'S'rsn=23之间=拆分/分配/取pte路径
		FlRingPush('S', KeGetCurrentProcessorNumber(), 21,
			orginalPagePFN, ((PEPT_PDE)oPde2M)->fileds.physicalAddr, 0);
	}

	if (cPed2M->fileds.ps)
	{
		//将当前的GPA所在的PDE 拆分成1个ptt 也就是512个pte
		BOOLEAN status = EptPdeToPte(cPed2M);
		if (!status)
		{
			FlRingPush('n', KeGetCurrentProcessorNumber(), 2,
				0, codePagePFN, 0);
			return;
		}
		//v3.43: 三步'S'之二(拆CodePage的2M完成)——b=新pte表物理帧号
		FlRingPush('S', KeGetCurrentProcessorNumber(), 22,
			codePagePFN, ((PEPT_PDE)cPed2M)->fileds.physicalAddr, 0);
	}
	//修改页属性，将执行权限去掉
	PEPT_PTE pte = EptGetPte(oPFN);//

	if (pte == NULL)
	{
		FlRingPush('n', KeGetCurrentProcessorNumber(), 2,
			orginalPagePFN, 0, 0);
		return;
	}
	pte->fileds.execute = 0;
	//刷新页表缓存TLB
	EPT_CTX ctx = { 0 };
	VmxInvept(2, &ctx);
	//v3.42: **布防完成标记**(每核一条, DMP解析判别: 8×S rsn=23=全核armed,
	//<8=有核死在EptSetHook路径=拆页/分配问题; 与'n'互斥)
	//v3.43: rsn从2改为23(21/22/23=拆原页/拆Code页/清execute三步)
	FlRingPush('S', KeGetCurrentProcessorNumber(), 23,
		orginalPagePFN, codePagePFN, 0);
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
	//v3.6: 必须4KB对齐(原版ExAllocatePool只16字节对齐, physicalAddr截断低12位
	//=EPT硬件读错位页表, Stage1拆分即触发不可解风暴)。原版本就泄漏ppte不释放,
	//raw指针不跟踪保持同粒度(每次泄漏2页, 仅调试期可接受)
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
	//v3.43: 视图切换留痕('x')——a=1读/2写/3执行, b=gpa, c=Code页PFN。
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
		//保持可读(原版为0=仅执行): "执行中读同页数据"的指令(如mov rax,[rip+X])
		//会在读视图/执行视图间无限互切, RIP永不前进=活锁卡死
		//代价: 读内存会看到跳板字节(对调试无影响, 隐蔽性以后用VMFUNC双EPT解决)
		ppte->fileds.present = 1;
		ppte->fileds.execute = 1;
		ppte->fileds.write = 0;
	}
}






