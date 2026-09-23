#include"Cr3.h"
#include"common.h"
#include"VMX.h"
#include"ept.h"
#include<intrin.h>

//==================== v1.12: 私有Host CR3(链D封堵) ====================
//root VA空间二分(NOTES v1.12设计):
//  VMM自身页(映像/VMX资源/EPT表/池...)  → 深拷贝页表路径=隔离
//  guest世界页(代执行取指/访存)         → 浅拷贝共享=裸机等价
//三条不变式: 拥有页PTE稳定(快照永不过期)/邻居陈旧不可达(root只碰
//两类VA)/鸡生蛋消除(池boot预分配, protect只消费)。
//
//exit每次重载HOST_CR3(bit63被硬件忽略=PCID0全刷, SDM 30.5.1)——树
//结构变更后其余核下次exit自愈, 无跨核TLB同步需求。

//池规格: 页0=PML4, 页1-3=窗口(PDPT/PD/PT), 其余=私有表页。
//耗尽→该区域fallback共享(不保护但可用)+'K'环留痕(设计裁决)
#define CR3_POOL_PAGES  384                 //1.5MB连续(≈192PT预算+余量)
#define CR3_SELFMAP_IDX 1                   //PML4[1]=自引用(VA基=1<<39
											//用户半区, root代码永不触及)
#define CR3_WINDOW_IDX  2                   //PML4[2]=物理窗口(VA基=2<<39)
#define CR3_WINDOW_VA   ((ULONG64)CR3_WINDOW_IDX << 39)
#define CR3_WINDOW_SLOTS 64                 //PT[N]=cpu N专用槽(无竞争)
//节点kind(池页用途)
#define CR3_KIND_PML4  0
#define CR3_KIND_PDPT  1                    //私有PDPT(pml4i定位)
#define CR3_KIND_PD    2                    //私有PD(pml4i+pdpti定位)
#define CR3_KIND_PT    3                    //私有PT=深拷贝(+pdi定位)
#define CR3_KIND_WPDPT 4                    //窗口PDPT
#define CR3_KIND_WPD   5                    //窗口PD
#define CR3_KIND_WPT   6                    //窗口PT
//大页区登记键上限(纯判据统计, 溢出停计)
#define CR3_LARGE_KEYS_MAX 128

typedef struct _CR3_NODE
{
	ULONG64* va;        //池页VA(512项)
	UCHAR   kind;
	USHORT  pml4i;      //位置三元组(PDPT只用pml4i, PD用前二, PT全用)
	USHORT  pdpti;
	USHORT  pdi;
} CR3_NODE;

static PVOID g_cr3PoolVa = NULL;            //池(MmAllocateContiguousMemory)
static ULONG64 g_cr3PoolPa = 0;
static CR3_NODE g_cr3Nodes[CR3_POOL_PAGES];
static ULONG g_cr3PoolUsed = 0;             //已切出页数(含PML4/窗口)
static ULONG64* g_cr3Pml4 = NULL;           //池页0=私有PML4
static volatile ULONG64* g_cr3WindowPt = NULL;  //窗口PT(池页3)
static ULONG64 g_cr3OsPml4Pa = 0;           //boot快照用OS PML4(内核态CR3,
//KPTI下=完整内核半区)
static volatile LONG g_cr3Ready = 0;
static volatile LONG g_cr3PtMutex = 0;      //root自旋互斥(IF=0无抢占,
//持有者必完成=有界自旋)
static ULONG g_cr3DeepPt = 0;               //深拷贝PT页数(判据行)
static ULONG g_cr3LargePd = 0;              //大页区登记数(判据行)
static ULONG g_cr3SharedFallback = 0;       //fallback共享区计数(boot日志)
static struct { USHORT pml4i, pdpti, pdi; } g_cr3LargeKeys[CR3_LARGE_KEYS_MAX];

//页表项位域(PML4/PDPT/PD/PT通用读写, 不依赖WDK结构)
#define CR3_PFN_MASK 0x000FFFFFFFFFF000ULL
#define CR3_LEAF_PS  0x80                   //PS位(PDE=2M/PDPTE=1G大页)
static ULONG64 Cr3EntryPa(ULONG64 e)
{
	return e & CR3_PFN_MASK;
}

//==================== 池管理 ====================

//切一池页(任意IRQL安全: 纯数组操作; 调用方持有互斥或boot单线程)
static CR3_NODE* Cr3PoolTake(UCHAR kind, USHORT pml4i, USHORT pdpti, USHORT pdi)
{
	if (g_cr3PoolUsed >= CR3_POOL_PAGES)
	{
		return NULL;
	}
	ULONG64* page = (ULONG64*)((PUCHAR)g_cr3PoolVa
		+ (ULONG64)g_cr3PoolUsed * PAGE_SIZE);
	ULONG idx = g_cr3PoolUsed++;
	RtlZeroMemory(page, PAGE_SIZE);
	g_cr3Nodes[idx].va = page;
	g_cr3Nodes[idx].kind = kind;
	g_cr3Nodes[idx].pml4i = pml4i;
	g_cr3Nodes[idx].pdpti = pdpti;
	g_cr3Nodes[idx].pdi = pdi;
	return &g_cr3Nodes[idx];
}

//池页物理地址(连续块内偏移)
static ULONG64 Cr3NodePa(CR3_NODE* n)
{
	return g_cr3PoolPa
		+ (ULONG64)((PUCHAR)n->va - (PUCHAR)g_cr3PoolVa);
}

//节点查找(线性扫描, ≤384; protect是冷路径)
static CR3_NODE* Cr3FindNode(UCHAR kind, USHORT pml4i, USHORT pdpti, USHORT pdi)
{
	for (ULONG i = 0; i < g_cr3PoolUsed; i++)
	{
		CR3_NODE* n = &g_cr3Nodes[i];
		if (n->kind == kind && n->pml4i == pml4i && n->pdpti == pdpti
			&& n->pdi == pdi)
		{
			return n;
		}
	}
	return NULL;
}

//大页区登记(去重计数; 1G区用pdi=0xFFFF哨兵)
static VOID Cr3LargeKey(USHORT pml4i, USHORT pdpti, USHORT pdi)
{
	for (ULONG i = 0; i < g_cr3LargePd && i < CR3_LARGE_KEYS_MAX; i++)
	{
		if (g_cr3LargeKeys[i].pml4i == pml4i && g_cr3LargeKeys[i].pdpti == pdpti
			&& g_cr3LargeKeys[i].pdi == pdi)
		{
			return;
		}
	}
	if (g_cr3LargePd < CR3_LARGE_KEYS_MAX)
	{
		g_cr3LargeKeys[g_cr3LargePd].pml4i = pml4i;
		g_cr3LargeKeys[g_cr3LargePd].pdpti = pdpti;
		g_cr3LargeKeys[g_cr3LargePd].pdi = pdi;
	}
	g_cr3LargePd++;
}

//==================== 物理页访问(两种模式) ====================

//boot物理读通道: x64全RAM在系统物理映射区有KVA别名(v1.12判例修正:
//原用MmMapIoSpace——本机Win10+对普通RAM页返回NULL拒绝映射, 仅
//固件/ACPI/MMIO页可映, Clock.c既有用法恰好全是后者故未触发;
//MmGetVirtualForPhysical才是RAM物理→KVA的标准API, 页表页=active
//PFN恒有别名, 零分配零映射开销)
static ULONG64* Cr3BootMap(ULONG64 pa)
{
	PHYSICAL_ADDRESS p = { 0 };
	p.QuadPart = (LONGLONG)(pa & ~0xFFFULL);
	return (ULONG64*)MmGetVirtualForPhysical(p);
}

//读OS页表项: pa=表页物理地址(4K对齐), idx=项号。boot=PASSIVE
//(物理映射区别名); root=本核窗口槽(IF=0无竞争)
static ULONG64 Cr3ReadEntry(ULONG64 pa, ULONG idx, BOOLEAN inRoot)
{
	ULONG64 v = 0;
	pa &= ~0xFFFULL;
	if (!inRoot)
	{
		ULONG64* map = Cr3BootMap(pa);
		if (map == NULL)
		{
			return 0;    //理论不可达(RAM恒有别名), 防御=按不present
		}
		v = map[idx];
	}
	else
	{
		ULONG cpu = KeGetCurrentProcessorNumber() & (CR3_WINDOW_SLOTS - 1);
		g_cr3WindowPt[cpu] = pa | 0x03;    //P|RW
		__invlpg((VOID*)(CR3_WINDOW_VA + (ULONG64)cpu * PAGE_SIZE));
		v = *(volatile ULONG64*)(CR3_WINDOW_VA
			+ (ULONG64)cpu * PAGE_SIZE + (ULONG64)idx * sizeof(ULONG64));
		g_cr3WindowPt[cpu] = 0;            //解除(卫生)
		__invlpg((VOID*)(CR3_WINDOW_VA + (ULONG64)cpu * PAGE_SIZE));
	}
	return v;
}

//整页深拷贝: srcPa(4K对齐)→dst池页。返回FALSE=读失败(调用方放弃
//该区私有化=fallback共享, 绝不装半空PT——空PT=root访问该2M必'I')
static BOOLEAN Cr3CopyTable(ULONG64 srcPa, ULONG64* dst, BOOLEAN inRoot)
{
	srcPa &= ~0xFFFULL;
	if (!inRoot)
	{
		ULONG64* map = Cr3BootMap(srcPa);
		if (map == NULL)
		{
			return FALSE;
		}
		RtlCopyMemory(dst, map, PAGE_SIZE);
		return TRUE;
	}
	ULONG cpu = KeGetCurrentProcessorNumber() & (CR3_WINDOW_SLOTS - 1);
	g_cr3WindowPt[cpu] = srcPa | 0x03;
	__invlpg((VOID*)(CR3_WINDOW_VA + (ULONG64)cpu * PAGE_SIZE));
	RtlCopyMemory(dst, (VOID*)(CR3_WINDOW_VA
		+ (ULONG64)cpu * PAGE_SIZE), PAGE_SIZE);
	g_cr3WindowPt[cpu] = 0;
	__invlpg((VOID*)(CR3_WINDOW_VA + (ULONG64)cpu * PAGE_SIZE));
	return TRUE;
}

//==================== 核心私有化 ====================

//私有化一个2MB区(pml4i,pdpti,pdi): 沿路确保私有PDPT→私有PD→
//(OS侧PDE为2M大页→整项已在拷贝内=登记/否则深拷贝整个OS PT页)。
//幂等。FALSE=池耗尽/OS侧不present/读失败(该区fallback共享)
static BOOLEAN Cr3Privatize2M(USHORT pml4i, USHORT pdpti, USHORT pdi,
	BOOLEAN inRoot)
{
	//① OS PML4项(present校验+OS PDPT物理地址)
	ULONG64 osPml4e = Cr3ReadEntry(g_cr3OsPml4Pa, pml4i, inRoot);
	if (!(osPml4e & 1))
	{
		return FALSE;
	}
	//② 私有PDPT(不存在→拷OS整页成功后才原子换PML4项)
	CR3_NODE* nPdpt = Cr3FindNode(CR3_KIND_PDPT, pml4i, 0, 0);
	if (nPdpt == NULL)
	{
		CR3_NODE* n = Cr3PoolTake(CR3_KIND_PDPT, pml4i, 0, 0);
		if (n == NULL)
		{
			return FALSE;
		}
		if (!Cr3CopyTable(Cr3EntryPa(osPml4e), n->va, inRoot))
		{
			return FALSE;    //页已切出(浪费1页, 无害), 该区保持共享
		}
		//换项: flags照抄OS(PML4无PS位), 只换PFN; 8字节对齐原子写
		g_cr3Pml4[pml4i] = (osPml4e & ~CR3_PFN_MASK) | Cr3NodePa(n);
		nPdpt = n;
	}
	//③ OS PDPT项(1G大页→该项已在PDPT拷贝内=登记即完成)
	ULONG64 osPdpte = Cr3ReadEntry(Cr3EntryPa(osPml4e), pdpti, inRoot);
	if (!(osPdpte & 1))
	{
		return FALSE;
	}
	if (osPdpte & CR3_LEAF_PS)
	{
		//1G大页: 私有PDPT拷贝已含OS项原样(整1G共享, 不可单独保护
		//——文档化接受, 同NOTES大页裁决)
		Cr3LargeKey(pml4i, pdpti, 0xFFFF);
		return TRUE;
	}
	//④ 私有PD(不存在→拷OS整页成功后才原子换私有PDPT项)
	CR3_NODE* nPd = Cr3FindNode(CR3_KIND_PD, pml4i, pdpti, 0);
	if (nPd == NULL)
	{
		CR3_NODE* n = Cr3PoolTake(CR3_KIND_PD, pml4i, pdpti, 0);
		if (n == NULL)
		{
			return FALSE;
		}
		if (!Cr3CopyTable(Cr3EntryPa(osPdpte), n->va, inRoot))
		{
			return FALSE;
		}
		nPdpt->va[pdpti] = (osPdpte & ~CR3_PFN_MASK) | Cr3NodePa(n);
		nPd = n;
	}
	//⑤ OS PDE: 2M大页→该项已在PD拷贝内=登记; 否则深拷贝整个PT
	ULONG64 osPde = Cr3ReadEntry(Cr3EntryPa(osPdpte), pdi, inRoot);
	if (!(osPde & 1))
	{
		return FALSE;
	}
	if (osPde & CR3_LEAF_PS)
	{
		Cr3LargeKey(pml4i, pdpti, pdi);
		return TRUE;
	}
	if (Cr3FindNode(CR3_KIND_PT, pml4i, pdpti, pdi) == NULL)
	{
		CR3_NODE* n = Cr3PoolTake(CR3_KIND_PT, pml4i, pdpti, pdi);
		if (n == NULL)
		{
			return FALSE;
		}
		if (!Cr3CopyTable(Cr3EntryPa(osPde), n->va, inRoot))
		{
			return FALSE;
		}
		nPd->va[pdi] = (osPde & ~CR3_PFN_MASK) | Cr3NodePa(n);
		g_cr3DeepPt++;
	}
	return TRUE;
}

//sync-on-alloc: 该2M区已私有→从共享OS PT同步单个PTE(否则新分配在
//私有区不可见!)。大页区无PTE可同步(整2M共享直接可见)
static VOID Cr3SyncPte(USHORT pml4i, USHORT pdpti, USHORT pdi, USHORT pti,
	BOOLEAN inRoot)
{
	CR3_NODE* nPt = Cr3FindNode(CR3_KIND_PT, pml4i, pdpti, pdi);
	if (nPt == NULL)
	{
		return;    //大页区/fallback共享
	}
	ULONG64 osPml4e = Cr3ReadEntry(g_cr3OsPml4Pa, pml4i, inRoot);
	ULONG64 osPdpte = Cr3ReadEntry(Cr3EntryPa(osPml4e), pdpti, inRoot);
	ULONG64 osPde = Cr3ReadEntry(Cr3EntryPa(osPdpte), pdi, inRoot);
	if (!(osPde & 1) || (osPde & CR3_LEAF_PS))
	{
		return;
	}
	nPt->va[pti] = Cr3ReadEntry(Cr3EntryPa(osPde), pti, inRoot);
}

//保护[va,va+len): 逐4K页迭代, 2M区去重(深拷贝一次)+逐页sync。
//inRoot=FALSE仅boot(PASSIVE); TRUE=vmcall处理器内(IF=0)
static BOOLEAN Cr3ProtectRange(ULONG64 va, ULONG64 len, BOOLEAN inRoot)
{
	if (len == 0)
	{
		return TRUE;
	}
	//用户半区拒绝(私有树用户半区恒零——root永不触及, 保护无意义)
	if (!(va & 0xFFFF800000000000ULL))
	{
		return FALSE;
	}
	ULONG64 end = (va + len + 0xFFF) & ~0xFFFULL;
	va &= ~0xFFFULL;
	BOOLEAN allOk = TRUE;
	ULONG64 lastKey = 0xFFFFFFFFFFFFFFFFULL;
	while (va < end)
	{
		USHORT pml4i = (USHORT)((va >> 39) & 0x1FF);
		USHORT pdpti = (USHORT)((va >> 30) & 0x1FF);
		USHORT pdi = (USHORT)((va >> 21) & 0x1FF);
		USHORT pti = (USHORT)((va >> 12) & 0x1FF);
		ULONG64 key = ((ULONG64)pml4i << 42) | ((ULONG64)pdpti << 33) | pdi;
		if (key != lastKey)
		{
			if (!Cr3Privatize2M(pml4i, pdpti, pdi, inRoot))
			{
				allOk = FALSE;
			}
			lastKey = key;
		}
		Cr3SyncPte(pml4i, pdpti, pdi, pti, inRoot);
		va += PAGE_SIZE;
	}
	return allOk;
}

//==================== 对外接口 ====================

//boot保护(PASSIVE, Cr3Init内部): 失败计数留痕不中断(逐区降级)
static VOID Cr3ProtectBoot(PVOID va, ULONG64 len, const char* what)
{
	if (va == NULL)
	{
		return;
	}
	if (!Cr3ProtectRange((ULONG64)va, len, FALSE))
	{
		g_cr3SharedFallback++;
		FlLog("CR3: %s区fallback共享(池耗尽/OS侧异常, VA=%p)——链D该区未封",
			what, va);
	}
}

//root侧入口(vmcall处理器, IF=0): 互斥+完成后CR3重载(bit63=0全刷)
//丢弃本核stale翻译(其余核下次exit的PCID0全刷自愈)
BOOLEAN Cr3ProtectRoot(ULONG64 va, ULONG64 len)
{
	if (g_cr3Ready == 0)
	{
		return FALSE;
	}
	while (InterlockedCompareExchange(&g_cr3PtMutex, 1, 0) != 0)
	{
		YieldProcessor();    //持有者IF=0必完成=有界
	}
	BOOLEAN ok = Cr3ProtectRange(va, len, TRUE);
	__writecr3(g_cr3PoolPa);
	g_cr3PtMutex = 0;
	return ok;
}

//统一入口: root(当前CR3=私有PML4)直接执行; guest经vmcall(13)提权
VOID Cr3ProtectAuto(PVOID va, ULONG64 len)
{
	if (g_cr3Ready == 0 || va == NULL)
	{
		return;
	}
	if ((__readcr3() & ~0xFFFULL) == g_cr3PoolPa)
	{
		Cr3ProtectRoot((ULONG64)va, len);
		return;
	}
	//guest: 亲和性钉住当前核再做in-guest判定+vmcall——防两步之间
	//线程迁移到非in-guest核(真机vmcall=#UD蓝屏; 部分接管是支持
	//形态, ClkInitAll同款模式)。非in-guest→跳过(fallback共享)
	KAFFINITY allCpus = KeQueryActiveProcessors();
	ULONG cpu = KeGetCurrentProcessorNumber();
	KeSetSystemAffinityThread((KAFFINITY)1UL << (cpu & 63));
	if (g_vcpu[cpu].bInGuest)
	{
		CmVmCall(GEPT_VMCALL_PTPROT, (ULONG64)va, len, 0);
	}
	KeSetSystemAffinityThread(allCpus);
}

ULONG64 Cr3PrivatePa(VOID)
{
	return g_cr3Ready ? g_cr3PoolPa : 0;
}
PVOID Cr3PoolVa(VOID)
{
	return g_cr3PoolVa;
}
ULONG Cr3PoolPages(VOID)
{
	return CR3_POOL_PAGES;
}
ULONG Cr3DeepPtCount(VOID)
{
	return g_cr3DeepPt;
}
ULONG Cr3LargePdCount(VOID)
{
	return g_cr3LargePd;
}

//==================== 生命周期 ====================

//PASSIVE: 池+树构建+boot快照集(全部launch前完成=Ophion约束: 先分配
//完再建树)。逐区降级而非全有全无(可用性优先)
BOOLEAN Cr3Init(PVOID drvBase, ULONG drvSize)
{
	//① 池(连续1.5MB, 512GB内=EPT恒等区WB+自检[5]兼容)
	PHYSICAL_ADDRESS max = { 0 };
	max.QuadPart = 0x7FFFFFFFFF;
	g_cr3PoolVa = MmAllocateContiguousMemory(
		(SIZE_T)CR3_POOL_PAGES * PAGE_SIZE, max);
	if (g_cr3PoolVa == NULL)
	{
		FlLog("CR3: 池分配失败(%u页)——私有Host CR3未启用(回退launch CR3)",
			(ULONG)CR3_POOL_PAGES);
		return FALSE;
	}
	RtlZeroMemory(g_cr3PoolVa, (SIZE_T)CR3_POOL_PAGES * PAGE_SIZE);
	g_cr3PoolPa = MmGetPhysicalAddress(g_cr3PoolVa).QuadPart;
	g_cr3PoolUsed = 0;
	g_cr3DeepPt = 0;
	g_cr3LargePd = 0;
	g_cr3SharedFallback = 0;
	//launch线程内核态CR3(KPTI下=完整内核半区; 内核半区跨进程共享
	//→任意进程CR3等价, 快照合法)
	g_cr3OsPml4Pa = __readcr3() & ~0xFFFULL;
	//② 私有PML4=池页0; 内核半区浅拷贝(OS运行期新增内核映射经共享
	//PDPT/PD/PT自动可见), 用户半区恒零(确定语义, 顺带修掉"launch
	//线程进程不确定"的隐含假设)
	{
		CR3_NODE* n = Cr3PoolTake(CR3_KIND_PML4, 0, 0, 0);
		g_cr3Pml4 = n->va;
		ULONG64* map = Cr3BootMap(g_cr3OsPml4Pa);
		if (map == NULL)
		{
			FlLog("CR3: OS PML4物理别名获取失败——私有Host CR3未启用");
			MmFreeContiguousMemory(g_cr3PoolVa);
			g_cr3PoolVa = NULL;
			g_cr3Pml4 = NULL;
			return FALSE;
		}
		for (ULONG i = 256; i < 512; i++)
		{
			g_cr3Pml4[i] = map[i];
		}
	}
	//③ self-map: PML4[1]→自身(root改PTE免切CR3; VA基=1<<39用户
	//半区零碰撞)。窗口: PML4[2]→WPDPT[0]→WPD[0]→WPT, WPT[N]=cpu N槽
	g_cr3Pml4[CR3_SELFMAP_IDX] = g_cr3PoolPa | 0x03;
	CR3_NODE* wpdpt = Cr3PoolTake(CR3_KIND_WPDPT, 0, 0, 0);
	CR3_NODE* wpd = Cr3PoolTake(CR3_KIND_WPD, 0, 0, 0);
	CR3_NODE* wpt = Cr3PoolTake(CR3_KIND_WPT, 0, 0, 0);
	g_cr3Pml4[CR3_WINDOW_IDX] = Cr3NodePa(wpdpt) | 0x03;
	wpdpt->va[0] = Cr3NodePa(wpd) | 0x03;
	wpd->va[0] = Cr3NodePa(wpt) | 0x03;
	g_cr3WindowPt = wpt->va;
	//④ boot快照集(共享零页改eager——快照集成员须先于树构建存在)
	EptEnsureHideZeroPage();
	FlLog("CR3: 树构建开始(PML4PA=%llX OS PML4=%llX, boot快照集)",
		(unsigned long long)g_cr3PoolPa, (unsigned long long)g_cr3OsPml4Pa);
	Cr3ProtectBoot(drvBase, drvSize, "驱动映像");
	ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
	for (ULONG i = 0; i < cpuCount; i++)
	{
		Cr3ProtectBoot(g_vcpu[i].VMXON, PAGE_SIZE, "VMXON");
		Cr3ProtectBoot(g_vcpu[i].VMCS, PAGE_SIZE, "VMCS");
		Cr3ProtectBoot(g_vcpu[i].VMMStack, PAGE_SIZE * 6, "VMM栈");
		Cr3ProtectBoot(g_vcpu[i].MsrBitMap, PAGE_SIZE, "MSR位图");
		Cr3ProtectBoot(g_vcpu[i].IoBitmaps, PAGE_SIZE * 2, "I/O位图");
		Cr3ProtectBoot(g_vcpu[i].RootIdt, PAGE_SIZE, "私有HostIDT");
		Cr3ProtectBoot(g_vcpu[i].PeptData, sizeof(EPT_DATA), "EPT_DATA");
		Cr3ProtectBoot(g_vcpu[i].PeptDataHooked, sizeof(EPT_DATA),
			"hooked EPT_DATA");
	}
	for (ULONG b = 0; b < EptArenaBlockCount(); b++)
	{
		Cr3ProtectBoot(EptArenaBlockVa(b), PAGE_SIZE * 512, "拆分arena");
	}
	Cr3ProtectBoot(EptHighPdptBlockVa(), PAGE_SIZE * 512, "高区pdpt块");
	Cr3ProtectBoot(EptMarkPageA(), PAGE_SIZE, "标记页A");
	Cr3ProtectBoot(EptMarkPageB(), PAGE_SIZE, "标记页B");
	Cr3ProtectBoot(EptHideZeroPageVa(), PAGE_SIZE, "共享零页");
	//池自身(鸡生蛋消除: 池=连续物理块整段拥有, PTE在boot期稳定)
	Cr3ProtectBoot(g_cr3PoolVa, (ULONG64)CR3_POOL_PAGES * PAGE_SIZE,
		"CR3池自身");
	//⑤ 就绪(HOST_CR3接线点读Cr3PrivatePa判此)
	g_cr3Ready = 1;
	FlLog("CR3: 私有Host CR3就绪 PML4=%llX 深拷贝PT=%u个大区 大页区=%u "
		"fallback共享=%u区(池%u/%u页)",
		(unsigned long long)g_cr3PoolPa, g_cr3DeepPt, g_cr3LargePd,
		g_cr3SharedFallback, g_cr3PoolUsed, (ULONG)CR3_POOL_PAGES);
	return TRUE;
}

//PASSIVE: 全核vmx_off后释放(root上下文已全部消亡)。清零后释放=
//取证反制; 幂等
VOID Cr3Shutdown(VOID)
{
	if (g_cr3PoolVa == NULL)
	{
		return;
	}
	ULONG deepWas = g_cr3DeepPt;
	ULONG largeWas = g_cr3LargePd;
	g_cr3Ready = 0;
	RtlZeroMemory(g_cr3PoolVa, (SIZE_T)CR3_POOL_PAGES * PAGE_SIZE);
	MmFreeContiguousMemory(g_cr3PoolVa);
	g_cr3PoolVa = NULL;
	g_cr3PoolPa = 0;
	g_cr3Pml4 = NULL;
	g_cr3WindowPt = NULL;
	g_cr3PoolUsed = 0;
	g_cr3DeepPt = 0;
	g_cr3LargePd = 0;
	g_cr3SharedFallback = 0;
	RtlZeroMemory(g_cr3Nodes, sizeof(g_cr3Nodes));
	RtlZeroMemory(g_cr3LargeKeys, sizeof(g_cr3LargeKeys));
	FlLog("CR3: 私有树已释放(%u个深拷贝PT+%u大页区)", deepWas, largeWas);
}
