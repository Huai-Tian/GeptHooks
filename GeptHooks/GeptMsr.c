#include <ntifs.h>
#include <intrin.h>
#include "GeptMsr.h"
#include "common.h"
#include "VMX.h"

//====================================================================
// v3.52 Phase5: MSR拦截简易API实现(接口契约见GeptMsr.h头注释)
//
//条目模型(与GeptApi同款架构纪律):
//  - 静态数组(GEPT_MSR_MAX个, 零动态内存→卸载无需释放流程)
//  - Install/Remove持自旋锁(PASSIVE); 分发器**无锁**(条目字段
//    安装后不可变; Removed用Interlocked发布/撤销)
//  - 发布顺序: 填字段→置位图→InterlockedExchange(Removed,0)发布;
//    x64 TSO保证其他核看到Removed=0时字段与位图均已就绪
//  - Remove: 先标Removed(分发立即停止命中)再清位图; 在途exit
//    (已过查表)的回调安全完成(与EPT hook同款语义)
//
//位图布局(SDM Vol3 25.6.9, 4KB): [读低1024][读高1024][写低1024]
//[写高1024]; 低区=MSR 0x0-0x1FFF, 高区=0xC0000000-0xC0001FFF。
//位图改动即时生效(硬件每次RDMSR/WRMSR现查内存, 无TLB类缓存,
//KVM同款运行期改位实践)——无需invept/DPC广播
//====================================================================

#define GEPT_MSR_MAX 16

typedef struct _GEPT_MSR_ENTRY
{
	volatile LONG Removed;   //1=空闲/已移除(分发跳过); 0=live
	ULONG32 Msr;
	PVOID Context;
	GEPT_MSR_READ_CB OnRead;    //NULL=读位不置(直通)
	GEPT_MSR_WRITE_CB OnWrite;  //NULL=写位不置(直通)
} GEPT_MSR_ENTRY, * PGEPT_MSR_ENTRY;

static GEPT_MSR_ENTRY s_msr[GEPT_MSR_MAX];
static KSPIN_LOCK s_msrLock = { 0 };
static volatile LONG s_msrLockInit = 0;
static KIRQL s_msrOldIrql = 0;

static VOID GeptMsrLock(VOID)
{
	if (InterlockedCompareExchange(&s_msrLockInit, 1, 0) == 0)
	{
		KeInitializeSpinLock(&s_msrLock);
		//静态数组零初始化会使Removed=0(语义=live)+Msr=0——显式
		//标空, 消除"空槽被当成MSR 0的live条目"的意外语义(位图全零
		//时分发实际到不了MSR 0, 但语义要干净)
		for (ULONG i = 0; i < GEPT_MSR_MAX; i++)
		{
			s_msr[i].Removed = 1;
		}
	}
	KeAcquireSpinLock(&s_msrLock, &s_msrOldIrql);
}

static VOID GeptMsrUnlock(VOID)
{
	KeReleaseSpinLock(&s_msrLock, s_msrOldIrql);
}

//位图寻址: 返回目标字节地址(该核位图内), *BitOut=位号; rw: 0=读/1=写
static PUCHAR GeptMsrBitAddr(ULONG cpu, ULONG32 msr, UCHAR rw, PULONG BitOut)
{
	PUCHAR base = (PUCHAR)g_vcpu[cpu].MsrBitMap;
	if (base == NULL)
	{
		return NULL;
	}
	if (rw != 0)
	{
		base += 1024 * 2;                     //写位图区(SDM 25.6.9)
	}
	ULONG64 m = msr;
	if (m >= 0xC0000000)
	{
		base += 1024;                         //高区(0xC0000000+)
		m -= 0xC0000000;
	}
	*BitOut = (ULONG)(m % 8);
	return base + (m / 8);
}

static VOID GeptMsrBitSet(ULONG cpu, ULONG32 msr, UCHAR rw, BOOLEAN set)
{
	ULONG bit = 0;
	PUCHAR p = GeptMsrBitAddr(cpu, msr, rw, &bit);
	if (p == NULL)
	{
		return;
	}
	if (set)
	{
		*p |= (UCHAR)(1 << bit);
	}
	else
	{
		*p &= (UCHAR)~(1 << bit);
	}
}

static BOOLEAN GeptMsrBitGet(ULONG cpu, ULONG32 msr, UCHAR rw)
{
	ULONG bit = 0;
	PUCHAR p = GeptMsrBitAddr(cpu, msr, rw, &bit);
	if (p == NULL)
	{
		return FALSE;
	}
	return ((*p >> bit) & 1) ? TRUE : FALSE;
}

//回调内取真实值(保留MSR勿调——root态真读=#GP蓝屏)
ULONG64 GeptMsrReadReal(ULONG32 Msr)
{
	return __readmsr(Msr);
}

//==== 分发器(VM-exit上下文, 无锁: 条目不可变+Removed原子) ====
BOOLEAN GeptMsrDispatchRead(ULONG32 Msr, ULONG64* OutValue)
{
	for (ULONG i = 0; i < GEPT_MSR_MAX; i++)
	{
		PGEPT_MSR_ENTRY e = &s_msr[i];
		if (e->Removed != 0 || e->Msr != Msr)
		{
			continue;
		}
		if (e->OnRead == NULL)
		{
			return FALSE;    //仅写hook: 读直通
		}
		if (OutValue != NULL)
		{
			*OutValue = e->OnRead(e->Context, Msr);
		}
		return TRUE;
	}
	return FALSE;
}

BOOLEAN GeptMsrDispatchWrite(ULONG32 Msr, ULONG64 Value)
{
	for (ULONG i = 0; i < GEPT_MSR_MAX; i++)
	{
		PGEPT_MSR_ENTRY e = &s_msr[i];
		if (e->Removed != 0 || e->Msr != Msr)
		{
			continue;
		}
		if (e->OnWrite == NULL)
		{
			return TRUE;    //仅读hook: 写放行
		}
		return e->OnWrite(e->Context, Msr, Value);
	}
	return TRUE;
}

NTSTATUS GeptMsrHookInstall(const GEPT_MSR_HOOK* Hook)
{
	if (Hook == NULL || (Hook->OnRead == NULL && Hook->OnWrite == NULL))
	{
		return STATUS_INVALID_PARAMETER;
	}
	//gate: 至少一核in-guest(位图只对in-guest核生效, 全败=无处拦截)
	ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
	ULONG inGuest = 0;
	for (ULONG i = 0; i < cpuCount; i++)
	{
		if (g_vcpu[i].bInGuest)
		{
			inGuest++;
		}
	}
	if (inGuest == 0)
	{
		FlLog("[MSR] Install拒绝: 零核in-guest(VT未启动), 无处拦截");
		return STATUS_NOT_SUPPORTED;
	}
	//查重复+找空槽
	GeptMsrLock();
	LONG slot = -1;
	for (ULONG i = 0; i < GEPT_MSR_MAX; i++)
	{
		if (s_msr[i].Removed != 0)
		{
			if (slot < 0)
			{
				slot = (LONG)i;
			}
			continue;
		}
		if (s_msr[i].Msr == Hook->Msr)
		{
			GeptMsrUnlock();
			FlLog("[MSR] Install拒绝: MSR=0x%X已安装(Remove后可重装)", Hook->Msr);
			return STATUS_UNSUCCESSFUL;
		}
	}
	if (slot < 0)
	{
		GeptMsrUnlock();
		FlLog("[MSR] Install拒绝: %u槽已满", (ULONG)GEPT_MSR_MAX);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	PGEPT_MSR_ENTRY e = &s_msr[slot];
	e->Removed = 1;    //填充期间对分发器不可见
	e->Msr = Hook->Msr;
	e->Context = Hook->Context;
	e->OnRead = Hook->OnRead;
	e->OnWrite = Hook->OnWrite;
	//全核位图置位(在锁内: 与并发的Remove/Install串行; 位图写入即时生效)
	for (ULONG i = 0; i < cpuCount; i++)
	{
		if (Hook->OnRead != NULL)
		{
			GeptMsrBitSet(i, Hook->Msr, 0, TRUE);
		}
		if (Hook->OnWrite != NULL)
		{
			GeptMsrBitSet(i, Hook->Msr, 1, TRUE);
		}
	}
	InterlockedExchange(&e->Removed, 0);    //发布(字段+位图已就绪)
	GeptMsrUnlock();
	//回读自检(v3.50b铁律: 上机证据链靠它——伪造自测在guest内真执行
	//rdmsr, 位图任一核失效=未拦截=#GP蓝屏, 必须当场拦截而非上机暴露)
	for (ULONG i = 0; i < cpuCount; i++)
	{
		if (!g_vcpu[i].bInGuest)
		{
			continue;
		}
		if (Hook->OnRead != NULL && !GeptMsrBitGet(i, Hook->Msr, 0))
		{
			e->Removed = 1;
			for (ULONG k = 0; k < cpuCount; k++)
			{
				GeptMsrBitSet(k, Hook->Msr, 0, FALSE);
				GeptMsrBitSet(k, Hook->Msr, 1, FALSE);
			}
			FlLog("[MSR] Install自检FAIL: cpu%u读位图读回=0(MSR=0x%X)——撤销安装防#GP",
				i, Hook->Msr);
			return STATUS_UNSUCCESSFUL;
		}
		if (Hook->OnWrite != NULL && !GeptMsrBitGet(i, Hook->Msr, 1))
		{
			e->Removed = 1;
			for (ULONG k = 0; k < cpuCount; k++)
			{
				GeptMsrBitSet(k, Hook->Msr, 0, FALSE);
				GeptMsrBitSet(k, Hook->Msr, 1, FALSE);
			}
			FlLog("[MSR] Install自检FAIL: cpu%u写位图读回=0(MSR=0x%X)——撤销安装",
				i, Hook->Msr);
			return STATUS_UNSUCCESSFUL;
		}
	}
	FlLog("[MSR] Install OK: MSR=0x%X 读=%s 写=%s 上下文=%p(全核位图置位+回读自检过)",
		Hook->Msr, Hook->OnRead != NULL ? "拦截" : "直通",
		Hook->OnWrite != NULL ? "拦截" : "直通", Hook->Context);
	return STATUS_SUCCESS;
}

NTSTATUS GeptMsrHookRemove(ULONG32 Msr)
{
	GeptMsrLock();
	PGEPT_MSR_ENTRY found = NULL;
	for (ULONG i = 0; i < GEPT_MSR_MAX; i++)
	{
		if (s_msr[i].Removed == 0 && s_msr[i].Msr == Msr)
		{
			found = &s_msr[i];
			break;
		}
	}
	if (found == NULL)
	{
		GeptMsrUnlock();
		return STATUS_NOT_FOUND;
	}
	//先标Removed(分发立即停止命中)再清位图; 在途回调安全完成
	found->Removed = 1;
	ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
	for (ULONG i = 0; i < cpuCount; i++)
	{
		GeptMsrBitSet(i, Msr, 0, FALSE);
		GeptMsrBitSet(i, Msr, 1, FALSE);
	}
	GeptMsrUnlock();
	FlLog("[MSR] Remove OK: MSR=0x%X(位图清位, 在途回调安全完成)", Msr);
	return STATUS_SUCCESS;
}

//v1.1: 枚举live MSR hook——与GeptApi.c GeptHookEnumerate同款语义
//(Buffer=NULL→*InOutCount=数量; 容量不足→STATUS_BUFFER_TOO_SMALL
//并回填所需数量)。条目字段逐个复制(不拷Removed——那是内部状态)
NTSTATUS GeptMsrHookEnumerate(GEPT_MSR_HOOK* Buffer, ULONG* InOutCount)
{
	if (InOutCount == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}
	ULONG cnt = 0;
	GeptMsrLock();
	for (ULONG i = 0; i < GEPT_MSR_MAX; i++)
	{
		if (s_msr[i].Removed == 0)
		{
			cnt++;
		}
	}
	if (Buffer == NULL)
	{
		*InOutCount = cnt;
		GeptMsrUnlock();
		return STATUS_SUCCESS;
	}
	if (cnt > *InOutCount)
	{
		*InOutCount = cnt;
		GeptMsrUnlock();
		return STATUS_BUFFER_TOO_SMALL;
	}
	ULONG i2 = 0;
	for (ULONG i = 0; i < GEPT_MSR_MAX; i++)
	{
		if (s_msr[i].Removed == 0)
		{
			Buffer[i2].Msr = s_msr[i].Msr;
			Buffer[i2].Context = s_msr[i].Context;
			Buffer[i2].OnRead = s_msr[i].OnRead;
			Buffer[i2].OnWrite = s_msr[i].OnWrite;
			i2++;
		}
	}
	GeptMsrUnlock();
	*InOutCount = cnt;
	return STATUS_SUCCESS;
}
