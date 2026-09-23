#include <ntifs.h>
#include <intrin.h>
#include "GeptMsr.h"
#include "common.h"
#include "VMX.h"

//====================================================================
// MSR拦截简易API实现(接口契约见GeptMsr.h头注释)
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
//KVM同款运行期改位实践)——无需invept/DPC广播。
//位图读写一律走root直写vmcall: EPT自我隐蔽把位图页改译零页,
//guest态直写=静默失效(v1.5c实测P0)
//====================================================================

#define GEPT_MSR_MAX 16

typedef struct _GEPT_MSR_ENTRY
{
	volatile LONG Removed;   //1=空闲/已移除(分发跳过); 0=live
	ULONG32 Msr;
	PVOID Context;
	GEPT_MSR_READ_CB OnRead;    //NULL=读位不置(直通)
	GEPT_MSR_WRITE_CB OnWrite;  //NULL=写位不置(直通)
} GEPT_MSR_ENTRY, *PGEPT_MSR_ENTRY;

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

//root侧位图原语(VMX.c的vmcall(GEPT_VMCALL_MSRBIT) case调用): 直接
//VA位运算——root模式访问不走EPT, 位图页自我隐蔽(改译零页)不影响;
//guest态直写=写进零页=静默失效+自检假阳性(v1.5c实测P0)。act:
//0=仅读/1=置位/2=清位; rw: 0=读位图/1=写位图。返回核位掩码(bit i=
//cpu i该位操作后现值, i≥64不计)。无锁无日志(VM-exit上下文安全)
ULONG64 GeptMsrBitmapOpRoot(ULONG32 Msr, UCHAR rw, UCHAR act)
{
	ULONG64 mask = 0;
	for (ULONG i = 0; i < 128; i++)
	{
		PUCHAR base = (PUCHAR)g_vcpu[i].MsrBitMap;
		if (base == NULL)
		{
			continue;
		}
		if (rw != 0)
		{
			base += 1024 * 2;                 //写位图区(SDM 25.6.9)
		}
		ULONG64 m = Msr;
		if (m >= 0xC0000000)
		{
			base += 1024;                     //高区(0xC0000000+)
			m -= 0xC0000000;
		}
		PUCHAR p = base + (m / 8);
		UCHAR bit = (UCHAR)(m % 8);
		if (act == 1)
		{
			*p |= (UCHAR)(1 << bit);
		}
		else if (act == 2)
		{
			*p &= (UCHAR)~(1 << bit);
		}
		if (i < 64 && ((*p >> bit) & 1))
		{
			mask |= 1ULL << i;
		}
	}
	return mask;
}

//guest侧包装: vmcall进root直写真位图。PASSIVE/DISPATCH(持锁)均可
//——exit handler无调度无锁。本核必须in-guest(真机vmcall=#UD蓝屏;
//不在=部分启动诊断态, 由调用方决策)。失败时位图未变更
static NTSTATUS GeptMsrBitmapVmcall(ULONG32 Msr, UCHAR rw, UCHAR act, ULONG64* maskOut)
{
	ULONG cur = KeGetCurrentProcessorNumber();
	if (cur >= 128 || !g_vcpu[cur].bInGuest)
	{
		return STATUS_DEVICE_NOT_READY;
	}
	ULONG64 mask = CmVmCall(GEPT_VMCALL_MSRBIT, Msr,
		((ULONG64)rw << 8) | act, 0);
	if (maskOut != NULL)
	{
		*maskOut = mask;
	}
	return STATUS_SUCCESS;
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
	//位图root直写+核掩码自检(在锁内: 与并发的Remove/Install串行)。
	//vmcall须本核in-guest(真机vmcall=#UD蓝屏; 不在=部分启动诊断态)
	ULONG64 maskR = 0, maskW = 0;
	NTSTATUS bmSt = STATUS_SUCCESS;
	if (Hook->OnRead != NULL)
	{
		bmSt = GeptMsrBitmapVmcall(Hook->Msr, 0, 1, &maskR);
	}
	if (NT_SUCCESS(bmSt) && Hook->OnWrite != NULL)
	{
		bmSt = GeptMsrBitmapVmcall(Hook->Msr, 1, 1, &maskW);
	}
	if (!NT_SUCCESS(bmSt))
	{
		//回收可能已置的读位(幂等, 失败亦无碍——分发器无live条目=直通)
		GeptMsrBitmapVmcall(Hook->Msr, 0, 2, NULL);
		GeptMsrBitmapVmcall(Hook->Msr, 1, 2, NULL);
		GeptMsrUnlock();
		FlLog("[MSR] Install拒绝: 位图原语不可达(本核未in-guest, MSR=0x%X)",
			Hook->Msr);
		return bmSt;
	}
	//自检: 全部in-guest核的位图位须已置(缺位=硬件不拦截=guest内
	//rdmsr直接#GP), 当场撤销
	{
		ULONG64 need = 0;
		for (ULONG i = 0; i < cpuCount && i < 64; i++)
		{
			if (g_vcpu[i].bInGuest)
			{
				need |= 1ULL << i;
			}
		}
		if ((Hook->OnRead != NULL && (maskR & need) != need) ||
			(Hook->OnWrite != NULL && (maskW & need) != need))
		{
			e->Removed = 1;
			GeptMsrBitmapVmcall(Hook->Msr, 0, 2, NULL);
			GeptMsrBitmapVmcall(Hook->Msr, 1, 2, NULL);
			GeptMsrUnlock();
			FlLog("[MSR] Install自检FAIL: 位图核掩码R=%llX W=%llX未覆盖in-guest=%llX(MSR=0x%X)——撤销安装防#GP",
				(unsigned long long)maskR, (unsigned long long)maskW,
				(unsigned long long)need, Hook->Msr);
			return STATUS_UNSUCCESSFUL;
		}
	}
	InterlockedExchange(&e->Removed, 0);    //发布(字段+位图已就绪)
	GeptMsrUnlock();
	FlLog("[MSR] Install OK: MSR=0x%X 读=%s 写=%s 上下文=%p(root直写位图+核掩码自检过)",
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
	//先标Removed(分发立即停止命中)再清位图; 在途回调安全完成。
	//root直写清位; 原语不可达(本核未in-guest)时位图残留——VMCS随
	//卸载销毁, 残留无害
	found->Removed = 1;
	NTSTATUS rmSt = GeptMsrBitmapVmcall(Msr, 0, 2, NULL);
	if (NT_SUCCESS(rmSt))
	{
		rmSt = GeptMsrBitmapVmcall(Msr, 1, 2, NULL);
	}
	GeptMsrUnlock();
	if (!NT_SUCCESS(rmSt))
	{
		FlLog("[MSR] Remove: 位图原语不可达(本核未in-guest), 位图残留至VMCS销毁: MSR=0x%X",
			Msr);
		return STATUS_SUCCESS;
	}
	FlLog("[MSR] Remove OK: MSR=0x%X(root直写清位, 在途回调安全完成)", Msr);
	return STATUS_SUCCESS;
}

//枚举live MSR hook——与GeptApi.c GeptHookEnumerate同款语义
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
