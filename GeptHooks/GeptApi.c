#include <ntifs.h>
#include "GeptApi.h"
#include "common.h"
#include "PageHook.h"
#include "VMX.h"

//====================================================================
// v3.50 Phase4: 简易API实现(VMFUNC双EPT detour)
//
//触发链: hooked视图hook页(=CodePage, 目标偏移处14B绝对跳转)
//   → 本hook独享trampoline槽(mov r10,entry; jmp GeptStubEntry)
//   → GeptStubEntry(hook.asm): vmfunc(0,0)切clean → SAVE_ALL
//     → GeptCallbackDispatch(本文件) → 用户回调
//     → vmfunc(0,1)切回hooked → ret回调用者(rax=回调返回值)
//
//为什么无需prologue重放/hookLen机器(相对v3.46跳板的本质简化):
//clean视图下原函数字节完好→GeptCallOriginal直接call Target原始入口;
//violation方案里"重放被覆盖的前N字节+jmp回+N"的整套trampoline机器
//只为绕过被覆盖的指令——双EPT下这问题不存在
//
//Remove语义: 不动EPT结构(hooked PTE仍指CodePage), 只把CodePage里被
//覆盖的前HookLen字节还原成原页内容(原页从未被修改=权威副本)+全核
//invept → hooked视图≡clean视图=hook死透; 在途回调(已过跳板的线程)
//安全完成(槽/条目延迟到卸载释放)。重装=PHHook重新整页复制+重新打
//跳转(CodePage重置), EPT已布防无需再广播
//====================================================================

//内部条目(安装后字段全部不可变→分发器无锁读安全)
typedef struct _GEPT_API_ENTRY
{
	LIST_ENTRY link;
	GEPT_HOOK pub;        //Target/Callback/Context
	PVOID Trampoline;     //本hook独享trampoline槽(可执行池页内)
	ULONG HookLen;        //被14B跳转覆盖的字节数(PHGetHookLen, Remove还原长度)
	volatile LONG Removed;//1=已移除(Enumerate跳过; 内存延迟到卸载)
} GEPT_API_ENTRY, * PGEPT_API_ENTRY;

static LIST_ENTRY s_apiList = { 0 };       //live+removed条目(卸载统一释放)
static KSPIN_LOCK s_apiLock = { 0 };       //Install/Remove/Enumerate互斥(均PASSIVE)
static volatile LONG s_apiLockInit = 0;

//trampoline槽池: 每槽64B(mov r10,imm64=10B + jmp[rip+0]=12B + 4B余量),
//每池页64槽。池页=NonPagedPool(x64 Win上NonPagedPool分配即可执行内存;
//NonPagedPoolNx才是不可执行变体——trampoline必须可执行)
#define GEPT_TRAMP_SLOT  64
#define GEPT_TRAMP_PER_PAGE (PAGE_SIZE / GEPT_TRAMP_SLOT)
static PVOID s_trampPool[32];    //池页(上限32页=2048个hook, demo足够)
static volatile LONG s_trampUsed = 0;
static KIRQL s_apiOldIrql = 0;

//每核当前hook(GeptCallbackDispatch设置/嵌套save-restore, GeptCallOriginal读)
static PGEPT_API_ENTRY volatile s_currentHook[128] = { 0 };

//hook.asm的detour stub入口(填进每个trampoline槽)
extern VOID GeptStubEntry(VOID);

static VOID GeptApiLock(VOID)
{
	if (InterlockedCompareExchange(&s_apiLockInit, 1, 0) == 0)
	{
		KeInitializeSpinLock(&s_apiLock);
	}
	if (s_apiList.Flink == NULL)
	{
		InitializeListHead(&s_apiList);
	}
	KeAcquireSpinLock(&s_apiLock, &s_apiOldIrql);
}
static VOID GeptApiUnlock(VOID)
{
	KeReleaseSpinLock(&s_apiLock, s_apiOldIrql);
}

//v3.50: 手动视图切换(asm stub/GeptCallOriginal共用)——VT已关/无VMFUNC核
//安全no-op。卸载竞态防御: vmx_off后non-root执行vmfunc=#UD蓝屏, 本检查把
//"在途回调跨卸载窗口"缩到check与vmfunc两条指令间被抢占的极小概率
//(配合DriverUload的GeptApiRemoveAll+2s宽限, 残余风险可忽略)
VOID GeptViewSwitch(ULONG eptpIndex)
{
	ULONG cpu = KeGetCurrentProcessorNumber();
	if (!g_vcpu[cpu].bInGuest || !g_vcpu[cpu].bVmfuncOn)
	{
		return;
	}
	CmVmfuncSwitch(eptpIndex);
}

//asm stub调用(rcx=API条目, rdx=GUEST_REGS帧): 设置每核当前hook(嵌套
//save/restore——回调内经线程迁移再触发另一hook时正确嵌套)后进用户回调
ULONG64 GeptCallbackDispatch(PVOID entryPtr, PGUEST_REGS regs)
{
	PGEPT_API_ENTRY e = (PGEPT_API_ENTRY)entryPtr;
	ULONG cpu = KeGetCurrentProcessorNumber();
	PGEPT_API_ENTRY prev = s_currentHook[cpu];
	s_currentHook[cpu] = e;
	ULONG64 ret = e->pub.Callback(e->pub.Context,
		regs->rcx, regs->rdx, regs->r8, regs->r9);
	s_currentHook[cpu] = prev;
	return ret;
}

ULONG64 GeptCallOriginal(ULONG64 Arg1, ULONG64 Arg2, ULONG64 Arg3, ULONG64 Arg4)
{
	ULONG cpu = KeGetCurrentProcessorNumber();
	PGEPT_API_ENTRY e = s_currentHook[cpu];
	if (e == NULL)
	{
		//非回调上下文调用(用户误用): 静默返回0+一次性留痕
		static volatile LONG s_warned = 0;
		if (InterlockedCompareExchange(&s_warned, 1, 0) == 0)
		{
			FlRingPush('w', cpu, 0, 0, 0, 0);
		}
		return 0;
	}
	//clean视图下原函数字节完好→直接调用原始入口(无重放/无trampoline)。
	//视图切换幂等(已clean时vmfunc到同值=合法no-op, SDM §28.5.7.3);
	//先切clean再调用再归位hooked=线程迁移安全(每核视图独立持久)
	GeptViewSwitch(0);
	typedef ULONG64(*GEPT_ORIG_FN)(ULONG64, ULONG64, ULONG64, ULONG64);
	ULONG64 ret = ((GEPT_ORIG_FN)e->pub.Target)(Arg1, Arg2, Arg3, Arg4);
	GeptViewSwitch(1);
	return ret;
}

//分配一个trampoline槽并填入跳板机器码:
//  49 BA <entry64>       mov r10, imm64   (r10=volatile, 函数入口clobber合法)
//  FF 25 00 00 00 00     jmp [rip+0]
//  <GeptStubEntry64>                      (位置无关, 不依赖±2GB邻近)
static PVOID GeptAllocTrampoline(PGEPT_API_ENTRY entry)
{
	if (s_trampUsed >= (LONG)(sizeof(s_trampPool) / sizeof(s_trampPool[0]) * GEPT_TRAMP_PER_PAGE))
	{
		return NULL;    //2048个hook上限
	}
	LONG slotIdx = InterlockedIncrement(&s_trampUsed) - 1;
	ULONG pageIdx = (ULONG)(slotIdx / GEPT_TRAMP_PER_PAGE);
	if (s_trampPool[pageIdx] == NULL)
	{
		s_trampPool[pageIdx] = ExAllocatePoolWithTag(
			NonPagedPool, PAGE_SIZE, 'tpeG');
		if (s_trampPool[pageIdx] == NULL)
		{
			return NULL;
		}
		RtlZeroMemory(s_trampPool[pageIdx], PAGE_SIZE);
	}
	PUCHAR t = (PUCHAR)s_trampPool[pageIdx] +
		(ULONG)(slotIdx % GEPT_TRAMP_PER_PAGE) * GEPT_TRAMP_SLOT;
	t[0] = 0x49;  t[1] = 0xBA;                        //mov r10, imm64
	*(ULONG64*)(t + 2) = (ULONG64)entry;
	t[10] = 0xFF; t[11] = 0x25;                       //jmp [rip+0]
	*(ULONG32*)(t + 12) = 0;
	*(ULONG64*)(t + 18) = (ULONG64)&GeptStubEntry;
	return t;
}

NTSTATUS GeptHookInstall(const GEPT_HOOK* Hook)
{
	if (Hook == NULL || Hook->Target == NULL || Hook->Callback == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}
	//detour stub无条件vmfunc: 要求全部in-guest核VMFUNC+双EPT就绪
	ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
	for (ULONG i = 0; i < cpuCount; i++)
	{
		if (g_vcpu[i].bInGuest &&
			(!g_vcpu[i].bVmfuncOn || g_vcpu[i].PeptDataHooked == NULL))
		{
			FlLog("[API] Install拒绝: cpu%u无VMFUNC/双EPT(detour stub需全核支持, 调用方应退化violation方案)", i);
			return STATUS_NOT_SUPPORTED;
		}
	}
	//重复安装检查(同Target)
	GeptApiLock();
	for (PLIST_ENTRY p = s_apiList.Flink; p != &s_apiList; p = p->Flink)
	{
		PGEPT_API_ENTRY e = CONTAINING_RECORD(p, GEPT_API_ENTRY, link);
		if (e->pub.Target == Hook->Target && !e->Removed)
		{
			GeptApiUnlock();
			FlLog("[API] Install拒绝: 目标%p已安装(Remove后可重装)", Hook->Target);
			return STATUS_UNSUCCESSFUL;
		}
	}
	GeptApiUnlock();
	PGEPT_API_ENTRY entry = (PGEPT_API_ENTRY)ExAllocatePoolWithTag(
		NonPagedPool, sizeof(GEPT_API_ENTRY), 'tpeG');
	if (entry == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	entry->pub = *Hook;
	entry->Removed = 0;
	entry->HookLen = PHGetHookLen((ULONG64)Hook->Target,
		sizeof(JMP_OPCODE64), TRUE);
	entry->Trampoline = GeptAllocTrampoline(entry);
	if (entry->Trampoline == NULL)
	{
		ExFreePool(entry);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	//PHHook(复用v3.46机器): CodePage整页复制+目标偏移14B绝对跳转→
	//我们的trampoline槽+DPC逐核EptSetHook(VMFUNC核: hooked表PTE→CodePage
	//+切hooked视图)。安装后本核系统运行在hooked视图, hook即时生效
	NTSTATUS st = PHHook(Hook->Target, entry->Trampoline);
	if (!NT_SUCCESS(st))
	{
		//PHHook失败(资源/中止): 条目作废(槽浪费, 卸载统一释放)
		entry->Removed = 1;
		GeptApiLock();
		InsertTailList(&s_apiList, &entry->link);
		GeptApiUnlock();
		FlLog("[API] Install失败: PHHook错误=0x%X(目标%p)", st, Hook->Target);
		return st;
	}
	GeptApiLock();
	InsertTailList(&s_apiList, &entry->link);
	GeptApiUnlock();
	FlLog("[API] Install OK: 目标=%p 回调=%p 上下文=%p 跳板槽=%p hookLen=%uB(detour式, 零重放机器)",
		Hook->Target, Hook->Callback, Hook->Context, entry->Trampoline, entry->HookLen);
	return STATUS_SUCCESS;
}

//Remove的DPC上下文(全核广播: 每核vmcall(7)还原字节+invept自身TLB)
typedef struct _GEPT_REMOVE_CTX
{
	ULONG64 DstVA;    //CodePage+页内偏移(还原目标)
	ULONG64 SrcVA;    //原页+页内偏移(权威副本, 原页从未被改)
	ULONG64 Len;      //HookLen
} GEPT_REMOVE_CTX;

static VOID GeptRemoveDpc(_In_ struct _KDPC* Dpc, _In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2)
{
	GEPT_REMOVE_CTX* ctx = (GEPT_REMOVE_CTX*)DeferredContext;
	ULONG cpu = KeGetCurrentProcessorNumber();
	if (ctx != NULL)
	{
		if (g_vcpu[cpu].bInGuest)
		{
			//vmcall(7): exit handler里memcpy+双视图invept(每核各一次:
			//memcpy幂等无害, invept按核生效故每核必做)
			CmVmCall(7, ctx->DstVA, ctx->SrcVA, ctx->Len);
		}
		else
		{
			FlRingPush('h', cpu, 7, ctx->DstVA, ctx->Len, 0);
		}
	}
	if (SystemArgument1)
	{
		KeSignalCallDpcDone(SystemArgument1);
	}
	if (SystemArgument2)
	{
		KeSignalCallDpcSynchronize(SystemArgument2);
	}
}

NTSTATUS GeptHookRemove(PVOID Target)
{
	PGEPT_API_ENTRY found = NULL;
	GeptApiLock();
	for (PLIST_ENTRY p = s_apiList.Flink; p != &s_apiList; p = p->Flink)
	{
		PGEPT_API_ENTRY e = CONTAINING_RECORD(p, GEPT_API_ENTRY, link);
		if (e->pub.Target == Target && !e->Removed)
		{
			found = e;
			break;
		}
	}
	GeptApiUnlock();
	if (found == NULL)
	{
		return STATUS_NOT_FOUND;
	}
	PPAGE_HOOK_ENTRY pe = PHGetHookEntryPage(PAGE_ALIGN(Target));
	if (pe == NULL)
	{
		FlLog("[API] Remove异常: 目标%p无CodePage条目(PHHook状态漂移?)", Target);
		return STATUS_UNSUCCESSFUL;
	}
	//字节还原+全核invept(vmcall(7)广播)。此后hooked视图≡clean视图=
	//hook死透; 已过跳板的在途回调安全完成(槽/条目不动)
	found->Removed = 1;
	GEPT_REMOVE_CTX ctx;
	ULONG off = (ULONG)((ULONG_PTR)Target & (PAGE_SIZE - 1));
	ctx.DstVA = (ULONG64)pe->CodePageVA + off;
	ctx.SrcVA = (ULONG64)pe->OriginalPageVA + off;
	ctx.Len = found->HookLen;
	KeGenericCallDpc(GeptRemoveDpc, &ctx);
	FlLog("[API] Remove OK: 目标=%p 还原%uB@CodePage+%03Xh+全核invept(hook失效; 在途回调安全完成)",
		Target, found->HookLen, off);
	return STATUS_SUCCESS;
}

NTSTATUS GeptHookEnumerate(GEPT_HOOK* Buffer, ULONG* InOutCount)
{
	if (InOutCount == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}
	ULONG cnt = 0;
	GeptApiLock();
	for (PLIST_ENTRY p = s_apiList.Flink; p != &s_apiList; p = p->Flink)
	{
		PGEPT_API_ENTRY e = CONTAINING_RECORD(p, GEPT_API_ENTRY, link);
		if (!e->Removed)
		{
			cnt++;
		}
	}
	if (Buffer == NULL)
	{
		*InOutCount = cnt;
		GeptApiUnlock();
		return STATUS_SUCCESS;
	}
	if (cnt > *InOutCount)
	{
		*InOutCount = cnt;
		GeptApiUnlock();
		return STATUS_BUFFER_TOO_SMALL;
	}
	ULONG i = 0;
	for (PLIST_ENTRY p = s_apiList.Flink; p != &s_apiList; p = p->Flink)
	{
		PGEPT_API_ENTRY e = CONTAINING_RECORD(p, GEPT_API_ENTRY, link);
		if (!e->Removed)
		{
			Buffer[i++] = e->pub;
		}
	}
	GeptApiUnlock();
	*InOutCount = cnt;
	return STATUS_SUCCESS;
}

//DriverUload在关VT**之前**调用: 移除全部live hook(新触发停止;
//在途回调随后的vmfunc(0,1)此刻VT仍开着=安全), 宽限期由调用方安排
VOID GeptApiRemoveAll(VOID)
{
	//快照目标列表(Remove内部会再拿锁)
	PVOID targets[32];
	ULONG n = 0;
	GeptApiLock();
	for (PLIST_ENTRY p = s_apiList.Flink; p != &s_apiList && n < 32; p = p->Flink)
	{
		PGEPT_API_ENTRY e = CONTAINING_RECORD(p, GEPT_API_ENTRY, link);
		if (!e->Removed)
		{
			targets[n++] = e->pub.Target;
		}
	}
	GeptApiUnlock();
	for (ULONG i = 0; i < n; i++)
	{
		GeptHookRemove(targets[i]);
	}
	if (n > 0)
	{
		FlLog("[API] RemoveAll: 已移除%u个hook(在途回调将安全完成)", n);
	}
}

//DriverUload在关VT**之后**调用(纯内存释放, 无VT依赖)
VOID GeptApiFreeMemory(VOID)
{
	//未安装过任何hook(链表头未初始化)=直接返回
	if (s_apiList.Flink == NULL)
	{
		return;
	}
	ULONG entries = 0;
	while (!IsListEmpty(&s_apiList))
	{
		PLIST_ENTRY p = RemoveHeadList(&s_apiList);
		PGEPT_API_ENTRY e = CONTAINING_RECORD(p, GEPT_API_ENTRY, link);
		ExFreePool(e);
		entries++;
	}
	s_apiList.Flink = NULL;    //幂等: 重复调用安全
	ULONG pages = 0;
	for (ULONG i = 0; i < sizeof(s_trampPool) / sizeof(s_trampPool[0]); i++)
	{
		if (s_trampPool[i] != NULL)
		{
			ExFreePool(s_trampPool[i]);
			s_trampPool[i] = NULL;
			pages++;
		}
	}
	s_trampUsed = 0;
	if (entries != 0 || pages != 0)
	{
		FlLog("[API] FreeMemory: 条目%u个+跳板池%u页已释放", entries, pages);
	}
}
