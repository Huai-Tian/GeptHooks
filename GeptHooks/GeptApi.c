#include <ntifs.h>
#include "GeptApi.h"
#include "common.h"
#include "PageHook.h"
#include "VMX.h"

//====================================================================
// API实现(VMFUNC双EPT detour)
//
//触发链: hooked视图hook页(=CodePage)目标偏移14B跳转 → trampoline槽
//  (mov r10,entry; jmp GeptStubEntry) → GeptStubEntry(hook.asm):
//  vmfunc(0,0)切clean → SAVE_ALL → GeptCallbackDispatch → 用户回调
//  → vmfunc(0,1)切回hooked → ret回调用者(rax=回调返回值)
//
//clean视图下原函数字节完好→GeptCallOriginal直接call Target(无需重放)。
//Remove: 还原CodePage被覆盖字节+全核invept→hooked≡clean=hook失效;
//在途回调安全完成(槽/条目延迟到卸载释放)
//====================================================================

//内部条目(安装后字段全部不可变→分发器无锁读安全)
typedef struct _GEPT_API_ENTRY
{
	LIST_ENTRY link;
	GEPT_HOOK pub;        //Target/Callback/Context
	PVOID Trampoline;     //本hook独享trampoline槽(可执行池页内)
	PVOID ReplayVA;       //LDE重定位跳板(副本prologue+尾jmp回; fallback的GeptCallOriginal+replay自测共用)
	ULONG ReplayLen;      //重定位覆盖的字节数(=PHHook跳转覆盖长度, 两者同源同长)
	volatile LONG Removed;//1=已移除(Enumerate跳过; 内存延迟到卸载)
} GEPT_API_ENTRY, *PGEPT_API_ENTRY;

static LIST_ENTRY s_apiList = { 0 };       //live+removed条目(卸载统一释放)
static KSPIN_LOCK s_apiLock = { 0 };       //Install/Remove/Enumerate互斥(均PASSIVE)
static volatile LONG s_apiLockInit = 0;

//trampoline槽池: 每槽64B, 每池页64槽。NonPagedPool=x64上可执行
//(NonPagedPoolNx才是不可执行变体)
#define GEPT_TRAMP_SLOT  64
#define GEPT_TRAMP_PER_PAGE (PAGE_SIZE / GEPT_TRAMP_SLOT)
static PVOID s_trampPool[32];    //池页(上限32页=2048个hook, demo足够)
static volatile LONG s_trampUsed = 0;
static KIRQL s_apiOldIrql = 0;

//每核当前hook(嵌套save-restore, GeptCallOriginal读)
static PGEPT_API_ENTRY volatile s_currentHook[128] = { 0 };
//每核当前触发帧(GeptCallOriginal据此取第5+栈参数源; 嵌套正确分层)
static PGUEST_REGS volatile s_currentRegs[128] = { 0 };

//hook.asm的detour stub入口(填进每个trampoline槽)
extern VOID GeptStubEntry(VOID);

//hook.asm GeptCallOrigAsm的参数块(偏移与hook.asm硬契约, 改一处须同步):
//  +00h Target  +08h StackArgs源  +10h Count  +18h..30h Arg1-4
typedef struct _GEPT_ORIG_CALL
{
	ULONG64 Target;
	ULONG64 StackArgs;
	ULONG64 Count;
	ULONG64 Arg1;
	ULONG64 Arg2;
	ULONG64 Arg3;
	ULONG64 Arg4;
} GEPT_ORIG_CALL;
extern ULONG64 GeptCallOrigAsm(GEPT_ORIG_CALL* Call);

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

//手动视图切换: VT已关/无VMFUNC核=no-op(vmx_off后vmfunc=#UD蓝屏)
VOID GeptViewSwitch(ULONG eptpIndex)
{
	ULONG cpu = KeGetCurrentProcessorNumber();
	if (!g_vcpu[cpu].bInGuest || !g_vcpu[cpu].bVmfuncOn)
	{
		return;
	}
	CmVmfuncSwitch(eptpIndex);
}

//asm stub调用(rcx=API条目, rdx=GUEST_REGS帧): 设置每核当前hook+触发帧
//后进用户回调。StackArgs>0时回调收第5+参数指针(=触发帧上实参
//regs->rsp+28h, 可读可写, 写后按改写值转发)
ULONG64 GeptCallbackDispatch(PVOID entryPtr, PGUEST_REGS regs)
{
	PGEPT_API_ENTRY e = (PGEPT_API_ENTRY)entryPtr;
	ULONG cpu = KeGetCurrentProcessorNumber();
	PGEPT_API_ENTRY prevHook = s_currentHook[cpu];
	PGUEST_REGS prevRegs = s_currentRegs[cpu];
	s_currentHook[cpu] = e;
	s_currentRegs[cpu] = regs;
	ULONG64* stackArgs = (e->pub.StackArgs != 0)
		? (ULONG64*)(regs->rsp + 0x28) : NULL;
	ULONG64 ret = e->pub.Callback(e->pub.Context,
		regs->rcx, regs->rdx, regs->r8, regs->r9, stackArgs);
	s_currentHook[cpu] = prevHook;
	s_currentRegs[cpu] = prevRegs;
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
	//双路径按当前核能力分派:
	//  VMFUNC核: 切clean→直接call原始入口→归位hooked
	//  fallback核: 直接call Target=撞跳转无限递归→经重定位跳板
	//StackArgs>0时走GeptCallOrigAsm桩重建完整x64调用帧, 栈参源=
	//触发帧上实参(回调可能已改写)
	if (e->pub.StackArgs != 0 && s_currentRegs[cpu] != NULL)
	{
		GEPT_ORIG_CALL oc;
		oc.Target = g_vcpu[cpu].bVmfuncOn
			? (ULONG64)e->pub.Target : (ULONG64)e->ReplayVA;
		oc.StackArgs = s_currentRegs[cpu]->rsp + 0x28;   //栈参源(影子之上)
		oc.Count = e->pub.StackArgs;
		oc.Arg1 = Arg1;
		oc.Arg2 = Arg2;
		oc.Arg3 = Arg3;
		oc.Arg4 = Arg4;
		if (g_vcpu[cpu].bVmfuncOn)
		{
			GeptViewSwitch(0);
			ULONG64 ret = GeptCallOrigAsm(&oc);
			GeptViewSwitch(1);
			return ret;
		}
		return GeptCallOrigAsm(&oc);   //fallback核: 跳板未被hook, 无需切视图
	}
	if (g_vcpu[cpu].bVmfuncOn)
	{
		GeptViewSwitch(0);
		typedef ULONG64(*GEPT_ORIG_FN)(ULONG64, ULONG64, ULONG64, ULONG64);
		ULONG64 ret = ((GEPT_ORIG_FN)e->pub.Target)(Arg1, Arg2, Arg3, Arg4);
		GeptViewSwitch(1);
		return ret;
	}
	typedef ULONG64(*GEPT_REPLAY_FN)(ULONG64, ULONG64, ULONG64, ULONG64);
	return ((GEPT_REPLAY_FN)e->ReplayVA)(Arg1, Arg2, Arg3, Arg4);
}

//trampoline槽机器码(24B/64B): [0..9]=mov r10,imm64 | [10..15]=jmp [rip+0]
//| [16..23]=GeptStubEntry地址。指针必须落t+16(jmp的RIP_after=t+16,
//disp32=0→CPU从t+16读操作数), 写错偏移=jmp处#GP, 故有回读自检
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
			NonPagedPool, PAGE_SIZE, 'Pool');
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
	*(ULONG64*)(t + 16) = (ULONG64)&GeptStubEntry;
	//回读自检: 按CPU实际读取路径(t+16)验证目标指针
	if (*(volatile ULONG64*)(t + 16) != (ULONG64)&GeptStubEntry)
	{
		FlLog("[API] trampoline编码自检FAIL(t+16读回≠GeptStubEntry)——拒绝该槽(编码回归?)");
		return NULL;
	}
	return t;
}

NTSTATUS GeptHookInstall(const GEPT_HOOK* Hook)
{
	if (Hook == NULL || Hook->Target == NULL || Hook->Callback == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}
	//栈参数个数上限(=hook.asm GeptCallOrigAsm固定帧32槽, 超限
	//拒绝——绝不让桩复制越界)
	if (Hook->StackArgs > GEPT_MAX_STACK_ARGS)
	{
		FlLog("[API] Install拒绝: StackArgs=%u超上限%u(目标%p)",
			Hook->StackArgs, (ULONG)GEPT_MAX_STACK_ARGS, Hook->Target);
		return STATUS_INVALID_PARAMETER;
	}
	//安装gate="至少一核in-guest"(零核=VT启动全败, PHHook无处布防, 拒绝):
	//  VMFUNC核: 双EPT零VM-Exit detour
	//  无VMFUNC核(老CPU/降级核): violation降级——EptSetHook按核分派,
	//    detour stub统一(GeptViewSwitch按核no-op), GeptCallOriginal
	//    按核走重定位跳板(见其注释)
	{
		ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
		ULONG inGuest = 0, vmfuncCores = 0;
		for (ULONG i = 0; i < cpuCount; i++)
		{
			if (g_vcpu[i].bInGuest)
			{
				inGuest++;
				if (g_vcpu[i].bVmfuncOn)
				{
					vmfuncCores++;
				}
			}
		}
		if (inGuest == 0)
		{
			FlLog("[API] Install拒绝: 零核in-guest(VT未启动), 无处布防");
			return STATUS_NOT_SUPPORTED;
		}
		if (vmfuncCores < inGuest)
		{
			FlLog("[API] Install: %u/%u核无VMFUNC——这些核走violation降级"
				"(每次触发1+次VM-Exit, 功能/API语义等价, 只是隐藏性降级)",
				inGuest - vmfuncCores, inGuest);
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
	entry->ReplayVA = NULL;
	entry->ReplayLen = 0;
	//LDE重定位跳板(所有路径无条件构建——fallback的CallOriginal必需
	//+replay自测用; VMFUNC纯核上仅自测用到, 96B成本可忽略)。
	//MinLen=14=PHHook跳转覆盖长度, 两者同源(PHGetHookLen同款解码循环)
	//→replay覆盖字节数≡CodePage跳转覆盖字节数, 重放/jmp回严格配套
	ULONG replayLen = 0;
	entry->ReplayVA = PHBuildRelocTrampoline((ULONG64)Hook->Target,
		sizeof(JMP_OPCODE64), &replayLen);
	if (entry->ReplayVA == NULL)
	{
		ExFreePool(entry);
		FlLog("[API] Install失败: 目标%p prologue不可重定位(相对分支/RIP相对超界, 详见[Reloc]行)",
			Hook->Target);
		return STATUS_UNSUCCESSFUL;
	}
	entry->ReplayLen = replayLen;
	entry->Trampoline = GeptAllocTrampoline(entry);
	if (entry->Trampoline == NULL)
	{
		ExFreePool(entry->ReplayVA);
		ExFreePool(entry);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	//PHHook: CodePage整页复制+目标偏移14B绝对跳转→我们的trampoline槽
	//+DPC逐核EptSetHook(VMFUNC核: hooked表PTE→CodePage+切hooked视图;
	//fallback核: 拆页+清execute的violation布防——按核自动分派)
	NTSTATUS st = PHHook(Hook->Target, entry->Trampoline, Hook->HideRead);
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
	FlLog("[API] Install OK: 目标=%p 回调=%p 上下文=%p 跳板槽=%p replay=%p(%uB, 回扫自检过) 栈参=%u 读透明=%u(detour式, 零重放机器)",
		Hook->Target, Hook->Callback, Hook->Context, entry->Trampoline,
		entry->ReplayVA, entry->ReplayLen, Hook->StackArgs, Hook->HideRead);
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
	//(还原长度=ReplayLen——与CodePage跳转覆盖长度同源同长)
	found->Removed = 1;
	GEPT_REMOVE_CTX ctx;
	ULONG off = (ULONG)((ULONG_PTR)Target & (PAGE_SIZE - 1));
	ctx.DstVA = (ULONG64)pe->CodePageVA + off;
	ctx.SrcVA = (ULONG64)pe->OriginalPageVA + off;
	ctx.Len = found->ReplayLen;
	KeGenericCallDpc(GeptRemoveDpc, &ctx);
	FlLog("[API] Remove OK: 目标=%p 还原%uB@CodePage+%03Xh+全核invept(hook失效; 在途回调安全完成)",
		Target, found->ReplayLen, off);
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

//replay自测——直接调用指定hook的重定位跳板(执行副本prologue→尾jmp
//进入原函数体→完整跑完原函数→正常返回)。用于上机验证LDE重定位生成器
//(任何Windows版本的目标函数, 不依赖本机构建); 传入伪句柄
//NtCurrentProcess()=安全且确定的判据(NtClose返回
//STATUS_INVALID_HANDLE 0xC0000008)。仅PASSIVE_LEVEL调试/自测用,
//**不进任何生产路径**
NTSTATUS GeptApiSelfTestReplay(PVOID Target, ULONG64 Arg1)
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
	if (found == NULL || found->ReplayVA == NULL)
	{
		return STATUS_NOT_FOUND;
	}
	typedef NTSTATUS(*GEPT_REPLAY_FN)(ULONG64);
	return ((GEPT_REPLAY_FN)found->ReplayVA)(Arg1);
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
	ULONG replays = 0;
	while (!IsListEmpty(&s_apiList))
	{
		PLIST_ENTRY p = RemoveHeadList(&s_apiList);
		PGEPT_API_ENTRY e = CONTAINING_RECORD(p, GEPT_API_ENTRY, link);
		if (e->ReplayVA != NULL)
		{
			ExFreePool(e->ReplayVA);
			replays++;
		}
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
		FlLog("[API] FreeMemory: 条目%u个(含replay跳板%u个)+跳板池%u页已释放",
			entries, replays, pages);
	}
}
