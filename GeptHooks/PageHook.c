#include <intrin.h>
#include"PageHook.h"
#include"LDasm.h"
#include"winApiDef.h"
#include"common.h"
#include"VMX.h"
LIST_ENTRY g_PageList = { 0 };
NTSTATUS PHHook(PVOID pFun, PVOID pHook)
{
	Log("PHHook: 目标=%p 跳板=%p", pFun, pHook);
	NTSTATUS status = STATUS_SUCCESS;
	PHYSICAL_ADDRESS phys = { 0 };
	phys.QuadPart = MAXULONG64;
	PUCHAR CodePage = NULL;
	BOOLEAN isNewCodePage = FALSE;
	//判断是否被hook过
	PPAGE_HOOK_ENTRY pEntry = PHGetHookEntryPage(pFun);
	//如果改页没有被HOOK过,那我们就申请一个新的页
	if (pEntry == NULL)
	{
		//新申请一个页用来存放原函数的页数据
		CodePage = MmAllocateContiguousMemory(PAGE_SIZE, phys);
		isNewCodePage = TRUE;
		//添加
		RtlZeroMemory(CodePage, PAGE_SIZE);
	}
	else
	{
		CodePage = pEntry->CodePageVA;
	}
	//复制原函数所在页到新申请的页

	memcpy(CodePage, PAGE_ALIGN(pFun), PAGE_SIZE);
	//构建跳转代码
	JMP_OPCODE64 jmpCode64 = { 0 };
	PHInitJmpCode(&jmpCode64, pHook);
	ULONG_PTR page_offset = (ULONG_PTR)pFun - (ULONG_PTR)PAGE_ALIGN(pFun);
	memcpy(CodePage + page_offset, &jmpCode64, sizeof(JMP_OPCODE64));
	//获取hook的实际代码长度超出了多少个字节,讲超出部门用nop填充，以免干扰
	ULONG realHookLen = PHGetHookLen(pFun, sizeof(JMP_OPCODE64), TRUE);
	ULONG offset = realHookLen - sizeof(JMP_OPCODE64);
	if (offset > 0)
	{
		memset(CodePage + page_offset + sizeof(JMP_OPCODE64), 0x90, offset);
	}
	//v3.43: 副本+跳板构建完成落盘——蓝屏窗口(<1s)内的第一锚点。
	//此后任何死亡, 文件日志最后一行=本行或下一锚点, 死亡点二分粒度
	//收敛到"分配/复制/写跳板"与"DPC广播"两个子窗口
	FlLog("[PHHook] 副本就绪: 原页PFN=%llX CodePagePFN=%llX va=%p 跳板%uB hookLen=%u(页内偏移%u)",
		(unsigned long long)((MmGetPhysicalAddress(pFun).QuadPart) >> 12),
		(unsigned long long)((MmGetPhysicalAddress(CodePage).QuadPart) >> 12),
		CodePage, (unsigned)sizeof(JMP_OPCODE64), realHookLen, (ULONG)page_offset);

	PPAGE_HOOK_ENTRY pHookListEntry = ExAllocatePool(NonPagedPool, sizeof(PAGE_HOOK_ENTRY));

	if (pHookListEntry == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	pHookListEntry->OriginalPtr = pFun;
	pHookListEntry->OriginalPageVA = PAGE_ALIGN(pFun);
	pHookListEntry->OriginalPagePFN = (MmGetPhysicalAddress(pFun).QuadPart) >> 12;
	pHookListEntry->CodePageVA = CodePage;
	pHookListEntry->CodePagePFN = (MmGetPhysicalAddress(CodePage).QuadPart) >> 12;
	//讲结构体添加到全局链表中
	if (g_PageList.Flink == NULL)
	{
		InitializeListHead(&g_PageList);
	}
	InsertTailList(&g_PageList, &pHookListEntry->link);
	if (isNewCodePage)
	{
		//
		HOOK_CONTEXT hookContext = { 0 };
		hookContext.CodePagePFN = pHookListEntry->CodePagePFN;
		hookContext.OriginalPagePFN = pHookListEntry->OriginalPagePFN;
		//v3.43: 广播前后双锚点——广播内=8核并行vmcall(2)→EptSetHook
		//(VM-exit上下文: 拆2M页×2+分配pte页+清execute+invept)。
		//蓝屏/冻结发生在两锚点之间=exit上下文的EptSetHook路径
		FlLog("[PHHook] DPC广播开始: 8核vmcall(2)→EptSetHook(拆页+清execute), 环'S'rsn=21/22/23按核留痕");
		KeGenericCallDpc(PHHookCallBackDpc, &hookContext);
		FlLog("[PHHook] DPC广播返回(全核EptSetHook已执行)");
	}
	return status;
}

void PHInitJmpCode(PJMP_OPCODE64 pjmpCode, ULONG64 jmpTo)
{
	PULARGE_INTEGER  jmpAddr = (PULARGE_INTEGER)&jmpTo;
	pjmpCode->pushOp = 0x68;
	pjmpCode->jmpAddressLow = jmpAddr->LowPart;
	pjmpCode->movOp = 0x042444C7;
	pjmpCode->jmpAddressHigh = jmpAddr->HighPart;
	pjmpCode->retOp = 0xC3;
}

ULONG PHGetHookLen(ULONG64 codeAddr, ULONG codeSize, BOOLEAN is64)
{
	//v3.46根因修复(v3.45蓝屏0x3B@nt!NtClose+0xE的裁决): 旧版
	//ldasm(codeAddr,...)永远解码**第一条指令**(src推进了却没用上),
	//返回值=ceil(codeSize/首指令长)×首指令长:
	//  GeptTestTarget: 首条mov(3B)×5=15, 恰好等于真实整指令边界(前5条
	//    指令全是3B)——STAGE1毕业全靠这个巧合掩盖了bug
	//  NtClose: 首条push rbx(2B)×7=14, 真实边界=22(2+1+2+2+2+4+9)
	//    →g_jmp_ntclose=NtClose+14≠asm重放22B→跳板重放22B后jmp+14
	//    落进mov rax,gs:[188h]指令中间(第2字节48)→错误解码
	//    mov rax,[0x188](绝对地址,丢GS前缀)→#PF→0x3B
	ULONG64 src = codeAddr;
	ULONG all_len = 0;
	ldasm_data ldData = { 0 };
	do
	{
		ULONG len = ldasm(src, &ldData, is64);
		src += len;
		all_len += len;
	} while (all_len < codeSize);
	return all_len;
}

PPAGE_HOOK_ENTRY PHGetHookEntryPage(PVOID funPageAddr)
{
	if (g_PageList.Flink == NULL || IsListEmpty(&g_PageList))
	{
		return NULL;
	}
	for (PLIST_ENTRY pListEntry = g_PageList.Flink; pListEntry != &g_PageList; pListEntry = pListEntry->Flink)
	{
		PPAGE_HOOK_ENTRY phookEntr = CONTAINING_RECORD(pListEntry, PAGE_HOOK_ENTRY, link);
		if (phookEntr->OriginalPageVA == funPageAddr)
		{
			return phookEntr;
		}
	}
	return NULL;
}

PPAGE_HOOK_ENTRY PHGetHookEntryPageBy(ULONG64 gpa)
{
	if (g_PageList.Flink == NULL || IsListEmpty(&g_PageList))
	{
		return NULL;
	}
	for (PLIST_ENTRY pListEntry = g_PageList.Flink; pListEntry != &g_PageList; pListEntry = pListEntry->Flink)
	{
		PPAGE_HOOK_ENTRY phookEntr = CONTAINING_RECORD(pListEntry, PAGE_HOOK_ENTRY, link);
		if (phookEntr->OriginalPagePFN == gpa)
		{
			return phookEntr;
		}
	}
	return NULL;
}

VOID PHHookCallBackDpc(_In_ struct _KDPC* Dpc, _In_opt_ PVOID DeferredContext, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2)
{
	PHOOK_CONTEXT hookContext = (PHOOK_CONTEXT)DeferredContext;
	if (hookContext != NULL)
	{
		//v3.41守卫: 仅已进入guest(KEEP)的核才能vmcall——真机上执行vmcall
		//=非法指令#UD=蓝屏0x1E@c000001d。KeGenericCallDpc广播到**所有**核,
		//若任一核launch失败/逃生后留在真机, 旧版无条件vmcall会把"单核启动
		//失败(本可安全降级)"升级成"整机蓝屏"。v3.40实测8核全inGuest=1,
		//此守卫当前是纯防御, 但STAGE 2(NtClose全系统调用)前必须就位
		ULONG hc = KeGetCurrentProcessorNumber();
		if (g_vcpu[hc].bInGuest)
		{
			//参数1:exitCode;参数2:传原函数的物理地址;参数3:CodePage物理地址
			CmVmCall(2, hookContext->OriginalPagePFN, hookContext->CodePagePFN, 0);
		}
		else
		{
			FlRingPush('h', hc, 2, hookContext->OriginalPagePFN,
				hookContext->CodePagePFN, 0);
		}
	}
	//KeGenericCallDpc约定这两个参数非空, 判空仅为满足SAL静态分析
	if (SystemArgument1)
	{
		KeSignalCallDpcDone(SystemArgument1);
	}
	if (SystemArgument2)
	{
		KeSignalCallDpcSynchronize(SystemArgument2);
	}
}
