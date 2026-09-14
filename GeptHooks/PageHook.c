#include <intrin.h>
#include"PageHook.h"
#include"LDasm.h"
#include"winApiDef.h"
#include"common.h"
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
		KeGenericCallDpc(PHHookCallBackDpc, &hookContext);
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
	ULONG64 src = codeAddr;
	ULONG all_len = 0;
	ldasm_data ldData = { 0 };
	do
	{
		ULONG len = ldasm(codeAddr, &ldData, is64);
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
		//参数1:exitCode;参数2:传原函数的物理地址;参数3:CodePage物理地址
		CmVmCall(2, hookContext->OriginalPagePFN, hookContext->CodePagePFN, 0);
	}
	KeSignalCallDpcDone(SystemArgument1);
	KeSignalCallDpcSynchronize(SystemArgument2);


}
