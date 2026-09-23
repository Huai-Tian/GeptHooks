#include <intrin.h>
#include"PageHook.h"
#include"LDasm.h"
#include"common.h"
#include"VMX.h"
LIST_ENTRY g_PageList = {0};
NTSTATUS PHHook(PVOID pFun, PVOID pHook, ULONG hideRead)
{
	NTSTATUS status = STATUS_SUCCESS;
	PHYSICAL_ADDRESS phys = {0};
	//框架页恒限低区512GB内(EPT恒等区=WB快路径; 超限=自检[5]拒绝vmlaunch)
	phys.QuadPart = 0x7FFFFFFFFF;
	PUCHAR CodePage = NULL;
	BOOLEAN isNewCodePage = FALSE;
	//判断是否被hook过
	PPAGE_HOOK_ENTRY pEntry=PHGetHookEntryPage(pFun);
	//如果改页没有被HOOK过,那我们就申请一个新的页
	if (pEntry==NULL)
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
	//副本+跳板构建完成落盘——此后的死亡可用日志锚点二分定位到
	//"分配/复制/写跳板"与"DPC广播"两个子窗口
	FlLog("[PHHook] 副本就绪: 原页PFN=%llX CodePagePFN=%llX va=%p 跳板%uB hookLen=%u(页内偏移%u)",
		(unsigned long long)((MmGetPhysicalAddress(pFun).QuadPart) >> 12),
		(unsigned long long)((MmGetPhysicalAddress(CodePage).QuadPart) >> 12),
		CodePage, (unsigned)sizeof(JMP_OPCODE64), realHookLen, (ULONG)page_offset);

	PPAGE_HOOK_ENTRY pHookListEntry = ExAllocatePool(NonPagedPool,sizeof(PAGE_HOOK_ENTRY));

	if (pHookListEntry==NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	pHookListEntry->OriginalPtr = pFun;
	pHookListEntry->OriginalPageVA = PAGE_ALIGN(pFun);
	pHookListEntry->OriginalPagePFN = (MmGetPhysicalAddress(pFun).QuadPart)>>12;
	pHookListEntry->CodePageVA = CodePage;
	pHookListEntry->CodePagePFN= (MmGetPhysicalAddress(CodePage).QuadPart) >>12;
	pHookListEntry->HideRead = hideRead;
	//讲结构体添加到全局链表中
	if (g_PageList.Flink==NULL)
	{
		InitializeListHead(&g_PageList);
	}
	InsertTailList(&g_PageList,&pHookListEntry->link);
	if (isNewCodePage)
	{
		//
		HOOK_CONTEXT hookContext = {0};
		hookContext.CodePagePFN = pHookListEntry->CodePagePFN;
		hookContext.OriginalPagePFN = pHookListEntry->OriginalPagePFN;
		hookContext.HideRead = hideRead;
		//广播前后双锚点——广播内=全核并行vmcall(2)→EptSetHook
		//(VM-exit上下文: 拆2M页×2+分配pte页+清execute+invept)。
		//蓝屏/冻结发生在两锚点之间=exit上下文的EptSetHook路径
		FlLog("[PHHook] DPC广播开始: 8核vmcall(2)→EptSetHook(拆页+清execute), 环'S'rsn=21/22/23按核留痕");
		KeGenericCallDpc(PHHookCallBackDpc,&hookContext);
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
	//顺序逐条解码到累计长度≥codeSize(返回整指令边界, 跳回点不错位)
	ULONG64 src = codeAddr;
	ULONG all_len = 0;
	ldasm_data ldData = {0};
	do
	{
		ULONG len = ldasm(src, &ldData, is64);
		src += len;
		all_len += len;
	} while (all_len< codeSize);
	return all_len;
}

PPAGE_HOOK_ENTRY PHGetHookEntryPage(PVOID funPageAddr)
{
	if (g_PageList.Flink==NULL || IsListEmpty(&g_PageList))
	{
		return NULL;
	}
	for (PLIST_ENTRY pListEntry=g_PageList.Flink;pListEntry!=&g_PageList;pListEntry=pListEntry->Flink)
	{
		PPAGE_HOOK_ENTRY phookEntr = CONTAINING_RECORD(pListEntry, PAGE_HOOK_ENTRY, link);
		if (phookEntr->OriginalPageVA== funPageAddr)
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
	if (hookContext!=NULL)
	{
		//守卫: 仅in-guest核才能vmcall(真机vmcall=#UD蓝屏;
		//KeGenericCallDpc广播到所有核)
		ULONG hc = KeGetCurrentProcessorNumber();
		if (g_vcpu[hc].bInGuest)
		{
			//参数1:exitCode;参数2:原页PFN;参数3:CodePagePFN;参数4:HideRead
			CmVmCall(2, hookContext->OriginalPagePFN, hookContext->CodePagePFN,
				hookContext->HideRead);
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

//LDE重定位跳板生成器(接口见PageHook.h):
//  ①逐指令解码, 无效/超长=拒
//  ②相对分支(E8/E9/EB/jcc/loop)=拒(rel8无法跨页重定位)
//  ③RIP-relative寻址: 重算disp32=绝对有效地址-新RIP_after, 超±2GB=拒
//  ④尾接 FF 25 00000000 + <Target+Len> 位置无关绝对跳转
//  ⑤回扫自检: 重新解码逐条比对长度+字节(disp区除外)+尾跳核对
PVOID PHBuildRelocTrampoline(ULONG64 Target, ULONG MinLen, PULONG OutLen)
{
	if (OutLen != NULL)
	{
		*OutLen = 0;
	}
	//缓冲: 最坏prologue=MinLen+14(单条15B跨界)+尾跳14B=42B; 96B留足余量
	PUCHAR buf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, 96, 'tpeG');
	if (buf == NULL)
	{
		FlLog("[Reloc] 拒绝: 跳板缓冲分配失败");
		return NULL;
	}
	RtlZeroMemory(buf, 96);
	ULONG total = 0;
	ULONG64 src = Target;
	BOOLEAN bad = FALSE;
	while (total < MinLen)
	{
		ldasm_data ld = { 0 };
		ULONG len = ldasm((PVOID)src, &ld, TRUE);
		if (len == 0 || (ld.flags & F_INVALID) || total + len > 80)
		{
			FlLog("[Reloc] 拒绝: 偏移+%u处指令解码失败/超长(len=%u flags=%02X)",
				total, len, (ULONG)ld.flags);
			bad = TRUE;
			break;
		}
		//相对分支=拒
		if ((ld.flags & F_IMM) && (ld.flags & F_RELATIVE))
		{
			FlLog("[Reloc] 拒绝: 偏移+%u处相对分支指令(%02X %02X...)——prologue不可重定位",
				total, *(PUCHAR)src, *((PUCHAR)src + 1));
			bad = TRUE;
			break;
		}
		RtlCopyMemory(buf + total, (PVOID)src, len);
		//③RIP-relative数据寻址: 重算disp32
		if ((ld.flags & F_DISP) && (ld.flags & F_RELATIVE) && ld.disp_size == 4)
		{
			LONG64 oldDisp = *(LONG*)(buf + total + ld.disp_offset);
			//原指令的绝对有效地址: 原RIP_after + 原disp
			ULONG64 effective = src + len + (ULONG64)oldDisp;
			//新disp: 保持同一绝对有效地址——有效地址 - 跳板内RIP_after
			LONG64 newDisp = (LONG64)effective - (LONG64)(buf + total + len);
			if (newDisp < -0x80000000LL || newDisp > 0x7FFFFFFFLL)
			{
				FlLog("[Reloc] 拒绝: 偏移+%u处RIP-relative目标超±2GB(disp需%llX)",
					total, (long long)newDisp);
				bad = TRUE;
				break;
			}
			*(LONG*)(buf + total + ld.disp_offset) = (LONG)newDisp;
		}
		total += len;
		src += len;
	}
	if (!bad)
	{
		//④尾接位置无关绝对跳转 → Target+total
		buf[total] = 0xFF;
		buf[total + 1] = 0x25;
		*(ULONG32*)(buf + total + 2) = 0;
		*(ULONG64*)(buf + total + 6) = Target + total;
		//⑤回扫自检: 按CPU视角重新解码生成物, 与原始指令序列逐条比对
		ULONG chk = 0;
		ULONG64 ori = Target;
		while (chk < total && !bad)
		{
			ldasm_data ldNew = { 0 };
			ldasm_data ldOld = { 0 };
			ULONG lNew = ldasm(buf + chk, &ldNew, TRUE);
			ULONG lOld = ldasm((PVOID)ori, &ldOld, TRUE);
			if (lNew == 0 || lNew != lOld || (ldNew.flags & F_INVALID))
			{
				FlLog("[Reloc] 回扫自检FAIL: 生成物偏移+%u解码异常(新len=%u 旧len=%u)",
					chk, lNew, lOld);
				bad = TRUE;
				break;
			}
			//字节比对: 除被调整的disp32区(4字节)外逐字节必须一致
			for (ULONG k = 0; k < lNew; k++)
			{
			 BOOLEAN skip = ((ldOld.flags & F_DISP) && (ldOld.flags & F_RELATIVE) &&
					ldOld.disp_size == 4 &&
					k >= (ULONG)ldOld.disp_offset && k < (ULONG)ldOld.disp_offset + 4);
				if (!skip && buf[chk + k] != ((PUCHAR)ori)[k])
				{
					FlLog("[Reloc] 回扫自检FAIL: 生成物偏移+%u第%u字节不符(%02X≠%02X)",
						chk, k, buf[chk + k], ((PUCHAR)ori)[k]);
					bad = TRUE;
					break;
				}
			}
			chk += lNew;
			ori += lOld;
		}
		if (!bad && (buf[total] != 0xFF || buf[total + 1] != 0x25 ||
			*(ULONG64*)(buf + total + 6) != Target + total))
		{
			FlLog("[Reloc] 回扫自检FAIL: 尾跳转码/目标不符");
			bad = TRUE;
		}
	}
	if (bad)
	{
		ExFreePool(buf);
		return NULL;
	}
	if (OutLen != NULL)
	{
		*OutLen = total;
	}
	FlLog("[Reloc] 跳板就绪: 目标=%llX len=%uB(回扫自检逐条通过, 尾跳→%llX)",
		(unsigned long long)Target, total, (unsigned long long)(Target + total));
	return buf;
}

//卸载终清理(VT已关/hook已移除后调用, 幂等): CodePage含跳转码+原页
//副本, 条目含全部指针——清零后释放(取证反制)。同页多hook共享
//CodePage, 按VA去重防double free(API上限32, 64槽封顶)
VOID PHFreeAllMemory(VOID)
{
	if (g_PageList.Flink == NULL)
	{
		return;
	}
	PVOID freed[64];
	ULONG nFreed = 0, pages = 0, entries = 0;
	while (!IsListEmpty(&g_PageList))
	{
		PLIST_ENTRY p = RemoveHeadList(&g_PageList);
		PPAGE_HOOK_ENTRY e = CONTAINING_RECORD(p, PAGE_HOOK_ENTRY, link);
		BOOLEAN seen = FALSE;
		for (ULONG i = 0; i < nFreed; i++)
		{
			if (freed[i] == e->CodePageVA)
			{
				seen = TRUE;
				break;
			}
		}
		if (!seen && nFreed < 64)
		{
			freed[nFreed++] = e->CodePageVA;
			RtlZeroMemory(e->CodePageVA, PAGE_SIZE);
			MmFreeContiguousMemory(e->CodePageVA);
			pages++;
		}
		RtlZeroMemory(e, sizeof(PAGE_HOOK_ENTRY));
		ExFreePool(e);
		entries++;
	}
	FlLog("[PH] 终清理: CodePage %u页+条目%u个(清零后释放)", pages, entries);
}
