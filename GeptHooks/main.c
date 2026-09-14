#include<ntifs.h>
#include"common.h"
#include"winApiDef.h"
#include"PageHook.h"

//分阶段联调开关:
//0 = 仅开启虚拟化(vmlaunch+EPT恒等映射), 用于先验证VT层稳定
//1 = 自测Hook: hook本驱动内的GeptTestTarget并调用一次, 指令布局自控不依赖系统版本
//2 = 正式Hook NtClose(危险: 需先确认本机NtClose前19字节prologue与hook.asm重放一致)
#define GEPT_HOOK_STAGE 0

ULONG64 g_jmp_ntclose = 0;
ULONG64 g_jmp_testtarget = 0;
NTSTATUS AsmHookNtClose(HANDLE hanle);
VOID GeptTestTarget();
VOID AsmHookTestTarget();

NTSTATUS HookNtClose()
{
	Log("NtClose hooked!");
	return 0;
}

VOID HookTestTarget()
{
	Log("GeptTestTarget hooked! EPT hook chain OK");
}

void DriverUload(PDRIVER_OBJECT pDriverObjct)
{
	KeGenericCallDpc(CommVtShutDown, NULL);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObjct, PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pRegPath);
	KeGenericCallDpc(CommVtStart, NULL);
	pDriverObjct->DriverUnload = DriverUload;

#if GEPT_HOOK_STAGE == 0
	Log("stage0: virtualization only, no hook installed");
#elif GEPT_HOOK_STAGE == 1
	//自测: 目标函数与跳板都在hook.asm, 前15字节指令布局完全已知
	g_jmp_testtarget = (ULONG64)GeptTestTarget + PHGetHookLen((ULONG64)GeptTestTarget, sizeof(JMP_OPCODE64), TRUE);
	PHHook(GeptTestTarget, AsmHookTestTarget);
	//触发一次: 日志出现"GeptTestTarget hooked!"且系统不死机 = EPT Hook全链路打通
	GeptTestTarget();
	Log("stage1: self-test hook done");
#else
	//NtClose: +19及hook.asm重放的prologue绑定特定Windows版本,
	//换系统前必须先反汇编本机NtClose确认一致, 否则会跳进指令中间导致卡死/蓝屏
	g_jmp_ntclose = (ULONG64)NtClose + PHGetHookLen((ULONG64)NtClose, sizeof(JMP_OPCODE64), TRUE);
	PHHook(NtClose, AsmHookNtClose);
	Log("stage2: NtClose hook installed");
#endif
	return STATUS_SUCCESS;
}
