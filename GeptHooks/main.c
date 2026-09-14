#include<ntifs.h>
#include"common.h"
#include"winApiDef.h"
#include"PageHook.h"
#include"VMX.h"
#include"ept.h"

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
	UNREFERENCED_PARAMETER(pDriverObjct);
	//各核退出VT: 成功进入guest的核vmcall退出, 仅vmxon成功的核直接vmx_off
	KeGenericCallDpc(CommVtShutDown, NULL);
	//PASSIVE_LEVEL释放全部资源(含EPT_DATA与动态页表)
	ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
	for (ULONG i = 0; i < cpuCount; i++)
	{
		VmxFreeCpuResources(i);
	}
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObjct, PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pRegPath);
	pDriverObjct->DriverUnload = DriverUload;

	//预分配阶段(PASSIVE_LEVEL): 每核VMXON/VMCS/VMM栈/MSR位图/2MB的EPT_DATA
	//绝不能推迟到DPC(DISPATCH_LEVEL)里分配, 那是此前整机卡死的根源之一
	ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
	Log("cpu数=%d, 开始预分配VT资源", cpuCount);
	for (ULONG i = 0; i < cpuCount; i++)
	{
		if (VMXInitCpuAlloc(i) != 0)
		{
			Log("cpu%d 资源预分配失败(连续内存不足?), 回滚", i);
			for (ULONG j = 0; j <= i; j++)
			{
				VmxFreeCpuResources(j);
			}
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		if (!NT_SUCCESS(EptInitEptData(i)))
		{
			Log("cpu%d EPT初始化失败, 回滚", i);
			for (ULONG j = 0; j <= i; j++)
			{
				VmxFreeCpuResources(j);
			}
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	}
	Log("预分配完成, 启动VT");

	//各核进入VT(vmlaunch在DPC中执行)
	KeGenericCallDpc(CommVtStart, NULL);

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
