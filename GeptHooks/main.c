#include<ntifs.h>
#include"common.h"
#include"VMX.h"
#include"GeptApi.h"
#include"GeptMsr.h"
#include"CPU.h"

//本文件=框架使用示例:
//  DriverEntry  → VmxStartAllCpus接管全核 → 安装自己的hook
//  DriverUnload → 移除hook → VmxShutdownAllCpus关停并释放资源
//框架细节(资源分配/串行启动/互斥仲裁/内置隐藏/日志)全在VMX.c,
//API契约见GeptApi.h/GeptMsr.h头注释

//目标: NtClose(演示期间全系统句柄关闭都会被拦截)
static PVOID g_demoNtClose = NULL;

//EPT hook回调(detour语义, 返回值=新函数返回值)
//回调运行在任意线程/任意IRQL(含DISPATCH级): 只做IRQL安全操作,
//禁止FlLog/DbgPrint/分页内存/阻塞(完整纪律见GeptApi.h)
static ULONG64 DemoNtCloseCallback(PVOID Context, ULONG64 Handle,
	ULONG64 Arg2, ULONG64 Arg3, ULONG64 Arg4, ULONG64* StackArgs)
{
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(StackArgs);
	//示例=透传原函数并返回其结果。
	//拦截=直接return STATUS_INVALID_HANDLE;
	//篡改=修改Handle/Arg后经GeptCallOriginal转发改写值
	return GeptCallOriginal(Handle, Arg2, Arg3, Arg4);
}

//MSR hook读回调(LSTAR=系统调用入口地址, 0xC0000082)
static ULONG64 DemoLstarOnRead(PVOID Context, ULONG32 Msr)
{
	UNREFERENCED_PARAMETER(Context);
	//示例=返回真值(零副作用监控)。
	//伪造=直接return任意值(guest的rdmsr只能见到它)
	return GeptMsrReadReal(Msr);
}

static VOID DemoHookInstall(VOID)
{
	//EPT hook: 目标=内核函数地址
	UNICODE_STRING ntCloseName;
	RtlInitUnicodeString(&ntCloseName, L"NtClose");
	g_demoNtClose = MmGetSystemRoutineAddress(&ntCloseName);
	if (g_demoNtClose != NULL)
	{
		GEPT_HOOK hook = { 0 };
		hook.Target = g_demoNtClose;
		hook.Callback = DemoNtCloseCallback;
		NTSTATUS st = GeptHookInstall(&hook);
		FlLog("[Demo] EPT hook NtClose(%p): %s",
			g_demoNtClose, NT_SUCCESS(st) ? "OK" : "FAIL(见[API]行)");
	}
	//MSR hook: 读拦截
	{
		GEPT_MSR_HOOK msrHook = { 0 };
		msrHook.Msr = MSR_LSTAR;
		msrHook.OnRead = DemoLstarOnRead;
		NTSTATUS st = GeptMsrHookInstall(&msrHook);
		FlLog("[Demo] MSR hook LSTAR(0x%X): %s",
			(ULONG)MSR_LSTAR, NT_SUCCESS(st) ? "OK" : "FAIL(见[MSR]行)");
	}
}

VOID DriverUload(PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	//按目标移除(未显式移除的hook由关停流程统一清理)
	GeptMsrHookRemove(MSR_LSTAR);
	if (g_demoNtClose != NULL)
	{
		GeptHookRemove(g_demoNtClose);
	}
	//关停: 移除残余hook→全核IPI原子退出VT→释放全部资源
	VmxShutdownAllCpus();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pRegPath);
	pDriverObject->DriverUnload = DriverUload;

	//框架接管全核; 失败时资源已自清理, 直接返回即可
	NTSTATUS st = VmxStartAllCpus(pDriverObject);
	if (!NT_SUCCESS(st))
	{
		return st;
	}

	//接管成功, 安装演示hook
	DemoHookInstall();
	return STATUS_SUCCESS;
}
