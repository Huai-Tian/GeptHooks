#include<ntifs.h>
#include"common.h"
#include"VMX.h"
#include"GeptApi.h"
#include"GeptMsr.h"
#include"CPU.h"

//本文件=框架使用示例(面向二次开发者):
//  DriverEntry  → VmxStartAllCpus接管全核 → 安装自己的hook
//  DriverUnload → 移除hook → VmxShutdownAllCpus关停并释放资源
//框架细节(资源分配/串行启动/互斥仲裁/内置隐藏/日志)全在VMX.c,
//使用者只需关心hook回调本身。API契约见GeptApi.h/GeptMsr.h头注释

//demo目标: NtClose(演示期间全系统句柄关闭都会被拦截)
static PVOID g_demoNtClose = NULL;

//demo1: EPT hook回调(detour语义, 返回值=新函数返回值)
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

//demo2: MSR hook读回调(LSTAR=系统调用入口地址, 0xC0000082)
static volatile LONG g_demoLstarFired = 0;   //自检: 回调真实触发计数

static ULONG64 DemoLstarOnRead(PVOID Context, ULONG32 Msr)
{
	UNREFERENCED_PARAMETER(Context);
	InterlockedIncrement(&g_demoLstarFired);
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
		hook.HideRead = 1;   //演示读透明: PG/扫描器读hook页只见原始字节
		NTSTATUS st = GeptHookInstall(&hook);
		FlLog("[Demo] EPT hook NtClose(%p): %s",
			g_demoNtClose, NT_SUCCESS(st) ? "OK" : "FAIL(见[API]行)");
		//读自检: 直接读hook目标首字节——HideRead生效=读到原始prologue
		//(MTF路径透出原页); 68开头=CodePage跳转可见=读透明失效
		if (NT_SUCCESS(st))
		{
			const UCHAR* b = (const UCHAR*)g_demoNtClose;
			FlLog("[Demo] 读自检: NtClose首8字节=%02X %02X %02X %02X %02X %02X %02X %02X(%s)",
				b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
				b[0] == 0x68 ? "FAIL:见跳转字节=读可见" : "OK:原始prologue=读透明");
			//REP读自检: rep movsb整串读hook页——走root仿真('q'事件,
			//单exit吸收整串, 不进MTF循环); 字节=原始prologue即通过
			UCHAR repBuf[8];
			CmRepMovsbDemo(repBuf, (PUCHAR)g_demoNtClose, 8);
			FlLog("[Demo] REP读自检: rep movsb×8=%02X %02X %02X %02X %02X %02X %02X %02X(%s)",
				repBuf[0], repBuf[1], repBuf[2], repBuf[3],
				repBuf[4], repBuf[5], repBuf[6], repBuf[7],
				repBuf[0] == 0x40 ? "OK:整串仿真命中" : "FAIL:见[Q]/[M]事件判路径");
		}
	}
	//MSR hook: 读拦截
	{
		GEPT_MSR_HOOK msrHook = { 0 };
		msrHook.Msr = MSR_LSTAR;
		msrHook.OnRead = DemoLstarOnRead;
		NTSTATUS st = GeptMsrHookInstall(&msrHook);
		FlLog("[Demo] MSR hook LSTAR(0x%X): %s",
			(ULONG)MSR_LSTAR, NT_SUCCESS(st) ? "OK" : "FAIL(见[MSR]行)");
		//正向自检: guest态真读一次被hook的MSR——位图→exit(31)→
		//分发→回调全链路(v1.5c位图静默失效正是缺此环节而漏检;
		//通过时心跳r31应+1)
		if (NT_SUCCESS(st))
		{
			ULONG64 v = __readmsr(MSR_LSTAR);
			FlLog("[Demo] MSR自检: guest态rdmsr LSTAR=%llX 回调触发=%u(%s)",
				(unsigned long long)v, (ULONG)g_demoLstarFired,
				g_demoLstarFired > 0 ? "OK:拦截生效" : "FAIL:位图未拦截");
		}
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
