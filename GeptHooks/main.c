#include<ntifs.h>
#include<intrin.h>
#include"common.h"
#include"PageHook.h"
#include"VMX.h"
#include"ept.h"
#include"GeptApi.h"

//构建标签: 会打进日志第一行, 用于核对测试机跑的是不是本次编译的
//二进制(见DriverEntry横幅)。**代码每次改动必须同步修改!**
//不用__DATE__/__TIME__——用户侧VS环境对其报"未声明的标识符"
#define GEPT_BUILD_TAG "v1.2"

//构建标签全局副本——黑匣子(GEPT_BLACKBOX)在FlInit时拷入,
//蓝屏DMP解析时自证二进制版本
CHAR g_geptBuildTag[24] = GEPT_BUILD_TAG;

//本驱动=框架生命周期模板: 资源分配→串行逐核启动VT→互斥仲裁→常驻。
//API使用方式: 把框架文件加入你自己的驱动工程, DriverEntry完成全核
//接管后即可调用GeptHookInstall/GeptMsrHookInstall(见README)

void DriverUload(PDRIVER_OBJECT pDriverObjct)
{
	UNREFERENCED_PARAMETER(pDriverObjct);
	//park守卫: 三重故障park核的VMM栈/park代码页(sti+hlt循环)仍被
	//占用, 卸载=释放后park核执行已释放内存=延迟崩溃。拒绝卸载,
	//保持加载让日志线程继续落盘, 用户收集日志后重启清理
	if (g_geptParkedMask != 0)
	{
		FlLog("Unload: 拒绝卸载! cpu掩码%X在三重故障park中(代码页/VMM栈被park核占用, 机器应存活)——请收集日志后重启系统", g_geptParkedMask);
		Log("unload refused: parked mask=%X, reboot to clean", g_geptParkedMask);
		return;
	}
	FlLog("Unload: 开始关闭VT(全核IPI原子退出)");
	//必须先移除全部API hook再关VT: ①移除后新触发停止 ②在途回调
	//(stub的vmfunc/GeptCallOriginal)此刻VT仍开=安全执行完毕。
	//随后的2s宽限让被抢占的在途回调跑完; GeptViewSwitch的bInGuest
	//检查再兜一层(vmx_off后执行vmfunc=#UD蓝屏, 这是已知最后风险点)
	GeptApiRemoveAll();
	{
		LARGE_INTEGER tick;
		tick.QuadPart = -2000000LL;    //2秒宽限
		KeDelayExecutionThread(KernelMode, FALSE, &tick);
	}
	ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
	//全核IPI原子退出: KeIpiGenericCall一次广播全部核(含发起核)进
	//IPI_LEVEL处理程序, 每核**原子**完成vmcall(1)退出+清VMXE+双PGE
	//冲刷。IPI_LEVEL高于DISPATCH, 处理程序内零调度零线程=各核退出
	//过程之间不存在任何线程切换窗口; IPI返回后各核VT已关死+TLB已
	//冲空, 后续一切进程切换基于空TLB从零重建。绝不能用"逐核亲和性
	//切换退出": DISPATCH级下线程不迁移, 循环全在发起核执行=只退
	//1核=释放其余核正在使用的VMCS/EPT=双重故障蓝屏
	//(实现: VmxStopAllIpi, 见VMX.c)
	KeIpiGenericCall(VmxStopAllIpi, 0);
	FlLog("Unload: 全核IPI退出完成(每核原子vmcall(1)+清VMXE+双PGE冲刷, 环'v'×%u核留痕, 零调度零窗口)", cpuCount);
	FlLog("Unload: VT已关闭, 释放资源");
	//PASSIVE_LEVEL释放全部资源(含EPT_DATA与动态页表)
	for (ULONG i = 0; i < cpuCount; i++)
	{
		VmxFreeCpuResources(i);
	}
	//释放共享高区页表(全部核EPT共用的pdpt, 幂等)
	EptShutdownHighMappings();
	//API内存(条目+跳板池, 纯pool释放无VT依赖; 此刻已无任何在途
	//代码引用——hook已移除+VT已关)
	GeptApiFreeMemory();
	FlLog("Unload: 完成, 关闭文件日志");
	FlShutdown();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObjct, PUNICODE_STRING pRegPath)
{
	pDriverObjct->DriverUnload = DriverUload;

	//文件日志最先初始化(之后无论在哪一步卡死, 日志都保留现场)。
	//默认关闭: FlInit读本驱动服务注册表键的LogEnable DWORD(=1才
	//启用), 关闭时后续所有FlLog均为空操作, 零后台线程零文件I/O
	FlInit(pRegPath);

	//预分配必须在PASSIVE_LEVEL: 每核VMXON/VMCS/VMM栈/MSR位图/EPT_DATA
	//绝不能推迟到DPC(DISPATCH_LEVEL)里分配
	ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
	FlLog("==== GeptHooks build %s | cpu数=%d ====",
		GEPT_BUILD_TAG, cpuCount);
	FlLog("黑匣子: BB=%p 魔数=GEPTBB01 看门狗v2(自旋+rdtsc, 30s不动)→蓝屏0xDEADC0DE→DMP",
		(PVOID)&g_flBlackBox);
	//蓝屏地址判读锚点: bugcheck 0x1E参数2若落在[base, base+size)内
	//=驱动内代码, 否则(ntoskrnl等)——配合事件查看器的BugCheck参数使用
	FlLog("驱动映像: base=%p size=0x%X", pDriverObjct->DriverStart, pDriverObjct->DriverSize);
	//模块清单: 沿DriverSection的InLoadOrderLinks遍历全部已加载模块,
	//蓝屏时用bugcheck参数2对照本清单即知崩溃模块(无需WinDbg离线判读)
	{
		typedef struct _GEPT_KLDR_ENTRY {
			LIST_ENTRY InLoadOrderLinks;          //+0x00
			LIST_ENTRY InMemoryOrderLinks;        //+0x10
			LIST_ENTRY InInitializationOrderLinks;//+0x20
			PVOID DllBase;                        //+0x30
			PVOID EntryPoint;                     //+0x38
			ULONG SizeOfImage;                    //+0x40
			UNICODE_STRING FullDllName;           //+0x48
			UNICODE_STRING BaseDllName;           //+0x58
		} GEPT_KLDR_ENTRY;
		GEPT_KLDR_ENTRY* start = (GEPT_KLDR_ENTRY*)pDriverObjct->DriverSection;
		if (start != NULL)
		{
			FlLog("=== 模块清单(蓝屏参数2判读: 看落在哪个模块的[base,base+size)内) ===");
			GEPT_KLDR_ENTRY* mod = start;
			ULONG cnt = 0;
			do
			{
				char name[24];
				ULONG n = mod->BaseDllName.Length / sizeof(WCHAR);
				if (n > 23)
				{
					n = 23;
				}
				for (ULONG c = 0; c < n; c++)
				{
					WCHAR wch = mod->BaseDllName.Buffer
						? mod->BaseDllName.Buffer[c] : L'?';
					name[c] = (wch < 128) ? (char)wch : '?';
				}
				name[n] = 0;
				FlLog("MOD %p +%06X %s", mod->DllBase, mod->SizeOfImage, name);
				mod = (GEPT_KLDR_ENTRY*)mod->InLoadOrderLinks.Flink;
				cnt++;
			} while (mod != start && cnt < 400);
		}
	}
	Log("cpu数=%d, 开始预分配VT资源", cpuCount);
	for (ULONG i = 0; i < cpuCount; i++)
	{
		//面包屑: 每步都落盘, 卡死时最后一行即精确卡点
		FlLog("cpu%u/%u: VMX资源分配(4块连续内存)...", i, cpuCount);
		if (VMXInitCpuAlloc(i) != 0)
		{
			Log("cpu%d 资源预分配失败(连续内存不足?), 回滚", i);
			FlLog("cpu%u VMX资源分配失败! 回滚返回(此时sc start应报错而非挂起)", i);
			for (ULONG j = 0; j <= i; j++)
			{
				VmxFreeCpuResources(j);
			}
			EptShutdownHighMappings();   //共享高区页(幂等)
			FlShutdown();
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		FlLog("cpu%u: EPT_DATA分配(2MB连续)+建表...", i);
		if (!NT_SUCCESS(EptInitEptData(i)))
		{
			Log("cpu%d EPT初始化失败, 回滚", i);
			FlLog("cpu%u EPT初始化失败! 回滚返回(此时sc start应报错而非挂起)", i);
			for (ULONG j = 0; j <= i; j++)
			{
				VmxFreeCpuResources(j);
			}
			EptShutdownHighMappings();   //共享高区页(幂等)
			FlShutdown();
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		FlLog("cpu%u: 预分配OK", i);
	}
	Log("预分配完成, 启动VT(串行逐核)");
	FlLog("预分配完成, 串行逐核启动VT(每步落盘, 冻结时最后一行=精确卡点)");

	//串行逐核启动(PASSIVE级+亲和性切换): 不用KeGenericCallDpc——
	//DPC让全核同时进DISPATCH级, 期间线程不可能被调度, 日志出现
	//结构性盲区; 串行模式每步落盘后再前进
#if GEPT_LAUNCH_CPU_BASE >= 0
	ULONG launchBase = GEPT_LAUNCH_CPU_BASE;
#else
	ULONG launchBase = cpuCount - 1;    //-1=最后一核(安静核)
#endif
	FlLog("启动模式: launchBase=cpu%u LIMIT=%d(0=不限制), 目标=全部%u核接管",
		launchBase, GEPT_LAUNCH_CPU_LIMIT, cpuCount);
	KAFFINITY allCpus = KeQueryActiveProcessors();
	for (ULONG i = 0; i < cpuCount; i++)
	{
		//只虚拟化[launchBase, launchBase+LIMIT)区间的核, 其余真机
		if (GEPT_LAUNCH_CPU_LIMIT != 0 &&
			(i < launchBase || i >= launchBase + GEPT_LAUNCH_CPU_LIMIT))
		{
			FlLog("cpu%u 跳过启动(目标区间外的核保持真机)", i);
			continue;
		}
		if (g_vcpu[i].VMXON == NULL || g_vcpu[i].VMCS == NULL)
		{
			FlLog("cpu%u 无资源, 跳过", i);
			continue;
		}
		FlLog("cpu%u: 切换亲和性, VT环境检查+启动...", i);
		KeSetSystemAffinityThread((KAFFINITY)1 << i);
		//记录虚拟化目标核(日志心跳读它)
		g_geptVcpuCpu = (LONG)i;
		if (CommCheckBios() && CommCheckCpuid() && CommCheckCr4())
		{
			VMXInitCpuStart();
		}
		else
		{
			FlLog("cpu%u VT环境检查未通过, 跳过", i);
		}
		KeSetSystemAffinityThread(allCpus);
	}

	//各核启动结果落盘: 哪些核进了guest/哪些失败, 一目了然
	FlLog("全部核心启动流程完成, 各核状态:");
	{
		ULONG inGuestTotal = 0;
		for (ULONG i = 0; i < cpuCount; i++)
		{
			FlLog("cpu%d inGuest=%d launchFailed=%d vmxon=%d",
				i, g_vcpu[i].bInGuest, g_vcpu[i].bLaunchFailed, g_vcpu[i].bVmxOn);
			if (g_vcpu[i].bInGuest)
			{
				inGuestTotal++;
			}
		}
		//零核in-guest=VT启动全败, 两大成因: ①Hyper-V/VBS占用
		//②同框架宿主已在场——我们的vmxon在宿主guest内执行→exit→
		//宿主伪造失败→__vmx_on逐核返回失败=VT-x原生互斥仲裁生效
		//(零签名零共享对象零暴露面)。此时手动释放全部资源
		//(DriverEntry失败时I/O管理器卸载映像**不调DriverUnload**,
		//必须在此自清)+返回失败=sc start报错干净退出, 宿主零扰动
		//(互斥协议: 后到者让位)
		if (inGuestTotal == 0)
		{
			FlLog("DriverEntry: **零核in-guest——VT启动全败**。成因: "
				"Hyper-V/VBS占用 或 同框架宿主hypervisor已在场。"
				"释放全部资源后干净退出, 系统不受影响");
			for (ULONG i = 0; i < cpuCount; i++)
			{
				if (g_vcpu[i].bVmxOn)
				{
					//防御性: vmxon成功但未进guest的核做标准停核
					//(此形态下通常bVmxOn=0, 分支空转——保险不伤)
					KeSetSystemAffinityThread((KAFFINITY)1 << i);
					VmxStopCpu();
					KeSetSystemAffinityThread(allCpus);
				}
			}
			for (ULONG i = 0; i < cpuCount; i++)
			{
				VmxFreeCpuResources(i);
			}
			EptShutdownHighMappings();
			FlShutdown();
			Log("junior refused (VT held by host/occupied), clean exit");
			return STATUS_UNSUCCESSFUL;
		}
	}
	//放行Desktop镜像: 到此驱动加载窗口期结束, 用户目录文件操作
	//不再有过滤驱动死锁风险
	FlMarkEntryDone();
	return STATUS_SUCCESS;
}
