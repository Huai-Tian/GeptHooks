#include<ntifs.h>
#include<intrin.h>
#include"common.h"
#include"VMX.h"
#include"ept.h"
#include"GeptApi.h"

//构建标签(v3.46): 每次改动代码必须同步修改! 会打进日志第一行,
//用于核对测试机跑的是不是本次编译的二进制(见DriverEntry横幅)
//v1.2: **交付形态: 测试代码剥离 + 日志系统默认关闭**
//  ①DriverEntry只保留框架生命周期: 资源分配→串行逐核启动VT→互斥仲裁
//    (零核in-guest=释放资源干净退出)→常驻。开发期验证用的全部自测代码
//    整体退役: STAGE1自测hook/STAGE2 NtClose demo/六参栈参数自测/病毒
//    模拟探针/VMFUNC与双EPT标记自测/TSC隐藏自测/MSR demo——API使用者
//    不需要它们(验证史与判据见NOTES.md与README里程碑表)。
//    bVmfuncOn能力探测本就在VMX.c启动路径(VmxSetupVmcs按ctls2 bit13
//    经MSR 0x48B掩码后存活判定), 自测移除不影响按核VMFUNC/violation降级
//  ②文件日志系统(含蓝屏黑匣子看门狗)默认关闭: 服务注册表键LogEnable=1
//    才启用(common.c FlInit读开关); 关闭=零后台线程/零文件I/O/零观测面,
//    全部Fl*接口为空操作
//  ③配套删除: hook.asm自测目标与病毒探针(GeptTestTarget/GeptTestTarget6/
//    AsmHookTestTarget/GeptVirusVmxDetectOff/GeptVirusVmxOn);
//    common-asm.asm的CmVmfuncTest(CmVmfuncSwitch保留——GeptViewSwitch用)
//v1.1d: 全核IPI原子退出(KeIpiGenericCall)根治卸载蓝屏(裁决见DriverUload
//  内注释与NOTES.md); v3.x-v1.1全部版本裁决史完整记录在NOTES.md
#define GEPT_BUILD_TAG "v1.2"

//v3.33: 构建标签全局副本——黑匣子(common.h GEPT_BLACKBOX)在FlInit时
//拷入, 蓝屏DMP解析时自证二进制版本
CHAR g_geptBuildTag[24] = GEPT_BUILD_TAG;

void DriverUload(PDRIVER_OBJECT pDriverObjct)
{
	UNREFERENCED_PARAMETER(pDriverObjct);
	//v3.35: park守卫——park核的VMM栈/park代码页(sti+hlt循环)仍被占用,
	//卸载=释放后park核执行已释放内存=延迟崩溃。拒绝卸载, 保持加载让
	//T1继续落盘, 用户收集日志后重启清理
	if (g_geptParkedMask != 0)
	{
		FlLog("Unload: 拒绝卸载! cpu掩码%X在三重故障park中(代码页/VMM栈被park核占用, 机器应存活)——请收集日志后重启系统", g_geptParkedMask);
		Log("unload refused: parked mask=%X, reboot to clean", g_geptParkedMask);
		return;
	}
	FlLog("Unload: 开始关闭VT(全核IPI原子退出)");
	//v3.50 Phase4: 先移除全部API hook(CodePage字节还原+全核invept)——
	//必须在vmx_off**之前**: ①移除后新触发停止 ②在途回调(stub的
	//vmfunc(0,1)/GeptCallOriginal)此刻VT仍开=安全执行完毕。
	//随后的2s宽限让被抢占的在途回调跑完; GeptViewSwitch的bInGuest
	//检查再兜一层(残余窗口=check与vmfunc两条指令间被抢占+停机2s,
	//概率可忽略; vmx_off后执行vmfunc=#UD蓝屏, 这是已知最后风险点)
	GeptApiRemoveAll();
	{
		LARGE_INTEGER tick;
		tick.QuadPart = -2000000LL;    //2秒宽限
		KeDelayExecutionThread(KernelMode, FALSE, &tick);
	}
	ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
	//v1.1d: **全核IPI原子退出**——v1.1c实测0x7F(8=double fault)裁决:
	//DISPATCH_LEVEL下KeSetSystemAffinityThread不迁移运行中的线程
	//(迁移靠FlLog睡眠让出=0x50窗口的同一机制), 串行循环8次全在发起核
	//执行→只退1核→释放其余7核正在使用的VMCS/EPT=双重故障(日志
	//"Unload: 完成"后崩=释放后残余核翻译已损坏; 本轮只有cpu7一条
	//[r]环事件=铁证)。v1.1d=KeIpiGenericCall一次广播全部核(含发起核)
	//进IPI_LEVEL处理程序: 每核**原子**完成vmcall(1)退出+清VMXE+双PGE
	//冲刷——IPI内零调度零线程, IPI返回后各核VT已关死+TLB已冲空,
	//被打断线程与后续一切切换基于空TLB从零重建=v1.1/v1.1b两轮0x50
	//的暴露窗(vmx_off后~调度切入其他进程线程)构造性为0。观测性:
	//IPI内禁等待(T1也被IPI打断), 每核FlRingPush('v')留痕(T1稍后落盘),
	//IPI返回后PASSIVE补日志
	KeIpiGenericCall(VmxStopAllIpi, 0);
	FlLog("Unload: 全核IPI退出完成(每核原子vmcall(1)+清VMXE+双PGE冲刷, "
		"环'v'×%u核留痕, 零调度零窗口)", cpuCount);
	FlLog("Unload: VT已关闭, 释放资源");
	//PASSIVE_LEVEL释放全部资源(含EPT_DATA与动态页表)
	for (ULONG i = 0; i < cpuCount; i++)
	{
		VmxFreeCpuResources(i);
	}
	//v3.18: 释放共享高区页表(8核EPT共用的511个pdpt, 幂等)
	EptShutdownHighMappings();
	//v3.50: API内存(条目+跳板池, 纯pool释放无VT依赖; 此刻已无任何
	//在途代码引用——hook已移除+VT已关)
	GeptApiFreeMemory();
	FlLog("Unload: 完成, 关闭文件日志");
	FlShutdown();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObjct, PUNICODE_STRING pRegPath)
{
	pDriverObjct->DriverUnload = DriverUload;

	//文件日志最先初始化: 之后无论在哪一步卡死, Desktop日志都保留现场
	//v1.2: 默认关闭——FlInit读本驱动服务注册表键的LogEnable DWORD
	//(=1才启用; 开启方式见common.h g_flEnabled注释)。关闭时本函数
	//后续所有FlLog均为空操作, 零后台线程零文件I/O
	FlInit(pRegPath);

	//预分配阶段(PASSIVE_LEVEL): 每核VMXON/VMCS/VMM栈/MSR位图/2MB的EPT_DATA
	//绝不能推迟到DPC(DISPATCH_LEVEL)里分配, 那是此前整机卡死的根源之一
	ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
	//v3.11构建横幅(手工标签, 不用__DATE__/__TIME__——用户侧VS环境对其报
	//"未声明的标识符")。**代码每次改动必须同步改GEPT_BUILD_TAG!**
	//用途: 日志第一行自证二进制版本。旧sys(v3.8及更早)没有横幅行,
	//第一行不是本横幅=旧二进制, 停止冻结分析, 先修部署(见NOTES.md 0.5)
	FlLog("==== GeptHooks build %s | cpu数=%d ====",
		GEPT_BUILD_TAG, cpuCount);
	//v3.34: 蓝屏黑匣子锚点行——冻结时自旋看门狗(双线程钉cpu0/1, 纯rdtsc
	//计时30s行环不动)主动蓝屏0xDEADC0DE写出MEMORY.DMP, 黑匣子(事件环尾48
	//+日志行尾20+exit计数)随DMP保留; 解析器backup/tools/gept_bb_parse.ps1
	//按魔数GEPTBB01扫描(黑匣子布局未变)
	FlLog("黑匣子: BB=%p 魔数=GEPTBB01 看门狗v2(自旋+rdtsc, 30s不动)→蓝屏0xDEADC0DE→DMP",
		(PVOID)&g_flBlackBox);
	//蓝屏地址判读锚点: bugcheck 0x1E参数2若落在[base, base+size)内=驱动内代码,
	//否则(ntoskrnl等)——配合事件查看器的BugCheck参数使用
	FlLog("驱动映像: base=%p size=0x%X", pDriverObjct->DriverStart, pDriverObjct->DriverSize);
	//v3.5模块清单: DriverSection=本驱动的加载条目, 沿InLoadOrderLinks可遍历全部
	//已加载模块(含ntoskrnl/杀软过滤驱动)。下次蓝屏时用参数2对照本清单即知
	//崩溃模块——不再需要WinDbg即可离线判读
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
			EptShutdownHighMappings();   //v3.18: 共享高区页(幂等)
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
			EptShutdownHighMappings();   //v3.18: 共享高区页(幂等)
			FlShutdown();
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		FlLog("cpu%u: 预分配OK", i);
	}
	Log("预分配完成, 启动VT(串行逐核)");
	FlLog("预分配完成, 串行逐核启动VT(每步落盘, 冻结时最后一行=精确卡点)");

	//串行逐核启动(取代KeGenericCallDpc): PASSIVE级+亲和性切换到目标核
	//理由: DPC让全核同时进DISPATCH级, 期间线程不可能被调度——两次实测L26+全部
	//随冻结丢失, 是结构性观测盲区; 串行模式每步FlLog同步落盘Temp后再前进
	//v3.32换核实验: 虚拟化目标从cpu0换到最后一核(安静核)。cpu0=存储MSI/
	//DPC默认路由核(全机磁盘I/O完成依赖它), 虚拟化cpu0=观测通道+全机I/O
	//全在爆炸半径(v3.17-31零事件冻结的统一解释)。安静核上: 存活=机器层
	//全通; 冻结=T1活着(结构性脱离依赖链), [I]/[i]身份+最后事件必然落盘
#if GEPT_LAUNCH_CPU_BASE >= 0
	ULONG launchBase = GEPT_LAUNCH_CPU_BASE;
#else
	ULONG launchBase = cpuCount - 1;    //-1=最后一核(安静核)
#endif
	FlLog("v3.40启动模式: launchBase=cpu%u LIMIT=%d(0=不限制), 目标=全部%u核接管(单核KEEP已闭环, 授权全核)",
		launchBase, GEPT_LAUNCH_CPU_LIMIT, cpuCount);
	KAFFINITY allCpus = KeQueryActiveProcessors();
	for (ULONG i = 0; i < cpuCount; i++)
	{
		//v3.32: 只虚拟化[launchBase, launchBase+LIMIT)区间的核, 其余真机
		//(v3.17-31是cpu0; 换核动机见上。BASE=-1+LIMIT=1 → 仅最后一核)
		if (GEPT_LAUNCH_CPU_LIMIT != 0 &&
			(i < launchBase || i >= launchBase + GEPT_LAUNCH_CPU_LIMIT))
		{
			FlLog("cpu%u 跳过启动(换核实验: 目标=cpu%u安静核, 本核保持真机作观测/对照组)", i, launchBase);
			continue;
		}
		if (g_vcpu[i].VMXON == NULL || g_vcpu[i].VMCS == NULL)
		{
			FlLog("cpu%u 无资源, 跳过", i);
			continue;
		}
		FlLog("cpu%u: 切换亲和性, VT环境检查+启动...", i);
		KeSetSystemAffinityThread((KAFFINITY)1 << i);
		//v3.32: 记录虚拟化目标核(T1心跳pend字段+签到行读它)
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
		//v3.53 v1.0.1: junior全败汇总——零核in-guest=本驱动VT启动全败。
		//两大成因: ①Hyper-V/VBS占用(传统形态) ②**同框架宿主已在场**
		//(新形态: 我们的vmxon在宿主guest内执行→rsn27 exit→宿主伪造
		//VMfailInvalid→__vmx_on逐核返回失败=VT-x原生互斥仲裁生效,
		//零签名零共享对象零暴露面)。旧版此形态=误导性STAGE日志+空载
		//常驻; 现在: 手动释放全部资源(DriverEntry失败时I/O管理器卸载
		//映像**不调DriverUnload**, 必须在此自清)+返回失败=sc start
		//报错干净退出, 宿主零扰动(互斥协议: 后到者让位)
		if (inGuestTotal == 0)
		{
			FlLog("DriverEntry: **零核in-guest——VT启动全败**。成因: "
				"Hyper-V/VBS占用 或 同框架宿主hypervisor已在场(其仲裁者对"
				"guest内vmxon伪造VMfailInvalid)。释放全部资源后干净退出, "
				"系统不受影响, 先到宿主继续服务");
			for (ULONG i = 0; i < cpuCount; i++)
			{
				if (g_vcpu[i].bVmxOn)
				{
					//防御性: vmxon成功但未进guest的核做标准停核
					//(junior全败形态下vmxon全失败bVmxOn=0, 此分支
					//理论上空转——保险不伤)
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
			Log("v1.0.1: junior refused (VT held by host/occupied), clean exit");
			return STATUS_UNSUCCESSFUL;
		}
	}
	//放行T2的Desktop镜像: 到此驱动加载窗口期结束, 用户目录文件操作不再有死锁风险
	FlMarkEntryDone();
	return STATUS_SUCCESS;
}
