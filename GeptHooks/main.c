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
//v3.41: 0→1——v3.40全核KEEP闭环(8核inGuest+11min稳定+干净卸载)授权
#define GEPT_HOOK_STAGE 1

//构建标签(v3.44): 每次改动代码必须同步修改! 会打进日志第一行,
//用于核对测试机跑的是不是本次编译的二进制(见DriverEntry横幅)
//v3.42: hook页隔离; b: ml64拒绝段内align 1000h, 改SEGMENT ALIGN(4096)段
//v3.43: 0x1E蓝屏根因修复——hook跳板sub rsp,20h违反x64 ABI(→28h),
//KiSwapContext movaps #GP两连蓝屏终结; STAGE1全链路实测打通
//v3.44: **卸载0x50蓝屏根因修复**——v3.43卸载中段蓝屏0x50@(用户VA,3,
//nt+0x2044BE,0xF): p4=0xF=NONPAGED_BUGCHECK_USER_VA_ACCESS_INCONSISTENT
//(微软文档: "内核态在不允许时访问用户VA")。nt反汇编: nt+0x2044BE=LPC/
//等待结果回写函数(状态码0x101/0x102/0xC0/0x80+32B条目), 调用者紧邻
//LpcRequestPort。DMP v6.2裁决: 行环到L861"cpu5: 已退出guest"(cpu5的
//vmcall退出本身成功, 排除退出路径), 崩在FlLog等T1的500ms睡眠窗内,
//受害者=另一线程(services.exe的LPC等待完成回写)。根因=vmx_off回真机
//不恢复CR3: VM-exit硬件加载HOST_CR3(System进程DTB, launch时快照),
//vmresume会恢复GUEST_CR3但vmx_off路径没有vmresume——卸载线程带着
//System页表跑(内核半区共享=看似正常), FlLog睡眠让出CPU后同进程线程
//切换不重载CR3, 下一个services.exe线程的系统调用写用户缓冲→用户VA
//在System页表下零映射→#PF→MmAccessFault判0xF→蓝屏。
//修复: 三处vmx_off路径(rcx==1卸载/逃生/rcx==3探针)vmread GUEST_CR3
//后立即__writecr3恢复触发线程自己的地址空间
#define GEPT_BUILD_TAG "v3.44"

//v3.33: 构建标签全局副本——黑匣子(common.h GEPT_BLACKBOX)在FlInit时
//拷入, 蓝屏DMP解析时自证二进制版本
CHAR g_geptBuildTag[24] = GEPT_BUILD_TAG;

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
	//v3.41: 成功证据走文件日志(测试链路=上传日志, DbgView非必开)。
	//这一行=EPT hook全链路自证: 原页执行violation→双视图切CodePage
	//→跳板AsmHookTestTarget→本函数→重放5条mov→jmp回原函数+15
	FlLog("[STAGE1] GeptTestTarget hooked! EPT hook全链路OK(violation→CodePage视图→跳板→重放→归位)");
	Log("GeptTestTarget hooked! EPT hook chain OK");
}

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
	FlLog("Unload: 开始关闭VT(串行逐核)");
	ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
	KAFFINITY allCpus = KeQueryActiveProcessors();
	//串行逐核退出VT(取代DPC): 成功进入guest的核vmcall退出, 仅vmxon的核直接vmx_off
	//每步落盘: 卸载卡死时Temp最后一行=卡在哪一核哪一步
	for (ULONG i = 0; i < cpuCount; i++)
	{
		if (!(g_vcpu[i].bInGuest || g_vcpu[i].bVmxOn))
		{
			continue;
		}
		KeSetSystemAffinityThread((KAFFINITY)1 << i);
		VmxStopCpu();
		KeSetSystemAffinityThread(allCpus);
	}
	FlLog("Unload: VT已关闭, 释放资源");
	//PASSIVE_LEVEL释放全部资源(含EPT_DATA与动态页表)
	for (ULONG i = 0; i < cpuCount; i++)
	{
		VmxFreeCpuResources(i);
	}
	//v3.18: 释放共享高区页表(8核EPT共用的511个pdpt, 幂等)
	EptShutdownHighMappings();
	FlLog("Unload: 完成, 关闭文件日志");
	FlShutdown();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObjct, PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pRegPath);
	pDriverObjct->DriverUnload = DriverUload;

	//文件日志最先初始化: 之后无论在哪一步卡死, Desktop日志都保留现场
	FlInit();

	//预分配阶段(PASSIVE_LEVEL): 每核VMXON/VMCS/VMM栈/MSR位图/2MB的EPT_DATA
	//绝不能推迟到DPC(DISPATCH_LEVEL)里分配, 那是此前整机卡死的根源之一
	ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
	//v3.11构建横幅(手工标签, 不用__DATE__/__TIME__——用户侧VS环境对其报
	//"未声明的标识符")。**代码每次改动必须同步改GEPT_BUILD_TAG!**
	//用途: 日志第一行自证二进制版本。旧sys(v3.8及更早)没有横幅行,
	//第一行不是本横幅=旧二进制, 停止冻结分析, 先修部署(见NOTES.md 0.5)
	FlLog("==== GeptHooks build %s | stage=%d cpu数=%d ====",
		GEPT_BUILD_TAG, GEPT_HOOK_STAGE, cpuCount);
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
	for (ULONG i = 0; i < cpuCount; i++)
	{
		FlLog("cpu%d inGuest=%d launchFailed=%d vmxon=%d",
			i, g_vcpu[i].bInGuest, g_vcpu[i].bLaunchFailed, g_vcpu[i].bVmxOn);
	}

#if GEPT_HOOK_STAGE == 0
	Log("stage0: virtualization only, no hook installed");
	FlLog("stage0: DriverEntry完成(v3.35=三重故障park化+看门狗观测t1Seq: TF→park机器存活日志落盘; 仍冻→30s→蓝屏→DMP), 心跳监控中(250ms一条)");
#if !GEPT_PROBE_EXIT
	//v3.19: 接管模式non-root存活签到——主线程(此刻运行于cpu0的guest里)
	//以500ms间隔睡眠/唤醒/FlLog共8轮(4秒), 每条签到行都是"non-root下
	//线程睡眠(时钟中断经注入唤醒)+环写入+T1协作"全链路的活体证明。
	//冻结若发生, 最后一条签到行的时间戳把冻结窗口切成500ms粒度;
	//8条全出后DriverEntry返回, 主线程继续活在EPT之下直至sc stop
	{
		//v3.25: 签到间隔500ms→100ms×20轮(2秒)——接管初期死亡窗口切到
		//100ms粒度; 每条签到都是"guest睡眠(时钟中断经注入唤醒)+环写入
		//+T1 write-through落盘"全链路的活体证明
		LARGE_INTEGER tick;
		tick.QuadPart = -1000000LL;    //100毫秒
		//v3.23: 签到行带cpu0.g(bInGuest)实况——v3.22实测'G'逃生后f:1但签到
		//仍打印"主线程在EPT之下"=标签失真(实际在真机); 此后按实况标注
		for (ULONG t = 1; t <= 20; t++)
		{
			//v3.32: 读虚拟化目标核实况(换核后不再是硬编码cpu0)
			LONG vc = g_geptVcpuCpu;
			KeDelayExecutionThread(KernelMode, FALSE, &tick);
			FlLog("[存活签到] t=%u×100ms cpu%d.g=%d (主线程%s: 睡眠+唤醒+日志全链路OK)",
				t, (int)vc, (vc >= 0) ? g_vcpu[vc].bInGuest : 0,
				((vc >= 0) && g_vcpu[vc].bInGuest) ? "在EPT之下" : "已回真机(逃生/失败后)");
		}
		FlLog("[存活签到] 签到完成(2秒), DriverEntry即将返回(此后主线程按上述状态持续运行)");
		//v3.25: 签到阶段结束, 熄灭T1热轮询(15秒看门狗兜底, 此处主动清)
		g_flLaunchHot = 0;
	}
#endif
#elif GEPT_HOOK_STAGE == 1
	//自测: 目标函数与跳板都在hook.asm, 前15字节指令布局完全已知
	//v3.42: 页隔离验证——被hook页只允许GeptTestTarget自己(v3.41实测教训:
	//目标曾与CmVmCall/common-asm机器码同页, DPC的vmcall返回路径自己卷进
	//双视图切换→蓝屏0x1E@nt)。同页=拒绝安装(防止链接器布局回归)
	if (PAGE_ALIGN(GeptTestTarget) == PAGE_ALIGN(AsmHookTestTarget) ||
		PAGE_ALIGN(GeptTestTarget) == PAGE_ALIGN(CmVmCall))
	{
		FlLog("[STAGE1] **页隔离FAIL**: 目标页=%p 跳板=%p CmVmCall=%p ——被hook页含其他机器码, 拒绝安装(检查hook.asm的GEPTTGT独立段)",
			PAGE_ALIGN(GeptTestTarget), PAGE_ALIGN(AsmHookTestTarget), PAGE_ALIGN(CmVmCall));
		FlMarkEntryDone();
		return STATUS_UNSUCCESSFUL;
	}
	g_jmp_testtarget = (ULONG64)GeptTestTarget + PHGetHookLen((ULONG64)GeptTestTarget, sizeof(JMP_OPCODE64), TRUE);
	FlLog("[STAGE1] 安装hook: 目标=%p(独立页%p) 跳板=%p(页%p) 跳回=%llx (8核已KEEP, DPC逐核EptSetHook)",
		GeptTestTarget, PAGE_ALIGN(GeptTestTarget), AsmHookTestTarget,
		PAGE_ALIGN(AsmHookTestTarget), (unsigned long long)g_jmp_testtarget);
	PHHook(GeptTestTarget, AsmHookTestTarget);
	//触发一次: 日志出现"[STAGE1] GeptTestTarget hooked!"且系统不死机
	//=EPT Hook全链路打通(violation→双视图→跳板→重放→归位)
	//v3.43: 触发前锚点——蓝屏窗口的最后一锚。本行之后死=死亡点在
	//[取指hook页→violation→EptExitHandler→'x'切视图→vmresume→
	// CodePage跳板→AsmHookTestTarget→HookTestTarget]链路内, DMP环的
	//'V'/'x'序列可直接二分定位到具体指令段
	FlLog("[STAGE1] 触发GeptTestTarget(下一行=hook命中或死亡点)");
	GeptTestTarget();
	FlLog("[STAGE1] 自测调用返回(未死机未蓝屏), EPT hook全链路打通");
	Log("stage1: self-test hook done");
#else
	//NtClose: +19及hook.asm重放的prologue绑定特定Windows版本,
	//换系统前必须先反汇编本机NtClose确认一致, 否则会跳进指令中间导致卡死/蓝屏
	g_jmp_ntclose = (ULONG64)NtClose + PHGetHookLen((ULONG64)NtClose, sizeof(JMP_OPCODE64), TRUE);
	PHHook(NtClose, AsmHookNtClose);
	Log("stage2: NtClose hook installed");
#endif
	//放行T2的Desktop镜像: 到此驱动加载窗口期结束, 用户目录文件操作不再有死锁风险
	FlMarkEntryDone();
	return STATUS_SUCCESS;
}
