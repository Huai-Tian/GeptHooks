#include"common.h"
#include"CPU.h"
#include"VMX.h"
#include<ntstrsafe.h>
BOOLEAN CommCheckBios()
{
	ULONG64 bios = __readmsr(MSR_IA32_FEATURE_CONTROL);
	ULONG64 result = bios & 5;
	if (result == 5)
	{
		return TRUE;
	}
	return FALSE;
}

BOOLEAN CommCheckCpuid()
{
	int cpuinfo[4] = { 0 };
	__cpuidex(cpuinfo, 1, 0);
	return (cpuinfo[2] >> 5) & 1;
}

BOOLEAN CommCheckCr4()
{
	ULONG64 cr4 = __readcr4();
	cr4 = cr4 >> 13;
	if ((cr4 & 1) == 0)
	{
		return TRUE;
	}
	return FALSE;
}
//CommVtStart/CommVtShutDown(DPC包装)已删除: KeGenericCallDpc让全核同时进入
//DISPATCH级DPC, 期间任何线程(含文件日志线程)都不可能被调度——v3两次实测
//L26+全部丢失即此盲区。改为main.c串行逐核(亲和性切换)调用VMXInitCpuStart/
//VmxStopCpu, 每步FlLog同步落盘Temp。

//==================== 冻结存活文件日志 v3 ====================
//v2实测铁证: Temp文件有第3行而Desktop没有 -> 执行流在FlLog里写完Temp后
//卡死在Desktop的ZwWriteFile(驱动加载窗口期, 杀软/过滤驱动扣住用户目录写请求
//形成循环等待) -> DriverEntry挂死(sc start无输出) + 心跳线程等mutex挂死(无[HB])。
//v3铁律: **DriverEntry/DriverUnload调用路径上零文件I/O**。
//  FlLog: 只格式化并入行环(无锁) + 踢事件唤醒写线程
//  T1后台线程: 打开Temp(系统目录,加载窗口期实测可写), 排空二进制环+行环,
//             1秒[HB]心跳; 它是权威副本
//  T2后台线程: 等DriverEntry完成(FlMarkEntryDone)后才打开Desktop文件做镜像,
//             即使T2被过滤驱动卡死也不影响T1/DriverEntry/系统其余部分
//v3.1修订(两次实测L25停+无心跳后): DPC期间全核DISPATCH级, 线程不可能被调度,
//L26+被困在环形缓冲里随冻结丢失——结构性盲区。改为main.c串行逐核启动。
//v3.2修订(v3.1实测"仅L1+sc start挂起+系统活着"): DriverEntry上下文直接
//ZwWriteFile在加载窗口期不可靠(v2的Desktop铁证同理, v3.1误以为Temp免疫;
//实测L1碰巧成功后L2与T1首写双双挂起)。修订:
//  **文件写只发生在T1线程上下文**(v3实测T1写到L25, 可靠);
//  FlLog入环后轮询等待T1把该行落盘(10ms*50, 上限500ms)——保留
//  "先落盘再前进"的观测性, DriverEntry自己不写一个字节;
//  Temp文件打开也移回T1(ZwCreateFile同有加载窗口期风险)
#define GEPT_LOG_PATH1 L"\\??\\C:\\Users\\User\\Desktop\\gept_log.txt"
#define GEPT_LOG_PATH2 L"\\??\\C:\\Windows\\Temp\\gept_log.txt"

static HANDLE g_flFileTemp = NULL;        //Temp句柄(仅T1触碰; T1退出后FlShutdown收尾)
static HANDLE g_flFileDesktop = NULL;     //仅T2线程触碰
static PVOID g_flThreadT1 = NULL;
static PVOID g_flThreadT2 = NULL;
static KEVENT g_flKickT1;                 //自动复位: 有新行/新事件立即唤醒T1
static KEVENT g_flKickT2;                 //自动复位: 有新行立即唤醒T2
static volatile LONG g_flStop = 0;        //停止标记(FlShutdown置1)
static volatile BOOLEAN g_flEntryDone = FALSE; //DriverEntry完成标记(放行T2)
static volatile LONG g_flRingHead = 0;    //二进制事件环单调序号
static volatile LONG g_flBinFlushed = 0;  //T1已排空的二进制环游标
static volatile LONG g_flLineHead = 0;    //行环单调序号
static volatile LONG g_flT1Seq = 0;       //Temp已写行游标(仅T1推进, FlLog轮询读; volatile防编译器把读取提出循环)
static LONG g_flT2Seq = 0;                //T2(Desktop)已写行游标(仅T2触碰)
static volatile LONG g_flWriteFailsT1 = 0;
static volatile LONG g_flWriteFailsT2 = 0;
static volatile LONG g_flT1Lag = 0;     //v3.5: FlLog等待T1落盘超时(500ms)累计次数
volatile LONG g_flLaunchHot = 0;        //v3.19: launch热轮询回归(见common.h)
volatile LONG g_flWriteGuard = 0;       //v3.28: 探针窗口写盘护卫(见common.h)
//v3.29: 护卫武装时刻(T1侧, 100ns单位)——置位时由T1记下, 超100ms未清
//=guest已挂死(probe窗口最多~15ms), T1强制解除并补写(修v3.28观测盲区:
//护卫解除依赖probe返回, guest挂死则T1活着也永远不写盘)
volatile LONG64 g_flWriteGuardTsc = 0;
//v3.32: 当前虚拟化目标核(-1=未启动, main.c启动前置位)。T1心跳pend字段
//与main.c签到行读它——换核实验后目标不再是硬编码的cpu0
volatile LONG g_geptVcpuCpu = -1;
//v3.35: 三重故障park核位掩码(bit i=cpu i已park)——main.c卸载守卫读它
//(park核的VMM栈/代码页仍被占用, 驱动绝不能卸载)
volatile LONG g_geptParkedMask = 0;
volatile LONG64 g_flExitCounts[GEPT_EXIT_REASON_MAX] = { 0 };

//v1.2: 日志系统总开关(默认0=关闭)——FlInit读服务注册表键的LogEnable
//DWORD(=1开启); 关闭时T1/T2/看门狗线程全部不创建, 全部Fl*接口为
//空操作=零后台线程零文件I/O零观测面(框架交付形态的隐蔽性基线)
volatile LONG g_flEnabled = 0;

//===== v3.33/v3.34: 蓝屏黑匣子 + 自旋看门狗 =====
//(设计动机与v3.33 DPC版失败判读见common.h GEPT_BLACKBOX注释)
static GEPT_RING_ENTRY g_flRing[GEPT_RING_SIZE];   //BSS: 非分页自动清零
static GEPT_LINE_ENTRY g_flLines[GEPT_LINE_RING_SIZE];
GEPT_BLACKBOX g_flBlackBox;                    //BSS自动清零(非分页)
static volatile LONG64 g_flWdArmed = 0;        //0=解除武装, 否则=武装时刻(100ns)
static volatile LONG  s_flWdFired = 0;         //v3.34: 防双路同时快照的竞态
static PVOID g_flWdThread[2] = { NULL, NULL }; //v3.34: 看门狗线程对象(卸载等待)
//v3.34: TSC频率(标定值, 默认2GHz)——看门狗计时免疫中断时钟冻结
volatile LONG64 g_flWdTscPerSec = 2000000000LL;
typedef struct _GEPT_WD_TRACK {                //每个看门狗线程私有(无锁)
	LONG64 lastLine;
	LONG64 lastProgress;
} GEPT_WD_TRACK;

VOID FlWdArm(VOID)
{
	//T1不存在则不武装: 无心跳源=看门狗必然误触发(健康机器被蓝屏)
	if (g_flThreadT1 == NULL)
	{
		return;
	}
	g_flWdArmed = KeQueryUnbiasedInterruptTime();
}

VOID FlWdDisarm(VOID)
{
	g_flWdArmed = 0;
}

//触发: 快照黑匣子+主动蓝屏。看门狗线程上下文(PASSIVE)或v3.33遗留语境,
//无锁无等待——机器此刻已级联冻结, 常规路径全死, 但crash dump栈是专用
//低层路径(接管磁盘写DMP, 专为死锁设计), 黑匣子必然随MEMORY.DMP落盘
static VOID FlWdFire(ULONG trk)
{
	//v3.34: 双路看门狗可能几乎同时检测到stall——只让第一路快照
	//(第二路进入=黑匣子正在被写, 自旋等待bugcheck接管即可)
	if (InterlockedCompareExchange(&s_flWdFired, 1, 0) != 0)
	{
		for (;;)
		{
			YieldProcessor();
		}
	}
	PGEPT_BLACKBOX bb = &g_flBlackBox;
	LONG rh = g_flRingHead;
	LONG lh = g_flLineHead;
	bb->fireTsc = __rdtsc();
	bb->fireIntrTime = KeQueryUnbiasedInterruptTime();
	bb->wdArmed = g_flWdArmed;
	bb->lineHead = lh;
	bb->ringHead = rh;
	bb->t1Seq = g_flT1Seq;
	bb->t2Seq = g_flT2Seq;
	bb->writeGuard = g_flWriteGuard;
	bb->launchHot = g_flLaunchHot;
	bb->vcpuCpu = g_geptVcpuCpu;
	bb->pendCount = (g_geptVcpuCpu >= 0)
		? (ULONG64)g_vcpu[g_geptVcpuCpu].PendingIntrCount : (ULONG64)-1;
	for (ULONG r = 0; r < GEPT_EXIT_REASON_MAX; r++)
	{
		bb->exitCounts[r] = g_flExitCounts[r];
	}
	//事件环尾48条: 原样拷贝, seq字段供解析器校验有效性
	for (LONG k = 0; k < 48; k++)
	{
		LONG idx = rh - 48 + k;
		if (idx < 0)
		{
			RtlZeroMemory(&bb->ring[k], sizeof(GEPT_RING_ENTRY));
			continue;
		}
		bb->ring[k] = g_flRing[idx & (GEPT_RING_SIZE - 1)];
	}
	//行环尾20条: seq匹配才算有效(防半写撕裂)
	for (LONG k = 0; k < 20; k++)
	{
		LONG idx = lh - 20 + k;
		if (idx < 0)
		{
			bb->lines[k][0] = 0;
			continue;
		}
		PGEPT_LINE_ENTRY e = &g_flLines[idx & (GEPT_LINE_RING_SIZE - 1)];
		if (e->seq == (ULONG)idx)
		{
			RtlStringCbCopyA(bb->lines[k], 256, e->text);
		}
		else
		{
			bb->lines[k][0] = 0;
		}
	}
	//参数1=黑匣子VA(DMP可直接定位), 参数2="GEPTBB01"魔数(事件查看器可读)
	KeBugCheckEx(0xDEADC0DE, (ULONG64)(ULONG_PTR)&g_flBlackBox,
		0x3130304242504547ULL, (ULONG64)lh, (ULONG64)trk);
}

//v3.34: 自旋看门狗线程(替代v3.33的DPC计时器版——实测180s不开火,
//根因=定时器到期与KeQueryUnbiasedInterruptTime都依赖"级联中会冻结"
//的共享中断时钟)。本线程纯rdtsc计时+纯自旋: 不睡眠(睡眠要时钟)、
//不依赖定时器/时钟/调度——只要本核还能执行指令, 检测就活着。
//两路独立: W0钉cpu0, W1钉cpu1(v3.32+虚拟化目标=最后一核cpu7,
//cpu0/1都是真机核; 若未来改回虚拟化cpu0, W0在guest内自旋——
//EPT对自旋透明, 仍能开火)
static VOID FlWdThreadProc(PVOID Context)
{
	ULONG idx = (ULONG)(ULONG_PTR)Context;
	//钉核(此处Context只有0/1两值, 见FlInit创建处)
	KeSetSystemAffinityThread((KAFFINITY)1 << (idx == 0 ? 0 : 1));
	//W0负责TSC频率标定: 驱动加载期(武装前)时钟健康, "1s睡眠前后
	//rdtsc差"即真实频率; 范围合理性校验(0.1G-20G)防怪值
	if (idx == 0)
	{
		ULONG64 t0 = __rdtsc();
		ULONG64 it0 = KeQueryUnbiasedInterruptTime();
		LARGE_INTEGER one;
		one.QuadPart = -10000000LL;    //1秒
		KeDelayExecutionThread(KernelMode, FALSE, &one);
		ULONG64 t1 = __rdtsc();
		ULONG64 it1 = KeQueryUnbiasedInterruptTime();
		if (it1 > it0)
		{
			LONG64 f = (LONG64)((t1 - t0) * 10000000ULL / (it1 - it0));
			if (f > 100000000LL && f < 20000000000LL)
			{
				InterlockedExchange64(&g_flWdTscPerSec, f);
			}
		}
	}
	GEPT_WD_TRACK tr;
	//v3.35: 观测对象lineHead→**t1Seq**(T1已写盘游标)——v3.34判读修正:
	//看门狗lineHead版可能永远见不到stall: T1"循环活着但阻塞在
	//ZwWriteFile内"时循环停转(其实那时lineHead也冻结)——真正的盲区是
	//护卫窗: 护卫=1期间T1按设计不写盘, 若guest死在护卫窗内且护卫自解除
	//后T1首次写盘即永久阻塞, lineHead冻结在最后一条[fl]行, 看门狗**应该**
	//开火而实测没开火=cpu0/1的W线程也被级联冻结(不再调度PASSIVE线程)。
	//t1Seq只在ZwWriteFile真正完成后推进: T1死/T1写阻塞/护卫窗(≤1s)全部
	//覆盖; 健康时T1每250ms写一批HB行, 30s阈值=120批的裕量
	tr.lastLine = g_flT1Seq;
	tr.lastProgress = __rdtsc();
	ULONG64 lastPoll = tr.lastProgress;
	while (g_flStop == 0)
	{
		ULONG64 now = __rdtsc();
		//活体证明: ~10Hz推进pollCnt(黑匣子里可判看门狗是否还在跑)
		if (now - lastPoll >= (ULONG64)g_flWdTscPerSec / 10ULL)
		{
			lastPoll = now;
			InterlockedIncrement64((volatile LONG64*)&g_flBlackBox.pollCnt);
		}
		if (g_flWdArmed == 0)
		{
			//未武装: 只跟踪, 不判定
			tr.lastLine = g_flT1Seq;
			tr.lastProgress = now;
		}
		else if (g_flT1Seq != (LONG)tr.lastLine)
		{
			//写盘在推进=存储链路活着, 重置stall计时
			tr.lastLine = g_flT1Seq;
			tr.lastProgress = now;
		}
		else if (now - tr.lastProgress >= (ULONG64)g_flWdTscPerSec * 30ULL)
		{
			//30s写盘零推进(健康时每250ms一批)=T1死/写阻塞=级联冻结
			//→蓝屏黑匣子(30s裕量: 探针窗~100ms+检查点500ms+护卫1s远不及)
			FlWdFire(idx);    //noreturn
		}
		YieldProcessor();
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}

static HANDLE FlOpenOneFile(PCWSTR path);   //前置声明(定义在线程函数之后)
static VOID FlDrainTempLocked(VOID);        //前置声明: T1(或T1退出后的FlShutdown)把行环推进Temp

//任意IRQL(含VM-exit): 无锁写环形缓冲, seq最后写作为提交标记
VOID FlRingPush(CHAR tag, ULONG cpu, ULONG reason, ULONG64 a, ULONG64 b, ULONG64 c)
{
	if (!g_flEnabled)
	{
		return;    //v1.2: 日志关闭=零观测面(VM-exit热路径仅此一次判断)
	}
	LONG idx = InterlockedIncrement(&g_flRingHead) - 1;
	PGEPT_RING_ENTRY e = &g_flRing[idx & (GEPT_RING_SIZE - 1)];
	e->a = a;
	e->b = b;
	e->c = c;
	e->tsc = __rdtsc();
	e->reason = reason;
	e->cpu = (USHORT)cpu;
	e->tag = tag;
	MemoryBarrier();      //防止编译器把字段store重排到seq之后
	e->seq = (ULONG)idx;
	//v3.8: 移除KeSetEvent——FlRingPush会被VM-exit上下文(VmxExitStormEscape/
	//EptExitHandler)调用, 而VM-exit时RFLAGS=0x2(IF=0)且被中断的guest上下文
	//可能持有任意调度器锁; KeSetEvent->KiReadyThread要拿调度器/线程锁,
	//与被中断上下文同核递归=永久自旋(锁级联冻结的候选机理, v3.7残留隐患)。
	//事件延迟由T1的50ms超时轮询兜底(冻结前最后快照<=50ms, v3.13从250ms压缩)。
}

//VM-exit统一采样: 所有reason计数; 高频exit只采样前N条入环
//(计数器仍精确——HB行显示全部流量)
VOID FlRingExit(ULONG cpu, ULONG reason, ULONG64 rip, ULONG64 qual)
{
	if (reason < GEPT_EXIT_REASON_MAX)
	{
		InterlockedIncrement64(&g_flExitCounts[reason]);
	}
	if (reason == EXIT_REASON_CPUID &&
		g_flExitCounts[EXIT_REASON_CPUID] > 16)
	{
		return;    //CPUID采样上限: 复用exit计数, 避免额外状态变量
	}
	//v3.20: vmcall环采样上限64——探针持续执行压测循环(5万次vmcall)会把
	//环刷爆(1024条), [W][F][L][X]等关键标记会被'E'挤出去。计数仍精确
	//(HB的r18=循环进度), 循环节奏由handler采样的'L'事件携带
	if (reason == EXIT_REASON_VMCALL &&
		g_flExitCounts[EXIT_REASON_VMCALL] > 64)
	{
		return;
	}
	//v3.19: ext-int exiting开启后reason 1高频(时钟1000Hz+设备)——
	//环采样限前32条, 否则[W][F][K]等关键标记被中断事件刷出环;
	//HB的r1计数仍精确反映中断流量(判读"冻结前中断是否异常涌入"的依据)
	if (reason == EXIT_REASON_EXTERNAL_INTERRUPT &&
		g_flExitCounts[EXIT_REASON_EXTERNAL_INTERRUPT] > 32)
	{
		return;
	}
	//v3.23: interrupt-window模式的开窗排空会把reason 7成串打出(每条积压
	//中断一个exit)——同样限前32条, 防止排空把[F][W][Y]等关键标记挤出环;
	//HB的r7计数仍精确=开窗投递总量
	if (reason == EXIT_REASON_PENDING_INTERRUPT &&
		g_flExitCounts[EXIT_REASON_PENDING_INTERRUPT] > 32)
	{
		return;
	}
	//v3.25: 已模拟的must-1指令exit(16 RDTSC/14 INVLPG/12 HLT/36 MWAIT)
	//在OS接管后是持续高频(RDTSC~1M/s)——环采样各限32条防刷爆;
	//HB的r12/r14/r16/r36计数仍精确=各指令真实流量
	if ((reason == 16 || reason == 14 || reason == 12 || reason == 36) &&
		g_flExitCounts[reason] > 32)
	{
		return;
	}
	FlRingPush('E', cpu, reason, rip, qual, 0);
}

//入环一行(已格式化): 无锁, 行号=入环序号(两文件编号一致)
static LONG FlEnqueueLine(const char* text)
{
	LONG idx = InterlockedIncrement(&g_flLineHead) - 1;
	PGEPT_LINE_ENTRY e = &g_flLines[idx & (GEPT_LINE_RING_SIZE - 1)];
	RtlStringCbCopyA(e->text, GEPT_LINE_TEXT, text);   //超长截断
	MemoryBarrier();      //防止store重排到seq之后
	e->seq = (ULONG)idx;
	KeSetEvent(&g_flKickT1, IO_NO_INCREMENT, FALSE);   //立即唤醒写线程
	KeSetEvent(&g_flKickT2, IO_NO_INCREMENT, FALSE);
	return idx;
}

//T1线程(或T1退出后的FlShutdown): 把行环新行推进Temp文件
//单写者模型无需锁; g_flT1Seq推进后, 等待中的FlLog(轮询)即被放行
//v3.16: 写盘合并+flush限流。v3.14/v3.15间歇性蓝屏(PAGE_FAULT_IN_NONPAGED_AREA,
//win32kfull.sys/本次cpu5窗口)的头号嫌疑=过滤驱动路径上的I/O压力:
//本机装着火绒(sysdiag.sys+hrwfpdrv.sys)+雷电模拟器(LdV*.sys), 日志文件
//是FILE_WRITE_THROUGH——旧实现**每行一次ZwWriteFile**=DriverEntry的800行
//突发=800次穿透整个过滤栈的同步写IRP, 与v3.4时代"密集write-through崩溃"
//同构(v3.4加20ms限速后消失; v3.14起系统活得够久+循环测试让它复发)。
//v3.16: ①合并缓冲4KB, 一批一次ZwWriteFile(IRP数量降一个数量级)
//       ②强flush固定250ms最多一次(冻结/蓝屏至多丢250ms尾部, 可接受)
static ULONG64 s_flLastFlushT = 0;
static VOID FlDrainTempLocked(VOID)
{
	char buf[4096];
	IO_STATUS_BLOCK iosb = { 0 };
	LONG head = g_flLineHead;
	LONG c = g_flT1Seq;
	ULONG used = 0;
	BOOLEAN wrote = FALSE;
	if (g_flFileTemp == NULL)
	{
		g_flT1Seq = head;    //Temp不可用: 只推进游标(Desktop镜像由T2负责)
		return;
	}
	if (head - c > GEPT_LINE_RING_SIZE)
	{
		RtlStringCbPrintfA(buf, sizeof(buf),
			"...行环溢出%d条, 从最新处继续...\r\n",
			head - c - GEPT_LINE_RING_SIZE);
		used = (ULONG)strlen(buf);
		ZwWriteFile(g_flFileTemp, NULL, NULL, NULL, &iosb,
			buf, used, NULL, NULL);
		used = 0;
		c = head - GEPT_LINE_RING_SIZE;
		wrote = TRUE;
	}
	for (; c < head; c++)
	{
		PGEPT_LINE_ENTRY e = &g_flLines[c & (GEPT_LINE_RING_SIZE - 1)];
		if (e->seq != (ULONG)c)
		{
			continue;    //半写, 跳过
		}
		RtlStringCbPrintfA(buf + used, sizeof(buf) - used,
			"L%05u %s\r\n", c + 1, e->text);
		used += (ULONG)strlen(buf + used);
		if (used >= sizeof(buf) - (GEPT_LINE_TEXT + 32))
		{
			//缓冲将满(放不下下一行): 先写出这批
			if (!NT_SUCCESS(ZwWriteFile(g_flFileTemp, NULL, NULL, NULL, &iosb,
				buf, used, NULL, NULL)))
			{
				g_flWriteFailsT1++;
			}
			used = 0;
			wrote = TRUE;
		}
	}
	if (used > 0)
	{
		if (!NT_SUCCESS(ZwWriteFile(g_flFileTemp, NULL, NULL, NULL, &iosb,
			buf, used, NULL, NULL)))
		{
			g_flWriteFailsT1++;
		}
		wrote = TRUE;
	}
	g_flT1Seq = head;
	//v3.4强刷的本意: 蓝屏丢缓存页(v3.2实测崩溃前1-2秒日志蒸发)。
	//v3.16改为250ms最多一次: 崩溃至多丢250ms尾部, 换取过滤栈压力大幅下降
	if (wrote)
	{
		ULONG64 nowT = KeQueryUnbiasedInterruptTime();
		if (nowT - s_flLastFlushT >= 2500000LL)
		{
			ZwFlushBuffersFile(g_flFileTemp, &iosb);
			s_flLastFlushT = nowT;
		}
	}
}

//仅PASSIVE_LEVEL: 里程碑日志入行环后**等待T1落盘**(10ms轮询, 上限500ms)。
//文件写只发生在T1线程(v3实测可靠到L25); DriverEntry上下文不写文件
//(v3.1实测: 加载窗口期DriverEntry直接ZwWriteFile=L2挂起+T1首写挂起=双死锁)。
//T1异常时500ms超时放行(观测性降级但加载流程不死)
VOID FlLog(const char* fmt, ...)
{
	char buf[512];
	va_list args;
	LARGE_INTEGER tick;
	if (!g_flEnabled || KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		return;    //v1.2: 日志未开启=空操作
	}
	va_start(args, fmt);
	RtlStringCbVPrintfA(buf, sizeof(buf), fmt, args);
	va_end(args);
	LONG idx = FlEnqueueLine(buf);
	tick.QuadPart = -100000LL;    //10ms
	int w = 0;
	for (; w < 50 && g_flT1Seq <= idx; w++)
	{
		KeDelayExecutionThread(KernelMode, FALSE, &tick);
	}
	if (g_flT1Seq <= idx)
	{
		//T1未能在500ms内落盘此行: 文件最后一行之后的内容不可信(可能在环里没写出)
		InterlockedIncrement(&g_flT1Lag);
	}
}

//v3.31: 自旋等待版FlLog(仅PASSIVE_LEVEL, IF=0下安全——FlLog的10ms睡眠
//依赖时钟中断, IF=0的guest核上会永久睡死)。用途: KEEP检查点——sti交付
//中断(EPT下首个ISR执行=冻结风险点)之前, 强制T1把探针事件+中断队列身份
//全部落盘。自旋用rdtsc限界(500ms), 不依赖任何中断维护的时钟源;
//T1在真机核(cpu1-7)上写盘, 存储此刻健康(vmnt冻结尚未发生)
VOID FlLogSpin(const char* fmt, ...)
{
	char buf[512];
	va_list args;
	//v1.1c: IRQL门从"仅PASSIVE"放宽到"≤DISPATCH"——自旋等待(YieldProcessor,
	//不睡眠不阻塞)在DISPATCH级完全合法, T1在其他核PASSIVE落盘照常; v1.1c
	//卸载路径全程DISPATCH_LEVEL(VmxStopCpu的日志全走本函数=同核无线程
	//切换+日志仍同步落盘, 两全)。原PASSIVE门是v3.25"KEEP检查点IF=0"时代
	//的保守限制, 并非自旋本身限制
	if (!g_flEnabled || KeGetCurrentIrql() > DISPATCH_LEVEL)
	{
		return;    //v1.2: 日志未开启=空操作
	}
	va_start(args, fmt);
	RtlStringCbVPrintfA(buf, sizeof(buf), fmt, args);
	va_end(args);
	LONG idx = FlEnqueueLine(buf);
	UINT64 t0 = __rdtsc();
	//~2GHz×0.5s≈1e9 tick; 超时放行(观测性降级但流程不死), lag留痕
	while (g_flT1Seq <= idx)
	{
		if (__rdtsc() - t0 > 1000000000ULL)
		{
			InterlockedIncrement(&g_flT1Lag);
			break;
		}
		YieldProcessor();
	}
}

//v3.22: launch观测预热(仅PASSIVE_LEVEL, VmxSetupVmcs在vmlaunch前调用;
//v3.25起launch全程IF=1, 无_disable前提)。
//v3.19热轮询有两重失效——四次冻结(v3.17/18/19/21)零[F][W][L]落盘的结构性根因:
//  ①g_flLaunchHot置1时T1正睡在250ms超时等待里, 而FlRingPush不踢事件
//    (v3.8裁决: VM-exit上下文禁KeSetEvent), T1根本不知道要进热模式;
//    探针的[W][L]事件只进二进制环, T1睡到冻结发生都不会醒
//  ②即使T1醒来看到hot=1, 循环头等待timeout恒250ms(v3.22已改hotWait修复)
//本函数修复①: 置hot+踢T1+睡5ms——此刻主线程IF=1(PASSIVE级), 延时可被
//时钟唤醒, T1得以立即醒来看到hot=1进入1ms热节奏, 之后的launch窗口
//(vmlaunch+探针循环+接管初期)全程毫秒级落盘。冻结时最后落盘的[L]的
//a值/最后[HB]的r18计数=精确死亡迭代号
VOID FlArmLaunchWatch(VOID)
{
	if (!g_flEnabled)
	{
		return;    //v1.2: 日志未开启=空操作(不触碰事件对象/不睡眠)
	}
	g_flLaunchHot = 1;
	KeSetEvent(&g_flKickT1, IO_NO_INCREMENT, FALSE);
	LARGE_INTEGER warm;
	warm.QuadPart = -50000LL;    //5ms
	KeDelayExecutionThread(KernelMode, FALSE, &warm);
}

//DriverEntry末尾调用: 放行T2的Desktop镜像(避开加载窗口期的过滤驱动死锁)
VOID FlMarkEntryDone(VOID)
{
	if (!g_flEnabled)
	{
		return;    //v1.2: 日志未开启=空操作
	}
	g_flEntryDone = TRUE;
	KeSetEvent(&g_flKickT2, IO_NO_INCREMENT, FALSE);
}

//T1: 把二进制事件环([E][V][H][S][R])格式化成行入行环(限流规则在FlRingExit里)
static VOID FlDrainBinRing(VOID)
{
	char buf[512];
	LONG head = g_flRingHead;
	LONG s = g_flBinFlushed;
	if (head - s > GEPT_RING_SIZE)
	{
		RtlStringCbPrintfA(buf, sizeof(buf),
			"[ring] 溢出%d条(exit风暴), 只保留最近%d条",
			head - s - GEPT_RING_SIZE, GEPT_RING_SIZE);
		FlEnqueueLine(buf);
		s = head - GEPT_RING_SIZE;
	}
	for (; s < head; s++)
	{
		PGEPT_RING_ENTRY e = &g_flRing[s & (GEPT_RING_SIZE - 1)];
		if (e->seq != (ULONG)s)
		{
			continue;    //半写, 跳过
		}
		RtlStringCbPrintfA(buf, sizeof(buf),
			"[%c] s=%ld cpu=%u rsn=%u a=%p b=%p c=%p",
			e->tag, s, e->cpu, e->reason,
			(PVOID)e->a, (PVOID)e->b, (PVOID)e->c);
		FlEnqueueLine(buf);
	}
	g_flBinFlushed = head;
}

//单文件顺序写: pCursor是该文件已写到的行号(仅属主线程触碰)
//v3.16: 写盘合并(同FlDrainTempLocked)——Desktop是用户路径=过滤最重,
//每行一次写IRP在T2放行后的镜像期同样压过滤栈
static VOID FlDrainLines(HANDLE hFile, PLONG pCursor, volatile LONG* pFails)
{
	char buf[4096];
	IO_STATUS_BLOCK iosb = { 0 };
	LONG head = g_flLineHead;
	LONG c = *pCursor;
	ULONG used = 0;
	if (hFile == NULL)
	{
		*pCursor = head;    //文件不可用: 只推进游标
		return;
	}
	if (head - c > GEPT_LINE_RING_SIZE)
	{
		//行环被写穿: 跳到最新一圈并留标记
		RtlStringCbPrintfA(buf, sizeof(buf),
			"...行环溢出%d条, 从最新处继续...\r\n",
			head - c - GEPT_LINE_RING_SIZE);
		used = (ULONG)strlen(buf);
		ZwWriteFile(hFile, NULL, NULL, NULL, &iosb, buf, used, NULL, NULL);
		used = 0;
		c = head - GEPT_LINE_RING_SIZE;
	}
	for (; c < head; c++)
	{
		PGEPT_LINE_ENTRY e = &g_flLines[c & (GEPT_LINE_RING_SIZE - 1)];
		if (e->seq != (ULONG)c)
		{
			continue;    //半写, 跳过
		}
		RtlStringCbPrintfA(buf + used, sizeof(buf) - used,
			"L%05u %s\r\n", c + 1, e->text);
		used += (ULONG)strlen(buf + used);
		if (used >= sizeof(buf) - (GEPT_LINE_TEXT + 32))
		{
			if (!NT_SUCCESS(ZwWriteFile(hFile, NULL, NULL, NULL, &iosb,
				buf, used, NULL, NULL)))
			{
				(*pFails)++;
			}
			used = 0;
		}
	}
	if (used > 0)
	{
		if (!NT_SUCCESS(ZwWriteFile(hFile, NULL, NULL, NULL, &iosb,
			buf, used, NULL, NULL)))
		{
			(*pFails)++;
		}
	}
	*pCursor = head;
}

//T1线程: 排空二进制环([E][W][K][F][f][V][H]...→行环) + 250ms心跳(v3.16)
//+ Temp排空。文件由T1自己打开(v3.2: DriverEntry上下文的ZwCreateFile
//同有加载窗口期风险)。v3.16: 热轮询机制(1ms节奏)已随使命完成而移除——
//launch窗口的观测任务已由v3.14/v3.15完成, 1ms级线程唤醒+写盘抖动
//反而是间歇性崩溃的嫌疑环境
static VOID FlThreadProcT1(PVOID Context)
{
	LARGE_INTEGER timeout;
	LARGE_INTEGER rest;
	ULONG64 hb = 0;
	UNREFERENCED_PARAMETER(Context);
	//v3.7: T1逃离cpu0——cpu0是首个被虚拟化的核, 万一guest侧死循环, 调度在
	//cpu0上的T1同归于尽, 日志全盲(v3.6实测: L233后零[HB]零事件)。钉在
	//cpu1..N上, cpu0之死不再影响日志通道(T2同理)。串行启动若卡在cpu0,
	//其余核未虚拟化, T1在健康核上继续记录
	//v3.32: 再排除最后一核(虚拟化目标, 安静核)——T1必须在"结构性不依赖
	//任何虚拟化核"的位置: v3.30/31的T1死因=补写批次ZwWriteFile的完成
	//中断/DPC路由经被虚拟化核, I/O永完不成→T1卡死→零落盘。排除后T1的
	//写盘完成走真机核的DPC队列, 目标核冻结时观测通道存活=死亡现场落盘
	{
		ULONG nCpu = KeQueryActiveProcessorCount(NULL);
		if (nCpu > 2)
		{
			ULONG_PTR avoid = (ULONG_PTR)1 | ((ULONG_PTR)1 << (nCpu - 1));
			KeSetSystemAffinityThread(~avoid);
		}
		else if (nCpu > 1)
		{
			KeSetSystemAffinityThread(~(ULONG_PTR)1);
		}
	}
	//v3.34: 看门狗改自旋线程(见FlWdThreadProc)——T1/T2不再挂DPC计时器
	g_flFileTemp = FlOpenOneFile(GEPT_LOG_PATH2);
	if (g_flFileTemp == NULL)
	{
		DbgPrint("[fl]T1: Temp文件打开失败, Temp落盘禁用(仅DbgView)\n");
	}
	FlEnqueueLine("T1线程启动(Temp+心跳, 已钉离cpu0)");
	FlDrainTempLocked();
	//v3.8: 心跳1秒->250ms; v3.13: 250ms->50ms; v3.16: 50ms->250ms。
	//50ms粒度的使命(launch窗口观测)已由[F]/[f]环事件+探针完成; 稳态下
	//20条/秒心跳=每秒20次写IRP+flush, 是过滤栈上无意义的持续压力
	//(v3.14/v3.15间歇蓝屏的环境因素)。250ms足够冻结检测(最后一条[HB]
	//距离冻结时刻<=250ms, [F]/[f]环事件提供窗口边界)
	timeout.QuadPart = -2500000LL;     //250毫秒
	rest.QuadPart = -200000LL;         //20毫秒
	//v3.19: launch热轮询节奏(1ms)与看门狗起点(见循环尾)。回归理由:
	//v3.17/v3.18冻结的<20ms盲区吞掉[F][W]; 移除原因(I/O压力)已被v3.16
	//合并写盘解决——热模式每轮落盘仍是批量一次写, flush仍限250ms
	LARGE_INTEGER hotRest;
	ULONG64 hotSince = 0;
	hotRest.QuadPart = -10000LL;       //1毫秒
	//v3.22: 热模式主等待超时(1ms)。v3.19的hotRest只缩短循环尾的附加延时,
	//循环头KeWaitForSingleObject的timeout恒250ms——T1醒来一次后下一轮又
	//睡满250ms, 1ms节奏从未生效(v3.17/18/19/21四次冻结零[F][W][L]落盘的
	//结构性根因之一)。热模式=等待与附加延时都1ms, 真正毫秒级观测
	LARGE_INTEGER hotWait;
	hotWait.QuadPart = -10000LL;       //1毫秒
	//v3.7: 心跳按墙钟强制发射——原设计与kick事件共用一次等待, 日志密集时
	//kick不断重置等待, timeout永不触发, 心跳被活活饿死(实测: 模块清单
	//190行落盘期间一条[HB]都没有)。改为每次醒来查墙钟, 距上次心跳>=间隔
	//就无条件发射
	ULONG64 lastHb = KeQueryUnbiasedInterruptTime();
	for (;;)
	{
		//v3.22: 热模式等待超时1ms(见hotWait注释), 常规250ms
		KeWaitForSingleObject(&g_flKickT1, Executive,
			KernelMode, FALSE, g_flLaunchHot ? &hotWait : &timeout);
		if (g_flStop)
		{
			break;
		}
		FlDrainBinRing();
		if (KeQueryUnbiasedInterruptTime() - lastHb >= 2500000LL)
		{
			//心跳行: 系统存活证明 + vcpu状态快照 + exit计数
			//g/f/o掩码: bit i = cpu i 的 bInGuest/bLaunchFailed/bVmxOn
			//(v3.8: 冻结时最后一条[HB]直接判读——g掩码=1的核vmlaunch成功,
			// f掩码=1的核启动失败, exits列出冻结前全部exit类型统计)
			char hbb[512];
			ULONG guestMsk = 0, failMsk = 0, onMsk = 0;
			ULONG cpuCnt = KeQueryActiveProcessorCount(NULL);
			if (cpuCnt > 32)
			{
				cpuCnt = 32;
			}
			for (ULONG c = 0; c < cpuCnt; c++)
			{
				if (g_vcpu[c].bInGuest)     guestMsk |= (1UL << c);
				if (g_vcpu[c].bLaunchFailed) failMsk |= (1UL << c);
				if (g_vcpu[c].bVmxOn)       onMsk |= (1UL << c);
			}
			RtlStringCbPrintfA(hbb, sizeof(hbb),
				"[HB%llu] up=%us lag=%ld wf=%ld/%ld g:%X f:%X o:%X p:%X vcpu=%d pend=%d exits:",
				++hb, (ULONG)(KeQueryUnbiasedInterruptTime() / 10000000ULL),
				g_flT1Lag, g_flWriteFailsT1, g_flWriteFailsT2,
				guestMsk, failMsk, onMsk, g_geptParkedMask,
				(int)g_geptVcpuCpu,
				(g_geptVcpuCpu >= 0) ? (int)g_vcpu[g_geptVcpuCpu].PendingIntrCount : 0);
			{
				char one[40];
				for (ULONG r = 0; r < GEPT_EXIT_REASON_MAX; r++)
				{
					if (g_flExitCounts[r] != 0)
					{
						RtlStringCbPrintfA(one, sizeof(one), " r%u=%lld",
							r, (LONGLONG)g_flExitCounts[r]);
						RtlStringCbCatA(hbb, sizeof(hbb), one);
					}
				}
			}
			FlEnqueueLine(hbb);
			lastHb = KeQueryUnbiasedInterruptTime();
		}
		//v3.28/v3.29: 写盘护卫——护卫期间零ZwWriteFile(HB/环事件照常入行环
		//缓冲, 容量1024行>>护卫窗产量), 清护卫后下轮(≤1ms)一次补写。
		//v3.29超时自解除。v3.29实测修正: 探针实际耗时~100ms(每次exit往返
		//≈12us×8192次, 非估算的8ms)——100ms阈值被正常运行触发(无害但留痕
		//误导判读)。v3.30阈值100ms→1000ms: 只在真挂死(probe最长~150ms+
		//KEEP接管初期)时触发; 触发时T1强制解除+补写——guest挂死时若T1
		//活着, 护卫期事件1秒后必然上盘(死亡现场!)
		if (g_flWriteGuard)
		{
			if (g_flWriteGuardTsc == 0)
			{
				g_flWriteGuardTsc = KeQueryUnbiasedInterruptTime();
			}
			else if (KeQueryUnbiasedInterruptTime() - g_flWriteGuardTsc > 10000000LL)
			{
				g_flWriteGuard = 0;
				g_flWriteGuardTsc = 0;
				FlEnqueueLine("[fl]护卫超时1000ms未清(guest挂死?), T1强制解除并补写");
			}
		}
		else
		{
			g_flWriteGuardTsc = 0;
		}
		if (!g_flWriteGuard)
		{
			FlDrainTempLocked();
		}
		//v3.19: launch热轮询——g_flLaunchHot置位期间(vmlaunch前置1, 结果行
		//落盘后清0), T1睡眠间隔20ms→1ms: 冻结前的[F][W][E]环事件毫秒级上盘,
		//盲区从20ms压到1ms。v3.25看门狗3秒→15秒: 签到阶段(2秒)也在
		//热观测覆盖内; 主线程若死在guest里没清标志, T1以1ms节奏继续
		//观测冻结如何杀死全机, 15秒后自动降温
		if (g_flLaunchHot)
		{
			if (hotSince == 0)
			{
				hotSince = KeQueryUnbiasedInterruptTime();
			}
			else if (KeQueryUnbiasedInterruptTime() - hotSince > 150000000LL)
			{
				g_flLaunchHot = 0;
				hotSince = 0;
				FlEnqueueLine("[fl]launch热轮询15秒超时(主线程未清标志, 疑卡死), 恢复常规节奏");
			}
		}
		else
		{
			hotSince = 0;
		}
		//v3.5限速(热窗口例外): 常规模式相邻两批落盘间隔>=20ms
		KeDelayExecutionThread(KernelMode, FALSE,
			g_flLaunchHot ? &hotRest : &rest);
	}
	//收尾: 排空全部剩余(关文件由FlShutdown做, T1退出后无并发)
	FlDrainBinRing();
	FlDrainTempLocked();
	PsTerminateSystemThread(STATUS_SUCCESS);
}

//T2线程: Desktop尽力镜像; 等DriverEntry完成才开文件(避开加载窗口期)
static VOID FlThreadProcT2(PVOID Context)
{
	LARGE_INTEGER timeout;
	UNREFERENCED_PARAMETER(Context);
	//v3.7: T2同样钉离cpu0(理由同T1)
	//v3.32: 同T1再排除最后一核(虚拟化目标)——见T1处注释
	{
		ULONG nCpu = KeQueryActiveProcessorCount(NULL);
		if (nCpu > 2)
		{
			ULONG_PTR avoid = (ULONG_PTR)1 | ((ULONG_PTR)1 << (nCpu - 1));
			KeSetSystemAffinityThread(~avoid);
		}
		else if (nCpu > 1)
		{
			KeSetSystemAffinityThread(~(ULONG_PTR)1);
		}
	}
	//v3.34: 看门狗改自旋线程——T2同样不再挂DPC计时器
	timeout.QuadPart = -30000000LL;    //3秒
	for (;;)
	{
		KeWaitForSingleObject(&g_flKickT2, Executive, KernelMode, FALSE, &timeout);
		if (g_flStop)
		{
			PsTerminateSystemThread(STATUS_SUCCESS);
			return;
		}
		if (g_flEntryDone)
		{
			break;
		}
		g_flT2Seq = g_flLineHead;    //镜像未放行: 只推进游标
	}
	g_flFileDesktop = FlOpenOneFile(GEPT_LOG_PATH1);
	if (g_flFileDesktop == NULL)
	{
		DbgPrint("[fl]T2: Desktop文件打开失败, Desktop镜像禁用(Temp为准)\n");
		PsTerminateSystemThread(STATUS_SUCCESS);
		return;
	}
	FlEnqueueLine("T2: DriverEntry已完成, Desktop镜像开始(此前行仅存在于Temp)");
	for (;;)
	{
		KeWaitForSingleObject(&g_flKickT2, Executive, KernelMode, FALSE, &timeout);
		if (g_flStop)
		{
			break;
		}
		FlDrainLines(g_flFileDesktop, &g_flT2Seq, &g_flWriteFailsT2);
	}
	FlDrainLines(g_flFileDesktop, &g_flT2Seq, &g_flWriteFailsT2);
	ZwClose(g_flFileDesktop);
	g_flFileDesktop = NULL;
	PsTerminateSystemThread(STATUS_SUCCESS);
}

//仅T1/T2线程内调用: 打开日志文件(追加+写直达)
static HANDLE FlOpenOneFile(PCWSTR path)
{
	UNICODE_STRING ustr;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK iosb = { 0 };
	HANDLE hFile = NULL;
	RtlInitUnicodeString(&ustr, path);
	InitializeObjectAttributes(&oa, &ustr,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	//FILE_OPEN_IF追加: 保留历史(冻结重启后旧日志不被覆盖)
	//FILE_WRITE_THROUGH: write完成即落盘
	NTSTATUS st = ZwCreateFile(&hFile,
		FILE_APPEND_DATA | SYNCHRONIZE, &oa, &iosb, NULL,
		FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_WRITE_THROUGH, NULL, 0);
	return NT_SUCCESS(st) ? hFile : NULL;
}

//DriverEntry最先调用: 读服务注册表键LogEnable开关(默认0=日志系统整体
//关闭——T1/T2/看门狗线程全部不创建, 零文件I/O, 全部Fl*接口空操作=框架
//交付形态零观测面); LogEnable=1才初始化同步对象+创建写线程/看门狗线程
//(v3.2: Temp文件由T1线程自己打开)
VOID FlInit(PCUNICODE_STRING ServiceRegPath)
{
	HANDLE hThread = NULL;
	//v1.2: 注册表开关——本驱动服务键(如...\Services\GeptHooks)下
	//DWORD值LogEnable(缺省/读失败=0=保持默认关闭)
	if (ServiceRegPath != NULL && ServiceRegPath->Buffer != NULL)
	{
		ULONG enable = 0;
		RTL_QUERY_REGISTRY_TABLE q[2];
		RtlZeroMemory(q, sizeof(q));
		q[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
		q[0].Name = L"LogEnable";
		q[0].EntryContext = &enable;
		q[0].DefaultType = REG_DWORD;
		q[0].DefaultData = &enable;
		q[0].DefaultLength = sizeof(ULONG);
		if (NT_SUCCESS(RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE,
			ServiceRegPath->Buffer, q, NULL, NULL)) && enable != 0)
		{
			g_flEnabled = 1;
		}
	}
	if (!g_flEnabled)
	{
		return;    //默认路径: 什么都不创建, 零线程零文件零看门狗
	}
	//v3.33: 黑匣子静态字段(动态字段由看门狗DPC在触发时快照)
	RtlCopyMemory(g_flBlackBox.magic, "GEPTBB01", 8);
	RtlStringCbCopyA(g_flBlackBox.build, sizeof(g_flBlackBox.build),
		g_geptBuildTag);
	g_flBlackBox.bbVer = 1;
	KeInitializeEvent(&g_flKickT1, SynchronizationEvent, FALSE);
	KeInitializeEvent(&g_flKickT2, SynchronizationEvent, FALSE);
	NTSTATUS st = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS,
		NULL, NULL, NULL, FlThreadProcT1, NULL);
	if (NT_SUCCESS(st))
	{
		ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, *PsThreadType,
			KernelMode, &g_flThreadT1, NULL);
		ZwClose(hThread);
	}
	else
	{
		DbgPrint("[fl]T1线程创建失败=0x%x(无心跳/环排空)\n", st);
	}
	st = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS,
		NULL, NULL, NULL, FlThreadProcT2, NULL);
	if (NT_SUCCESS(st))
	{
		ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, *PsThreadType,
			KernelMode, &g_flThreadT2, NULL);
		ZwClose(hThread);
	}
	else
	{
		DbgPrint("[fl]T2线程创建失败=0x%x(无Desktop镜像)\n", st);
	}
	//v3.34: 双自旋看门狗线程(W0=cpu0, W1=cpu1)——冻结检测的时基是
	//rdtsc(纯硬件), 与中断时钟/定时器/调度完全解耦(v3.33 DPC版实测
	//180s不开火的根因修复); 线程创建失败仅DbgPrint(黑匣子降级, 不致命)
	for (ULONG w = 0; w < 2; w++)
	{
		st = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS,
			NULL, NULL, NULL, FlWdThreadProc, (PVOID)(ULONG_PTR)w);
		if (NT_SUCCESS(st))
		{
			ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS,
				*PsThreadType, KernelMode, &g_flWdThread[w], NULL);
			ZwClose(hThread);
		}
		else
		{
			DbgPrint("[fl]W%u看门狗线程创建失败=0x%x(黑匣子无看门狗)\n", w, st);
		}
	}
}

//DriverUnload最后调用: 停线程+最终排空+关Temp(T2有界等待, 可能卡死在Desktop写)
VOID FlShutdown(VOID)
{
	if (!g_flEnabled)
	{
		return;    //v1.2: 日志未开启=无任何线程/文件需要收尾
	}
	//v3.33: 最先解除看门狗——卸载期间HB可能停顿(线程退出/最终排空),
	//不解除=可能把健康卸载误判成冻结蓝屏
	FlWdDisarm();
	g_flStop = 1;
	KeSetEvent(&g_flKickT1, IO_NO_INCREMENT, FALSE);
	KeSetEvent(&g_flKickT2, IO_NO_INCREMENT, FALSE);
	if (g_flThreadT1 != NULL)
	{
		//T1只写Temp(系统目录): 无过滤驱动死锁风险, 无界等待
		KeWaitForSingleObject(g_flThreadT1, Executive, KernelMode, FALSE, NULL);
		ObDereferenceObject(g_flThreadT1);
		g_flThreadT1 = NULL;
	}
	//最终排空(捕获T1退出后到此刻之间的新行; T1已退出, 无并发)
	FlDrainTempLocked();
	if (g_flFileTemp != NULL)
	{
		ZwClose(g_flFileTemp);
		g_flFileTemp = NULL;
	}
	if (g_flThreadT2 != NULL)
	{
		LARGE_INTEGER t2;
		t2.QuadPart = -20000000LL;    //最多2秒
		if (KeWaitForSingleObject(g_flThreadT2, Executive, KernelMode,
			FALSE, &t2) == STATUS_TIMEOUT)
		{
			//T2卡死在Desktop写(过滤驱动死锁): 泄漏线程与句柄, 仅调试阶段可接受
			DbgPrint("[fl]T2卡死在Desktop写! 句柄泄漏, 建议重启而勿反复卸载\n");
		}
		else
		{
			ObDereferenceObject(g_flThreadT2);
			g_flThreadT2 = NULL;
		}
	}
	//v3.34: 等看门狗线程退出(自旋循环头检查g_flStop, 微秒级退出;
	//有界等待防异常卡死卸载)
	for (ULONG w = 0; w < 2; w++)
	{
		if (g_flWdThread[w] != NULL)
		{
			LARGE_INTEGER tw;
			tw.QuadPart = -20000000LL;    //最多2秒
			if (KeWaitForSingleObject(g_flWdThread[w], Executive,
				KernelMode, FALSE, &tw) == STATUS_TIMEOUT)
			{
				DbgPrint("[fl]W%u看门狗线程未退出! 泄漏\n", w);
			}
			else
			{
				ObDereferenceObject(g_flWdThread[w]);
				g_flWdThread[w] = NULL;
			}
		}
	}
}

