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

//==================== 常驻全局(与日志无关, 两种构建都在) ====================
//当前虚拟化目标核(-1=未启动), VMX.c启动循环置位(Debug构建的T1心跳读它)
volatile LONG g_geptVcpuCpu = -1;
//三重故障park核位掩码(bit i=cpu i已park)——VMX.c关停守卫读它
//(park核的VMM栈/代码页仍被占用, 驱动绝不能卸载)
volatile LONG g_geptParkedMask = 0;
//launch热轮询标志(VMX.c置位/清零)——Debug构建下T1据此进入1ms热节奏
volatile LONG g_flLaunchHot = 0;
//探针窗口写盘护卫(VMX.c置位/清零)——Debug构建下T1护卫期间停写盘
volatile LONG g_flWriteGuard = 0;
//exit精确计数(VMX.c exit handler无条件累加; Debug构建的HB/黑匣子/卸载总结读)
volatile LONG64 g_flExitCounts[GEPT_EXIT_REASON_MAX] = { 0 };
//构建标签全局副本——FlInit时拷入黑匣子
CHAR g_geptBuildTag[24] = GEPT_BUILD_TAG;

#if DBG
//==================== 文件日志(仅Debug构建编译) ====================
//DriverEntry/DriverUnload路径零文件I/O(加载窗口期过滤驱动可能死锁):
//FlLog只入行环; T1线程持有Temp权威副本+心跳+环排空; T2等
//FlMarkEntryDone后镜像Desktop。启动/卸载用串行逐核而非DPC广播
//(DPC全核进DISPATCH级, 线程不可调度)
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
static volatile LONG g_flT1Lag = 0;     //FlLog等待T1落盘超时(500ms)累计次数
//护卫武装时刻(100ns单位)——超时未清=T1强制解除并补写
volatile LONG64 g_flWriteGuardTsc = 0;

//日志运行态标志: FlInit置1; Release构建本区整体不编译(#if DBG)
volatile LONG g_flEnabled = 0;

//===== 蓝屏黑匣子 + 自旋看门狗(动机见common.h) =====
static GEPT_RING_ENTRY g_flRing[GEPT_RING_SIZE];   //BSS: 非分页自动清零
static GEPT_LINE_ENTRY g_flLines[GEPT_LINE_RING_SIZE];
GEPT_BLACKBOX g_flBlackBox;                    //BSS自动清零(非分页)
static volatile LONG64 g_flWdArmed = 0;        //0=解除武装, 否则=武装时刻(100ns)
static volatile LONG  s_flWdFired = 0;         //防双路同时快照的竞态
static PVOID g_flWdThread[2] = { NULL, NULL }; //看门狗线程对象(卸载等待)
//TSC频率(标定值, 默认2GHz)——看门狗计时免疫中断时钟冻结
volatile LONG64 g_flWdTscPerSec = 2000000000LL;
typedef struct _GEPT_WD_TRACK {                //每个看门狗线程私有(无锁)
	LONG64 lastLine;
	LONG64 lastProgress;
} GEPT_WD_TRACK;

VOID FlWdArm(VOID)
{
	//T1不存在则不武装(无心跳源会误触发)
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

//触发: 快照黑匣子+主动蓝屏(crash dump栈随MEMORY.DMP保留黑匣子)
static VOID FlWdFire(ULONG trk)
{
	//双路同时检测: 只让第一路快照, 第二路自旋等bugcheck
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

//自旋看门狗线程: 纯rdtsc计时+纯自旋, 不睡眠不依赖定时器/调度
//(rdtsc免疫时钟冻结)。W0钉cpu0, W1钉cpu1
static VOID FlWdThreadProc(PVOID Context)
{
	ULONG idx = (ULONG)(ULONG_PTR)Context;
	//钉核(此处Context只有0/1两值, 见FlInit创建处)
	KeSetSystemAffinityThread((KAFFINITY)1 << (idx == 0 ? 0 : 1));
	//W0负责TSC频率标定: 1s睡眠前后rdtsc差=真实频率(0.1G-20G校验)
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
	//观测t1Seq(已写盘游标): 只在ZwWriteFile完成后推进, 覆盖T1死/写
	//阻塞场景; 健康时每250ms一批, 30s阈值裕量充足
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
			//30s写盘零推进=级联冻结→蓝屏黑匣子
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
		return;    //日志关闭=零观测面(VM-exit热路径仅此一次判断)
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
	//绝不KeSetEvent: VM-exit上下文(IF=0)可能持调度器锁, 唤醒=死锁;
	//T1的超时轮询兜底(≤250ms)
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
	//vmcall采样上限64: 防高频调用方刷爆环; 计数仍精确
	if (reason == EXIT_REASON_VMCALL &&
		g_flExitCounts[EXIT_REASON_VMCALL] > 64)
	{
		return;
	}
	//reason 1/7高频(时钟中断/开窗排空): 采样限前32条, 计数仍精确
	if (reason == EXIT_REASON_EXTERNAL_INTERRUPT &&
		g_flExitCounts[EXIT_REASON_EXTERNAL_INTERRUPT] > 32)
	{
		return;
	}
	if (reason == EXIT_REASON_PENDING_INTERRUPT &&
		g_flExitCounts[EXIT_REASON_PENDING_INTERRUPT] > 32)
	{
		return;
	}
	//高频指令exit(16/14/12/36/28/51/30)各限采样32条防刷爆; 计数仍精确
	//r31/r32(MSR读写, v1.9b判例: MSR hook热读者刷穿行环)同限
	if ((reason == 16 || reason == 14 || reason == 12 || reason == 36 ||
		reason == 28 || reason == 51 || reason == 30 ||
		reason == 31 || reason == 32) &&
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

//T1(或T1退出后的FlShutdown): 行环→Temp文件。单写者无锁。
//写盘合并: 4KB一批+强flush限250ms一次(崩溃至多丢250ms尾部)
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
	//强flush限250ms一次: 蓝屏至多丢250ms尾部
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

//仅PASSIVE_LEVEL: 入行环后等待T1落盘(10ms轮询, 上限500ms超时放行)
VOID FlLog(const char* fmt, ...)
{
	char buf[512];
	va_list args;
	LARGE_INTEGER tick;
	if (!g_flEnabled || KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		return;    //日志未开启=空操作
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

//自旋等待版FlLog(≤DISPATCH_LEVEL/IF=0安全): 自旋用rdtsc限界500ms,
//不依赖时钟中断; T1在其他核PASSIVE落盘照常
VOID FlLogSpin(const char* fmt, ...)
{
	char buf[512];
	va_list args;
	if (!g_flEnabled || KeGetCurrentIrql() > DISPATCH_LEVEL)
	{
		return;    //日志未开启=空操作
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

//launch观测预热(仅PASSIVE_LEVEL, vmlaunch前调用): 置hot+踢T1+睡5ms,
//T1醒来进入1ms热节奏, launch窗口毫秒级落盘
VOID FlArmLaunchWatch(VOID)
{
	if (!g_flEnabled)
	{
		return;    //日志未开启=空操作(不触碰事件对象/不睡眠)
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
		return;    //日志未开启=空操作
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

//单文件顺序写: pCursor=已写行号(仅属主线程); 写盘合并同FlDrainTempLocked
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

//T1线程: 排空二进制环→行环 + 250ms心跳 + Temp排空。文件由T1自己打开
static VOID FlThreadProcT1(PVOID Context)
{
	LARGE_INTEGER timeout;
	LARGE_INTEGER rest;
	ULONG64 hb = 0;
	UNREFERENCED_PARAMETER(Context);
	//T1钉离cpu0与最后一核(虚拟化目标核): 保证写盘完成不依赖虚拟化核
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
	g_flFileTemp = FlOpenOneFile(GEPT_LOG_PATH2);
	if (g_flFileTemp == NULL)
	{
		DbgPrint("[fl]T1: Temp文件打开失败, Temp落盘禁用(仅DbgView)\n");
	}
	FlEnqueueLine("T1线程启动(Temp+心跳, 已钉离cpu0)");
	FlDrainTempLocked();
	//心跳250ms: [HB]提供存活证明+状态快照
	timeout.QuadPart = -2500000LL;     //250毫秒
	rest.QuadPart = -200000LL;         //20毫秒
	//launch热轮询: 热模式等待与附加延时均1ms
	LARGE_INTEGER hotRest;
	ULONG64 hotSince = 0;
	hotRest.QuadPart = -10000LL;       //1毫秒
	LARGE_INTEGER hotWait;
	hotWait.QuadPart = -10000LL;       //1毫秒
	//心跳按墙钟强制发射: kick不断重置等待会饿死心跳, 改为醒来查墙钟
	ULONG64 lastHb = KeQueryUnbiasedInterruptTime();
	for (;;)
	{
		//热模式等待超时1ms(见hotWait注释), 常规250ms
		KeWaitForSingleObject(&g_flKickT1, Executive,
			KernelMode, FALSE, g_flLaunchHot ? &hotWait : &timeout);
		if (g_flStop)
		{
			break;
		}
		FlDrainBinRing();
		if (KeQueryUnbiasedInterruptTime() - lastHb >= 2500000LL)
		{
			//心跳行: 存活证明+vcpu状态快照+exit计数
			//g/f/o掩码: bit i = cpu i 的 bInGuest/bLaunchFailed/bVmxOn
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
		//写盘护卫: 护卫期间零ZwWriteFile, 清护卫后下轮补写;
		//超时1000ms自解除(guest挂死时强制落盘)
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
		//launch热轮询: hot置位期间睡眠间隔20ms→1ms; 15秒未清自动降温
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
		//常规限速(热窗口例外): 常规模式相邻两批落盘间隔>=20ms
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
	//T2同样钉离cpu0与最后一核(理由同T1)
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

//DriverEntry最先调用: 置g_flEnabled+创建T1/T2/看门狗线程(整体在
//#if DBG内, Release构建不编译)
VOID FlInit(VOID)
{
	g_flEnabled = 1;
	//黑匣子静态字段(动态字段由看门狗在触发时快照)
	RtlCopyMemory(g_flBlackBox.magic, "GEPTBB01", 8);
	RtlStringCbCopyA(g_flBlackBox.build, sizeof(g_flBlackBox.build),
		g_geptBuildTag);
	g_flBlackBox.bbVer = 1;
	KeInitializeEvent(&g_flKickT1, SynchronizationEvent, FALSE);
	KeInitializeEvent(&g_flKickT2, SynchronizationEvent, FALSE);
	HANDLE hThread = NULL;
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
	//双自旋看门狗线程(W0=cpu0, W1=cpu1); 创建失败仅DbgPrint(不致命)
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
		return;    //日志未开启=无任何线程/文件需要收尾
	}
	//最先解除看门狗(卸载期间HB停顿会误判冻结)
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
			//T2卡死在Desktop写: 泄漏线程与句柄(仅调试可接受)
			DbgPrint("[fl]T2卡死在Desktop写! 句柄泄漏, 建议重启而勿反复卸载\n");
		}
		else
		{
			ObDereferenceObject(g_flThreadT2);
			g_flThreadT2 = NULL;
		}
	}
	//等看门狗线程退出(有界等待防卡死卸载)
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
#endif  //#if DBG——日志实现区结束(Release构建: 零日志代码进产物)

