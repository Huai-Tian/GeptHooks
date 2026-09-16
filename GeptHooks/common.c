#include"common.h"
#include"winApiDef.h"
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
volatile LONG64 g_flExitCounts[GEPT_EXIT_REASON_MAX] = { 0 };
static GEPT_RING_ENTRY g_flRing[GEPT_RING_SIZE];   //BSS: 非分页自动清零
static GEPT_LINE_ENTRY g_flLines[GEPT_LINE_RING_SIZE];

static HANDLE FlOpenOneFile(PCWSTR path);   //前置声明(定义在线程函数之后)
static VOID FlDrainTempLocked(VOID);        //前置声明: T1(或T1退出后的FlShutdown)把行环推进Temp

//任意IRQL(含VM-exit): 无锁写环形缓冲, seq最后写作为提交标记
VOID FlRingPush(CHAR tag, ULONG cpu, ULONG reason, ULONG64 a, ULONG64 b, ULONG64 c)
{
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
	//事件延迟由T1的250ms超时轮询兜底(冻结前最后快照<=250ms)。
}

//VM-exit统一采样: 所有reason计数; 非高频exit全部入环, 高频CPUID只采前16条
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
static VOID FlDrainTempLocked(VOID)
{
	char buf[GEPT_LINE_TEXT + 32];
	IO_STATUS_BLOCK iosb = { 0 };
	LONG head = g_flLineHead;
	LONG c = g_flT1Seq;
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
		ZwWriteFile(g_flFileTemp, NULL, NULL, NULL, &iosb,
			buf, (ULONG)strlen(buf), NULL, NULL);
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
		RtlStringCbPrintfA(buf, sizeof(buf), "L%05u %s\r\n", c + 1, e->text);
		if (!NT_SUCCESS(ZwWriteFile(g_flFileTemp, NULL, NULL, NULL, &iosb,
			buf, (ULONG)strlen(buf), NULL, NULL)))
		{
			g_flWriteFailsT1++;
		}
		wrote = TRUE;
	}
	g_flT1Seq = head;
	//v3.4: 每批写完立即强刷磁盘。ZwWriteFile只进缓存管理器, 蓝屏不回写脏页
	//=崩溃前最后1-2秒的日志蒸发(v3.2实测停在L30, 真实崩溃点可能晚数秒)
	//强刷后每行都是"已在盘上", 蓝屏零丢失; 调试期每行一次磁盘写完全可接受
	if (wrote)
	{
		ZwFlushBuffersFile(g_flFileTemp, &iosb);
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
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		return;
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

//DriverEntry末尾调用: 放行T2的Desktop镜像(避开加载窗口期的过滤驱动死锁)
VOID FlMarkEntryDone(VOID)
{
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
static VOID FlDrainLines(HANDLE hFile, PLONG pCursor, volatile LONG* pFails)
{
	char buf[GEPT_LINE_TEXT + 32];
	IO_STATUS_BLOCK iosb = { 0 };
	LONG head = g_flLineHead;
	LONG c = *pCursor;
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
		ZwWriteFile(hFile, NULL, NULL, NULL, &iosb,
			buf, (ULONG)strlen(buf), NULL, NULL);
		c = head - GEPT_LINE_RING_SIZE;
	}
	for (; c < head; c++)
	{
		PGEPT_LINE_ENTRY e = &g_flLines[c & (GEPT_LINE_RING_SIZE - 1)];
		if (e->seq != (ULONG)c)
		{
			continue;    //半写, 跳过
		}
		RtlStringCbPrintfA(buf, sizeof(buf), "L%05u %s\r\n", c + 1, e->text);
		if (!NT_SUCCESS(ZwWriteFile(hFile, NULL, NULL, NULL, &iosb,
			buf, (ULONG)strlen(buf), NULL, NULL)))
		{
			(*pFails)++;
		}
	}
	*pCursor = head;
}

//T1线程: 排空二进制环([E][V][H][S][R]→行环) + 1秒心跳 + Temp排空
//文件由T1自己打开(v3.2: DriverEntry上下文的ZwCreateFile同有加载窗口期风险)
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
	if (KeQueryActiveProcessorCount(NULL) > 1)
	{
		KeSetSystemAffinityThread(~(ULONG_PTR)1);
	}
	g_flFileTemp = FlOpenOneFile(GEPT_LOG_PATH2);
	if (g_flFileTemp == NULL)
	{
		DbgPrint("[fl]T1: Temp文件打开失败, Temp落盘禁用(仅DbgView)\n");
	}
	FlEnqueueLine("T1线程启动(Temp+心跳, 已钉离cpu0)");
	FlDrainTempLocked();
	//v3.8: 心跳1秒->250ms。v3.7实测冻结发生在最后落盘行之后<1秒内,
	//1秒粒度的心跳一条都来不及发射(冻结时[HB]完全缺席)。250ms保证
	//冻结前最后一条[HB]距离冻结时刻<=250ms, 其携带的vcpu快照+exit计数
	//即为冻结现场
	timeout.QuadPart = -2500000LL;     //250毫秒
	rest.QuadPart = -200000LL;         //20ms
	//v3.7: 心跳按墙钟强制发射——原设计与kick事件共用一次等待, 日志密集时
	//kick不断重置等待, timeout永不触发, 心跳被活活饿死(实测: 模块清单
	//190行落盘期间一条[HB]都没有)。改为每次醒来查墙钟, 距上次心跳>=间隔
	//就无条件发射
	ULONG64 lastHb = KeQueryUnbiasedInterruptTime();
	for (;;)
	{
		KeWaitForSingleObject(&g_flKickT1, Executive,
			KernelMode, FALSE, &timeout);
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
				"[HB%llu] up=%us lag=%ld wf=%ld/%ld g:%X f:%X o:%X exits:",
				++hb, (ULONG)(KeQueryUnbiasedInterruptTime() / 10000000ULL),
				g_flT1Lag, g_flWriteFailsT1, g_flWriteFailsT2,
				guestMsk, failMsk, onMsk);
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
		FlDrainTempLocked();
		//v3.5限速: 相邻两批落盘间隔>=20ms, 避免密集write-through+flush
		//触发过滤驱动/文件系统竞态
		KeDelayExecutionThread(KernelMode, FALSE, &rest);
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
	if (KeQueryActiveProcessorCount(NULL) > 1)
	{
		KeSetSystemAffinityThread(~(ULONG_PTR)1);
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

//DriverEntry最先调用: 只初始化同步对象+创建两个写线程, 零文件I/O
//(v3.2: Temp文件由T1线程自己打开)
VOID FlInit(VOID)
{
	HANDLE hThread = NULL;
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
}

//DriverUnload最后调用: 停线程+最终排空+关Temp(T2有界等待, 可能卡死在Desktop写)
VOID FlShutdown(VOID)
{
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
}

