#pragma once
#ifndef COMMON_H
#define COMMON_H
#include<ntifs.h>
#include<ntddk.h>
#include<intrin.h>
#define Log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[VT][%s]: " format "\n", __FUNCTION__, ##__VA_ARGS__)

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct _GUEST_REGS
	{
		ULONG64 rax;
		ULONG64 rcx;
		ULONG64 rdx;
		ULONG64 rbx;
		ULONG64 rsp;
		ULONG64 rbp;
		ULONG64 rsi;
		ULONG64 rdi;
		ULONG64 r8;
		ULONG64 r9;
		ULONG64 r10;
		ULONG64 r11;
		ULONG64 r12;
		ULONG64 r13;
		ULONG64 r14;
		ULONG64 r15;
	} GUEST_REGS, * PGUEST_REGS;

	typedef struct
	{
		USHORT sel;
		USHORT attributes;
		ULONG32 limit;
		ULONG64 base;
	} SEGMENT_SELECTOR;

#pragma warning(push)
#pragma warning(disable: 4201)
	typedef struct
	{
		USHORT LimitLow;
		USHORT BaseLow;
		UCHAR BaseMid;
		UCHAR AttributesLow;
		struct
		{
			UCHAR LimitHigh : 4;
			UCHAR AttributesHigh : 4;
		};
		UCHAR BaseHigh;
	} SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;
#pragma warning(pop)

	BOOLEAN CommCheckBios();
	BOOLEAN CommCheckCpuid();
	BOOLEAN CommCheckCr4();
	//串行逐核启动/停止(main.c调用, PASSIVE+亲和性切换; 取代KeGenericCallDpc:
	//DPC全核同时DISPATCH级运行, 线程无法调度=文件日志结构性盲区, v3两次实测均无法
	//观测到DPC内部卡点; 串行模式每步FlLog同步落盘Temp, 冻结点必在文件最后一行)

	void CmGeustRip();
	void CmGuestRsp();
	void CmVmCall(ULONG opcode, ULONG64 arg2, ULONG64 arg3, ULONG64 arg4);

	//===== 冻结存活文件日志 v3.5: 加载路径零文件I/O =====
	//v2教训: DriverEntry里同步写Desktop文件会被杀软/过滤驱动在驱动加载窗口期
	//死锁(实测第3次ZwWriteFile永久挂起) -> sc start挂起+心跳线程被mutex拖死。
	//v3.1教训: DriverEntry上下文写Temp同样会挂(实测L1成功后L2+T1首写双挂起)。
	//v3.2: FlLog把已格式化的行写入无锁行环后**轮询等待T1落盘**(10ms*50上限);
	//磁盘写只发生在后台线程:
	//  T1(Temp): 权威副本C:\Windows\Temp\gept_log.txt + 1秒心跳 + 二进制环排空
	//  T2(Desktop): 尽力镜像, DriverEntry完成后才开文件(避开加载窗口期)
	//v3.4: 每批ZwFlushBuffersFile强刷(蓝屏丢缓存页问题) + main.c记录驱动base/size
	//v3.5: T1限速20ms/批(突发快写崩溃实验) + FlLog超时lag计数([HB]行显示)
	//     + DriverSection遍历记录全部模块基址(蓝屏参数2自解码) + asm栈对齐修正
	//v3.7: T1/T2钉离cpu0(日志通道不被首个虚拟化核拖死) + 心跳按墙钟强制发射
	//     (修复kick事件饿死心跳的bug) + exit路径全部移除DbgPrint(同核重入死锁)
#define GEPT_RING_SIZE       1024   //二进制事件环条目数(须为2的幂)
#define GEPT_LINE_RING_SIZE  512    //格式化行环条目数(须为2的幂)
#define GEPT_LINE_TEXT       496    //单行最大长度
#define GEPT_EXIT_REASON_MAX 64

	typedef struct _GEPT_RING_ENTRY
	{
		ULONG64 a;        //rip 或 gpa
		ULONG64 b;        //exit qualification / 辅助参数
		ULONG64 c;        //辅助参数
		ULONG64 tsc;
		ULONG  seq;       //提交标记: 等于环形序号才算有效(防读到半写条目)
		ULONG  reason;
		USHORT cpu;
		CHAR   tag;       //E=VM-exit V=EPT violation H=动态建表 S=DPC阶段 R=vmresume失败
		USHORT pad;
	} GEPT_RING_ENTRY, * PGEPT_RING_ENTRY;

	typedef struct _GEPT_LINE_ENTRY
	{
		ULONG  seq;       //提交标记(=入环序号, 即最终行号-1)
		CHAR   text[GEPT_LINE_TEXT];
	} GEPT_LINE_ENTRY, * PGEPT_LINE_ENTRY;

	VOID FlInit(VOID);                  //DriverEntry最先调用: 只创建T1/T2后台线程
	VOID FlShutdown(VOID);              //DriverUnload最后调用: 停线程+T1最终落盘
	VOID FlLog(const char* fmt, ...);   //仅PASSIVE_LEVEL: 入行环(零文件I/O)
	VOID FlMarkEntryDone(VOID);         //DriverEntry末尾调用: 放行T2的Desktop镜像
	VOID FlRingPush(CHAR tag, ULONG cpu, ULONG reason, ULONG64 a, ULONG64 b, ULONG64 c);
	//任意IRQL(含VM-exit): 无锁写二进制事件环
	VOID FlRingExit(ULONG cpu, ULONG reason, ULONG64 rip, ULONG64 qual);
	//VM-exit统一采样入口(内部含reason计数)
	extern volatile LONG64 g_flExitCounts[GEPT_EXIT_REASON_MAX];

#ifdef __cplusplus
}
#endif

#endif // COMMON_H
