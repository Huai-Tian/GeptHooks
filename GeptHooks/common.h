#pragma once
#ifndef COMMON_H
#define COMMON_H
#include<ntifs.h>
#include<ntddk.h>
#include<intrin.h>
//DbgPrint通道已移除(v1.3c): 唯一日志通道=文件日志FlLog(构建配置统辖,
//见下方DBG节)——内核调试器输出对交付形态是纯暴露面且测试机无调试器

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

	void CmGeustRip();
	void CmGuestRsp();
	void CmGuestProbe();
	void CmVmCall(ULONG opcode, ULONG64 arg2, ULONG64 arg3, ULONG64 arg4);
	void CmTripleFaultPark();    //三重故障park本体(asm, sti+hlt自旋, 永不返回)
	void CmVmfuncSwitch(ULONG eptpIndex);   //guest内单次VMFUNC(0, idx)EPTP切换(0=clean/1=hooked, 零VM-Exit); 仅bVmfuncOn核可调, 否则#UD蓝屏

	//三重故障park核位掩码(bit i=cpu i已park)。卸载守卫读它:
	//park核的VMM栈/park代码页仍被占用, 驱动绝不能卸载(拒绝并提示重启)
	extern volatile LONG g_geptParkedMask;

	//落地探针魔数: CmGuestProbe(vm-asm)首条vmcall携带, handler据此推'W'环标记。
	//改动时必须同步common-asm.asm里的 mov rcx, 5ABEh
#define GEPT_PROBE_MAGIC 0x5ABE

//VMCALL签名门(安全): 内部vmcall调用方(CmVmCall/落地探针四段)在r10/r11
//携带的128位签名——exit handler的VMCALL case进case先校验, 不符→'u'环
//留痕+#UD注入(=裸机VMCALL"不在VMX operation"语义, 零新增可观测差异)。
//选易失寄存器=x64 ABI不破坏C调用方(跨调用本就不保持); 双寄存器=病毒
//单碰巧命中概率平方级缩小。值=无语义散列; **改动必须同步common-asm.asm
//里的mov r10/r11立即数(CmVmCall一处+探针四段)**——漏改一处=功能崩
#define GEPT_VMCALL_SIG0 0x9E3779B97F4A7C15ULL
#define GEPT_VMCALL_SIG1 0xBF58476D1CE4E5B9ULL

//===== 运行模式开关 =====
//GEPT_PROBE_EXIT: 1=探针自测模式(第二段vmcall触发vmx_off立即回真机,
//  guest只执行少量受控指令不接管OS); 0=接管模式(探针vmcall后guest
//  经CmGeustRip恢复栈ret回VMXInitCpuStart在non-root继续, 该核从此
//  运行在EPT之下, 对OS透明)。调试launch/exit机器层时才用1
#define GEPT_PROBE_EXIT 0
//GEPT_LAUNCH_CPU_LIMIT: 接管核数上限(0=不限制)。
//GEPT_LAUNCH_CPU_BASE: 虚拟化起始核(-1=最后一核)。诊断故障时可
//  用两者限定单核(其余核真机), 保证日志通道存活
#define GEPT_LAUNCH_CPU_LIMIT 0
#define GEPT_LAUNCH_CPU_BASE 0

//当前虚拟化目标核(-1=未启动), 启动循环置位, 日志心跳读它
	extern volatile LONG g_geptVcpuCpu;

	//===== 冻结存活文件日志 =====
	//架构: DriverEntry/DriverUnload调用路径上零文件I/O(驱动加载窗口期
	//杀软/过滤驱动可能死锁文件写)。FlLog只把已格式化的行写入无锁行环,
	//磁盘写只发生在后台线程:
	//  T1(Temp): 权威副本C:\Windows\Temp\gept_log.txt + 心跳 + 二进制环排空
	//  T2(Desktop): 尽力镜像, DriverEntry完成后才开文件(避开加载窗口期)
	//纪律: FlLog仅PASSIVE_LEVEL; FlLogSpin≤DISPATCH_LEVEL(自旋等待);
	//FlRingPush任意IRQL(含VM-exit上下文)
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
		CHAR   tag;       //环事件类型(见下方tag表)
		USHORT pad;
	} GEPT_RING_ENTRY, * PGEPT_RING_ENTRY;

	//环事件tag含义(日志判读表; 解析器依赖此语义):
	//  E=VM-exit V=EPT violation H=动态建表 S=DPC阶段 R=vmresume失败
	//  W=落地探针 C=EPT misconfig T=三重故障 G=entry失败33
	//  D=同(reason,rip)环路 X=violation/misconfig风暴 A=动态建表失败
	//  P=低地址环路 Z=len0未知exit U=len>0未知exit
	//  L=探针压测循环进度 Y=压测循环完成 Q=guest回到VMXInitCpuStart续跑
	//  I=外部中断到达(a=vector) i=中断交付给guest(a=vector)
	//  r=卸载CR3证据(a=GUEST_CR3 b=回读 c=HOST_CR3快照)
	//  v=全核IPI原子退出留痕(a=本核曾in-guest, b=bVmxOn终值应0)
	//  u=VMCALL签名门拒绝(rsn=18, b=病毒试探的功能码; 区分于case59
	//    VMFUNC失败exit的'u'——按rsn分)  c=CR访问exit(28)留痕(采样)
	//  t=卸载时TSC_OFFSET终值 m=vmcall(7)还原字节
	typedef struct _GEPT_LINE_ENTRY
	{
		ULONG  seq;       //提交标记(=入环序号, 即最终行号-1)
		CHAR   text[GEPT_LINE_TEXT];
	} GEPT_LINE_ENTRY, * PGEPT_LINE_ENTRY;

	//===== 蓝屏黑匣子(冻结观测的最后通道) =====
	//级联冻结时磁盘日志通道可能一起被拖死(存储链路在爆炸半径内),
	//唯一能穿越冻结的通道=主动蓝屏: bugcheck的crash dump栈是专用低层
	//路径(接管磁盘+独立IRP, 专为系统死锁设计), 黑匣子(事件环尾快照+
	//日志行尾快照+全部元数据)随MEMORY.DMP完整保留。
	//检测者=双自旋看门狗线程(钉cpu0/cpu1, 纯rdtsc计时, 不睡眠不依赖
	//定时器/时钟/调度——rdtsc是纯硬件计数器, 冻结对它无效)。
	//解析: backup/tools/gept_bb_parse.py(.ps1测试机版) 扫MEMORY.DMP找
	//"GEPTBB01"魔数(解析器与此结构逐字节契约)
	typedef struct _GEPT_BLACKBOX
	{
		//字节偏移(解析器必须与此逐字节一致; 全部自然对齐, 无pragma pack)
		CHAR    magic[8];       //+0x000 "GEPTBB01"
		CHAR    build[24];      //+0x008 构建标签
		ULONG64 bbVer;          //+0x020 =1(布局版本)
		ULONG64 fireTsc;        //+0x028 触发时刻rdtsc
		ULONG64 fireIntrTime;   //+0x030 触发时刻中断时钟(100ns)
		ULONG64 wdArmed;        //+0x038 武装时刻(0=未武装)
		ULONG64 lineHead;       //+0x040 行环写游标(冻结时的最后行号)
		ULONG64 ringHead;       //+0x048 事件环写游标
		ULONG64 t1Seq;          //+0x050 T1已写行游标
		ULONG64 t2Seq;          //+0x058 T2已镜像行游标
		ULONG64 writeGuard;     //+0x060 写盘护卫状态
		ULONG64 launchHot;      //+0x068 热轮询状态
		ULONG64 vcpuCpu;        //+0x070 虚拟化目标核
		ULONG64 pendCount;      //+0x078 目标核积压中断数
		ULONG64 pollCnt;        //+0x080 看门狗DPC累计轮询数(活体证明)
		ULONG64 exitCounts[GEPT_EXIT_REASON_MAX];  //+0x088 全部exit精确计数(512B)
		GEPT_RING_ENTRY ring[48];   //+0x288 事件环尾48条快照(按seq升序)
		CHAR    lines[20][256];     //+0xB88 行环尾20条快照(超256截断)
		CHAR    magic2[8];          //+0x1F88 "GEPTBB02"(完整性尾标)
	} GEPT_BLACKBOX, * PGEPT_BLACKBOX;   //sizeof=0x1F90
	//(g_flBlackBox/g_flWdTscPerSec的extern在下方#if DBG块内——Release
	//构建零引用不定义; 结构体定义本身无条件保留=解析器契约文档)

	//===== 文件日志系统总开关(构建配置判据, v1.3c终态) =====
	//唯一开关=DBG(由VS构建配置决定, vcxproj两个配置已显式定义):
	//  Debug构建(DBG=1)  = 完整观测设施(T1/T2写盘+二进制事件环+蓝屏黑匣子
	//    看门狗, 含30s冻结检测→主动蓝屏0xDEADC0DE→MEMORY.DMP——调试专用)
	//  Release构建(DBG=0)= 全部Fl*接口编译期空操作——调用点的参数与格式
	//    串整体不参与编译(攻防形态: 诊断字符串=可静态扫描的IoC), 零后台
	//    线程/零文件I/O/零环写入, 日志实现代码不进产物
	//沿革: v1.2注册表LogEnable(键值=可静态签名暴露面, 弃用)→v1.3b编译期
	//GEPT_LOG_ENABLE宏(需手工改值, 弃用)→v1.3c DBG构建配置判据(终态:
	//选构建即选产物形态, 无任何手工步骤)
#if DBG
	extern volatile LONG g_flEnabled;      //1=开启(FlInit置位; 仅Debug构建可达)
	VOID FlInit(VOID);                     //DriverEntry最先调用: 创建T1/T2/看门狗线程
	VOID FlShutdown(VOID);                 //DriverUnload最后调用: 停线程+T1最终落盘
	VOID FlLog(const char* fmt, ...);      //仅PASSIVE_LEVEL: 入行环(零文件I/O)
	VOID FlLogSpin(const char* fmt, ...);  //自旋等待版(IF=0/≤DISPATCH_LEVEL安全, rdtsc限界500ms)——FlLog的10ms睡眠依赖时钟中断, IF=0的guest核上会永久睡死
	VOID FlMarkEntryDone(VOID);            //DriverEntry末尾调用: 放行T2的Desktop镜像
	VOID FlRingPush(CHAR tag, ULONG cpu, ULONG reason, ULONG64 a, ULONG64 b, ULONG64 c);
	//任意IRQL(含VM-exit): 无锁写二进制事件环
	VOID FlRingExit(ULONG cpu, ULONG reason, ULONG64 rip, ULONG64 qual);
	//VM-exit统一采样入口(内部含reason计数)
//launch观测预热: 置hot+踢T1+睡5ms(仅PASSIVE_LEVEL, VmxSetupVmcs
//在vmlaunch前调用)——保证launch窗口毫秒级落盘
	VOID FlArmLaunchWatch(VOID);
	//vmlaunch前调用(VMX.c): 武装看门狗——此后行环游标30s不动=蓝屏黑匣子。
	//T1不存在则不武装。保持武装直到卸载(FlShutdown解除)
	VOID FlWdArm(VOID);
	//仅FlShutdown/VMfail路径调用: 解除武装
	VOID FlWdDisarm(VOID);
	extern volatile LONG64 g_flWriteGuardTsc;   //护卫武装时刻(T1侧100ns单位)——超时未清=T1强制解除并补写(防guest挂死时护卫永不清导致永不写盘)
	extern GEPT_BLACKBOX g_flBlackBox;
	extern volatile LONG64 g_flWdTscPerSec;     //TSC频率(标定, 默认2GHz)
#else
//Release构建: 空操作宏——调用点连参数带格式串整体消失
#define FlInit()
#define FlShutdown()
#define FlLog(fmt, ...)
#define FlLogSpin(fmt, ...)
#define FlMarkEntryDone()
#define FlRingPush(tag, cpu, reason, a, b, c)
#define FlRingExit(cpu, reason, rip, qual)
#define FlArmLaunchWatch()
#define FlWdArm()
#define FlWdDisarm()
#endif

//常驻全局(与日志无关, 两种构建都必须在——VMX.c/main.c无条件引用):
//launch热轮询标志: VMX.c在vmlaunch前置1(经FlArmLaunchWatch), 结果行
//落盘后清0; Debug构建下T1热模式毫秒级落盘, 内置看门狗自动降温
	extern volatile LONG g_flLaunchHot;
	//探针窗口写盘护卫: VMX.c置1/清0, 置位期间T1(Debug构建)停止一切
	//ZwWriteFile(事件照常入环), probe返回后清0补写
	extern volatile LONG g_flWriteGuard;
	//exit精确计数: VMX.c exit handler无条件累加(Debug构建的HB心跳/
	//黑匣子/卸载总结读取它)
	extern volatile LONG64 g_flExitCounts[GEPT_EXIT_REASON_MAX];

	extern CHAR g_geptBuildTag[24];      //main.c定义(=GEPT_BUILD_TAG)

#ifdef __cplusplus
}
#endif

#endif // COMMON_H
