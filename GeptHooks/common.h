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
	typedef struct _GEPT_LINE_ENTRY
	{
		ULONG  seq;       //提交标记(=入环序号, 即最终行号-1)
		CHAR   text[GEPT_LINE_TEXT];
	} GEPT_LINE_ENTRY, * PGEPT_LINE_ENTRY;

	//===== 文件日志系统总开关(默认关闭) =====
	//关闭(默认): 零后台线程(T1/T2/看门狗全部不创建)/零文件I/O/零观测面,
	//  FlLog/FlLogSpin/FlRingPush等全部接口为空操作——交付形态的隐蔽性基线
	//手动开启: 在本驱动服务注册表键下新建DWORD值LogEnable=1再启动服务:
	//  reg add HKLM\SYSTEM\CurrentControlSet\Services\GeptHooks ^
	//      /v LogEnable /t REG_DWORD /d 1 /f
	//开启后: Temp权威副本+Desktop尽力镜像+蓝屏黑匣子看门狗(30s冻结
	//  检测→主动蓝屏0xDEADC0DE写MEMORY.DMP——调试期专用, 交付部署勿开)
	extern volatile LONG g_flEnabled;      //0=关闭(Fl*全空操作), 1=开启(FlInit读LogEnable置位)

	VOID FlInit(PCUNICODE_STRING ServiceRegPath);   //DriverEntry最先调用: 读服务键LogEnable开关, 开启才创建T1/T2/看门狗线程
	VOID FlShutdown(VOID);              //DriverUnload最后调用: 停线程+T1最终落盘(未开启=空操作)
	VOID FlLog(const char* fmt, ...);   //仅PASSIVE_LEVEL: 入行环(零文件I/O); 未开启=空操作
	VOID FlMarkEntryDone(VOID);         //DriverEntry末尾调用: 放行T2的Desktop镜像; 未开启=空操作
	VOID FlRingPush(CHAR tag, ULONG cpu, ULONG reason, ULONG64 a, ULONG64 b, ULONG64 c);
	//任意IRQL(含VM-exit): 无锁写二进制事件环; 未开启=空操作
	VOID FlRingExit(ULONG cpu, ULONG reason, ULONG64 rip, ULONG64 qual);
	//VM-exit统一采样入口(内部含reason计数)
	extern volatile LONG64 g_flExitCounts[GEPT_EXIT_REASON_MAX];

	//launch热轮询标志: VMX.c在vmlaunch前置1(经FlArmLaunchWatch), 结果行
	//落盘后清0; T1热模式毫秒级落盘, 内置看门狗自动降温
	extern volatile LONG g_flLaunchHot;

	//探针窗口写盘护卫: 置1期间T1停止一切ZwWriteFile(事件照常入环),
	//probe返回后清0补写
	extern volatile LONG g_flWriteGuard;
	//护卫武装时刻(T1侧100ns单位)——超100ms未清=T1强制解除并补写
	//(防guest挂死时护卫永不清导致永不写盘)
	extern volatile LONG64 g_flWriteGuardTsc;

	//launch观测预热: 置hot+踢T1+睡5ms(仅PASSIVE_LEVEL, VmxSetupVmcs
	//在vmlaunch前调用)——保证launch窗口毫秒级落盘
	VOID FlArmLaunchWatch(VOID);

	//自旋等待版FlLog(IF=0/≤DISPATCH_LEVEL下安全, rdtsc限界500ms):
	//FlLog的10ms睡眠依赖时钟中断, IF=0的guest核上会永久睡死——
	//KEEP检查点等该场景用本函数
	VOID FlLogSpin(const char* fmt, ...);

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

	extern GEPT_BLACKBOX g_flBlackBox;
	extern CHAR g_geptBuildTag[24];      //main.c定义(=GEPT_BUILD_TAG)
	extern volatile LONG64 g_flWdTscPerSec;   //TSC频率(标定, 默认2GHz)

	//vmlaunch前调用(VMX.c): 武装看门狗——此后行环游标30s不动=蓝屏黑匣子。
	//保持武装直到卸载(FlShutdown解除)
	VOID FlWdArm(VOID);
	//仅FlShutdown/VMfail路径调用: 解除武装
	VOID FlWdDisarm(VOID);

#ifdef __cplusplus
}
#endif

#endif // COMMON_H
