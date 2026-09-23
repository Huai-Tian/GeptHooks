#pragma once
#ifndef COMMON_H
#define COMMON_H
#include<ntifs.h>
#include<ntddk.h>
#include<intrin.h>
//日志通道=文件日志FlLog(构建配置统辖, 见下方DBG节)

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
	ULONG64 CmVmCall(ULONG opcode, ULONG64 arg2, ULONG64 arg3, ULONG64 arg4);   //rax=返回值(功能码自定义, 不写的功能码=功能码本身)
	void CmTripleFaultPark();    //三重故障park本体(asm, sti+hlt自旋, 永不返回)

	//三重故障park核位掩码(bit i=cpu i已park)。park核的VMM栈/代码页仍被
	//占用, 卸载守卫据此拒绝卸载
	extern volatile LONG g_geptParkedMask;

	//落地探针魔数: CmGuestProbe首条vmcall携带。
	//改动必须同步common-asm.asm的 mov rcx, 5ABEh
#define GEPT_PROBE_MAGIC 0x5ABE

//VMCALL签名门: 内部vmcall(CmVmCall/落地探针)在r10/r11携带128位签名,
//exit handler的VMCALL case先校验, 不符→'u'环留痕+#UD注入(=裸机VMCALL
//"不在VMX operation"语义)。改动必须同步common-asm.asm的mov r10/r11
//立即数(CmVmCall一处+探针两段)
#define GEPT_VMCALL_SIG0 0x9E3779B97F4A7C15ULL
#define GEPT_VMCALL_SIG1 0xBF58476D1CE4E5B9ULL

//内部vmcall功能码: 8=MSR位图原语(GeptMsr安装/移除, root直写真位图
//——自我隐蔽配套, 详见GeptMsr.c); 10=TSC校准探针(空handler, guest
//侧rdtsc夹逼测泄漏, 见VmxTscCalibrateAll); 11=时钟布防(MMIO页+端口
//I/O位, ClkInitAll逐核调用, 见Clock.c); 12=CodePage物理隐蔽/恢复
//(GeptHookRemove的DPC: rdx=GPA r8=hide)
#define GEPT_VMCALL_MSRBIT 8
#define GEPT_VMCALL_TSCCAL 10
#define GEPT_VMCALL_CLKARM 11
#define GEPT_VMCALL_CPHIDE 12

//当前虚拟化目标核(-1=未启动), 启动循环置位, 日志心跳读它
	extern volatile LONG g_geptVcpuCpu;

	//===== 文件日志 =====
	//DriverEntry/DriverUnload路径零文件I/O(加载窗口期过滤驱动可能死锁):
	//FlLog只写入无锁行环, 磁盘写只发生在后台线程:
	//  T1(Temp): 权威副本+心跳+二进制环排空;  T2(Desktop): 尽力镜像
	//IRQL约束: FlLog仅PASSIVE_LEVEL; FlLogSpin≤DISPATCH_LEVEL;
	//FlRingPush任意IRQL(含VM-exit上下文)
#define GEPT_RING_SIZE       1024   //二进制事件环条目数(须为2的幂)
#define GEPT_LINE_RING_SIZE  512    //格式化行环条目数(须为2的幂)
#define GEPT_LINE_TEXT       496    //单行最大长度
#define GEPT_EXIT_REASON_MAX 82

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
	//  Q=guest回到VMXInitCpuStart续跑
	//  I=外部中断到达(a=vector) i=中断交付给guest(a=vector)
	//  r=卸载CR3证据(a=GUEST_CR3 b=回读 c=HOST_CR3快照)
	//  v=全核IPI原子退出留痕(a=本核曾in-guest, b=bVmxOn终值应0)
	//  u=VMCALL签名门拒绝(rsn=18, b=病毒试探的功能码; 区分于case59
	//    VMFUNC兜底#UD注入的'u'——按rsn分)  c=CR访问exit(28)留痕(采样)
	//  t=卸载时TSC_OFFSET终值 m=vmcall(7)还原字节
	//  M=MTF读透明切换(HideRead页读/写violation, 采样推; 布防形态'S'rsn=25)
	//  H=EPT自我隐蔽完成(每核launch前, a=零页PFN, b=拆分pte页数)
	//  b=MSR位图root直写原语(vmcall8: a=MSR b=操作 c=核掩码)
	//  O=自我隐蔽异常(rsn=0: 拆分pte登记溢出, a=idx; rsn=48: 隐蔽页被
	//    guest访问权限兜底放开, a=gpa b=PTE帧——框架路径误写隐蔽页暴露口)
	//  q=REP串root仿真命中(rsn=48, a=rip b=剩余元素数, 采样)
	//  j=TSC校准完成(a=K b=rdtsc对开销 c=vmcall往返均值)
	//  y=时钟仿真命中(rsn=48 a=gpa b=rip c=虚拟值 / rsn=30 a=端口 b=值,
	//    采样; v1.9b起MSR时钟不封堵, 无rsn=31形态)
	//  a=时钟布防(rsn=11, a=HPET页 b=PM_TMR页, 0=未布防; rsn=13=端口
	//    I/O位置/清, a=端口 b=1置/0清)
	//  g=时钟flicker回退(rsn=48 a=gpa b=rip / rsn=30 a=端口, 采样;
	//    rsn=37=MTF回捕)
	//  l=时钟校准完成(a=Ratio b=计数器GPA)
	//  c=CodePage隐蔽/恢复(rsn=12, a=GPA b=hide c=结果)
	//  z=卸载驻留量化(a=总exit b=K均值 c=累计驻留cycles)
	typedef struct _GEPT_LINE_ENTRY
	{
		ULONG  seq;       //提交标记(=入环序号, 即最终行号-1)
		CHAR   text[GEPT_LINE_TEXT];
	} GEPT_LINE_ENTRY, * PGEPT_LINE_ENTRY;

	//===== 蓝屏黑匣子 =====
	//级联冻结时磁盘日志可能一起失效, 黑匣子(环尾快照+元数据)由看门狗
	//主动KeBugCheckEx(0xDEADC0DE)随MEMORY.DMP保留。检测者=双自旋看门狗
	//线程(钉cpu0/cpu1, 纯rdtsc计时)。
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
		ULONG64 exitCounts[GEPT_EXIT_REASON_MAX];  //+0x088 全部exit精确计数(656B)
		GEPT_RING_ENTRY ring[48];   //+0x320 事件环尾48条快照(按seq升序)
		CHAR    lines[20][256];     //+0xC20 行环尾20条快照(超256截断)
		CHAR    magic2[8];          //+0x2020 "GEPTBB02"(完整性尾标)
	} GEPT_BLACKBOX, * PGEPT_BLACKBOX;   //sizeof=0x2028
	//(g_flBlackBox/g_flWdTscPerSec的extern在下方#if DBG块内; 结构体
	//定义无条件保留=解析器契约)

	//===== 文件日志开关(构建配置判据) =====
	//唯一开关=DBG(VS构建配置):
	//  Debug(DBG=1)  = 完整观测(T1/T2写盘+事件环+看门狗黑匣子)
	//  Release(DBG=0)= 全部Fl*接口空操作宏, 日志实现代码不进产物
#if DBG
	extern volatile LONG g_flEnabled;      //1=开启(FlInit置位; 仅Debug构建可达)
	VOID FlInit(VOID);                     //DriverEntry最先调用: 创建T1/T2/看门狗线程
	VOID FlShutdown(VOID);                 //DriverUnload最后调用: 停线程+T1最终落盘
	VOID FlLog(const char* fmt, ...);      //仅PASSIVE_LEVEL: 入行环(零文件I/O)
	VOID FlLogSpin(const char* fmt, ...);  //自旋等待版(≤DISPATCH_LEVEL/IF=0安全, rdtsc限界500ms)
	VOID FlMarkEntryDone(VOID);            //DriverEntry末尾调用: 放行T2的Desktop镜像
	VOID FlRingPush(CHAR tag, ULONG cpu, ULONG reason, ULONG64 a, ULONG64 b, ULONG64 c);
	//任意IRQL(含VM-exit): 无锁写二进制事件环
	VOID FlRingExit(ULONG cpu, ULONG reason, ULONG64 rip, ULONG64 qual);
	//VM-exit统一采样入口(内部含reason计数)
//launch观测预热: 置hot+踢T1+睡5ms(仅PASSIVE_LEVEL, vmlaunch前调用),
//launch窗口毫秒级落盘
	VOID FlArmLaunchWatch(VOID);
	//武装看门狗(行环游标30s不动=触发黑匣子蓝屏); FlShutdown解除
	VOID FlWdArm(VOID);
	//仅FlShutdown/VMfail路径调用: 解除武装
	VOID FlWdDisarm(VOID);
	extern volatile LONG64 g_flWriteGuardTsc;   //护卫武装时刻(100ns单位)——超时未清=T1强制解除并补写
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

//常驻全局(两种构建都在, VMX.c无条件引用):
//launch热轮询标志: vmlaunch前置1, 结果行落盘后清0(T1热模式毫秒级落盘)
	extern volatile LONG g_flLaunchHot;
	//探针窗口写盘护卫: 置位期间T1停止ZwWriteFile(事件照常入环), probe返回后补写
	extern volatile LONG g_flWriteGuard;
	//exit精确计数: exit handler累加(HB心跳/黑匣子/卸载总结读取)
	extern volatile LONG64 g_flExitCounts[GEPT_EXIT_REASON_MAX];

	//构建标签: 打进日志第一行核对二进制版本。代码改动必须同步修改
#define GEPT_BUILD_TAG "v1.10e"
	extern CHAR g_geptBuildTag[24];      //common.c定义(=GEPT_BUILD_TAG)

#ifdef __cplusplus
}
#endif

#endif // COMMON_H
