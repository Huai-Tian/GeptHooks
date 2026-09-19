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
	void CmGuestProbe();
	void CmVmCall(ULONG opcode, ULONG64 arg2, ULONG64 arg3, ULONG64 arg4);
	void CmTripleFaultPark();    //v3.35: 三重故障park本体(asm, sti+hlt自旋, 永不返回)

	//v3.35: 三重故障park核位掩码(bit i=cpu i已park)。main.c卸载守卫读它:
	//park核的VMM栈/park代码页仍被占用, 驱动绝不能卸载(拒绝并提示重启)
	extern volatile LONG g_geptParkedMask;

	//v3.13落地探针魔数: CmGuestProbe(vm-asm)首条vmcall携带, handler据此推'W'环标记。
	//改动时必须同步common-asm.asm里的 mov rcx, 5ABEh
#define GEPT_PROBE_MAGIC 0x5ABE

//v3.17: 运行模式开关(从VMX.c移到此处, main.c的启动循环也要用)。
//GEPT_PROBE_EXIT=1: 探针自测模式——第二段vmcall触发vmx_off立即回真机,
//  guest全程只执行6条受控指令、不接管OS(v3.14-v3.16累计37次干净exit
//  闭环+干净卸载, launch/exit机器层已证明无恙)
//GEPT_PROBE_EXIT=0: 接管模式(v3.17当前)——探针两段vmcall后guest经
//  CmGeustRip恢复栈, ret回VMXInitCpuStart在non-root继续, 该核从此
//  运行在EPT之下(OS正常调度, EPT恒等+UC对MMIO, 对OS透明)
//GEPT_LAUNCH_CPU_LIMIT: 接管核数上限(v3.17首测=1, 仅cpu0)。其余核
//  保持真机不启动VT——T1/T2钉在真机核上: 若接管后冻结, 日志通道
//  存活, [HB]/环事件持续记录冻结边界(v3.12/v3.13全核接管冻结时T1
//  同死=零信息; 单核把"全核盲死"变成"可观测的局部死亡")。
//  稳定后改8(或0=不限制)做全核接管
//v3.26: 判别性实验=自测模式(IF=1)。v3.25(KEEP+IF1)冻结且零事件——
//直接注入路径(时钟tick→ext-int exit→注入→ISR在guest内跑)是唯一从未
//被测试过的新机制(v3.22注入到IF=0失败33; v3.23/24窗口位失效未注入)。
//自测模式让探针8ms窗在IF=1下跑完(必撞时钟tick=注入机制受控检验),
//'K'退出回真机, 系统安全(EXIT模式历史37/37存活)。
//存活+[E]rsn=1+[K]落盘 → 注入链路工作, 凶手在接管续跑段;
//冻结 → 注入机制本身有bug, 且1ms热观测给出最后事件
//v3.29实测: EXIT+IF0+pin16 **全流程通过**(r18=8195精确吻合, [W][L][Y][K]
//全落盘+干净卸载)——探针窗口+8192次exit风暴+EPT翻译+launch机制全部无辜;
//结合v3.25/26/27(有中断交付→冻)裁决: **凶手=虚拟化cpu0上的中断交付**。
//v3.30: 切回KEEP(接管)模式——probe窗口已被证明无辜, 现在检验接管续跑:
//probe结束后_enable()→IRR中憋着的中断原生直递→首个ISR在EPT下跑。
//冻结则最后落盘=[Y]+护卫超时行(probe事件已由超时机制保全)→接管期ISR死;
//存活则[Q]+"已进入guest"+签到g=1——全链路打通
//v3.31实测(零事件冻结)判读: T1死于护卫解除后第一次补写——ZwWriteFile
//的完成中断/DPC默认路由经cpu0(存储MSI亲和核), 而cpu0正是被虚拟化核→
//补写批次(含KEEP检查点行)的I/O永完不成→T1卡死→1000ms护卫超时/15s热
//轮询超时行一条都没有(循环体死, 非超时未到)。**观测通道在爆炸半径内=
//结构性循环依赖**; 这也统一解释v3.17-31全部"零事件冻结"(全机磁盘I/O
//完成都经cpu0的DPC队列, cpu0虚拟化后不可交付→全机I/O停摆=卡死非蓝屏)
//与v3.29独活('K'后cpu0回真机跑DPC, I/O恢复)。
//v3.32换核实验: 虚拟化目标cpu0→**最后一核**(安静核: 无存储MSI路由,
//IRQ最少)。T1/T2钉核改排除cpu0+最后一核(=1..N-2核, 结构性脱离虚拟化
//核依赖)。两种结果都决定性:
//  存活→KEEP+注入+全链路在安静核通过, cpu0系列冻结=I/O路由级联(下一步
//        做中断路由策略); 冻结→T1活着(写盘完成走真机cpu0的DPC),
//        [I]/[i]向量身份+最后事件+HB时间线**首次必然落盘**(死亡现场!)
#define GEPT_PROBE_EXIT 0
//v3.40: **全核接管**——LIMIT 1→0(0=不限制), BASE -1→0(从cpu0起全部启动)。
//授权依据: v3.38/v3.39单核(安静核cpu7)KEEP模式全生命周期闭环——
//vmlaunch成功+20min/6min稳定运行(r10/r18外零exit)+**干净卸载**
//(v3.39实测L01507"cpu7: 已退出guest"cpu号正确=GPR修复生效, VMXE清,
//Unload完成)。直投+ctls2许可位+GPR恢复+DTR还原四修复全部就位。
//历史注意: v3.12/v3.13全核KEEP曾零信息冻结——现已归因于中断注入状态机
//(v3.36删)+ctls2缺许可位#UD(v3.38修), 两个凶手都已清算。
//风险备案: T1/T2钉核(1..N-2)也将运行于EPT之下(史上首次全核KEEP观测
//通道入局); 若冻结, NMI协议(v3.35节)是后备通道
#define GEPT_LAUNCH_CPU_LIMIT 0
//v3.32: 虚拟化起始核。-1=最后一核(安静核, 通常cpu7); >=0=从该核开始。
//v3.40: BASE=0+LIMIT=0 → 全部核虚拟化
#define GEPT_LAUNCH_CPU_BASE 0

//v3.32: 当前虚拟化目标核(-1=未启动)。main.c启动前置位; T1的HB pend字段
//与main.c签到行读它(HB行g/f/o掩码仍是全核快照)
	extern volatile LONG g_geptVcpuCpu;

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
		//W=落地探针(v3.13) C=EPT misconfig T=三重故障 G=entry失败33
		//D=同(reason,rip)环路 X=violation/misconfig风暴 A=动态建表失败
		//P=低地址环路 Z=len0未知exit U=len>0未知exit
		//F=热轮询标志置位(v3.15) f=标志清零(与F配对实证追踪卡1之谜)
		//v3.20: L=探针压测循环进度(a=rbx剩余, 每1024次采样1条)
		//       Y=压测循环完成(rbx=0, 即将进入接管/退出分流)
		//v3.21: 'D'已豁免探针代码段内的vmcall(5万次循环是设计形态,
		//       v3.20曾在第502次迭代被'D'误杀→蓝屏@GeptHooks+0x1055);
		//       逃生(VmxExitStormEscape)对reason=18必推RIP(vmcall真机=#UD)
		//v3.25: Q=guest回到VMXInitCpuStart续跑(探针+栈恢复+ret全过,
		//       此刻IF=1——'Q'与[Y]间隙=rcx=3放行→CmGeustRip窗口)
		//v3.31: I=外部中断到达(a=vector, b=intrInfo全量, rsn=1)
		//       i=中断交付给guest(a=vector, rsn=1=直接注入/7=开窗
		//       注入, b=交付后剩余队列)——冻结时最后一条'i'=
		//       正在EPT下执行的凶手ISR身份!
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

	//v3.19: launch热轮询标志回归(v3.16曾移除)。v3.17/v3.18接管模式两次冻结
	//在"vmlaunch..."后<20ms内——[F][W]环事件入环了但T1(20ms节奏)没来得及
	//排空, 盲区吞掉全部证据。v3.16移除热轮询的原因(1ms写盘I/O压力)已被
	//合并写盘+flush限250ms解决——现在1ms节奏只影响T1的睡眠间隔, 每轮
	//落盘仍是批量一次ZwWriteFile, I/O压力不回归。VMX.c在vmlaunch前置1、
	//结果行落盘后清0; T1内置3秒看门狗自动降温
	//v3.22修正: v3.19设计有两重失效(置位后T1不被唤醒+循环头timeout恒250ms),
	//四次冻结零[F][W][L]落盘。修复=FlArmLaunchWatch(踢T1+预热)+T1热模式
	//等待1ms(hotWait)。此标志不再由VMX.c直接置1, 改经FlArmLaunchWatch
	extern volatile LONG g_flLaunchHot;

	//v3.28: 探针窗口写盘护卫(判别实验)——置1期间T1停止一切ZwWriteFile
	//(HB/环事件照常入行环缓冲), probe返回后清0, 下一轮(≤1ms)一次性补写。
	//判别: 冻结且最后落盘行=护卫标记行("vmlaunch...(护卫开...)")=T1并发
	//磁盘I/O被构造性排除→凶手在guest执行/中断直递路径; 存活+补写完整=
	//guest窗口无辜→凶手=T1磁盘I/O(完成IRQ/IRP与虚拟化窗口的交互)
	extern volatile LONG g_flWriteGuard;

	//v3.29: 护卫武装时刻(T1侧100ns单位)——超100ms未清=T1强制解除+补写
	//(修v3.28盲区: guest挂死则护卫永不清, T1活着也永远不写盘)
	extern volatile LONG64 g_flWriteGuardTsc;

	//v3.22: launch观测预热——置hot+踢T1+睡5ms(仅PASSIVE_LEVEL, VmxSetupVmcs
	//在vmlaunch前调用; v3.25起launch全程IF=1)。见common.c实现头注释
	VOID FlArmLaunchWatch(VOID);

	//v3.31: 自旋等待版FlLog(IF=0下安全, rdtsc限界500ms)——KEEP检查点用:
	//sti交付中断前强制T1落盘探针事件+中断队列身份。见common.c实现头注释
	VOID FlLogSpin(const char* fmt, ...);

	//===== v3.33/v3.34: 蓝屏黑匣子(冻结观测的最后通道) =====
	//背景: v3.17-32共12次KEEP冻结全部"零事件"——T1死于循环体内(无HB/无护卫
	//超时/无热轮询超时行), 换核(v3.32安静核)也没救: 冻结级联把T1的磁盘写路径
	//(Cc/Mm锁车队/写完成依赖)一起拖死。磁盘日志通道在爆炸半径内=结构性失效。
	//SDM §32.5裁决(x2APIC EOI在non-root直通真LAPIC)排除了EOI理论后, 唯一
	//能穿越级联冻结的通道=**主动蓝屏**: bugcheck的crash dump栈是专用低层路径
	//(接管磁盘+独立IRP, 专为系统死锁设计), 冻结时仍能写出MEMORY.DMP——
	//黑匣子(事件环尾快照+日志行尾快照+全部元数据)随DMP完整保留。
	//v3.33看门狗(T1/T2钉核各挂1s周期DPC计时器, 行环10s不动触发)实测失败:
	// 180s不开火——**双依赖缺陷**: ①DPC靠定时器到期触发, 到期时刻对比的是
	// KUSER_SHARED_DATA中断时间(由时钟ISR维护, 级联中冻结)②elapsed也用
	// KeQueryUnbiasedInterruptTime——同一个冻结时钟→要么DPC不再触发要么
	// elapsed恒0。教训: **冻结检测器不能依赖任何"被冻结会死"的时基**。
	//v3.34(当前): 双**自旋看门狗线程**(钉cpu0/cpu1, 纯rdtsc计时)——rdtsc是
	// 纯硬件计数器, 永不受中断/时钟/调度冻结影响; 线程自旋不睡眠不依赖
	// 定时器。武装后行环游标30s不动(健康时T1每250ms入队HB行)→FlWdFire
	// 快照黑匣子+KeBugCheckEx(0xDEADC0DE)。TSC频率由W0在驱动加载时用
	// "1s睡眠前后rdtsc差"标定(武装前时钟健康, 测量有效; 失败则默认2GHz)。
	//解析: backup/tools/gept_bb_parse.py(.ps1测试机版) 扫MEMORY.DMP找
	//"GEPTBB01"魔数(黑匣子布局v3.33起未变, 解析器兼容)
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
	extern volatile LONG64 g_flWdTscPerSec;   //v3.34: TSC频率(标定, 默认2GHz)

	//vmlaunch前调用(VMX.c): 武装看门狗——此后行环游标30s不动=蓝屏黑匣子。
	//保持武装直到卸载(FlShutdown解除): 冻结无论发生在probe/接管/运行期,
	//黑匣子都必然随MEMORY.DMP保留死亡现场(v3.34起检测者为自旋线程+rdtsc)
	VOID FlWdArm(VOID);
	//仅FlShutdown/VMfail路径调用: 解除武装
	VOID FlWdDisarm(VOID);

#ifdef __cplusplus
}
#endif

#endif // COMMON_H
