#include"VMX.h"
#include"CPU.h"
#include"reg.h"
#include"common.h"
#include<intrin.h>

//v3.17: 运行模式开关GEPT_PROBE_EXIT/GEPT_LAUNCH_CPU_LIMIT已移至common.h
//(main.c启动循环也要用; 本文件曾在此#define, 若与common.h并存会
// 覆盖其值——勿在此重复定义!)。版本史:
//v3.14(自测模式): 4次测试2成功/1蓝屏win32kfull/1冻结
//v3.15: 5核全通后cpu5窗口蓝屏0x50; [f]b/c栈地址=用户侧[f]调用缺参铁证
//v3.16(合并写盘+flush限250ms+心跳回250ms+热轮询移除): 全绿——8核全通,
//  [F]/[f]配对, [W]/[K]各16, 干净卸载, 零异常(backup/logs/v3.16_success*)
//v3.17(接管模式KEEP+单核LIMIT=1): cpu0接管后<20ms全机冻结(L287"vmlaunch..."
//  后零事件零心跳)——与v3.12/v3.13全核接管同签名; 机器层已被37次探针
//  闭环证明无恙 => 凶手=OS在EPT下的行为。头号根因(ept.c头注释): 高地址
//  MMIO violation → exit上下文ExAllocatePoolWithTag → 池锁自旋死锁全机
//v3.18(当前): EptInitEptData预建高区(511×512×1GB UC恒等, 512GB-256TB,
//  8核共享)——高MMIO直接翻译零exit零分配; EPT自检新增[6]高区链校验
//v3.32: 换核实验(虚拟化cpu0→最后一核安静核)——v3.31判读: T1卡死在
//  补写批次ZwWriteFile(完成中断/DPC路由经被虚拟化的cpu0=存储MSI亲和核),
//  观测通道在爆炸半径内=循环依赖; 安静核上T1脱离依赖链, 冻结时
//  KEEP检查点+[I]/[i]中断身份首次必然落盘(见main.c启动循环/VmxSetupVmcs
//  pin注释/VMXInitCpuStart检查点注释)
//v3.32实测判读: 换核后**仍零事件冻结**(无HB33/无护卫超时/无热轮询超时=
//  T1循环体死)——"I/O完成路由经cpu0"理论被推翻(存储IRQ不可能同时在
//  cpu0和cpu7); 冻结级联的机制是**锁车队**: cpu7的IF0探针+检查点窗内
//  IPI/TLB-shootdown发送核自旋等待应答(持有Mm/Cc/调度器锁), 其他核
//  (含T1的ZwWriteFile→Cc/Mm路径)阻塞在该锁上→全机I/O停摆→T1死于
//  循环体内。SDM §32.5裁决(x2APIC EOI在non-root直通真LAPIC)排除EOI
//  理论后, 唯一能穿越级联的观测通道=主动蓝屏的crash dump
//v3.33: 蓝屏黑匣子——vmlaunch前FlWdArm()武装看门狗(T1/T2钉核
//  各挂1s周期DPC计时器), 行环游标10s不动=T1循环死=级联冻结→DPC快照
//  黑匣子(事件环尾48+日志行尾20+全部exit计数+元数据)+KeBugCheckEx
//  (0xDEADC0DE)→MEMORY.DMP保留死亡现场(解析器backup/tools/gept_bb_parse.py)
//v3.33实测#2: 冻结后等了180s看门狗**不开火**——双依赖缺陷: DPC靠定时器
//  到期(对比KUSER_SHARED_DATA中断时间, 级联中冻结)+elapsed同用中断
//  时钟→要么DPC不再触发要么elapsed恒0。冻结检测器不能依赖"被冻结
//  会死"的时基
//v3.34: 看门狗v2=双**自旋线程**(W0钉cpu0/W1钉cpu1, 纯rdtsc计时,
//  W0加载期标定TSC频率)——不睡眠不依赖定时器/时钟/调度; 30s行环不动
//  →FlWdFire快照+蓝屏。VMX行为零改动(单变量纪律: 只修观测)
//v3.34实测: 冻结后长时间等待, 自旋看门狗**也没开火**——级联冻结深到
//  cpu0/cpu1的PASSIVE线程都不再被调度(发送核在DISPATCH级自旋持锁)
//v3.35: 统一理论——**cpu7三重故障→VmxTripleFaultHalt的_disable
//  +__halt永久停核(IF=0)→本核IPI永不处理→TLB-flush广播发送核自旋
//  (持锁DISPATCH级)→全机冻结(含看门狗核)**。修复: 三重故障停核→**park**
//  (vmx_off+清EOI债+sti/hlt自旋服务中断)。实测: park未触发=冻结点
//  不在TF——三重故障理论也被排除, 陷入16版死循环, 转入外部调研
//v3.36(未上机): 调研裁决(HyperPlatform/hvpp/SimpleVisor/HyperDbg/TinyVT
//  五项目源码考古+UC论坛实锤案例)——**中断直投**: pin期望0x1→0(关
//  ext-int exiting), exit期望0x8200→0x200(关ack-on-exit); case1/case7
//  的注入状态机('i'注入/PendingIntrVec入队/开窗关窗)整段删除, 改防御
//  标记。机理: ack-on-exit把中断从IRR移进物理LAPIC ISR, 我们注入回
//  guest的只是VM-entry事件, guest ISR的EOI管不到物理LAPIC→ISR位
//  永不清→时钟中断永久阻塞→整机静默冻结(看门狗死/无蓝屏/间歇性=
//  哪个核哪个中断先被ack的轮盘赌)。v3.19起16个版本的冻结全部发生
//  在这条路径上。直投=中断在non-root经guest IDT原生交付, EOI直写
//  真LAPIC, VMM零参与(五项目共同配置, 亦即v3.16全绿时的隐式配置)
//v3.37(TinyVT专项调研行动项): ctls2期望0x2→0x41A——补开
//  bit3 rdtscp/bit4 xsaves/bit10 invpcid三**指令许可**位(TinyVT
//  "for Win10"/hvpp/HyperPlatform三项目全开)。内核启动时CPUID检出
//  这些指令可用→选定路径; non-root下未开许可位→执行即#UD→
//  普通上下文=蓝屏0x1E@0xC000001D(STATUS_ILLEGAL_INSTRUCTION,
//  **测试机v3.22时期已发生过一次, 当时无解**)→持锁/高IRQL上下文=
//  异常分发挂起→静默冻结(部分冻结案例同源)。INVPCID最大嫌疑:
//  Win10/11 TLB shootdown/进程切换高频路径。另补EXIT_REASON_XSETBV
//  (55)case: XSETBV在non-root无条件exit, TinyVT/HyperPlatform均
//  代执行, 缺case=落default走'U'逃生(vmx_off静默脱离VT无人知晓)
//v3.37实测: **vmlaunch错误码7**(控制字段非法), cpu7安全回真机,
//  心跳/卸载全正常——失败路径完美, 但虚拟化未启动("10分钟稳定"
//  实为空转)。判读: 五控制字段(pin=16/proc=94006172/exit=36FFB/
//  entry=13FB/ctls2=41A)逐一对照MSR原值全部"合法", 凶手=ctls2错位
//v3.38实测: **历史性突破**——vmlaunch成功, [W][Y][Q]+KEEP检查点全通,
//  cpu7接管OS运行于EPT下约20分钟零异常(r10=60 CPUID/r18=515探针,
//  心跳正常, 中断直投+ctls2许可位双修复生效=16版冻结正式清算)。
//  但卸载vmcall退出VT后蓝屏0x7E@(0xC0000005, driver+0x558F1):
//  L01731"cpu3509829504"垃圾参数(cpuNumber被exit handler的C代码
//  残留寄存器值覆盖)——旧VmxJumGuest只切RSP+JMP不恢复GPR, 卸载
//  循环拿垃圾寄存器访问g_vcpu→访问违例。EXIT模式(v3.16)从未暴露:
//  探针vmcall落点=jmp CmGeustRip, pop链从guest栈恢复了全部寄存器
//v3.39(当前): **vmx_off回真机出口的GPR恢复**——新增VmxJumGuestRegs
//  (vmx-asm.asm): 从GuestRegs帧恢复全部非易失GPR(rbx/rbp/rsi/rdi/
//  r12-r15)后再切栈跳(易失寄存器不恢复: vmcall=调用边界, ABI合法)。
//  应用于: ①rcx==1卸载路径 ②VmxExitStormEscape(guestRegs非NULL时,
//  VmxResumeFailedEntry传NULL=其GPR已被pop链恢复) ③探针rcx==3 EXIT
//  路径。另修: a)GDTR/IDTR limit还原(VM-exit强制0xFFFF, TinyVT/
//  HyperPlatform同款, VmxRestoreDtrLimits必须在vmx_off前调用=
//  vmread依赖VMX operation) b)rcx==1路径补bInGuest=0(旧版漏复位)
//v3.39实测: **全生命周期闭环**——单核(安静核cpu7)KEEP: vmlaunch成功
//  →6min稳定(心跳1122条lag=0, exits仅r10=12+r18=516)→**干净卸载**
//  (L01507"cpu7: 已退出guest"cpu号正确=GPR修复生效铁证, VMXE已清,
//  Unload完成, 零蓝屏零异常)。KEEP模式从launch到unload正式打通
//v3.40(全核接管, common.h LIMIT 1→0/BASE -1→0): 单核闭环授权全部
//  8核KEEP。史上首次全核KEEP观测通道(T1/T2)入局; v3.12/13全核冻结
//  的两个凶手(注入状态机/ctls2许可位)均已清算
//v3.40实测: **全核KEEP闭环**——8核vmlaunch全成功(L293-635逐核"已进入
//  guest"), 8×inGuest=1; 11min稳定(心跳2043条, r18=4120=8核×515精确
//  吻合, r10=CPUID正常); 卸载8核串行全干净(8×"已退出guest"cpu号全对
//  +8×"VMXE已清"+"Unload: 完成")。**VT层至此彻底稳固**
//v3.41(STAGE 1, main.c GEPT_HOOK_STAGE 0→1): 自测hook(GeptTestTarget)
//  ——EPT hook全链路首次通电: PHHook建CodePage+跳板→KeGenericCallDpc
//  逐核vmcall(2)→EptSetHook拆2M→4K+清execute→GeptTestTarget()触发
//  violation→EptUpdatePageAcess切CodePage视图→跳板→HookTestTarget
//  ([STAGE1]落盘)→重放5条mov→jmp归位。PageHook.c加守卫: 非guest核
//  禁vmcall(真机vmcall=#UD蓝屏, 'h'留痕), STAGE 2前必须就位
//v3.41实测: STAGE1安装行(L649)后<250ms蓝屏0x1E@(0xC0000005,
//  nt+0x405B4F, 读地址-1)——死在从未运行过的hook布防路径。判读:
//  **结构性缺陷=hook页含VT机器码**——实测目标(...10D6)/跳板(...10E6)
//  /探针(...103D)/CmVmCall(...1075)全在同一4K页! EptSetHook清execute
//  后, DPC自己的vmcall(2)返回ret就在被hook页上=立即violation, 全部
//  VT机器码卷入双视图互切(exec视图write=0=活锁雷区)。自测≠真实场景
//v3.42: **自测页隔离**——hook.asm GeptTestTarget用align 1000h
//  隔离到独立页+跳板推到下一页; main.c STAGE1页隔离断言(目标页与
//  跳板/CmVmCall同页=拒绝安装); ept.c EptSetHook布防环标记('S'=每核
//  armed完成/'n'=中止, DMP解析判别8核是否全部布防成功)
//v3.42b: v3.42的ml64编译失败修正——段内`align 1000h`报"invalid
//  combination with segment alignment:4096"(.code段默认ALIGN(16), 段内
//  align不得超段属性)。改用SEGMENT伪指令: GeptTestTarget放
//  `GEPTTGT SEGMENT ALIGN(4096) 'CODE'`独立段→链接器给独立PE section,
//  SectionAlignment=0x1000天然整页独占; 跳板回.code段(不同section必然
//  不同页, 无需align)。VS错误列表的19条"未找到函数定义"=IntelliSense
//  噪音(不解析.asm), 非构建错误
//v3.42b实测: 页隔离**生效**(L639: 目标=...79000独立页/跳板=...710D6
//  不同页)但**同签名蓝屏**0x1E@(0xC0000005, nt+0x405B4F, 0, -1)!
//  两连蓝屏(v3.41/v3.42b)RVA完全相同(nt基址不同), 且异常地址在
//  **驱动外**(GeptHooks=[...50370000,+170000), 两次蓝屏地址均不落内)
//  ——页隔离修的是假设问题, 真凶另有其人。日志停在L639"安装hook"
//  (无DriverEntry完成行), 死亡窗口=PHHook全程(MmAllocateContiguous
//  Memory→复制→跳板→DPC广播vmcall(2)→EptSetHook)或GeptTestTarget()
//  首次触发, 窗口内**零布点**(环'S'未落盘, Log=DbgPrint不可见)
//v3.43(当前): **蓝屏根因修复(反汇编裁决)**——用户上传ntoskrnl.exe
//  (SizeOfImage 0x1046000与日志模块清单精确吻合=同构建), 反汇编RVA
//  0x405B4F: `movaps xmmword ptr [rsp+30h], xmm6`, 所属函数[405B40,
//  405C16)为KiSwapContext入口shell(全xmm6-15+非易失GPR保存, 自定义
//  寄存器约定rbx=gs:[20h](KPRCB)/rdi=旧线程/rsi=新线程调worker
//  405E90=KiSwapContext本体: fxsave/xsave+mov [rdi+58h],rsp(存旧栈)
//  +mov rsp,[rsi+58h](切新栈), 26个调用者全在调度器区)。蓝屏参数
//  (0xC0000005, rip, 0, -1)的"读地址-1"实为#GP(0)的AV记录哨兵:
//  movaps要求操作数16字节对齐, [rsp+30h]≡8(mod16)→#GP→内核构造
//  AV记录时info[0]=0(读)/info[1]=-1(地址未知)→0x1E。
//  错位源头(工程侧): hook.asm AsmHookTestTarget/AsmHookNtClose的
//  `sub rsp,20h`+call C函数——入口RSP%16==8(跳板push+ret净值0),
//  16 push(128B)+20h(32B)不改奇偶→call时RSP%16==8违反ABI(须≡0),
//  HookTestTarget整棵子树错8字节运行→FlLog等T1落盘线程阻塞→
//  KiCommitThreadWait在错位栈上调用切换shell→movaps #GP→蓝屏。
//  全部事实自洽: 两连蓝屏同RVA(确定性调度路径)/异常在nt不在驱动/
//  页隔离前后同签名(与hook页内容无关)/Stage0无此路径零蓝屏。
//  修复: 两个跳板sub/add 20h→28h(32B影子空间+8B对齐补偿, 与
//  CmGuestRsp的sub 28h同理)。另附死亡窗口插桩: PHHook三锚点FlLog/
//  EptSetHook三步'S'(rsn=21/22/23)/EptUpdatePageAcess视图切换'x'。
//  静态审计排除项: invept(2)=all-context合法(VMX.h枚举与Intel编号
//  一致); GUEST_REGS布局rsp槽吸收双push rbp无错位; EptPdeToPte公式
//  (2M帧号*512+i)正确; VMM栈HOST_RSP=base+0x5000十六对齐+exit
//  prologue(16push+sub100h)奇偶正确=VM-exit路径无辜

VCPU g_vcpu[128];
//v3.10: 段AR指纹(CS/TR最终写入VMCS的值), 供vmlaunch前指纹日志行——
//每次测试先看指纹行确认跑的是新编译的sys(本次v3.9教训: 测试机加载的
//旧二进制让全部修复"看似无效", 日志形态与v3.8一模一样)
static volatile ULONG g_dbgCsAr = 0;
static volatile ULONG g_dbgTrAr = 0;

PVCPU VmxGetCurrentVcpu(ULONG cpuNumber)
{
	return &g_vcpu[cpuNumber];
}
//PASSIVE_LEVEL预分配: DriverEntry里调用.
//绝不能在DPC(DISPATCH_LEVEL)里做MmAllocateContiguousMemory:
//文档要求IRQL<=APC_LEVEL, 且每核2MB连续内存搜索在系统碎片化后
//会让所有核的DPC同时自旋等待 -> 整机冻结(无蓝屏)
int VMXInitCpuAlloc(ULONG cpuNumber)
{
	PHYSICAL_ADDRESS phys = { 0 };
	phys.QuadPart = MAXULONG64;
	PVMX_VMCS pvmxon = (PVMX_VMCS)MmAllocateContiguousMemory(sizeof(VMX_VMCS), phys);
	PVMX_VMCS pvmcs = (PVMX_VMCS)MmAllocateContiguousMemory(sizeof(VMX_VMCS), phys);
	PVOID MsrBitMap = MmAllocateContiguousMemory(PAGE_SIZE, phys);
	PVOID pvmmStack = MmAllocateContiguousMemory(PAGE_SIZE * 6, phys);
	if (pvmmStack == NULL || MsrBitMap == NULL || pvmxon == NULL || pvmcs == NULL)
	{
		//释放已成功的部分, 调用方负责清理
		if (pvmmStack) MmFreeContiguousMemory(pvmmStack);
		if (MsrBitMap) MmFreeContiguousMemory(MsrBitMap);
		if (pvmxon) MmFreeContiguousMemory(pvmxon);
		if (pvmcs) MmFreeContiguousMemory(pvmcs);
		return 1;
	}
	RtlZeroMemory(pvmxon, sizeof(VMX_VMCS));
	RtlZeroMemory(pvmcs, sizeof(VMX_VMCS));
	RtlZeroMemory(pvmmStack, PAGE_SIZE * 6);
	//MSR位图必须清零!(myVt原版同样缺失) CPU_BASED启用了"use MSR bitmaps"(bit28),
	//垃圾位图=随机MSR触发exit; 且exit handler缺WRMSR case会静默丢弃写——
	//x2APIC系统的EOI(WRMSR 0x80B)被吞 → APIC中断卡死 → 整机冻结无蓝屏(vmlaunch成功后秒冻)
	//全零位图=不拦截任何MSR, guest直接访问, 零exit零风险
	RtlZeroMemory(MsrBitMap, PAGE_SIZE);
	pvmxon->RevisionId = (ULONG)__readmsr(MSR_IA32_VMX_BASIC);
	pvmcs->RevisionId = (ULONG)__readmsr(MSR_IA32_VMX_BASIC);
	g_vcpu[cpuNumber].VMXON = pvmxon;
	g_vcpu[cpuNumber].VMMStack = pvmmStack;
	g_vcpu[cpuNumber].VMCS = pvmcs;
	g_vcpu[cpuNumber].MsrBitMap = MsrBitMap;
	g_vcpu[cpuNumber].bInGuest = 0;
	g_vcpu[cpuNumber].bLaunchFailed = 0;
	return 0;
}

//串行模式(亲和性切换到目标核, PASSIVE_LEVEL): vmxon -> vmclear/vmptrld -> 填VMCS -> vmlaunch
//每步FlLog面包屑同步落盘Temp: 冻结时文件最后一行即精确卡点
int VMXInitCpuStart()
{
	ULONG cpuNumber = KeGetCurrentProcessorNumber();
	PHYSICAL_ADDRESS physvmon = { 0 };
	PHYSICAL_ADDRESS physvmcs = { 0 };
	if (g_vcpu[cpuNumber].VMXON == NULL || g_vcpu[cpuNumber].VMCS == NULL)
	{
		FlLog("cpu%u 无预分配资源, 跳过", cpuNumber);
		return 1;
	}
	FlLog("cpu%u: vmxon...", cpuNumber);
	ULONG64 mycr4 = __readcr4();
	mycr4 |= __readmsr(MSR_IA32_VMX_CR4_FIXED0);
	mycr4 &= __readmsr(MSR_IA32_VMX_CR4_FIXED1);
	ULONG64 mycr0 = __readcr0();
	mycr0 |= __readmsr(MSR_IA32_VMX_CR0_FIXED0);
	mycr0 &= __readmsr(MSR_IA32_VMX_CR0_FIXED1);
	__writecr0(mycr0);
	__writecr4(mycr4);
	physvmon = MmGetPhysicalAddress(g_vcpu[cpuNumber].VMXON);
	physvmcs = MmGetPhysicalAddress(g_vcpu[cpuNumber].VMCS);
	UCHAR vmonResult = __vmx_on(&physvmon);
	if (vmonResult)
	{
		FlLog("cpu%u vmxon失败=%d (Hyper-V/VBS占用?)", cpuNumber, vmonResult);
		g_vcpu[cpuNumber].bLaunchFailed = 1;
		return vmonResult;
	}
	g_vcpu[cpuNumber].bVmxOn = 1;
	FlLog("cpu%u: vmxon OK, 填充VMCS...", cpuNumber);

	FlLog("cpu%u: vmclear/vmptrld...", cpuNumber);
	__vmx_vmclear(&physvmcs);
	__vmx_vmptrld(&physvmcs);
	FlLog("cpu%u: 进CmGuestRsp填充VMCS...", cpuNumber);
	//填充VMCS区域(vmlaunch在其中)
	CmGuestRsp();
	//v3.28: 关写盘护卫——CmGuestRsp()返回=所有路径的汇合点:
	//KEEP续跑/'K'退出/'G'逃生/VMfail(fall-through CmGeustRip的ret)。
	//T1在≤1ms内补写护卫期间积压的全部行(判读见VmxSetupVmcs护卫注释)
	g_flWriteGuard = 0;
	if (!g_vcpu[cpuNumber].bLaunchFailed)
	{
		g_vcpu[cpuNumber].bInGuest = 1;
		//v3.25: 'Q'环事件=guest回到VMXInitCpuStart续跑的精确标记
		//(探针四段+栈恢复+ret全链路通过, 且此刻IF=0)
		FlRingPush('Q', cpuNumber, 0, 0, 0, 0);
		//v3.31: KEEP检查点(**sti之前, IF=0下自旋等待安全**)——强制T1
		//把探针事件[F][W][L][Y]全部落盘, 然后才进入直投世界。
		//v3.36: 中断已改直投(pin=0), 无队列无注入——cli窗口内到达的
		//中断安然留在LAPIC IRR(不被ack), sti后硬件自行投递, 零丢失
		//零状态机。此检查点保留: 它仍强制T1在"接管边界"前把探针证据
		//写出去(冻结时最后落盘的就是它之前的世界)
		FlLogSpin("cpu%u KEEP检查点(v3.36中断直投): pin=0无队列无注入, 即将sti——IRR积压中断由硬件直投guest ISR",
			cpuNumber);
	}
	//v3.29: 恢复IF0窗→此处sti(v3.15原设计)。'K'/'G'路径guest原IF=0
	//跳过了自己的sti, 全靠这一行恢复; cli窗内到达的中断在LAPIC IRR
	//排队, sti后硬件直接投递guest ISR(non-root下执行, EOI直写真LAPIC,
	//VMM零参与)。必须在任何FlLog之前(IF=0下其等待会永久睡眠)
	_enable();
	if (!g_vcpu[cpuNumber].bLaunchFailed)
	{
		//此日志在non-root下打印(EPT翻译, 对OS透明)
		//v3.17接管模式: 看到它=该核vmlaunch+探针('W'标记)+栈恢复全通过,
		//且**本行之后的OS执行全部发生在EPT之下**——本行是接管边界的
		//精确标记; 之后若冻结/卡死, 边界就在本行与下一条日志之间
		//(v3.14-v3.16自测模式不走此分支: 探针vmcall已置bLaunchFailed回真机)
		FlLog("cpu%u vmlaunch成功, 已进入guest(接管: 此后本核OS运行于EPT之下)", cpuNumber);
	}
	else
	{
		//v3.14: bLaunchFailed有三来源——①vmlaunch直接VMfail(错误码见上一条)
		//②EPT自检失败放弃 ③探针probe-exit完成('W'+'K'环标记, 自测模式正常
		//路径: guest两段vmcall后vmx_off回真机, 本核已干净脱离VT)
		FlLog("cpu%u vmlaunch失败或probe-exit完成(判读: [W][K]标记=自测通过; 错误码行=VMfail), 本核已回真机", cpuNumber);
	}
	//v3.15: 'f'环事件=launch窗口完成标记(与'F'配对);
	//v3.19: 同时熄灭T1热轮询(结果行已落盘)
	FlRingPush('f', cpuNumber, 0, 0, 0, 0);
	g_flLaunchHot = 0;
	return 0;
}

//串行模式(亲和性切换到目标核, PASSIVE_LEVEL)逐核退出VT(DriverUnload调用)
//取代原CommVtShutDown DPC: 卸载路径同样需要每步落盘可观测
void VmxStopCpu()
{
	ULONG cpuNumber = KeGetCurrentProcessorNumber();
	if (g_vcpu[cpuNumber].bInGuest)
	{
		FlLog("cpu%u: vmcall退出VT...", cpuNumber);
		//成功进入guest的核: vmcall退出(handler内vmx_off后跳回此处)
		CmVmCall(1, 0, 0, 0);
		FlLog("cpu%u: 已退出guest", cpuNumber);
	}
	else if (g_vcpu[cpuNumber].bVmxOn)
	{
		//vmlaunch失败但vmxon成功的核: 仍在root, 直接off
		FlLog("cpu%u: root模式直接vmx_off...", cpuNumber);
		__vmx_off();
	}
	if (g_vcpu[cpuNumber].bVmxOn)
	{
		//清CR4.VMXE, 恢复干净状态
		ULONG64 cr4 = __readcr4();
		cr4 &= ~0x2000;
		__writecr4(cr4);
		g_vcpu[cpuNumber].bVmxOn = 0;
		FlLog("cpu%u: VMXE已清, VT完全停止", cpuNumber);
	}
	else
	{
		FlLog("cpu%u: 未启用VT, 无需停止", cpuNumber);
	}
}

//控制字段计算。SDM Appendix A.3原文裁决(v3.12, 推翻v3.9的补码"修复"):
//  "Bits 31:0 indicate the allowed 0-settings ... VM entry allows control X
//   to be 0 if bit X in the MSR is CLEARED to 0; if bit X in the MSR is
//   SET to 1, VM entry fails if control X is 0."
//即: 能力MSR低32位**置1的位=控制位必须为1**, 清零的位才允许为0; 高32位=
//允许为1的位。新旧MSR语义相同! 旧式(0x481-0x484)对default1类位恒读1(谎报),
//TRUE MSR(0x48D-0x490)如实上报——这是两者唯一区别, 位语义并不相反。
//所以经典公式 (低32|期望) & 高32 对新旧MSR都正确, myVt原版没写错。
//v3.11b实证(8核vmlaunch全报错误码7): 日志控制字段pin=69/proc=FBF99E8C/
//exit=01FC9204/entry=0003EE04, 恰好全部等于各TRUE MSR的高32位(允许为1掩码)。
//机理: 本机TRUE MSR低32位=0(无必须为1的位), 补码公式~0=全1把掩码全开:
//TPR shadow(需APIC虚拟页,未填)+I/O位图(需位图页,未填)+NMI-window(需virtual
//NMI,未开)等控制位一致性检查失败→VM-entry失败错误码7。
//v3.9把v3.7/v3.8的冻结归因于此公式是误诊(真凶是EPT全WB吞MMIO写, v3.8已修)。
ULONG VmxMsrAdjuest(ULONG64 msrNum, ULONG controlValue)
{
	LARGE_INTEGER msrValue;
	msrValue.QuadPart = __readmsr(msrNum);
	return (msrValue.LowPart | controlValue) & msrValue.HighPart;
}

//PASSIVE_LEVEL释放指定CPU的全部VT资源(DriverUload调用)
void VmxFreeCpuResources(ULONG cpuNumber)
{
	if (g_vcpu[cpuNumber].VMCS)
	{
		MmFreeContiguousMemory(g_vcpu[cpuNumber].VMCS);
		g_vcpu[cpuNumber].VMCS = NULL;
	}
	if (g_vcpu[cpuNumber].VMXON)
	{
		MmFreeContiguousMemory(g_vcpu[cpuNumber].VMXON);
		g_vcpu[cpuNumber].VMXON = NULL;
	}
	if (g_vcpu[cpuNumber].VMMStack)
	{
		MmFreeContiguousMemory(g_vcpu[cpuNumber].VMMStack);
		g_vcpu[cpuNumber].VMMStack = NULL;
	}
	if (g_vcpu[cpuNumber].MsrBitMap)
	{
		MmFreeContiguousMemory(g_vcpu[cpuNumber].MsrBitMap);
		g_vcpu[cpuNumber].MsrBitMap = NULL;
	}
	if (g_vcpu[cpuNumber].PeptData)
	{
		MmFreeContiguousMemory(g_vcpu[cpuNumber].PeptData);
		g_vcpu[cpuNumber].PeptData = NULL;
	}
	//释放>512GB动态建立的pdpt页(必须用raw指针: HighPdptVa是4KB对齐后的
	//地址, 不在pool块起始处, 直接ExFreePool会池损坏)
	for (ULONG i = 0; i < 512; i++)
	{
		if (g_vcpu[cpuNumber].HighPdptRawVa[i])
		{
			ExFreePool(g_vcpu[cpuNumber].HighPdptRawVa[i]);
			g_vcpu[cpuNumber].HighPdptRawVa[i] = NULL;
			g_vcpu[cpuNumber].HighPdptVa[i] = NULL;
		}
	}
	g_vcpu[cpuNumber].bInGuest = 0;
	g_vcpu[cpuNumber].bLaunchFailed = 0;
	g_vcpu[cpuNumber].bVmxOn = 0;
}

//v3.39: vmx_off回真机前还原GDTR/IDTR limit(卸载vmcall/逃生两处共用)。
//VM-exit无条件把两个limit压成0xFFFF(SDM 27.5: host-state区只有base
//无limit字段), KEEP期间root模式带0xFFFF跑无害(guest向量全在0xFFF内),
//但vmx_off跳回真机后残留=后续内核/驱动sgdt/sidt读到异常limit。
//base不用动(host-state=launch时写的原值)。**必须在vmx_off之前调用**
//(退出VMX operation后vmread非法)。limit来源=GUEST_GDTR/IDTR_LIMIT
//(guest状态在KEEP期间未被改动, 恒等于launch时快照=真机正确值)。
//描述符布局: WORD limit@+0, QWORD base@+2(reg.asm sgdt读侧同款,
//WDK DESCRIPTOR64 pack(2)格式, 10字节)
static void VmxRestoreDtrLimits(void)
{
	UCHAR dtr[10];
	ULONG64 lim = 0;
	//GDTR
	__vmx_vmread(GUEST_GDTR_LIMIT, &lim);
	*(USHORT*)dtr = (USHORT)lim;
	*(ULONG64*)(dtr + 2) = GetGdtBase();
	VmxLoadGdtr(dtr);
	//IDTR
	__vmx_vmread(GUEST_IDTR_LIMIT, &lim);
	*(USHORT*)dtr = (USHORT)lim;
	*(ULONG64*)(dtr + 2) = GetIdtBase();
	VmxLoadIdtr(dtr);
}

void VmxSetMsrRw(ULONG64 msrNum, UCHAR rw, BOOLEAN flag)
{
	ULONG cpuNumber = KeGetCurrentProcessorNumber();
	//v3.8: 值拷贝->指针(避免8.4KB压栈, 同VmxSetupVmcs)
	PVCPU currentCpu = &g_vcpu[cpuNumber];
	PUCHAR msrBitMapAddr = currentCpu->MsrBitMap;
	ULONG64 msrByteOffset = 0;
	ULONG msrBitOffset = 0;
	if (rw == 1)
	{
		msrBitMapAddr += 1024 * 2;
	}
	if (msrNum >= 0xC0000000)
	{
		msrBitMapAddr += 1024;
		msrNum -= 0xC0000000;
	}
	msrByteOffset = msrNum / 8;
	msrBitOffset = msrNum % 8;
	msrBitMapAddr += msrByteOffset;
	if (flag)
	{
		(*msrBitMapAddr) |= 1 << msrBitOffset;

	}
	else
	{
		(*msrBitMapAddr) &= ~(1 << msrBitOffset);
	}
}

void VmxCpuidHandler(PGUEST_REGS GuestRegs)
{
	//所有leaf先透传真实硬件结果
	int cpuinfo[4] = { 0 };
	__cpuidex(cpuinfo, (int)GuestRegs->rax, (int)GuestRegs->rcx);
	if (GuestRegs->rax == 1)
	{
		//只清ECX bit31(hypervisor present), 隐藏"运行在VT之上"这一事实
		//原版直接返回全零是致命的: CPUID.1携带FPU/SSE2/XSAVE/APIC-ID(EBX 31:24)等
		//特性位, 全零=整颗CPU"退化"成无FPU无APIC的史前芯片, DWM/Defender/
		//新进程特性探测/多线程库的核映射全部行为未定义 -> 运行期整机卡死
		cpuinfo[2] &= ~(1 << 31);
	}
	GuestRegs->rax = cpuinfo[0];
	GuestRegs->rbx = cpuinfo[1];
	GuestRegs->rcx = cpuinfo[2];
	GuestRegs->rdx = cpuinfo[3];
}
void VmxMsrReadHandler(PGUEST_REGS GuestRegs)
{
	//v3.8: 移除DbgPrint——本函数在VM-exit上下文执行, DbgPrint内部锁与被中断
	//线程可能同核重入死锁(位图全零时本case实际不会触发, 属残留地雷)
	ULONG64 msrValue = __readmsr(GuestRegs->rcx);
	GuestRegs->rax = msrValue & 0xFFFFFFFF;
	GuestRegs->rdx = (msrValue >> 32) & 0xFFFFFFFF;
}

void VmxExitHandler(PGUEST_REGS GuestRegs)
{

	ULONG vmexitReason = 0;
	ULONG64 exitCodeLen = 0;
	ULONG64 guestRip = 0;
	ULONG64 guestRsp = 0;
	ULONG64 exitQual = 0;
	__vmx_vmread(VM_EXIT_REASON, &vmexitReason);
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &exitCodeLen);
	__vmx_vmread(GUEST_RIP, &guestRip);
	__vmx_vmread(GUEST_RSP, &guestRsp);
	__vmx_vmread(EXIT_QUALIFICATION, &exitQual);
	vmexitReason = vmexitReason & 0xFFFF;
	//v3.7通用环路检测: 同一(reason,rip)连续重复>500次=不可解exit循环
	//(修不好的violation/推进不了的fault无限重入)。500次在微秒级完成,
	//先于持锁线程的锁级联冻结触发——v3.10起走逃生(vmx_off回真机)而非
	//停核, 其余核与T1继续记录, 主线程也能继续启动后续核。
	//豁免: 48(EPT violation, ept.c有专属风暴检测且hook期同RIP交替属正常)
		//      10(CPUID, 用户态cpuid自旋属合法高频同RIP重复)
		//      1(外部中断, 中断风暴属合法高频同RIP重复)
		//      18(VMCALL)+RIP落在探针代码段: v3.20压测循环=5万次同(18,循环
		//      vmcall地址)exit, 属**设计形态**——v3.20实测被'D'在第502次迭代
		//      误杀: 逃生vmx_off后RIP不推进, 真机重执行vmcall=#UD, 蓝屏
		//      0x1E@c000001d, 故障地址=GeptHooks+0x1055(循环vmcall指令, 与
		//      探针VA+0x103D+24的指令布局推算逐字节吻合)。只豁免探针区间
		//      [CmGuestProbe, CmVmCall)内的vmcall——OS接管阶段的vmcall环路
		//      仍受'D'保护(真环路检测不能丢)
	{
		static volatile LONG s_sameCnt[64] = { 0 };
		static volatile ULONG s_lastReason[64] = { 0 };
		static volatile ULONG64 s_lastRip[64] = { 0 };
		ULONG cpuD = KeGetCurrentProcessorNumber();
		if (cpuD < 64)
		{
			if (vmexitReason == s_lastReason[cpuD] && guestRip == s_lastRip[cpuD])
			{
				if (vmexitReason != EXIT_REASON_EPT_VIOLATION &&
					vmexitReason != EXIT_REASON_CPUID &&
					vmexitReason != EXIT_REASON_EXTERNAL_INTERRUPT &&
					vmexitReason != EXIT_REASON_PENDING_INTERRUPT &&
					//v3.25: 已模拟的指令exit豁免——RDTSC计时自旋/INVLPG
					//同指令高重复(上下文切换同一invlpg调用点)/HLT空闲自旋
					//都是合法同(reason,rip)高频形态
					vmexitReason != EXIT_REASON_RDTSC &&
					vmexitReason != EXIT_REASON_INVLPG &&
					vmexitReason != EXIT_REASON_HLT &&
					vmexitReason != EXIT_REASON_MWAIT_INSTRUCTION &&
					!(vmexitReason == EXIT_REASON_VMCALL &&
						guestRip >= (ULONG64)(ULONG_PTR)CmGuestProbe &&
						guestRip < (ULONG64)(ULONG_PTR)CmVmCall) &&
					InterlockedIncrement(&s_sameCnt[cpuD]) > 500)
				{
					VmxExitStormEscape('D', vmexitReason, guestRip, exitQual,
						GuestRegs);
				}
			}
			else
			{
				s_lastReason[cpuD] = vmexitReason;
				s_lastRip[cpuD] = guestRip;
				s_sameCnt[cpuD] = 1;
			}
		}
	}
	//文件日志: 所有exit按reason计数; EPT violation在EptExitHandler里
	//单独入环(需要gpa), 其余在此采样, 心跳线程每秒落盘到Desktop日志
	if (vmexitReason == EXIT_REASON_EPT_VIOLATION)
	{
		InterlockedIncrement64(&g_flExitCounts[EXIT_REASON_EPT_VIOLATION]);
	}
	else
	{
		FlRingExit(KeGetCurrentProcessorNumber(), vmexitReason, guestRip, exitQual);
	}
	//DbgPrint("code:%d", vmexitReason);
	switch (vmexitReason)
	{
	case EXIT_REASON_CPUID:
	{
		VmxCpuidHandler(GuestRegs);
	}
	break;
	case EXIT_REASON_VMCALL:
	{
		if (GuestRegs->rcx == 1)//表示要退出vt
		{
			//v3.8: Log->FlRingPush(exit上下文禁止DbgPrint, 同核重入死锁)
			FlRingPush('V', KeGetCurrentProcessorNumber(), 18,
				guestRip, exitCodeLen, 0);
			//v3.10: vmx_off后按guest原RFLAGS恢复IF——VM-exit时IF被硬件
			//清0, 跳回后VmxStopCpu的FlLog->KeDelayExecutionThread睡眠
			//依赖时钟中断, IF=0=本核时钟被屏蔽=睡眠永不唤醒=卸载死锁
			ULONG64 vmcallFlags = 0;
			__vmx_vmread(GUEST_RFLAGS, &vmcallFlags);
			//v3.15: vmx_off前invept全上下文——guest期间缓存的EPT派生
			//TLB表项(EPTP标签组合翻译)全部作废, 卸载后真机翻译零残留
			//(sc start/stop循环测试时, 上一轮残留+下一轮同物理页重用
			//=静默错译的经典源)
			//v3.46: 统一入口(能力探测+VMfail留痕, 见ept.c实现)
			EptInveptCurrent();
			//v3.39: 状态一致性——bInGuest清零(旧版漏: KEEP卸载路径
			//从不复位, 卸载流程虽不再读它, 但保持语义正确)
			g_vcpu[KeGetCurrentProcessorNumber()].bInGuest = 0;
			//v3.39: vmx_off前还原GDTR/IDTR limit——VM-exit把两个limit
			//无条件压成0xFFFF(SDM 27.5, host-state无limit字段), 整个
			//KEEP期间root模式带着0xFFFF跑(无害), 但vmx_off回真机后
			//残留=内核读到异常limit(TinyVT VmxPrepareOff/HyperPlatform
			//同款修复)。vmread必须在vmx_off之前(退出VMX operation后
			//vmread非法), 故整个块前置
			VmxRestoreDtrLimits();
			//v3.44: 卸载路径CR3恢复(根因修复)——VM-exit硬件加载HOST_CR3
			//(=vmlaunch时System进程的页表基址, VMX.c填充时快照, launch后
			//永不更新)。vmresume路径每次都会重载GUEST_CR3, 但vmx_off路径
			//没有vmresume: 跳回后本线程(services.exe的SCM线程)带着System
			//页表继续跑——内核半区全进程共享所以FlLog/CR4/亲和切换全部正常
			//(v3.39-3.43五版"干净退出"的假象来源), 但同进程线程切换
			//(KiSwapContext只在进程变化时重载CR3)会把错误页表传播给本核
			//后续调度的同进程线程; 其系统调用写用户缓冲(LPC应答/等待结果,
			//nt+0x2044BE写32B)时用户VA在System页表下零映射→#PF→
			//MmAccessFault判"内核态访问用户VA不允许"(p4=0xF)→蓝屏0x50。
			//v3.43实测: cpu0-4五次退出赌赢, cpu5退出后<500ms赌输。
			//修复=vmx_off后立即写回触发线程自己的CR3(=GUEST_CR3快照,
			//即vmcall时该线程所属进程的DTB)。vmread必须在vmx_off前。
			ULONG64 unloadCr3 = 0;
			__vmx_vmread(GUEST_CR3, &unloadCr3);
			__vmx_off();
			__writecr3(unloadCr3);
			if (vmcallFlags & 0x200)
			{
				_enable();
			}
			//返回到正确的位置——v3.39: 改用VmxJumGuestRegs, 从
			//GuestRegs帧恢复全部非易失GPR(rbx/rbp/rsi/rdi/r12-r15)
			//后再切栈跳转。v3.16-v3.38旧VmxJumGuest只切RSP+JMP:
			//本handler的C代码(编译器自由使用非易失寄存器)早已覆盖
			//它们, 跳回后调用者(CmVmCall的ret→VmxStopCpu)拿垃圾
			//寄存器继续跑——v3.38 KEEP首次真卸载即实测翻车:
			//L01731"cpu3509829504"垃圾参数(cpuNumber被残留值覆盖)
			//+卸载循环垃圾索引访问g_vcpu→蓝屏0x7E@(0xC0000005,
			//driver+0x558F1)。EXIT模式(v3.16)从未暴露此bug: 探针
			//vmcall落点=jmp CmGeustRip, 那条pop链从guest栈恢复了
			//全部寄存器。易失寄存器(rax/rcx/rdx/r8-r11)不恢复:
			//vmcall=x64调用边界, 调用者本就不跨调用持有(ABI合法)
			VmxJumGuestRegs(GuestRegs, guestRsp, guestRip + exitCodeLen);
		}
		//EPT hook
		else if (GuestRegs->rcx == 2)
		{
			EptSetHook(GuestRegs->rdx, GuestRegs->r8);
		}
		//v3.13落地探针(唯一合法来源=CmGuestProbe首条vmcall, 探针页已过
		//launch前EptVerifyTables[5]样本走查): 看到它=全链路自证通过
		//"VM-entry转换+EPT取指翻译+vmcall exit+本handler+RIP推进+vmresume"。
		//'W'入环由T1落盘——v3.12冻结形态是"vmlaunch后零环标记", 有W/无W
		//直接二分: 冻结在落地前(entry转换/EPT取指)还是落地后(栈恢复/ret
		//回VMXInitCpuStart)。放行走函数末尾通用RIP推进, 探针jmp CmGeustRip
		else if (GuestRegs->rcx == GEPT_PROBE_MAGIC)
		{
			FlRingPush('W', KeGetCurrentProcessorNumber(), 18,
				guestRip, exitQual, exitCodeLen);
		}
		//v3.14 probe第二段(能执行到此=vmresume已成功过): GEPT_PROBE_EXIT=1
		//自测模式——vmx_off立即回真机, guest不接管任何OS执行。
		//v3.17起GEPT_PROBE_EXIT=0(接管模式): 本分支编译为空, 落到函数
		//末尾通用RIP推进——探针jmp CmGeustRip恢复栈, ret回
		//VMXInitCpuStart在non-root继续, 该核从此运行在EPT之下
		else if (GuestRegs->rcx == 3)
		{
#if GEPT_PROBE_EXIT
			FlRingPush('K', KeGetCurrentProcessorNumber(), 18,
				guestRip, exitQual, exitCodeLen);
			ULONG64 probeFlags = 0;
			__vmx_vmread(GUEST_RFLAGS, &probeFlags);
			//v3.15: vmx_off前invept全上下文——guest窗口期间缓存的EPT
			//派生TLB表项全部作废。v3.14的4次测试中2次间歇性死亡
			//(win32kfull蓝屏/冻结), TLB残留(尤其sc start/stop循环时
			//下轮重用同物理页)是候选根因之一, 此处彻底排除
			//v3.46: 统一入口(能力探测+VMfail留痕)
			EptInveptCurrent();
			//v3.26: vmx_off前排空积压in-service债(与VmxExitStormEscape
			//同款)——v3.25起IF=1, 探针窗内注入的ISR运行时(IF=0中断门)
			//到达的ext-int会入队; 'K'直接vmx_off=队列vector永卡LAPIC
			//in-service=真机上中断屏蔽=v3.17-25冻结同款机理!
			//x2APIC(IA32_APICBASE bits11:10=10)用WRMSR 0x80B清
			{
				ULONG probeCpuX = KeGetCurrentProcessorNumber();
				if (g_vcpu[probeCpuX].PendingIntrCount > 0)
				{
					ULONG64 apicBaseX = __readmsr(0x1B);
					if ((apicBaseX & 0xC00) == 0xC00)
					{
						for (LONG pk = 0; pk < g_vcpu[probeCpuX].PendingIntrCount; pk++)
						{
							__writemsr(0x80B, 0);
						}
					}
					g_vcpu[probeCpuX].PendingIntrCount = 0;
				}
			}
			//v3.39: vmx_off前还原GDTR/IDTR limit(同rcx==1路径)
			VmxRestoreDtrLimits();
			//v3.44: CR3恢复(同rcx==1卸载路径, 见其注释; vmread必须在
			//vmx_off前)
			ULONG64 probeExitCr3 = 0;
			__vmx_vmread(GUEST_CR3, &probeExitCr3);
			__vmx_off();
			__writecr3(probeExitCr3);
			ULONG64 probeCr4 = __readcr4();
			probeCr4 &= ~0x2000;              //清CR4.VMXE, 干净回真机
			__writecr4(probeCr4);
			ULONG probeCpu = KeGetCurrentProcessorNumber();
			g_vcpu[probeCpu].bVmxOn = 0;
			g_vcpu[probeCpu].bLaunchFailed = 1;
			//v3.29: IF0窗下probeFlags.IF=0→跳过sti(真机IF由
			//VMXInitCpuStart的CmGuestRsp后_enable()统一恢复)
			if (probeFlags & 0x200)
			{
				_enable();
			}
			//跳回vmcall下一条(=探针的jmp CmGeustRip): 真机执行纯栈恢复,
			//ret回VMXInitCpuStart后走bLaunchFailed分支, 串行启动下一核
			//(v3.39: 用VmxJumGuestRegs恢复非易失GPR——落点是探针的
			//纯jmp+pop链虽会重恢复, 但统一出口零成本更稳妥)
			VmxJumGuestRegs(GuestRegs, guestRsp, guestRip + exitCodeLen);
#endif
			//GEPT_PROBE_EXIT=0(接管模式): 不做任何事, 落到函数末尾通用
			//RIP推进, 探针jmp CmGeustRip后guest正式接管OS执行
		}
		//v3.20/v3.25: 持续执行压测循环(探针②段, 8192次vmcall≈8ms)——
		//每1024次采样1条'L'(a=rbx剩余值)。若冻结发生在循环中, 最后
		//落盘的'L'的a值=死亡迭代号(8192-a); HB的r18计数为精确总量。
		//v3.25起IF=1: 循环中的rsn=1事件=中断即时注入的活体证明。
		//注意: 本分支不推'E'(FlRingExit已把r18环采样限到64条,
		//否则数千事件刷爆环把[W][F]等标记挤出去)
		else if (GuestRegs->rcx == 4)
		{
			if ((GuestRegs->rbx & 0x3FF) == 0)
			{
				FlRingPush('L', KeGetCurrentProcessorNumber(), 18,
					GuestRegs->rbx, 0, 0);
			}
		}
		//v3.20: 探针③段——5万次循环完成(rbx=0), 即将进入rcx=3分流。
		//'Y'落盘后死亡=[rcx=3的exit→vmresume→jmp CmGeustRip→add/pop/ret
		//→_enable→FlLog]窗口; 无'Y'=死在循环内(看最后'L'的a值)
		//(用'Y'不用'X': 'X'已被violation风暴逃生占用)
		else if (GuestRegs->rcx == 6)
		{
			FlRingPush('Y', KeGetCurrentProcessorNumber(), 18,
				GuestRegs->rbx, 0, 0);
		}
	}
	break;
	case EXIT_REASON_INVD:
	{

		VmxInvd();
	}
	break;
	case EXIT_REASON_WBINVD:
	{
		//INVD/WBINVD在guest内无条件VM-exit, 必须由VMM代执行
		//缺此case会落进default被"推进RIP跳过", 缓存写回丢失->隐蔽的数据损坏
		__wbinvd();
	}
	break;
	//=============== v3.25: must-1强制exit的指令模拟 ===============
	//v3.25注释(已被v3.27的SDM裁决修正): 曾按"经典KVM布局"推断本机
	//PROC低32位0x04006172的置位集{1,4,5,6,8,13,14,26}中 bit4=HLT/
	//bit5=INVLPG/bit6=MWAIT/bit8=RDTSC exiting被强制开启。
	//**SDM(本PDF, Table 27-6, 27-11页)裁决: 本世代表布局为 bit7=HLT/
	//bit9=INVLPG/bit10=MWAIT/bit12=RDTSC/bit19,20=CR8**, 而must-1集
	//{1,4,5,6,8,13,14,26}全部落在**非控制位空洞**(三重交叉验证: bit0
	//固定0/13,14为must-1保留位/17,18禁设)——即本机这些指令exiting
	//全部关闭, 以下case大概率永不触发(保留无害, 若未来日志见r16/r14
	//计数>0则证明经典布局成立, 届时这些模拟就是必需的)
	case EXIT_REASON_RDTSC:
	{
		//TSC直通: root读真实TSC回填rax/rdx(本机bit3 TSC-offsetting=0,
		//无偏移语义)。不碰ecx(RDTSC本就不写ecx; RDTSCP才写——罕见,
		//v1先不管)。每次exit走完整handler, 计数留痕(r16)
		ULONG64 tsc = __rdtsc();
		GuestRegs->rax = tsc & 0xFFFFFFFF;
		GuestRegs->rdx = tsc >> 32;
	}
	break;
	case EXIT_REASON_INVLPG:
	{
		//INVLPG代执行: EXIT_QUALIFICATION=操作的线性地址。
		//root与guest共用CR3(恒等虚拟化), root执行invlpg语义一致
		//(guest侧由EPT翻译, invept由v3.15的exit前全上下文冲刷覆盖)
		__invlpg((void*)(ULONG_PTR)exitQual);
	}
	break;
	case EXIT_REASON_HLT:
	{
		//v1: 空转模拟(跳过hlt指令)。空闲线程会自旋+每次循环exit一次
		//(exit风暴~1M/s, 已豁免'D'环检+环采样限流, 可承受);
		//v3.26再做正确的HLT(activity state + 注入唤醒)
		//什么都不做, 落到函数尾通用RIP推进=跳过hlt
	}
	break;
	case EXIT_REASON_MWAIT_INSTRUCTION:
	{
		//MWAIT v1同HLT: 跳过(空转)。MONITOR(39)无副作用, 同跳过
	}
	break;
	case EXIT_REASON_MONITOR_INSTRUCTION:   //39
	{
		//MONITOR: 建立监控地址, 无架构可见副作用, 跳过即可
	}
	break;
	case EXIT_REASON_MSR_READ:
	{
		VmxMsrReadHandler(GuestRegs);
	}
	break;
	case EXIT_REASON_MSR_WRITE:
	{
		//WRMSR代执行: rdx:rax=64位值, rcx=MSR号(SDM 25.1.2寄存器映射)
		//此前缺此case: 落default被"推进RIP"=写被静默丢弃 —— 整机冻结根因C
		__writemsr(GuestRegs->rcx,
			((ULONG64)GuestRegs->rdx << 32) | (GuestRegs->rax & 0xFFFFFFFF));
	}
	break;
	case EXIT_REASON_XSETBV:   //55
	{
		//v3.37(TinyVT调研行动项): XSETBV在non-root**无条件**VM-exit
		//(SDM 25.1.3), 与ctls2许可位无关。TinyVT(VmExitHandler.cpp
		//ExitXsetbv)/HyperPlatform均代执行。缺此case=落default走'U'
		//未知exit逃生(vmx_off静默脱离VT, EPT hook全失效且无人知晓)。
		//rcx=XCR索引, rdx:rax=64位值(寄存器映射同WRMSR)
		_xsetbv((unsigned int)GuestRegs->rcx,
			((ULONG64)GuestRegs->rdx << 32) | (GuestRegs->rax & 0xFFFFFFFF));
	}
	break;
	case EXIT_REASON_TRIPLE_FAULT:
	{
		//三重故障: guest状态已不可恢复(异常级联), 不能重执行(真机三重
		//故障=重启)。v3.35: 停核→park——vmx_off+sti/hlt自旋继续服务
		//中断, 切断"IF=0停核→IPI发送核自旋→全机冻结"的级联(v3.30-34
		//五连冻结+看门狗死的统一解释), 机器存活, 'T'+环尾由T1落盘
		VmxTripleFaultPark();    //noreturn
	}
	break;
	case EXIT_REASON_INVALID_GUEST_STATE:
	{
		//v3.10关键case: VM-entry failure(vmlaunch时guest状态非法, 如
		//CR0/CR4固定位不符/EFER不一致/段AR保留位非0)。控制流已跳到
		//HOST_RIP而非vmlaunch下一条——主线程此刻停在vmlaunch调用点,
		//GUEST_RSP=启动栈。逃生跳回入口: 恢复栈+ret后主线程从
		//CmGuestRsp()调用返回, 判bLaunchFailed走失败分支, 继续启动
		//后续核(系统不冻结, 死因'G'由T1落盘)。
		//v3.9及以前缺此case: 落default len=0 -> 'Z'停核cpu0 -> loader锁
		//挂死+磁盘中断级联 -> "vmlaunch后零心跳冻结"
		//v3.13: GUEST_RIP现指向CmGuestProbe(落地探针), 但本场景从未
		//真正进入guest——逃生若跳回探针, 其vmcall在真机模式=#UD蓝屏!
		//必须改写RIP到CmGeustRip(纯栈恢复代码, 真机可安全执行),
		//逃生才能干净地回到VMXInitCpuStart失败分支
		//v3.25: 33有两类场景, 必须区分——launch期(vmlaunch入口失败:
		//guestRip=探针区间, GUEST_RSP=启动栈)才做CmGeustRip改写;
		//运行期(注入vmresume入口失败: guestRip=被中断的OS上下文,
		//GUEST_RSP=OS线程栈)若仍改写=在OS栈上执行add rsp,28h+pop×16
		//+ret=栈粉碎蓝屏! 直接逃回被中断上下文(真机续跑该指令)
		if (guestRip >= (ULONG64)(ULONG_PTR)CmGuestProbe &&
			guestRip < (ULONG64)(ULONG_PTR)CmVmCall)
		{
			__vmx_vmwrite(GUEST_RIP, CmGeustRip);
		}
		VmxExitStormEscape('G', 33, guestRip, exitQual, GuestRegs);    //noreturn
	}
	break;
	case EXIT_REASON_EXTERNAL_INTERRUPT:
	{
		//v3.36: pin期望=0(外部中断直投guest), 本case**理论不可达**。
		//原v3.19-3.35的注入状态机(IF判别+VM_ENTRY_INTR_INFO注入+
		//PendingIntrVec入队+开窗)整段删除——调研裁决见VmxSetupVmcs
		//控制字段段注释: 五个成熟项目(HyperPlatform/hvpp/SimpleVisor/
		//HyperDbg/TinyVT)全部直投, ack-on-exit+注入状态机=EOI债/
		//窗口位/优先级/MP竞争四重雷区(UC Ophion帖实锤冻结机理,
		//v3.30-3.35五连零事件冻结同签名)。
		//防御: 万一到达(pin配置未生效)='I'标记留痕, 同核超100次=
		//配置异常风暴, 逃生'J'留死因, 不拖全机
		ULONG64 intrInfo = 0;
		__vmx_vmread(VM_EXIT_INTR_INFO, &intrInfo);
		ULONG cpuX = KeGetCurrentProcessorNumber();
		FlRingPush('I', cpuX, 1, intrInfo & 0xFF, intrInfo, 0);
		static volatile LONG s_iCnt[64] = { 0 };
		if (InterlockedIncrement(&s_iCnt[cpuX & 63]) > 100)
		{
			VmxExitStormEscape('J', 1, intrInfo, guestRip, GuestRegs);    //noreturn
		}
		//非指令性exit: 原样写回RIP, 绝不能推进。无ack-on-exit时中断
		//仍在LAPIC IRR, resume后guest IF=1时硬件自行投递(零丢失)
		__vmx_vmwrite(GUEST_RIP, guestRip);
		return;
	}
	break;
	case EXIT_REASON_PENDING_INTERRUPT:   //7: interrupt-window exiting=guest可中断了
	{
		//v3.36: 窗口从未开启(proc期望无bit2, case1入队逻辑已删),
		//本case**理论不可达**。防御: 'J'标记留痕后放行
		FlRingPush('J', KeGetCurrentProcessorNumber(), 7, guestRip, 0, 0);
		//非指令性exit: 原样写回RIP, 绝不能推进
		__vmx_vmwrite(GUEST_RIP, guestRip);
		return;
	}
	break;
	case EXIT_REASON_EPT_VIOLATION:
	{
		EptExitHandler(GuestRegs);
		return;
	}
	break;
	case EXIT_REASON_EPT_CONFIG:
	{
		//EPT misconfiguration: PTE格式非法(非指令性exit, 不能推进RIP)
		//出现说明EPT页表有结构性bug(如页表页未4KB对齐)。计数留痕,
		//超1000次=修复无效, v3.10走逃生(vmx_off回真机重执行)而非停核
		static volatile LONG eptCfgCount = 0;
		ULONG64 cfgGpa = 0;
		__vmx_vmread(GUEST_PHYSICAL_ADDRESS, &cfgGpa);
		if (InterlockedIncrement(&eptCfgCount) == 1)
		{
			FlRingPush('C', KeGetCurrentProcessorNumber(), 49,
				cfgGpa, guestRip, 0);
		}
		if (eptCfgCount > 1000)
		{
			VmxExitStormEscape('X', 49, cfgGpa, guestRip, GuestRegs);    //noreturn
		}
	}
	return;
	default:
	{
		//v3.10: 未知exit reason——指令未模拟执行, **绝不能推进RIP**:
		//  len>0推进 = 静默跳过指令(CR3-load被丢=地址空间错乱,
		//             WRMSR被丢=APIC EOI吞掉=中断卡死, v3.8的教训)
		//  len=0推进 = 原地重执行 = 无限循环
		//也不能原地vmresume重试(同因exit必然再来)。正确动作=逃生:
		//vmx_off回真机模式重执行该指令(真机无VMCS控制位拦截, 必然
		//正常执行), 'U'(len>0)/'Z'(len=0)标记由T1落盘, 系统继续跑
		VmxExitStormEscape(exitCodeLen == 0 ? 'Z' : 'U',
			vmexitReason, guestRip, exitQual, GuestRegs);    //noreturn
	}
	break;
	}
	__vmx_vmwrite(GUEST_RIP, guestRip + exitCodeLen);
}




//vmresume失败处理(asm VmxResumeFailed跳入, 永不返回)
//v3.10: 停核->逃生。vmresume的VMfail(VMCS状态坏)不影响vmx_off逃生:
//GUEST_RIP/RSP/RFLAGS仍可从VMCS读出, 跳回guest重执行;'R'标记入环留死因
void VmxResumeFailedEntry(void)
{
	//v3.39: guestRegs=NULL——本路径的GPR已被asm的pop链恢复(vmresume
	//失败点在HVM_RESTORE_ALL_NOSEGREGS之后), 无帧可传也无需恢复
	VmxExitStormEscape('R', 0, 0, 0, NULL);
}

//风暴逃生(v3.10, 永不返回): 标记入环后vmx_off脱离VT, 跳回guest触发点
//重执行。**所有逃生场景的指令都未成功执行, RIP一律不推进**(推进=静默
//丢弃指令效果: CR3-load被跳过=地址空间错乱, len=0推进=原地死循环)。
//v3.21唯一例外: reason=18(VMCALL)必须推进RIP——vmcall在真机模式=非法
//指令(#UD), 不推RIP跳回=真机重执行vmcall=必然蓝屏0x1E@c000001d。
//v3.20实测: 'D'误杀探针压测循环(5万次同(18,rip)未豁免)→逃生不推RIP
//→真机vmcall→蓝屏@GeptHooks+0x1055。reason=18的exit唯一来源就是vmcall
//指令本身, len恒=3, 推进=跳过它(它对真机本就无意义), 安全。
//v3.7-v3.9的"停核"方案实测有级联冻结: cpu0停核后落在该核的磁盘/时钟
//中断永不完成 -> T1的ZwWriteFile挂死 -> 死因标记困在内存环+心跳全停
//= "停在cpu0 vmlaunch+零[HB]"的零信息冻结(三次实测同一形态)。
//逃生后本核回真机模式: 中断正常、主线程从CmGuestRsp()返回继续启动
//后续核(bLaunchFailed=1防误判成功)、系统与其余核无感、T1必活->死因必然落盘。
//IF恢复: VM-exit时RFLAGS.IF被硬件清0; 跳回前按GUEST_RFLAGS原值恢复——
//guest原IF=0(其临界区)时强制sti会破坏其临界区, 必须按原值还原。
//tag: 'X'=violation/misconfig风暴 'A'=动态建表失败 'P'=低地址环路
//     'D'=同(reason,rip)通用环路 'Z'=len0未知exit 'U'=len>0未知exit
//     'R'=vmresume失败 'G'=VM-entry failure(guest状态非法)
void VmxExitStormEscape(char tag, ULONG reason, ULONG64 a, ULONG64 b,
	PVOID guestRegs)
{
	ULONG cpu = KeGetCurrentProcessorNumber();
	FlRingPush(tag, cpu, reason, a, b, 0);
	//vmread必须在vmx_off之前(退出VMX operation后vmread非法)
	ULONG64 guestRsp = 0, guestRip = 0, guestRflags = 0;
	__vmx_vmread(GUEST_RSP, &guestRsp);
	__vmx_vmread(GUEST_RIP, &guestRip);
	__vmx_vmread(GUEST_RFLAGS, &guestRflags);
	//v3.21: 触发指令=vmcall时必须推RIP再跳(见函数头注释)。
	//len需vmread(在vmx_off前); 'R'路径reason=0不触发; 'G'路径GUEST_RIP
	//已被改写为CmGeustRip且reason=33不触发——互不干扰
	if (reason == EXIT_REASON_VMCALL)
	{
		ULONG64 vmcallLen = 0;
		__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &vmcallLen);
		if (vmcallLen > 0 && vmcallLen <= 15)
		{
			guestRip += vmcallLen;
		}
	}
	//v3.15: vmx_off前invept全上下文(EPT派生TLB零残留, 同[K]路径理由)
	//v3.46: 统一入口(能力探测+VMfail留痕)
	EptInveptCurrent();
	//v3.39: vmx_off前还原GDTR/IDTR limit(VM-exit强制0xFFFF, 见
	//VmxRestoreDtrLimits注释; 同样必须前置=vmread依赖VMX operation)
	VmxRestoreDtrLimits();
	//v3.44: CR3恢复(同rcx==1卸载路径, 见其注释)——逃生=随机guest线程
	//执行中vmx_off回真机, VM-exit加载的HOST_CR3(System进程DTB)同样
	//残留; 逃逸线程带着System页表继续跑OS代码, 其任何用户VA访问
	//(系统调用写用户缓冲)都会蓝屏0x50/0xF。vmread必须在vmx_off前。
	ULONG64 escapeCr3 = 0;
	__vmx_vmread(GUEST_CR3, &escapeCr3);
	__vmx_off();
	__writecr3(escapeCr3);
	ULONG64 cr4 = __readcr4();
	cr4 &= ~0x2000;              //清CR4.VMXE, 干净回真机
	__writecr4(cr4);
	g_vcpu[cpu].bVmxOn = 0;
	g_vcpu[cpu].bInGuest = 0;
	g_vcpu[cpu].bLaunchFailed = 1;   //主线程判此标志走失败分支(不再冻结)
	//v3.23: 逃生前清积压中断的in-service债——ack on exit使PendingIntr队列
	//里的vector已被ack进LAPIC ISR, 逃生后真机永不跑其ISR=永不EOI, 不清则
	//≤其优先级的全部中断在本核被永久屏蔽(v3.17-21冻结轮盘的机理, 详见
	//EXIT_REASON_EXTERNAL_INTERRUPT case注释)。x2APIC的EOI=MSR 0x80B;
	//xAPIC(MMIO 0xFEE000B0)需映射, 现代Windows默认x2APIC, 略过
	if (g_vcpu[cpu].PendingIntrCount > 0)
	{
		ULONG64 apicBase = __readmsr(0x1B);       //IA32_APICBASE
		if ((apicBase & 0xC00) == 0xC00)          //bits11:10=10: x2APIC使能
		{
			for (LONG pe = 0; pe < g_vcpu[cpu].PendingIntrCount; pe++)
			{
				__writemsr(0x80B, 0);             //EOI: 清一条in-service
			}
		}
		g_vcpu[cpu].PendingIntrCount = 0;         //xAPIC时只能弃(计数清零防重复)
	}
	if (guestRflags & 0x200)
	{
		_enable();               //已脱离VMX, 恢复guest原始IF
	}
	//v3.39: 跳回出口分流——guestRegs非NULL(exit handler的C上下文调用):
	//先从帧恢复全部非易失GPR再切栈跳(同rcx==1卸载路径, 防"垃圾寄存器
	//回真机"蓝屏, 见VmxJumGuestRegs注释); NULL(VmxResumeFailedEntry):
	//寄存器已被asm的pop链恢复, 直接切栈跳(旧VmxJumGuest语义)
	if (guestRegs != NULL)
	{
		VmxJumGuestRegs(guestRegs, guestRsp, guestRip);
	}
	VmxJumGuest(guestRsp, guestRip); //重执行触发指令(真机无VMCS拦截, 必然通过)
}

//三重故障专用park(v3.35重写v3.10停核版, 永不返回): guest已异常级联
//不可恢复, 逃生**重执行**=真机三重故障=重启。但v3.10的"_disable+__halt"
//停核被v3.30-34五连冻结判读推翻: IF=0停核=本核IPI永不处理=各核的
//TLB-flush广播发送核自旋等待(持锁, DISPATCH级)=全机级联冻结→T1死+
//看门狗线程死(cpu0/1也不再调度PASSIVE线程)=观测全盲。park新方案:
//'T'入环+清EOI债+vmx_off脱离VT+**sti+hlt自旋**(见common-asm.asm)——
//本核继续服务一切中断, 发送核等待解除, 机器存活, T1把'T'+环尾(最后
//exit的RIP/vector!)全部落盘。代价: 本核线程永久park(sc start不返回,
//可接受), 驱动不得卸载(main.c守卫拒绝, park代码页/VMM栈仍被占用)。
//注意: 此处不调FlLog(IRQL未知, 其睡眠等待非法), 只FlRingPush(任意IRQL安全)
void VmxTripleFaultPark(void)
{
	ULONG cpu = KeGetCurrentProcessorNumber();
	FlRingPush('T', cpu, 2, 0, 0, 0);
	//EOI债: pin17+ack-on-exit期间ack进LAPIC in-service但未投递的vector
	//(同'K'路径的清债逻辑)——不清则真机上这些vector永久屏蔽中断
	if (g_vcpu[cpu].PendingIntrCount > 0)
	{
		ULONG64 apicBase = __readmsr(0x1B);
		if ((apicBase & 0xC00) == 0xC00)          //x2APIC
		{
			for (LONG pe = 0; pe < g_vcpu[cpu].PendingIntrCount; pe++)
			{
				__writemsr(0x80B, 0);             //EOI: 清一条in-service
			}
		}
		g_vcpu[cpu].PendingIntrCount = 0;
	}
	//脱离VMX(此刻仍在exit上下文/VMM栈, host状态合法)
	//v3.46: 统一入口(能力探测+VMfail留痕)——EPT派生TLB残留全作废(同'K')
	EptInveptCurrent();
	__vmx_off();
	ULONG64 cr4 = __readcr4();
	cr4 &= ~0x2000;                               //清CR4.VMXE, 干净回真机
	__writecr4(cr4);
	g_vcpu[cpu].bVmxOn = 0;
	g_vcpu[cpu].bInGuest = 0;
	g_vcpu[cpu].bLaunchFailed = 1;                //卸载路径跳过本核vmcall
	//park位掩码(main.c卸载守卫): park核的VMM栈/park代码页不能释放
	InterlockedOr(&g_geptParkedMask, (LONG)(1UL << (cpu & 31)));
	//park本体(asm, 永不返回): sti+hlt自旋持续服务中断, 切断级联冻结
	CmTripleFaultPark();
}

int VmxSetupVmcs(PVOID GuestRsp)
{
	ULONG cpuNumber = KeGetCurrentProcessorNumber();
	//v3.8: 值拷贝->指针。VCPU含HighPdptVa[512]+HighPdptRawVa[512]约8.4KB,
	//原写法每次调用把整个结构体压进内核栈(内核栈仅12-24KB, 深路径下
	//栈溢出=蓝屏0x1E/栈损坏, 极其隐蔽)
	PVCPU currentCpu = &g_vcpu[cpuNumber];
	//DbgBreakPoint();
	//分段面包屑[1/6]: 每段FlLog同步落盘后才前进——蓝屏时最后一行=崩溃段
	FlLog("cpu%u VMCS[1/6]: 段寄存器...", cpuNumber);
	VmxFillSelectorData(RegGetEs(), 0);
	VmxFillSelectorData(RegGetCs(), 1);
	VmxFillSelectorData(RegGetSs(), 2);
	VmxFillSelectorData(RegGetDs(), 3);
	VmxFillSelectorData(RegGetFs(), 4);
	VmxFillSelectorData(RegGetGs(), 5);
	VmxFillSelectorData(GetLdtr(), 6);

	__vmx_vmwrite(HOST_ES_SELECTOR, RegGetEs() & 0XFFF8);
	__vmx_vmwrite(HOST_CS_SELECTOR, RegGetCs() & 0XFFF8);
	__vmx_vmwrite(HOST_SS_SELECTOR, RegGetSs() & 0XFFF8);
	__vmx_vmwrite(HOST_DS_SELECTOR, RegGetDs() & 0XFFF8);
	__vmx_vmwrite(HOST_FS_SELECTOR, RegGetFs() & 0XFFF8);
	__vmx_vmwrite(HOST_GS_SELECTOR, RegGetGs() & 0XFFF8);
	//填充TR寄存器
	FlLog("cpu%u VMCS[2/6]: TR+FS/GS base...", cpuNumber);
	USHORT trSelector = GetTrSelector();
	trSelector = trSelector &= 0xFFF8;
	ULONG trLimit = __segmentlimit(trSelector);
	ULONG64 gdtBase = GetGdtBase();
	LARGE_INTEGER trSegement = { 0 };
	PULONG trContext = (PULONG)(gdtBase + trSelector);
	trSegement.LowPart = ((trContext[0] >> 16) & 0xFFFF) | ((trContext[1] & 0xFF) << 16) | ((trContext[1] & 0xFF000000));
	trSegement.HighPart = trContext[2];
	ULONG trAttr = (trContext[1] & 0x00F0FF00) >> 8;
	g_dbgTrAr = trAttr;   //指纹留痕(v3.10)
	__vmx_vmwrite(GUEST_TR_BASE, trSegement.QuadPart);
	__vmx_vmwrite(GUEST_TR_LIMIT, trLimit);
	__vmx_vmwrite(GUEST_TR_AR_BYTES, trAttr);
	__vmx_vmwrite(GUEST_TR_SELECTOR, trSelector);
	__vmx_vmwrite(HOST_TR_BASE, trSegement.QuadPart);
	__vmx_vmwrite(HOST_TR_SELECTOR, trSelector);

	__vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));
	__vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));
	__vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
	__vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));
	//CR
	FlLog("cpu%u VMCS[3/6]: CR/DR7/MSR状态...", cpuNumber);
	__vmx_vmwrite(GUEST_CR0, __readcr0());
	__vmx_vmwrite(GUEST_CR3, __readcr3());
	__vmx_vmwrite(GUEST_CR4, __readcr4());
	__vmx_vmwrite(GUEST_DR7, __readdr(7));
	__vmx_vmwrite(HOST_CR0, __readcr0());
	__vmx_vmwrite(HOST_CR3, __readcr3());
	__vmx_vmwrite(HOST_CR4, __readcr4());
	//IA_32
	__vmx_vmwrite(VMCS_LINK_POINTER, -1);
	__vmx_vmwrite(VMCS_LINK_POINTER_HIGH, -1);
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL));
	__vmx_vmwrite(GUEST_IA32_PAT, __readmsr(MSR_IA32_PAT));
	__vmx_vmwrite(GUEST_IA32_EFER, __readmsr(MSR_IA32_EFER));
	//host PAT/EFER: VMexit时host按此加载IA32_PAT/EFER——VMclear后为0,
	//而VM_EXIT_CONTROLS含"host address-space size"=64位host → 不填必vmlaunch error 8
	//(myVt原版遗漏; 此前vmlaunch没走到这一步就先在别处蓝屏, 修好当前崩溃后必踩)
	__vmx_vmwrite(HOST_IA32_PAT, __readmsr(MSR_IA32_PAT));
	__vmx_vmwrite(HOST_IA32_EFER, __readmsr(MSR_IA32_EFER));

	//sysenter
	__vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	__vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	__vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	__vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	//__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));

	//GDT
	FlLog("cpu%u VMCS[4/6]: GDTR/IDTR/RSP/RIP...", cpuNumber);
	__vmx_vmwrite(GUEST_GDTR_BASE, GetGdtBase());
	__vmx_vmwrite(GUEST_GDTR_LIMIT, GetGdtLimit());
	__vmx_vmwrite(HOST_GDTR_BASE, GetGdtBase());
	//IDT
	__vmx_vmwrite(GUEST_IDTR_BASE, GetIdtBase());
	__vmx_vmwrite(GUEST_IDTR_LIMIT, GetIdtLimit());
	__vmx_vmwrite(HOST_IDTR_BASE, GetIdtBase());
	//guest rsp rip
	__vmx_vmwrite(GUEST_RSP, GuestRsp);
	//v3.13: GUEST_RIP指向落地探针(不再直接CmGeustRip)。探针首条vmcall
	//自证"VM-entry转换+EPT取指翻译+VM-exit+RIP推进+vmresume"全链路,
	//handler推'W'环标记后放行, 探针jmp CmGeustRip恢复栈正常落地。
	//探针不触碰RSP(GUEST_RSP仍=CmGuestRsp保存值, 供CmGeustRip的add/pop/ret
	//恢复), 也不依赖GPR(VMCS不保存GPR, 落地时GPR是launch现场垃圾值,
	//CmGeustRip的pop会从栈恢复全部寄存器), 见common-asm.asm CmGuestProbe
	__vmx_vmwrite(GUEST_RIP, CmGuestProbe);
	__vmx_vmwrite(GUEST_RFLAGS, __readeflags());
	__vmx_vmwrite(HOST_RSP, (ULONG64)currentCpu->VMMStack + PAGE_SIZE * 5);
	__vmx_vmwrite(HOST_RIP, VmxVmexitHandler);
	ULONG64 basicMsr = __readmsr(MSR_IA32_VMX_BASIC);
	//VMX_BASIC bit55: TRUE能力MSR存在标志。存在则用TRUE MSR(0x48D-0x490,
	//如实上报必须为1的位), 否则用旧式MSR(0x481-0x484, default1类位恒读1)。
	//v3.12裁决: 两种MSR位语义相同(见VmxMsrAdjuest注释), 经典公式通吃,
	//此标志只决定读哪组MSR。v3.9-v3.11b曾误判语义相反引入补码公式→8核
	//vmlaunch错误码7(实测控制字段=各TRUE MSR高32位, 即掩码被全开)
	BOOLEAN useTrueCtl = ((basicMsr >> 55) & 1) != 0;
	ULONG64 result = 0;
	ULONG64 entryMsrNum = MSR_IA32_VMX_ENTRY_CTLS;
	ULONG64 exitMsrNum = MSR_IA32_VMX_EXIT_CTLS;
	ULONG64 pinMsr = MSR_IA32_VMX_PINBASED_CTLS;
	ULONG64	procMsr = MSR_IA32_VMX_PROCBASED_CTLS;
	if (useTrueCtl)
	{
		entryMsrNum = MSR_IA32_VMX_TRUE_ENTRY_CTLS;
		exitMsrNum = MSR_IA32_VMX_TRUE_EXIT_CTLS;

		pinMsr = MSR_IA32_VMX_TRUE_PINBASED_CTLS;
		procMsr = MSR_IA32_VMX_TRUE_PROCBASED_CTLS;
	}
	FlLog("cpu%u VMCS[5/6]: 控制字段+MSR位图 (bit55=%d)...", cpuNumber, (int)useTrueCtl);
	//v3.14: 能力MSR原值一次性落盘(全部后续判读的最终依据)。高32=允许为1
	//掩码, 低32=必须为1位。结合控制字段行可反解每个位的来源; v3.13实测
	//本机pin=0x16(bits1,2,4=default1类保留位, SDM Table27-5裁决: 本机
	//三个可选控制全部关闭的合法最小值)
	{
		static volatile LONG s_msrLogged = 0;
		if (InterlockedCompareExchange(&s_msrLogged, 1, 0) == 0)
		{
			FlLog("MSR原值: PIN=%llX PROC=%llX EXIT=%llX ENTRY=%llX (实际读取的%s)",
				(unsigned long long)__readmsr(pinMsr),
				(unsigned long long)__readmsr(procMsr),
				(unsigned long long)__readmsr(exitMsrNum),
				(unsigned long long)__readmsr(entryMsrNum),
				useTrueCtl ? "TRUE MSR" : "旧式MSR");
			FlLog("MSR原值: SEC(48Bh)=%llX EPT_VPID_CAP(48Ch)=%llX",
				(unsigned long long)__readmsr(MSR_IA32_VMX_PROCBASED_CTLS2),
				(unsigned long long)__readmsr(MSR_IA32_VMX_EPT_VPID_CAP));
		}
	}
	//v3.12: 经典公式(低32|期望)&高32对新旧MSR都正确(见VmxMsrAdjuest注释),
	//不再有trueCtl参数; secondary(0x48B)本就无TRUE变体, 亦同公式
	//v3.36调研裁决: pin期望回到**0**(外部中断直投guest, 不exit不注入)。
	//v3.19-3.35开ext-int exiting+ack-on-exit+interrupt-window注入状态机
	//(十六个版本的冻结泥潭)被外部调研彻底否决:
	//  ①五个成熟项目全部不拦截外部中断——HyperPlatform(git考古2016至今
	//    从未开过, 作者还专门删了无用的ack-on-exit位)/hvpp/SimpleVisor/
	//    HyperDbg(默认关,显式开时才配ack-on-exit)/TinyVT(Win10 1903实测,
	//    pin期望全零)。EPT hook靠violation/MTF, 与中断路径正交, 无需拦截。
	//  ②UC论坛Ophion帖(SOLVED)实锤: ack-on-exit后中断被CPU从IRR移进ISR,
	//    hypervisor注入的只是VM-entry事件, guest ISR的EOI管不到物理LAPIC
	//    →ISR位永不清→时钟中断永久阻塞→整机静默冻结(看门狗死/无蓝屏,
	//    与我们v3.30-3.35五连零事件冻结同签名)。
	//  ③UC MP案例结论: 这套状态机=重写半个虚拟APIC(EOI债/窗口位开关/
	//    IF+STI/MOVSS+TPR判别/优先级有序注入), 多核竞争下漏一项=间歇冻结
	//    ——"要么写完整虚拟APIC, 要么关ack-on-exit让中断留给guest"。
	//直投模式: 中断在non-root直接经guest IDT交付ISR, EOI直写真LAPIC,
	//VMM零参与零状态机零EOI债——这也是v3.16全绿成功(8核+干净卸载)时的
	//隐式配置(当时EXIT模式无KEEP, 中断路径从未被VMM触碰)。
	ULONG pinCtl = VmxMsrAdjuest(pinMsr, 0);
	ULONG procCtl = VmxMsrAdjuest(procMsr, 0X10000000 | 0X80000000);
	//exitCtl期望去掉bit15(0x8000=acknowledge interrupt on exit, v3.x起
	//误开至今), 只留bit9(0x200=host address-space size, 64位host必须)
	ULONG exitCtl = VmxMsrAdjuest(exitMsrNum, 0x200);
	ULONG entryCtl = VmxMsrAdjuest(entryMsrNum, 0x200);
	//控制字段留痕(v3.36期望): pin=00000016(直投模式, 原0x17去bit0),
	//proc=94006172, exit=00036FFB(原0x3EFFB去bit15), entry=000013FB。
	//偏离期望=公式/MSR又被改
	FlLog("cpu%u 控制字段(v3.36直投): pin=%08X proc=%08X exit=%08X entry=%08X",
		cpuNumber, pinCtl, procCtl, exitCtl, entryCtl);
	__vmx_vmwrite(VM_ENTRY_CONTROLS, entryCtl);
	__vmx_vmwrite(VM_EXIT_CONTROLS, exitCtl);
	__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, pinCtl);
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, procCtl);
	PHYSICAL_ADDRESS msrPhyAddr = MmGetPhysicalAddress(currentCpu->MsrBitMap);
	__vmx_vmwrite(MSR_BITMAP, msrPhyAddr.QuadPart);
	__vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
	__vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);
	__vmx_vmwrite(GUEST_ACTIVITY_STATE, 0);   // 处于正常执行指令状态
	//0xC0000082
	//VmxSetMsrRw(0xC0000082,0,TRUE);
	FlLog("cpu%u VMCS[6/6]: 填充完成, 启用EPT", cpuNumber);
	//EPT数据已在DriverEntry(PASSIVE_LEVEL)预分配, 此处只写入VMCS
	if (g_vcpu[cpuNumber].PeptData != NULL)
	{
		//v3.15: 弃VPID。v3.14曾开VPID(cpuNumber+1)——真机同场PCID与guest
		//VPID共用TLB资源的混叠疑点无法从软件侧排除, 且Stage 0无需VPID
		//(它是vcpu切换免TLB冲刷的优化)。彻底关掉, 翻译退化为EP4TA+CR3
		//标签, invept全上下文即可完整冲刷。远期VMFUNC/EPTP切换再按需重开
		//v3.37(TinyVT调研行动项): 补开rdtscp/xsaves/invpcid三**指令许可**位
		//(TinyVT"for Win10"/hvpp/HyperPlatform三项目全开)。机理: 内核启动时
		//(无虚拟化)CPUID检出这些指令可用→选定路径; non-root下未开许可位
		//→执行即#UD→蓝屏0x1E@c000001D(STATUS_ILLEGAL_INSTRUCTION, 测试机
		//v3.22已发生过)/持锁上下文异常分发挂起→静默冻结(部分冻结同源)
		//v3.38**位布局修正**(v3.37实测错误码7的根因): v3.37凭记忆写
		//bit4=xsaves/bit10=invpcid是**错的**——正确布局(TinyVT ia32.h
		//L949-979/SimpleVisor vmx.h/hvpp/KVM四源一致): bit3=rdtscp/
		//bit4=virtualize_x2apic_mode/bit10=pause_loop_exiting/
		//bit12=invpcid/bit20=xsaves_xstors。0x41A实际开了x2APIC虚拟化
		//+PLE→PLE开启时VM-entry要求PLE_Gap/PLE_Window非全零(SDM 26.2.1.1,
		//我们从未写)→控制字段检查失败=错误码7。且bit4/bit10恰都在本机
		//MSR 0x48B允许域(实测High=0x1FBCFF含{0..7,10..13,15..20})内,
		//VmxMsrAdjuest公式无法拦截。正确期望=0x10100A(bit1|bit3|bit12|bit20),
		//四位均在允许域内
		ULONG64 ctls2Value = VmxMsrAdjuest(MSR_IA32_VMX_PROCBASED_CTLS2,
			0x2 | 0x8 | 0x1000 | 0x100000);
		__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, ctls2Value);
		__vmx_vmwrite(EPT_POINTER, g_vcpu[cpuNumber].Eptp.ALL);
		FlLog("cpu%u ctls2=%llX (v3.38期望0010100A=EPT+rdtscp+invpcid+xsaves, 无VPID)",
			cpuNumber, (unsigned long long)ctls2Value);
	}
	else
	{
		//EPT未就绪: 无EPT无VPID(仍可虚拟化运行, 无hook能力), 但v3.37
		//指令许可位(rdtscp/xsaves/invpcid)仍必须开——它们与EPT正交,
		//缺了照样#UD蓝屏/冻结。v3.38位布局修正: 0x418→0x101008
		FlLog("cpu%u 无EPT数据(预分配失败?), ctls2仅指令许可位", cpuNumber);
		ULONG64 ctls2Value = VmxMsrAdjuest(MSR_IA32_VMX_PROCBASED_CTLS2,
			0x8 | 0x1000 | 0x100000);
		__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, ctls2Value);
	}

	//v3.13: EPT软件自检门(见ept.c EptVerifyTables)——launch前用软件走查
	//复演硬件EPT翻译(EPTP链/pdpte链/262144个2M叶全扫/探针页等关键样本页)。
	//失败=放弃本核vmlaunch(留在root模式, 系统存活, T1继续记录), 把v3.12的
	//"死在黑盒"(vmlaunch后250ms全机冻/零exit零环标记)变成"launch前精确
	//报错+安全放弃"。无EPT数据时EPT未启用(硬件直接翻译, 无黑盒), 跳过自检
	if (g_vcpu[cpuNumber].PeptData != NULL)
	{
		ULONG eptFails = EptVerifyTables(cpuNumber, (ULONG64)(ULONG_PTR)GuestRsp);
		if (eptFails > 0)
		{
			g_vcpu[cpuNumber].bLaunchFailed = 1;
			FlLog("cpu%u EPT自检失败(%u组), 放弃vmlaunch(本核留在root模式)",
				cpuNumber, eptFails);
			return 1;
		}
	}
	//v3.10指纹行(每次测试必核对!): 缺此行=测试机加载的是旧编译的sys。
	//CS.AR期望值(v3.11b实测裁决)=209B: x64 Windows内核CS(0x10)的真实GDT
	//值就是L=1/D=0/G=0/limit=0xFFFFF(长模式CS取指只查canonical不查
	//limit, G=0+20位limit自洽; "期望A09B"是32位/Linux时代的想当然)。
	//TR.AR=008B(IA-32e的TSS仍用32位busy type=0xB)。CS.AR若bit13(L)=0
	//(如009B)=AR填充回归旧bug
	//v3.13增: EPT自检/探针VA; v3.14增: 模式; v3.15增: IF0窗/无VPID/invept;
	//v3.16增: 合并写盘; v3.17增: 接管(KEEP)+单核; v3.18增: 高区预建;
	//v3.19增: 中断注入(pin=0x17)+热轮询; v3.20增: 探针5万次压测循环('L'/'Y');
	//v3.21增: 'D'豁免探针vmcall+逃生vmcall推RIP(修v3.20蓝屏@+0x1055);
	//v3.22增: T1热轮询双重失效修复(FlArmLaunchWatch+hotWait, launch窗口毫秒级观测);
	//v3.23增: interrupt-window中断模式(IF0窗入队+开窗投递+逃生EOI, 修v3.22实证的
	//         注入entry-failure 33+ack-on-exit丢中断冻结轮盘)
	//v3.24增: 开窗位修正bit1→bit2(v3.23误写|2=纯no-op, 窗口从未开=积压永不
	//         投递=时钟卡in-service=零落盘全机冻) + HB行pend0积压观测
	//v3.25增: 撤IF0窗(launch全程IF=1, 中断即时注入即时跑, T1写盘完成路径
	//         永不依赖事后排空) + must-1指令模拟(RDTSC/INVLPG/HLT/MWAIT/MONITOR)
	//         + 33运行期栈粉碎修复 + 'Q'标记 + 探针循环8ms
	//v3.26增: 判别性实验GEPT_PROBE_EXIT=1(自测+IF1, 注入机制受控检验)
	//         + 'K'路径vmx_off前EOI清积压in-service债
	//v3.27增: pin=0x16判别实验(关ext-int exiting, 中断原生直递guest,
	//         VMM中断机制整体旁路; T1存储IRQ也直递→观测按构造存活)
	//v3.28增: 写盘护卫(探针窗口T1零落盘, 排除磁盘I/O混杂变量)
	//v3.29增: 护卫超时自解除(实测探针~100ms, v3.30阈值→1000ms) + IF0探针窗
	//v3.30增: 切KEEP接管模式(v3.29实证probe窗口全无辜: r18=8195精确吻合,
	//         零中断交付下[全程通过]——现在检验接管续跑: _enable()后IRR
	//         中断原生直递, 首个ISR在EPT下执行)
	//v3.36指纹: 调研裁决落地——中断直投(pin=0+exit无bit15), 删除注入
	//         状态机('i'注入/PendingIntrVec入队/开窗关窗全删, case1/7改
	//         防御标记), 对齐HyperPlatform/hvpp/SimpleVisor/HyperDbg/TinyVT
	//         五项目的共同配置。看门狗/TFpark/写盘护卫/KEEP检查点全保留
	FlLog("cpu%u v3.36指纹(中断直投): CS.AR=%04lX TR.AR=%04lX (期望209B/008B) EPT自检=PASS(含高区[6]) EPTP=%llX 探针VA=%llX 模式=%s+pin0直投+无ack-on-exit+写盘护卫+KEEP检查点+512压测循环+D豁免+热观测+TFpark",
		cpuNumber, g_dbgCsAr, g_dbgTrAr,
		(unsigned long long)g_vcpu[cpuNumber].Eptp.ALL,
		(unsigned long long)(ULONG_PTR)CmGuestProbe,
#if GEPT_PROBE_EXIT
		"EXIT(自测)"
#else
		"KEEP(接管)"
#endif
	);
	//这条落盘后下一步就是vmlaunch。判读: 冻结/蓝屏时最后一行是它
	//=死在vmlaunch指令本身或探针两段vmcall前后; [W][K][F][f]环标记
	//与"probe-exit完成"行把死亡点二分到指令级
	//v3.28: 本行是护卫判读锚点——护卫期间T1零落盘, 若冻结且这是最后
	//落盘行=T1磁盘I/O被构造性排除(凶手在guest执行/中断直递);
	//存活则护卫解除后此行下面紧跟[F][W][E]..[Y][K]补写=guest窗口无辜
	FlLog("cpu%u vmlaunch...(护卫开: T1停写盘至probe返回)", cpuNumber);
	//v3.22: 观测预热——置hot+踢T1+睡5ms, T1醒来进入1ms热节奏,
	//launch窗口(vmlaunch+探针循环+接管初期)全程毫秒级观测(缓冲)
	FlArmLaunchWatch();
	//v3.28: 开写盘护卫(此时"护卫开"行已由FlLog同步落盘; FlArmLaunchWatch
	//的5ms睡眠武装的LAPIC定时器IRQ≈vmlaunch时刻到达——v3.22的r1=1@+0.2ms
	//极可能就是它, 本实验刻意保留该触发源, 只排除T1磁盘I/O这一混杂变量)
	g_flWriteGuard = 1;
	//v3.33/v3.34: 武装蓝屏黑匣子看门狗——此后行环游标30s不动(=T1循环死
	//=冻结级联)→自旋看门狗线程(钉cpu0/1, 纯rdtsc计时)快照黑匣子+
	//KeBugCheckEx(0xDEADC0DE)→MEMORY.DMP保留死亡现场(v3.30-33四连零事件
	//冻结的观测破局: T1磁盘日志通道在级联爆炸半径内结构性失效, bugcheck
	//的crash dump栈是唯一为死锁设计的低层通道)。v3.34教训: 检测器不能
	//依赖"被冻结会死"的时基——v3.33的DPC+中断时钟实测180s不开火
	FlWdArm();
	//v3.29: 恢复IF0探针窗口(v3.15设计, 判别实验)——v3.28实测冻结且最后行
	//=护卫行=T1磁盘I/O被排除, 凶手在guest窗口内(探针执行/中断ISR)。
	//IF0下(pin16)中断到达cpu0但不投递(留IRR), 探针8ms窗内**零ISR执行**;
	//'K'退出回真机→sti→IRR中断在真机投递(安全)。
	//判别: 存活=窗口+循环无辜→凶手=EPT下ISR执行(v3.17-28统一理论);
	//冻结=窗口内非中断死因(循环vmcall效应)→二分循环次数
	//注意: _disable必须在FlArmLaunchWatch之后(其5ms睡眠依赖IF1)
	_disable();
	//重写GUEST_RFLAGS(此刻IF=0)——探针全程IF=0, [K]处理器的
	//"按guest原IF恢复"分支自然跳过, 真机IF由VMXInitCpuStart统一恢复
	__vmx_vmwrite(GUEST_RFLAGS, __readeflags());
	//(v3.25的IF1设计已随v3.29判别实验退役: 死链见上v3.23/24注释,
	// 但那是pin17+ack语境; v3.29=pin16+IF0=中断留IRR零ISR执行)
	//v3.36: IF0窗+pin0直投——中断留IRR(不被ack), KEEP的sti后硬件直投
	//guest ISR; 与v3.29唯一区别=ISR在EPT下执行(直投, 无注入状态机)
	//v3.15: 'F'环事件=launch窗口开启标记(与'f'配对)
	FlRingPush('F', cpuNumber, 0, 0, 0, 0);
	result = __vmx_vmlaunch();

	if (result)
	{
		ULONG vmerr = 0;
		__vmx_vmread(VM_INSTRUCTION_ERROR, &vmerr);
		g_vcpu[cpuNumber].bLaunchFailed = 1;
		//v3.28: 先清护卫再FlLog(否则失败行要等500ms超时)
		g_flWriteGuard = 0;
		//v3.29: 恢复IF0窗→vmlaunch失败路径也要sti(IF=0下FlLog的
		//500ms等待依赖时钟中断, 不恢复=永久睡眠)
		_enable();
		FlLog("cpu%u vmlaunch失败! 错误码=%d (7=控制字段非法 8=host状态非法, SDM Table 33-1)", cpuNumber, vmerr);
		g_flLaunchHot = 0;
	}
	return (int)result;
}

void VmxFillSelectorData(USHORT selector, USHORT index)
{
	SEGMENT_SELECTOR segMentSelector = { 0 };
	segMentSelector.sel = selector;
	segMentSelector.limit = __segmentlimit(segMentSelector.sel);
	segMentSelector.base = 0;
	//获取Gdt表
	ULONG64 gdtBase = GetGdtBase();
	//获取段描述符 0x23 10 0000 *
	PSEGMENT_DESCRIPTOR segmentDes =
		(PSEGMENT_DESCRIPTOR)(gdtBase + (ULONG64)(segMentSelector.sel & 0xFFF8));//等价与 gdtBase+index*8
	//segmentDes->BaseLow| segmentDes->BaseMid
	segMentSelector.base =
		segmentDes->BaseHigh << 24 | segmentDes->BaseMid << 16 | segmentDes->BaseLow;
	segMentSelector.attributes = segmentDes->AttributesHigh << 8 | segmentDes->AttributesLow;
	//AR字段位布局(SDM 24.4.1, 本项目已用SDM PDF裁决+KVM/Xen/HyperPlatform
	//三方实现交叉验证): Type[3:0] S[4] DPL[6:5] P[7] AVL[12] L[13] D/B[14]
	//G[15] Unusable[16]——AttrHigh的AVL/L/D-B/G恰好左移12位就位,
	//即 byte0 | byte1<<12。**myVt原版公式正确, 勿"修复"**(v3.10曾险些
	//按错误布局改写成AVL→10/L→12/D-B→13/G→14, 会把L=1的内核CS标成
	//32位兼容段→内核取指non-canonical→#GP风暴三重故障)
	ULONG attr = ((PUCHAR)&segMentSelector.attributes)[0]
		| ((PUCHAR)&segMentSelector.attributes)[1] << 12;
	if (selector == 0)
	{
		attr |= 0x10000;   //unusable(空选择子DS/ES/LDTR)
	}
	if (index == 1)
	{
		g_dbgCsAr = attr;  //指纹留痕(v3.10, 见VmxSetupVmcs末尾指纹行)
	}
	__vmx_vmwrite(GUEST_ES_SELECTOR + index * 2, segMentSelector.sel);
	__vmx_vmwrite(GUEST_ES_LIMIT + index * 2, segMentSelector.limit);
	__vmx_vmwrite(GUEST_ES_BASE + index * 2, segMentSelector.base);
	__vmx_vmwrite(GUEST_ES_AR_BYTES + index * 2, attr);
	//RIP RSP
	//1检测环境
	//2申请内存cpu vmxON vmcx
	//3 vmxon 进入 vt root host
	//4填充vmcs区域 RSP RIP
	//5 vmlaunch 从host层回到 guest  类似从r0回到r3
}

