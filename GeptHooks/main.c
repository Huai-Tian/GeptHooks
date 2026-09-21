#include<ntifs.h>
#include<intrin.h>
#include"common.h"
#include"PageHook.h"
#include"VMX.h"
#include"ept.h"
#include"GeptApi.h"
#include"GeptMsr.h"

//分阶段联调开关:
//0 = 仅开启虚拟化(vmlaunch+EPT恒等映射), 用于先验证VT层稳定
//1 = 自测Hook: hook本驱动内的GeptTestTarget并调用一次, 指令布局自控不依赖系统版本
//2 = 正式Hook NtClose(全系统高频监控; prologue逐字节校验不过=拒绝安装)
//v3.41: 0→1——v3.40全核KEEP闭环授权
//v3.45: 1→2——v3.44 STAGE1毕业(3.1h稳定+干净卸载)授权。STAGE2分支
//=先跑STAGE1自测(机制前置验证)再装NtClose hook; 本机prologue已实测
//适配(hook.asm 22B重放+main.c安装校验双保险, 旧19B重放在本机会蓝屏)
#define GEPT_HOOK_STAGE 2

//构建标签(v3.46): 每次改动代码必须同步修改! 会打进日志第一行,
//用于核对测试机跑的是不是本次编译的二进制(见DriverEntry横幅)
//v3.42: hook页隔离; b: ml64拒绝段内align 1000h, 改SEGMENT ALIGN(4096)段
//v3.43: 0x1E蓝屏根因修复——hook跳板sub rsp,20h违反x64 ABI(→28h)
//v3.44: 卸载0x50蓝屏根因修复——vmx_off后__writecr3恢复GUEST_CR3
//(HOST_CR3=System DTB残留→同进程线程继承错误页表→LPC写用户缓冲
//0xF蓝屏); 实测STAGE1毕业(3.1h稳定+8核干净卸载)
//v3.45: **STAGE 2(NtClose)上电**——①hook.asm重放适配本机prologue
//(实测22B: push rbx/rdi/r13/r14/r15+sub rsp,40h+mov rax,gs:[188h];
//旧19B重放绑定作者2022 Win10, 在本机会跳进指令中间=蓝屏) ②安装前
//逐字节校验NtClose前22B, 不一致拒绝安装(版本漂移防蓝屏) ③STAGE2=
//先跑STAGE1自测再装NtClose hook ④HookNtClose监控模式: 原子计数+
//每65536次采样'N'环事件(绝不FlLog/DbgPrint: 前者任意线程上下文死锁
//风险, 后者性能风暴), 返回值被丢弃=原函数照常执行 ⑤卸载打印总计数
//**v3.45实测蓝屏0x3B@nt+0x63E0AE=NtClose+0xE**(mov rax,gs:[188h]指令
//中间), 三缺陷叠加的裁决:
//  a) PHGetHookLen的ldasm旧bug(重复解码第一条指令): NtClose首条
//     push rbx(2B)×7=14≠重放22B→跳回落指令中间→错误解码
//     mov rax,[0x188]→#PF。STAGE1碰巧全3B指令(3×5=15=真边界)毕业
//     掩盖了它。**v3.46修复: ldasm(src)顺序解码**
//  b) VmxInvept裸ret不查VMfail: CPU若不支持all-context(EPT_VPID_CAP
//     bit26=0)则invept全静默无效→NtClose热路径TLB旧exec条目存活
//     数小时→hook"已布防未触发"→TLB自然逐出后第一次走进跳板才撞上
//     a)蓝屏(布防到蓝屏隔了数小时的原因)。STAGE1冷函数(无TLB条目,
//     靠walk触发)从未暴露。**v3.46修复: asm返回ZF+能力探测+EPTP填充**
//  c) hookLen与重放无交叉校验(防御缺失)。**v3.46修复: 强校验≠22拒绝安装**
//v3.47 Phase1(VMFUNC路线, 看雪图谱4.2): VMFUNC EPTP switching基础设施
//上电——EPTP-list页+VMCS配置(secondary ctl bit13+VMFUNC control bit0+
//EPTP_LIST)+全核guest内裸往返自测。list[0]=[1]同EPTP(切换no-op), 只验证
//"指令可执行+配置正确"; Phase2才拆clean/hooked两套视图实现零VM-Exit hook。
//**v3.47b: 探测修正**——撤销CPUID.7.EBX[16]检查(该位实为AVX512F,
//客户端Skylake读0导致v3.47误判i7-6700HQ"无VMFUNC"; 实则SDM中VMFUNC
//无任何CPUID枚举位, 唯一权威判据=ctls2 bit13经MSR 0x48B掩码后存活)
//**v3.47c: 机器码修正**——CmVmfuncTest的vmfunc嵌入码0F01C4→**0F01D4**。
//v3.47b实测蓝屏0x7E@(C000001D, GeptHooks+0x1085)裁决: 0F01C4=**VMXOFF**
//(从看雪帖抄的错误opcode, 未与SDM核对)! 完整链条: guest内执行VMXOFF
//→VM-exit reason 26→handler无case走'U'逃生→vmx_off回真机从+0x1085
//重执行→**VMX operation之外执行VMXOFF=#UD**→系统线程异常未处理→0x7E。
//环铁证: [E]seq=104 rsn=26 a=+0x1085 + tally U:0=1。VMFUNC=0F01D4(SDM)
//**v3.47d: VMCS字段编码修正**——v3.47c实测仍蓝屏0x7E@C000001D@+0x1085
//但环无rsn=26(vmfunc已非VMXOFF)。裁决: VMFUNC_CONTROL/EPTP_LIST_ADDRESS
//编码凭记忆写错(0x2015/0x2016实为APIC-access高半区/posted-int描述符,
//被硬件忽略)→真VM-function controls恒0→vmfunc=unsupported function=
//#UD(guest内直接异常无VM-exit)→0x7E。**权威源(Linux asm/vmx.h)**:
//VM_FUNCTION_CONTROL=0x2018, EPTP_LIST_ADDRESS=0x2024。
//三次同型教训(位号/opcode/字段编码=全凭记忆不查权威): 此后所有
//硬件相关常量必须在注释标注权威源出处
//v3.48: **Phase 2——双EPT拆分+VMFUNC hook闭环**(看雪图谱4.2核心)。
//设计依据=SDM §28.5.7.3权威裁决(NOTES "Phase 2设计依据"节, 动工前
//逐条对SDM PDF核对): VMFUNC切换会写回EPT_POINTER字段=切换跨exit/entry
//持久+root侧vmwrite(EPT_POINTER)同义。要点:
//  ①每核hooked EPT(深拷贝, 自指链重指): EPTP-list[0]=clean/[1]=hooked
//  ②标记页remap(hooked EPT独有): guest内同一VA在两视图读出
//    "CLEANEPT"/"HOOKEDPT"=双EPT真实分叉的软件证据(自测)
//  ③EptSetHook VMFUNC主路径: hooked表里hook页PTE→CodePage(X=1,R=1,W=0)
//    +vmwrite(EPT_POINTER)切hooked视图——hook触发**零VM-Exit**(r48
//    计数不再增长=毕业判据); clean视图原页字节完好(读写看原始字节)
//  ④violation兜底改作用于ACTIVE视图表(EptGetActiveData): VMFUNC核的
//    写兜底(hook页W=0)与fallback核的v3.46互切共用骨架
//  ⑤case 59(VMFUNC失败exit): 推RIP跳过+自测判FAIL降级, 绝不走'U'逃生
//    (真机重执行vmfunc=#UD蓝屏, rsn59绝非#UD——SDM裁决)
// ⑥EPT自检新增[7][8][9](hooked表结构/标记remap/高区共享链), launch前
//    软件走查把黑盒死亡变成精确报错
//v3.49: **Phase 3——隐藏**(看雪图谱4.4: CPUID伪装+TSC补偿)。全部语义
//对SDM核对(Table 27-6页27-11 + §28.3页28-11原文, 见NOTES Phase3节):
//  ①TSC补偿: procCtl+bit3(use TSC offsetting)→guest的RDTSC/RDTSCP/
//    RDMSR(0x10)硬件自动返回 真TSC+TSC_OFFSET; asm exit handler每exit
//    调VmxTscCompensate把root驻留时长从offset中扣除=guest时间线上
//    "exit从未发生"。IA32_TSC_DEADLINE(0x6E0)不受offset影响(SDM原文)
//    =LAPIC定时器/时钟中断零扰动。欠补偿方向安全(绝不倒退)
//  ②CPUID伪装: 0x40000000-0x4000000F全0(无hypervisor签名)+leaf0
//    maxleaf>0x1F收敛(防嵌套泄漏; 本机0x16不触发)+leaf1 bit31清0(已有)
//  ③自测: 逐核rdtsc环绕CPUID(单次+1000次平均)落盘+CPUID伪装值自证;
//    卸载't'环事件=最终TSC_OFFSET(累计隐藏总时长的负值)
//v3.50: **Phase 4——简易API框架化**(用户初衷之二: 普通开发者零虚拟化
//知识即可用虚拟层HOOK)。GeptApi.h/GeptApi.c新增:
//  GeptHookInstall/Remove/Enumerate + GeptCallOriginal(detour式)
//  ①触发链: hooked视图CodePage跳转→独享trampoline槽(mov r10,entry;
//    jmp GeptStubEntry)→stub: vmfunc切clean→SAVE_ALL→分发器→用户回调
//    →GeptViewSwitch(1)归位→ret(全程零VM-Exit, 回调返回值=函数返回值)
//  ②本质简化: clean视图原函数字节完好→GeptCallOriginal直接call原始
//    入口, **prologue重放/hookLen跳回/trampoline机器整套消亡**
//  ③Remove: 还原CodePage被覆盖字节(源=原页权威副本)+全核双视图invept
//    (vmcall(7))→hooked视图≡clean视图=hook死透; 在途回调安全完成
//  ④卸载纪律: GeptApiRemoveAll(关VT**前**, 让在途回调的vmfunc安全执行)
//    +2s宽限+GeptApiFreeMemory(关VT后)
//  ⑤STAGE2=API demo三段式: 装观测2s→移除冻结2s→重装恢复2s=生命周期
//    闭环证据(旧AsmHookNtClose路径保留为无VMFUNC机器的fallback)
//**v3.50b: trampoline编码off-by-2修复**——GeptStubEntry指针曾写t+18,
//而jmp[rip+0]从t+16读(RIP_after=t+16)→读出[00 00+地址低6B]=非规范
//地址→#GP(0)于jmp指令本身→蓝屏0x3B@C0000005@槽+0x0A, Install后首次
//hook触发即崩(日志铁证: 跳板槽=...A000/蓝屏RIP=...A00A)。修复=指针
//改写t+16+回读自检(t+16读回≠GeptStubEntry=拒绝该槽, 编码回归当场
//拦截而非上机蓝屏)
//v3.51: **Phase 6——fallback动态化+版本无关化**(violation方案去硬编码,
//老CPU/新Windows通吃)。核心=PHBuildRelocTrampoline(PageHook.c): LDE
//逐指令解码目标prologue→复制到跳板缓冲+重算RIP-relative disp32→
//尾接jmp回Target+Len——经典Detours重定位跳板, 替代hook.asm硬编码
//22B重放(版本绑定的根源)。保守拒绝策略: 相对分支/重定位目标超±2GB/
//回扫自检不符=Install当场拒绝(绝不带病上机)。配套:
//  ①GeptCallOriginal双路径: VMFUNC核切clean直call原入口(不变);
//    fallback核经重定位跳板(原函数首字节已被14B跳转覆盖, 直call=递归)
//  ②detour stub统一(GeptStubEntry): 入口裸vmfunc改GeptViewSwitch(按核
//    no-op), 同一stub服务VMFUNC核+fallback核(混合机器正确); 顺带修两处
//    latent bug(retval/API条目曾跨call持有volatile寄存器)
//  ③Install gate从"全部核VMFUNC"放宽为"至少一核in-guest"; 无VMFUNC核
//    走violation降级(功能/API语义等价, 隐藏性降级: 每次触发1+次VM-Exit)
//  ④main.c STAGE2: 硬编码prologue校验+hookLen==22强校验+AsmHookNtClose
//    重放路径全部退役删除(hook.asm同步删除); 新增replay自测
//    (GeptApiSelfTestReplay: NtClose(伪句柄-1)应返回0xC0000008)
//v3.52: **Phase 5——MSR数据伪装**(看雪图谱4.3, 简易API第二面)。
//GeptMsr.c/h新增(配套重构: 删winApiDef.h——与PageHook.h的
//KeGenericCallDpc族原型纯重复; 删VMX.c死代码VmxSetMsrRw——
//从未被调用, 位图逻辑由GeptMsr.c接管):
//  ①GeptMsrHookInstall/Remove: 全核MSR位图置位/清位+**回读自检**
//    (任一in-guest核位图读回不符=拒绝——伪造自测在guest内真执行
//    rdmsr, 位图失效=未拦截=#GP蓝屏, 绝不带病上机)
//  ②读回调返回值=rdmsr可见值(伪造); 写回调TRUE=放行/FALSE=静默丢弃
//  ③RDMSR/WRMSR exit handler接线(GeptMsrDispatch*); 位图零开销:
//    未hook的MSR仍直通(硬件按位图判定, 不产生exit)
//  ④demo: 保留MSR(0xC00000B0)伪造自测(全链路证明: guest rdmsr→
//    位图exit→分发→回调伪造值→rax:rdx, 未拦截=#GP) + LSTAR
//    canary(读监控原值+写报警, 持续到卸载——运行期写LSTAR=有
//    东西在patch syscall入口=安全信号)
//v3.53: **v1.0.1——VMX指令族exit处置(安全修复+VT-x原生互斥)**。
//三重身份: ①安全修复: 19-27/50/53族此前无case全落default 'U'逃生
//(vmx_off回真机重执行)——内核态病毒狂喷VMXOFF=0x7E蓝屏(v3.47c实证
//死法), 狂喷VMXON=逃生后真机重执行可能成功=病毒抢VMX root脑裂;
//未知vmcall码旧版静默放行=裸机VMCALL本应#UD=hypervisor在场信号泄漏
//②互斥仲裁(用户裁决: 拒绝签名互斥——对抗场景单点失效): 同框架
//junior实例的vmxon在宿主guest内=rsn27 exit→宿主伪造VMfailInvalid
//→junior全核失败→**本版新增的全败汇总干净退出**。零签名/零共享
//对象/零新增可扫描物, 仲裁者=VT-x硬件本身 ③裸机精确仿真(SDM四
//指令页原文): 家族"not in VMX operation→#UD"→注入#UD(编码=SDM
//Vol3C Table 24-13: 0x80000306, type3=硬件异常); 唯VMXON例外(入口
//指令)→伪造VMfailInvalid(CF=1,ZF=0)。'D'环路检测同步豁免该族
//(每次exit都有guest可见进展)
//自测判据: 病毒模拟探针(hook.asm)——VMXOFF探针异常码应=0xC000001D
//(v3.47c死法重放为毕业判据), VMXON探针CF应=1
#define GEPT_BUILD_TAG "v3.53"

//v3.33: 构建标签全局副本——黑匣子(common.h GEPT_BLACKBOX)在FlInit时
//拷入, 蓝屏DMP解析时自证二进制版本
CHAR g_geptBuildTag[24] = GEPT_BUILD_TAG;

ULONG64 g_jmp_testtarget = 0;
//v3.53: VMXON探针哑操作数(hook.asm GeptVirusVmxOn引用)——PA=0:
//宿主伪造VMfail不读操作数(SDM: non-root下VMexit替代指令执行);
//裸机上PA=0非4KB对齐同样VMfailInvalid, 探针在两种环境都无副作用
ULONG64 g_geptDummyVmxonPa = 0;
VOID GeptTestTarget();
VOID AsmHookTestTarget();
//v3.53: 病毒模拟探针(hook.asm, 仅DriverEntry自测调用)
VOID GeptVirusVmxDetectOff();
ULONG64 GeptVirusVmxOn();

//v3.45: NtClose拦截计数器(DemoNtCloseCallback每调用+1; 卸载时落盘总结)
//(v3.51: 旧HookNtClose监控回调随AsmHookNtClose重放路径一并退役——
//其唯一调用方是hook.asm已删除的22B重放跳板; 频率纪律由DemoNtCloseCallback
//继承, 见其注释)
LONG g_geptNtCloseCount = 0;

//v3.50 Phase4: STAGE 2的API demo回调(detour式)——计数+采样+经
//GeptCallOriginal透传原函数并**返回其真实NTSTATUS**(detour完整
//控制权的演示; 旧violation路径的返回值被丢弃只能旁路)
//频率纪律(v3.45血泪预判, 继承自退役的HookNtClose): 全系统NtClose
//每秒上千次, 回调在任意线程上下文/任意IRQL执行——
//  绝不FlLog: 调用者可能持文件系统锁, FlLog等T1落盘(500ms)而T1写
//    文件要同一把锁=死锁
//  绝不DbgPrint: 高频=性能风暴
//只做原子计数+每65536次采样1条'N'环事件(无锁, 任意IRQL安全,
//T1异步格式化成"[N] s=.. cpu=.. a=计数"行落盘temp日志)
//+GeptCallOriginal(vmfunc与普通call在任意IRQL安全)
static ULONG64 DemoNtCloseCallback(PVOID Context, ULONG64 Arg1, ULONG64 Arg2,
	ULONG64 Arg3, ULONG64 Arg4)
{
	UNREFERENCED_PARAMETER(Context);
	LONG n = InterlockedIncrement(&g_geptNtCloseCount);
	if (n == 1 || (n & 0xFFFF) == 0)
	{
		FlRingPush('N', KeGetCurrentProcessorNumber(), 0,
			(ULONG64)(ULONG)n, Arg1, 0);
	}
	//回调此刻: VMFUNC核已被StubEntry切到clean视图(原函数字节完好),
	//fallback核仍在violation视图(执行走CodePage)——GeptCallOriginal
	//按**当前核**能力分派(VMFUNC核直call原入口/fallback核重定位跳板),
	//线程迁移到异类核亦正确
	return GeptCallOriginal(Arg1, Arg2, Arg3, Arg4);
}

//v3.52 Phase5: MSR canary计数器(卸载时落盘总结)
static volatile LONG g_geptMsrForgeHits = 0;    //保留MSR伪造命中
static volatile LONG g_geptLstarReadCount = 0;  //LSTAR读计数
static volatile LONG g_geptLstarWriteCount = 0; //LSTAR写计数(应为0)

//保留MSR(0xC00000B0)伪造回调: 直接返回标记值——该MSR真读=#GP,
//**绝不调GeptMsrReadReal**。纪律: VM-exit上下文=只Interlocked+采样
//环事件(与DemoNtCloseCallback同源)
static ULONG64 DemoMsrForgeRead(PVOID Context, ULONG32 Msr)
{
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(Msr);
	LONG n = InterlockedIncrement(&g_geptMsrForgeHits);
	if (n == 1 || (n & 0xFFFF) == 0)
	{
		FlRingPush('M', KeGetCurrentProcessorNumber(), 0,
			(ULONG64)(ULONG)n, 0, 0);
	}
	return 0xDEADBEEFCAFEBABEULL;
}

//LSTAR读回调: 原值透传——拦截链路已由保留MSR自测证明, 这里不改
//语义只监控(谁在读syscall入口: AV/EDR的典型探测行为)
static ULONG64 DemoMsrLstarRead(PVOID Context, ULONG32 Msr)
{
	UNREFERENCED_PARAMETER(Context);
	ULONG64 real = GeptMsrReadReal(Msr);
	LONG n = InterlockedIncrement(&g_geptLstarReadCount);
	if (n == 1 || (n & 0xFFFF) == 0)
	{
		FlRingPush('M', KeGetCurrentProcessorNumber(), 1,
			(ULONG64)(ULONG)n, real, 0);
	}
	return real;
}

//LSTAR写回调: 报警+放行(监控模式不改变行为)。系统运行期不该写
//LSTAR——计数>0=有代码在patch syscall入口(经典攻击行为), 写必是
//异常事件故每次推环事件(合法频率=0, 无风暴风险)
static BOOLEAN DemoMsrLstarWrite(PVOID Context, ULONG32 Msr, ULONG64 Value)
{
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(Msr);
	LONG n = InterlockedIncrement(&g_geptLstarWriteCount);
	FlRingPush('M', KeGetCurrentProcessorNumber(), 2,
		(ULONG64)(ULONG)n, Value, 0);
	return TRUE;
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
	//v3.50 Phase4: 先移除全部API hook(CodePage字节还原+全核invept)——
	//必须在vmx_off**之前**: ①移除后新触发停止 ②在途回调(stub的
	//vmfunc(0,1)/GeptCallOriginal)此刻VT仍开=安全执行完毕。
	//随后的2s宽限让被抢占的在途回调跑完; GeptViewSwitch的bInGuest
	//检查再兜一层(残余窗口=check与vmfunc两条指令间被抢占+停机2s,
	//概率可忽略; vmx_off后执行vmfunc=#UD蓝屏, 这是已知最后风险点)
	GeptApiRemoveAll();
	{
		LARGE_INTEGER tick;
		tick.QuadPart = -2000000LL;    //2秒宽限
		KeDelayExecutionThread(KernelMode, FALSE, &tick);
	}
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
	//v3.50: API内存(条目+跳板池, 纯pool释放无VT依赖; 此刻已无任何
	//在途代码引用——hook已移除+VT已关)
	GeptApiFreeMemory();
	//v3.45: STAGE 2总结——此时全核vmx_off已完成(EPT失效=NtClose hook
	//自动解除, 全系统回到原函数), 计数器定格
	if (g_geptNtCloseCount > 0)
	{
		FlLog("Unload: [STAGE2总结] NtClose共拦截%ld次(hook已随EPT解除, 系统回到原生NtClose)",
			g_geptNtCloseCount);
	}
	//v3.52: MSR canary总结——LSTAR读计数+写报警定格(位图已随vmx_off
	//失效, rdmsr回到原生直通; 写>0=运行期有人patch syscall入口)
	FlLog("Unload: [STAGE2-MSR总结] LSTAR读%ld次/写%ld次(写>0=运行期patch "
		"syscall入口=安全信号); 伪造自测命中%ld次",
		g_geptLstarReadCount, g_geptLstarWriteCount, g_geptMsrForgeHits);
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
	{
		ULONG inGuestTotal = 0;
		for (ULONG i = 0; i < cpuCount; i++)
		{
			FlLog("cpu%d inGuest=%d launchFailed=%d vmxon=%d",
				i, g_vcpu[i].bInGuest, g_vcpu[i].bLaunchFailed, g_vcpu[i].bVmxOn);
			if (g_vcpu[i].bInGuest)
			{
				inGuestTotal++;
			}
		}
		//v3.53 v1.0.1: junior全败汇总——零核in-guest=本驱动VT启动全败。
		//两大成因: ①Hyper-V/VBS占用(传统形态) ②**同框架宿主已在场**
		//(新形态: 我们的vmxon在宿主guest内执行→rsn27 exit→宿主伪造
		//VMfailInvalid→__vmx_on逐核返回失败=VT-x原生互斥仲裁生效,
		//零签名零共享对象零暴露面)。旧版此形态=误导性STAGE日志+空载
		//常驻; 现在: 手动释放全部资源(DriverEntry失败时I/O管理器卸载
		//映像**不调DriverUnload**, 必须在此自清)+返回失败=sc start
		//报错干净退出, 宿主零扰动(互斥协议: 后到者让位)
		if (inGuestTotal == 0)
		{
			FlLog("DriverEntry: **零核in-guest——VT启动全败**。成因: "
				"Hyper-V/VBS占用 或 同框架宿主hypervisor已在场(其仲裁者对"
				"guest内vmxon伪造VMfailInvalid)。释放全部资源后干净退出, "
				"系统不受影响, 先到宿主继续服务");
			for (ULONG i = 0; i < cpuCount; i++)
			{
				if (g_vcpu[i].bVmxOn)
				{
					//防御性: vmxon成功但未进guest的核做标准停核
					//(junior全败形态下vmxon全失败bVmxOn=0, 此分支
					//理论上空转——保险不伤)
					KeSetSystemAffinityThread((KAFFINITY)1 << i);
					VmxStopCpu();
					KeSetSystemAffinityThread(allCpus);
				}
			}
			for (ULONG i = 0; i < cpuCount; i++)
			{
				VmxFreeCpuResources(i);
			}
			EptShutdownHighMappings();
			FlShutdown();
			Log("v1.0.1: junior refused (VT held by host/occupied), clean exit");
			return STATUS_UNSUCCESSFUL;
		}
	}

	//v3.47 Phase1: VMFUNC全核自测——逐核亲和性切换, 在该核guest内执行
	//CmVmfuncTest(vmfunc(0,1)→vmfunc(0,0)裸往返)。v3.48起list[0]=clean/
	//list[1]=hooked(真实双EPT), 本往返=真实视图切换环, 验证"指令在
	//non-root可执行+VMCS配置正确+list项合法"——任一环节错=当场rsn59
	//exit(case59跳过指令, 自测读到旧视图判FAIL)或#UD蓝屏(错误配置的核
	//当场暴露, 不留到hook期)。bVmfuncOn=0的核(能力探测未过)跳过=它们
	//的hook走v3.46 violation方案(fallback语义)
	{
		ULONG vmfuncOk = 0, vmfuncSkip = 0;
		for (ULONG i = 0; i < cpuCount; i++)
		{
			if (!g_vcpu[i].bInGuest)
			{
				continue;    //未进guest的核(启动失败/跳过)无从谈guest内自测
			}
			KeSetSystemAffinityThread((KAFFINITY)1 << i);
			if (g_vcpu[i].bVmfuncOn)
			{
				FlLog("[VMFUNC] cpu%u自测开始(切list[1]=hooked→切回list[0]=clean, 真实双EPT往返; 下一行=通过)",
					i);
				CmVmfuncTest();
				FlLog("[VMFUNC] cpu%u自测通过: EPTP切换往返零VM-Exit, VMFUNC链路OK",
					i);
				vmfuncOk++;
			}
			else
			{
				FlLog("[VMFUNC] cpu%u未启用(能力探测未过), 跳过自测(hook走violation方案)",
					i);
				vmfuncSkip++;
			}
			KeSetSystemAffinityThread(allCpus);
		}
		FlLog("[VMFUNC] Phase1全核汇总: 通过%u核, 跳过%u核(Phase2按此分派: VMFUNC主路径/violation fallback)",
			vmfuncOk, vmfuncSkip);
	}

	//v3.48 Phase2: 双EPT标记自测——hooked EPT里标记页GPA被改译到另一
	//物理页(EptInitEptData布防), guest内读同一VA三次:
	//  clean读="CLEANEPT" → vmfunc(0,1)切hooked读="HOOKEDPT" →
	//  vmfunc(0,0)切回clean读="CLEANEPT"
//"HOOKEDPT"的出现=VMFUNC切换到的是**真实独立翻译的第二套EPT**(Phase1
//往返no-op验证的功能升级; 若TLB残留旧翻译/切换未生效/rsn59被跳过,
//读到的都是旧视图值→FAIL)。FAIL核bVmfuncOn=0→hook走v3.46方案(按核
//降级, 互不影响)。测试线程已钉核(亲和性), 视图状态确定不串核
	{
		ULONG dualOk = 0, dualFail = 0;
		for (ULONG i = 0; i < cpuCount; i++)
		{
			if (!g_vcpu[i].bInGuest || !g_vcpu[i].bVmfuncOn)
			{
				continue;
			}
			KeSetSystemAffinityThread((KAFFINITY)1 << i);
			if (g_vcpu[i].PeptDataHooked != NULL && g_geptMarkVA != NULL)
			{
				volatile ULONG64* mark = (volatile ULONG64*)g_geptMarkVA;
				FlLog("[双EPT] cpu%u标记自测开始: 同一VA两视图应读CLEANEPT/HOOKEDPT",
					i);
				ULONG64 v0 = *mark;          //clean视图(恒等): 应=CLEANEPT
				CmVmfuncSwitch(1);           //切hooked视图(零VM-Exit)
				ULONG64 v1 = *mark;          //hooked视图(remap): 应=HOOKEDPT
				CmVmfuncSwitch(0);           //切回clean视图
				ULONG64 v2 = *mark;          //应=CLEANEPT
				if (v0 == GEPT_MARK_A && v1 == GEPT_MARK_B && v2 == GEPT_MARK_A)
				{
					dualOk++;
					FlLog("[双EPT] cpu%u标记自测通过: %llX→%llX→%llX(两套EPT真实独立生效, VMFUNC切换闭环)",
						i, (unsigned long long)v0, (unsigned long long)v1,
						(unsigned long long)v2);
				}
				else
				{
					dualFail++;
					g_vcpu[i].bVmfuncOn = 0;    //降级: 该核hook走violation方案
					FlLog("[双EPT] cpu%u标记自测FAIL: %llX→%llX→%llX(期望CLEANEPT→HOOKEDPT→CLEANEPT)——降级violation方案",
						i, (unsigned long long)v0, (unsigned long long)v1,
						(unsigned long long)v2);
				}
			}
			else
			{
				dualFail++;
				g_vcpu[i].bVmfuncOn = 0;    //无hooked EPT/标记页: 同样降级
				FlLog("[双EPT] cpu%u无hooked EPT/标记页, 降级violation方案", i);
			}
			KeSetSystemAffinityThread(allCpus);
		}
		FlLog("[双EPT] Phase2标记自测汇总: 通过%u核, FAIL降级%u核(hook安装按核分派VMFUNC/violation)",
			dualOk, dualFail);
	}

	//v3.49 Phase3(隐藏): TSC补偿+CPUID伪装自测——逐核钉核测量(钉核=每核
	//VMCS独立TSC_OFFSET, 迁移会混核)。本块全程运行于guest(non-root):
	//__rdtsc读数已被硬件加offset, CPUID走我们的exit handler=自证闭环
	//  ①基线: 相邻rdtsc对(纯guest执行零exit)≈几十cycle
	//  ②单次CPUID环绕(1次VM-exit): 补偿生效=只剩asm测不到的硬件exit/
	//    entry转换(百cycle级); 补偿失效(offset未应用)=全exit成本千cycle级
	//  ③1000次CPUID平均: 放大信号(顺带走0x40000000伪造分支=一举两得)
	//  ④CPUID.0x40000000返回值(应全0)+CPUID.1.ECX.bit31(应0)
	{
		ULONG hideOk = 0;
		for (ULONG i = 0; i < cpuCount; i++)
		{
			if (!g_vcpu[i].bInGuest)
			{
				continue;
			}
			KeSetSystemAffinityThread((KAFFINITY)1 << i);
			//①基线: 相邻rdtsc(纯guest执行)
			ULONG64 b0 = __rdtsc();
			ULONG64 b1 = __rdtsc();
			//②单次CPUID环绕(1次exit; 测量窗口两端的硬件转换+补偿扣除
			//都在窗口内, 读数=补偿后guest可见成本)
			int ci[4] = { 0 };
			ULONG64 t0 = __rdtsc();
			__cpuidex(ci, (int)0x40000000, 0);
			ULONG64 t1 = __rdtsc();
			//③1000次平均(leaf=0x40000000=伪造分支+exit, 信号放大)
			ULONG64 l0 = __rdtsc();
			for (volatile LONG n = 0; n < 1000; n++)
			{
				__cpuidex(ci, (int)0x40000000, 0);
			}
			ULONG64 l1 = __rdtsc();
			//④CPUID伪装值(读取经我们的handler=伪造结果的自证)
			int hv[4] = { 0 };
			__cpuidex(hv, (int)0x40000000, 0);
			int f1[4] = { 0 };
			__cpuidex(f1, 1, 0);
			ULONG hvZero = (hv[0] == 0 && hv[1] == 0 && hv[2] == 0 && hv[3] == 0);
			ULONG bit31 = (f1[2] >> 31) & 1;
			hideOk += (hvZero && !bit31) ? 1 : 0;
			FlLog("[隐藏] cpu%u TSC补偿: 基线=%llu cyc 单次CPUID(1exit)=%llu cyc "
				"1000次均=%llu cyc | CPUID.0x40000000=%08X %08X %08X %08X(全0=%s) "
				"CPUID.1.ECX.bit31=%lu(应0)",
				i,
				(unsigned long long)(b1 - b0),
				(unsigned long long)(t1 - t0),
				(unsigned long long)((l1 - l0) / 1000),
				hv[0], hv[1], hv[2], hv[3], hvZero ? "OK" : "FAIL",
				bit31);
			KeSetSystemAffinityThread(allCpus);
		}
		FlLog("[隐藏] Phase3自测汇总: %u核CPUID伪装全绿(TSC判读: 单次exit成本"
			"=残留硬件转换~1-2k cyc(SDM: 无法软件扣除); 若offset未被应用"
			"=全成本2.5k+且卸载't'事件=0; 最终裁决看卸载't'=累计隐藏总时长)",
			hideOk);
	}

	//==== v3.53 v1.0.1: 病毒模拟自测(VMX指令族exit处置的终审) ====
	//在当前核的guest内真实执行VMXOFF/VMXON——模拟内核态病毒的反虚拟化
	//探针(安全软件用本框架调试病毒的场景里, 病毒真会做的事)。仅依赖
	//VT不依赖hook, 任何stage都跑; VT已确认≥1核in-guest(否则上方已退出)
	{
		//①VMXOFF探针: 期望宿主case26注入#UD→内核SEH捕获→异常码
		//=0xC000001D(STATUS_ILLEGAL_INSTRUCTION)=裸机行为逐位一致
		//(裸机上该指令同样#UD——病毒探针零泄漏)。这是**v3.47c确切
		//死法的正规判据重放**: 当年这条机器码蓝屏过整机, 现在它必须
		//活着穿过新case; 无异常=新case未注入(FAIL), 蓝屏='U'逃生回归
		NTSTATUS udCode = STATUS_SUCCESS;
		__try
		{
			GeptVirusVmxDetectOff();
			//到达=无异常=宿主未注入#UD(判FAIL, udCode仍=0)
		}
		__except (udCode = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)
		{
		}
		//②VMXON探针: 期望宿主case27伪造VMfailInvalid(CF=1)→探针
		//setc返回1=VT-x原生互斥仲裁在场的活体证据(同框架junior实例
		//的__vmx_on走的就是这条路)
		ULONG64 vmonCf = GeptVirusVmxOn();
		FlLog("[v1.0.1] 病毒模拟自测: VMXOFF探针异常码=0x%X(应C000001D="
			"#UD注入=裸机一致) VMXON探针CF=%llu(应1=伪造VMfailInvalid=互斥"
			"仲裁在场)——两项全对=VMX指令族处置毕业(v3.47c死法已封死)",
			udCode, (unsigned long long)vmonCf);
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
#elif GEPT_HOOK_STAGE >= 1
	//自测: 目标函数与跳板都在hook.asm, 前15字节指令布局完全已知
	//v3.45: 条件==1改>=1——STAGE2也先跑自测(机制前置验证: 8核EPT
	//hook链路确认无恙后再碰系统函数NtClose)
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
	//v3.48: 零VM-Exit证据——VMFUNC主路径下hook触发是纯EPTP翻译切换
	//(hooked视图hook页→CodePage), 全程零EPT violation(v3.46方案每次
	//触发至少1次)。r48为全局计数, 此时全系统唯一受限页=本hook页且
	//无背景violation → Δ=0即VMFUNC hook闭环直接证据; Δ>0=该核走了
	//violation方案(看[双EPT]自测是否FAIL降级)或写兜底被触发
	LONG64 r48Before = g_flExitCounts[EXIT_REASON_EPT_VIOLATION];
	GeptTestTarget();
	LONG64 r48After = g_flExitCounts[EXIT_REASON_EPT_VIOLATION];
	FlLog("[STAGE1] 零VM-Exit证据: r48 %lld→%lld(Δ=%lld, VMFUNC主路径应Δ=0; violation方案Δ=1+)",
		(long long)r48Before, (long long)r48After,
		(long long)(r48After - r48Before));
	FlLog("[STAGE1] 自测调用返回(未死机未蓝屏), EPT hook全链路打通");
	Log("stage1: self-test hook done");
#if GEPT_HOOK_STAGE >= 2
	//v3.51 Phase6: STAGE 2——hook ntoskrnl!NtClose经简易API(detour式)。
	//v3.45硬编码prologue校验/v3.46 hookLen==22强校验/AsmHookNtClose重放
	//跳板**全部退役**(三者=绑定本机Windows版本的根源): GeptHookInstall
	//内部PHBuildRelocTrampoline动态生成重定位跳板(LDE解码+RIP-relative
	//重算+回扫自检), prologue不可重定位=Install当场拒绝——任何Windows
	//版本通用; "跳回落点≠重放长度"被构造性根除(重放MinLen与CodePage
	//跳转覆盖长度同源=严格同长, v3.46教训不复存在)
	{
		//==== v3.50 Phase4: STAGE 2 = API demo(detour式三段生命周期) ====
		//demo回调=DemoNtCloseCallback(计数+采样+GeptCallOriginal透传
		//并返回真实NTSTATUS)——detour完整控制权的活体演示
		GEPT_HOOK geptDemo = { 0 };
		geptDemo.Target = (PVOID)NtClose;
		geptDemo.Callback = DemoNtCloseCallback;
		geptDemo.Context = NULL;
		NTSTATUS apiSt = GeptHookInstall(&geptDemo);
		if (NT_SUCCESS(apiSt))
		{
			//v3.51 Phase6: replay自测——直接调用本hook的重定位跳板(副本
			//prologue→尾jmp进原函数体→完整执行→正常返回)。伪句柄-1=
			//NtClose安全且确定的判据: 应返回STATUS_INVALID_HANDLE
			//(0xC0000008)=LDE重定位生成器(版本无关化核心)的上机证据;
			//跳板页未被hook, VMFUNC核/fallback核语义一致
			NTSTATUS replaySt = GeptApiSelfTestReplay((PVOID)NtClose,
				(ULONG64)NtCurrentProcess());
			FlLog("[STAGE2-API] replay自测: NtClose(-1)经重定位跳板返回0x%X"
				"(应0xC0000008=STATUS_INVALID_HANDLE, 任何偏差=生成器bug立即暴露)",
				replaySt);
			FlLog("[STAGE2-API] NtClose已装(detour): 触发链=CodePage跳转→trampoline槽"
				"→GeptStubEntry(GeptViewSwitch按核分派)→DemoNtCloseCallback(计数+采样)"
				"→GeptCallOriginal(VMFUNC核直call原入口/fallback核重定位跳板)→ret");
			Log("stage2: NtClose hook installed");
			//三段式生命周期演示(每段2s): 装→拦截增长→移除→拦截冻结→重装→恢复
			//=Install/Remove/Reinstall闭环证据, Phase 4毕业判据
			LARGE_INTEGER tick;
			tick.QuadPart = -2000000LL;    //2秒
			LONG64 r48a = g_flExitCounts[EXIT_REASON_EPT_VIOLATION];
			LONG n0 = g_geptNtCloseCount;
			KeDelayExecutionThread(KernelMode, FALSE, &tick);
			LONG64 r48b = g_flExitCounts[EXIT_REASON_EPT_VIOLATION];
			LONG n1 = g_geptNtCloseCount;
			FlLog("[STAGE2-API] 窗口1(已装,2s): 拦截%ld→%ld(+%ld), Δr48=%lld"
				"(应: 拦截增长; Δ=0=全VMFUNC核零VM-Exit, Δ>0=含fallback核violation降级属正常)",
				n0, n1, n1 - n0, (long long)(r48b - r48a));
			//移除: CodePage字节还原+全核invept(vmcall(7)×8核)→hook死透
			NTSTATUS rmSt = GeptHookRemove((PVOID)NtClose);
			if (NT_SUCCESS(rmSt))
			{
				KeDelayExecutionThread(KernelMode, FALSE, &tick);
				LONG n2 = g_geptNtCloseCount;
				FlLog("[STAGE2-API] 窗口2(已移除,2s): 拦截%ld→%ld(+%ld)"
					"(应: ≈0=移除生效, NtClose直回原函数)",
					n1, n2, n2 - n1);
				//重装: PHHook重整页复制+重打跳转(EPT已布防无需再广播)
				GEPT_HOOK geptDemo2 = { 0 };
				geptDemo2.Target = (PVOID)NtClose;
				geptDemo2.Callback = DemoNtCloseCallback;
				geptDemo2.Context = NULL;
				NTSTATUS reSt = GeptHookInstall(&geptDemo2);
				if (NT_SUCCESS(reSt))
				{
					KeDelayExecutionThread(KernelMode, FALSE, &tick);
					LONG64 r48c = g_flExitCounts[EXIT_REASON_EPT_VIOLATION];
					LONG n3 = g_geptNtCloseCount;
					FlLog("[STAGE2-API] 窗口3(重装,2s): 拦截%ld→%ld(+%ld), Δr48=%lld"
						"(应: 恢复增长=Install/Remove/Reinstall生命周期闭环)",
						n2, n3, n3 - n2, (long long)(r48c - r48b));
					ULONG live = 0;
					GeptHookEnumerate(NULL, &live);
					FlLog("[STAGE2-API] 生命周期闭环: 装Δ%ld/卸Δ%ld/重装Δ%ld, 枚举live=%u"
						"(此后NtClose持续detour监控直至卸载GeptApiRemoveAll)",
						n1 - n0, n2 - n1, n3 - n2, live);
				}
				else
				{
					FlLog("[STAGE2-API] **重装失败(0x%X)**——保持无hook状态继续观测", reSt);
				}
			}
			else
			{
				FlLog("[STAGE2-API] **Remove失败(0x%X)**——保持已装状态继续监控", rmSt);
			}
		}
		else
		{
			//v3.51: AsmHookNtClose重放路径已随Phase 6退役(hook.asm同删)——
			//Install失败(零核in-guest/prologue不可重定位/资源不足)即放弃
			//STAGE2 hook: STAGE1自测已过, 系统保持无hook稳定运行(绝不带病上机)
			FlLog("[STAGE2-API] API安装未成(0x%X)——重定位跳板拒绝或资源不足;"
				"保持无hook状态(STAGE1自测已过, 系统稳定, 不再退回旧asm重放路径)",
				apiSt);
		}
	}
#endif
#if GEPT_HOOK_STAGE >= 1
	//==== v3.52 Phase5: MSR拦截demo(伪造自测+LSTAR canary) ====
	//仅依赖VT(与EPT hook无关), STAGE1门槛即可; 默认stage=2紧跟
	//STAGE2-API块之后执行
	{
		//--- 1) 保留MSR伪造自测: 全链路终审 ---
		//0xC00000B0=架构保留MSR(Intel/AMD均未定义, 真读=#GP): 无人
		//读=零干扰; guest内rdmsr若未被拦截=本行直接#GP蓝屏——Install
		//的位图回读自检已确保就绪, 这一行是链路的最终裁决(未拦截=
		//蓝屏, 拦截=拿到伪造标记值)。移除后**不再读**(位图已清=直通
		//=保留MSR真读=#GP)
		GEPT_MSR_HOOK msrForge = { 0 };
		msrForge.Msr = 0xC00000B0;
		msrForge.OnRead = DemoMsrForgeRead;
		NTSTATUS msrSt = GeptMsrHookInstall(&msrForge);
		if (NT_SUCCESS(msrSt))
		{
			ULONG64 forged = __readmsr(0xC00000B0);
			FlLog("[STAGE2-MSR] 伪造自测: rdmsr(保留MSR 0xC00000B0)返回%llX"
				"(期望DEADBEEFCAFEBABE), 命中%ld次——相等即全链路证明"
				"(guest RDMSR→位图exit→分发→回调伪造值→rax:rdx)",
				(unsigned long long)forged, g_geptMsrForgeHits);
			GeptMsrHookRemove(0xC00000B0);
		}
		else
		{
			FlLog("[STAGE2-MSR] 伪造自测Install失败(0x%X)——跳过MSR demo(系统不受影响)",
				msrSt);
		}
		//--- 2) LSTAR canary: 读监控(原值)+写报警, 持续监控至卸载 ---
		//看雪4.3组合技的现代形态: 双EPT下clean视图读syscall入口字节
		//恒原始(EPT hook天然隐藏), 本canary补数据面——LSTAR读取计数
		//(谁在探测)+写入报警(运行期patch syscall入口=攻击行为)
		ULONG64 lstar0 = __readmsr(0xC0000082);    //安装前真实值(KiSystemCall64)
		GEPT_MSR_HOOK msrLstar = { 0 };
		msrLstar.Msr = 0xC0000082;
		msrLstar.OnRead = DemoMsrLstarRead;
		msrLstar.OnWrite = DemoMsrLstarWrite;
		NTSTATUS lstarSt = GeptMsrHookInstall(&msrLstar);
		if (NT_SUCCESS(lstarSt))
		{
			ULONG64 lstar1 = __readmsr(0xC0000082); //安装后: 经回调应返回原值
			FlLog("[STAGE2-MSR] LSTAR canary已装: 读=%llX(安装前=%llX, 应相等"
				"且读计数=1), 读%ld次/写%ld次(写>0=运行期patch syscall入口"
				"=安全信号); 持续监控至卸载(卸载总结打印计数)",
				(unsigned long long)lstar1, (unsigned long long)lstar0,
				g_geptLstarReadCount, g_geptLstarWriteCount);
		}
		else
		{
			FlLog("[STAGE2-MSR] LSTAR canary安装失败(0x%X)——MSR监控未生效(系统不受影响)",
				lstarSt);
		}
	}
#endif
#endif
	//放行T2的Desktop镜像: 到此驱动加载窗口期结束, 用户目录文件操作不再有死锁风险
	FlMarkEntryDone();
	return STATUS_SUCCESS;
}
