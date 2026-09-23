# README_AGENT.md — AI 协作者契约文档

> **本文档的读者是大语言模型 / 编码 Agent，不是人类。** 人类请阅读 [README.md](README.md)。
>
> 你（Agent）即将在一个**内核态 Type-1 hypervisor**项目上工作。这不是普通的驱动开发：
> 本框架在**正在运行的 Windows 系统**上虚拟化全部 CPU 核心。一个错误的 VMCS 字段、
> 一次错误的 RIP 推进、一个在错误 IRQL 上的阻塞调用，都会直接蓝屏（bugcheck）或
> 静默破坏内存。历史上每一个蓝屏判例都已写进本文档。
>
> 本文档包含三类知识：
> 1. **红线铁律**（§2）：惯性思维最想"修复"但绝对不能碰的代码模式，每条附违例后果；
> 2. **架构与执行模型**（§4-§7）：快速建立正确的系统心智模型；
> 3. **验证协议**（§10-§11）：改完之后如何证明没有破坏系统。

---

## 0. 阅读协议（元指令）

- **权威顺序**：源码注释 > 本文档 > README。若本文档与代码注释冲突，以代码为准，并视为本文档的 bug。
- 本文档**自包含**：不引用任何仓库外文档。
- §2 的每条铁律都标注了 `[违例后果]`。这些不是代码风格偏好，是已发生事故的总结。
- 修改任何 `.c/.h/.asm` 之前：先过 §9 的 checklist。
- 你无法在本机运行此项目（需要 Windows + VS2022 + WDK + 实机/测试签名环境）。你能做的验证是：静态编译正确性推理、与本文档契约的一致性核对、编码规范校验（§13）。
- **生成代码时的默认姿态**：这个代码库的设计决策经常与教科书/通用驱动开发直觉相反（§3）。当你觉得"这里明显写错了"时，**先假设是你错了**，去 §2/§3 找依据；找不到再向人类提出质疑。

---

## 1. 项目本质（30 秒版）

**GeptHooks = Windows 10/11 x64 内核驱动，用 Intel VT-x 接管正在运行的全部 CPU 核心，通过双 EPT 视图实现零 VM-Exit 的内核函数 hook，并对 guest（即被虚拟化的 OS）隐藏自身的全部存在痕迹。**

核心事实：

| 事实 | 含义 |
|---|---|
| 驱动形态，非可执行安装包 | 以源码并入使用者自己的驱动工程编译 |
| 全核接管 | `DriverEntry` → 逐核 vmlaunch，OS 从此运行在 EPT 之下 |
| 双 EPT 视图 | clean（恒等映射）/ hooked（hook 页改译 CodePage），按核持有 |
| hook 命中零 VM-Exit | hooked 视图取指直进 CodePage 跳转码，纯 guest 态 detour |
| 反检测是一等公民 | CPUID/TSC/时钟域/VMX 指令面/物理内存扫描/页表攻击全部有对策 |
| bug = 蓝屏 | 没有用户态进程的容错边界，一切以裸机正确性为准 |

**VMFUNC 专项说明**（易被旧资料误导）：本框架**不使用** VMFUNC 指令。VMFUNC（EPTP switching）本身是 hypervisor 探测面，已被封堵（ctls2 bit13=0，guest 执行 VMFUNC 触发 exit 59 → 注入 #UD = 裸机语义）。双视图切换全部由 root 侧 `__vmx_vmwrite(EPT_POINTER, ...)` 在 hook 安装/移除时完成。任何"为了性能引入 VMFUNC"的改动都是**方向性错误**。

---

## 2. 红线铁律（RED LINES — 绝对禁止清单）

每条格式：**规则 / 为什么 / [违例后果]**。按主题分组。编号 RL-xx 供引用。

### A. exit handler 上下文纪律（VMX root 态，最高危区）

- **RL-01** exit handler（`VmxExitHandler` 及其一切被调函数）内**绝不** `DbgPrint`/`KdPrint`/`DbgBreakPoint`。DbgPrint 内部有锁且可能引发 IPI 广播，而当前核正处于 VMX root、IF 状态受限。 `[同核重入死锁 → 系统冻结]` 日志只能用 `FlRingPush`（无锁环，任意 IRQL 安全）。
- **RL-02** exit handler / hook 回调 / IPI 上下文内**绝不** `FlLog`/`FlLogSpin`。FlLog 依赖 T1 后台线程落盘，exit 上下文等待它 = 等待一个可能永远不被调度的事件。`[死锁]`
- **RL-03** exit handler 内**绝不**阻塞/睡眠/等待对象/获取可能被占的锁。被中断的线程可能持有任意锁。 `[死锁/优先级反转]`
- **RL-04** exit handler 内**绝不**访问分页内存（可能缺页 → root 态 #PF）。 `[root 异常 → park]` 框架自身数据全部 NonPaged。
- **RL-05** 新增 exit 采样点**必须**带限流（`FlRingExit` 模式：同 (reason,rip) 计数，首事件+周期采样）。 `[风暴场景下观测体系自身成为放大器：行环写穿+写盘洪水]`
- **RL-06** exit handler 内的跨核并发计数用 `InterlockedXXX` + `static volatile`（多核同时 exit 是常态）。每核数组索引统一 `[cpu & 63]` 或 `[cpu & 127]`（与既有数组宽度一致）。

### B. RIP 推进规则（exit 分发核心语义，错=跳过指令或死循环）

- **RL-07** 指令性 exit（CPUID/RDMSR/WRMSR/VMCALL/INVD/RDRAND 等）：handler 逻辑完成后由公共尾码 `__vmx_vmwrite(GUEST_RIP, guestRip + exitCodeLen)` 推进。case 内不要自己推进（除非提前 return 且明确写了 RIP）。
- **RL-08** 非指令性 exit（外部中断 1 / interrupt-window 7 / triple fault 2 / EPT misconfig 49 / MTF 37 的部分路径）：**RIP 原样写回，绝不推进**。这些 exit 没有指令长度语义，推进 = 跳过 guest 指令。 `[副作用丢失 → 内存损坏/蓝屏]`
- **RL-09** 未知 exit 且 `exitCodeLen==0`：**既不能推进（len=0 推进=原地无限循环）也不能原样 resume（同样无限循环）**。唯一出路是 `VmxExitStormEscape('Z', ...)` 逃生（vmx_off 回真机重执行）。
- **RL-10** 逃生函数 `VmxExitStormEscape` 的唯一例外：reason 18（VMCALL）逃生时 RIP 必须推进（vmcall 指令本身已成功陷入，重执行会再次 vmcall）。

### C. VMX 指令族与防御 case 族

- **RL-11** VMX 指令族 exit（VMCLEAR/VMLAUNCH/VMPTRLD/VMPTRST/VMREAD/VMRESUME/VMWRITE/VMXOFF/VMXON/INVEPT/INVVPID）**必须**注入 #UD。裸机上"不在 VMX operation 执行这些指令 = #UD"，guest（含病毒/检测器）看到 #UD 才与裸机一致。 `[走 default 逃生=vmx_off 后真机重执行 VMXOFF=#UD 蓝屏；VMXON 可能真成功=抢占 root]`
- **RL-12** exit reason 56-81 的防御 case 族**不可删除**（RDRAND/RDSEED/INVPCID/ENCLS/UMWAIT/TPAUSE/SEAMCALL/TDCALL/RDMSRLIST 等）。当前控制位配置下理论不可达，它们是"must-1 控制位异变"的保险：case 语义按裸机模拟。 `[删掉=落 default 逃生=攻击者可诱导"指令执行后 hypervisor 消失"的检测向量]`
- **RL-13** VMFUNC 封堵不可拆除：procCtl2 bit13 保持 0 + exit 59 注入 #UD。 `[VMFUNC 在裸机不存在，若放行/仿真=EPTP list 可被探测=hypervisor 自曝]`
- **RL-14** `__vmx_on` 必须带 SEH（`__try/__except`）。宿主 Hypervisor 在场时该指令抛 #GP（内核态未处理异常=蓝屏）。SEH 捕获后与 VMfailInvalid 同语义返回。互斥仲裁（见 RL-33）依赖此行为。

### D. 双 EPT 视图纪律

- **RL-15** **视图是核级状态，绝不是线程/stub 级状态。** 绝不能恢复"hook 回调前后在 GeptStubEntry 里切换视图"的设计（历史方案：vmfunc(0,0) 切 clean → 回调 → vmfunc(0,1) 切回）。回调期间线程可能迁移到另一核，或被阻塞后本核跑其他线程——任何 stub 级切换都会造成"旧核视图错乱"。 `[竞态：原函数入口序言在错误视图取指 → CodePage 跳转码中段被当指令解码 → 0xC0000005 蓝屏]` 当前正确语义：回调恒在当前视图执行（嵌套 hook 正常触发，标准 detour 语义），`GeptCallOriginal` 经 LDE 重定位跳板（视图无关）调原函数。
- **RL-16** EPT 表（任一视图）PTE 修改后**必须** `EptInveptCurrent()`（本核）+ 对其他核 DPC 广播 vmcall 逐核失效。 `[陈旧 TLB → 硬件仍按旧翻译走 → 布防不生效或视图撕裂]`
- **RL-17** `EptPdeToPte` 拆 2M 页为 4K 时，新 PTE **必须继承源 2M 大页的 memoryType**（RAM=WB）。 `[漏设=整页 UC → 该 2M 区域所有访存变 uncached → 性能塌方 → 整机卡死]`
- **RL-18** 框架自有物理页（VMXON/VMCS/VMM 栈/位图/EPT 表等）**必须恒分配在低区 512GB 内**（EPT 恒等映射区，WB 快路径）。EPT 自检[5]会逐项核对，超限 = 放弃 vmlaunch。这不是建议，是 launch 前置条件。
- **RL-19** EPT 高区（512GB-256TB，MMIO 区）预建 1GB UC 大页 + RAM 位图（洞=UC）。exit 上下文**零动态建表**（`EptBuildHighMapping` 的 'A' 逃生路径只是兜底）。 `[exit 上下文分配失败/缺页 = root 崩溃；MMIO 误映射 WB = 硬件写缓冲错乱 = 整机冻结]`
- **RL-20** `invept(2, &ctx)`（all-context）是**合法且有效**的用法，勿"修复"为 single-context。注释里的写法经过 SDM 核对。

### E. hook 原函数调用与栈契约

- **RL-21** hook 回调内调用**本 hook 的原函数必须经 `GeptCallOriginal`**。直接 `call Target` = hooked 视图下取指进 CodePage 的 14B 跳转码（或其中段）= 无限递归或跳转码中段被解码成野指令。 `[0xC0000005 @ nt!RtlCopyMemory 系蓝屏]`
- **RL-22** `GeptCallOriginal` 的实现 = LDE 重定位跳板（`ReplayVA`：副本 prologue 重放 + 尾 jmp 回原函数体），**视图无关**。不要改成"切 clean 视图直调原入口"——那正是 RL-15 判例删除的方案。
- **RL-23** `hook.asm` 栈纪律不可破坏：`GeptStubEntry` 的 `sub rsp, 28h`（保证 call 点 RSP%16==0）；`GeptCallOrigAsm` 的 `sub rsp, 120h` 固定布局（32B 影子空间 + 32 槽栈参区，arg5 恒在 `[rsp+20h]`）。 `[x64 ABI 违反 = 被调函数 movaps 对齐 #GP 蓝屏族]`
- **RL-24** `GUEST_REGS.rsp` 的语义因路径而异，**不可统一**：hook 路径 = StubEntry 存的 RSP0（guest 入口 rsp=帧基+80h）；VM-exit 路径 = VMCS 硬件保存值。栈参数（第 5+ 参）统一取 `regs->rsp + 0x28`（x64 ABI：返回地址+32B 影子空间之后）。
- **RL-25** `GeptCallOrigAsm` 必须保持 `PROC FRAME` + unwind 指令（`.pushreg/.setframe/.allocstack`）：被调原函数抛异常且上层 SEH 捕获时，内核 unwinder 要能穿越此帧。 `[删 unwind = 异常展开野指针]`

### F. MSR 与时钟域

- **RL-26** MSR 位图（每核 4KB）的操作**必须**经 vmcall(8) → `GeptMsrBitmapOpRoot` root 直写。MSR 位图页已被 EPT 自我隐蔽改译到零页：guest 态（驱动代码在 guest 里跑）直写位图 = 写进零页 = 静默失效 + 事后回读自检假阳性。 `[MSR hook 整体失效且无报错（历史 P0 判例）]`
- **RL-27** **MSR 时钟（APeRF 0xE7/MPERF 0xE8/TMCCT 0x839）不做位图拦截**（v1.9b 裁决，勿回退）。GPU 驱动类 rdmsr 自旋环读者每次读产生 exit → r31 风暴 → GPU TDR 黑屏。残余 TSC 轴泄漏已低于晶体容差，无归因价值。
- **RL-28** 虚拟时钟计数器值（HPET/PM_TMR 仿真）**必须**过 `ClkClampMonotonic` 单调钳制：新值小于上次且差 < 半量程 → 钳到上次值。 `[快速连读时补偿量随 TSC_OFFSET 变负导致虚拟值倒退 = 裸机不可能的自造检测向量 + 等待环永不满足=卡死]`
- **RL-29** `IA32_TSC_DEADLINE`(0x6E0) 的读写 hook 必须做时间轴换算（读=真值+TSC_OFFSET，写=值-TSC_OFFSET），0 直通。 `[guest 写入的 deadline 是"虚拟 TSC 轴"上的值，root 代写硬件时必须换算回真实轴，否则定时器错位]`
- **RL-30** 时钟影子 flicker 的 PTE 必须**显式 UC 内存类型**（memoryType=0）。 `[WB 缓存里残留影子行 → 后续真值读不失效陈旧行 → 旧补偿值泄漏 = 检测向量]`
- **RL-31** MMIO 时钟页仿真读值 = 真值 + TSC_OFFSET/Ratio（与 guest 可见 TSC 同轴）。两轴不一致（如只透传真值）= 驻留泄漏 = hypervisor 直接证据。

### G. 物理地址与 KVA（多起蓝屏判例的根源）

- **RL-32** RAM 物理页 → 内核虚拟地址：**必须 `MmGetVirtualForPhysical`**。`MmMapIoSpace` 对普通 RAM 页返回 NULL 拒绝映射（它的契约是固件/MMIO 页）。反向：MMIO 时钟页用 `MmMapIoSpace`（勿混用）。
- **RL-33** 从 PTE/CR3/VMCS 字段提取物理地址**必须用位掩码**（bits 51:12，剥 NX bit63 等标志位）。裸写 `entry & ~0xFFF`：内核栈页 PTE 恒 NX=1 → 残留 bit63 → 垃圾"物理地址" → 野指针。 `[0x139(4) FAST_FAIL_INCORRECT_STACK：root #PF 落在 VMM 栈而非线程栈，异常分发栈归属校验失败]`
- **RL-34** `MmGetVirtualForPhysical` 的**返回值必须校验 canonical**（≥0xFFFF800000000000）或用已知合法范围 gate。它对 KsegAddressTable 覆盖缝隙的输入会返回**非 canonical 垃圾而非 NULL**。 `[0xD1 驱动读了非 canonical 地址]`
- **RL-35** `MmGetPhysicalAddress`+pool 分配的页给硬件页表用时**必须 4KB 对齐**（pool 只保证 16B 对齐；自建有 `EptAllocAlignedPage`——用 pool 头基址回退到页边界）。 `[硬件按页边界读页表 → 读到相邻 pool 对象 → 翻译指向随机物理页 → 数据损坏]`

### H. 生命周期与卸载（卸载路径 = 历史蓝屏重灾区）

- **RL-36** 卸载顺序**不可变动**：`GeptApiRemoveAll()`/`GeptMsrHookRemove()`（关 VT **前**，让在途回调安全完成）→ `VmxShutdownAllCpus()`（全核 IPI 原子退出 VT）→ `GeptApiFreeMemory()`（关 VT **后**，纯内存释放）。参考 `main.c` 的 `DriverUload`。
- **RL-37** 卸载 = `KeIpiGenericCall` 全核 IPI 原子广播（每核原子完成 vmcall(1) 退出 + 清 VMXE + 双 PGE 冲刷），**勿回退串行逐核方案**。串行方案两个已验证死法：① `0x50`（FlLog 睡眠窗内调度器切入其他进程线程 → TLB 跨进程污染）；② `0x7F`（DISPATCH 级 `KeSetSystemAffinityThread` 不迁移运行中线程 → 只退出 1 核 → 释放其余核仍在用的 VMCS）。
- **RL-38** IPI 上下文（IPI_LEVEL > DISPATCH，处理内零调度）：**绝不** FlLog/FlLogSpin/睡眠/等待。只 `FlRingPush`。 `[T1 线程也被 IPI 打断，任何等待=死锁]`
- **RL-39** vmx_off 前必须把 HOST_IDTR 恢复为 OS IDT。OS IDT 基址/limit 的**数据源是 VMCS 的 GUEST_IDTR_BASE/GUEST_IDTR_LIMIT**（vmx_off 时的 sidt 读到的是私有 Host IDT——v1.11a 判例）。 `[vmx_off 后 IDTR 仍指私有页 → 中断进私有门 → 递归异常 → 机器直接黑屏硬重启]`
- **RL-40** vmx_off 回真机的路径必须：`VmxJumGuestRegs`（从 GuestRegs 帧恢复非易失 GPR + 切换 RSP/RIP）+ `VmxRestoreDtrLimits` + `VmxRestoreOsIdtr`。易失寄存器不恢复是刻意的（vmcall/异常=调用边界）。
- **RL-41** 三重故障（exit 2）= `VmxTripleFaultPark`（vmx_off + sti/hlt 自旋继续服务中断，本核永久 park），**不是重执行**（重执行=真机再次三重故障=硬复位）。park 核的 VMM 栈/代码页仍被占用，`g_geptParkedMask` 守卫使 `VmxShutdownAllCpus` 拒绝卸载。
- **RL-42** `VmxSetupVmcs` 内 VCPU 结构（约 8.4KB）**必须指针访问**。值拷贝 = 内核栈溢出。

### I. 隐蔽与自我防护

- **RL-43** CPUID 处理 = 透传真实硬件结果 + 定点修饰（leaf1 ECX 清 bit31 hypervisor-present；leaf 0x40000000-0x4000000F 归零；leaf0 maxleaf 收敛到 0x1F 且只降不升）。**绝不全零/重写整个 leaf**。 `[leaf1 特性位丢失 = 系统行为未定义；缓存 leaf 含每核 APIC ID/拓扑，重写=失真=检测特征]`
- **RL-44** EPT 自我隐蔽页（框架私有物理页改译零页）被 guest 访问触发的 violation 兜底分支（环事件 'O' rsn48）：**只对该次访问放行权限**，绝不能恢复恒等映射（那是框架页身份，恒等恢复=自我隐蔽整体失效）。同时它是"框架路径误写隐蔽页"的暴露口留痕——出现即查调用方。
- **RL-45** CodePage 在 `GeptHookRemove` 释放前必须先 vmcall(12) 恢复恒等（双视图）。 `[物理页归还 pool 后 PFN 被复用，隐蔽残留 PTE 指向别人的页]`
- **RL-46** 互斥仲裁（防同机双实例）两层勿拆：0x3A 读伪造恒 1（让 junior 实例的 BIOS 检查判"VT 已被 BIOS 禁用"而干净退出）+ vmxon 时 #GP/SEH 仲裁（junior 资源全释，`sc start` 返回失败，I/O 管理器自动卸载，不调 DriverUnload）。
- **RL-47** VMCALL 签名门：内部 vmcall 在 r10/r11 携带 128 位签名（`GEPT_VMCALL_SIG0/SIG1`，common.h）。exit handler 的 VMCALL case 先校验，不符 = 'u' 环留痕 + 注入 #UD（= 裸机"不在 VMX operation"语义）。**改动签名值必须同步 common-asm.asm 三处 mov 立即数**（CmVmCall 一处 + 落地探针两段）。未知功能码（签名对但功能码不识）同样注入 #UD——静默放行 = hypervisor 泄漏。
- **RL-48** 落地探针 `CmGuestProbe`（common-asm.asm）是**结构件**：它是每个核 vmlaunch 的 GUEST_RIP 入口（自证 VM-entry+EPT 取指+exit+RIP 推进+vmresume 全链路）+ VM-entry failure（exit 33）时的逃生锚点（改写 RIP 到 `CmGeustRip` 纯栈恢复）。不可拆、不可"简化"。
- **RL-49** `GEPT_PROBE_MAGIC`(0x5ABE) 改动必须同步 common-asm.asm 的 `mov rcx, 5ABEh`。

### J. 时序与 TSC

- **RL-50** TSC offsetting 只单调向负推（`VmxTscCompensate`：每次 exit 的 root 驻留时长 + 采样点外净泄漏 K 全部从 guest 可见 TSC 扣除）。K 来自 `VmxTscCalibrateAll` 的每核校准（guest 态 rdtsc 夹逼空 vmcall 采样）。不要引入任何"正向补偿"——过补 = 时间轴前跳 = 检测向量。
- **RL-51** RDTSC/RDTSCP/RDMSR(0x10) 不开 exiting（procCtl bit12=0），靠硬件 TSC offsetting 自动加偏移——零 exit。exit case 16/51 仅作控制位异变的防御保留。

### K. 编码与构建（编译期就会咬人的）

- **RL-52** 源文件编码铁律：`.c/.h` = **UTF-8 带 BOM + 纯 CRLF**；`.asm` = **无 BOM + CRLF**；全部字符必须 GBK 可表示（执行字符集转换）。 `[无 BOM 的 .c/.h 被 cl 按 CP936 解析 → 中文注释/字符串撕裂 → C2001/C2143 连锁编译错误；ml64 对混合行尾崩溃]` **AI 工具改写文件后必须字节级验证 BOM+行尾**（工具默认常剥 BOM/转 LF）。
- **RL-53** 任何代码改动必须同步 `GEPT_BUILD_TAG`（common.h，打进日志第一行）。上机测试第一件事 = 核对横幅版本号（历史三次跑旧二进制的教训）。
- **RL-54** MSVC x64 不支持 `__asm` 内联汇编——需要裸指令（RDRAND/RDSEED/INVPCID 等 WDK 头缺 intrinsic 的）时写入 vmx-asm.asm。

---

## 3. 反直觉设计决策（"看起来错"但正确的代码）

当你产生"这段该重构/修复"的冲动时，先查此表：

| 直觉冲动 | 为什么是错的 | 正确认知 |
|---|---|---|
| "CPUID 应该过滤/白名单化隐藏细节" | 缓存/拓扑 leaf 携带每核 APIC ID、缓存共享拓扑，任何重写都是失真，失真=特征 | 透传构造 + 三处定点修饰（RL-43） |
| "外部中断应该拦截注入更可控" | 每个中断一次 exit + 注入延迟 = 双重暴露 | pinCtl=0 中断直投 guest IDT，零 exit 零延迟 |
| "MOV-DR 应该拦截防调试器" | 拦截 = 行为差异 = 检测向量 | DR 全真值直通（不拦） |
| "MSR 0x3A 读应该返回真值" | 真值 bit5（VMX enable）=1 但 guest 又执行 VMXON 会 #GP——矛盾即特征 | 读伪造恒 1 + VMXON #GP(0)：讲一个"BIOS 锁定且禁用 VT"的自洽故事 |
| "CR4 shadow 让 VMXE=0 是 bug" | GUEST_CR4 必须保持真值（VMXE=1，VMXON 持续有效），CR4_READ_SHADOW 清 bit13（guest 读 CR4 见 0） | CR4_GUEST_HOST_MASK=bit13：读走 shadow，写 VMXE 触发 exit 28 落地 |
| "TSC 偏移应该可正可负" | 补偿只有单向语义（扣驻留） | 单调向负（RL-50） |
| "invept(2,&ctx) all-context 太粗暴" | all-context 对本框架语义完全正确且更快 | 勿改 single-context（RL-20） |
| "EPT 拆页后原 PDE 指针应该跟踪释放" | 交付语义：泄漏 2 页/hook 换 exit 上下文零管理 | 有意为之，勿"修"（PageHook.c） |
| "互斥失败应该继续运行共存" | 双 hypervisor 共存 = 双方都暴露 | 仲裁互斥，junior 干净退出（RL-46） |
| "私有 Host IDT/CR3 是为了反检测" | host-state 字段 guest 架构上不可见，共享 OS IDT 零可观测差异 | 真实价值=exit 窗口内 NMI/异常/页表篡改竞态的**加固**（抗攻击，非反检测） |
| "时钟页应该整页仿真" | hal 热读是 GPR-MOV 族 | 快路径只仿真计数器读（零额外 exit），慢路径影子 flicker（RL-28/30/31），自然流量=0 |
| "看门狗蓝屏 0xDEADC0DE 是恶意行为" | Debug 构建专属：日志线程 30s 冻结时主动 bugcheck 抓 DMP | 这是调试设施，Release 构建整体不编译（§10.1） |
| "TSC 校准探针是死代码可删" | `TscCalibK` 被 `VmxTscCompensate` 消费 | 功能件（每 exit 补偿的一部分），非探针 |
| "EPT 自检/回扫自检失败应该警告后继续" | 带病上机 = 蓝屏在你不能调试的时机爆发 | FAIL → 放弃 vmlaunch / 拒绝安装 / 撤销安装（安全门语义） |

---

## 4. 架构地图

```
仓库根/
├── README.md / README_ZH.md     人类文档（英文/中文）
├── README_AGENT.md              本文档
├── DbgTools/                    调试工具集（见 §11，建设中）
└── GeptHooks/                   源码（VS 工程）
    ├── main.c                   使用示例：DriverEntry→VmxStartAllCpus→demo hooks→DriverUload
    ├── VMX.c/.h                 VT 核心：资源分配/VMCS 填充/vmlaunch/exit 分发/逃生/park
    ├── ept.c/.h                 EPT：恒等表构建/双视图/自检/自我隐蔽/拆页/HideRead/REP 仿真
    ├── PageHook.c/.h            CodePage 构建 + LDE 重定位跳板生成器（回扫自检）
    ├── GeptApi.c/.h             对外 hook API：Install/Remove/Enumerate/CallOriginal 分发
    ├── GeptMsr.c/.h             对外 MSR API：位图 root 直写/核掩码自检/分发
    ├── Clock.c/.h               时钟域封堵：发现/校准/布防/快慢路径仿真/影子 flicker
    ├── Cr3.c/.h                 私有 Host CR3：树构建/深拷贝/protect/释放
    ├── common.c/.h              日志系统（Fl* 家族）/黑匣子/看门狗（整体 #if DBG）
    ├── common-asm.asm           落地探针/CmVmCall 入口/三重故障 park
    ├── vmx-asm.asm              VM-exit 汇编壳/RootExceptStub/RDRAND 等助手
    ├── hook.asm                 GeptStubEntry（detour stub）/GeptCallOrigAsm（栈参转发桩）
    ├── reg.asm/.h               段寄存器/GDTR/IDTR 读写助手
    └── LDasm.c/.h               LDE 反汇编引擎（长度计算/指令边界）
```

关键数据流（一屏版）：

```
DriverEntry(main.c)
  → VmxStartAllCpus(VMX.c): FlInit→逐核VMXInitCpuAlloc(预分配)→Cr3Init(私有CR3树)
    →逐核VMXInitCpuStart: vmxon→vmptrld→VmxSetupVmcs→vmlaunch→CmGuestProbe自证→KEEP接管
    →内置hook: 0x3A读伪造(互斥) + 0x6E0时间轴换算 + (可选)0x38F perf同步
    →VmxTscCalibrateAll→ClkInitAll(时钟域布防)
  → DemoHookInstall(main.c): NtClose EPT hook + LSTAR MSR hook（示例，可替换为你的逻辑）

hook 命中（双 EPT 核，零 VM-Exit）:
  guest取指hook目标 → hooked视图PTE→CodePage → 目标偏移14B绝对跳转
  → trampoline槽(mov r10,entry; jmp GeptStubEntry) → SAVE_ALL
  → GeptCallbackDispatch → 你的回调(可GeptCallOriginal) → RESTORE_ALL → ret
  （fallback核: 同一跳转布局, 取指触发violation→root切视图→同一stub, 每次命中1+exit）

卸载(DriverUload): RemoveAll hooks → VmxShutdownAllCpus(IPI全核原子退出) → GeptApiFreeMemory
```

---

## 5. 执行模型（建立心智模型）

### 5.1 两种特权态

| | VMX non-root（guest） | VMX root（VMM） |
|---|---|---|
| 运行者 | OS 全部代码 + 我们的驱动代码（驱动在 guest 里！） | exit handler / vmcall 处理器 / DPC 里的 root 段 |
| 地址翻译 | 经 EPT（两套视图之一） | 不经 EPT（裸物理），走**私有 Host CR3** |
| 触发进入 | 敏感指令/事件 → VM-exit | — |
| 关键约束 | — | 见 §2.A 全部铁律（IRQL/锁/分页/日志纪律） |

**关键认知**：本驱动的代码大部分时间以 guest 身份运行（包括 `GeptHookInstall` 的 PASSIVE 段）；只有 exit handler、vmcall 处理器内段、以及显式 root 段（MSR 位图直写、EPT 表操作）在 root 态。**同一函数可能两种态都跑**——用"当前是否在 exit 处理链"判断纪律适用性。

### 5.2 双 EPT 视图

- 每核 `VCPU` 持有 `PeptData/Eptp`（clean：全恒等）+ `PeptDataHooked/EptpHooked`（hook 页 PTE→CodePage）。
- 切换 = root 侧 `__vmx_vmwrite(EPT_POINTER, ...)`（hook 安装/移除的 DPC 广播时逐核执行一次）。
- 当前视图查询：`EptGetActiveData()`（vmread EPT_POINTER 比对，仅 root 上下文）。
- hook 页 PTE 形态：X=1,R=1,W=0（exec-only 时 R=0，见 HideRead）。原页物理页从未被写字节。
- VMFUNC 已封堵（RL-13）。guest 任何 VMFUNC 尝试 = #UD。

### 5.3 VM-exit 分发（VmxExitHandler）

```
vmread五元组(reason/len/RIP/RSP/exitQual) → 风暴限流(同(reason,rip)>500逃生'D')
→ switch(reason):
   10 CPUID→透传+修饰 | 18 VMCALL→签名门→功能码分发(§6.4) | 31/32 MSR→hook分发/代执行
   28 CR访问→CR4影子化落地 | 30 IO→时钟端口仿真 | 48 EPT violation→EptExitHandler
   (hook读透明MTF/时钟flicker/REP仿真/隐蔽页兜底 全在此内)
   37 MTF→flicker回捕/读透明回捕 | 49 misconfig→留痕+计数逃生
   0 异常NMI→注入决策 | 1 外部中断→'I'留痕(理论不可达) | 2 三重故障→park
   19-27,50,53,59 VMX指令族→#UD注入 | 56-81 防御case族→按裸机语义
   default→'Z'/'U'逃生(vmx_off回真机)
→ 公共尾: vmwrite(GUEST_RIP, rip+exitCodeLen)   ← 指令性exit统一推进
```

### 5.4 asm 帧布局契约（改 hook.asm/分发器前必背）

`GeptStubEntry` 的 SAVE_ALL 帧（push 序，rax 最低）：

```
偏移(帧基起): rax@00 rcx@08 rdx@10 rbx@18 rbp@20(双push占位) rsi@30 rdi@38
              r8@40 r9@48 r10@50 r11@58 ...（r10槽=API条目, C侧重取@[rsp+78h]）
RSP0(guest入口rsp)=帧基+80h;  栈参数首址=RSP0+28h  (= C侧 regs->rsp+28h)
sub rsp,28h 后 call 点 RSP%16==0  —— 28h 不是笔误(20h=栈错位#GP)
```

`GUEST_REGS`（common.h）= exit 路径的 C 侧寄存器帧，字段顺序与上表一致（rbp 槽=真实 rbp）。

### 5.5 每核资源（VMXInitCpuAlloc 分配，全部低区 512GB 内 + EPT 自我隐蔽）

VMXON / VMCS / VMM 栈(5 页, HOST_RSP=栈基+0x5000) / MSR 位图(4KB) / I/O 位图(8KB) / 双 EPT 表 / 私有 Host IDT(4KB, 256 门→VmxRootExceptStub) / 共享: 高区 pdpt 块 + 拆分 pte arena(8×2MB) + 标记页 + 零页。

### 5.6 私有 Host CR3（Cr3.c）

root 态 HOST_CR3 指向私有树：VMM 自身页=深拷贝页表路径（guest 改共享 PTE 不影响 root），guest 世界页=浅拷贝（共享，裸机等价），用户半区恒零。全局单树共享，`Cr3ProtectAuto` 运行期把新分配（API 条目/跳板）私有化。树未就绪=回退 launch CR3（可用性优先，'K'环 c=0 可辨）。

---

## 6. API 契约（二次开发视角）

### 6.1 EPT hook（GeptApi.h，完整契约见其头注释）

```c
GEPT_HOOK hook = { 0 };
hook.Target   = (PVOID)NtClose;        // 内核函数地址
hook.Callback = OnNtClose;              // detour 回调
hook.Context  = NULL;                   // 原样传回
hook.StackArgs = 0;                     // 目标第5+栈参数个数(0=不转发, ≤32)
hook.HideRead = 1;                      // 读透明(见下)
GeptHookInstall(&hook);                 // PASSIVE_LEVEL
GeptHookRemove((PVOID)NtClose);         // PASSIVE_LEVEL
```

- 回调签名 `ULONG64 (*)(Context, Arg1..Arg4, StackArgs*)`，返回值=hook 的新返回值（完整 detour 控制权：可改参/改返回值/吞调用）。
- `GeptCallOriginal(Arg1..Arg4)`：仅回调上下文有效（否则静默 0+'w' 环留痕）；栈参自动转发（回调对 StackArgs 的改写一并生效）。
- `HideRead=1`：hooked 视图 hook 页 R=0（exec-only，需 CPU 支持，否则自动回退）——读/写 violation → MTF 单步透出原页字节（PG/扫描器兼容），代价=该页每次数据访问 +2 exit。`HideRead=0`：读可见 14B 跳转字节。
- 嵌套语义：回调内调用其他 hook 目标正常触发（detour 语义）。
- 跳板池上限 8192 个 hook。

### 6.2 MSR hook（GeptMsr.h）

```c
GEPT_MSR_HOOK m = { 0 };
m.Msr = 0xC0000082;  m.OnRead = OnRead;  m.OnWrite = OnWrite;
GeptMsrHookInstall(&m);      // 全核位图root直写+核掩码自检
```

- 读回调返回值=rdmsr 可见值（伪造）；需真值调 `GeptMsrReadReal(Msr)`（**架构保留 MSR 勿调——root 真读 #GP**）。
- 写回调 TRUE=放行代写 / FALSE=静默丢弃。对系统运行期合法写的 MSR（GS base 等）慎用 FALSE。
- 纪律与 6.1 回调相同（exit 上下文，RL-01..04 全适用）。

### 6.3 回调上下文纪律（两类 API 共同）

回调运行在**原函数的任意线程、任意 IRQL（含 DISPATCH 级）**。只允许：Interlocked 操作 / 无锁环事件 / GeptCallOriginal / GeptMsrReadReal。禁止：FlLog/DbgPrint/分页内存/阻塞（= §2.A 铁律的来源）。

### 6.4 内部 vmcall 功能码表（common.h，签名门保护）

| 码 | 语义 | 参数 |
|---|---|---|
| 1 | 退出 VT（卸载路径） | — |
| 2 | EPT hook 布防（DPC 逐核） | rdx=原页PFN r8=CodePagePFN r9=HideRead |
| 3 | 探针末段 KEEP 放行 | — |
| 5ABE | 落地探针首段（'W' 留痕） | — |
| 7 | hook 移除：还原被覆盖字节 | rdx=目标VA r8=源VA r9=len |
| 8 | MSR 位图原语（root 直写） | rdx=MSR r8=act/rw 编码 |
| 10 | TSC 校准空探针 | — |
| 11 | 时钟布防（ClkArmCpu） | — |
| 12 | CodePage 隐蔽/恢复 | rdx=GPA r8=hide |
| 13 | 私有 CR3 树 protect | rdx=VA r8=len |

**新增功能码时**：功能码空间是安全面（RL-47）——未知码必须保持 #UD 注入语义，不得"宽容放行"。

---

## 7. 日志与观测体系（Debug 构建；Release 零代码）

### 7.1 Fl* 家族 IRQL 矩阵

| 接口 | 允许上下文 | 说明 |
|---|---|---|
| `FlLog` | 仅 PASSIVE_LEVEL | 格式化→行环，T1 线程落盘 Temp 权威副本 |
| `FlLogSpin` | ≤ DISPATCH_LEVEL | 自旋等待版（卸载/停止路径） |
| `FlRingPush` | **任意 IRQL（含 exit/IPI）** | 48B 二进制环条目，唯一 exit 安全通道 |
| `FlMarkEntryDone` | PASSIVE | 放行 T2 Desktop 镜像 |
| `FlShutdown` | PASSIVE | 解除看门狗+停线程 |

### 7.2 事件环 tag 表（日志判读/DMP 解析依赖；与 common.h 注释同步维护）

```
E=exit采样 V=violation(rsn48)或卸载vmcall(rsn18) S=布防(21/22/23) x=视图切换
W=落地探针 Q=guest续跑 F/f=热轮询开/关 T=三重故障 C=misconfig
D=同(reason,rip)环路 X=风暴逃生 A=动态建表失败 P=低址环路
Z=len0未知exit U=len>0未知exit R=vmresume失败 G=entry失败33
I=外部中断到达 i=中断交付 K=私有CR3 protect(c=1成/0降级)
v=IPI卸载留痕 r=卸载CR3取证(a=GUEST_CR3 b=回读 c=HOST_CR3快照)
M=MTF读透明布防 m=vmcall(7)还原字节 H=自我隐蔽完成
b=MSR位图root直写(a=MSR b=操作 c=核掩码) O=隐蔽异常(rsn0溢出/48兜底)
c=CodePage隐蔽(rsn12) t=卸载TSC_OFFSET终值 u=签名门拒绝(rsn18)/VMFUNC#UD(rsn59)
y=时钟仿真命中 a=时钟布防 l=时钟校准 g=慢路径flicker(c=1影子/0降级)
j=TSC校准(a=K) q=REP仿真命中 w=回调异常(线程迁移NULL臂, 已知项)
```

### 7.3 黑匣子与看门狗

Debug 构建创建双自旋看门狗线程（纯 rdtsc 计时）：行环游标 30s 不动 → 主动 `KeBugCheckEx(0xDEADC0DE)` → MEMORY.DMP 保留黑匣子（环尾快照+元数据）。**这是调试设施**；Release 构建 common.c 日志区整体 `#if DBG` 不编译，零线程零文件 I/O。

---

## 8. 蓝屏判例速查表（历史事故 → 根因 → 修复）

判读 DMP 时按 bugcheck 码定位（本表供理解"为什么铁律长这样"）：

| 症状 | 根因 | 判例教训 |
|---|---|---|
| 0x50 (PFN_NONPAGED) @ nt 内部 | stub 级视图切换竞态：线程迁移后原核视图错乱，原入口序言在错误视图取指 | RL-15（v1.10b 移除 stub 切换） |
| 0x50 卸载时 | 串行卸载 FlLog 睡眠窗内调度器切入其他进程 → TLB 跨进程污染 | RL-37（IPI 原子卸载） |
| 0x7F (DOUBLE_FAULT) | DISPATCH 级 KeSetSystemAffinityThread 不迁移运行中线程 → 只退 1 核 → 释放其余核在用 VMCS | RL-37 |
| 0x139(4) FAST_FAIL_INCORRECT_STACK | PTE 提取未剥 NX(bit63) → 野"物理地址"→ MmGetVirtualForPhysical 野指针 → root #PF 落 VMM 栈 → 异常分发栈校验失败 | RL-33 |
| 0xD1 读非 canonical | MmGetVirtualForPhysical 对 KSEG 缝隙输入返回非 canonical 垃圾（非 NULL） | RL-34 |
| 0x1E @ ntoskrnl | hook 页与 VT 机器码同 4K 页，EPT 布防把 vmcall 返回路径卷进双视图互切 | CodePage/框架页布局分离（RL-18/19） |
| 0x7E | demo 把 `L"NtClose"` 直接传 MmGetSystemRoutineAddress（需 PUNICODE_STRING） | API 用法判例（main.c 已正确） |
| 卸载瞬间黑屏硬重启 | vmx_off 后 IDTR 仍指私有 Host IDT → 中断进私有门 → 递归 | RL-39（从 GUEST_IDTR_BASE 恢复） |
| GPU TDR 黑屏 | MSR 时钟位图拦截 → rdmsr 自旋环 exit 风暴 | RL-27 |
| 编译崩 C2001/C2143 连锁 | .c/.h 无 BOM，cl 按 CP936 撕裂中文字符串 | RL-52 |
| ml64 崩 | 混合行尾 / 非 GBK 字符 | RL-52 |
| 卸载后蓝屏（延迟爆发） | park 核在场仍卸载（VMM 栈/代码页被占用） | RL-41 |
| 回调返回值错乱 | stub 帧retval/API条目未立即落帧（volatile 跨 C 调用） | hook.asm 帧契约（RL-23/24） |

---

## 9. 修改代码前的 Checklist（逐项过）

```
[ ] 我改动的函数在哪些上下文运行?(guest PASSIVE / exit handler / IPI / DPC) → §2.A 纪律适用?
[ ] 是否触碰了 exit handler 的 RIP 语义? → RL-07..10
[ ] 是否新增/删除 exit case? → RL-11/12 防御族不可删; 新case的RIP推进语义明确?
[ ] 是否涉及视图/EPT 表? → RL-15..20 (invept? memoryType继承? 512GB限?)
[ ] 是否动了 hook 链/asm? → RL-21..25 (帧契约? CallOriginal路径?)
[ ] 是否涉及 MSR/时钟/TSC? → RL-26..31, 50, 51
[ ] 物理地址/KVA 转换? → RL-32..35
[ ] 卸载/生命周期? → RL-36..42
[ ] 隐蔽面变化? → RL-43..49 (新框架页要进自我隐蔽清单!)
[ ] 新增内部 vmcall 功能码? → RL-47 签名+未知码#UD语义
[ ] GEPT_BUILD_TAG 已更新? → RL-53
[ ] 文件编码(BOM/CRLF/GBK) 字节级验证? → RL-52
[ ] 新观测点带限流? → RL-05
[ ] 新分配的框架页: 低区512GB内? 纳入EptHideFrameworkPages? 纳入私有CR3保护?
```

---

## 10. 构建与上机验证协议

### 10.1 构建

- VS2022 + WDK，x64，工程在 `GeptHooks/`（.sln/.vcxproj）。
- **Debug 构建（DBG=1）= 完整观测**：T1 写 `C:\Windows\Temp\gept_log.txt`（权威）+ T2 Desktop 镜像 + 二进制环 + 看门狗黑匣子。开发/排障一律用它。
- **Release 构建（DBG=0）= 零日志代码进产物**（Fl* 全部空操作宏，无后台线程/文件 I/O）。交付形态。
- 日志开关已废弃的旧机制（勿再引入）：注册表 LogEnable、`GEPT_LOG_ENABLE` 宏——现为 DBG 构建统辖。

### 10.2 上机判据序列（Debug 构建，每次改动后全过一遍）

1. **横幅**：日志第一行 `build vXXX` 与源码 GEPT_BUILD_TAG 一致（防旧二进制）。
2. **接管**：每核 `vmxon OK` → `vmlaunch成功` × 全核；私有 Host CR3/IDT 回读一致；EPT 自检 [1]-[9] 全 PASS。
3. **hook**：`[Reloc] 跳板就绪`(回扫自检过) → `[API] Install OK` → demo 拦截生效。
4. **运行**：零 'I'（外部中断意外 exit）/ 零 'O'（隐蔽异常）/ 零 'D'（环路）/ 'g' 环=0（时钟慢路径自然流量为零）。
5. **卸载**：MSR/API Remove OK → 'v'×全核 → 私有树释放（区数=boot+每 hook 增量）→ 干净收尾。
6. **Release 崩溃无环**：任何 Release 构建的崩溃，先换 Debug 构建复现再判读（Release 无观测）。

### 10.3 崩溃取证

Debug 构建崩溃 → `MEMORY.DMP`（看门狗 0xDEADC0DE 或原生）→ 用 §11 工具解析黑匣子环（物理散列免疫）→ 对照 §8 判例表。

---

## 11. 调试工具（DbgTools/）

> 路径：https://github.com/Huai-Tian/GeptHooks/tree/main/DbgTools
> 索引与用法详见 DbgTools/README.md。

| 工具 | 用途 |
|---|---|
| `gept_bb_parse.ps1`（Windows 实机主力） | 深度解析 MEMORY.DMP：黑匣子（GEPTBB01/02）+ 事件环全局 seq 重组（免疫 DMP 物理散列）+ 行环重组 + bugcheck 头 + 崩溃时 CR3 取证 |
| `gept_bb_parse.py`（沙箱/Linux） | 同类黑匣子解析（黑匣子段） |
| `ntkit.py` | 离线分析 ntoskrnl.exe（须同构建）：`info` / `at <RVA>`（函数识别+反汇编窗口）/ `callers <RVA>` / `bugcheck <code>`（raise 站点）/ `branches <RVA>` |
| `make_test_dmp.py` | 合成 DMP 回归测试（解析器改动的冒烟验证） |

**维护契约（改环相关代码时）**：环事件 tag 语义在 `common.h` 环 tag 注释、两个解析器的 tag 表三处同步；黑匣子布局变更同步解析器偏移常量。

用法原则：崩溃 DMP → 黑匣子解析出环时间线 → 最后一条事件 = 死亡点附近 → 对照 §8/§2 找根因；需 nt 符号级分析用 ntkit。**环是真相，文件日志的最后一行 ≠ 真实死亡点**（异步落盘滞后）。

---

## 12. 已知边界与残余臂（勿当 bug 修）

| 项 | 状态 | 说明 |
|---|---|---|
| 端口型时钟（PM_TMR SystemIO）串指令 | 残余臂 | INS/OUTS 逐迭代放行（I/O 位图机制），值未补偿；MMIO 型已全覆盖 |
| 影子页分配失败核 | 安全降级 | 时钟慢路径降级 plain flicker（真值放行），'g'环 c=0 可辨，自然流量 0 |
| 回调线程迁移（'w' 环事件） | 已知项 | s_currentHook 跨核失配 → CallOriginal 静默 0+一次性留痕，间歇出现 |
| Release 构建崩溃无观测 | 设计使然 | §10.2 第 6 条流程 |
| EPT 拆页每 hook 泄漏 2 页 | 交付语义 | exit 上下文零管理换来的，勿"修"（§3） |
| 高区 512GB-256TB 共享链 | 设计使然 | 全核共享 pdpt（MMIO 区无 per-core hook 需求） |
| MSR 时钟不封堵 | 裁决（RL-27） | 残余泄漏低于晶体容差地板 |
| 硬件级 DMA 检测 | 明确不管 | 超出 EPT/VT 能力域 |

---

## 13. 编码与提交规范

- **编码铁律**：RL-52（.c/.h=UTF-8 BOM+CRLF，.asm=无 BOM+CRLF，全 GBK 可表示；工具改写后字节级验证）。
- **代码注释**：中文；契约/不变式/判例教训写在紧邻代码处（本文档 §2/§3 的条目大多在源码有对应注释——修改行为时同步注释）。
- **每次代码改动**：同步 `GEPT_BUILD_TAG` + 日志判据（§10.2）更新到对应测试记录。
- **新增框架页/全局资源**：三件事同步——低区 512GB 分配、纳入 `EptHideFrameworkPages` 自我隐蔽清单、纳入私有 CR3 保护（`Cr3ProtectAuto`）。
- **不引入**：运行时日志开关/注册表配置（静态签名风险）、VMFUNC、任何"方便调试"的 exit 上下文阻塞调用。

---

*本文档随代码演进同步维护。若你（Agent）发现文档与代码冲突：以代码为准，并在你的修改说明中指出文档偏差。*
