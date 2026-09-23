# GeptHooks

简体中文 | [English](README.md) | [AI 协作文档](README_AGENT.md)

## 📖 介绍

**GeptHooks** 是一个隐藏式 Windows EPT 钩子框架（支持 Windows 10 - 11）。

它通过 Intel VT-x 虚拟化正在运行的系统，利用**每核双 EPT 视图（clean / hooked）**拦截函数执行——让你的驱动可以钩取任意内核函数，**不修改原始内存的任何一个字节，且每次钩子命中不产生任何 VM-Exit**。

执行流的重定向完全由 EPT 页表翻译完成：clean 视图恒等映射（读内存与 CRC 校验看到的全是原始字节），hooked 视图把钩子页改译到影子副本（目标偏移处是一条绝对跳转）。视图切换在钩子安装/移除时由 VMM 一次性完成，运行期命中是纯客户机态 detour——钩子的时间开销在构造上即为零。框架同时对客户机隐藏自身的全部存在痕迹：CPUID、TSC 时间轴、交叉时钟域、VMX 指令面、物理内存扫描、页表攻击均有对策。

> **使用 AI 助手（Copilot / Claude / GPT 等）参与本项目的二次开发？** 请先阅读 [README_AGENT.md](README_AGENT.md)——它专为 AI 编写，包含本项目大量**反直觉的安全设计与红线约束**，跳过它直接改代码极可能引入蓝屏级缺陷。

## ✨ 功能特性

- **双 EPT 视图零 VM-Exit detour**
  每个核心持有两套 EPT 视图：*clean* 视图（恒等映射，原始字节）与 *hooked* 视图（钩子页改译到影子副本）。命中 = 翻译直达，而不是陷入：**每次钩子命中零 VM-Exit**。实测：累计 **144 万+次** NtClose 拦截期间 EPT violation 计数始终为 0。

- **detour 完整控制权**
  回调收到原始参数，可以调用原函数（`GeptCallOriginal`）、修改参数或返回值、或整体吞掉这次调用。没有 prologue 重放，没有指令长度机器——clean 视图里就是完好如初的原始代码。

- **第 5+ 栈参数转发**
  安装时通过 `GEPT_HOOK.StackArgs` 声明目标函数栈参数个数（最多 32 个），回调即收到指向触发栈上实参的 `StackArgs` 指针（可读**可写**，改写后的值随 `GeptCallOriginal` 一并转发）——多参数内核函数的钩取不再有参数缺口。

- **版本无关的运行时跳板**
  跳板由 LDE 重定位引擎在运行时生成——逐指令解码、RIP-relative 重定位、生成后按 CPU 视角回扫自检。没有绑定某个 Windows 构建的硬编码 prologue：钩子可跨 Windows 版本安装；不可重定位的 prologue 在安装时即被拒绝。

- **钩子页读透明（可选）**
  `HideRead=1` 时钩子页在 hooked 视图仅可执行（exec-only）：任何读/写该页的访问被单步透出到原始字节——补丁防护（PG）与内存扫描器看到的就是原始页面。需要 CPU 支持 exec-only（`EPT_VPID_CAP` bit0），不支持时自动回退。

- **Hypervisor 全面隐身**
  - **CPUID**：透传真实硬件结果 + 定点修饰（清 hypervisor-present 位、归零 hypervisor 专用叶子、收敛 maxleaf）——不破坏特性位与缓存/拓扑信息；
  - **TSC 时间轴**：每次 VM-Exit 的 root 驻留时长经 TSC offsetting 从客户机可见 TSC 中扣除，并按每核校准值补偿指令开销——客户机时间线上"exit 从未发生过"；
  - **时钟域**：HPET / PM_TMR 计数器读取被仿真为与虚拟 TSC 同轴（含影子页 flicker：任意指令形态的慢路径读均得到补偿语义），交叉时钟对比无时间轴空洞；TSC-Deadline 定时器自动换算；
  - **VMX 指令面**：VMXON/VMXOFF/VMREAD 等指令族执行结果与裸机完全一致（#UD / #GP 语义模拟），病毒与检测器无从探测；VMFUNC 已封堵（裸机语义 #UD）；
  - **物理内存扫描免疫**：框架全部私有物理页（VMXON/VMCS/VMM 栈/位图/EPT 表/跳板页等）在两套视图统一改译零页——客户机物理内存扫描只见零。

- **root 态加固（抗篡改）**
  私有 Host IDT（256 门重定向）与私有 Host CR3（VMM 页表深拷贝隔离）：exit 窗口内的 NMI/异常投递与页表攻击面被隔离，客户机篡改 OS 的 IDT/共享页表无法触及 VMM。

- **互斥仲裁**
  同机第二实例在 `sc start` 时被原生机制干净拒绝（资源全释放后退出），不会与在位实例互相破坏。

- **简洁的驱动友好 API**
  在你自己的内核驱动里用几个 C 调用即可完成钩子的安装、移除、枚举与原函数调用——无需任何 hypervisor 背景知识。

- **MSR 拦截（读伪造 / 写监控）**
  通过每核 MSR 位图可钩取任意 MSR：读回调返回值即客户机可见值（可伪造），写回调可放行或静默丢弃。未钩取的 MSR 保持零开销直通。安装 / 移除 / 枚举与函数钩子 API 完全对称。

- **观测体系与交付形态构建统辖**
  整套观测设施（双写盘线程、二进制事件环、蓝屏黑匣子看门狗）由构建配置统辖：**Debug 构建 = 完整观测**（权威日志写入 `C:\Windows\Temp\gept_log.txt`，桌面尽力镜像；日志停滞 30 秒看门狗主动蓝屏抓取内存转储——调试设施，不进交付产物）；**Release 构建 = 零日志代码进产物**（无后台线程、无文件 I/O、零观测面）。刻意不用运行期/注册表开关：注册表值既是可以被 AV/EDR 静态签名的特征，也会在目标机上留下配置痕迹。

- **干净的交付形态**
  驱动入口只执行框架生命周期（资源分配 → 逐核启动虚拟化 → 互斥仲裁 → 常驻）与演示钩子（`main.c` 可替换为你自己的逻辑）。框架以源码形态集成——把源文件加入你自己的驱动工程即可。

## 📐 零 VM-Exit 钩子的工作原理

```
                clean 视图                    hooked 视图
                ┌────────────┐               ┌────────────┐
                │  恒等映射   │               │ 钩子页 PTE │
                └─────┬──────┘               └─────┬──────┘
                      │ 原始字节完好                 │ → 影子副本(CodePage)
   guest(运行视图由VMM按需切换)                    │ (X=1, R=1, W=0)
   ─────────────────┴──────────────────────────────┴─────────────────
        安装/移除: VMM 逐核切换 EPTP(一次性)——运行期命中零陷入
```

钩子触发链（全程客户机态，零 VM-Exit）：

```
调用者 → 目标函数(hooked视图=CodePage, 目标偏移处14字节绝对跳转)
  → 本hook独享的trampoline槽(mov r10,条目; jmp GeptStubEntry)
  → GeptStubEntry: SAVE_ALL → 分发你的回调
      (可 GeptCallOriginal: 经LDE重定位跳板调用原函数——视图无关,
        回调内调用的其他钩子目标正常触发=标准detour语义)
    → RESTORE_ALL
  ← 调用者(RAX = 你回调的返回值)
```

个别核心在罕见的资源条件下（hooked EPT 表深拷贝失败、布防自检不通过）会**自动降级**为经典 EPT violation 方案（取指陷入 → 视图切换 → 同一跳板链）——API 语义完全一致、你的代码零改动。

## 🚀 快速开始

安装并启动驱动：

```
sc create GeptHooks type= kernel start= demand binPath= "C:\path\to\GeptHooks.sys"
sc start GeptHooks
```

停止并卸载（全部钩子先被干净移除，随后通过 IPI 广播在全部核心原子关闭 VT）：

```
sc stop GeptHooks
sc delete GeptHooks
```

调试日志无需任何开关：直接用 **Debug 构建**即获得完整观测（文件日志 + 事件环 + 黑匣子看门狗）；**Release 构建**产物零日志代码。

## 🧩 API 使用

```c
#include "GeptApi.h"

// 你的detour回调: 运行在原函数的线程与IRQL上下文,
// 返回值即钩子函数的返回值。
// StackArgs: 第5+个参数(栈参数)数组, 可读可写——
// 改写后的值随GeptCallOriginal一并转发; 未声明StackArgs时为NULL。
static ULONG64 OnNtClose(PVOID Context,
    ULONG64 Arg1, ULONG64 Arg2, ULONG64 Arg3, ULONG64 Arg4,
    ULONG64* StackArgs)
{
    ULONG64 status = GeptCallOriginal(Arg1, Arg2, Arg3, Arg4);
    return status;   // 也可以伪造——你拥有完整控制权
}

// 安装 / 移除 / 枚举
GEPT_HOOK Hook = { 0 };
Hook.Target    = (PVOID)NtClose;
Hook.Callback  = OnNtClose;
Hook.Context   = NULL;
Hook.StackArgs = 0;   // 目标函数第5+栈参数个数(0=不转发; 见下方示例)
Hook.HideRead  = 1;   // 可选: 钩子页读透明(PG/扫描器只见原始字节)

GeptHookInstall(&Hook);
// ... 钩子已在全部核心生效 ...
GeptHookRemove((PVOID)NtClose);

ULONG Count = 0;
GeptHookEnumerate(NULL, &Count);   // 查询live钩子数量
```

钩取 6 参数以上（含栈参数）的函数——声明个数即可：

```c
// 目标原型: ULONG64 F(ULONG64 A1..A4, ULONG64 A5, ULONG64 A6);
GEPT_HOOK Hook = { 0 };
Hook.Target    = (PVOID)F;
Hook.Callback  = OnF;
Hook.StackArgs = 2;               // A5/A6 两个栈参数

static ULONG64 OnF(PVOID Ctx, ULONG64 A1, ULONG64 A2,
    ULONG64 A3, ULONG64 A4, ULONG64* StackArgs)
{
    StackArgs[0] ^= 1;            // 改写第5参——转发时生效
    return GeptCallOriginal(A1, A2, A3, A4);  // 栈参数自动转发
}
```

MSR 钩子（数据面）同样简单——安装、移除、枚举齐全：

```c
#include "GeptMsr.h"

static ULONG64 OnLstarRead(PVOID Ctx, ULONG32 Msr)
{
    return GeptMsrReadReal(Msr);   // 透传——也可以伪造任意值
}
static BOOLEAN OnLstarWrite(PVOID Ctx, ULONG32 Msr, ULONG64 Value)
{
    return TRUE;                    // TRUE = 放行, FALSE = 静默丢弃
}

GEPT_MSR_HOOK M = { 0 };
M.Msr     = 0xC0000082;             // IA32_LSTAR
M.OnRead  = OnLstarRead;            // NULL = 读直通
M.OnWrite = OnLstarWrite;           // NULL = 写直通
GeptMsrHookInstall(&M);

// ... 监控期间 ...
GeptMsrHookRemove(0xC0000082);      // 移除: 该MSR恢复直通

ULONG MsrCount = 0;
GeptMsrHookEnumerate(NULL, &MsrCount);   // 枚举live的MSR钩子
```

**回调上下文约定**：

1. 回调运行在原函数的线程与 IRQL 上下文（可达 DISPATCH 级）——回调内只应执行 IRQL 安全的操作（原子操作、无锁日志、`GeptCallOriginal`、`GeptMsrReadReal`）。
2. 调用本钩子的原函数**必须**经 `GeptCallOriginal`——它经版本无关的重定位跳板调用原函数并自动转发栈参数（直接调用原入口会在 hooked 视图下撞入跳转码）。
3. 嵌套语义（标准 detour）：回调内调用的其他钩子目标**正常触发**。
4. 读回调需要 MSR 真值时用 `GeptMsrReadReal`；对架构保留 MSR（真读即 #GP）绝不可调，直接返回伪造值。

卸载时须在关闭 VT **之前**移除全部钩子（`GeptApiRemoveAll`），关闭 VT **之后**再释放内存（`GeptApiFreeMemory`）——参考 `main.c` 的 `DriverUload` 标准序列。

## ⚙️ 环境要求

- **CPU**：支持 VT-x + EPT 的 Intel 处理器（Haswell 及以上可获完整特性；个别核心资源不足时自动降级，API 一致）
- **操作系统**：Windows 10 / 11 x64
- **虚拟化冲突**：需关闭 Hyper-V、基于虚拟化的安全（VBS）、内存完整性（核心隔离）与 WHP——GeptHooks 必须作为根 hypervisor 运行
- **测试签名**：执行 `bcdedit /set testsigning on` 开启测试签名，或对驱动进行正式签名
- **构建**：Visual Studio 2022 + Windows Driver Kit（WDK）
- **运行**：管理员权限

## 🧪 能力验证矩阵

全部核心路径已在真实硬件（8 核 Intel Skylake，Windows 10 x64）完成多轮实测：

| 能力 | 实测证据 |
|---|---|
| 全核 VT 接管 | 8 核逐核 vmlaunch → 接管 → 干净卸载，多轮稳定（含长时间运行） |
| 零 VM-Exit 拦截 | 累计 144 万+ 次 NtClose 拦截，EPT violation 计数恒为 0 |
| detour 完整控制权 | 六参靶自测四证明（读回 / 栈参改写 / 寄存器改写 / 移除恢复） |
| 版本无关跳板 | LDE 跳板回扫自检逐条通过；重放自测 NtClose(-1) = 0xC0000008 |
| MSR 数据面 | 保留 MSR 读伪造为 `DEADBEEFCAFEBABE`；LSTAR canary 计数与写入监控 |
| TSC 时间轴 | 每 exit 净驻留补偿至千 cycle 级（ppm 级一致），卸载驻留量化留痕 |
| 时钟域同轴 | HPET / PM_TMR 读取与虚拟 TSC 同轴；自然流量零额外 exit（慢路径环事件 = 0） |
| 物理扫描免疫 | 框架页双视图改译零页，EPT 布防自检逐项通过 |
| root 态加固 | 私有 Host IDT / CR3 每核接线回读一致；页表深拷贝区数十个闭环 |
| 全核原子卸载 | IPI 广播每核原子退出（零调度零窗口），静置压力多轮全绿 |
| Release 交付形态 | 无日志构建长时间运行无异常 |

## ⚠️ 项目状态

全部核心路径（虚拟化、双 EPT 钩子、隐身、detour API、运行时重定位、MSR 数据面、时钟域封堵、root 态加固）已在真实硬件上完成分阶段实测毕业。本框架为研究级质量：hypervisor 层的缺陷仍可能导致蓝屏——**请务必在可弃置的测试机上运行**。

## 🚫 非商业声明

本项目由开发者出于个人兴趣与技术研究目的发起，具有**非商业**性质：

- **永久免费**：
本项目完全免费，**没有任何付费功能、会员、订阅或内购**。所有功能对所有用户完全开放。

- **无赞助渠道**：
作者**从未开设任何赞助渠道**，也**不接受任何形式的金钱捐赠**——以保持项目的中立性与纯粹性。

- **非营利目的**：
本项目不涉及任何商业运营，作者不会从中获取任何直接或间接的经济利益。

- **研究导向**：
本项目始终定位于**安全研究、驱动开发与软件测试**——为社区提供研究工具，而非商业产品。任何对本项目的商业使用均为使用者个人行为，与本项目无关。

- **禁止转售**：
严禁转售、以营利为目的的再分发或商业使用。请仅从本仓库（GitHub）或其他官方指定渠道获取。开发者对非官方渠道产生的任何问题概不负责。

## ⚖️ 免责声明

- **用途限制**：
本项目仅供**安全研究、驱动开发、软件测试与学习交流**使用。
请勿将本项目用于任何非法用途（包括但不限于恶意软件开发、反作弊绕过、数据窃取与系统入侵）。

- **后果警示**：
使用本框架进行钩取**可能违反第三方软件的服务条款及你所在司法辖区的法律**。
使用前请自行评估风险。开发者与贡献者**对由此产生的任何账号封禁、法律责任或其他后果概不负责**。

- **系统稳定性**：
hypervisor 级驱动运行在机器的最高特权层。**一个 bug 即可导致系统蓝屏或数据损坏。**请务必在虚拟机或可弃置的机器上测试，并做好备份。

- **无担保**：
本软件按其许可证条款提供，**不附带任何明示或默示的担保**，包括但不限于适销性、特定用途适用性与非侵权性。

- **兼容性免责**：
本软件**不保证与所有 Windows 版本、CPU 型号或固件完全兼容**。开发者对因系统更新、微码变更或其他不可控因素导致的功能异常或损失概不负责。

- **责任限制**：
在适用法律允许的最大范围内，**无论是否被告知可能性，作者或贡献者均不对因使用或无法使用本软件而产生的任何直接、间接、附带、特殊或后果性损害承担责任**。

- **用户责任**：
使用者须自行承担使用本项目所产生的一切法律责任。

- **最终解释权**：
本免责声明的最终解释权归本项目作者所有。

## 💬 联系方式

欢迎通过 GitHub Issues 提交问题、建议与 bug 报告。

## ⭐ 支持项目

如果你觉得本项目对你有帮助，或认可它在技术研究上的价值，欢迎在 GitHub 上点一个 ⭐。

你的支持能让更多人发现这个项目，也能让作者感受到持续维护的意义。

感谢你的认可。
