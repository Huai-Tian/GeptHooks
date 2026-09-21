# GeptHooks

简体中文 | [English](README.md)

## 📖 介绍

**GeptHooks** 是一个隐藏式 Windows EPT 钩子框架（支持 Windows 10 - 11）。

它通过 Intel VT-x 虚拟化正在运行的系统，利用 **VMFUNC 在双 EPT 视图（clean / hooked）间的零成本切换**来拦截函数执行——让你的驱动可以钩取任意内核函数，**不修改原始内存的任何一个字节，且每次钩子命中不产生任何 VM-Exit**。

这实现了隐藏性最高的虚拟层钩子设计：执行流的重定向完全由 EPT 页表翻译切换完成；原始页面在 clean 视图下逐字节完好（读内存与 CRC 校验看到的全是原始内容）；钩子的时间开销在构造上即为零。

## ✨ 功能特性

- **VMFUNC 双 EPT 钩子（零 VM-Exit detour）—— v3.48**
每个核心持有两套 EPT 视图：*clean* 视图（恒等映射，原始字节）与 *hooked* 视图（钩子页改译到影子副本）。钩住执行 = 切换翻译，而不是陷入：**每次钩子命中零 VM-Exit**。实测：多轮累计 **126 万+次** NtClose 拦截期间 EPT violation 计数始终为 0。

- **detour 完整控制权 —— v3.50**
回调收到原始参数，可以直接调用原函数（`GeptCallOriginal`）、修改参数或返回值、或整体吞掉这次调用。没有 prologue 重放，没有指令长度机器——clean 视图里就是完好如初的原始代码。

- **版本无关的运行时跳板 —— v3.51**
跳板由 LDE 重定位引擎在运行时生成——逐指令解码、RIP-relative 重定位、生成后按 CPU 视角回扫自检。没有绑定某个 Windows 构建的硬编码 prologue：钩子可跨 Windows 版本安装；不可重定位的 prologue 在安装时即被拒绝。

- **Hypervisor 隐身 —— v3.49**
CPUID 的 `0x40000000-0x4000000F` 叶子全部归零（不泄漏任何 hypervisor 签名），`CPUID.1:ECX[31]` 清零，并以 **TSC offsetting 补偿**把每次 VM-Exit 的 root 驻留时长从客户机可见的 TSC 中扣除——客户机时间线上"exit 从未发生过"。

- **老 CPU 自动降级 —— v3.51**
无 VMFUNC 的核心上，钩子按核透明降级到经典 EPT violation 方案（拆 2M 页 + X 位切换），`GeptCallOriginal` 自动改走重定位跳板——API 语义完全一致、你的代码零改动；混合机器按核分派。

- **简洁的驱动友好 API**
在你自己的内核驱动里用几个 C 调用即可完成钩子的安装、移除、枚举与原函数调用——无需任何 hypervisor 背景知识。

- **MSR 拦截（读伪造 / 写监控）—— v3.52**
通过每核 MSR 位图可钩取任意 MSR：读回调返回值即客户机可见值（可伪造），写回调可放行或静默丢弃。未钩取的 MSR 保持零开销直通。实测演示：保留 MSR 读回 `DEADBEEFCAFEBABE`；LSTAR canary 计数 syscall 入口探测并在写入时报警。

## 📐 零 VM-Exit 钩子的工作原理

```
                EPTP-list[0]                 EPTP-list[1]
                ┌────────────┐               ┌────────────┐
                │ clean EPTP │               │ hooked EPTP│
                └─────┬──────┘               └─────┬──────┘
                      │ 恒等映射                    │ 钩子页 PTE → 影子副本
   guest(默认clean视图)                           │ (X=1, R=1, W=0)
   ─────────────────┴──────────────────────────────┴─────────────────
        vmfunc(0, 1)  ── 零VM-Exit切换(新EPTP写回VMCS, 即刻生效)
```

钩子触发链（全程客户机态，零 VM-Exit）：

```
调用者 → NtClose(hooked视图=影子页, 14字节绝对跳转)
  → 本hook独享的trampoline槽
  → GeptStubEntry:  vmfunc(0,0)切到clean → SAVE_ALL
      → 你的回调  (可GeptCallOriginal: 直接调用原始入口——
        clean视图里就是真实字节)
      → vmfunc(0,1)切回hooked → ret
  ← 调用者(RAX = 你回调的返回值)
```

## 🚀 快速开始

安装并启动驱动：

```
sc create GeptHooks type= kernel start= demand binPath= "C:\path\to\GeptHooks.sys"
sc start GeptHooks
```

停止并卸载（全部钩子先被干净移除，随后关闭 VT）：

```
sc stop GeptHooks
sc delete GeptHooks
```

## 🧩 API 使用

```c
#include "GeptApi.h"

// 你的detour回调: 运行在原函数的上下文
// (任意线程 / 任意IRQL)。返回值即钩子函数的返回值。
static ULONG64 OnNtClose(PVOID Context,
    ULONG64 Arg1, ULONG64 Arg2, ULONG64 Arg3, ULONG64 Arg4)
{
    // 只做IRQL安全的操作: 原子计数/无锁日志/GeptCallOriginal...
    // 绝不阻塞, 绝不碰分页内存。
    ULONG64 status = GeptCallOriginal(Arg1, Arg2, Arg3, Arg4);
    return status;   // 也可以伪造——你拥有完整控制权
}

// 安装 / 移除 / 枚举
GEPT_HOOK Hook = { 0 };
Hook.Target   = (PVOID)NtClose;
Hook.Callback = OnNtClose;
Hook.Context  = NULL;

GeptHookInstall(&Hook);
// ... 钩子已在全部核心生效 ...
GeptHookRemove((PVOID)NtClose);

ULONG Count = 0;
GeptHookEnumerate(NULL, &Count);   // 查询live钩子数量
```

MSR 钩子（数据面）同样简单：

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
```

**回调纪律**（血泪经验，完整事故记录见 NOTES.md）：

1. 回调在原函数的 IRQL 下运行——只允许原子操作、无锁日志和 `GeptCallOriginal`。不阻塞、不碰分页内存、不刷 `DbgPrint`。
2. 调用原函数必须经 `GeptCallOriginal`——它保证 clean 视图并在返回后恢复 hooked 视图（线程迁移安全）。
3. 回调执行期间本核处于 clean 视图：回调里调用的其他钩子目标**不会被拦截**（已知限制，已文档化）。
4. 第 5 个及以后的栈参数（rcx/rdx/r8/r9 之外）v1 不转发。

卸载时须在关闭 VT **之前**调用 `GeptApiRemoveAll()`，关闭 VT **之后**调用 `GeptApiFreeMemory()`——参考 `main.c` 的 `DriverUload` 标准序列。

## ⚙️ 环境要求

- **CPU**：支持 VT-x + EPT 的 Intel 处理器；**VMFUNC（Haswell 及以上）解锁零 VM-Exit 路径**——更老或混合 CPU 按核降级到 violation 路径（API 一致）
- **操作系统**：Windows 10 / 11 x64
- **虚拟化冲突**：需关闭 Hyper-V、基于虚拟化的安全（VBS）、内存完整性（核心隔离）与 WHP——GeptHooks 必须作为根 hypervisor 运行
- **测试签名**：执行 `bcdedit /set testsigning on` 开启测试签名，或对驱动进行正式签名
- **构建**：Visual Studio 2022 + Windows Driver Kit（WDK）
- **运行**：管理员权限

## 🧪 已验证里程碑

| 阶段 | 里程碑 | 实测证据 |
|---|---|---|
| STAGE 1 | 自测 EPT 钩子（violation 方案） | 钩子全链路打通，干净卸载 |
| STAGE 2 | NtClose 全系统监控 | 多轮累计 **126 万+次**拦截，16–89 分钟稳定运行 |
| Phase 1 | VMFUNC 基础设施，8/8 核 | 零 VM-Exit EPTP 往返自测通过 |
| Phase 2 | 双 EPT 零 VM-Exit 钩子 | 标记页在两视图读出不同值；拦截增长而 Δr48 = 0 |
| Phase 3 | 隐身（CPUID + TSC） | CPUID 签名全部抹除；每核 TSC 偏移 ≈ −0.6 ms 隐藏 exit 时长 |
| Phase 4 | 简易 API 生命周期 | 装 +388/2s → 卸 +0/2s → 重装 +14/2s，干净卸载 |
| Phase 6 | 运行时重定位（版本无关） | LDE 跳板回扫自检两次通过；replay 自测 NtClose(-1) = 0xC0000008；三窗口 +209/+0/+65 |
| Phase 5 | MSR 数据面 API | 保留 MSR 读伪造为 `DEADBEEFCAFEBABE`；LSTAR canary 两次读相等、写 0 次 |

## ⚠️ 项目状态

全部核心路径（虚拟化、双 EPT VMFUNC 钩子、隐身、detour API、运行时重定位、MSR 数据面）已在 i7-6700HQ（8 核，Windows 10 x64）上完成分阶段实测毕业。本框架为研究级质量：仍可能存在导致蓝屏的缺陷——请务必在可弃置的测试机上运行。

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
