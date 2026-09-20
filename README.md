# GeptHooks

[简体中文](README_ZH.md) | English

## 📖 Introduction

**GeptHooks** is a hidden EPT hook framework for Windows (Windows 10 - 11).

It virtualizes the running system with Intel VT-x and uses **VMFUNC EPTP switching between dual EPT views** (clean / hooked) to intercept function execution — letting your driver hook any kernel function **without modifying a single byte of the original memory, and without a single VM-Exit per hook hit**.

This implements the highest-stealth virtual-layer hook design: execution is redirected purely by EPT page-table translation, the original page stays byte-for-byte intact for reads and CRC checks (clean view), and the timing cost of hooking is zero by design.

## ✨ Features

- **VMFUNC dual-EPT hooks (zero VM-Exit detour) — v3.48**
Every core runs with two EPT views: a *clean* view (identity, original bytes) and a *hooked* view (hook page remapped to a shadow copy). Hooking execution = switching translation, not trapping: **each hook hit costs zero VM-Exits**. Measured: 187k+ NtClose interceptions with the EPT-violation counter pinned at 0.

- **Detour with full control — v3.50**
Your callback receives the original arguments, can call the original function directly (`GeptCallOriginal`), modify arguments or return values, or swallow the call entirely. No prologue replay, no instruction-length machinery — the clean view holds the pristine original code.

- **Hypervisor concealment — v3.49**
CPUID leaves `0x40000000-0x4000000F` are zeroed (no hypervisor signature leaks), `CPUID.1:ECX[31]` is cleared, and **TSC offsetting compensation** subtracts every VM-Exit's root-mode dwell time from the guest-visible TSC — the guest's timeline behaves as if no exit ever happened.

- **Fallback path for older CPUs**
On CPUs without VMFUNC, hooks transparently fall back to the classic EPT-violation scheme (split 2M pages, X-bit toggling) — same API, zero code changes on your side.

- **Simple, driver-friendly API**
Install, remove, enumerate hooks, and call originals with a few C calls from your own kernel driver — no hypervisor knowledge required.

- **MSR interception (MSR bitmap) — planned**
Infrastructure is in place (`VmxSetMsrRw`); read-forging samples (e.g. IA32_LSTAR) are on the roadmap.

## 📐 How the zero-VM-Exit hook works

```
                EPTP-list[0]                 EPTP-list[1]
                ┌────────────┐               ┌────────────┐
                │ clean EPTP │               │ hooked EPTP│
                └─────┬──────┘               └─────┬──────┘
                      │ identity mapping           │ hook page PTE → shadow copy
   guest (default: clean view)                    │ (X=1, R=1, W=0)
   ─────────────────┴──────────────────────────────┴─────────────────
        vmfunc(0, 1)  ── zero-VM-Exit switch (writes EPTP back into the VMCS)
```

Hook trigger chain (all in guest mode, no VM-Exit):

```
caller → NtClose (hooked view = shadow page, 14-byte absolute jump)
  → per-hook trampoline slot
  → GeptStubEntry:  vmfunc(0,0) switch to clean → SAVE_ALL
      → your callback  (may GeptCallOriginal: direct call to the
        pristine original — clean view holds the real bytes)
      → vmfunc(0,1) switch back to hooked → ret
  ← caller (RAX = your callback's return value)
```

## 🚀 Quick Start

Install and start the driver:

```
sc create GeptHooks type= kernel start= demand binPath= "C:\path\to\GeptHooks.sys"
sc start GeptHooks
```

Stop and uninstall (all hooks are removed cleanly, then VT is torn down):

```
sc stop GeptHooks
sc delete GeptHooks
```

## 🧩 Using the API

```c
#include "GeptApi.h"

// Your detour callback: runs in the original function's context
// (arbitrary thread / IRQL). Return value becomes the hook's return value.
static ULONG64 OnNtClose(PVOID Context,
    ULONG64 Arg1, ULONG64 Arg2, ULONG64 Arg3, ULONG64 Arg4)
{
    // IRQL-safe work only: counters, ring events, GeptCallOriginal...
    // NEVER block, never touch paged memory.
    ULONG64 status = GeptCallOriginal(Arg1, Arg2, Arg3, Arg4);
    return status;   // or forge it — you have full control
}

// Install / remove / enumerate
GEPT_HOOK Hook = { 0 };
Hook.Target   = (PVOID)NtClose;
Hook.Callback = OnNtClose;
Hook.Context  = NULL;

GeptHookInstall(&Hook);
// ... hooks are live on all cores ...
GeptHookRemove((PVOID)NtClose);

ULONG Count = 0;
GeptHookEnumerate(NULL, &Count);   // query live hook count
```

**Callback discipline** (enforced by reality, see NOTES.md for the war stories):

1. Callbacks run at the original function's IRQL — only interlocked ops, lock-free logging, and `GeptCallOriginal` are safe. No blocking, no paged memory, no `DbgPrint` storms.
2. Always call the original through `GeptCallOriginal` — it guarantees the clean view and restores the hooked view afterwards (thread-migration safe).
3. While your callback runs, the current core is on the clean view: other hook targets invoked from within the callback are **not** intercepted (documented limitation).
4. Stack arguments beyond the first four (rcx/rdx/r8/r9) are not forwarded in v1.

On unload, call `GeptApiRemoveAll()` **before** VT teardown, then `GeptApiFreeMemory()` after — see `main.c`'s `DriverUload` for the reference sequence.

## ⚙️ Requirements

- **CPU**: Intel with VT-x + EPT; **VMFUNC (Haswell or later) required for the zero-VM-Exit path** — older CPUs get the violation fallback
- **OS**: Windows 10 / 11 x64
- **Hypervisor conflicts**: Hyper-V, Virtualization-Based Security (VBS), Memory Integrity (Core Isolation), and WHP must be disabled — GeptHooks needs to be the root hypervisor
- **Test signing**: enable with `bcdedit /set testsigning on`, or sign the driver properly
- **Build**: Visual Studio 2022 + Windows Driver Kit (WDK)
- **Runtime**: administrator privileges

## 🧪 Verified Milestones

| Phase | Milestone | Measured evidence |
|---|---|---|
| STAGE 1 | Self-test EPT hook (violation scheme) | hook chain live, clean unload |
| STAGE 2 | NtClose system-wide monitoring | 780k+ interceptions total across runs, 16–90 min stability |
| Phase 1 | VMFUNC infrastructure, 8/8 cores | zero-VM-Exit EPTP round-trip self-test |
| Phase 2 | Dual-EPT zero-VM-Exit hooks | marker pages read different values per view; Δr48 = 0 while interception grows |
| Phase 3 | Concealment (CPUID + TSC) | CPUID signature fully masked; per-core TSC offset ≈ −0.6 ms of hidden exit time |
| Phase 4 | Simple API lifecycle | install +388/2s → remove +0/2s → reinstall +14/2s, clean unload |

## ⚠️ Project Status

Core paths (virtualization, dual-EPT VMFUNC hooks, concealment, detour API) are graduated from staged on-hardware testing on an i7-6700HQ (8 cores, Windows 10 x64). The framework is research-grade: bugs may still bugcheck the system — always test on a disposable machine.

## 🚫 Non-Commercial Statement

This project is initiated by the developer out of personal interest and for technical research purposes, and is **non-commercial** in nature:

- **Permanently Free**:
This project is completely free, with **no paid features, memberships, subscriptions, or in-app purchases**. All features are fully accessible to all users.

- **No Sponsorship Channels**:
The author has **never opened any sponsorship channels**, nor does the author **accept any financial donations** — to maintain the project's neutrality and purity.

- **Non-Profit Purpose**:
This project involves no commercial operations, and the author derives no direct or indirect financial benefit from it.

- **Research-Oriented**:
This project is consistently positioned for **security research, driver development, and software testing** — providing a research tool for the community, not a commercial product. Any commercial use of this project is the user's own initiative and is unrelated to this project.

- **Resale Prohibited**:
Resale, redistribution for profit, or commercial use of this project is strictly prohibited. Please obtain it only from this repository (GitHub) or other officially designated channels. The developer assumes no responsibility for any issues arising from unofficial sources.

## ⚖️ Disclaimer

- **Purpose Limitation**:
This project is intended for **security research, driver development, software testing, and educational purposes** only.
Do not use this project for any illegal purposes (including but not limited to malware development, anti-cheat evasion, data theft, and system compromise).

- **Consequences Warning**:
Hooking with this framework **may violate the terms of service of third-party software and the laws of your jurisdiction**.
You should assess the risks before using it. The developer and contributors **are not responsible for any account bans, legal liabilities, or other consequences** arising from such use.

- **System Stability**:
A hypervisor-level driver operates with the highest privilege on your machine. **A bug may bugcheck (BSOD) the system or corrupt data.** Always test in a virtual machine or on a disposable machine, and keep backups.

- **No Warranty**:
This software is provided under the terms of its license, **without any express or implied warranties**, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement.

- **Compatibility Disclaimer**:
This software **does not guarantee full compatibility with all Windows versions, CPU models, or firmware**. The developer assumes no responsibility for functional issues or losses caused by system updates, microcode changes, or other uncontrollable factors.

- **Limitation of Liability**:
To the fullest extent permitted by applicable law, **in no event shall the author or contributors be liable** for any direct, indirect, incidental, special, or consequential damages arising out of or in connection with the use or inability to use this software, even if advised of the possibility of such damages.

- **User Responsibility**:
Users assume all legal responsibilities arising from the use of this project.

- **Final Interpretation**:
The final interpretation of this disclaimer belongs to the author of this project.

## 💬 Contact

You are welcome to submit issues, suggestions, and bug reports via GitHub Issues.

## ⭐ Support the Project

If you find this project helpful, or if you recognize its value in technical research, consider giving it a ⭐ on GitHub.

Your support helps more people discover this project, and also lets the author feel the significance of continued maintenance.

Thank you for your recognition.
