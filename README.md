# GeptHooks

[简体中文](README_ZH.md) | English | [AI collaboration doc](README_AGENT.md)

## 📖 Introduction

**GeptHooks** is a hidden EPT hook framework for Windows (Windows 10 - 11).

It virtualizes the running system with Intel VT-x and uses **per-core dual EPT views (clean / hooked)** to intercept function execution — letting your driver hook any kernel function **without modifying a single byte of the original memory, and without a single VM-Exit per hook hit**.

The redirection is performed purely by EPT translation: the *clean* view is an identity mapping (reads and CRC checks always see the pristine bytes), while the *hooked* view remaps the hook page to a shadow copy (an absolute jump at the target offset). Views are switched once by the VMM at hook install/remove time; a hit at runtime is a pure guest-mode detour — the timing cost of hooking is zero by construction. The framework also conceals its own existence from the guest: CPUID, the TSC timeline, cross-clock domains, the VMX instruction face, physical-memory scanning, and page-table attacks are all covered.

> **Using an AI assistant (Copilot / Claude / GPT ...) for development on this project?** Read [README_AGENT.md](README_AGENT.md) first — it is written specifically for AI and contains the project's many **counter-intuitive safety designs and hard red lines**. Skipping it and editing code directly is very likely to introduce bugcheck-grade defects.

## ✨ Features

- **Dual-EPT zero-VM-Exit detour**
  Every core runs with two EPT views: a *clean* view (identity, original bytes) and a *hooked* view (hook page remapped to a shadow copy). A hit = translation, not a trap: **each hook hit costs zero VM-Exits**. Measured: 1.44M+ NtClose interceptions across runs with the EPT-violation counter pinned at 0.

- **Detour with full control**
  Your callback receives the original arguments, can call the original function (`GeptCallOriginal`), modify arguments or return values, or swallow the call entirely. No prologue replay, no instruction-length machinery — the clean view holds the pristine original code.

- **Stack-argument forwarding (5th argument and beyond)**
  Declare the target's stack-argument count in `GEPT_HOOK.StackArgs` (up to 32); your callback receives a `StackArgs` pointer to the live arguments on the trigger stack — readable and **writable**, with modifications forwarded through `GeptCallOriginal`. No argument gaps when hooking multi-parameter kernel functions.

- **Version-independent trampolines**
  Trampolines are generated at runtime by an LDE relocation engine — per-instruction decode, RIP-relative fixups, and a CPU-view back-scan self-check before going live. No hardcoded prologues bound to one Windows build: hooks install across Windows versions, and unrelocatable prologues are rejected at install time.

- **Optional hook-page read transparency**
  With `HideRead=1` the hook page is execute-only in the hooked view: any read/write access to the page is single-stepped to reveal the original bytes — patch guards (PG) and memory scanners see the pristine page. Requires exec-only EPT support (`EPT_VPID_CAP` bit 0); falls back automatically when unsupported.

- **Comprehensive hypervisor concealment**
  - **CPUID**: pass-through of real hardware results plus surgical edits (clear the hypervisor-present bit, zero the hypervisor leaves, clamp maxleaf) — feature bits and cache/topology info stay intact;
  - **TSC timeline**: every VM-Exit's root-mode dwell time is subtracted from the guest-visible TSC via TSC offsetting, with per-core calibration absorbing instruction overhead — "the exit never happened" on the guest's timeline;
  - **Clock domains**: HPET / PM_TMR counter reads are emulated on the same axis as the virtual TSC (including a shadow-page flicker: slow-path reads of any instruction form receive compensated semantics), leaving no timeline hole in cross-clock comparisons; TSC-Deadline timers are converted automatically;
  - **VMX instruction face**: VMXON/VMXOFF/VMREAD and the whole instruction family behave exactly as on bare metal (faithful #UD / #GP semantics) — nothing for a detector or virus to probe; VMFUNC is sealed (#UD, bare-metal semantics);
  - **Physical-memory scan immunity**: every framework-private physical page (VMXON/VMCS/VMM stack/bitmaps/EPT tables/trampolines) is remapped to the shared zero page in both views — a guest physical-memory scan sees only zeros.

- **Root-state hardening (anti-tamper)**
  A private host IDT (all 256 gates redirected) and a private host CR3 (VMM page tables deep-copied and isolated): NMI/exception delivery inside the exit window and the page-table attack surface are isolated — guest tampering with the OS IDT or shared page tables cannot reach the VMM.

- **Mutual-exclusion arbitration**
  A second instance on the same machine is cleanly rejected at `sc start` by native mechanisms (all resources released, then exit) — instances never corrupt each other.

- **Simple, driver-friendly API**
  Install, remove, enumerate hooks, and call originals with a few C calls from your own kernel driver — no hypervisor knowledge required.

- **MSR interception (read-forging / write-monitoring)**
  Any MSR can be hooked through the per-core MSR bitmap: read callbacks return the value the guest will see (forge it), write callbacks allow or silently drop. Unhooked MSRs stay zero-cost pass-through. Install / remove / enumerate mirror the function-hook API exactly.

- **Observability governed by build configuration**
  The whole observation stack (dual writer threads, binary event ring, BSOD black-box watchdog) is governed by the build type: **Debug builds = full observability** (authoritative log in `C:\Windows\Temp\gept_log.txt`, best-effort desktop mirror; if logging stalls for 30 s the watchdog deliberately bugchecks to capture a memory dump — a debugging aid, never part of a delivery build); **Release builds = zero logging code in the binary** (no background threads, no file I/O, no observable surface). Deliberately no runtime/registry switch: a registry value is both a static signature an AV/EDR can flag and a configuration footprint left on the target.

- **Clean delivery form**
  The driver entry runs only the framework lifecycle (resource allocation → per-core virtualization launch → arbitration → resident) plus demo hooks (`main.c` is yours to replace). The framework is consumed as source — add the files to your own driver project.

## 📐 How the zero-VM-Exit hook works

```
                clean view                     hooked view
                ┌────────────┐               ┌────────────┐
                │  identity  │               │ hook page  │
                └─────┬──────┘               └─────┬──────┘
                      │ pristine bytes             │ → shadow copy (CodePage)
   guest (VMM switches the view as needed)         │ (X=1, R=1, W=0)
   ─────────────────┴──────────────────────────────┴─────────────────
        install/remove: VMM switches EPTP per core (once) — hits never trap
```

Hook trigger chain (all in guest mode, zero VM-Exit):

```
caller → target function (hooked view = CodePage, 14-byte absolute jump
  at the target offset)
  → per-hook trampoline slot (mov r10, entry; jmp GeptStubEntry)
  → GeptStubEntry: SAVE_ALL → dispatch to your callback
      (may GeptCallOriginal: calls the original via the LDE-relocated
        trampoline — view-independent; other hook targets invoked from
        the callback trigger normally = standard detour semantics)
    → RESTORE_ALL
  ← caller (RAX = your callback's return value)
```

On rare resource conditions (hooked-EPT deep-copy failure, failed arm self-check) individual cores **degrade automatically** to the classic EPT-violation scheme (fetch trap → view switch → same trampoline chain) — same API semantics, zero changes on your side.

## 🚀 Quick Start

Install and start the driver:

```
sc create GeptHooks type= kernel start= demand binPath= "C:\path\to\GeptHooks.sys"
sc start GeptHooks
```

Stop and uninstall (all hooks are removed cleanly first, then VT is torn down atomically on all cores via an IPI broadcast):

```
sc stop GeptHooks
sc delete GeptHooks
```

Debug logging needs no switches: just build the **Debug configuration** for full observability (file log + event ring + black-box watchdog); **Release builds** ship zero logging code.

## 🧩 Using the API

```c
#include "GeptApi.h"

// Your detour callback: runs in the original function's thread and
// IRQL context. Return value becomes the hook's return value.
// StackArgs: array of the 5th+ (stack) arguments — readable and
// writable; modifications are forwarded by GeptCallOriginal.
// NULL when StackArgs was not declared at install time.
static ULONG64 OnNtClose(PVOID Context,
    ULONG64 Arg1, ULONG64 Arg2, ULONG64 Arg3, ULONG64 Arg4,
    ULONG64* StackArgs)
{
    ULONG64 status = GeptCallOriginal(Arg1, Arg2, Arg3, Arg4);
    return status;   // or forge it — you have full control
}

// Install / remove / enumerate
GEPT_HOOK Hook = { 0 };
Hook.Target    = (PVOID)NtClose;
Hook.Callback  = OnNtClose;
Hook.Context   = NULL;
Hook.StackArgs = 0;   // number of the target's 5th+ stack arguments (0 = off)
Hook.HideRead  = 1;   // optional: hook-page read transparency

GeptHookInstall(&Hook);
// ... hooks are live on all cores ...
GeptHookRemove((PVOID)NtClose);

ULONG Count = 0;
GeptHookEnumerate(NULL, &Count);   // query live hook count
```

Hooking functions with six or more parameters (stack arguments) — just declare the count:

```c
// Target prototype: ULONG64 F(ULONG64 A1..A4, ULONG64 A5, ULONG64 A6);
GEPT_HOOK Hook = { 0 };
Hook.Target    = (PVOID)F;
Hook.Callback  = OnF;
Hook.StackArgs = 2;               // two stack arguments (A5/A6)

static ULONG64 OnF(PVOID Ctx, ULONG64 A1, ULONG64 A2,
    ULONG64 A3, ULONG64 A4, ULONG64* StackArgs)
{
    StackArgs[0] ^= 1;            // modify the 5th argument — takes effect on forwarding
    return GeptCallOriginal(A1, A2, A3, A4);  // stack arguments forwarded automatically
}
```

MSR hooks (the data plane) are just as simple — install, remove, and enumerate:

```c
#include "GeptMsr.h"

static ULONG64 OnLstarRead(PVOID Ctx, ULONG32 Msr)
{
    return GeptMsrReadReal(Msr);   // pass through — or forge any value
}
static BOOLEAN OnLstarWrite(PVOID Ctx, ULONG32 Msr, ULONG64 Value)
{
    return TRUE;                    // TRUE = allow, FALSE = silently drop
}

GEPT_MSR_HOOK M = { 0 };
M.Msr     = 0xC0000082;             // IA32_LSTAR
M.OnRead  = OnLstarRead;            // NULL = reads pass through
M.OnWrite = OnLstarWrite;           // NULL = writes pass through
GeptMsrHookInstall(&M);

// ... monitoring period ...
GeptMsrHookRemove(0xC0000082);      // remove: the MSR reverts to pass-through

ULONG MsrCount = 0;
GeptMsrHookEnumerate(NULL, &MsrCount);   // enumerate live MSR hooks
```

**Callback context contract**:

1. Callbacks run in the original function's thread and IRQL context (up to DISPATCH_LEVEL) — only perform IRQL-safe work inside (interlocked operations, lock-free logging, `GeptCallOriginal`, `GeptMsrReadReal`).
2. Always call this hook's original through `GeptCallOriginal` — it invokes the original via the version-independent relocated trampoline and forwards stack arguments automatically (calling the original entry directly would run into the jump code under the hooked view).
3. Nesting semantics (standard detour): other hook targets invoked from within your callback **trigger normally**.
4. Use `GeptMsrReadReal` when a read callback needs the true MSR value; never call it on architecturally reserved MSRs (a real read is #GP) — just return the forged value.

On unload, remove all hooks **before** VT teardown (`GeptApiRemoveAll`), then free memory **after** it (`GeptApiFreeMemory`) — see `main.c`'s `DriverUload` for the reference sequence.

## ⚙️ Requirements

- **CPU**: Intel with VT-x + EPT (Haswell or later for the full feature set; rare resource-constrained cores degrade automatically — same API)
- **OS**: Windows 10 / 11 x64
- **Hypervisor conflicts**: Hyper-V, Virtualization-Based Security (VBS), Memory Integrity (Core Isolation), and WHP must be disabled — GeptHooks needs to be the root hypervisor
- **Test signing**: enable with `bcdedit /set testsigning on`, or sign the driver properly
- **Build**: Visual Studio 2022 + Windows Driver Kit (WDK)
- **Runtime**: administrator privileges

## 🧪 Capability Verification Matrix

All core paths have been verified over multiple runs on real hardware (8-core Intel Skylake, Windows 10 x64):

| Capability | Measured evidence |
|---|---|
| All-core VT takeover | 8 cores: per-core vmlaunch → takeover → clean unload, stable across runs (incl. long-duration sessions) |
| Zero-VM-Exit interception | 1.44M+ NtClose interceptions with the EPT-violation counter at 0 |
| Full detour control | Six-argument target, four proofs (read-back / stack-arg write / register write / removal restore) |
| Version-independent trampolines | LDE back-scan self-checks passed; replay self-test NtClose(-1) = 0xC0000008 |
| MSR data plane | Reserved MSR forged to `DEADBEEFCAFEBABE`; LSTAR canary counting + write monitoring |
| TSC timeline | Per-exit net dwell compensated to the ~kilocycle range (ppm-level consistency); unload dwell quantification logged |
| Clock-domain coherence | HPET / PM_TMR reads on the same axis as the virtual TSC; zero extra exits in natural traffic (slow-path ring events = 0) |
| Physical scan immunity | Framework pages remapped to the zero page in both views; EPT arm self-checks all passed |
| Root-state hardening | Private host IDT / CR3 wired per core with consistent read-backs; dozens of deep-copied page-table regions closed-loop |
| Atomic all-core unload | IPI broadcast, per-core atomic exit (zero scheduling, zero window), multiple clean runs under idle stress |
| Release delivery form | Log-free build running long-duration without anomalies |

## ⚠️ Project Status

All core paths (virtualization, dual-EPT hooks, concealment, detour API, runtime relocation, MSR data plane, clock-domain sealing, root-state hardening) have graduated from staged on-hardware testing. The framework is research-grade: a hypervisor-level bug may still bugcheck the system — always test on a disposable machine.

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
