# GeptHooks

[简体中文](README_ZH.md) | English

## 📖 Introduction

**GeptHooks** is a General EPT hook framework for Windows (Windows 10 - 11).

It virtualizes the running system with Intel VT-x and uses Extended Page Tables (EPT) to intercept memory reads, writes, and execution — letting your driver hook, monitor, or shadow any kernel or user-mode address **without modifying a single byte of the original memory**.

## ✨ Features

- **Execution hooks (hidden breakpoints)**
Intercept execution of any address in kernel or user space. No INT3, no page-table tricks, no debug registers — invisible to the guest.

- **Inline EPT hooks**
Redirect execution to your handler through a stealth trampoline. The original code remains untouched from the guest's point of view.

- **Read/write monitors**
Watch memory reads and writes like hardware debug registers — but without the 4-slot or size limitations.

- **Memory shadowing**
Present different memory contents for the read, write, and execute views of the same page.

- **VMFUNC EPTP switching (zero VM-Exit)**
Switch between clean and hooked EPT views with the VMFUNC instruction — instruction-level speed with no VM-Exit, defeating timing-based detection (requires Haswell or later).

- **MSR interception (MSR bitmap)**
Forge MSR reads such as IA32_LSTAR while the real value stays under your control — code and data disguised at the same time.

- **Hypervisor concealment (CPUID masking + TSC offsetting)**
CPUID results are forged to clear the hypervisor-present bit, and TSC offsetting erases the measurable timing delay of VM-exits — defeating both CPUID-based and timing-based hypervisor detection.

- **Simple, driver-friendly API**
Install, remove, and enumerate hooks with a few C calls from your own kernel driver — no hypervisor knowledge required.

- **More features coming soon...**

## ⚠️ Project Status

This project is currently in an early development stage. Bugs, incomplete features, and breaking changes may occur.

## ⚙️ Requirements

- **CPU**: Intel processor with VT-x and EPT support (Haswell or later required for VMFUNC EPTP switching)
- **OS**: Windows 10 / 11 x64
- **Hypervisor conflicts**: Hyper-V, Virtualization-Based Security (VBS), Memory Integrity (Core Isolation), and WHP must be disabled — GeptHooks needs to be the root hypervisor
- **Test signing**: enable with `bcdedit /set testsigning on`, or sign the driver properly
- **Build**: Visual Studio 2022 + Windows Driver Kit (WDK)
- **Runtime**: administrator privileges

## 🚀 Quick Start

Install and start the driver:

```
sc create GeptHooks type= kernel start= demand binPath= "C:\path\to\GeptHooks.sys"
sc start GeptHooks
```

Stop and uninstall:

```
sc stop GeptHooks
sc delete GeptHooks
```

Use from your driver (preview API):

```c
GEPT_HOOK Hook = { 0 };
Hook.TargetAddress = TargetFunction;
Hook.Type          = GeptHookExecute;
Hook.Callback      = OnTargetExecuted;

GeptHookInstall(&Hook);
// ... your test logic ...
GeptHookRemove(&Hook);
```

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

You are welcome to submit issues, suggestions, or bug reports via GitHub Issues.

## ⭐ Support the Project

If you find this project helpful, or if you recognize its value in technical research, consider giving it a ⭐ on GitHub.

Your support helps more people discover this project, and also lets the author feel the significance of continued maintenance.

Thank you for your recognition.
