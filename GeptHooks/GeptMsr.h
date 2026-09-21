#pragma once
#ifndef GEPTMSR_H
#define GEPTMSR_H
#include<ntifs.h>

//====================================================================
// v3.52 Phase5: MSR拦截简易API(看雪图谱4.3 MSR数据伪装)
//
//原理: 每核MSR位图(VMCS MSR_BITMAP, v3.15起已接线但恒零=全直通)
//置位后, guest内RDMSR/WRMSR对该MSR产生VM-exit → 分发到用户回调:
//  - 读回调返回值=rdmsr可见值(伪造: 可返回假地址/假数据)
//  - 写回调返回TRUE=放行代写, FALSE=静默丢弃(guest认为写成功)
//位图零开销: 未hook的MSR仍直通(硬件按位图判定, 不产生exit)
//
//与EPT hook(GeptApi)的关系: 互补能力——EPT hook管"执行/内存视图",
//MSR hook管"寄存器数据面"(LSTAR/调试寄存器配置/平台信息MSR等)。
//看雪4.3组合技(LSTAR读伪造+syscall入口EPT hook)在双EPT架构下
//clean视图天然返回原始字节, 本API提供任意MSR的读伪造/写监控
//
//使用纪律(与GEPT_CALLBACK同源, 血泪浓缩):
//  1. 回调运行在VM-exit上下文(任意线程/任意IRQL, 被中断线程可能
//     持任意锁): 只做Interlocked*/无锁环事件/GeptMsrReadReal;
//     绝不FlLog(死锁)/绝不DbgPrint/绝不阻塞
//  2. 读回调需要真实值时调GeptMsrReadReal(Msr)——对架构保留MSR
//     (真读=#GP)绝不可调, 直接返回伪造值即可
//  3. 写回调返回FALSE=静默丢弃: guest读到"写成功"假象。对系统
//     运行期会合法写的MSR(如GS base)慎用, 监控场景用TRUE放行
//  4. Remove后新触发立即停止; 在途exit(已查表)安全完成
//====================================================================

//读回调: 返回值=rdmsr可见值(伪造)。需要真值→GeptMsrReadReal
typedef ULONG64(*GEPT_MSR_READ_CB)(PVOID Context, ULONG32 Msr);
//写回调: 返回TRUE=放行代写(监控语义), FALSE=静默丢弃(拦截语义)
typedef BOOLEAN(*GEPT_MSR_WRITE_CB)(PVOID Context, ULONG32 Msr, ULONG64 Value);

typedef struct _GEPT_MSR_HOOK
{
	ULONG32 Msr;               //目标MSR号(如IA32_LSTAR=0xC0000082)
	PVOID Context;             //用户上下文(原样传给回调)
	GEPT_MSR_READ_CB OnRead;   //NULL=读不拦截(位图读位不置)
	GEPT_MSR_WRITE_CB OnWrite; //NULL=写不拦截(位图写位不置)
} GEPT_MSR_HOOK, * PGEPT_MSR_HOOK;

//安装(PASSIVE_LEVEL): 全核位图置位+**回读自检**(任一in-guest核位图
//读回不符=拒绝, 绝不带病上机——伪造自测在guest内真执行rdmsr,
//位图失效=未拦截=#GP蓝屏)。同MSR重复安装=拒绝
NTSTATUS GeptMsrHookInstall(const GEPT_MSR_HOOK* Hook);

//移除(PASSIVE_LEVEL): 全核位图清位, 条目标记Removed(静态数组
//无动态内存, 卸载无需释放)
NTSTATUS GeptMsrHookRemove(ULONG32 Msr);

//回调内取真实MSR值(root态__readmsr; 保留MSR勿调——会#GP蓝屏)
ULONG64 GeptMsrReadReal(ULONG32 Msr);

//==== exit handler内部调用(VMX.c RDMSR/WRMSR case, 勿直接调) ====
//TRUE=已拦截, *OutValue=回调返回值(伪造值); FALSE=未hook→直通
BOOLEAN GeptMsrDispatchRead(ULONG32 Msr, ULONG64* OutValue);
//TRUE=允许代写(未hook/回调放行); FALSE=回调拒绝(静默丢弃)
BOOLEAN GeptMsrDispatchWrite(ULONG32 Msr, ULONG64 Value);

#endif // GEPTMSR_H
