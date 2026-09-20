#pragma once
#ifndef GEPTAPI_H
#define GEPTAPI_H
#include<ntifs.h>

//====================================================================
// v3.50 Phase4: 简易API(用户初衷之二)——普通开发者零虚拟化知识
// 即可用上虚拟层HOOK(VMFUNC双EPT detour式)
//
//语义(看雪图谱4.2+4.4架构红利):
//  - hook触发=CodePage跳转→GeptStubEntry→vmfunc切clean视图→SAVE_ALL
//    →用户回调→vmfunc切回hooked视图→ret回调用者(全程零VM-Exit)
//  - clean视图下原函数字节完好无损→回调内GeptCallOriginal**直接调用**
//    原函数(无需prologue重放/hookLen/trampoline机器=特征码硬编码消亡)
//  - 回调返回值=hook函数的新返回值(完整detour控制权: 可改参数/返回值/
//    不调用原函数直接拦截)
//
//使用纪律(血泪浓缩, 违反=蓝屏/死锁风险):
//  1. 回调运行在原函数的**任意线程/任意IRQL上下文**(含DISPATCH级):
//     只做IRQL安全操作(Interlocked*/无锁环事件/GeptCallOriginal);
//     绝不FlLog(等待落盘线程死锁)/绝不DbgPrint(性能风暴)/绝不分页内存
//     访问/绝不阻塞等待
//  2. 回调内调用本hook的原函数**必须经GeptCallOriginal**(保证clean视图
//     +视图归位); 直接调用Target在clean视图下碰巧也安全, 但线程迁移
//     后不保证——统一走GeptCallOriginal
//  3. 已知限制(文档化): 回调执行期间本核处于clean视图——回调里调用
//     的其他hook目标(或原函数内部调用的其他hook目标)不被拦截;
//     回调阻塞=本核hook持续失效直到返回
//  4. 第5+参数(stack参数)v1不转发(GeptCallOriginal只转发rcx/rdx/r8/r9
//     四个寄存器参数)——覆盖绝大多数内核函数; 全参数转发留待增强
//
//硬件要求: 全部in-guest核VMFUNC+双EPT自测通过(Haswell+, 本路线v3.48
//起全绿); 不满足GeptHookInstall返回STATUS_NOT_SUPPORTED, 调用方退化
//到violation方案(v3.46跳板重放, Phase 6动态化)
//====================================================================

//detour回调: 返回值=hook函数的返回值; Context=安装时原样传入;
//Arg1-4=原函数的rcx/rdx/r8/r9(x64前4个寄存器参数)
typedef ULONG64(*GEPT_CALLBACK)(
	PVOID Context, ULONG64 Arg1, ULONG64 Arg2, ULONG64 Arg3, ULONG64 Arg4);

//安装描述(值语义, 安装后内部自持)
typedef struct _GEPT_HOOK
{
	PVOID Target;             //目标函数(内核虚拟地址)
	GEPT_CALLBACK Callback;   //detour回调
	PVOID Context;            //用户上下文(原样传给回调)
} GEPT_HOOK, * PGEPT_HOOK;

//安装hook(PASSIVE_LEVEL): CodePage构建+每核hooked EPT布防(PHHook复用)
NTSTATUS GeptHookInstall(const GEPT_HOOK* Hook);

//移除hook(PASSIVE_LEVEL): 还原CodePage被覆盖字节(源=原页, 原页从未被
//修改)+全核双视图invept→hook立即失效(hooked视图≡clean视图);
//正在回调中的线程安全完成(槽/条目延迟到卸载释放)
NTSTATUS GeptHookRemove(PVOID Target);

//枚举live hook(Buffer=NULL时*InOutCount返回数量)
NTSTATUS GeptHookEnumerate(GEPT_HOOK* Buffer, ULONG* InOutCount);

//回调内调用原函数(仅回调上下文有效, 其他上下文返回0):
//确保clean视图→直接call Target(原始字节)→视图归位hooked
ULONG64 GeptCallOriginal(ULONG64 Arg1, ULONG64 Arg2, ULONG64 Arg3, ULONG64 Arg4);

//高级: 手动切换EPT视图(0=clean原始字节/1=hooked)。
//VT已关/未启用VMFUNC的核=安全no-op。GeptStubEntry/GeptCallOriginal内部使用
VOID GeptViewSwitch(ULONG eptpIndex);

//卸载收尾: DriverUload在关VT**之前**调用(移除全部hook, 让在途回调
//安全完成); 关VT之后调用GeptApiFreeMemory释放内存
VOID GeptApiRemoveAll(VOID);
VOID GeptApiFreeMemory(VOID);

#endif // GEPTAPI_H
