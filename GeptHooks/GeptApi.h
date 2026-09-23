#pragma once
#ifndef GEPTAPI_H
#define GEPTAPI_H
#include<ntifs.h>

//====================================================================
// 简易API——普通开发者零虚拟化知识即可用虚拟层HOOK
// (双EPT detour式)
//
//语义:
//  - hook触发=hooked视图CodePage跳转→GeptStubEntry→SAVE_ALL
//    →用户回调→ret回调用者(执行路径零VM-Exit)
//  - GeptCallOriginal经LDE重定位跳板调原函数(prologue重放+尾跳,
//    视图无关; 跳板尾跳点在两视图下均为原始字节)
//  - 回调返回值=hook函数的新返回值(完整detour控制权: 可改参数/返回值/
//    不调用原函数直接拦截)
//
//使用纪律(违反=蓝屏/死锁风险):
//  1. 回调运行在原函数的**任意线程/任意IRQL上下文**(含DISPATCH级):
//     只做IRQL安全操作(Interlocked*/无锁环事件/GeptCallOriginal);
//     绝不FlLog(等待落盘线程死锁)/绝不DbgPrint(性能风暴)/绝不分页内存
//     访问/绝不阻塞等待
//  2. 回调内调用本hook的原函数**必须经GeptCallOriginal**(直接call
//     Target=hooked视图下撞CodePage跳转码无限递归)
//  3. 嵌套hook语义(文档化): 回调在当前视图执行——回调里调用的其他
//     hook目标正常触发(标准detour语义); GeptCallOriginal走重定位
//     跳板(视图无关)
//  4. 第5+参数(栈参数)可转发: 安装时GEPT_HOOK.StackArgs=目标
//     函数栈参数个数(≤GEPT_MAX_STACK_ARGS)→回调收到StackArgs指针
//     (指向触发帧上实参, **可读可写**——写后GeptCallOriginal按改写值
//     转发)+GeptCallOriginal自动转发; StackArgs=0=旧语义(仅4寄存器参)
//
//硬件要求: 至少一核VT in-guest即可安装——
//  双EPT核: hooked视图remap=执行零VM-Exit detour(隐藏性最优,
//    视图切换=root侧vmwrite, 不依赖VMFUNC指令)
//  无hooked EPT核(深拷贝失败降级): violation降级——API语义完全
//    等价, 只是每次触发产生1+次VM-Exit(隐藏性降级)
//  目标prologue含相对分支/RIP-relative超±2GB=Install拒绝(极罕见,
//  日志[Reloc]行留痕, 绝不带病上机)
//====================================================================

//detour回调: 返回值=hook函数的返回值; Context=安装时原样传入;
//Arg1-4=原函数的rcx/rdx/r8/r9(x64前4个寄存器参数);
//StackArgs=第5+参数数组(指向触发帧上实参, 可读**可写**——写后
//GeptCallOriginal按改写值转发; NULL=安装时StackArgs=0未声明)
typedef ULONG64(*GEPT_CALLBACK)(
	PVOID Context, ULONG64 Arg1, ULONG64 Arg2, ULONG64 Arg3, ULONG64 Arg4,
	ULONG64* StackArgs);

//栈参数转发上限(hook.asm GeptCallOrigAsm固定帧=32槽×8B)
#define GEPT_MAX_STACK_ARGS 32

//安装描述(值语义, 安装后内部自持)
typedef struct _GEPT_HOOK
{
	PVOID Target;             //目标函数(内核虚拟地址)
	GEPT_CALLBACK Callback;   //detour回调
	PVOID Context;            //用户上下文(原样传给回调)
	ULONG StackArgs;          //目标函数第5+栈参数个数(0=不转发;
	//>0时回调收StackArgs指针+CallOriginal自动
	//转发; ≤GEPT_MAX_STACK_ARGS, 超限Install拒绝)
	ULONG HideRead;           //hook页读透明(双EPT核生效): 1=读/写violation
	//→MTF单步透出原页字节(PG/扫描器兼容); 代价=
	//该页每次数据访问+2 exit; CPU不支持exec-only
	//时自动回退。0=执行零exit, 读可见跳转字节
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
//统一经LDE重定位跳板(版本无关, 无prologue硬编码, 视图无关)
//声明StackArgs>0的hook, 第5+参数自动从触发帧转发
//(回调对StackArgs数组的改写一并生效; Arg1-4=本函数实参——
//经hook.asm GeptCallOrigAsm重建完整调用帧)
ULONG64 GeptCallOriginal(ULONG64 Arg1, ULONG64 Arg2, ULONG64 Arg3, ULONG64 Arg4);

//卸载收尾: DriverUload在关VT**之前**调用(移除全部hook, 让在途回调
//安全完成); 关VT之后调用GeptApiFreeMemory释放内存
VOID GeptApiRemoveAll(VOID);
VOID GeptApiFreeMemory(VOID);

//replay自测(仅调试/演示用)——直接调用指定hook的LDE重定位跳板,
//执行副本prologue后进入原函数体并正常返回。上机验证重定位生成器:
//传伪句柄NtCurrentProcess()给NtClose的replay→应返回STATUS_INVALID_HANDLE
NTSTATUS GeptApiSelfTestReplay(PVOID Target, ULONG64 Arg1);

#endif // GEPTAPI_H
