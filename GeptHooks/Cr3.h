#pragma once
#ifndef CR3_H
#define CR3_H
#include<ntifs.h>

//==================== v1.12: 私有Host CR3 ====================
//root VA空间二分: VMM自身页=深拷贝页表路径(隔离, guest改共享PTE不
//影响root), guest世界页=浅拷贝(共享, 裸机等价)。全局单树八核共享。
//设计/不变式论证/SDM裁决见NOTES v1.12节。
//
//树未就绪(g_cr3Ready=0)时HOST_CR3照旧=launch线程CR3(可用性优先
//回退, 同RootIdt回退模式——链D未封但机器可用)

//PASSIVE: 池分配+树构建+boot快照集(DriverEntry预分配完成后、首个
//vmlaunch前调用——Ophion约束: 先分配完再建树)。drvBase/drvSize=
//驱动映像范围(boot快照第一项)。失败=树不就绪(回退), 不致命
BOOLEAN Cr3Init(PVOID drvBase, ULONG drvSize);
//PASSIVE: 全核vmx_off后释放(清零后释放=取证反制; 幂等)
VOID Cr3Shutdown(VOID);
//root侧深拷贝/sync(vmcall(13)处理器内调用, IF=0): [va,va+len)逐2M区
//私有化+逐页sync-on-alloc。池耗尽→该区域fallback共享+'K'环留痕,
//返回FALSE(非致命)
BOOLEAN Cr3ProtectRoot(ULONG64 va, ULONG64 len);
//统一入口(PASSIVE guest或root皆可): root(当前CR3=私有PML4)直接执行,
//guest经vmcall(13)提权执行; 非in-guest核跳过(fallback共享)
VOID Cr3ProtectAuto(PVOID va, ULONG64 len);
//观测: 私有PML4 PA(0=未就绪)/池VA与页数(EPT隐蔽+自检[5]用)/统计
ULONG64 Cr3PrivatePa(VOID);
PVOID Cr3PoolVa(VOID);
ULONG Cr3PoolPages(VOID);
ULONG Cr3DeepPtCount(VOID);
ULONG Cr3LargePdCount(VOID);

#endif // CR3_H
