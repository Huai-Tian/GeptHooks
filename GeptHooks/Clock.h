#pragma once
#ifndef CLOCK_H
#define CLOCK_H
#include<ntifs.h>
#include"common.h"

//guest可读MMIO时钟描述(发现/校准结果, 布防与仿真的共享状态)
typedef struct _GEPT_CLK
{
	BOOLEAN Armed;       //发现+校验+校准通过(布防目标)
	ULONG64 Gpa;         //时钟页物理地址(4K对齐)
	PUCHAR  RootVA;      //root侧IoSpace映射(直读真值; guest态访问=陷阱)
	LONG64  Ratio;       //ΔTSC/Δclk(rdtsc夹逼标定, 补偿换算系数)
	USHORT  CtrOff;      //计数器页内偏移(HPET=0xF0, PM_TMR=0)
	UCHAR   CtrSize;     //计数器宽度字节(HPET 8/4, PM_TMR 4)
	ULONG64 CtrMask;     //计数器模掩(32位HPET/24位PM_TMR)
} GEPT_CLK, * PGEPT_CLK;

//发现(ACPI注册表镜像)+校准+逐核布防(VmxStartAllCpus末尾, PASSIVE)
VOID ClkInitAll(VOID);
//解除IoSpace映射(VmxShutdownAllCpus, VT已关后)
VOID ClkShutdown(VOID);
//vmcall(GEPT_VMCALL_CLKARM)的root侧: 当前核两套视图时钟页
//拆2M+清RWX+invept
VOID ClkArmCpu(VOID);
//EPT violation路径: 时钟页访存仿真。TRUE=已处置(RIP/RSP已写)
BOOLEAN ClkTryEmulate(PGUEST_REGS GuestRegs, ULONG64 guestRip,
	ULONG64 guestRsp, ULONG64 gpa);
//MTF(37)路径: flicker回捕(重封堵)。TRUE=已处置
BOOLEAN ClkMtfFinish(VOID);
//demo自检: guest态读计数器(布防后=仿真路径)。FALSE=该时钟未布防
BOOLEAN ClkDemoRead(ULONG idx, ULONG64* Val);

#endif // CLOCK_H
