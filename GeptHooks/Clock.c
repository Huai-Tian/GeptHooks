#include"Clock.h"
#include"VMX.h"
#include"CPU.h"
#include"ept.h"
#include"LDasm.h"

//==== MMIO时钟域封堵(v1.8) ====
//TSC offsetting隐藏exit驻留, 但guest可读的其他时钟计数器(HPET主
//计数器/ACPI PM定时器)按真实时间推进——与TSC交叉对比即暴露时间轴
//空洞。本模块把时钟页EPT清RWX: 每次访存violation→root仿真——
//计数器值=真值+TSC_OFFSET/Ratio(虚拟时钟与guest可见TSC同轴),
//页内其余寄存器root直读写(静态值, 无时序面); 不可解码指令flicker
//回退(放行单步→MTF回捕重封堵, 值未补偿=裸机语义的安全降级)。
//x2APIC TMCCT(0x83E): Win10在TSC-deadline模式下恒读0(惰性),
//无时序面, 不封堵; 端口型PM_TMR(legacy罕见)日志留痕跳过

#define GEPT_CLK_MAX 2
static GEPT_CLK s_clk[GEPT_CLK_MAX];   //[0]=HPET [1]=PM_TMR
//flicker回捕状态(每核一个, 0=无pending)
static volatile ULONG64 s_clkFlicker[128];

//root侧精确宽度MMIO读写(guest态调用同VA=走EPT陷阱, 布防后即仿真路径)
static ULONG64 ClkRead(PGEPT_CLK c, USHORT off, ULONG size)
{
	switch (size)
	{
	case 1: return *(volatile UCHAR*)(c->RootVA + off);
	case 2: return *(volatile USHORT*)(c->RootVA + off);
	case 4: return *(volatile ULONG*)(c->RootVA + off);
	}
	return *(volatile ULONG64*)(c->RootVA + off);
}

static VOID ClkWrite(PGEPT_CLK c, USHORT off, ULONG size, ULONG64 v)
{
	switch (size)
	{
	case 1: *(volatile UCHAR*)(c->RootVA + off) = (UCHAR)v; break;
	case 2: *(volatile USHORT*)(c->RootVA + off) = (USHORT)v; break;
	case 4: *(volatile ULONG*)(c->RootVA + off) = (ULONG)v; break;
	default: *(volatile ULONG64*)(c->RootVA + off) = v; break;
	}
}

//==== ACPI表发现(RSDP物理扫描——固件权威源) ====
//不依赖Windows注册表镜像(布局随版本变化不可靠): 直接扫RSDP——
//EBDA(BDA 0x40E字)+0xE0000-0xFFFFF, 16字节对齐+区和校验;
//RSDP(rev2+)→XSDT(8B项)/rev1→RSDT(4B项)→按签名取整表
static BOOLEAN ClkChksum(const UCHAR* p, ULONG len)
{
	UCHAR s = 0;
	for (ULONG i = 0; i < len; i++)
	{
		s += p[i];
	}
	return s == 0;
}

//物理直读(按页映射拷贝, 仅PASSIVE一次性发现用)
static BOOLEAN ClkReadPhys(ULONG64 gpa, PVOID buf, ULONG len)
{
	PUCHAR dst = (PUCHAR)buf;
	while (len > 0)
	{
		ULONG off = (ULONG)(gpa & 0xFFF);
		ULONG chunk = 0x1000 - off;
		if (chunk > len)
		{
			chunk = len;
		}
		PHYSICAL_ADDRESS pa;
		pa.QuadPart = (LONGLONG)(gpa & ~0xFFFULL);
		PUCHAR va = (PUCHAR)MmMapIoSpace(pa, PAGE_SIZE, MmNonCached);
		if (va == NULL)
		{
			return FALSE;
		}
		RtlCopyMemory(dst, va + off, chunk);
		MmUnmapIoSpace(va, PAGE_SIZE);
		dst += chunk;
		gpa += chunk;
		len -= chunk;
	}
	return TRUE;
}

//范围内找RSDP。*xsdtOut: 1=XSDT(rev2+) 0=RSDT(rev1)
static BOOLEAN ClkScanRsdp(ULONG64 start, ULONG64 len, ULONG64* sdtOut,
	UCHAR* xsdtOut)
{
	if (len == 0 || start + len <= start)
	{
		return FALSE;
	}
	PHYSICAL_ADDRESS pa;
	pa.QuadPart = (LONGLONG)start;
	PUCHAR va = (PUCHAR)MmMapIoSpace(pa, (SIZE_T)len, MmNonCached);
	if (va == NULL)
	{
		return FALSE;
	}
	BOOLEAN ok = FALSE;
	for (ULONG64 o = 0; o + 36 <= len; o += 16)
	{
		if (memcmp(va + o, "RSD PTR ", 8) != 0 || !ClkChksum(va + o, 20))
		{
			continue;
		}
		UCHAR rev = va[o + 15];
		if (rev >= 2)
		{
			if (!ClkChksum(va + o, 36))
			{
				continue;
			}
			RtlCopyMemory(sdtOut, va + o + 24, 8);
			*xsdtOut = 1;
		}
		else
		{
			ULONG32 p = 0;
			RtlCopyMemory(&p, va + o + 16, 4);
			*sdtOut = p;
			*xsdtOut = 0;
		}
		ok = TRUE;
		break;
	}
	MmUnmapIoSpace(va, (SIZE_T)len);
	return ok;
}

//XSDT/RSDT内按签名取表: 返回ExAllocatePool整表缓冲(调用方ExFreePool)
static PVOID ClkTableBySig(ULONG64 sdt, BOOLEAN isXsdt, const char* sig)
{
	UCHAR hdr[36];
	ULONG sdtLen = 0;
	if (!ClkReadPhys(sdt, hdr, 36) ||
		memcmp(hdr, isXsdt ? "XSDT" : "RSDT", 4) != 0)
	{
		return NULL;
	}
	RtlCopyMemory(&sdtLen, hdr + 4, 4);
	ULONG esz = isXsdt ? 8 : 4;
	if (sdtLen < 36 + esz || sdtLen > 0x4000)
	{
		return NULL;
	}
	UCHAR* sdtBuf = (UCHAR*)ExAllocatePoolWithTag(NonPagedPool, sdtLen, 'Pool');
	if (sdtBuf == NULL)
	{
		return NULL;
	}
	if (!ClkReadPhys(sdt, sdtBuf, sdtLen) || !ClkChksum(sdtBuf, sdtLen))
	{
		ExFreePool(sdtBuf);
		return NULL;
	}
	PVOID r = NULL;
	for (ULONG o = 36; o + esz <= sdtLen; o += esz)
	{
		ULONG64 tp = 0;
		if (isXsdt)
		{
			RtlCopyMemory(&tp, sdtBuf + o, 8);
		}
		else
		{
			ULONG32 p = 0;
			RtlCopyMemory(&p, sdtBuf + o, 4);
			tp = p;
		}
		UCHAR th[36];
		ULONG tLen = 0;
		if (tp == 0 || !ClkReadPhys(tp, th, 36) || memcmp(th, sig, 4) != 0)
		{
			continue;
		}
		RtlCopyMemory(&tLen, th + 4, 4);
		if (tLen < 36 || tLen > 0x1000)
		{
			continue;    //签名命中但长度异常
		}
		UCHAR* tb = (UCHAR*)ExAllocatePoolWithTag(NonPagedPool, tLen, 'Pool');
		if (tb == NULL)
		{
			break;
		}
		if (ClkReadPhys(tp, tb, tLen) && ClkChksum(tb, tLen))
		{
			r = tb;
			break;
		}
		ExFreePool(tb);
	}
	ExFreePool(sdtBuf);
	return r;
}

//HPET表: +0x28 GAS space, +0x2C u64基址(非对齐读)
static BOOLEAN ClkFindHpet(PGEPT_CLK c, ULONG64 sdt, BOOLEAN isXsdt)
{
	PVOID tbl = ClkTableBySig(sdt, isXsdt, "HPET");
	if (tbl == NULL)
	{
		FlLog("Clock: 系统描述表内无HPET表");
		return FALSE;
	}
	ULONG64 base = 0;
	UCHAR space = ((PUCHAR)tbl)[0x28];
	RtlCopyMemory(&base, (PUCHAR)tbl + 0x2C, sizeof(base));
	ExFreePool(tbl);
	if (space != 0 || (base & 0xFFF) != 0 || base >= 0x8000000000ULL)
	{
		FlLog("Clock: HPET表地址非法(space=%u base=%llX), 跳过",
			(ULONG)space, base);
		return FALSE;
	}
	c->Gpa = base;
	c->CtrOff = 0xF0;
	c->CtrSize = 8;
	c->CtrMask = ~0ULL;
	return TRUE;
}

//FADT: X_PM_TMR_BLK GAS@0xD0(space@+0 宽@+1 地址@+4), 表长须≥0xDC
static BOOLEAN ClkFindPmtmr(PGEPT_CLK c, ULONG64 sdt, BOOLEAN isXsdt)
{
	PVOID tbl = ClkTableBySig(sdt, isXsdt, "FACP");
	if (tbl == NULL)
	{
		FlLog("Clock: 系统描述表内无FADT表");
		return FALSE;
	}
	ULONG tblLen = 0;
	UCHAR space = 0, width = 0;
	ULONG64 addr = 0;
	RtlCopyMemory(&tblLen, (PUCHAR)tbl + 4, 4);
	if (tblLen >= 0xDC)
	{
		space = ((PUCHAR)tbl)[0xD0];
		width = ((PUCHAR)tbl)[0xD1];
		RtlCopyMemory(&addr, (PUCHAR)tbl + 0xD4, sizeof(addr));
	}
	ExFreePool(tbl);
	if (addr == 0 || width == 0)
	{
		FlLog("Clock: FADT无X_PM_TMR块(表长%u)——跳过", tblLen);
		return FALSE;
	}
	if (space != 0)
	{
		FlLog("Clock: PM_TMR为端口型(IO%llX)——未封堵, 留痕观察", addr);
		return FALSE;
	}
	if ((addr & 0xFFF) > 0xFFC || addr >= 0x8000000000ULL)
	{
		FlLog("Clock: PM_TMR地址非法(%llX), 跳过", addr);
		return FALSE;
	}
	c->Gpa = addr & ~0xFFFULL;
	c->CtrOff = (USHORT)(addr & 0xFFF);
	c->CtrSize = 4;
	ULONG bits = width;
	if (bits < 1 || bits > 32)
	{
		bits = 32;
	}
	c->CtrMask = (bits >= 32) ? 0xFFFFFFFFULL : ((1ULL << bits) - 1);
	return TRUE;
}

//HPET硬件验证: caps有效+周期合理+计数器活着; COUNT_SIZE_CAP=0按32位
static BOOLEAN ClkVerifyHpet(PGEPT_CLK c)
{
	ULONG64 caps = ClkRead(c, 0x00, 8);
	if ((ULONG32)caps == 0xFFFFFFFFULL || (caps & 0xFF) == 0)
	{
		return FALSE;    //MMIO洞(全1)或rev0=无HPET
	}
	ULONG64 period = ClkRead(c, 0x04, 8);   //fs/clk
	if (period < 10000 || period > 1000000000ULL)
	{
		return FALSE;    //10ns..1ms之外=不合理
	}
	if (((caps >> 13) & 1) == 0)
	{
		c->CtrSize = 4;
		c->CtrMask = 0xFFFFFFFFULL;
	}
	ULONG64 a = ClkRead(c, c->CtrOff, c->CtrSize);
	LARGE_INTEGER d;
	d.QuadPart = -10000;    //1ms
	KeDelayExecutionThread(KernelMode, FALSE, &d);
	ULONG64 b = ClkRead(c, c->CtrOff, c->CtrSize);
	return b != a;    //计数器推进=活着
}

//Ratio=ΔTSC/Δclk: guest侧rdtsc(已含TSC_OFFSET)与真计数器(未布防
//直读)同窗采样。按guest可见时间轴标定=检测者对照的同一条轴; 残余
//exit密度偏置<0.01%(低于MMIO读抖动), 不修正
static BOOLEAN ClkCalibrate(PGEPT_CLK c)
{
	ULONG64 best = 0;
	for (ULONG round = 0; round < 2; round++)
	{
		ULONG64 t0 = __rdtsc();
		ULONG64 c0 = ClkRead(c, c->CtrOff, c->CtrSize);
		LARGE_INTEGER d;
		d.QuadPart = -20000;    //2ms
		KeDelayExecutionThread(KernelMode, FALSE, &d);
		ULONG64 c1 = ClkRead(c, c->CtrOff, c->CtrSize);
		ULONG64 t1 = __rdtsc();
		if (c1 == c0 || t1 <= t0 || c1 - c0 > t1 - t0)
		{
			return FALSE;
		}
		ULONG64 r = (t1 - t0) / (c1 - c0);
		if (best == 0 || r < best)
		{
			best = r;
		}
	}
	if (best < 8 || best > 0x40000)
	{
		return FALSE;    //1kHz..1GHz之外=防呆
	}
	c->Ratio = (LONG64)best;
	return TRUE;
}

VOID ClkInitAll(VOID)
{
	//RSDP发现: 先EBDA(BDA 0x40E字×16), 后0xE0000-0xFFFFF全区
	ULONG64 sdt = 0;
	UCHAR xsdt = 0;
	{
		UCHAR bda[2] = { 0, 0 };
		if (ClkReadPhys(0x40E, bda, 2))
		{
			USHORT seg = (USHORT)(bda[0] | ((USHORT)bda[1] << 8));
			if (seg != 0 && (ULONG64)seg * 16 + 0x400 <= 0xE0000)
			{
				ClkScanRsdp((ULONG64)seg * 16, 0x400, &sdt, &xsdt);
			}
		}
		if (sdt == 0)
		{
			ClkScanRsdp(0xE0000, 0x20000, &sdt, &xsdt);
		}
	}
	if (sdt == 0)
	{
		FlLog("Clock: RSDP未发现(EBDA+0xE0000-0xFFFFF)——跳过时钟封堵");
		return;
	}
	FlLog("Clock: RSDP→%s@%llX", xsdt ? "XSDT" : "RSDT", sdt);
	static const char* names[GEPT_CLK_MAX] = { "HPET", "PM_TMR" };
	ULONG armed = 0;
	for (ULONG i = 0; i < GEPT_CLK_MAX; i++)
	{
		PGEPT_CLK c = &s_clk[i];
		if ((i == 0 ? ClkFindHpet(c, sdt, xsdt)
			: ClkFindPmtmr(c, sdt, xsdt)) == FALSE)
		{
			continue;
		}
		PHYSICAL_ADDRESS pa;
		pa.QuadPart = (LONGLONG)c->Gpa;
		c->RootVA = (PUCHAR)MmMapIoSpace(pa, PAGE_SIZE, MmNonCached);
		if (c->RootVA == NULL)
		{
			FlLog("Clock: %s IoSpace映射失败(%llX)", names[i], c->Gpa);
			continue;
		}
		if ((i == 0 && !ClkVerifyHpet(c)) || !ClkCalibrate(c))
		{
			FlLog("Clock: %s 校验/校准失败(计数器不动或比值异常), 跳过",
				names[i]);
			MmUnmapIoSpace(c->RootVA, PAGE_SIZE);
			c->RootVA = NULL;
			continue;
		}
		c->Armed = TRUE;
		armed++;
		FlLog("Clock: %s就绪 页=%llX 计数器@+%03X宽%u Ratio=%lld(ΔTSC/Δclk)",
			names[i], c->Gpa, (ULONG)c->CtrOff, (ULONG)c->CtrSize, c->Ratio);
		FlRingPush('l', KeGetCurrentProcessorNumber(), 0,
			(ULONG64)c->Ratio, c->Gpa + c->CtrOff, 0);
	}
	if (armed == 0)
	{
		FlLog("Clock: 无可封堵MMIO时钟(HPET/PM_TMR缺失或校验失败)");
		return;
	}
	//逐核布防: vmcall(11)→root在当前核两套视图拆页+清RWX+invept
	ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
	KAFFINITY allCpus = KeQueryActiveProcessors();
	for (ULONG i = 0; i < cpuCount; i++)
	{
		if (g_vcpu[i].bInGuest)
		{
			KeSetSystemAffinityThread((KAFFINITY)1 << i);
			CmVmCall(GEPT_VMCALL_CLKARM, 0, 0, 0);
		}
	}
	KeSetSystemAffinityThread(allCpus);
	FlLog("Clock: 布防完成(%u个时钟, %u核×两视图清RWX, 环'a'留痕)",
		armed, cpuCount);
}

VOID ClkShutdown(VOID)
{
	for (ULONG i = 0; i < GEPT_CLK_MAX; i++)
	{
		if (s_clk[i].RootVA != NULL)
		{
			MmUnmapIoSpace(s_clk[i].RootVA, PAGE_SIZE);
			s_clk[i].RootVA = NULL;
		}
		s_clk[i].Armed = FALSE;
	}
}

//vmcall(11)root侧: 时钟页在两套视图(cleanup陷阱与hook视图正交,
//任一视图下访存都要exit)拆2M+PTE清RWX。exit上下文arena切槽安全
VOID ClkArmCpu(VOID)
{
	ULONG cpu = KeGetCurrentProcessorNumber();
	if (!g_vcpu[cpu].bInGuest)
	{
		return;
	}
	for (ULONG i = 0; i < GEPT_CLK_MAX; i++)
	{
		PGEPT_CLK c = &s_clk[i];
		if (!c->Armed)
		{
			continue;
		}
		for (ULONG v = 0; v < 2; v++)
		{
			PEPT_DATA e = (v == 0) ? g_vcpu[cpu].PeptData
				: g_vcpu[cpu].PeptDataHooked;
			if (e == NULL || (v == 1 && !g_vcpu[cpu].bVmfuncOn))
			{
				continue;
			}
			PEPT_PDE_2M pde = EptGetPde2B(e, c->Gpa);
			if (pde == NULL)
			{
				continue;
			}
			if (pde->fileds.ps && !EptPdeToPte(pde))
			{
				continue;
			}
			PEPT_PTE pte = EptGetPte(e, c->Gpa);
			if (pte == NULL)
			{
				continue;
			}
			pte->fileds.present = 0;
			pte->fileds.write = 0;
			pte->fileds.execute = 0;
		}
	}
	EptInveptCurrent();
	FlRingPush('a', cpu, GEPT_VMCALL_CLKARM,
		s_clk[0].Gpa, s_clk[1].Gpa, 0);
}

//==== 访存指令解码+仿真 ====
typedef struct _CLK_ACC
{
	ULONG len;         //指令长度
	ULONG size;        //访存宽度字节
	BOOLEAN isRead;    //TRUE=load→GPR
	BOOLEAN zx;        //MOVZX(零扩写回)
	UCHAR reg;         //读=目的/写=源寄存器号(0-15, REX.R扩展)
	BOOLEAN isImm;     //写源=立即数(C6/C7)
	ULONG64 imm;       //写立即数
} CLK_ACC;

//GPR号→GUEST_REGS字段: 字段序=硬件编码序(rax..rdi=0-7, r8-r15)
static VOID ClkSetGpr(PGUEST_REGS regs, UCHAR reg, ULONG64 v, ULONG size)
{
	PULONG64 gp = (PULONG64)regs;
	if (size == 8)
	{
		gp[reg] = v;
	}
	else if (size == 4)
	{
		gp[reg] = (ULONG)v;    //32位写零扩
	}
	else if (size == 1)
	{
		gp[reg] = (gp[reg] & ~0xFFULL) | (v & 0xFF);
	}
	else
	{
		gp[reg] = (gp[reg] & ~0xFFFFULL) | (v & 0xFFFF);
	}
}

//解码单条访存指令: MOV族(88/89/8A/8B/C6/C7)+MOVZX(0F B6/B7)。
//violation已给出GPA, 无需计算有效地址; SSE/串/66/67/LOCK前缀等
//不支持→FALSE(flicker回退)。取指root直读内核VA(取指页正在执行
//=恒present)
static BOOLEAN ClkDecode(ULONG64 rip, CLK_ACC* acc)
{
	if ((rip >> 48) != 0xFFFF)
	{
		return FALSE;    //非canonical内核VA(防御)
	}
	ULONG64 rest = (rip | 0xFFFULL) + 1 - rip;
	if (rest < 2)
	{
		return FALSE;
	}
	UCHAR code[16];
	ULONG cap = rest < 15 ? (ULONG)rest : 15;
	RtlCopyMemory(code, (PVOID)rip, cap);
	ldasm_data ld;
	ULONG len = ldasm(code, &ld, 1);
	if (len == 0 || len > cap || !(ld.flags & F_MODRM))
	{
		return FALSE;
	}
	//前缀区仅允许段覆盖与REX; 66/67/F0/F2/F3=不支持
	for (ULONG i = 0; i < ld.opcd_offset; i++)
	{
		UCHAR p = code[i];
		if (p >= 0x40 && p <= 0x4F)
		{
			continue;
		}
		if (p == 0x2E || p == 0x36 || p == 0x3E || p == 0x26 ||
			p == 0x64 || p == 0x65)
		{
			continue;
		}
		return FALSE;
	}
	UCHAR op = code[ld.opcd_offset];
	if (((ld.modrm >> 6) & 3) == 3)
	{
		return FALSE;    //寄存器操作数(不应触发violation)
	}
	UCHAR reg = (UCHAR)(((ld.modrm >> 3) & 7) | ((ld.rex & 4) ? 8 : 0));
	BOOLEAN w = (ld.rex & 8) != 0;
	RtlZeroMemory(acc, sizeof(*acc));
	acc->reg = reg;
	if (op == 0x0F)
	{
		UCHAR op2 = code[ld.opcd_offset + 1];
		if (op2 != 0xB6 && op2 != 0xB7)
		{
			return FALSE;    //仅MOVZX
		}
		acc->isRead = TRUE;
		acc->zx = TRUE;
		acc->size = (op2 == 0xB6) ? 1 : 2;
	}
	else
	{
		switch (op)
		{
		case 0x8A: acc->isRead = TRUE; acc->size = 1; break;
		case 0x8B: acc->isRead = TRUE; acc->size = w ? 8 : 4; break;
		case 0x88: acc->isRead = FALSE; acc->size = 1; break;
		case 0x89: acc->isRead = FALSE; acc->size = w ? 8 : 4; break;
		case 0xC6: acc->isRead = FALSE; acc->size = 1; acc->isImm = TRUE; break;
		case 0xC7: acc->isRead = FALSE; acc->size = 4; acc->isImm = TRUE; break;
		default: return FALSE;
		}
		if (acc->isImm)
		{
			if (ld.imm_size != acc->size)
			{
				return FALSE;    //66前缀(2字节imm)已在前缀区排除
			}
			RtlCopyMemory(&acc->imm, code + ld.imm_offset, acc->size);
		}
	}
	acc->len = len;
	return TRUE;
}

//不可解码访存: 放行当前指令(恢复页权限)+MTF单步→MTF exit回捕
//重封堵。值未补偿=安全降级(裸机语义一致); REP串=逐迭代2 exit
//(MMIO串读病态场景, 正确性优先)。FALSE=PTE不可得(理论不可能,
//调用方回落常规路径)
static BOOLEAN ClkFlicker(ULONG64 gpa)
{
	ULONG cpu = KeGetCurrentProcessorNumber();
	PEPT_PTE pte = EptGetPte(EptGetActiveData(), gpa);
	if (pte == NULL)
	{
		return FALSE;
	}
	pte->fileds.present = 1;
	pte->fileds.write = 1;
	pte->fileds.execute = 1;
	EptInveptCurrent();
	s_clkFlicker[cpu & 127] = gpa;
	ULONG64 ctl = 0;
	__vmx_vmread(CPU_BASED_VM_EXEC_CONTROL, &ctl);
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, ctl | 0x08000000ULL);
	return TRUE;
}

BOOLEAN ClkTryEmulate(PGUEST_REGS GuestRegs, ULONG64 guestRip,
	ULONG64 guestRsp, ULONG64 gpa)
{
	PGEPT_CLK c = NULL;
	for (ULONG i = 0; i < GEPT_CLK_MAX; i++)
	{
		if (s_clk[i].Armed && (gpa & ~0xFFFULL) == s_clk[i].Gpa)
		{
			c = &s_clk[i];
			break;
		}
	}
	if (c == NULL)
	{
		return FALSE;
	}
	ULONG cpu = KeGetCurrentProcessorNumber();
	CLK_ACC acc;
	if (!ClkDecode(guestRip, &acc) ||
		(gpa & 0xFFF) + acc.size > 0x1000)
	{
		//不可解码/跨页错位: flicker放行
		if (ClkFlicker(gpa))
		{
			static volatile LONG s_gCnt[128] = { 0 };
			LONG gn = InterlockedIncrement(&s_gCnt[cpu & 127]);
			if (gn == 1 || (gn & 0xFFF) == 0)
			{
				FlRingPush('g', cpu, 48, gpa, guestRip, 0);
			}
			__vmx_vmwrite(GUEST_RIP, guestRip);
			__vmx_vmwrite(GUEST_RSP, guestRsp);
			return TRUE;
		}
		return FALSE;
	}
	USHORT off = (USHORT)(gpa & 0xFFF);
	ULONG ctrLo = c->CtrOff;    //ULONG统一比较类型(USHORT+UCHAR提升为int=符号警告)
	ULONG ctrHi = (ULONG)c->CtrOff + c->CtrSize;
	if (acc.isRead)
	{
		ULONG64 val = 0;
		BOOLEAN virt = FALSE;
		if (off >= ctrLo && off + acc.size <= ctrHi)
		{
			//计数器窗: 真值+TSC_OFFSET/Ratio(与guest可见TSC同轴)
			ULONG64 real = ClkRead(c, c->CtrOff, c->CtrSize);
			ULONG64 tscOff = 0;
			__vmx_vmread(TSC_OFFSET, &tscOff);
			LONG64 comp = (LONG64)tscOff / c->Ratio;
			val = ((real + (ULONG64)comp) & c->CtrMask)
				>> (8 * (off - c->CtrOff));
			virt = TRUE;
		}
		else if (off + acc.size <= ctrLo || off >= ctrHi)
		{
			val = ClkRead(c, off, acc.size);    //其余寄存器直读真值
		}
		else
		{
			//跨计数器边界错位访问: flicker放行
			if (ClkFlicker(gpa))
			{
				__vmx_vmwrite(GUEST_RIP, guestRip);
				__vmx_vmwrite(GUEST_RSP, guestRsp);
				return TRUE;
			}
			return FALSE;
		}
		if (acc.zx)
		{
			ClkSetGpr(GuestRegs, acc.reg, val, 8);    //MOVZX: 零扩全宽写
		}
		else
		{
			ClkSetGpr(GuestRegs, acc.reg, val, acc.size);
		}
		if (virt)
		{
			//'y'留痕(采样: 首次+每4096次)
			static volatile LONG s_yCnt[128] = { 0 };
			LONG yn = InterlockedIncrement(&s_yCnt[cpu & 127]);
			if (yn == 1 || (yn & 0xFFF) == 0)
			{
				FlRingPush('y', cpu, 48, gpa, guestRip, val);
			}
		}
	}
	else
	{
		if (off < ctrHi && off + acc.size > ctrLo)
		{
			;    //计数器只读: 写丢弃(与真硬件一致)
		}
		else
		{
			ULONG64 v;
			if (acc.isImm)
			{
				v = acc.imm;
			}
			else
			{
				PULONG64 gp = (PULONG64)GuestRegs;
				v = gp[acc.reg];
				if (acc.size == 1)
				{
					v &= 0xFF;
				}
				else if (acc.size == 4)
				{
					v = (ULONG)v;
				}
			}
			ClkWrite(c, off, acc.size, v);
		}
	}
	__vmx_vmwrite(GUEST_RIP, guestRip + acc.len);
	__vmx_vmwrite(GUEST_RSP, guestRsp);
	return TRUE;
}

BOOLEAN ClkMtfFinish(VOID)
{
	ULONG cpu = KeGetCurrentProcessorNumber();
	ULONG64 gpa = s_clkFlicker[cpu & 127];
	if (gpa == 0)
	{
		return FALSE;
	}
	s_clkFlicker[cpu & 127] = 0;
	PEPT_PTE pte = EptGetPte(EptGetActiveData(), gpa);
	if (pte != NULL)
	{
		pte->fileds.present = 0;
		pte->fileds.write = 0;
		pte->fileds.execute = 0;
		EptInveptCurrent();
	}
	ULONG64 ctl = 0;
	__vmx_vmread(CPU_BASED_VM_EXEC_CONTROL, &ctl);
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, ctl & ~0x08000000ULL);
	return TRUE;
}

BOOLEAN ClkDemoRead(ULONG idx, ULONG64* Val)
{
	if (idx >= GEPT_CLK_MAX || !s_clk[idx].Armed || Val == NULL)
	{
		return FALSE;
	}
	PGEPT_CLK c = &s_clk[idx];
	//布防后本读即走仿真路径(virtual值), 'y'留痕
	*Val = ClkRead(c, c->CtrOff, c->CtrSize) & c->CtrMask;
	return TRUE;
}
