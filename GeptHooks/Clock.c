#include"Clock.h"
#include"VMX.h"
#include"CPU.h"
#include"ept.h"
#include"LDasm.h"
#include"Cr3.h"

//==== MMIO时钟域封堵(v1.8) ====
//TSC offsetting隐藏exit驻留, 但guest可读的其他时钟计数器(HPET主
//计数器/ACPI PM定时器)按真实时间推进——与TSC交叉对比即暴露时间轴
//空洞。本模块把时钟页EPT清RWX: 每次访存violation→root仿真——
//计数器值=真值+TSC_OFFSET/Ratio(虚拟时钟与guest可见TSC同轴),
//页内其余寄存器root直读写(静态值, 无时序面); 不可解码指令flicker
//回退(放行单步→MTF回捕重封堵, 值未补偿=裸机语义的安全降级)。
//MSR时钟(APeRF/MPERF/TMCCT)不封堵(v1.9b裁决): 位图拦截=热读者每读
//一次exit, 实测GPU驱动类rdmsr自旋环被打成r31风暴→TDR黑屏(NOTES
//v1.9b); 残余驻留已低于晶体容差地板('z'量化)无归因价值; x2APIC
//TMCCT实为0x839(0x83E=定时器分频寄存器DCR)。端口型PM_TMR(SystemIO)
//走I/O位图封堵(见下端口段); 虚拟计数器单调钳制(见下节)

#define GEPT_CLK_MAX 2
static GEPT_CLK s_clk[GEPT_CLK_MAX];   //[0]=HPET [1]=PM_TMR
//flicker回捕状态(每核一个, 0=无pending)
static volatile ULONG64 s_clkFlicker[128];

//==== 影子flicker(v1.12a: 慢路径统一补偿) ====
//旧plain flicker放行=guest读真值(未补偿)→与rdtsc不同轴=驻留泄漏臂
//(MOVSX/SSE读/错位读/AVX/x87等一切非GPR-MOV指令可达; 自然流量0,
//纯主动检测面)。影子方案: 慢路径把时钟页PTE临时改译到影子页
//(=真页4KB副本+计数器字节替换为补偿值)→指令原样重执行, 读到
//补偿语义——**方向无关+指令无关**(无opcode枚举表, SSE/AVX/x87
//天然全覆盖=枚举解码方案的严格超集)。写回: MTF后diff影子vs基线
//(=指令前影子快照)得guest本条指令的store字节, 逐段ClkWrite回真
//页(计数器窗除外=硬件只读)——store落真页, 封掉"影子写被吞后读回"
//检测臂。每核独立影子+基线(两核并发flicker互不污染)。
static PUCHAR s_clkShadow[128];      //每核影子页(flicker改译目标)
static PUCHAR s_clkShadowBase[128];  //每核基线页(diff基准)
static ULONG64 s_clkFlickerPte[128]; //flicker前PTE原值(MTF整体回写)
static LONG s_clkFlickerClk[128];    //flicker时钟槽号(-1=plain降级)

//==== 虚拟计数器单调钳制(v1.9b) ====
//补偿量=TSC_OFFSET/Ratio, 而TSC_OFFSET随本核每次exit单调变负, 读
//时钟本身又产生exit——快速连读时虚拟值可倒退(裸机计数器永不倒退)
//=自造检测向量+等待环永不满足(v1.9a黑屏的助推机制)。钳制: 新值
//小于上次且差<半量程→钳到上次值(等值合法, 真硬件快读同值常见);
//≥半量程=自然回绕放行。全局共享+CAS有界重试, 无锁, exit安全
static volatile LONG64 s_clkLastVirt[GEPT_CLK_MAX];   //MMIO时钟上次虚拟值
static volatile LONG64 s_clkIoLastVirt;               //端口时钟上次虚拟值

static ULONG64 ClkClampMonotonic(volatile LONG64* last, ULONG64 v, ULONG64 mask)
{
	for (ULONG k = 0; k < 4; k++)
	{
		LONG64 cur = *last;
		LONG64 d = (LONG64)v - cur;
		if (d < 0 && (ULONG64)(-d) < (mask >> 1))
		{
			return (ULONG64)cur;    //小幅倒退→钳到上次值(不推进)
		}
		if (d == 0)
		{
			return v;
		}
		if (InterlockedCompareExchange64(last, (LONG64)v, cur) == cur)
		{
			return v;    //前进/大步回绕(≥半量程=wrap)已落账
		}
		//CAS失败=他核并发推进: 重读重试
	}
	return v;    //重试耗尽(病态并发): 放行原值
}

//==== 端口时钟(PM_TMR SystemIO型)====
//I/O位图置位→exit(30)→root仿真: IN=真值+TSC_OFFSET/Ratio(与TSC
//同轴), OUT直写(计数器RO, 写被硬件忽略); 串INS/OUTS=清位放行单
//迭代+MTF回捕重置位(逐迭代2 exit, 同MMIO flicker语义, 值未补偿
//的病态场景安全降级)
static USHORT s_clkIoPort = 0;              //0=无端口时钟
static ULONG64 s_clkIoMask = 0xFFFFFFFFULL; //计数器位宽掩码
static LONG64 s_clkIoRatio = 0;             //ΔTSC/Δport
static volatile USHORT s_clkIoFlicker[128]; //MTF回捕pending(端口号, 0=无)

//端口时钟校准(ClkInitAll内, 布防前——此时位图全零端口直通)
static BOOLEAN ClkIoCalibrate(USHORT port)
{
	ULONG64 best = 0;
	for (ULONG round = 0; round < 2; round++)
	{
		ULONG64 t0 = __rdtsc();
		ULONG64 c0 = __indword(port);
		LARGE_INTEGER d;
		d.QuadPart = -20000;    //2ms
		KeDelayExecutionThread(KernelMode, FALSE, &d);
		ULONG64 c1 = __indword(port);
		ULONG64 t1 = __rdtsc();
		if (c1 == c0 || t1 <= t0 || (c1 - c0) > (t1 - t0))
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
	s_clkIoRatio = (LONG64)best;
	return TRUE;
}

//root侧(ClkArmCpu布防/flicker回捕调用): 当前核I/O位图置/清端口位
//(位图页自我隐蔽, guest态直写=落零页; root直写真页)。I/O位图无
//缓存, 即时生效
static VOID ClkIoArmCpu(USHORT port, BOOLEAN set)
{
	ULONG cpu = KeGetCurrentProcessorNumber();
	PUCHAR bm = (PUCHAR)g_vcpu[cpu].IoBitmaps;
	if (bm == NULL || port == 0)
	{
		return;
	}
	PUCHAR byte = (port < 0x8000) ? &bm[port / 8] : &bm[PAGE_SIZE + (port - 0x8000) / 8];
	UCHAR bit = (UCHAR)(1 << (port % 8));
	if (set)
	{
		*byte |= bit;
	}
	else
	{
		*byte &= (UCHAR)~bit;
	}
	FlRingPush('a', cpu, 13, port, set ? 1 : 0, 0);
}

//exit(30)路径(VmxExitHandler调用): TRUE=已处置(走通用RIP推进);
//FALSE=串指令flicker(调用方不推进RIP重执行)
BOOLEAN ClkIoTryEmulate(PGUEST_REGS GuestRegs, ULONG64 exitQual)
{
	//qualification: bits2:0=宽度-1, bit3=方向(0=OUT 1=IN),
	//bit4=串指令, bits31:16=端口号(SDM 24.6.4)
	USHORT port = (USHORT)(exitQual >> 16);
	//串指令(INS/OUTS): 清位放行单迭代+MTF回捕。时钟端口回捕后重
	//置位(逐迭代2 exit, 同MMIO flicker); 非时钟端口(理论不到达——
	//位图仅时钟位置位)回捕后保持清位=永久直通
	if ((exitQual >> 4) & 1)
	{
		ULONG cpu = KeGetCurrentProcessorNumber();
		ClkIoArmCpu(port, FALSE);
		if (port == s_clkIoPort && s_clkIoPort != 0)
		{
			s_clkIoFlicker[cpu & 127] = port;
		}
		ULONG64 ctl = 0;
		__vmx_vmread(CPU_BASED_VM_EXEC_CONTROL, &ctl);
		__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, ctl | 0x08000000ULL);
		FlRingPush('g', cpu, 30, port, exitQual, 0);
		return FALSE;
	}
	if (port != s_clkIoPort || s_clkIoPort == 0)
	{
		//非时钟端口(理论不到达——位图仅时钟位置位): 标量直通兜底
		ULONG size = (ULONG)(exitQual & 7) + 1;
		if ((exitQual >> 3) & 1)
		{
			GuestRegs->rax = (size == 1) ? __inbyte(port) :
				(size == 2) ? __inword(port) : __indword(port);
		}
		else
		{
			ULONG64 v = GuestRegs->rax;
			if (size == 1) { __outbyte(port, (UCHAR)v); }
			else if (size == 2) { __outword(port, (USHORT)v); }
			else { __outdword(port, (ULONG)v); }
		}
		return TRUE;    //走通用RIP推进
	}
	ULONG size = (ULONG)(exitQual & 7) + 1;
	if ((exitQual >> 3) & 1)
	{
		//IN: 真值+TSC_OFFSET/Ratio(有符号补偿, 与guest可见TSC同轴)
		//+单调钳制(见ClkClampMonotonic)
		ULONG64 val = __indword(port);
		if (size == 4 && s_clkIoRatio != 0)
		{
			ULONG64 tscOff = 0;
			__vmx_vmread(TSC_OFFSET, &tscOff);
			LONG64 comp = (LONG64)tscOff / s_clkIoRatio;
			val = (ULONG64)(((LONG64)(val & s_clkIoMask) + comp)
				& (LONG64)s_clkIoMask);
			val = ClkClampMonotonic(&s_clkIoLastVirt, val, s_clkIoMask);
		}
		if (size == 1) { GuestRegs->rax = val & 0xFF; }
		else if (size == 2) { GuestRegs->rax = val & 0xFFFF; }
		else { GuestRegs->rax = val; }
		static volatile LONG s_ioCnt[128] = { 0 };
		ULONG cpu = KeGetCurrentProcessorNumber();
		LONG n = InterlockedIncrement(&s_ioCnt[cpu & 127]);
		if (n == 1 || (n & 0xFFF) == 0)
		{
			FlRingPush('y', cpu, 30, port, val, 0);
		}
	}
	else
	{
		//OUT: 直写(计数器RO硬件忽略; 其他寄存器本端口无)
		ULONG64 v = GuestRegs->rax;
		if (size == 1) { __outbyte(port, (UCHAR)v); }
		else if (size == 2) { __outword(port, (USHORT)v); }
		else { __outdword(port, (ULONG)v); }
	}
	return TRUE;    //走通用RIP推进
}

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
		//端口型(SystemIO): I/O位图封堵路径(见上"端口时钟"段),
		//返回TRUE走端口校准+布防, 不占MMIO槽位
		if (addr > 0xFFFF)
		{
			FlLog("Clock: PM_TMR端口越界(%llX), 跳过", addr);
			return FALSE;
		}
		s_clkIoPort = (USHORT)addr;
		ULONG bits = width;
		if (bits < 1 || bits > 32)
		{
			bits = 32;
		}
		s_clkIoMask = (bits >= 32) ? 0xFFFFFFFFULL : ((1ULL << bits) - 1);
		FlLog("Clock: PM_TMR为端口型(端口%llX宽%u)——走I/O位图封堵",
			addr, bits);
		return TRUE;
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
		//端口型PM_TMR: 走I/O位图路径(校准+逐核布防), 不占MMIO槽
		if (s_clkIoPort != 0)
		{
			if (!ClkIoCalibrate(s_clkIoPort))
			{
				FlLog("Clock: 端口PM_TMR校准失败(计数器不动), 跳过");
				s_clkIoPort = 0;
			}
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
		//v1.12: 时钟页RootVA深拷贝入私有CR3树(root读者——ClkReadRoot
		//经此VA读HPET计数器; guest PASSIVE→vmcall(13)提权执行)
		Cr3ProtectAuto(c->RootVA, PAGE_SIZE);
		FlLog("Clock: %s就绪 页=%llX 计数器@+%03X宽%u Ratio=%lld(ΔTSC/Δclk)",
			names[i], c->Gpa, (ULONG)c->CtrOff, (ULONG)c->CtrSize, c->Ratio);
		FlRingPush('l', KeGetCurrentProcessorNumber(), 0,
			(ULONG64)c->Ratio, c->Gpa + c->CtrOff, 0);
	}
	if (armed == 0)
	{
		FlLog("Clock: 无可封堵MMIO时钟(HPET/PM_TMR缺失或校验失败)");
	}
	//影子flicker页(v1.12a): 每核影子+基线(慢路径改译目标/diff基准;
	//分配失败核自动降级plain flicker='g'环c=0可辨)
	if (armed > 0)
	{
		ULONG shadowCpus = KeQueryActiveProcessorCount(NULL);
		ULONG shadowOk = 0;
		for (ULONG i = 0; i < shadowCpus && i < 128; i++)
		{
			s_clkShadow[i] = ExAllocatePoolWithTag(
				NonPagedPool, PAGE_SIZE, 'Pool');
			s_clkShadowBase[i] = ExAllocatePoolWithTag(
				NonPagedPool, PAGE_SIZE, 'Pool');
			if (s_clkShadow[i] != NULL && s_clkShadowBase[i] != NULL)
			{
				RtlZeroMemory(s_clkShadow[i], PAGE_SIZE);
				RtlZeroMemory(s_clkShadowBase[i], PAGE_SIZE);
				shadowOk++;
				//v1.12: root写者(影子构建/写回均在exit上下文)→私有CR3树
				Cr3ProtectAuto(s_clkShadow[i], PAGE_SIZE);
				Cr3ProtectAuto(s_clkShadowBase[i], PAGE_SIZE);
			}
			else
			{
				if (s_clkShadow[i]) { ExFreePool(s_clkShadow[i]); s_clkShadow[i] = NULL; }
				if (s_clkShadowBase[i]) { ExFreePool(s_clkShadowBase[i]); s_clkShadowBase[i] = NULL; }
			}
		}
		FlLog("Clock: 影子flicker页就绪 %u/%u核(每核影子+基线, 慢路径统一补偿)",
			shadowOk, shadowCpus);
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
	if (armed > 0)
	{
		FlLog("Clock: MMIO布防完成(%u个时钟, %u核×两视图清RWX, 环'a'留痕)",
			armed, cpuCount);
	}
	if (s_clkIoPort != 0)
	{
		FlLog("Clock: 端口PM_TMR布防完成(端口%X, %u核I/O位图置位→exit(30)补偿仿真)",
			(ULONG)s_clkIoPort, cpuCount);
	}
	FlLog("Clock: MSR时钟(APeRF/MPERF/TMCCT)不封堵——v1.9b裁决(热读者exit风暴, 见NOTES)");
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
	//影子flicker页(v1.12a; VT已关=零exit上下文, 释放安全; 清零=
	//取证反制——页含HPET寄存器副本+补偿计数器痕迹)
	for (ULONG i = 0; i < 128; i++)
	{
		if (s_clkShadow[i] != NULL)
		{
			RtlZeroMemory(s_clkShadow[i], PAGE_SIZE);
			ExFreePool(s_clkShadow[i]);
			s_clkShadow[i] = NULL;
		}
		if (s_clkShadowBase[i] != NULL)
		{
			RtlZeroMemory(s_clkShadowBase[i], PAGE_SIZE);
			ExFreePool(s_clkShadowBase[i]);
			s_clkShadowBase[i] = NULL;
		}
		s_clkFlicker[i] = 0;
		s_clkFlickerClk[i] = -1;
	}
}

//vmcall(11)root侧: 时钟页在两套视图(cleanup陷阱与hook视图正交,
//任一视图下访存都要exit)拆2M+PTE清RWX+端口时钟I/O位置位。exit
//上下文arena切槽安全
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
			if (e == NULL)
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
	//端口时钟(PM_TMR SystemIO型): 本核I/O位图置位(procCtl bit25已
	//开, 位图全零=直通; 置位后该端口IN/OUT→exit(30)→ClkIoTryEmulate)
	if (s_clkIoPort != 0)
	{
		ClkIoArmCpu(s_clkIoPort, TRUE);
	}
	//影子flicker页EPT隐蔽(v1.12a: 页含HPET寄存器副本+补偿计数器=
	//框架痕迹, 物理扫描可见; 两视图改译零页, 同CodePage物理隐蔽
	//语义——flicker改译的是时钟GPA的PTE, 与影子自身GPA的隐蔽PTE
	//互不干扰)
	if (s_clkShadow[cpu & 127] != NULL)
	{
		EptHideVaBothViews(g_vcpu[cpu].PeptData,
			g_vcpu[cpu].PeptDataHooked, s_clkShadow[cpu & 127], PAGE_SIZE);
	}
	if (s_clkShadowBase[cpu & 127] != NULL)
	{
		EptHideVaBothViews(g_vcpu[cpu].PeptData,
			g_vcpu[cpu].PeptDataHooked, s_clkShadowBase[cpu & 127],
			PAGE_SIZE);
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

//plain flicker降级(v1.12a起仅影子页不可得时走): 恢复真页权限放行
//当前指令+MTF回捕重封堵。值未补偿=泄漏臂残留(分配失败核的降级
//形态, 'g'环c=0可辨); REP串=逐迭代2 exit。FALSE=PTE不可得
static BOOLEAN ClkFlicker(ULONG64 gpa)
{
	ULONG cpu = KeGetCurrentProcessorNumber();
	PEPT_PTE pte = EptGetPte(EptGetActiveData(), gpa);
	if (pte == NULL)
	{
		return FALSE;
	}
	s_clkFlickerPte[cpu & 127] = pte->ALL;    //MTF整体回写基准
	s_clkFlickerClk[cpu & 127] = -1;          //plain降级(无写回)
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

//影子flicker(v1.12a慢路径统一入口, 见块头注释): 基线=真页4KB快照
//→影子=基线副本+计数器窗替换为补偿值(与快路径同公式同钳制)→时钟
//GPA的PTE改译影子PFN|RWX|UC(UC绕缓存: WB读会把影子行缓存到该VA,
//后续plain放行的UC真值读不失效陈旧行=读到旧补偿值)→MTF单步。
//4KB MMIO快照≈百µs级=慢路径专属代价(自然流量0, 纯攻击面);
//FALSE=影子页未分配/ PTE不可得(调用方走plain降级)
static BOOLEAN ClkFlickerShadow(PGEPT_CLK c, ULONG clkIdx, ULONG64 gpa)
{
	ULONG cpu = KeGetCurrentProcessorNumber();
	PUCHAR shadow = s_clkShadow[cpu & 127];
	PUCHAR base = s_clkShadowBase[cpu & 127];
	PEPT_PTE pte = EptGetPte(EptGetActiveData(), gpa);
	if (shadow == NULL || base == NULL || pte == NULL)
	{
		return FALSE;
	}
	RtlCopyMemory(base, c->RootVA, PAGE_SIZE);
	RtlCopyMemory(shadow, base, PAGE_SIZE);
	ULONG64 real = ClkRead(c, c->CtrOff, c->CtrSize);
	ULONG64 tscOff = 0;
	__vmx_vmread(TSC_OFFSET, &tscOff);
	LONG64 comp = (LONG64)tscOff / c->Ratio;
	ULONG64 ctr = ClkClampMonotonic(&s_clkLastVirt[clkIdx],
		(real + (ULONG64)comp) & c->CtrMask, c->CtrMask);
	RtlCopyMemory(shadow + c->CtrOff, &ctr, c->CtrSize);
	s_clkFlickerPte[cpu & 127] = pte->ALL;    //MTF整体回写(含原PFN/mt)
	s_clkFlickerClk[cpu & 127] = (LONG)clkIdx;
	pte->ALL = 0;
	pte->fileds.present = 1;
	pte->fileds.write = 1;
	pte->fileds.execute = 1;
	pte->fileds.memoryType = 0;               //UC
	pte->fileds.physicalAddr
		= MmGetPhysicalAddress(shadow).QuadPart >> 12;
	EptInveptCurrent();
	s_clkFlicker[cpu & 127] = gpa;
	ULONG64 ctl = 0;
	__vmx_vmread(CPU_BASED_VM_EXEC_CONTROL, &ctl);
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, ctl | 0x08000000ULL);
	return TRUE;
}

//慢路径统一入口(v1.12a): 影子优先, plain降级。返回FALSE=两者都
//不可得(理论不可达, 调用方回落常规路径)
static BOOLEAN ClkSlowPath(PGEPT_CLK c, ULONG clkIdx, ULONG64 gpa,
	ULONG64 guestRip, ULONG64 guestRsp)
{
	ULONG cpu = KeGetCurrentProcessorNumber();
	BOOLEAN ok = ClkFlickerShadow(c, clkIdx, gpa);
	if (!ok)
	{
		ok = ClkFlicker(gpa);
	}
	if (!ok)
	{
		return FALSE;
	}
	static volatile LONG s_gCnt[128] = { 0 };
	LONG gn = InterlockedIncrement(&s_gCnt[cpu & 127]);
	if (gn == 1 || (gn & 0xFFF) == 0)
	{
		FlRingPush('g', cpu, 48, gpa, guestRip,
			s_clkFlickerClk[cpu & 127] >= 0 ? 1 : 0);   //c=1影子/0降级
	}
	__vmx_vmwrite(GUEST_RIP, guestRip);
	__vmx_vmwrite(GUEST_RSP, guestRsp);
	return TRUE;
}

BOOLEAN ClkTryEmulate(PGUEST_REGS GuestRegs, ULONG64 guestRip,
	ULONG64 guestRsp, ULONG64 gpa)
{
	PGEPT_CLK c = NULL;
	ULONG clkIdx = 0;
	for (ULONG i = 0; i < GEPT_CLK_MAX; i++)
	{
		if (s_clk[i].Armed && (gpa & ~0xFFFULL) == s_clk[i].Gpa)
		{
			c = &s_clk[i];
			clkIdx = i;
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
		//不可解码/跨页错位: 慢路径统一影子flicker(v1.12a)
		return ClkSlowPath(c, clkIdx, gpa, guestRip, guestRsp);
	}
	USHORT off = (USHORT)(gpa & 0xFFF);
	ULONG ctrLo = c->CtrOff;    //ULONG统一比较类型(USHORT+UCHAR提升为int=符号警告)
	ULONG ctrHi = (ULONG)c->CtrOff + c->CtrSize;
	BOOLEAN overlap = off < ctrHi && off + acc.size > ctrLo;
	BOOLEAN inWindow = off >= ctrLo && off + acc.size <= ctrHi;
	if (overlap && !inWindow)
	{
		//错位(与计数器窗部分重叠, 读/写皆走): 读=影子页补偿语义;
		//写=store经MTF diff写回落真页(替代旧的整写丢弃=写被吞臂)
		return ClkSlowPath(c, clkIdx, gpa, guestRip, guestRsp);
	}
	if (acc.isRead)
	{
		ULONG64 val = 0;
		BOOLEAN virt = FALSE;
		if (inWindow)
		{
			//计数器窗: 真值+TSC_OFFSET/Ratio(与guest可见TSC同轴)
			//+单调钳制(倒退向量封堵, 见ClkClampMonotonic)
			ULONG64 real = ClkRead(c, c->CtrOff, c->CtrSize);
			ULONG64 tscOff = 0;
			__vmx_vmread(TSC_OFFSET, &tscOff);
			LONG64 comp = (LONG64)tscOff / c->Ratio;
			ULONG64 ctr = ClkClampMonotonic(&s_clkLastVirt[clkIdx],
				(real + (ULONG64)comp) & c->CtrMask, c->CtrMask);
			val = ctr >> (8 * (off - c->CtrOff));
			virt = TRUE;
		}
		else
		{
			val = ClkRead(c, off, acc.size);    //其余寄存器直读真值
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
		if (inWindow)
		{
			;    //计数器窗内整写: 只读丢弃(与真硬件一致; 错位写已上行走影子)
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
	//端口flicker回捕: 重置位(串指令下一迭代exit(30)→再flicker,
	//2 exit/迭代); 无视图切换(I/O位图与EPT视图正交)
	USHORT ioPort = s_clkIoFlicker[cpu & 127];
	if (ioPort != 0)
	{
		s_clkIoFlicker[cpu & 127] = 0;
		ClkIoArmCpu(ioPort, TRUE);
		ULONG64 ctl = 0;
		__vmx_vmread(CPU_BASED_VM_EXEC_CONTROL, &ctl);
		__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, ctl & ~0x08000000ULL);
		return TRUE;
	}
	ULONG64 gpa = s_clkFlicker[cpu & 127];
	if (gpa == 0)
	{
		return FALSE;
	}
	s_clkFlicker[cpu & 127] = 0;
	//PTE整体回写(v1.12a: 影子flicker的PTE指向影子PFN——逐位清
	//P/W/X会残留影子PFN, 下次plain放行=泄漏陈旧影子; 原值整体
	//回写含原PFN/mt, plain/影子两形态统一)
	PEPT_PTE pte = EptGetPte(EptGetActiveData(), gpa);
	if (pte != NULL)
	{
		pte->ALL = s_clkFlickerPte[cpu & 127];
		EptInveptCurrent();
	}
	//写回(v1.12a影子专属): diff影子vs基线=guest本条指令的store
	//字节, 逐段ClkWrite回落真页(计数器窗除外=硬件只读忽略);
	//plain降级(s_clkFlickerClk=-1)无影子, 跳过
	LONG fk = s_clkFlickerClk[cpu & 127];
	s_clkFlickerClk[cpu & 127] = -1;
	PUCHAR shadow = s_clkShadow[cpu & 127];
	PUCHAR base = s_clkShadowBase[cpu & 127];
	if (fk >= 0 && fk < GEPT_CLK_MAX && shadow != NULL && base != NULL)
	{
		PGEPT_CLK c = &s_clk[fk];
		ULONG ctrLo = c->CtrOff;
		ULONG ctrHi = (ULONG)c->CtrOff + c->CtrSize;
		ULONG i = 0;
		while (i < PAGE_SIZE)
		{
			if (shadow[i] == base[i] || (i >= ctrLo && i < ctrHi))
			{
				i++;
				continue;
			}
			ULONG start = i;    //连续diff段(段内字节全异且均在窗外)
			while (i < PAGE_SIZE && shadow[i] != base[i]
				&& !(i >= ctrLo && i < ctrHi))
			{
				i++;
			}
			for (ULONG o = start; o < i; )   //≤8B分块MMIO写
			{
				ULONG n = i - o;
				if (n > 8)
				{
					n = 8;
				}
				ULONG64 v = 0;
				RtlCopyMemory(&v, shadow + o, n);
				ClkWrite(c, (USHORT)o, n, v);
				o += n;
			}
		}
	}
	ULONG64 ctl = 0;
	__vmx_vmread(CPU_BASED_VM_EXEC_CONTROL, &ctl);
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, ctl & ~0x08000000ULL);
	return TRUE;
}
