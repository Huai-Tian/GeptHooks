#!/usr/bin/env python3
"""GeptHooks 蓝屏黑匣子解析器 v7 (沙箱/Linux版; Windows实机用gept_bb_parse.ps1)。

用法: python3 gept_bb_parse.py <MEMORY.DMP路径> [--all]

原理: 驱动含GEPT_BLACKBOX全局结构(魔数"GEPTBB01"开头, 尾标"GEPTBB02")。
冻结时看门狗线程(行环30s不动=级联冻结)快照事件环尾48条+日志行尾20条+
全部exit计数并KeBugCheckEx(0xDEADC0DE), 黑匣子随MEMORY.DMP落盘。
本脚本在DMP里按魔数扫描并解码。

v7: tag表与common.h环事件tag注释全量对齐(新增q/j/y/a/l/g/z时钟域族+
K私有CR3新语义; 退役tag保留判读旧DMP)。**修改环tag语义时必须同步
common.h与本表**——解析器按tag含义翻译事件, 失步=判读误导。

结构布局(与common.h GEPT_BLACKBOX逐字节一致, 自然对齐无pack):
  +0x000  CHAR    magic[8]        "GEPTBB01"
  +0x008  CHAR    build[24]       构建标签
  +0x020  ULONG64 bbVer           布局版本(=1)
  +0x028  ULONG64 fireTsc         触发时刻rdtsc
  +0x030  ULONG64 fireIntrTime    触发时刻中断时钟(100ns单位)
  +0x038  ULONG64 wdArmed         武装时刻(0=未武装)
  +0x040  ULONG64 lineHead        行环写游标(冻结时最后行号-1)
  +0x048  ULONG64 ringHead        事件环写游标
  +0x050  ULONG64 t1Seq           T1已写行游标
  +0x058  ULONG64 t2Seq           T2已镜像行游标
  +0x060  ULONG64 writeGuard      写盘护卫状态
  +0x068  ULONG64 launchHot       热轮询状态
  +0x070  ULONG64 vcpuCpu         虚拟化目标核
  +0x078  ULONG64 pendCount       目标核积压中断数
  +0x080  ULONG64 pollCnt         看门狗DPC轮询数(活体证明)
  +0x088  ULONG64 exitCounts[82]  全部exit精确计数(v1.10d扩至81)
  +0x320  RING[48]                事件环尾48条, 每条48字节:
             +0 a(rip/gpa) +8 b(qual) +16 c +24 tsc
             +32 seq +36 reason +40 cpu(H) +42 tag(C) +44 pad(H)
  +0xC20  CHAR lines[20][256]     行环尾20条(seq失配=半写=空串)
  +0x2020 CHAR magic2[8]          "GEPTBB02"
  sizeof = 0x2028 (8232字节)
"""
import struct
import sys

MAGIC = b"GEPTBB01"
MAGIC2 = b"GEPTBB02"
BB_SIZE = 0x2028
RING_OFF = 0x320
LINES_OFF = 0xC20
RING_STRIDE = 48
LINES_STRIDE = 256

TAG_MEANING = {
    #—— 现役tag(与common.h环事件tag注释同步; 修改tag语义须同步此表) ——
    b'E': "VM-exit采样", b'V': "EPT violation(rsn48)或卸载vmcall(rsn18)",
    b'H': "EPT自我隐蔽完成(a=零页PFN, b=拆分pte页数)",
    b'S': "DPC布防阶段(21拆原页/22拆Code页/23清execute)",
    b'R': "vmresume失败", b'W': "落地探针",
    b'C': "EPT misconfig(rsn49)", b'T': "三重故障",
    b'G': "VM-entry失败33", b'D': "同(reason,rip)环路",
    b'X': "violation/misconfig风暴逃生", b'A': "动态建表失败",
    b'P': "低地址环路", b'Z': "len0未知exit", b'U': "len>0未知exit",
    b'F': "热轮询开启", b'f': "热轮询关闭",
    b'Q': "guest回到VMXInitCpuStart续跑",
    b'I': "外部中断到达(a=vector, b=intrInfo)",
    b'i': "中断交付给guest(a=vector, rsn=1直注/7开窗)",
    b'K': "私有CR3树protect(vmcall13: a=VA, b=len, c=1成功/0降级)",
    b'v': "IPI卸载留痕(a=曾in-guest, b=bVmxOn终值应0)",
    b'r': "卸载CR3取证(a=GUEST_CR3, b=回读, c=HOST_CR3快照, a==b=正常)",
    b'M': "MTF读透明布防(rsn48: a=gpa, b=rip; 布防形态'S'rsn=25)",
    b'm': "vmcall(7)还原字节(a=dst, b=src, c=len)",
    b'b': "MSR位图root直写(vmcall8: a=MSR, b=操作, c=核掩码)",
    b'O': "自我隐蔽异常(rsn0=拆分登记溢出a=idx / rsn48=隐蔽页被guest访问兜底放开a=gpa b=PTE帧)",
    b'c': "CodePage隐蔽/恢复(rsn12: a=GPA, b=hide, c=结果) / CR访问exit28留痕(采样, b=exitQual, c=源GPR值)",
    b't': "卸载时TSC_OFFSET终值(a=offset, 负)",
    b'u': "VMCALL签名门拒绝(rsn18, b=试探功能码) / VMFUNC兜底#UD(rsn59)——按rsn分",
    b'y': "时钟仿真命中(rsn48: a=gpa b=rip c=虚拟值 / rsn30: a=端口 b=值)",
    b'a': "时钟布防(rsn11: a=HPET页 b=PM_TMR页 / rsn13: a=端口 b=1置/0清)",
    b'l': "时钟校准完成(a=Ratio, b=计数器GPA)",
    b'g': "时钟慢路径flicker(rsn48: a=gpa b=rip c=1影子补偿/0真值降级 / rsn30: a=端口)",
    b'z': "卸载驻留量化(a=总exit, b=K均值, c=累计驻留cycles)",
    b'j': "TSC校准完成(a=K, b=rdtsc对开销, c=vmcall往返均值)",
    b'q': "REP串root仿真命中(rsn48: a=rip, b=剩余元素数)",
    b'w': "回调异常(线程迁移s_currentHook空臂)",
    b'B': "VMX族#UD/#GP注入采样(rsn=exit reason)",
    b'e': "invept VMfail留痕(a=EPT_VPID_CAP)",
    b'x': "fallback核视图切换(a=1读/2写/3执行, b=gpa, c=Code页PFN)",
    #—— 历史tag(发射代码已退役; 保留判读旧版本二进制的DMP) ——
    b'L': "[退役]压测循环进度(a=rbx剩余)", b'Y': "[退役]压测循环完成",
    b'N': "[退役]NtClose hook采样(a=累计次数, b=句柄)",
    b'k': "[退役]K路径EOI",
    b'n': "EptSetHook中止", b'h': "非guest核跳过vmcall",
}


def parse_bb(buf, file_offset):
    """buf=从黑匣子首字节开始的BB_SIZE缓冲; file_offset=其在DMP中的偏移"""
    off = 0
    bb = {}
    bb["file_offset"] = file_offset
    bb["build"] = buf[off + 8: off + 32].split(b"\0")[0].decode("ascii", "replace")
    (bb["bbVer"], bb["fireTsc"], bb["fireIntrTime"], bb["wdArmed"],
     bb["lineHead"], bb["ringHead"], bb["t1Seq"], bb["t2Seq"],
     bb["writeGuard"], bb["launchHot"], bb["vcpuCpu"], bb["pendCount"],
     bb["pollCnt"]) = struct.unpack_from("<13Q", buf, off + 0x20)
    bb["exitCounts"] = struct.unpack_from("<82Q", buf, off + 0x88)
    # 事件环尾48条
    bb["ring"] = []
    for i in range(48):
        o = off + RING_OFF + i * RING_STRIDE
        a, b, c, tsc, seq, reason = struct.unpack_from("<4QIH", buf, o)
        cpu, tag = struct.unpack_from("<Hc", buf, o + 40)
        bb["ring"].append({
            "idx": i, "seq": seq, "tag": tag, "cpu": cpu,
            "reason": reason, "a": a, "b": b, "c": c, "tsc": tsc,
        })
    # 行环尾20条
    bb["lines"] = []
    for i in range(20):
        o = off + LINES_OFF + i * LINES_STRIDE
        bb["lines"].append(buf[o: o + LINES_STRIDE].split(b"\0")[0]
                           .decode("utf-8", "replace"))
    return bb


def fmt_q(v):
    return "0x%X" % v if v > 9 else str(v)


def dump_bb(bb):
    print("=" * 78)
    print("黑匣子 @DMP文件偏移 0x%X  构建=%s  布局版本=%d"
          % (bb["file_offset"], bb["build"], bb["bbVer"]))
    print("-" * 78)
    tsc_s = bb["fireIntrTime"] / 1e7
    print("触发: 中断时钟=%.3fs后启动(相对) rdtsc=0x%X pollCnt=%d(看门狗活体)"
          % (tsc_s, bb["fireTsc"], bb["pollCnt"]))
    print("武装时刻=%.3fs  行环lineHead=%d  事件环ringHead=%d"
          % (bb["wdArmed"] / 1e7, bb["lineHead"], bb["ringHead"]))
    print("T1已写=%d行 T2已镜像=%d行  护卫=%d 热轮询=%d"
          % (bb["t1Seq"], bb["t2Seq"], bb["writeGuard"], bb["launchHot"]))
    print("虚拟化目标核=%s  积压中断=%s"
          % (fmt_q(bb["vcpuCpu"]), fmt_q(bb["pendCount"])))
    nz = {r: c for r, c in enumerate(bb["exitCounts"]) if c}
    if nz:
        print("exit精确计数: " + "  ".join(
            "r%d=%d" % (r, c) for r, c in sorted(nz.items())))
    else:
        print("exit精确计数: 全零(vmlaunch后零exit——冻结在guest内或环未及)")
    print("-" * 78)
    print(">>> 事件环尾48条(冻结前最后48个事件; seq失配=撕裂条目, 跳过判读):")
    for e in bb["ring"]:
        if e["seq"] == 0 and e["tag"] in (b"\0",):
            continue  # 从未写的空槽
        tag = e["tag"].decode("ascii", "replace")
        meaning = TAG_MEANING.get(e["tag"], "未知标记")
        print("  [%s] seq=%-6d cpu=%-2d rsn=%-3d a=%s b=%s %s"
              % (tag, e["seq"], e["cpu"], e["reason"],
                 fmt_q(e["a"]), fmt_q(e["b"]), meaning))
    print("-" * 78)
    print(">>> 行环尾20条(冻结前最后20行日志):")
    for i, ln in enumerate(bb["lines"]):
        if ln:
            print("  L%06d? %s" % (bb["lineHead"] - 20 + i, ln))
    print("=" * 78)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    path = sys.argv[1]
    show_all = "--all" in sys.argv[2:]
    chunk = 8 << 20
    overlap = BB_SIZE
    found = []
    with open(path, "rb") as f:
        data_base = 0          # 绝对偏移: 本轮data[0]在文件中的位置
        tail = b""
        while True:
            buf = f.read(chunk)
            if not buf:
                break
            data = tail + buf
            start = 0
            while True:
                i = data.find(MAGIC, start)
                if i < 0:
                    break
                # 尾标校验(完整性): 排除日志文本里碰巧出现的魔数
                if len(data) >= i + BB_SIZE and \
                        data[i + 0x2020: i + 0x2028] == MAGIC2:
                    found.append(data_base + i)
                start = i + 1
            tail = data[-overlap:]
            data_base += len(data) - overlap
    if not found:
        print("未找到黑匣子(魔数GEPTBB01+尾标GEPTBB02)。")
        print("可能原因: ①冻结但看门狗两路DPC也被饿死(极端级联) "
              "②DMP未含内核内存 ③跑的不是v3.33+二进制")
        sys.exit(2)
    print("找到 %d 个黑匣子实例%s\n" % (len(found),
          "" if show_all else " (默认只解析第一个, --all看全部)"))
    with open(path, "rb") as f:
        for off in (found if show_all else found[:1]):
            f.seek(off)
            buf = f.read(BB_SIZE)
            dump_bb(parse_bb(buf, off))


if __name__ == "__main__":
    main()
