#!/usr/bin/env python3
# 构造合成 MEMORY.DMP 用于冒烟测试 gept_bb_parse.py / gept_bb_parse.ps1
# 模拟 v3.43 卸载0x50坠机现场: 头部0x50+EXCEPTION_RECORD64, 事件环/行环
# 物理散布(测试全局seq重组), 黑匣子NOT fired(0x2028布局). 纯机制验证,
# 非真实证据. 解析器改动后跑本脚本+解析脚本=回归测试.
# 用法: python3 make_test_dmp.py [输出路径(默认test_synth.dmp)]
import struct, random, sys

random.seed(0x50)
OUT = sys.argv[1] if len(sys.argv) > 1 else "test_synth.dmp"
SIZE = 2 * 1024 * 1024
buf = bytearray(b'\x00' * SIZE)

def put(off, data):
    buf[off:off+len(data)] = data

# ---------- 1. DMP 头部 ----------
put(0x00, b"PAGE")                      # sig
put(0x04, b"DU64")                      # version
struct.pack_into("<I", buf, 0x38, 0x50) # BugCheckCode = 0x50
struct.pack_into("<Q", buf, 0x40, 0x172CC83C1A0)  # p1 = 用户VA(被写)
struct.pack_into("<Q", buf, 0x48, 3)               # p2 = 3
struct.pack_into("<Q", buf, 0x50, 0xFFFFF802244444BE)  # p3 = nt rip
struct.pack_into("<Q", buf, 0x58, 0xF)             # p4
# EXCEPTION_RECORD64 @0xF98: code,flags(8),record(8),addr(8),n(4),pad(4),info[0..15]
EXC = 0xF98
struct.pack_into("<I", buf, EXC + 0x00, 0xC0000005)   # code = AV
struct.pack_into("<Q", buf, EXC + 0x10, 0xFFFFF802244444BE)  # addr = rip
struct.pack_into("<I", buf, EXC + 0x18, 2)            # nparams
struct.pack_into("<Q", buf, EXC + 0x20, 1)            # info[0] = 1 (WRITE)
struct.pack_into("<Q", buf, EXC + 0x28, 0x172CC83C1A0)  # info[1] = fault VA

# ---------- 1b. v6.3测试数据: DTB + 物理内存描述符 + System式PML4 ----------
# 模拟"错误CR3"现场: DTB指向用户半区全零、内核半区有映射的PML4(System进程特征)
# Run[0]={BasePage=0x1000,PageCount=0x100}: 物理P → 文件偏移 = 0x2000 + (P-0x1000000)
# PML4内容写在文件偏移0x32000 → 对应物理0x1030000 → DTB=0x1030000
struct.pack_into("<Q", buf, 0x10, 0x1030000)      # DirectoryTableBase
struct.pack_into("<I", buf, 0x34, 8)              # NumberProcessors
# PHYSICAL_MEMORY_DESCRIPTOR @0xF80: nRuns=1, nPages=0x100, Run[0]={0x1000,0x100}
struct.pack_into("<I", buf, 0xF80, 1)
struct.pack_into("<I", buf, 0xF84, 0x100)
struct.pack_into("<Q", buf, 0xF88, 0x1000)        # BasePage
struct.pack_into("<Q", buf, 0xF90, 0x100)         # PageCount
# PML4 @文件偏移0x32000(=物理0x1030000): 用户半区全零+内核半区伪值
PML4_OFF = 0x32000
for e in range(256, 512):
    if e in (256, 257, 300, 511):
        struct.pack_into("<Q", buf, PML4_OFF + e * 8, 0x00000002ABC00063)

# ---------- 2. 事件环条目 (48B: a,b,c,tsc,seq,rsn,cpu,tag,pad5) ----------
def ev(seq, tag, cpu, rsn, a=0, b=0, c=0, tsc=0):
    e = bytearray(48)
    struct.pack_into("<Q", e, 0, a)
    struct.pack_into("<Q", e, 8, b)
    struct.pack_into("<Q", e, 16, c)
    struct.pack_into("<Q", e, 24, tsc)
    struct.pack_into("<I", e, 32, seq)
    struct.pack_into("<I", e, 36, rsn)
    struct.pack_into("<H", e, 40, cpu)
    e[42] = ord(tag)
    return bytes(e)

CmVmCall_rip = 0xFFFFF80050771076
events = [
    ev(130, 'F', 4, 0, tsc=0x1000),
    ev(131, 'W', 4, 0, tsc=0x1100),
    ev(132, 'Y', 4, 0, tsc=0x1200),
    ev(133, 'Q', 4, 0, tsc=0x1300),
    ev(134, 'S', 4, 21, a=0x13D4, tsc=0x1400),   # 拆原页
    ev(135, 'S', 4, 23, a=0x27A9DA, tsc=0x1500), # 清execute
    ev(136, 'V', 4, 48, a=0x27A8B7000, b=CmVmCall_rip, c=0x82, tsc=0x1600),  # 触发violation
    ev(137, 'x', 4, 0, a=3, b=0x27A8B7000, c=0x27A9DA, tsc=0x1700),          # 切exec视图
    ev(138, 'V', 0, 48, a=0x27A8B7000, b=CmVmCall_rip, c=0x82, tsc=0x1800),  # cpu0接力
    ev(139, 'x', 0, 0, a=3, b=0x27A8B7000, c=0x27A9DA, tsc=0x1900),
]
# 卸载段: 8核V rsn=18 (假设a形态: 全部退出)
for i in range(8):
    events.append(ev(140 + i, 'V', i, 18, a=CmVmCall_rip, tsc=0x2000 + i))
# v3.45: NtClose采样事件('N': a=累计计数, b=句柄)
events.append(ev(148, 'N', 2, 0, a=1, b=0x7FF1234, tsc=0x3000))          # 首次命中
events.append(ev(149, 'N', 5, 0, a=65536, b=0xABC, tsc=0x4000))         # 65536次
events.append(ev(150, 'N', 0, 0, a=131072, b=0xDEF0, tsc=0x5000))       # 131072次
# 重复条目(模拟重叠窗口重扫, tsc更大, 测试保最大tsc去重)
events.append(ev(140, 'V', 0, 18, a=CmVmCall_rip, tsc=0x9000))

# ---------- 3. 行环条目 (500B: seq DWORD + 496B GBK文本) ----------
def line(seq, text):
    e = bytearray(500)
    struct.pack_into("<I", e, 0, seq)
    g = text.encode('gbk')[:496]
    e[4:4+len(g)] = g
    return bytes(e)

lines = [
    (110, "[HB] uptime=120s lag=0 exits r10=60 r18=4120 r48=2"),
    (640, "[STAGE1] 安装hook: 目标=FFFFF80050379000(独立页...79000) 跳板=FFFFF800503710D6(页...71000)"),
    (646, "[PHHook] 副本就绪 原页PFN=27A8B7 CodePagePFN=27A9DA 跳板长=14 页内偏移=0"),
    (647, "[PHHook] DPC广播开始"),
    (665, "[STAGE1] 触发GeptTestTarget(下一行=hook命中或死亡点)"),
    (666, "[STAGE1] GeptTestTarget hooked! EPT hook全链路OK(violation→CodePage视图→跳板→重放→归位)"),
    (838, "Unload: 开始关闭VT(串行逐核)"),
]
for i in range(5):  # cpu0-4
    lines.append((840 + i * 2, f"cpu{i}: vmcall退出VT..."))
    lines.append((841 + i * 2, f"cpu{i}: 已退出guest"))
lines += [
    (860, "cpu5: vmcall退出VT..."),
    (861, "cpu5: 已退出guest"),   # 假设a: 行环有L00860之后的内容
    (862, "cpu6: vmcall退出VT..."),
    (863, "cpu6: 已退出guest"),
    (864, "cpu7: vmcall退出VT..."),
    (865, "cpu7: 已退出guest"),
    (866, "Unload: 完成, 关闭文件日志"),
    (900, "[V] s=140 cpu=0 rsn=18 a=FFFFF80050771076"),
    (901, "[S] s=134 cpu=4 rsn=21 b=13D4"),
    (902, "[x] s=137 cpu=4 a=3 b=0000027A8B7000"),
    (903, "[N] s=148 cpu=2 rsn=0 a=1 b=7FF1234"),
    (904, "[N] s=149 cpu=5 rsn=0 a=65536 b=ABC"),
]

# ---------- 4. 黑匣子 (0x2028, NOT fired) ----------
bb = bytearray(0x2028)
bb[0:8] = b"GEPTBB01"
bb[8:8+5] = b"v3.43"
struct.pack_into("<q", bb, 0x20, 343)   # ver
struct.pack_into("<q", bb, 0x28, 0)     # fired=0 (原生蓝屏路径)
struct.pack_into("<q", bb, 0x80, 12345) # pollCnt (LIVE)
struct.pack_into("<q", bb, 0x88 + 10*8, 60)   # exit计数 r10=60
struct.pack_into("<q", bb, 0x88 + 18*8, 4120) # r18
struct.pack_into("<q", bb, 0x88 + 48*8, 2)    # r48
bb[0x2020:0x2028] = b"GEPTBB02"

# ---------- 5. 物理散布(全局seq重组的试金石) ----------
put(0x2000, b"==== GeptHooks build v3.43 | stage=1 cpu count=8 ====")  # 横幅
cur = 0x4000
random.shuffle(events)
for e in events:
    put(cur, e)
    cur += 48 + random.randint(64, 512)   # 条目间夹垃圾(模拟物理散列)
    # 夹随机垃圾
    j = random.randint(64, 512)
    put(cur, bytes(random.randint(0x41, 0x5A) for _ in range(min(j, len(buf)-cur))))
    cur += j
random.shuffle(lines)
for sq, txt in lines:
    put(cur, line(sq, txt))
    cur += 500 + random.randint(0, 256)
cur = max(cur, 1024 * 1024)
put(cur, bytes(bb))

open(OUT, "wb").write(bytes(buf))
print(f"合成DMP: {OUT} {len(buf)}字节, 事件{len(events)}条, 行{len(lines)}条, 黑匣子@0x{cur:X}")
