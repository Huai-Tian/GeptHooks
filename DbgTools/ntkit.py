#!/usr/bin/env python3
"""ntkit.py - GeptHooks DbgTools: offline ntoskrnl PE analyzer (generic).

One tool replacing a family of one-off case scripts: PE sections/exports/
.pdata function bounds, RVA -> function identification, capstone disasm
windows, direct-call/callers scan, and KeBugCheckEx call-site analysis.

The typical workflow after a BSOD: WinDbg says the fault is at
nt+RVA (e.g. 0x405B4F). Get the matching ntoskrnl.exe (SAME build as the
crashed machine - version + SizeOfImage must match the dump's module list),
then:

  # what function is nt+0x405B4F? disasm around it
  python3 ntkit.py -m ntoskrnl.exe at 0x405B4F

  # who calls the enclosing function?
  python3 ntkit.py -m ntoskrnl.exe callers 0x405B40

  # all KeBugCheckEx(0x50) raise sites, labeled by 1st argument
  python3 ntkit.py -m ntoskrnl.exe bugcheck 0x50

  # raw branch scan for anything targeting an address
  python3 ntkit.py -m ntoskrnl.exe branches 0x209D63

Notes:
  - Addresses are RVAs (offsets from ImageBase), as printed by WinDbg
    after stripping the random nt base ("nt+0x...").
  - Disassembly starts from a heuristic aligned point (scan back to CC/00
    padding); if the window looks misaligned, narrow with --start.
  - callers/branches scan .text for E8/E9 rel32 whose target == the given
    RVA; indirect calls are invisible to it.
  - bugcheck finds `mov ecx,<code>` followed by a call whose target is the
    KeBugCheckEx export; the 4th/5th args (MmAccessFault subtypes etc.)
    come from the surrounding window - read the disasm output.

Requires: python3 + capstone (pip install capstone).
"""
import argparse
import struct
import sys

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
except ImportError:
    print("error: capstone not installed  (pip install capstone)")
    sys.exit(1)


# ---------------- PE parsing ----------------

class PE:
    def __init__(self, path):
        self.data = open(path, "rb").read()
        e = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[e:e + 4] != b"PE\x00\x00":
            sys.exit("error: not a PE file")
        coff = e + 4
        (self.machine, nsec, tds, _psym, _nsym, optsz,
         _chars) = struct.unpack_from("<HHIIIHH", self.data, coff)
        opt = coff + 20
        magic = struct.unpack_from("<H", self.data, opt)[0]
        if magic != 0x20B:
            sys.exit("error: not PE32+ (x64)")
        self.imgbase = struct.unpack_from("<Q", self.data, opt + 24)[0]
        self.sizeimg = struct.unpack_from("<I", self.data, opt + 56)[0]
        self.timestamp = tds
        # sections
        self.secs = []
        so = opt + optsz
        for _ in range(nsec):
            name = self.data[so:so + 8].rstrip(b"\x00").decode(
                "ascii", "replace")
            vsz, va, rsz, ro = struct.unpack_from("<IIII", self.data, so + 8)
            self.secs.append((name, va, vsz, ro, rsz))
            so += 40
        # exports: name -> rva
        self.exports = {}
        try:
            expdir = struct.unpack_from("<II", self.data, opt + 112)
            if expdir[0]:
                base = self.rva2off(expdir[0])[0]
                (nnames,) = struct.unpack_from("<I", self.data, base + 24)
                names_off = self.rva2off(
                    struct.unpack_from("<I", self.data, base + 32)[0])[0]
                funcs_rva = struct.unpack_from("<I", self.data, base + 28)[0]
                ords_off = self.rva2off(
                    struct.unpack_from("<I", self.data, base + 36)[0])[0]
                for i in range(nnames):
                    nrva = struct.unpack_from(
                        "<I", self.data, names_off + i * 4)[0]
                    noff = self.rva2off(nrva)[0]
                    # find the terminator without slicing the whole tail
                    # (data[noff:].split() copies ~5MB per export -> minutes)
                    nend = self.data.find(b"\x00", noff, noff + 64)
                    if nend < 0:
                        nend = noff + 32
                    name = self.data[noff:nend].decode("ascii", "replace")
                    (ordn,) = struct.unpack_from(
                        "<H", self.data, ords_off + i * 2)
                    frva = struct.unpack_from(
                        "<I", self.data,
                        self.rva2off(funcs_rva)[0] + ordn * 4)[0]
                    self.exports[name] = frva
        except Exception:
            pass
        # .pdata function bounds: sorted list of (begin, end)
        self.pdata = []
        for (name, va, vsz, ro, rsz) in self.secs:
            if name == ".pdata":
                for o in range(ro, ro + rsz, 12):
                    b, e_, _u = struct.unpack_from("<II I", self.data, o)
                    if b and e_ > b:
                        self.pdata.append((b, e_))
                self.pdata.sort()
                break

    def rva2off(self, rva):
        for (name, va, vsz, ro, rsz) in self.secs:
            if va <= rva < va + max(vsz, rsz):
                off = rva - va + ro
                if off < ro + rsz:
                    return off, name
        return None, None

    def off2rva(self, off):
        for (name, va, vsz, ro, rsz) in self.secs:
            if ro <= off < ro + rsz:
                return off - ro + va, name
        return None, None

    def func_of(self, rva):
        """(begin, end) of the .pdata chunk containing rva, else None"""
        lo, hi = 0, len(self.pdata)
        while lo < hi:
            mid = (lo + hi) // 2
            if self.pdata[mid][0] <= rva:
                lo = mid + 1
            else:
                hi = mid
        if lo and self.pdata[lo - 1][0] <= rva < self.pdata[lo - 1][1]:
            return self.pdata[lo - 1]
        return None

    def nearest_exports(self, rva, k=3):
        """k exports with the largest RVA <= given"""
        pre = sorted(((v, n) for n, v in self.exports.items() if v <= rva),
                     reverse=True)[:k]
        return pre


# ---------------- disasm ----------------

def sweep_start(pe, target_off):
    """walk back to CC/00 padding for an instruction-aligned sweep"""
    o = target_off
    floor = max(target_off - 0x2000, 0)
    while o > floor:
        if pe.data[o - 1] == 0xCC and pe.data[o - 2] == 0xCC:
            return o
        if pe.data[o - 1] == 0x00 and pe.data[o - 2] == 0x00 \
                and pe.data[o - 3] == 0x00:
            return o
        o -= 1
    return target_off - 0x80


def disasm_window(pe, center_rva, before=0x100, after=0x60,
                  mark="<<<<<<"):
    off, sec = pe.rva2off(center_rva)
    if off is None:
        print("RVA 0x%X not mapped in any section" % center_rva)
        return
    sw = sweep_start(pe, max(off - before, 0))
    sw_rva = pe.off2rva(sw)[0]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    seen = False
    for ins in md.disasm(pe.data[sw:sw + (center_rva - sw_rva) + after],
                         sw_rva):
        tag = ""
        if ins.address == center_rva:
            tag = "   %s" % mark
            seen = True
        ann = ""
        if ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
            tgt = int(ins.op_str, 16)
            for (v, n) in pe.nearest_exports(tgt, 1):
                if v == tgt:
                    ann = "   ; %s" % n
        print("  0x%X: %-26s %s %s%s"
              % (ins.address, ins.bytes.hex()[:24], ins.mnemonic,
                 ins.op_str, tag + ann))
        if seen and ins.address > center_rva:
            break


# ---------------- commands ----------------

def cmd_info(pe, _args):
    print("machine=0x%X  TimeDateStamp=0x%X  ImageBase=0x%X  "
          "SizeOfImage=0x%X  exports=%d  pdata-chunks=%d"
          % (pe.machine, pe.timestamp, pe.imgbase, pe.sizeimg,
             len(pe.exports), len(pe.pdata)))
    print("sections:")
    for (name, va, vsz, ro, rsz) in pe.secs:
        print("  %-10s VA=0x%08X VSZ=0x%08X RAW=0x%08X RSZ=0x%08X"
              % (name, va, vsz, ro, rsz))


def cmd_at(pe, args):
    rva = parse_rva(args.rva)
    off, sec = pe.rva2off(rva)
    print("RVA 0x%X -> file offset 0x%X (section %s)" % (rva, off or 0, sec))
    f = pe.func_of(rva)
    if f:
        print("function bounds (from .pdata): [0x%X, 0x%X) size=0x%X "
              "RVA+0x%X inside"
              % (f[0], f[1], f[1] - f[0], rva - f[0]))
        for (v, n) in pe.nearest_exports(f[0], 3):
            hit = " == entry" if v == f[0] else \
                  " (entry -0x%X)" % (f[0] - v)
            print("  nearest export: %s @0x%X%s" % (n, v, hit))
    else:
        print("no .pdata chunk covers this RVA")
    print("disasm window:")
    disasm_window(pe, rva)


def _scan_branches(pe, target_rva, opcodes=(0xE8, 0xE9)):
    """yield (src_rva, op) for every E8/E9 rel32 in exec sections whose
    target == target_rva. Fast: bytes.find jumps + arithmetic RVA (no
    per-byte off2rva calls)."""
    for (name, va, vsz, ro, rsz) in pe.secs:
        if name not in (".text", "PAGE", "PAGEDATA", "PAGELK", "PAGEVRFY"):
            continue
        blob = pe.data
        for op in opcodes:
            pos = ro
            needle = bytes([op])
            end = ro + rsz - 5
            while True:
                o = blob.find(needle, pos, end)
                if o < 0:
                    break
                pos = o + 1
                rel = struct.unpack_from("<i", blob, o + 1)[0]
                src_rva = o - ro + va
                if src_rva + 5 + rel == target_rva:
                    yield src_rva, op


def cmd_callers(pe, args):
    tgt = parse_rva(args.rva)
    hits = 0
    for (src_rva, op) in _scan_branches(pe, tgt):
        kind = "call" if op == 0xE8 else "jmp"
        f = pe.func_of(src_rva)
        where = ("in [0x%X,0x%X)" % f) if f else "(no pdata)"
        exp = ""
        if f:
            for (v, n) in pe.nearest_exports(f[0], 1):
                if v == f[0]:
                    exp = " = %s" % n
        print("0x%X: %s -> 0x%X  %s%s" % (src_rva, kind, tgt, where, exp))
        hits += 1
    print("%d direct branch(es) target 0x%X "
          "(indirect calls are not visible to this scan)" % (hits, tgt))


def cmd_bugcheck(pe, args):
    code = parse_rva(args.code)
    ke = pe.exports.get("KeBugCheckEx")
    if not ke:
        sys.exit("KeBugCheckEx export not found")
    print("KeBugCheckEx @0x%X; scanning for `mov ecx,<code>` (B9 xx xx xx xx)"
          " near direct branches to it..." % ke)
    # KeBugCheckEx is noreturn: compilers emit jmp (E9) from raise sites
    # and call (E8) from generic wrappers - scan both.
    sites = 0
    for (src_rva, op) in _scan_branches(pe, ke):
        off = pe.rva2off(src_rva)[0]
        # look back up to 0x20 bytes for `mov ecx, imm32` == code
        found = False
        for back in range(5, 0x25):
            p = off - back
            if p < 0 or pe.data[p] != 0xB9:
                continue
            imm = struct.unpack_from("<I", pe.data, p + 1)[0]
            if imm == code:
                site = src_rva - back
                print("\n=== KeBugCheckEx(0x%X) site @0x%X ===" % (code, site))
                disasm_window(pe, site, before=0x40, after=0x14,
                              mark="<<<<< raise")
                sites += 1
                found = True
            break
        if not found:
            print("  (branch @0x%X to KeBugCheckEx: no immediate mov ecx,"
                  " code likely in a register - inspect manually)"
                  % src_rva)
    print("\n%d raise site(s) for code 0x%X. Each disasm shows how the"
          " subtype args are built (for 0x50 the 5th arg is the"
          " MmAccessFault condition code)." % (sites, code))


def cmd_branches(pe, args):
    tgt = parse_rva(args.rva)
    hits = 0
    for (src_rva, op) in _scan_branches(pe, tgt):
        print("0x%X: %02X rel32 -> 0x%X" % (src_rva, op, tgt))
        hits += 1
    print("%d raw branch(es) target 0x%X" % (hits, tgt))


def parse_rva(s):
    s = s.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s, 16) if any(c in "abcdefABCDEF" for c in s) else int(s)


def main():
    ap = argparse.ArgumentParser(
        description="offline ntoskrnl (or any x64 PE) analyzer")
    ap.add_argument("-m", "--module", required=True,
                    help="path to the PE (must match the crashed build)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("info", help="sections/exports/pdata summary")
    p = sub.add_parser("at", help="identify function at RVA + disasm window")
    p.add_argument("rva")
    p = sub.add_parser("callers", help="find direct callers of RVA")
    p.add_argument("rva")
    p = sub.add_parser("bugcheck",
                       help="find KeBugCheckEx(<code>) raise sites")
    p.add_argument("code", help="bugcheck code, e.g. 0x50")
    p = sub.add_parser("branches", help="raw E8/E9 scan targeting RVA")
    p.add_argument("rva")
    args = ap.parse_args()
    pe = PE(args.module)
    {"info": cmd_info, "at": cmd_at, "callers": cmd_callers,
     "bugcheck": cmd_bugcheck, "branches": cmd_branches}[args.cmd](pe, args)


if __name__ == "__main__":
    main()
