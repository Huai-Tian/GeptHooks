#!/usr/bin/env powershell
# GeptHooks DMP deep parser v7.0 (PowerShell, ASCII-only, zero deps)
# v7.0 over v6.4 (blackbox alignment fix + tag table sync):
#   - [A] blackbox layout 0x1F90 -> 0x2028 and tail-magic offset
#     0x1F88 -> 0x2020 (exitCounts[82] since v1.10d). The stale layout made
#     the GEPTBB02 tail check fail on EVERY current-binary DMP, reporting
#     "[A] blackbox NOT FOUND" while the ring sections kept working.
#   - [A] exitCounts dump extended 64 -> 82 reasons.
#   - Get-TagMeaning synced with common.h ring-tag comments: new clock-domain
#     family (y/a/l/g/z), TSC calib (j), REP emu (q), private-CR3 protect
#     (K, new meaning), fallback view switch (x); retired tags (L/Y/N/k)
#     kept and marked for old-DMP readability.
#   - rule: whenever a ring tag is added/retired in common.h, update this
#     table (and gept_bb_parse.py) in the same change.
# v6.4: header/report banner version bump only.
# v6.3 over v6.2:
#   - [V] section: reads bugcheck-time CR3 (DTB@0x10) + PHYSICAL_MEMORY_
#     DESCRIPTOR runs (0xF80) -> locates the PML4 page -> checks the USER
#     half (entries 0..255). ALL ZERO = the crashing CPU ran with the System
#     process page tables = confirms the v3.44 wrong-CR3 root cause
#     (vmx_off left CR3 = HOST_CR3 snapshot from vmlaunch time).
#   - header hexdump 0xF60-0x1100 (structure identification).
#   - [C] prints ALL events sorted by seq (v6.2 printed only the last 100,
#     which on garbage-dominated recoveries hid all real low-seq entries).
# v6.2 fixes over v6.1 (all found by synthetic-DMP smoke test on pwsh):
#   1. GetH: [int][char]$x.ToString("X2") -> member access binds tighter than
#      casts, Char has no ToString(String) -> "overload not found" error and
#      EMPTY a/b/c/tsc hex fields. Fixed with the -f format operator.
#   2. [D+] info line: -eq 0xC0000005 never matched (PS parses that hex
#      literal as NEGATIVE Int32 -1073741819). Fixed with decimal 3221225477.
#   3. [A] blackbox header: -f with commas inside AppendLine(...) split into
#      3 method arguments -> format error, header line lost. Fixed with parens.
#
# WHY v6: v5.1 recovered the event ring by walking CONTIGUOUS file offsets -
# but MEMORY.DMP stores memory in PHYSICAL order, while the rings are
# VIRTUALLY contiguous and PHYSICALLY scattered (48KB ring = 12 pages).
# v5.1's walk broke at seq 142 (a page boundary jump in the file), losing
# the death-time events (seq 143+). Same reason [B] line-ring failed.
#
# v6 GLOBAL SEQ ASSEMBLY (physical scattering immune):
#   - event entries end with tag(1)+pad(5 zero bytes) - scan the WHOLE file
#     for "tag + 5 NULs" (33 tags), validate seq/reason/cpu fields at fixed
#     offsets BEFORE the tag, collect ALL entries, reassemble by seq
#   - line entries: scan for 25 known ASCII line prefixes ("cpu0: ", "[HB",
#     "[V] s=", "Unload: ", ...), seq DWORD at -4, collect + reassemble
#   - reads bugcheck header + EXCEPTION_RECORD64 at 0xF98 (read/write + VA)
#   - blackbox GEPTBB01/02 section kept
# Usage (admin PowerShell):
#   powershell -ExecutionPolicy Bypass -File gept_bb_parse.ps1
#     -Dmp "C:\Windows\MEMORY.DMP" -Out "C:\Users\User\Desktop\gept_bb.txt"
# NOTE: keep this file pure ASCII (PS5.1 misreads BOM-less UTF-8).
param(
    [string]$Dmp = "C:\Windows\MEMORY.DMP",
    [string]$Out = "$env:USERPROFILE\Desktop\gept_bb.txt"
)

$MAGIC1 = "GEPTBB01"
$MAGIC2 = "GEPTBB02"
#v7 FIX: blackbox layout is 0x2028 (exitCounts[82] since v1.10d); old 0x1F90
#made the GEPTBB02 tail check read at 0x1F88 -> always failed -> "[A] NOT FOUND"
#on every current-binary DMP. Ring reassembly (v6 global seq) was unaffected.
$BB_SIZE  = 0x2028
$BB_TAIL  = 0x2020
$BANNER   = "==== GeptHooks build"

function Get-TagMeaning([string]$t) {
    switch -CaseSensitive ($t) {
        # ---- active tags (kept in sync with common.h ring-tag comments) ----
        'E' { "VM-exit sample" }
        'V' { "EPT violation (rsn48) OR unload-vmcall (rsn18); a=gpa/rip" }
        'H' { "EPT self-conceal done (a=zeroPFN, b=split-pte count)" }
        'S' { "EptSetHook step (21 split-orig / 22 split-code / 23 exec-cleared)" }
        'R' { "vmresume fail" }
        'W' { "landing probe" }
        'C' { "EPT misconfig (rsn49)" }
        'T' { "triple fault" }
        'G' { "entry fail 33" }
        'D' { "same (reason,rip) loop" }
        'X' { "storm escape" }
        'A' { "map alloc fail" }
        'P' { "low-addr loop" }
        'Z' { "len0 unknown exit" }
        'U' { "len>0 unknown exit" }
        'F' { "hot-poll armed" }
        'f' { "hot-poll cleared" }
        'Q' { "guest back in VMXInitCpuStart" }
        'I' { "intr arrived (a=vector)" }
        'i' { "intr delivered (a=vector)" }
        'K' { "private-CR3 protect vmcall13 (a=VA, b=len, c=1 ok/0 fallback)" }
        'v' { "IPI unload per-cpu (a=was-in-guest b=bVmxOn end)" }
        'r' { "unload CR3 forensics (a=GUEST_CR3 b=readback c=HOST_CR3 snap, a==b ok)" }
        'M' { "MTF read-transparency arm (a=gpa b=rip; armed as 'S'rsn=25)" }
        'm' { "vmcall(7) byte restore (a=dst b=src c=len)" }
        'b' { "MSR bitmap root-write vmcall8 (a=MSR b=op c=cpu mask)" }
        'O' { "self-conceal anomaly (rsn0 split overflow a=idx / rsn48 hidden-page guest access a=gpa b=PTE frame)" }
        'c' { "CodePage hide/restore vmcall12 (rsn12: a=GPA b=hide c=ok) / CR access 28 sample (b=exitQual c=src GPR)" }
        't' { "final TSC_OFFSET at unload (a=offset, negative)" }
        'u' { "VMCALL-sig reject rsn18 (b=attempted opcode) OR VMFUNC #UD rsn59" }
        'y' { "clock emu hit (rsn48: a=gpa b=rip c=virt val / rsn30: a=port b=val)" }
        'a' { "clock arm (rsn11: a=HPET b=PM_TMR / rsn13: a=port b=1 set/0 clear)" }
        'l' { "clock calib done (a=Ratio b=ctr GPA)" }
        'g' { "clock slow-path flicker (rsn48: c=1 shadow/0 plain / rsn30: a=port)" }
        'z' { "unload dwell quant (a=total exits b=K avg c=accrued cycles)" }
        'j' { "TSC calib done (a=K)" }
        'q' { "REP-string root emu hit (rsn48: a=rip b=elements left)" }
        'w' { "callback thread migrated (s_currentHook NULL arm)" }
        'B' { "VMX-family #UD/#GP injection sample (rsn=exit reason)" }
        'e' { "invept VMfail trace (a=EPT_VPID_CAP)" }
        'x' { "fallback-core view switch (a=1 read/2 write/3 exec, b=gpa, c=CodePage PFN)" }
        'n' { "EptSetHook ABORT" }
        'h' { "vmcall skipped on non-guest cpu" }
        # ---- retired tags (emission code removed; kept for old DMPs) ----
        'L' { "[retired] stress loop left(a=rbx)" }
        'Y' { "[retired] stress loop done" }
        'N' { "[retired] NtClose hook sample (a=count b=handle)" }
        'k' { "[retired] K-path EOI" }
        default { "unknown tag" }
    }
}

if (-not (Test-Path $Dmp)) {
    Write-Host "ERROR: not found $Dmp"; exit 1
}
$dmpLen = (Get-Item $Dmp).Length
Write-Host "Scanning $Dmp ($([math]::Round($dmpLen/1MB,1)) MB)..."

$enc = [System.Text.Encoding]::GetEncoding(28591)   # latin-1: byte<->char 1:1
$gk  = [System.Text.Encoding]::GetEncoding(936)      # GBK for driver log text

$sb = New-Object System.Text.StringBuilder
function FlushOut { [System.IO.File]::WriteAllText($Out, $sb.ToString(), [System.Text.Encoding]::UTF8) }

# little-endian readers on latin-1 chunk string (char code == byte value)
# v6.1 FIX: GetQ used [long] arithmetic - kernel VAs (0xFFFFF800... ~1.84e19)
# EXCEED Int64.MaxValue (9.22e18) -> PS5.1 threw InvalidCastIConvertible on
# every real event. All 64-bit fields now read as 16-char HEX STRINGS
# (no arithmetic, no overflow, ordinal compare preserves unsigned order).
function GetD([string]$s, [int]$i) {
    return [int][char]$s[$i] -bor (([int][char]$s[$i+1] -shl 8) -bor (([int][char]$s[$i+2] -shl 16) -bor ([int][char]$s[$i+3] -shl 24)))
}
function GetW([string]$s, [int]$i) {
    return [int][char]$s[$i] -bor ([int][char]$s[$i+1] -shl 8)
}
function GetH([string]$s, [int]$i) {
    $hx = ""
    # v6.2 FIX: [int][char]$x.ToString("X2") parses as [int]([char]($x.ToString("X2")))
    # - member access binds TIGHTER than casts, and Char has NO ToString(String)
    # overload -> "Cannot find overload for ToString, argument count 1" on every
    # call (statement-terminating, script continued with EMPTY hex fields).
    # Use the -f format operator instead (PS5.1-safe, no method resolution).
    for ($k = 7; $k -ge 0; $k--) { $hx += ("{0:X2}" -f [int][char]$s[$i + $k]) }
    return $hx
}

# ---------- D. dump header: bugcheck + exception record ----------
$hdr = $null; $exc = $null; $hdrBuf = $null
try {
    $fs0 = [System.IO.File]::OpenRead($Dmp)
    try {
        $hb = New-Object byte[] 0x1100
        $got = $fs0.Read($hb, 0, 0x1100)
        $hdrBuf = $hb
        if ($got -ge 0x60) {
            $hdr = @{
                sig = $enc.GetString($hb, 0, 4); vd = $enc.GetString($hb, 4, 4)
                bc  = [BitConverter]::ToUInt32($hb, 0x38)
                p1  = [BitConverter]::ToUInt64($hb, 0x40)
                p2  = [BitConverter]::ToUInt64($hb, 0x48)
                p3  = [BitConverter]::ToUInt64($hb, 0x50)
                p4  = [BitConverter]::ToUInt64($hb, 0x58)
                dtb = [BitConverter]::ToUInt64($hb, 0x10)
                ncpu= [BitConverter]::ToUInt32($hb, 0x34)
            }
        }
        if ($got -ge 0x1098) {
            # EXCEPTION_RECORD64 at 0xF98: code(4) flags(4) record(8) addr(8) n(4) pad(4) info[15](120)
            $eCode = [BitConverter]::ToUInt32($hb, 0xF98)
            $eAddr = [BitConverter]::ToUInt64($hb, 0xF98 + 0x10)
            $eN    = [BitConverter]::ToUInt32($hb, 0xF98 + 0x18)
            if ($eCode -ne 0 -and $eN -le 15) {
                $info0 = [BitConverter]::ToUInt64($hb, 0xF98 + 0x20)
                $info1 = [BitConverter]::ToUInt64($hb, 0xF98 + 0x28)
                $exc = @{ code = $eCode; addr = $eAddr; n = $eN; i0 = $info0; i1 = $info1 }
            }
        }
    } finally { $fs0.Close() }
} catch { }

[void]$sb.AppendLine("=== GeptHooks DMP deep report v6.4 (v3.45) ===")
[void]$sb.AppendLine(("DMP: {0} ({1} MB)" -f $Dmp, [math]::Round($dmpLen/1MB,0)))
if ($hdr) {
    [void]$sb.AppendLine(("[D] header sig={0}{1} bugcheck 0x{2:X8}" -f $hdr.sig, $hdr.vd, $hdr.bc))
    [void]$sb.AppendLine(("    p1=0x{0:X16} p2=0x{1:X16}" -f $hdr.p1, $hdr.p2))
    [void]$sb.AppendLine(("    p3=0x{0:X16} (rip) p4=0x{1:X16}" -f $hdr.p3, $hdr.p4))
    if ($hdr.bc -eq 0x50) {
        [void]$sb.AppendLine("    -> PAGE_FAULT_IN_NONPAGED_AREA: p1=memory referenced (user VA!), p3=faulting rip")
    }
}
if ($exc) {
    [void]$sb.AppendLine(("[D+] EXCEPTION_RECORD64 @0xF98: code=0x{0:X8} addr=0x{1:X16} nparams={2}" -f `
        $exc.code, $exc.addr, $exc.n))
    # v6.2 FIX: compare as DECIMAL - PowerShell parses the hex literal 0xC0000005
    # as a NEGATIVE Int32 (-1073741819), so a UInt32 code can never equal it and
    # the info[0]/info[1] line silently never printed in v6/v6.1.
    if ($exc.code -eq 3221225477) {
        [void]$sb.AppendLine(("    info[0]={0} (0=read 1=write) info[1]=0x{1:X16} (fault VA)" -f $exc.i0, $exc.i1))
    }
}

# ---------- V. v6.3: bugcheck-time CR3 (DTB) verification ----------
# THEORY (v3.44 fix): vmx_off left CR3 = HOST_CR3 (System process DTB captured
# at vmlaunch). If the 0x50/0xF crash thread ran with the WRONG CR3, the
# bugcheck-time DTB (header+0x10) belongs to the System process, whose PML4
# USER half (entries 0..255) is ALL ZERO (System has no user address space).
# A healthy user-process DTB would have many nonzero user-half entries.
# We locate the PML4 physical page via the PHYSICAL_MEMORY_DESCRIPTOR runs
# (header+0xF80) and inspect the user half.
if ($hdr -and $hdrBuf) {
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine(("[V] bugcheck-time CR3 (DTB@0x10) = 0x{0:X16}  NumberProcessors@0x34 = {1}" -f `
        $hdr.dtb, $hdr.ncpu))
    $pml4Phys = [long]($hdr.dtb -band 0x000FFFFFFFFFF000L)
    [void]$sb.AppendLine(("    PML4 physical = 0x{0:X}" -f $pml4Phys))
    # PHYSICAL_MEMORY_DESCRIPTOR at 0xF80: NumberOfRuns(4) NumberOfPages(4) Run[](16 each)
    $nRuns = [BitConverter]::ToUInt32($hdrBuf, 0xF80)
    $nPages = [BitConverter]::ToUInt32($hdrBuf, 0xF84)
    [void]$sb.AppendLine(("    physmem runs @0xF80: NumberOfRuns={0} NumberOfPages={1}" -f $nRuns, $nPages))
    $fileOff = -1L
    if ($nRuns -ge 1 -and $nRuns -le 64) {
        $acc = 0x2000L   # dump data starts after the 0x2000-byte header
        $okRun = $false
        for ($r = 0; $r -lt $nRuns; $r++) {
            $basePg = [BitConverter]::ToUInt64($hdrBuf, 0xF88 + $r*16)
            $cntPg  = [BitConverter]::ToUInt64($hdrBuf, 0xF90 + $r*16)
            if ($pml4Phys -ge ($basePg * 4096) -and $pml4Phys -lt (($basePg + $cntPg) * 4096)) {
                $fileOff = $acc + ($pml4Phys - $basePg * 4096)
                $okRun = $true
                break
            }
            $acc += [long]$cntPg * 4096
        }
        if (-not $okRun) { $fileOff = -1L }
    }
    if ($fileOff -ge 0 -and $fileOff + 4096 -le $dmpLen) {
        $fsV = [System.IO.File]::OpenRead($Dmp)
        $pml4 = New-Object byte[] 4096
        $null = $fsV.Seek($fileOff, 'Begin')
        $null = $fsV.Read($pml4, 0, 4096)
        $fsV.Close()
        $userNZ = 0; $kernNZ = 0
        for ($e = 0; $e -lt 512; $e++) {
            $v = [BitConverter]::ToUInt64($pml4, $e*8)
            if ($v -ne 0) { if ($e -lt 256) { $userNZ++ } else { $kernNZ++ } }
        }
        [void]$sb.AppendLine(("    PML4 entries nonzero: USER half (0..255) = {0}, KERNEL half (256..511) = {1}" -f $userNZ, $kernNZ))
        $line = "    PML4[0..15]:"
        for ($e = 0; $e -lt 16; $e++) {
            $v = [BitConverter]::ToUInt64($pml4, $e*8)
            $line += (" {0:X16}" -f $v)
        }
        [void]$sb.AppendLine($line)
        if ($kernNZ -eq 0) {
            [void]$sb.AppendLine("    kernel half ALL ZERO -> offset math failed on this dump type, INCONCLUSIVE")
        } elseif ($userNZ -eq 0) {
            [void]$sb.AppendLine("    >>> USER HALF EMPTY: bugcheck-time CR3 has NO user address space = System process DTB")
            [void]$sb.AppendLine("    >>> WRONG-CR3 THEORY CONFIRMED (crash thread ran with System page tables)")
        } else {
            [void]$sb.AppendLine("    user half has entries -> bugcheck CR3 looks like a user process (theory NOT confirmed)")
        }
    } else {
        [void]$sb.AppendLine("    PML4 page not found in dump (kernel-dump layout) - INCONCLUSIVE")
    }
    # header hexdump 0xF60-0x1100 for structure identification
    [void]$sb.AppendLine("    ---- header hexdump 0xF60..0x10FF ----")
    for ($o = 0xF60; $o -lt 0x1100; $o += 16) {
        $hx = ""; $asc = ""
        for ($k = 0; $k -lt 16; $k++) {
            $b = $hdrBuf[$o + $k]
            $hx += ("{0:X2} " -f $b)
            if ($b -ge 32 -and $b -le 126) { $asc += [char]$b } else { $asc += "." }
        }
        [void]$sb.AppendLine(("    {0:X4}: {1} {2}" -f $o, $hx, $asc))
    }
}
FlushOut
Write-Host "[D] header done"

# ---------- anchor strings ----------
$lineAnchors = @(
    "cpu0: ", "cpu1: ", "cpu2: ", "cpu3: ", "cpu4: ", "cpu5: ", "cpu6: ", "cpu7: ",
    "[HB", "[V] s=", "[S] s=", "[x] s=", "[E] s=", "[F] s=", "[W] s=", "[Y] s=",
    "[Q] s=", "[I] s=", "[i] s=", "[K] s=", "[L] s=", "[n] s=", "[h] s=",
    "[N] s=", "[e] s=", "Unload: ", "[STAGE1]", "[STAGE2]", "[PHHook]", "[fl]", "T2: ", "[ring]",
    "[MSR] ", "[API] "
)
$eventTags = @('E','V','H','S','R','W','C','T','G','D','X','A','P','Z','U','F','f','L','Y','Q','I','i','K','k','n','h','x','b','g','m','N','e','u','c','t','r','v','B','M','w','O')
$evPats = @()
foreach ($t in $eventTags) {
    $evPats += ("$t" + [char]0 + [char]0 + [char]0 + [char]0 + [char]0)
}

# ---------- single streaming scan: collect ring entries globally ----------
$fs = [System.IO.File]::OpenRead($Dmp)
$CHUNK = 16MB
$OVER  = 65536
$buf = New-Object byte[] $CHUNK
$tailStr = $null
$base = [long]0
$hitBB  = New-Object System.Collections.Generic.List[long]
$hitBan = New-Object System.Collections.Generic.List[long]
$evMap  = @{}          # seq -> hashtable entry (keep max tsc)
$lnMap  = @{}          # seq -> text
$lnRaw  = @{}          # seq -> raw char string (for GBK decode later)
$readTotal = [long]0
$evRawCnt = 0; $lnRawCnt = 0
$sw = [System.Diagnostics.Stopwatch]::StartNew()
while (($n = $fs.Read($buf, 0, $CHUNK)) -gt 0) {
    $readTotal += $n
    if ($tailStr) { $s = $tailStr + $enc.GetString($buf, 0, $n) }
    else { $s = $enc.GetString($buf, 0, $n) }
    $sLen = $s.Length
    foreach ($m in [regex]::Matches($s, [regex]::Escape($MAGIC1)))  { $hitBB.Add($base + $m.Index) }
    foreach ($m in [regex]::Matches($s, [regex]::Escape($BANNER))) { $hitBan.Add($base + $m.Index) }
    # event entries: tag + 5 NULs; fields at tag-10(seq) -6(reason) -2(cpu)
    foreach ($p in $evPats) {
        $pos = 0
        while (($i = $s.IndexOf($p, $pos, [System.StringComparison]::Ordinal)) -ge 0) {
            $pos = $i + 1
            if ($i -lt 42) { continue }
            $seq = GetD $s ($i - 10)
            if ($seq -lt 1 -or $seq -gt 60000) { continue }
            $reason = GetD $s ($i - 6)
            if ($reason -lt 0 -or $reason -gt 63) { continue }   #v6.1: 负值(高字节>=0x80)也拒
            $cpu = GetW $s ($i - 2)
            if ($cpu -gt 63) { continue }
            $tsc = GetH $s ($i - 18)
            $evRawCnt++
            $prev = $evMap[$seq]
            if ($null -eq $prev -or [string]::CompareOrdinal($tsc, $prev.tsc) -gt 0) {
                $evMap[$seq] = @{
                    tag = [string]$s[$i]; cpu = $cpu; reason = $reason; tsc = $tsc
                    a = GetH $s ($i - 42); b = GetH $s ($i - 34); c = GetH $s ($i - 26)
                }
            }
        }
    }
    # line entries: known ASCII prefixes; seq DWORD at -4
    foreach ($p in $lineAnchors) {
        $pos = 0
        while (($i = $s.IndexOf($p, $pos, [System.StringComparison]::Ordinal)) -ge 0) {
            $pos = $i + 1
            if ($i -lt 4) { continue }
            $seq = GetD $s ($i - 4)
            if ($seq -lt 1 -or $seq -gt 60000) { continue }
            $prevTxt = $lnMap[$seq]
            if ($null -ne $prevTxt -and $prevTxt.Length -ge 470) { continue }
            $len = 0
            while ($len -lt 496 -and ($i + $len) -lt $sLen -and $s[$i + $len] -ne [char]0) { $len++ }
            if ($len -lt 3) { continue }
            if ($null -ne $prevTxt -and $len -le $prevTxt.Length) { continue }
            $lnRawCnt++
            $lnMap[$seq] = $s.Substring($i, $len)
        }
    }
    if ($sLen -gt $OVER) {
        $tailStr = $s.Substring($sLen - $OVER)
        $base += $sLen - $OVER
    } else { $tailStr = $s }
    if (($readTotal % (256MB)) -lt $CHUNK) {
        $pct = [int](100 * $readTotal / $dmpLen)
        Write-Host ("  ...{0} MB / {1} MB ({2}%) {3:F0}s ev={4} ln={5}" -f `
            [math]::Round($readTotal/1MB), [math]::Round($dmpLen/1MB), $pct, $sw.Elapsed.TotalSeconds, $evRawCnt, $lnRawCnt)
    }
}
$fs.Close()
Write-Host ("Scan done {0:F0}s. raw candidates: events={1} lines={2}; unique: events={3} lines={4}" -f `
    $sw.Elapsed.TotalSeconds, $evRawCnt, $lnRawCnt, $evMap.Count, $lnMap.Count)
[void]$sb.AppendLine("")
[void]$sb.AppendLine(("[scan] unique entries recovered: events={0} lines={1} (global seq assembly)" -f $evMap.Count, $lnMap.Count))
FlushOut

# ---------- A. blackbox ----------
$fsR = [System.IO.File]::OpenRead($Dmp)
function ReadWin([long]$off, [int]$len) {
    $len = [int][Math]::Min($len, $dmpLen - $off)
    if ($len -le 0) { return $null }
    $b = New-Object byte[] $len
    $null = $fsR.Seek($off, 'Begin')
    $got = 0
    while ($got -lt $len) {
        $r = $fsR.Read($b, $got, $len - $got)
        if ($r -le 0) { break }
        $got += $r
    }
    return $b
}
if ($hitBB.Count -eq 0) {
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("[A] blackbox: NOT FOUND (magic GEPTBB01 missing)")
} else {
    foreach ($off in $hitBB) {
        $bb = ReadWin $off $BB_SIZE
        if ($null -eq $bb) { continue }
        $tailOk = $true
        for ($k = 0; $k -lt 8; $k++) {
            if ($bb[$BB_TAIL + $k] -ne [byte][char]$MAGIC2[$k]) { $tailOk = $false; break }
        }
        if (-not $tailOk) { continue }
        function Q([int]$o) { [BitConverter]::ToInt64($bb, $o) }
        [void]$sb.AppendLine("")
        # v6.2 FIX: the -f expression MUST be wrapped in parens here - inside a
        # method call the commas would split into 3 AppendLine arguments and the
        # -f got only $off (1 arg vs 3 placeholders -> format error, line lost).
        [void]$sb.AppendLine(("[A] blackbox @0x{0:X} build={1} ver={2}" -f $off, `
            $enc.GetString($bb, 8, 24).Split([char]0)[0], (Q 0x20)))
        $fired = (Q 0x28) -ne 0
        if ($fired) {
            [void]$sb.AppendLine(("    FIRED: intr-clock={0:F3}s rdtsc=0x{1:X} armed={2:F3}s" -f `
                ((Q 0x30)/1e7), (Q 0x28), ((Q 0x38)/1e7)))
            [void]$sb.AppendLine(("    lineHead={0} ringHead={1} t1Seq={2} t2Seq={3} guard={4} hot={5}" -f `
                (Q 0x40), (Q 0x48), (Q 0x50), (Q 0x58), (Q 0x60), (Q 0x68)))
            [void]$sb.AppendLine(("    vcpu={0} pend={1}" -f (Q 0x70), (Q 0x78)))
            $exTxt = @()
            for ($r = 0; $r -lt 82; $r++) {   # v7: 82 exit reasons (was 64)
                $c = Q (0x88 + $r*8)
                if ($c -ne 0) { $exTxt += ("r{0}={1}" -f $r, $c) }
            }
            [void]$sb.AppendLine("    exits: " + $(if ($exTxt) { $exTxt -join "  " } else { "ALL ZERO" }))
        } else {
            [void]$sb.AppendLine("    NOT fired (native BSOD path - expected for 0x50). LIVE pollCnt=$((Q 0x80))")
        }
    }
}
$fsR.Close()
FlushOut
Write-Host "[A] blackbox done"

# ---------- B. assembled LINE ring ----------
if ($lnMap.Count -eq 0) {
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("[B] LINE RING: no entries recovered")
} else {
    $seqs = @($lnMap.Keys | Sort-Object)
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine(("[B] LINE RING assembled: {0} unique lines (seq {1}..{2})" -f $seqs.Count, $seqs[0], $seqs[-1]))
    [void]$sb.AppendLine("    (compare with the uploaded temp log: lines BEYOND its last line L00860 = the death window)")
    $skipBefore = 0
    if ($seqs.Count -gt 130) { $skipBefore = $seqs[$seqs.Count - 130] }
    foreach ($sq in $seqs) {
        if ($sq -lt $skipBefore) { continue }
        $raw = $lnMap[$sq]
        $bytes = New-Object byte[] $raw.Length
        for ($k = 0; $k -lt $raw.Length; $k++) { $bytes[$k] = [byte][int][char]$raw[$k] }
        $txt = $gk.GetString($bytes)
        [void]$sb.AppendLine(("  L{0:d6} {1}" -f ($sq + 1), $txt))
    }
}
FlushOut
Write-Host "[B] line ring done"

# ---------- C. assembled EVENT ring ----------
if ($evMap.Count -eq 0) {
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("[C] EVENT RING: no entries recovered")
} else {
    $seqs = @($evMap.Keys | Sort-Object)
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine(("[C] EVENT RING assembled: {0} unique events (seq {1}..{2})" -f $seqs.Count, $seqs[0], $seqs[-1]))
    $rsnTally = @{}
    foreach ($sq in $seqs) {
        $e = $evMap[$sq]
        $key = ("{0}:{1}" -f $e.tag, $e.reason)
        if ($rsnTally.ContainsKey($key)) { $rsnTally[$key]++ } else { $rsnTally[$key] = 1 }
    }
    $tTxt = @()
    foreach ($kk in ($rsnTally.Keys | Sort-Object)) { $tTxt += ("{0}={1}" -f $kk, $rsnTally[$kk]) }
    [void]$sb.AppendLine("    tag:reason tally: " + ($tTxt -join "  "))
    [void]$sb.AppendLine("    ---- decoder ----")
    [void]$sb.AppendLine("    V rsn18 = unload vmcall(1) per cpu  |  V rsn48 = EPT violation (a=gpa, b=rip, c=qual)")
    [void]$sb.AppendLine("    x a=3 = view switch to CodePage     |  S 21/22/23 = EptSetHook steps")
    [void]$sb.AppendLine("    T=triple fault C=misconfig D=loop P=lowaddr X=storm U/Z=unknown-exit A=alloc-fail")
    $showFrom = 0
    # v6.3: print ALL events sorted by seq (v6.2 printed only the last 100 by seq,
    # which on a garbage-dominated recovery HID all the real low-seq ring entries)
    for ($k = $showFrom; $k -lt $seqs.Count; $k++) {
        $sq = $seqs[$k]
        $e = $evMap[$sq]
        $mean = Get-TagMeaning $e.tag
        [void]$sb.AppendLine(("  [{0}] seq={1,-6} cpu={2,-2} rsn={3,-3} a=0x{4} b=0x{5} c=0x{6} {7}" -f `
            $e.tag, $sq, $e.cpu, $e.reason, $e.a, $e.b, $e.c, $mean))
    }
    $last = $evMap[$seqs[-1]]
    [void]$sb.AppendLine(("    LAST EVENT: [{0}] cpu={1} rsn={2} a=0x{3} b=0x{4} c=0x{5}" -f `
        $last.tag, $last.cpu, $last.reason, $last.a, $last.b, $last.c))
}
[void]$sb.AppendLine("")
[void]$sb.AppendLine("=== end of report ===")
FlushOut
Write-Host ""
Write-Host "Report saved to: $Out  (upload this file)"
Write-Host $sb.ToString()
