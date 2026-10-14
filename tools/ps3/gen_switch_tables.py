#!/usr/bin/env python3
"""Detect the jump tables (switch) GCC emits in a PS3 EBOOT and write the XenonRecomp
switch table TOML (switch_table_file_path).

GCC PPC64 (PS3) pattern:
    cmplwi crN, rI, MAX        ; bound (bgt -> default)
    bgt    crN, default
    lwz    rT, off(rB)         ; table address
    rldic/slwi rS, rI, 2       ; index * 4
    lwzx   r0, rS, rT          ; relative offset
    extsw  r0, r0
    add    r0, r0, rT          ; target = table + offset
    mtctr  r0
    bctr
The table usually sits right after the bctr. Targets are validated: aligned and inside the function.
The switch is on rS >> 2 (rS = index*4), which is still intact at the bctr (r0 is not),
hence `shift = 2` in the output.

Usage: python tools/ps3/gen_switch_tables.py EBOOT.elf game.toml > switch.toml
(game.toml = the output of gen_functions_toml.py, used for function bounds)
Requires: pip install capstone
"""
import re, struct, sys, bisect
import capstone

def main():
    elf, toml = sys.argv[1], sys.argv[2]
    d = open(elf, 'rb').read()
    e_phoff = struct.unpack_from('>Q', d, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from('>HH', d, 0x36)
    segs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        typ = struct.unpack_from('>I', d, o)[0]
        off, va, _pa, fsz = struct.unpack_from('>QQQQ', d, o + 8)
        if typ == 1: segs.append((va, off, fsz))
    def u32(a):
        for va, off, sz in segs:
            if va <= a < va + sz - 3: return struct.unpack_from('>I', d, off + a - va)[0]
        return None
    funcs = sorted((int(m.group(1), 16), int(m.group(2), 16)) for m in
                   re.finditer(r'address = 0x([0-9A-F]+), size = 0x([0-9A-F]+)', open(toml).read()))
    starts = [f[0] for f in funcs]
    inicios = set(starts)  # a case can jump to the start of another function (tail call)
    md = capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_64 | capstone.CS_MODE_BIG_ENDIAN)
    md.detail = False
    found, bad = [], []
    for fb, fs in funcs:
        fe = fb + fs
        a = fb
        while a < fe:
            if u32(a) != 0x4E800420: a += 4; continue
            bctr = a; a += 4
            # word by word: capstone would not stop on data (another table) right before
            txt = []
            for x in range(max(fb, bctr - 64), bctr, 4):
                i = next(md.disasm(struct.pack('>I', u32(x) or 0), x), None)
                txt.append((i.mnemonic, i.op_str.replace(' ', '')) if i else ('.long', ''))
            if len(txt) < 5 or txt[-1][0] != 'mtctr' or txt[-2][0] != 'add' or txt[-3][0] != 'extsw' or txt[-4][0] != 'lwzx':
                continue
            rT = txt[-2][1].split(',')[2]
            rS = txt[-4][1].split(',')[1]
            rI, count, alias = None, None, None
            for mn, op in reversed(txt[:-4]):
                if rI is None and mn in ('rldic', 'slwi', 'rlwinm', 'sldi') and op.split(',')[0] == rS:
                    rI = op.split(',')[1]
                elif rI is not None and mn in ('cmplwi', 'cmpldi'):
                    p = op.split(',')
                    if p[-2] in (rI, ) or (alias and p[-2] == alias):
                        count = int(p[-1], 0) + 1; break
                elif rI is not None and mn in ('clrlwi', 'mr', 'clrldi') and op.split(',')[1] == rI:
                    alias = op.split(',')[0]
                if mn in ('blr', 'b', 'bctr'): break
            if rI is None or rS == txt[-4][1].split(',')[0]:
                bad.append(bctr); continue
            # The table follows the bctr and ends where the first target starts
            # (or where a value stops pointing inside the function).
            tbl = bctr + 4
            labels, lim = [], fe
            while tbl + 4 * len(labels) < lim and len(labels) < (count or 4096):
                w = u32(tbl + 4 * len(labels))
                t = (tbl + struct.unpack('>i', struct.pack('>I', w))[0]) & 0xFFFFFFFF
                if t % 4 or not (fb <= t < fe or t in inicios) or (tbl <= t < tbl + 4 * (len(labels) + 1)): break
                labels.append(t)
                if t > tbl: lim = min(lim, t)
            if not labels or (count and len(labels) != count):
                bad.append(bctr); continue
            found.append((bctr, int(rS[1:]), labels))
            a = max(a, tbl + 4 * len(labels))
    for bctr, r, labels in found:
        print('[[switch]]')
        print('base = 0x%X' % bctr)
        print('r = %d' % r)
        print('shift = 2')
        print('labels = [' + ', '.join('0x%X' % x for x in labels) + ']')
        print()
    print('# tables: %d, unresolved bctr matching the pattern: %d' % (len(found), len(bad)), file=sys.stderr)
    for b in bad[:30]: print('#  unresolved: 0x%X' % b, file=sys.stderr)

if __name__ == '__main__':
    main()
