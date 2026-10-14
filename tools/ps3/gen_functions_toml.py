#!/usr/bin/env python3
"""Generate the XenonRecomp TOML (function list) for a PS3 EBOOT.

Usage:  python tools/ps3/gen_functions_toml.py EBOOT.elf > game.toml
        python tools/ps3/gen_switch_tables.py EBOOT.elf game.toml > switch.toml

Function list = targets of 'bl' inside the code  U  .opd entries (plus tail-call targets).
Each function's size = up to the start of the next one, minus trailing zero padding.
This way the recompiler does not have to guess where functions start (its automatic
analysis can hang on large PS3 executables).

Standard library only. Reads YOUR decrypted EBOOT; contains nothing from any game.
"""
import struct
import sys


def leer_elf(ruta):
    d = open(ruta, 'rb').read()
    assert d[:4] == b'\x7fELF' and d[4] == 2 and d[5] == 2, 'Se espera ELF64 big-endian (EBOOT descifrado)'
    e_entry, e_phoff, e_shoff = struct.unpack_from('>QQQ', d, 0x18)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('>HHH', d, 0x3A)
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        _n, typ, flags, addr, off, size = struct.unpack_from('>IIQQQQ', d, o)
        secs.append((typ, flags, addr, off, size))
    return d, e_entry, secs


def main():
    ruta = sys.argv[1]
    d, entry, secs = leer_elf(ruta)

    def va2off(va):
        for typ, flags, addr, off, size in secs:
            if typ != 8 and addr <= va < addr + size:
                return off + va - addr
        return None

    def u32(va):
        o = va2off(va)
        return struct.unpack_from('>I', d, o)[0] if o is not None else None

    # Entry point's .opd descriptor: (code, TOC)
    toc = u32(entry + 4)

    code = [(a, s, o) for (t, f, a, o, s) in secs if (f & 4) and t == 1 and s > 0]
    def en_codigo(x):
        return any(a <= x < a + s for a, s, _ in code)

    starts = set()
    # .opd: (code, TOC) pairs in data sections
    for typ, flags, addr, off, size in secs:
        if typ != 1 or (flags & 4) or size < 8:
            continue
        for i in range(0, size - 7, 8):
            c, t = struct.unpack_from('>II', d, off + i)
            if t == toc and en_codigo(c) and c % 4 == 0:
                starts.add(c)
    # bl targets
    for a, s, o in code:
        for i in range(0, s, 4):
            w = struct.unpack_from('>I', d, o + i)[0]
            if (w >> 26) == 18 and (w & 3) == 1:
                li = w & 0x03FFFFFC
                if li & 0x02000000:
                    li -= 0x04000000
                t = a + i + li
                if en_codigo(t):
                    starts.add(t)

    # Tail calls: 'b' (no link) or 'bc' that jump OUTSIDE their function land on the start
    # of another function (e.g. a constructor reached with 'b'). Without adding them the
    # recompiler does not know where to go and skips that code. Repeat until nothing new
    # appears, since every new start splits a function in two.
    colas = set()  # jumps into the middle of ANOTHER function (GCC shares epilogues)
    while True:
        colas.clear()
        orden = sorted(starts)
        nuevos = set()
        for a, s, o in code:
            ss = [x for x in orden if a <= x < a + s]
            for k, x in enumerate(ss):
                fin = ss[k + 1] if k + 1 < len(ss) else a + s
                tabla = False
                for i in range(x, fin, 4):
                    w = struct.unpack_from('>I', d, o + i - a)[0]
                    # A jump table (small offsets) usually follows a bctr:
                    # it is data, not instructions.
                    if tabla and (w < 0x00100000 or w > 0xFFF00000):
                        continue
                    tabla = (w == 0x4E800420)
                    op = w >> 26
                    if w & 1 or w & 2:      # link or absolute: not a tail call
                        continue
                    if op == 18:
                        li = w & 0x03FFFFFC
                        if li & 0x02000000:
                            li -= 0x04000000
                    elif op == 16:
                        li = w & 0xFFFC
                        if li & 0x8000:
                            li -= 0x10000
                    else:
                        continue
                    t = (i + li) & 0xFFFFFFFF
                    if not (x <= t < fin) and en_codigo(t) and t not in starts:
                        # Only if the target looks like a function start: it is preceded by
                        # an end (blr, b, bctr) or padding. Otherwise it is a jump inside a
                        # function we split wrongly, and it must not split it further.
                        prev = u32(t - 4)
                        if prev in (0x4E800020, 0x4E800420, 0, 0x60000000) or (prev >> 26 == 18 and not prev & 1):
                            nuevos.add(t)
                        elif op == 18:
                            colas.add(t)
        if not nuevos:
            break
        starts |= nuevos

    out = []
    for a, s, o in code:
        fin_sec = a + s
        ss = sorted(x for x in starts if a <= x < fin_sec)
        for k, x in enumerate(ss):
            fin = ss[k + 1] if k + 1 < len(ss) else fin_sec
            while fin > x + 4 and u32(fin - 4) == 0:
                fin -= 4
            out.append((x, fin - x))

    # Jumps into the middle of ANOTHER function (GCC shares epilogues): for each one, add an
    # extra overlapping function from that point to the end of the function containing it.
    # The original is left alone (the code is duplicated, but correct). Repeat, because the
    # copy can itself jump backwards, outside its range.
    import bisect
    primarias = list(out)
    ini = [x for x, _ in primarias]
    todas = {x: n for x, n in primarias}
    pendientes = list(primarias)
    while pendientes:
        nuevas = []
        for x, n in pendientes:
            for i in range(x, x + n, 4):
                w = u32(i)
                op = w >> 26
                if w & 3 or op not in (16, 18):
                    continue
                if op == 18:
                    li = w & 0x03FFFFFC
                    if li & 0x02000000:
                        li -= 0x04000000
                else:
                    li = w & 0xFFFC
                    if li & 0x8000:
                        li -= 0x10000
                t = (i + li) & 0xFFFFFFFF
                if x <= t < x + n or t in todas or not en_codigo(t):
                    continue
                k = bisect.bisect_right(ini, t) - 1
                if k < 0:
                    continue
                px, pn = primarias[k]
                if t < px + pn:
                    todas[t] = px + pn - t
                    nuevas.append((t, px + pn - t))
        pendientes = nuevas
    out = sorted(todas.items())

    print('[main]')
    print('file_path = "%s"' % ruta.replace('\\', '/'))
    print('out_directory_path = "out"')
    print('switch_table_file_path = "switch.toml"  # generated by gen_switch_tables.py')
    print('functions = [')
    for x, n in out:
        print('  { address = 0x%X, size = 0x%X },' % (x, n))
    print(']')
    print('# %d functions' % len(out), file=sys.stderr)


if __name__ == '__main__':
    main()
