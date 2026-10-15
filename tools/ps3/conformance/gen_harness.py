# Instruction conformance test for the PS3 fork.
#
# Builds a tiny PS3-style ELF64 with one function per test case (the instruction, then blr;
# vector cases load their inputs with lvx and store the result with stvx), the XenonRecomp
# TOML for it, and a C++ harness that runs every recompiled function and compares registers,
# CA, CR and memory with the expected values.
#
# The cases (instruction words, inputs, expected results) come from ps3recomp's PPU lifter
# conformance suite, tools/test_ppu_lift.py (https://github.com/sp00nznet/ps3recomp, MIT,
# Copyright (c) 2026 Ned Heller / sp00nznet). They are not copied here: dump_cases.py reads
# them from your own checkout of ps3recomp. See README.md.
#
# Usage: python gen_harness.py cases.json
import json, struct, sys
d = json.load(open(sys.argv[1]))
BASE = 0x10000
words, funcs = [], []   # funcs: (addr, size, kind, case)
def add(ws, kind, c):
    addr = BASE + 4 * len(words); words.extend(ws); funcs.append((addr, 4 * len(ws), kind, c))
BLR = 0x4E800020
for c in d["cases"]:
    add([c["word"], BLR], "g", c)
def lvx(vt, rb): return (31 << 26) | (vt << 21) | (rb << 11) | (103 << 1)
def stvx(vs, rb): return (31 << 26) | (vs << 21) | (rb << 11) | (231 << 1)
for c in d["vcases"]:
    ws = []
    if c["va_reg"] is not None: ws.append(lvx(c["va_reg"], 20))
    ws.append(lvx(c["vb_reg"], 21))
    if c["vc_reg"] is not None: ws.append(lvx(c["vc_reg"], 22))
    ws += [c["word"], stvx(c["vd_reg"], 23), BLR]
    add(ws, "v", c)
text = b"".join(struct.pack(">I", w) for w in words)
opd_addr = BASE + len(text); opd_addr = (opd_addr + 15) & ~15
pad = opd_addr - BASE - len(text)
opd = struct.pack(">IIII", BASE, 0x8000, BASE, 0x8000)
seg = text + b"\0" * pad + opd
# ELF64 BE: header, 1 phdr, data, 3 shdrs (null, .text, .opd)
EH, PH, SH = 64, 56, 64
data_off = EH + PH
sh_off = data_off + len(seg); sh_off = (sh_off + 7) & ~7
hdr = b"\x7fELF" + bytes([2, 2, 1, 0x66]) + b"\0" * 8
hdr += struct.pack(">HHIQQQIHHHHHH", 2, 21, 1, opd_addr, EH, sh_off, 0, EH, PH, 1, SH, 3, 0)
ph = struct.pack(">IIQQQQQQ", 1, 5, data_off, BASE, BASE, len(seg), len(seg), 0x10000)
def shdr(t, fl, addr, off, sz): return struct.pack(">IIQQQQIIQQ", 0, t, fl, addr, off, sz, 0, 0, 16, 0)
shs = shdr(0, 0, 0, 0, 0) + shdr(1, 6, BASE, data_off, len(text)) + shdr(1, 3, opd_addr, data_off + len(text) + pad, 16)
elf = hdr + ph + seg
elf += b"\0" * (sh_off - len(elf)) + shs
open("pruebas.elf", "wb").write(elf)
with open("pruebas.toml", "w") as f:
    f.write('[main]\nfile_path = "pruebas.elf"\nout_directory_path = "out"\nfunctions = [\n')
    for a, s, _, _ in funcs: f.write("  { address = 0x%X, size = 0x%X },\n" % (a, s))
    f.write("]\n")
# harness
def fname(a): return "_xstart" if a == BASE else f"sub_{a:X}"  # the entry point gets XenonRecomp's _xstart name
H = []
H.append('#include "ppc_recomp_shared.h"\n#include <cstdio>\n#include <cstring>\n#include <sys/mman.h>\n')
H.append('void ps3_syscall(PPCContext&, uint8_t*) {}\nuint64_t ps3_timebase() { return 0; }\n')
H.append('static int fails = 0, total = 0, unsup = 0;\nstatic void fail(const char* n, const char* what, unsigned long long got, unsigned long long exp) { fails++; std::printf("FAIL %s: %s got %llx expected %llx\\n", n, what, got, exp); }\n')
H.append('static uint8_t* base;\nstatic void putbytes(uint32_t a, const char* hex) { for (size_t i = 0; hex[2*i]; i++) { unsigned v; std::sscanf(hex + 2*i, "%2x", &v); base[a + i] = (uint8_t)v; } }\n')
H.append('static bool cmpbytes(const char* n, uint32_t a, const char* hex) { bool ok = true; char got[64] = {0}; for (size_t i = 0; hex[2*i]; i++) { unsigned v; std::sscanf(hex + 2*i, "%2x", &v); std::sprintf(got + 2*i, "%02x", base[a + i]); if (base[a + i] != v) ok = false; } if (!ok) { fails++; std::printf("FAIL %s: mem/vector got %s expected %s\\n", n, got, hex); } return ok; }\n')
H.append('static uint8_t crnib(const PPCCRRegister& c) { return (c.lt ? 8 : 0) | (c.gt ? 4 : 0) | (c.eq ? 2 : 0) | (c.so ? 1 : 0); }\n')
H.append('int main() { setvbuf(stdout, nullptr, _IONBF, 0);\n  base = (uint8_t*)mmap(nullptr, 0x100000000ull, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);\n')
for a, s, kind, c in funcs:
    n = c["name"].replace('"', "'")
    H.append('  { total++; PPCContext ctx{}; ctx.fpscr.loadFromHost(); std::memset(base, 0, 0x10000);\n')
    if kind == "g":
        for r, v in c["in_regs"].items(): H.append(f'    ctx.r{r}.u64 = 0x{v:x}ull;\n')
        for r, v in c["in_fpr"].items(): H.append(f'    ctx.f{r}.u64 = 0x{v:x}ull;\n')
        for addr, hx in c["in_mem"].items(): H.append(f'    putbytes(0x{int(addr):x}, "{hx}");\n')
        if c["in_ca"] is not None: H.append(f'    ctx.xer.ca = {int(bool(c["in_ca"]))};\n')
        H.append(f'    {fname(a)}(ctx, base);\n')
        for r, v, m in c["expects"]:
            H.append(f'    if ((ctx.r{r}.u64 & 0x{m:x}ull) != (0x{v:x}ull & 0x{m:x}ull)) fail("{n}", "r{r}", ctx.r{r}.u64 & 0x{m:x}ull, 0x{v:x}ull & 0x{m:x}ull);\n')
        for r, v in c["exp_fpr"]: H.append(f'    if (ctx.f{r}.u64 != 0x{v:x}ull) fail("{n}", "f{r}", ctx.f{r}.u64, 0x{v:x}ull);\n')
        for addr, hx in c["exp_mem"].items(): H.append(f'    cmpbytes("{n}", 0x{int(addr):x}, "{hx}");\n')
        if c["exp_ca"] is not None: H.append(f'    if (ctx.xer.ca != {int(bool(c["exp_ca"]))}) fail("{n}", "ca", ctx.xer.ca, {int(bool(c["exp_ca"]))});\n')
        if c["exp_cr"] is not None:
            nib, sh = c["exp_cr"]; fld = (28 - sh) // 4
            H.append(f'    if (crnib(ctx.cr{fld}) != {nib}) fail("{n}", "cr{fld}", crnib(ctx.cr{fld}), {nib});\n')
    else:
        H.append('    ctx.r20.u64 = 0x8000; ctx.r21.u64 = 0x8010; ctx.r22.u64 = 0x8020; ctx.r23.u64 = 0x8030;\n')
        if c["va_bytes"]: H.append(f'    putbytes(0x8000, "{c["va_bytes"]}");\n')
        H.append(f'    putbytes(0x8010, "{c["vb_bytes"]}");\n')
        if c["vc_bytes"]: H.append(f'    putbytes(0x8020, "{c["vc_bytes"]}");\n')
        H.append(f'    {fname(a)}(ctx, base);\n    cmpbytes("{n}", 0x8030, "{c["exp_bytes"]}");\n')
    H.append('  }\n')
H.append('  std::printf("%d cases, %d failures\\n", total, fails);\n  return fails != 0;\n}\n')
open("harness.cpp", "w").write("".join(H))
print(len(funcs), "functions")
