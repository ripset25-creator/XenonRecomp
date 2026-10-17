# Instruction conformance test

Checks the code this fork generates for single PPU instructions against expected results, using the test cases of [ps3recomp](https://github.com/sp00nznet/ps3recomp)'s PPU lifter conformance suite (`tools/test_ppu_lift.py`). Thanks to its authors: the cases come from the PowerISA definitions and found the bugs listed below.

The cases are not included here. `dump_cases.py` reads them from your own checkout of ps3recomp (MIT license, Copyright (c) 2026 Ned Heller / sp00nznet).

```
git clone https://github.com/sp00nznet/ps3recomp
python dump_cases.py ps3recomp/tools          # -> cases.json
python extra_cases.py                         # -> extra.json (this fork's own cases)
python gen_harness.py cases.json extra.json   # -> pruebas.elf, pruebas.toml, harness.cpp
mkdir out
../../../build/XenonRecomp/XenonRecomp pruebas.toml ../../../XenonUtils/ppc_context.h
clang++ -std=c++20 -O1 -march=native -I out -I ../../../thirdparty/simde -I ../../../XenonUtils out/*.cpp harness.cpp -o pruebas
./pruebas                                     # Linux (the harness reserves 4 GB with mmap)
```

Result on 2026-10-16: 1 010 cases, 76 failures, all of them forms the fork did not translate yet (`addeo`, `subfeo`, `mulhwo`, `mulhwuo`; fixed since, see below). Before the fixes in the same commit it was 184 failures:

- `CA` was computed from the low 32 bits in `addc`, `adde`, `addze`, `addic`, `subfc`, `subfe`, `subfic`. Cell user code runs in 64-bit mode, so the carry comes from the 64-bit result.
- Record forms (`add.`, `and.`, `rlwinm.`…) set cr0 from the low 32 bits; in 64-bit mode it is the 64-bit result.
- `sraw`/`srad` cleared `CA` when the shift amount was 32/64 or more; every bit is shifted out, so `CA` is the sign.
- `vmaxfp`/`vminfp` returned the second operand for NaN inputs and for +0/-0.
- Missing: `addme`, `subfme`, `subfze`, `lfdu`, `ptesync`, `vcmpgtsh`, `vcmpbfp`.

## This fork's own cases

`extra_cases.py` writes 619 more cases whose expected values it computes from the PowerISA definitions (64-bit mode, VMX denormals flushed to zero as on the Cell). They check what ps3recomp's suite does not: `XER[OV]` and `XER[SO]`, cr0 of every record form, and cr6 of the vector compares. The harness also checks `ov`, `so` and the vector `cr6` when a case gives them. On 2026-10-17 all 1 629 cases pass; with the recompiler from before that commit, 943 checks failed (76 of them in ps3recomp's cases):

- OE forms (`addo`, `addco`, `addeo`, `addzeo`, `addmeo`, `subfo`, `subfco`, `subfeo`, `subfzeo`, `subfmeo`, `nego`, `mullwo`, `mulldo`, `divwo`, `divwuo`, `divdo`, `divduo`) were not translated.
- Record forms that left cr0 untouched: `nand.`, `nor.`, `orc.`, `cntlzw.`, `cntlzd.`, `sld.`, `srd.`, `srad.`, `sradi.`, `mulld.`, `mulhw.`, `mulhwu.`, `mulhd.`, `mulhdu.`, `divd.`, `rlwimi.`, `rotlw.`, `rotld.`, `rotldi.`, `clrldi.`, `rldic.`, `rldimi.`.
- `rlwimi` dropped the replicated high word when the mask wraps (mb > me); `rlwnm` with a mask was not translated.
- `neg` of 0x8000000000000000 was signed overflow in C++ (the compiler set cr0 to "greater than").
- `vcmpgtsw.`, `vcmpgtub.`, `vcmpgtuh.` did not set cr6; `vcmpgtsh.` tested 32-bit lanes, so a word with only its high halfword greater counted as all true. `vcmpgtsb`, `vcmpequh`, `vcmpgtuw` were not translated.
- `mulhwo`/`mulhwuo` (the reserved OE bit set) were not decoded; they now run as `mulhw`/`mulhwu`.

Floating-point record forms (`fadd.` etc., which copy FPSCR exception bits to cr1) still leave cr1 untouched: the fork does not track FPSCR exceptions, and compilers do not emit them.
