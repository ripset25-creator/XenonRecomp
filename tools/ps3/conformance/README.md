# Instruction conformance test

Checks the code this fork generates for single PPU instructions against expected results, using the test cases of [ps3recomp](https://github.com/sp00nznet/ps3recomp)'s PPU lifter conformance suite (`tools/test_ppu_lift.py`). Thanks to its authors: the cases come from the PowerISA definitions and found the bugs listed below.

The cases are not included here. `dump_cases.py` reads them from your own checkout of ps3recomp (MIT license, Copyright (c) 2026 Ned Heller / sp00nznet).

```
git clone https://github.com/sp00nznet/ps3recomp
python dump_cases.py ps3recomp/tools          # -> cases.json
python gen_harness.py cases.json              # -> pruebas.elf, pruebas.toml, harness.cpp
mkdir out
../../../build/XenonRecomp/XenonRecomp pruebas.toml ../../../XenonUtils/ppc_context.h
clang++ -std=c++20 -O1 -march=native -I out -I ../../../thirdparty/simde -I ../../../XenonUtils out/*.cpp harness.cpp -o pruebas
./pruebas                                     # Linux (the harness reserves 4 GB with mmap)
```

Result on 2026-10-16: 1 010 cases, 76 failures, all of them forms the fork does not translate (`addeo`, `subfeo`) or that are not valid instructions (`mulhwo`, `mulhwuo`). Before the fixes in the same commit it was 184 failures:

- `CA` was computed from the low 32 bits in `addc`, `adde`, `addze`, `addic`, `subfc`, `subfe`, `subfic`. Cell user code runs in 64-bit mode, so the carry comes from the 64-bit result.
- Record forms (`add.`, `and.`, `rlwinm.`…) set cr0 from the low 32 bits; in 64-bit mode it is the 64-bit result.
- `sraw`/`srad` cleared `CA` when the shift amount was 32/64 or more; every bit is shifted out, so `CA` is the sign.
- `vmaxfp`/`vminfp` returned the second operand for NaN inputs and for +0/-0.
- Missing: `addme`, `subfme`, `subfze`, `lfdu`, `ptesync`, `vcmpgtsh`, `vcmpbfp`.
