# XenonRecomp for PS3

This is an **unofficial** fork of [XenonRecomp](https://github.com/hedge-dev/XenonRecomp) that recompiles **PS3 (Cell PPU)** executables into C++. It is not affiliated with or endorsed by the XenonRecomp authors. Please report problems with the PS3 changes here, not in the upstream repository.

The `ps3` branch is upstream commit `ddd128b` plus a short series of commits, one per topic, so the changes can be reviewed and rebased on upstream separately. It is being developed alongside the [inFamous port](https://github.com/ripset25-creator/infamous-re), where it translates the whole EBOOT (18 839 functions, 0 unknown instructions) and the result builds with clang on Windows and Linux.

## What changes compared to XenonRecomp

| Area | Change |
| --- | --- |
| Loader | Big-endian ELF64 loader for decrypted EBOOTs; entry point resolved through its `.opd` descriptor; `.opd` found by contents because EBOOT section names are stripped |
| Function discovery | Functions seeded from `.opd` when there is no `.pdata`; data and padding in `.text` skipped; a function that does not end in a branch continues into the next one |
| Jump tables | Optional `shift` per switch table (GCC keeps index × 4); cases that leave the function become tail calls; indirect call in the default case |
| CTR branches | `bdz`/`bdnz`/`bdnzf` may target code outside the function |
| Cell semantics | 128-byte `dcbz`; division by zero returns 0; `mfocrf` with any CR field; `rldicl.`/`rldicr.` update cr0; 64-bit mode: `CA` from the 64-bit result (`addc`, `adde`, `addze`, `addic`, `subfc`, `subfe`, `subfic`) and cr0 of record forms from the 64-bit result; `sraw`/`srad` set `CA` to the sign when the shift is 32/64 or more; `vmaxfp`/`vminfp` return a quiet NaN for NaN inputs and order +0/-0 |
| New instructions | `vspltish`, `vandc`, `vminsw`, `vcmpgtsw`, `vrlw`, `vsl`, `vslo`, `lvebx`, `lfsu`, `stfsu`, `lhzu`, `sthu`, `stdux`, `rldic`, `mulhd`, `mulhdu`, `frsqrte`, `mfctr`, `mtocrf`, `mcrf`, `cror`, `isync`, traps (ignored) and `sc`; for PlayStation All-Stars Battle Royale also `addc`, unconditional `bcctrl`, `rldcl`, `rotld`, `eqv`, `stfdu`, `fnmadd`, `crorc`, `crnor`, `crnand`, `crandc`, `tw` (ignored) and `mtvrsave`/`mfvrsave`; from ps3recomp's test cases also `addme`, `subfme`, `subfze`, `lfdu`, `ptesync`, `vcmpgtsh` and `vcmpbfp` |
| Runtime hooks | `sc` calls `PPC_CALL_SYSCALL` (default `ps3_syscall(ctx, base)`, syscall number in r11); `mftb` calls `PPC_QUERY_TIMEBASE` (default `ps3_timebase()`, 79.8 MHz on real hardware) |
| Debugging | Build the generated code with `-DPPC_CHECK_R1` to get `ppc_check_r1_warning()` calls when a function returns with a different r1 |

Only the PPU is recompiled. SPU programs, the LV2 kernel, and system libraries (GCM/RSX, SPURS, sysutil, file system…) are up to your runtime, as with XenonRecomp on Xbox 360.

## Tools (`tools/ps3/`)

| File | What it does |
| --- | --- |
| `gen_functions_toml.py` | Writes the XenonRecomp TOML with every function (bl targets ∪ `.opd` ∪ tail calls). Standard library only. |
| `gen_switch_tables.py` | Finds GCC jump tables and writes `switch.toml` with `shift = 2`. Needs `pip install capstone`. |
| `gen_imports.py` | Writes `imports_gen.cpp`: one strong `sub_XXXXXXXX` per system import stub, calling `ps3_import(ctx, base, index)`, plus a `g_imports` table (stub, module, NID, name). |
| `nids.csv` | 5 450 NID → function name pairs (`module,nid,name`) used by `gen_imports.py`. |
| `instruction_coverage.cpp` | Counts the instructions an EBOOT uses, to see what a new game needs. Built with the rest of the project. |
| `stub_main.cpp` | Empty `main`, `ps3_syscall` and `ps3_timebase` to check that the translation links. |
| `conformance/` | Instruction conformance test: runs ps3recomp's PPU test cases (1 010) through the fork and checks the results. See its README. |

`nids.csv` was generated from the function names listed in the [RPCS3](https://github.com/RPCS3/rpcs3) source code: each NID is the first 4 bytes, little-endian, of SHA-1(function name + a fixed 16-byte suffix). Credit for collecting the names goes to the RPCS3 project.

## Usage

You need your own decrypted EBOOT as an ELF (for example `EBOOT.elf`). Nothing from any game is included here, and the generated code is derived from the game, so do not publish it.

```
git clone --recursive -b ps3 https://github.com/ripset25-creator/XenonRecomp
cd XenonRecomp
cmake -B build -G Ninja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release
cmake --build build

mkdir work && cd work
python ../tools/ps3/gen_functions_toml.py EBOOT.elf > game.toml
python ../tools/ps3/gen_switch_tables.py EBOOT.elf game.toml > switch.toml
../build/XenonRecomp/XenonRecomp game.toml ../XenonUtils/ppc_context.h
python ../tools/ps3/gen_imports.py EBOOT.elf ../tools/ps3/nids.csv > imports_gen.cpp
```

On Windows, use the "x64 Native Tools Command Prompt for VS 2022" and `clang-cl` as the compiler. The `out/` folder then holds the translated C++; compile it together with `imports_gen.cpp` and your runtime. "Unable to decode" warnings for jump table data are expected.

## Credits

- [RPCS3](https://github.com/RPCS3/rpcs3): function names behind `nids.csv`.
- [ps3recomp](https://github.com/sp00nznet/ps3recomp) (MIT, Copyright (c) 2026 Ned Heller / sp00nznet): the PPU instruction test cases used by `tools/ps3/conformance/` (read from your own checkout, not copied), which found the carry, cr0, `sraw`/`srad`, `vmaxfp`/`vminfp` and missing-instruction fixes listed above.

## License

MIT, like XenonRecomp. See [LICENSE.md](LICENSE.md).
