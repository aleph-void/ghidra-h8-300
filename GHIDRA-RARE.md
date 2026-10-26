# Hitachi/Renesas H8 (H8/300, H8/300L, H8/300H, H8S, H8SX)

Ghidra processor module for the H8 family: the 8/16-bit H8/300 and H8/300L, the 32-bit
H8/300H, the H8S/2000 and H8S/2600 and the H8SX, in every CPU operating mode. It is a community
module, [shizmob/ghidra-h8-300](https://github.com/shizmob/ghidra-h8-300) (WTFPL), imported by
Ghidra-Rare, tested and rebuilt: the instruction set is now generated from the code tables of the
Renesas manuals. See [CREDITS.md](CREDITS.md) for provenance and the list of changes.

| Language ID | CPU, operating mode | Address space |
|---|---|---|
| `h8_300:BE:16:normal` | H8/300 | 64 Kbytes |
| `h8_300l:BE:16:normal` | H8/300L (no MOVFPE/MOVTPE) | 64 Kbytes |
| `h8_300h:BE:32:normal` | H8/300H, normal mode | 64 Kbytes |
| `h8_300h:BE:32:advanced` | H8/300H, advanced mode | 16 Mbytes |
| `h8s:BE:32:normal` | H8S/2000, H8S/2600, normal mode | 64 Kbytes |
| `h8s:BE:32:advanced` | H8S/2000, H8S/2600, advanced mode | 16 Mbytes |
| `h8sx:BE:32:normal` | H8SX, normal mode | 64 Kbytes |
| `h8sx:BE:32:middle` | H8SX, middle mode (16-bit data addresses, sign-extended) | 16 Mbytes |
| `h8sx:BE:32:advanced` | H8SX, advanced mode (24-bit program addresses) | 4 Gbytes |
| `h8sx:BE:32:maximum` | H8SX, maximum mode | 4 Gbytes |

The ELF opinion matches `EM_H8_300` (46) and picks the language from `e_flags` bits 16-23, which
GNU tools set per CPU and mode (H8/300, H8/300H, H8S, H8SX; normal or advanced). Middle and
maximum mode have no flag value: choose them by hand. The H8S languages decode the H8S/2600
multiply-accumulate instructions, which the H8S/2000 lacks.

## How it is built

- `tools/parse_sx_table.py` reads Table 2.2, "List of Instruction Codes", of the H8SX Family
  Software Manual (REJ09B0102-0400, pages 635-889) from the PDF's text layout (`pdftotext -bbox`:
  every opcode field is placed by its x position under the 15/8/7/0 column headers). The 8,493 rows
  cover every instruction in every addressing-mode combination.
- `tools/clean_rows.py` joins rows split over two lines, fixes two errata of the table and adds
  the H8S codes the table's note marks as "also executable" (see below). Result:
  `tools/h8sx_codes.json` (8,496 rows).
- `tools/gen_h8.py` writes one SLEIGH constructor per row (`data/languages/h8_*_insn.sinc`), with
  p-code written from the instruction descriptions (section 2.2 of the same manual), and one
  `.slaspec` per CPU and mode. `tools/gen_specs.py` writes the ldefs, pspecs, cspecs, DWARF maps
  and the opinion.
- The older CPUs execute a subset of the H8SX codes (the H8SX is object-code compatible with them).
  Each core's subset is the list of instruction forms in its own manual (`tools/forms_*.txt`:
  H8S/2600-2000 REJ09B0139-0400, H8/300H REJ09B0213-0300, H8/300 Programming Manual); the H8/300L
  is the H8/300 without MOVFPE and MOVTPE (H8/300L Series Software Manual REJ09B0214, 55 types).

To regenerate after changing the generator: `python3 tools/gen_h8.py && python3
tools/gen_specs.py`. To rebuild the table from the manual: download REJ09B0102-0400, run
`pdftotext -f 653 -l 907 -bbox h8sx.pdf table.html`, then `parse_sx_table.py table.html raw.json`
and `clean_rows.py raw.json tools/h8sx_codes.json`.

## What it models

- Registers ER0-ER7 with their E, R, RH and RL parts (R0-R7 only on the H8/300), PC, CCR as
  separate flag registers (I, UI, H, U, N, Z, V, C), EXR (bits 6-3 read as 1), VBR, SBR, MACH:MACL.
- All addressing modes, including the H8SX ones: `@(d:2,ERn)` scaled by the operand size,
  index registers `@(d,RnL.B/Rn.W/ERn.L)` scaled by the operand size, pre-increment and
  post-decrement, memory-to-memory operations, `@aa:8` relative to SBR (H'FF00/H'FFFF00 on the
  older CPUs), `@aa:16` sign-extended, `@@aa:8` and `@@vec:7` through one-word or longword vectors.
  Effective addresses follow the operating mode: normal mode uses the low 16 bits, the 16-Mbyte
  modes the low 24, middle mode sign-extends the low 16 bits of data addresses, H8SX advanced
  mode keeps 24-bit branch addresses. When a register is both an address and a data operand,
  the data is read after the address calculation, as section 1.8.5 specifies.
- Flags for every instruction as the manual's condition-code tables give them: H at bits 3/11/27,
  ADDX/SUBX keep Z when the result is zero, DAA/DAS from the adjustment tables, MULXS/DIVXS/
  DIVS/DIVU N and Z rules, shifts and rotates by 1, 2, 4, 8, 16 or a count, TAS, the bit
  instructions on C and Z.
- Multiply and divide (MULXU/MULXS, DIVXU/DIVXS, H8SX MULU/MULS/DIVU/DIVS and the /U forms;
  division by zero leaves the destination unchanged), MAC with the 42-bit sign-extended MAC
  register and its N/Z/V-MULT flags, BFLD/BFST, MOVA, EEPMOV, MOVMD, MOVSD (with its branch on a
  zero byte), LDM/STM, RTS/L and RTE/L register lists, BRA/S with its delay slot, BRA/BS-BC and
  BSR/BS-BC.
- Calls push one word (normal mode) or one longword; TRAPA pushes PC and CCR in the mode's frame
  layout and calls through the vector (VBR-relative on the H8SX); RTE pops the same frame.
- Two settings the code does not show are context bits (H8S and H8SX; set them for the program
  or an address range with Set Register Values, both 0 at reset): `exrvalid`, EXR is valid
  (interrupt control mode 2), so TRAPA and RTE also push and pop the EXR word (maximum mode
  always does); `macsat`, MAC saturates MACL to 32 bits (SYSCR.MACS = 1).
- Compiler specs for GCC's convention (arguments in ER0-ER2, return value in ER0/ER1, ER4-ER6
  preserved), with the Renesas two- and three-register conventions as alternatives. DWARF register
  maps, ELF opinion and relocation handler, function-start patterns.

## Results

Reference: GNU binutils 2.45 `objdump` H8 disassembler (libopcodes, through `test/slotdis.c`;
machine `h8300`, `h8300h`, `h8300hn`, `h8300s`, `h8300sn`, `h8300sx`, `h8300sxn` to match the
language). "Semantic" allows the size suffixes objdump leaves out (`addx`/`addx.b`, `ldc`/
`ldc.w`, `inc`/`inc.b` ...). "Manual table" is a second, independent decoder: `tools/h8table.py`
matches each slot against the parsed code table and renders the row it finds.

Decode differential, all ten languages, 0 unexplained (`test/summarize.py`):

| Language | Slots | Exact | Semantic | Both invalid | Explained | Unexplained | Manual table agrees |
|---|---|---|---|---|---|---|---|
| `h8_300` | 185,122 | 118,493 | 22,937 | 20,213 | 23,479 | 0 | 100% |
| `h8_300l` | 185,068 | 118,342 | 23,025 | 20,179 | 23,522 | 0 | 100% |
| `h8_300h` normal | 186,107 | 127,369 | 23,218 | 21,034 | 14,486 | 0 | 100% |
| `h8_300h` advanced | 186,107 | 135,057 | 23,218 | 21,034 | 6,798 | 0 | 100% |
| `h8s` normal | 187,836 | 127,775 | 23,667 | 23,276 | 13,118 | 0 | 100% |
| `h8s` advanced | 187,836 | 134,763 | 23,667 | 23,276 | 6,130 | 0 | 100% |
| `h8sx` normal | 240,507 | 173,151 | 21,989 | 37,092 | 8,275 | 0 | 100% |
| `h8sx` middle | 240,507 | 180,046 | 21,989 | 37,092 | 1,380 | 0 | 100% |
| `h8sx` advanced | 240,507 | 180,046 | 21,989 | 37,092 | 1,380 | 0 | 100% |
| `h8sx` maximum | 240,507 | 180,047 | 21,989 | 37,092 | 1,379 | 0 | 100% |

Each language has four corpora: every row of the code table with random fields (H8SX: 8,492
rows x 4 = 33,968 slots), 50,000 random slots, every first 16-bit word with random extension
words (131,072), and an assembler corpus (every row the core has, written as GNU as source three
times with random operands, assembled and linked; 450 to 25,467 lines). In the assembler corpus
every encoding gas produced is the row the line was written from (the corpus avoids the
operands that trigger two gas bugs, below). Explained differences, all languages:

| Count | Class |
|---|---|
| 37,724 | branch target wrapped to the mode's program-address width (objdump prints it unwrapped) |
| 35,175 | a later core's instruction objdump decodes in an earlier core's mode |
| 15,410 | E0-E7 registers objdump decodes in `h8300` mode |
| 5,804 | bits the manual reserves, which objdump ignores |
| 2,988 | odd 16-bit branch displacement objdump rejects (the manual encodes all 16 bits) |
| 1,954 | objdump register list the manual does not define |
| 629 | objdump's `@@vec:7` in normal mode with 4-byte vectors |
| 242 | register list the H8S does not allow |
| 21 | objdump's `bpt` (H'7AFF) |

The "semantic" matches are spellings: size suffixes objdump omits and the `:3`/`:8`/`:16`
annotations it prints differently.

Every-entry test (`CoverageCheck.java`): every constructor of every language is reached by a
code built from its own pattern (H8SX 8,633 of 8,633, H8S 399, H8/300H 289, H8/300 161,
H8/300L 159), and the codes the manual lists all decode.

Emulator (hand-computed expectations, `test/emu_tests.py`): H8/300 and H8/300L 26, H8/300H 49
per mode, H8S 58 per mode, H8SX 85 per mode, all passing; each language's deliberately broken
expectation is reported as a failure.

GDB simulator test programs (GDB 17.2 `sim/testsuite/h8300`, 192 program/CPU builds, run in
Ghidra's emulator through the ELF loader): 190 pass. The two others (addb, stc on the H8SX)
fail at checks that depend on blocks dropped because they test simulator behaviour the manual
contradicts (see below). Without the filter: 169 of 192.

Real code, GCC 14.3 / newlib 4.5 / zlib 1.3.1 programs for the H8/300H, H8S and H8SX (16
binaries, normal and advanced mode, `-mint32`): 351,877 instructions, 351,477 identical to
objdump, 400 the same instruction spelled differently, 0 different; at least 99.9% of each
image's bytes disassembled as instructions; 3,343 of 3,359 functions decompile (the 16
failures: `signal` and `_signal_r` in the 24-bit-space binaries, see Known gaps). Relocatable
zlib objects (deflate.o, inflate.o, trees.o: 9,768 relocations) relocated by the module's
handler are byte-identical to GNU ld's output.

Upstream, for comparison (its only loadable language after fixing the cspec, H8/300H advanced):
75.0% of the H8/300H table corpus and 82.9% of the every-first-word corpus decoded as the same
instruction as the manual, and no H8S or H8SX instruction.

## Errata and contradictions in the manuals

- Table 2.2, page 642: `ADD.B @(d:32,Rs.W),@ERd+` is printed with second word H'6A24 and
  destination mode 00000 (@ERd). Every other @(d:32,Rs.W) source row has H'6A2C and every other
  @ERd+ destination 10000; objdump decodes only the regular form. Fixed in `clean_rows.py`.
- Table 2.2, page 673: the operand text of `AND.B @(d:32,ERs.L),@(d:32,ERd.L)` is missing.
- Table 2.2 marks `MOV.L @(d:32,ERs),ERd` and `MOV.L ERs,@(d:32,ERd)` with "the instruction codes
  for the H8S/2600 and H8S/2000 CPUs are also executable" but lists only the H8SX code; the H8S
  code (01 00 78 0ers 0 6B 2 0erd) is added, and for the store both values of the bit the H8S
  manual (note 2 to its code table) calls don't-care. GNU as emits the H8S form with that bit set.
- `BRA Rn.B/Rn.W/ERn.L`: section 1.8.9 says the register is multiplied by 2, the instruction
  description (2.2.23: "PC + Rn -> PC", "the branch destination address must be even") does not.
  The module follows the instruction description, as does the GDB simulator's test.

## Confirmed reference-tool bugs and deviations

GNU objdump (binutils 2.45), all classified per slot by `test/explain.py`:

- It ignores bits the manual reserves (must be 0 or 1) in many rows and decodes such codes as the
  base instruction; the module rejects them, as the manual's table does not list them.
- LDM/STM and RTS/L/RTE/L register lists: it prints lists that start below ER0, run past ER7 or
  hold more than four registers; on the H8S it accepts lists the H8S manual does not allow
  (two: ER0-ER1, ER2-ER3, ...; three: ER0-ER2, ER4-ER6; four: ER0-ER3, ER4-ER7).
- `@@vec:7` (JSR/JMP) in normal mode reads 4-byte vectors; the manual's normal-mode vector table
  is H'0100-H'01FF with 2-byte entries.
- In `h8300` mode it decodes E0-E7 registers and later cores' forms the H8/300 does not have.
- It prints `bpt` for H'7AFF (a GNU simulator breakpoint, not in the manual) and rejects 16-bit
  branch displacements with bit 0 set, which the manual encodes with all 16 bits.

GNU as and ld (2.45): `bsr` with an 8-bit displacement out of range is silently truncated to the
wrong target (no error); gas refuses H8S register lists that end at ER7, which the manual
allows; on the H8SX, a shift written with a 5-bit count that has a dedicated short form
(`shll.w #0x4:5,r2`) right after a long-form shift (`shll.w #0xe:5,r0`) is assembled with a wrong
register or opcode (`10 26`, shll.w #4,r6, or `14 22`, or.b r2h,r2h); as the first instruction it
assembles correctly (`10 22`). `mova/l.l @(d,e6.w),er6` (an E index register with the
destination's number) is assembled as `@(d,r6.w),er6`, a different register, without a warning.
Both found by the assembler corpus, which now avoids those operands.

GDB 17.2 simulator, from its own test programs (blocks dropped by `test/sim_filter.py`): EXR's
reserved bits 6-3 read as 0 (manual: 1), `@aa:8` without SBR aliasing low memory, SBR's low bits
kept, `@aa:16` not sign-extended in one test (shlr.s), and `@@vec:7` without VBR. Its suite found
four bugs in this module (H8SX MULU/MULS flags, BRA Rn scaling, RTS/L with one register, the
MAC flags after CLRMAC), fixed before the results above.

## Upstream limitations and issues

The upstream README listed "Bugs: Probably many!" and gave build-only install steps; the sources
had no TODO/FIXME comments. Its one issue, #1 "Can't load H8 bin" (on GitHub and on Codeberg,
open), is the cspec XML error that stopped every language from loading; fixed (CREDITS.md item 3).
The upstream H8/300 and H8/300H normal-mode specs did not compile (fixed by the rebuild). The
README now marks these as fixed and points here.

## Known gaps

- **Chip peripherals.** No on-chip I/O register or memory maps: the H8 family has hundreds of
  derivatives with different maps. Label them per program (or with a data type script).
- **Mode and settings are chosen by the user.** H8SX middle and maximum mode, the H8/300L and the
  `exrvalid`/`macsat` context bits have no ELF flag; pick the language and set the bits by hand.
  The H8S languages decode the H8S/2600 MAC instructions, which an H8S/2000 does not have.
- **Decompiler, 24-bit spaces:** in each H8/300H and H8S advanced-mode test program, newlib's
  `signal` and `_signal_r` do not decompile (16 of 3,359 functions): they compare a pointer with
  `SIG_ERR`, `(void *)-1`, a 32-bit constant that does not fit the 3-byte address space ("Offset
  must be between 0x0 and 0xffffff"). Everything else decompiles, including all H8SX functions.
- **DWARF line numbers (Ghidra, not the module).** GCC's H8 line tables use `line_range` 242;
  Ghidra 12.1's DWARF line reader decodes some of their line numbers 256 too low (fp-bit.c line
  199 at H'2344 comes out as -57; objdump decodes 199) and rejects those source-map entries with
  Error/DWARF bookmarks ("Additional errors suppressed"). Data types, functions, parameters and
  the remaining source-map entries import.
- **Hardware behaviour not modelled:** interrupts, SLEEP (a pcodeop), the H8/300's and H8/300H's
  bus-cycle timing, MOVFPE/MOVTPE's E-clock synchronisation (they are plain moves).

Unverified (no freely licensed sample or reference available): code from the Renesas/Hitachi
compilers (HEW, CC-H8) and the Renesas object formats (SYSROF, ELF from Renesas tools); real
firmware images; H8SX middle and maximum mode and the H8/300L in real code (they are covered by
the decode differential, the every-entry test and the emulator tests only); the saturating MAC and
EXR frames are checked against hand-computed results from the manual, not a second
implementation.

## Testing

```
test/build-toolchain.sh <workdir> <prefix>      # h8300-elf binutils 2.45, GCC 14.3.0, newlib 4.5 (once)
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC H8_TC=<prefix> JAVA_HOME=<a JDK>
BU_SRC=<binutils-2.45 source> BU_BUILD=<its h8300-elf build tree> test/run-tests.sh <workdir> [--real]
```

`run-tests.sh` checks that the generators reproduce the checked-in files, compiles every spec,
links the module into the Ghidra install and builds `lib/H8.jar`, then runs the decode
differential (`decode-tests.sh`), the every-entry test (`CoverageCheck.java`) and the emulator
tests (`emu-tests.sh`). `--real` builds the GCC test programs (`test/real/fetch-and-build.sh`,
zlib fetched by pinned URL and SHA-256), checks them (`real-binaries.sh`, `reloc-check.sh`) and
runs the GDB simulator's test programs (`simtests.sh`, GDB 17.2 fetched by pinned URL and SHA-256).
Nothing fetched or built is committed. `test/summarize.py <workdir>/dec` tabulates the decode
reports.
