# Credits: Hitachi/Renesas H8 module

This module is a community SLEIGH module that Ghidra-Rare imported, tested and rebuilt. Testing
showed that two of the three upstream specs did not compile, that none of the languages loaded
(the compiler specs failed validation), and that the one spec that compiled (H8/300H advanced,
loaded after fixing its cspec) decoded 75.0% of the H8/300H code-table corpus and 82.9% of the
every-first-word corpus as the same instruction as the manual, with no H8S or H8SX instructions. The instruction set was therefore
regenerated from the Renesas code tables. The module's purpose, layout, language IDs of the
H8/300, H8/300L and H8/300H languages, the register-based design of the operating modes and the
Renesas compiler conventions in the compiler specs come from the original author.

## Upstream

| | |
|---|---|
| Selected source | [shizmob/ghidra-h8-300](https://github.com/shizmob/ghidra-h8-300) (now also at [codeberg.org/shiz/ghidra-h8-300](https://codeberg.org/shiz/ghidra-h8-300), same history), commit `b60714c54e9d2d2df94bb9d737c4ee8789fbf0b7` (2025-04-16) |
| License | WTFPL, version 2 (`COPYING`, unchanged; also copied to `LICENSE`) |
| Original author | Shiz ([@shizmob](https://github.com/shizmob), commits as "Shiz") |
| Compared, not borrowed | [ThomHPL/ghidra-h8s](https://github.com/ThomHPL/ghidra-h8s) (GPL-3.0, Thomas Herpoel; a fork of this module extended for the H8S); [carllom/sleigh-h8](https://github.com/carllom/sleigh-h8) (no license, Carl Lom) and [Thodoris1999/H8-38602R](https://github.com/Thodoris1999/H8-38602R) (no license, built on carllom's, H8/300H normal mode). A GitHub search found no other H8/300-family module (giulioz/ghidra-h8-500 and the other H8/500 repositories are a different CPU and unlicensed) |

No code was copied from the alternatives, so the module stays under the WTFPL. Nothing in it is
derived from GNU binutils sources: the encodings come from the Renesas manuals, GNU objdump and
GNU as were run only as black boxes, and the ELF relocation formulas were worked out from
GCC-built objects and checked against GNU ld's output.

Manuals used (all Renesas, downloaded from renesas.com):

- H8SX Family Software Manual, REJ09B0102-0400 (Table 2.2, "List of Instruction Codes", is the
  source of every encoding; section 2.2 of the instruction semantics);
- H8S/2600 Series, H8S/2000 Series Software Manual, REJ09B0139-0400;
- H8/300H Series Software Manual, REJ09B0213-0300;
- H8/300 Programming Manual; H8/300L Series Software Manual, REJ09B0214-0200.

Ghidra-Rare's changes are separate commits on branch `ghidra-rare` of a fork of the upstream
repository, on top of the upstream history, so the original license and authorship are
preserved.

## Ghidra-Rare changes

Each item names the problem and how it was found.

1. **Instruction set generated from the manual's code table.** `tools/parse_sx_table.py` reads
   Table 2.2 of the H8SX manual (8,493 rows, every addressing-mode combination of every
   instruction) from the PDF's text layout; `tools/clean_rows.py` joins split rows and fixes two
   errata of the table (see GHIDRA-RARE.md); `tools/gen_h8.py` writes one SLEIGH constructor per
   row, with p-code from the instruction descriptions. The H8/300, H8/300L, H8/300H and H8S
   languages use the rows their own manuals list (`tools/forms_*.txt`, `tools/h8variants.py`).
   Found by: compiling upstream (the H8/300 and H8/300H normal-mode specs failed: register attach
   lists of mixed sizes), then differential testing of the one spec that compiled. Problems
   included:
   - `rotr.w`/`rotr.l` decoded as `rotl`; every 24/32-bit address form of MOV, LDC and STC
     (`@(d:24,ERn)`, `@aa:24`) and the `@(d:16,ERn)` forms of LDC/STC absent; `@aa:16`
     operands of MOV.B, MOVFPE and MOVTPE printed and sized as `@aa:8`, those of MOV.L as
     `@aa:32`; 16-bit branch targets not wrapped to the 24-bit space;
   - no H8S or H8SX instructions (EXR, LDM/STM, TAS, MAC, 2-bit shifts; all H8SX addressing modes,
     memory-to-memory operations, MOVA, MOVMD/MOVSD, BFLD/BFST, conditional bit operations, ...);
   - ADDX/SUBX dropped the carry of the first addition (only the second one set C) and set Z
     when the result was zero, where the manual leaves Z unchanged (Z is only cleared, when the
     result is not zero, so that a multi-byte chain tests zero over all its bytes).

   Later rounds of testing corrected the generated semantics too: the GDB simulator's test
   programs found that H8SX MULU/MULS do not change the flags, that `BRA Rn` adds the register
   unscaled (see GHIDRA-RARE.md), that `RTS/L ERn` restores one register and that STMAC after
   CLRMAC reports zero; the emulator tests
   found MAC's operand size.
2. **Nine languages, one per CPU and operating mode**, sharing `h8_common.sinc`: H8/300,
   H8/300L (without MOVFPE/MOVTPE, as its manual lists 55 instruction types), H8/300H and H8S in
   normal (64 Kbytes) and advanced (16 Mbytes) mode, H8SX in normal, middle, advanced and maximum
   mode. The address-space size, the width of branch and data addresses (middle mode sign-extends
   16-bit data addresses), the size of return addresses and memory-indirect vectors, and the
   exception frames follow the mode. Upstream language IDs are kept for the H8/300, H8/300L and
   H8/300H; `h8s:*` and `h8sx:*` are new.
3. **Compiler specs.** The upstream cspec did not load (upstream issue #1: a `pentry` with two
   `register` elements); every language failed to import. New cspecs describe GCC's convention
   (first three arguments in ER0-ER2, return in ER0/ER1, ER4-ER6 preserved) with the Renesas
   two- and three-register conventions kept as alternatives. The stack pointer is R7 in the
   16-bit spaces and the low 24 bits of ER7 in the 24-bit space, because the decompiler's stack
   offsets must fit the address space. Found by importing and decompiling the real binaries.
4. **pspecs, DWARF register maps and ldefs** for every language; H8SX `@aa:8` operands use
   SBR, which the pspec tracks at its reset value.
5. **ELF opinion** (`EM_H8_300` = 46, CPU and mode from `e_flags`, values checked with
   `h8300-elf-gcc -mh/-ms/-msx/-mn` and gas) and **ELF relocation handler**
   (`src/main/java`, R_H8_DIR32, DIR16, DIR24R8, DIR24A8, DIR32A16, DISP32A16, PCREL8, PCREL16),
   checked byte for byte against GNU ld. Upstream had neither: no ELF file was recognised.
6. **Function-start patterns** for the H8/300H, H8S and H8SX (the upstream constraint file named
   a language that did not exist).
7. **Context bits** `exrvalid` and `macsat` (H8S, H8SX) for two run-time settings the code does
   not show: exception frames with EXR (interrupt control mode 2) for TRAPA and RTE, and the
   saturating MAC (SYSCR.MACS). MAC also keeps the N-MULT and Z-MULT flags that STMAC copies to
   CCR. Found by reading the manuals against the emulator tests (upstream had neither instruction).
8. **README.md**: the language list, install steps and the upstream "Bugs" note updated; links
   to GHIDRA-RARE.md and the Releases page. The original text and license section are kept.

Ghidra-Rare additions (not upstream): `GHIDRA-RARE.md`, `CREDITS.md`, `LICENSE` (a copy of
`COPYING`), `build.gradle` and `extension.properties` (replaced), `.gitignore` entries,
`tools/` and `test/`.
