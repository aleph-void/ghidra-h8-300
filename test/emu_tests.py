#!/usr/bin/env python3
"""P-code semantic tests for the H8 languages, run in Ghidra's emulator by EmuCheck.java.

  emu_tests.py <lang> <outdir> [--break NAME]  -> emu.s, emu.bin (h8300-elf-as/ld), emu.txt

<lang> is one of: 300, 300h_normal, 300h_advanced, h8s_normal, h8s_advanced, sx_normal,
sx_middle, sx_advanced, sx_maximum.  Each test is a short sequence at its own label; emu.txt has
  <name> <start-hex> <stop-hex> <init key=val,...|-> <expect key=val,...>
Keys: register names (er0, r0, r0l, e1, C, V, Z, N, H, I, exr, sbr, vbr, mach, macl) or
m1:/m2:/m4:<addr> for big-endian memory.  Values are hex.  Before every test all general
registers, flags, EXR, VBR and MAC are 0, SP (er7/r7) is 3F00 and SBR is FFFFFF00.
The expected values were worked out by hand from the H8SX, H8S/2600, H8/300H and H8/300
software manuals, never taken from the module's output.  --break NAME makes that test's first
expectation wrong, to show that the harness can fail.
"""
import os
import subprocess
import sys

TOOLS = os.environ.get('H8_TOOLS', os.path.expanduser('~/.cache/ghidra-rare-scratch/tools/x-h8300-elf/bin'))

# lang -> (core, mode, gas directive, ld emulation)
LANGS = {
    '300': ('300', 'normal', '', 'h8300elf'),
    '300l': ('300', 'normal', '', 'h8300elf'),
    '300h_normal': ('300h', 'normal', '.h8300hn', 'h8300hnelf'),
    '300h_advanced': ('300h', 'advanced24', '.h8300h', 'h8300helf'),
    'h8s_normal': ('h8s', 'normal', '.h8300sn', 'h8300snelf'),
    'h8s_advanced': ('h8s', 'advanced24', '.h8300s', 'h8300self'),
    'sx_normal': ('sx', 'normal', '.h8300sxn', 'h8300sxnelf'),
    'sx_middle': ('sx', 'middle', '.h8300sx', 'h8300sxelf'),
    'sx_advanced': ('sx', 'advanced', '.h8300sx', 'h8300sxelf'),
    'sx_maximum': ('sx', 'maximum', '.h8300sx', 'h8300sxelf'),
}

C3 = ('300h', 'h8s', 'sx')     # ER-register cores
C4 = ('300', '300h', 'h8s', 'sx')

# name, cores, asm, init, expect  (asm/init/expect for the ER cores; H8/300 variants below)
TESTS = [
    ('mov_imm', C3, ['mov.b #0x12,r0l', 'mov.w #0x3456,r1', 'mov.l #0x789abcde,er2'], {},
     {'er0': 0x12, 'er1': 0x3456, 'er2': 0x789abcde, 'N': 0, 'Z': 0, 'V': 0}),
    ('add_b_overflow', C4, ['add.b #1,r0l'], {'r0l': 0x7f},
     {'r0l': 0x80, 'V': 1, 'N': 1, 'Z': 0, 'C': 0, 'H': 1}),
    ('add_w_carry', C3, ['add.w #1,r1'], {'r1': 0xffff},
     {'r1': 0, 'C': 1, 'Z': 1, 'V': 0, 'N': 0, 'H': 1}),
    ('sub_l_borrow', C3, ['sub.l #2,er2'], {'er2': 1},
     {'er2': 0xffffffff, 'C': 1, 'N': 1, 'Z': 0, 'V': 0, 'H': 1}),
    ('cmp_w_eq', C3, ['cmp.w #0x1234,r3'], {'r3': 0x1234}, {'r3': 0x1234, 'Z': 1, 'C': 0, 'N': 0, 'V': 0}),
    ('addx_chain', C4, ['add.b #1,r0l', 'addx #0,r0h'], {'r0l': 0xff},
     {'r0': 0x0100, 'C': 0, 'Z': 0}),
    ('subx_chain', C4, ['sub.b r1l,r0l', 'subx #0,r0h'], {'r1l': 1},
     {'r0': 0xffff, 'C': 1, 'N': 1, 'Z': 0}),
    ('neg_b', C4, ['neg.b r0l'], {'r0l': 0x80}, {'r0l': 0x80, 'V': 1, 'C': 1, 'N': 1, 'Z': 0, 'H': 0}),
    ('logic_b', C4, ['and.b #0x0f,r0l', 'or.b #0xa0,r0l', 'xor.b #0xff,r0l'], {'r0l': 0x5a},
     {'r0l': 0x55, 'N': 0, 'Z': 0, 'V': 0}),
    ('not_w', C3, ['not.w r1'], {'r1': 0x00ff}, {'r1': 0xff00, 'N': 1, 'Z': 0}),
    ('inc_dec', C3, ['inc.w #1,r0', 'dec.l #2,er1'], {'r0': 0x7fff, 'er1': 1},
     {'r0': 0x8000, 'er1': 0xffffffff, 'N': 1, 'V': 0, 'Z': 0}),
    ('inc_overflow', C3, ['inc.w #1,r0'], {'r0': 0x7fff}, {'r0': 0x8000, 'V': 1, 'N': 1}),
    ('adds_subs', C3, ['adds #4,er0', 'subs #1,er0'], {'er0': 0x10}, {'er0': 0x13, 'C': 0, 'Z': 0}),
    ('ext', C3, ['extu.w r0', 'exts.w r0', 'exts.l er0'], {'er0': 0x12340080},
     {'er0': 0xffffff80, 'N': 1, 'Z': 0, 'V': 0}),
    ('mulxu_divxu', C4, ['mulxu.b r0l,r1', 'divxu.b r0l,r1'], {'r0l': 0x10, 'r1': 0x0020},
     {'r1': 0x0020, 'N': 0, 'Z': 0}),
    ('divxu_rem', C4, ['divxu.b r0l,r1'], {'r0l': 0x07, 'r1': 0x0064}, {'r1': 0x020e}),
    ('mulxs_w', C3, ['mulxs.w r0,er1'], {'r0': 0xfffe, 'er1': 3}, {'er1': 0xfffffffa, 'N': 1, 'Z': 0}),
    ('divxs_w', C3, ['divxs.w r0,er1'], {'r0': 2, 'er1': 0xfffffff9}, {'er1': 0xfffffffd, 'N': 1, 'Z': 0}),
    ('shift_b', C4, ['shll.b r0l', 'shar.b r0l'], {'r0l': 0x81}, {'r0l': 0x01, 'C': 0}),
    ('shal_overflow', C4, ['shal.b r0l'], {'r0l': 0x40}, {'r0l': 0x80, 'V': 1, 'C': 0, 'N': 1}),
    ('rot_b', C4, ['rotl.b r0l', 'rotr.b r0l', 'rotxl.b r0l', 'rotxr.b r0l'], {'r0l': 0x81},
     {'r0l': 0x81, 'C': 1, 'N': 1}),
    ('daa_carry', C4, ['add.b #1,r0l', 'daa r0l'], {'r0l': 0x99}, {'r0l': 0x00, 'C': 1, 'Z': 1}),
    ('daa_low', C4, ['add.b #1,r0l', 'daa r0l'], {'r0l': 0x09}, {'r0l': 0x10, 'C': 0}),
    ('das', C4, ['sub.b r1l,r0l', 'das r0l'], {'r0l': 0x10, 'r1l': 1}, {'r0l': 0x09, 'C': 0}),
    ('mem_postinc_predec', C3, ['mov.b @er1+,r0l', 'mov.b @er1,r0h', 'mov.b r0l,@-er1'],
     {'er1': 0x2000, 'm2:2000': 0x1122}, {'r0': 0x2211, 'er1': 0x2000, 'm1:2000': 0x11}),
    ('mem_disp16', C3, ['mov.l #0x01020304,er0', 'mov.l er0,@(0x10:16,er1)', 'mov.b @(0x13:16,er1),r2l',
                        'mov.w @(-2:16,er3),r2'],
     {'er1': 0x2000, 'er3': 0x2012}, {'m4:2010': 0x01020304, 'r2': 0x0102}),
    ('mem_disp24', C3, ['mov.b @(0x11:24,er1),r2h'], {'er1': 0x2000, 'm1:2011': 0x5c}, {'r2h': 0x5c}),
    ('mov_abs16', C3, ['mov.b r0l,@0x2100:16', 'mov.w @0x2100:16,r1'], {'r0l': 0x5a, 'm1:2101': 0x77},
     {'m1:2100': 0x5a, 'r1': 0x5a77}),
    ('mov_abs16_negative', C3, ['mov.b r0l,@0x8000:16'], {'r0l': 0x77}, {'m1:{AA16NEG}': 0x77}),
    ('mov_abs8', C3, ['mov.b r0l,@0x20:8', 'mov.b @0x21:8,r0h'], {'r0l': 0x5a, 'm1:{AA8}21': 0x3c},
     {'m1:{AA8}20': 0x5a, 'r0h': 0x3c}),
    ('mov_abs24', ('300h', 'h8s'), ['mov.w r0,@0x2200:24', 'mov.l @0x2200:24,er1'],
     {'r0': 0xabcd, 'm2:2202': 0x0102}, {'m2:2200': 0xabcd, 'er1': 0xabcd0102}),
    ('bit_reg', C4, ['bset #3,r0l', 'bnot #0,r0l', 'bclr #3,r0l', 'btst #0,r0l', 'bld #0,r0l',
                     'bst #7,r0l', 'bist #1,r0l'], {}, {'r0l': 0x81, 'C': 1, 'Z': 0}),
    ('bit_mem', C3, ['bset #2,@er1', 'bset r2l,@er1', 'btst #1,@er1', 'bior #0,@er1'],
     {'er1': 0x2000, 'r2l': 0x09}, {'m1:2000': 0x06, 'Z': 0, 'C': 1}),
    ('bit_logic', C4, ['bld #7,r0l', 'band #0,r0l', 'bxor #1,r0l', 'bior #2,r0l'], {'r0l': 0x81},
     {'C': 1}),
    ('beq_bgt', C4, ['cmp.b #3,r0l', 'beq 1f', 'mov.b #1,r1l', '1: bgt 2f', 'mov.b #2,r1h', '2: bls 3f',
                     'mov.b #3,r2l', '3: nop'], {'r0l': 5}, {'r1l': 1, 'r1h': 0, 'r2l': 3}),
    ('bcc_bcs', C4, ['cmp.b #6,r0l', 'bcc 1f', 'mov.b #1,r1l', '1: bcs 2f', 'mov.b #2,r1h', '2: nop'],
     {'r0l': 5}, {'r1l': 1, 'r1h': 0, 'C': 1}),
    ('blt_bge', C4, ['cmp.b #1,r0l', 'blt 1f', 'mov.b #1,r1l', '1: nop'], {'r0l': 0x80},
     {'r1l': 0, 'N': 0, 'V': 1}),
    ('bsr_rts', C4, ['bsr sub_seven:16', 'mov.b r0l,r1l'], {}, {'r0l': 7, 'r1l': 7, 'SP': 0x3f00}),
    ('jsr_reg', C3, ['mov.l #sub_seven,er1', 'jsr @er1'], {}, {'r0l': 7, 'SP': 0x3f00}),
    ('jsr_memind', C4, ['jsr @@0x40'], {}, {'r0l': 7, 'SP': 0x3f00}),
    ('jsr_frame', C4, ['jsr @sub_sp:24'], {}, {'ER1': '{RETFRAME}', 'SP': 0x3f00}),
    ('trapa_rte', C3, ['trapa #0', 'mov.b r0l,r1l'], {}, {'r0l': 9, 'r1l': 9, 'I': 0, 'SP': 0x3f00}),
    ('trapa_i', C3, ['trapa #1'], {}, {'r2l': 0x80, 'I': 0, 'SP': 0x3f00}),
    ('ldc_stc', C4, ['ldc #0x05,ccr', 'stc ccr,r0l', 'andc #0xfe,ccr', 'orc #0x80,ccr', 'stc ccr,r0h',
                     'xorc #0x84,ccr'], {}, {'r0l': 0x05, 'r0h': 0x84, 'I': 0, 'Z': 0, 'C': 0}),
    ('ldc_stc_mem', C3, ['ldc @er1,ccr', 'stc ccr,@(2:16,er1)'], {'er1': 0x2000, 'm2:2000': 0x8100},
     {'I': 1, 'C': 1, 'm1:2002': 0x81}),
    ('push_pop', C3, ['push.l er1', 'push.w r2', 'pop.w r3', 'pop.l er4'], {'er1': 0x11223344, 'r2': 0x5566},
     {'r3': 0x5566, 'er4': 0x11223344, 'SP': 0x3f00, 'm4:3efc': 0x11223344}),
    ('eepmov_b', C4, ['eepmov.b'], {'er5': 0x2000, 'er6': 0x2100, 'r4l': 2, 'm2:2000': 0xa1b2},
     {'m2:2100': 0xa1b2, 'er5': 0x2002, 'er6': 0x2102, 'r4l': 0}),
    # --- H8S and later
    ('stm_ldm', ('h8s', 'sx'), ['stm.l er0-er1,@-sp', 'mov.l #0,er0', 'mov.l #0,er1', 'ldm.l @sp+,er0-er1'],
     {'er0': 0x11111111, 'er1': 0x22222222}, {'er0': 0x11111111, 'er1': 0x22222222, 'SP': 0x3f00,
                                              'm4:3efc': 0x11111111, 'm4:3ef8': 0x22222222}),
    ('tas', ('h8s', 'sx'), ['tas @er1'], {'er1': 0x2000}, {'m1:2000': 0x80, 'Z': 1, 'N': 0}),
    ('shal_2', ('h8s', 'sx'), ['shll.w #2,r0', 'shar.l #2,er1'], {'r0': 0x4001, 'er1': 0x80000007},
     {'r0': 0x0004, 'er1': 0xe0000001, 'C': 1}),
    ('rot_2', ('h8s', 'sx'), ['rotl.w #2,r0'], {'r0': 0xc000}, {'r0': 0x0003, 'C': 1}),
    ('mac', ('h8s', 'sx'), ['clrmac', 'mac @er1+,@er2+', 'mac @er1+,@er2+', 'stmac macl,er0'],
     {'er1': 0x2000, 'er2': 0x2100, 'm4:2000': 0x0003fffe, 'm4:2100': 0x00040005},
     {'er0': 2, 'er1': 0x2004, 'er2': 0x2104}),
    # CLRMAC leaves MAC zero, which STMAC reports as Z (found by the GDB simulator's mac.s)
    ('clrmac_flags', ('h8s', 'sx'), ['clrmac', 'stmac mach,er0'], {'er0': 0x1234, 'N': 1},
     {'er0': 0, 'Z': 1, 'N': 0, 'V': 0}),
    ('exr', ('h8s', 'sx'), ['ldc #3,exr', 'stc exr,r0l', 'orc #0x80,exr', 'stc exr,r0h'], {},
     {'r0l': 0x7b, 'r0h': 0xfb}),
    # MAC saturating mode (context macsat=1): 3 x 0x7FFF*0x7FFF = H'BFFD0003 saturates to H'7FFFFFFF,
    # V-MULT is set and shows in the LSB of MACH
    ('mac_sat', ('h8s', 'sx'), ['clrmac', 'mac @er1+,@er2+', 'mac @er1+,@er2+', 'mac @er1+,@er2+',
                                'stmac macl,er0', 'stmac mach,er3'],
     {'macsat': 1, 'er1': 0x2000, 'er2': 0x2100, 'm4:2000': 0x7fff7fff, 'm2:2004': 0x7fff,
      'm4:2100': 0x7fff7fff, 'm2:2104': 0x7fff}, {'er0': 0x7fffffff, 'er3': 1, 'V': 1, 'N': 0, 'Z': 0}),
    # exception frame with EXR (context exrvalid=1): an EXR word below the CCR/PC frame, restored by RTE
    ('trap_exr', ('h8s', 'sx'), ['trapa #0'], {'exrvalid': 1, 'exr': 5}, {'{FRAMEX}': 0, 'exr': 5, 'SP': 0x3f00}),
    # --- H8SX
    ('sx_postdec_preinc', ('sx',), ['mov.w #0xbeef,r0', 'mov.w r0,@+er1', 'mov.w @er1-,r2'], {'er1': 0x2000},
     {'m2:2002': 0xbeef, 'r2': 0xbeef, 'er1': 0x2000}),
    ('sx_disp32_d2', ('sx',), ['mov.l @(8:2,er1),er0', 'mov.b @(0x11:32,er1),r2h'],
     {'er1': 0x2000, 'm4:2008': 0xcafebabe, 'm1:2011': 0x42}, {'er0': 0xcafebabe, 'r2h': 0x42}),
    ('sx_index', ('sx',), ['mov.w @(0x2000:16,r1l.b),r0', 'mov.l @(0x1ff0:32,r2.w),er3'],
     {'er1': 0x103, 'er2': 0x10002, 'm2:2006': 0x1357, 'm4:1ff8': 0x24680ace},
     {'r0': 0x1357, 'er3': 0x24680ace}),
    ('sx_mem2mem', ('sx',), ['mov.w @er1+,@er2+', 'add.w @er1,@er2'],
     {'er1': 0x2000, 'er2': 0x2100, 'm4:2000': 0x01020003, 'm4:2100': 0x00000005},
     {'m2:2100': 0x0102, 'm2:2102': 0x0008, 'er1': 0x2002, 'er2': 0x2102}),
    ('sx_imm2mem', ('sx',), ['add.b #5,@er1', 'sub.b #0x20,@er1'], {'er1': 0x2000, 'm1:2000': 0x10},
     {'m1:2000': 0xf5, 'C': 1, 'N': 1}),
    ('sx_alu_memsrc', ('sx',), ['sub.l @er1,er0'], {'er1': 0x2000, 'er0': 0x20, 'm4:2000': 0x10}, {'er0': 0x10}),
    ('sx_same_reg_twice', ('sx',), ['mov.b @er0+,@er0+'], {'er0': 0x2000, 'm1:2000': 0xaa},
     {'m1:2001': 0xaa, 'er0': 0x2002}),
    ('sx_reg_after_ea', ('sx',), ['mov.w r0,@er0+'], {'er0': 0x2000}, {'m2:2000': 0x2002, 'er0': 0x2002}),
    ('sx_xor_reg_after_ea', ('sx',), ['xor.b r0l,@er0+'], {'er0': 0x2034, 'm1:2034': 0x0f},
     {'m1:2034': 0x3a, 'er0': 0x2035}),
    ('sx_mulu_divu', ('sx',), ['mulu.l er1,er0', 'divu.l #4,er0'], {'er0': 0x10000, 'er1': 0x30},
     {'er0': 0xc0000, 'N': 0, 'Z': 0}),
    ('sx_mulsu', ('sx',), ['muls/u.l er1,er0'], {'er0': 0x80000000, 'er1': 2}, {'er0': 0xffffffff, 'N': 1}),
    ('sx_divs', ('sx',), ['divs.w #3,r0'], {'r0': 0xfff8}, {'r0': 0xfffe, 'N': 1, 'Z': 0}),
    ('sx_shll_var', ('sx',), ['shll.l r0l,er2', 'shlr.l #31,er2'], {'r0l': 31, 'er2': 1},
     {'er2': 1, 'C': 0, 'N': 0}),
    ('sx_shll_16', ('sx',), ['shll.l #16,er0'], {'er0': 0x00018000}, {'er0': 0x80000000, 'C': 1, 'N': 1}),
    ('sx_extu_2', ('sx',), ['extu.l #2,er0'], {'er0': 0xffffff80}, {'er0': 0x80, 'N': 0}),
    ('sx_bit_cond', ('sx',), ['cmp.b #0,r0l', 'bset/eq #0,@er1', 'bclr/ne #0,@er1', 'bstz #7,@er1',
                              'bistz #6,@er1'], {'er1': 0x2000}, {'m1:2000': 0x81}),
    ('sx_bfld_bfst', ('sx',), ['bfld #0x3c,@er1,r0l', 'bfst r0h,#0xf0,@er1'],
     {'er1': 0x2000, 'm1:2000': 0xb4, 'r0h': 0x05}, {'r0l': 0x0d, 'm1:2000': 0x54}),
    ('sx_bra_s', ('sx',), ['bra/s 1f', 'mov.b #1,r0l', 'mov.b #2,r0l', '1: nop'], {}, {'r0l': 1}),
    ('sx_bra_bs', ('sx',), ['bra/bs #2,@er1,1f', 'mov.b #1,r0l', '1: bra/bc #2,@er1,2f', 'mov.b #2,r0h', '2: nop'],
     {'er1': 0x2000, 'm1:2000': 0x04}, {'r0l': 0, 'r0h': 2}),
    ('sx_bsr_bc', ('sx',), ['bsr/bc #0,@er1,sub_seven', 'mov.b r0l,r1l'], {'er1': 0x2000, 'm1:2000': 0x02},
     {'r1l': 7, 'SP': 0x3f00}),
    ('sx_bra_rn', ('sx',), ['bra r1l.b', 'mov.b #1,r0l', 'mov.b #2,r0h', 'nop'], {'er1': 2}, {'r0l': 0, 'r0h': 2}),
    ('sx_rts_l_one', ('sx',), ['bsr sub_rtsl1:16'], {'er4': 4}, {'er4': 4, 'SP': 0x3f00}),
    ('sx_mulu_flags', ('sx',), ['mulu.w r2,r1'], {'r1': 0x20, 'r2': 0xfffe, 'N': 1, 'Z': 1},
     {'r1': 0xffc0, 'N': 1, 'Z': 1, 'C': 0, 'V': 0}),
    ('sx_rts_l', ('sx',), ['bsr sub_rtsl:16'], {'er4': 4, 'er5': 5}, {'er4': 4, 'er5': 5, 'SP': 0x3f00, 'r0l': 3}),
    ('sx_mova', ('sx',), ['mova/w.l @(0x100:16,r1l.b),er2', 'mova/l.l @(0x10:16,@er3.w),er4'],
     {'er1': 3, 'er3': 0x2000, 'm2:2000': 0x0002}, {'er2': 0x106, 'er4': 0x18}),
    ('sx_movmd', ('sx',), ['movmd.b'], {'er5': 0x2000, 'er6': 0x2100, 'r4': 3, 'm4:2000': 0x01020300},
     {'m2:2100': 0x0102, 'm1:2102': 3, 'er5': 0x2003, 'er6': 0x2103, 'r4': 0}),
    ('sx_movsd', ('sx',), ['movsd.b 1f', 'mov.b #1,r0l', '1: nop'],
     {'er5': 0x2000, 'er6': 0x2100, 'r4': 10, 'm4:2000': 0x41420043},
     {'m2:2100': 0x4142, 'm1:2102': 0, 'er5': 0x2003, 'er6': 0x2103, 'r4': 7, 'r0l': 0}),
    ('sx_ldc_vbr', ('sx',), ['ldc.l er1,vbr', 'stc.l vbr,er2'], {'er1': 0x12345678}, {'er2': 0x12345000}),
    # data addresses: in middle mode the low 16 bits are sign-extended, in normal mode only the
    # low 16 bits count, in the 16-Mbyte modes the low 24 bits
    ('ea_width', C3, ['mov.b r0l,@er1'], {'r0l': 0x5a, 'er1': 0x12348000}, {'m1:{EA8000}': 0x5a}),
    # exception frame left below SP by TRAPA (C set at the trap): normal mode PC word and a CCR
    # word; 16-Mbyte modes one longword CCR:PC(24); maximum mode PC longword, CCR and EXR words
    ('trap_frame', C3, ['trapa #0'], {'C': 1}, {'{FRAME}': 0}),
]

# H8/300 forms of the classic tests (16-bit address registers)
TESTS_300 = {
    'mulxu_divxu': (['mulxu.b r0l,r1', 'divxu.b r0l,r1'], {'r0l': 0x10, 'r1': 0x0020}, {'r1': 0x0020}),
    'bsr_rts': (['bsr 1f', 'mov.b r0l,r1l', 'bra 2f', '1: mov.b #7,r0l', 'rts', '2: nop'], {},
                {'r0l': 7, 'r1l': 7, 'SP': 0x3f00}),
    'jsr_memind': (['jsr @@0x40'], {}, {'r0l': 7, 'SP': 0x3f00}),
    'jsr_frame': (['jsr @sub_sp'], {}, {'r1': '{RETFRAME}', 'SP': 0x3f00}),
    'eepmov_b': (['eepmov'], {'r5': 0x2000, 'r6': 0x2100, 'r4l': 2, 'm2:2000': 0xa1b2},
                 {'m2:2100': 0xa1b2, 'r5': 0x2002, 'r6': 0x2102, 'r4l': 0}),
    'mem_300': (['mov.b @r1+,r0l', 'mov.b @r1,r0h', 'mov.b r0l,@-r1', 'mov.w @(0x10:16,r1),r2',
                 'mov.b r0h,@0x20:8'],
                {'r1': 0x2000, 'm2:2000': 0x1122, 'm2:2010': 0xabcd},
                {'r0': 0x2211, 'r1': 0x2000, 'r2': 0xabcd, 'm1:ff20': 0x22}),
    'push_pop_300': (['push r1', 'pop r2'], {'r1': 0x1234}, {'r2': 0x1234, 'SP': 0x3f00, 'm2:3efe': 0x1234}),
    'add_w_300': (['add.w r1,r0'], {'r0': 0x8000, 'r1': 0x8000}, {'r0': 0, 'C': 1, 'V': 1, 'Z': 1}),
}


def setup(lang):
    core, mode, directive, emul = LANGS[lang]
    aa8 = {'normal': 'ff', 'advanced24': 'ffff', 'middle': 'ffff', 'advanced': 'ffffff', 'maximum': 'ffffff'}[mode]
    if core == 'sx':
        aa8 = {'normal': 'ff', 'middle': 'ffff'}.get(mode, 'ffffff')
    aa16neg = {'normal': '8000', 'advanced24': 'ff8000', 'middle': 'ff8000', 'advanced': 'ffff8000',
               'maximum': 'ffff8000'}[mode]
    return core, mode, directive, emul, aa8, aa16neg


def main():
    lang, out = sys.argv[1], sys.argv[2]
    brk = sys.argv[sys.argv.index('--break') + 1] if '--break' in sys.argv else None
    core, mode, directive, emul, aa8, aa16neg = setup(lang)
    os.makedirs(out, exist_ok=True)
    normal = mode == 'normal'
    ptr = 2 if normal else 4
    L = []
    L.append('\t' + directive if directive else '')
    L.append('\t.section .text')
    L.append('\t.global _start')
    L.append('_start:')
    # vectors: TRAPA #0/#1 at H'0010/H'0012 (normal) or H'0020/H'0024; @@0x40 -> sub_seven
    vec = '.word' if normal else '.long'
    if core != '300':
        L.append('\t.org %s' % ('0x10' if normal else '0x20'))
        L.append('\t%s trap_handler' % vec)
        L.append('\t%s trap_i' % vec)
    L.append('\t.org 0x40')
    L.append('\t%s sub_seven' % vec)
    L.append('\t.org 0x400')
    tests = []
    for name, cores, asm, init, expect in TESTS:
        if core == '300':
            continue
        if core not in cores:
            continue
        tests.append((name, asm, init, expect))
    if core == '300':
        for name, cores, asm, init, expect in TESTS:
            if '300' in cores and name not in TESTS_300:
                tests.append((name, asm, init, expect))
        for name, (asm, init, expect) in TESTS_300.items():
            tests.append((name, asm, init, expect))
    for name, asm, init, expect in tests:
        L.append('T_%s:' % name)
        for a in asm:
            if ':' in a.split()[0] and a.split()[0].endswith(':'):
                lab, rest = a.split(None, 1)
                L.append(lab)
                L.append('\t' + rest)
            else:
                L.append('\t' + a)
        L.append('E_%s:' % name)
        L.append('\tnop')
    sp = 'r7' if core == '300' else 'er7'
    a5 = 'r' if core == '300' else 'er'
    L += ['sub_seven:', '\tmov.b #7,r0l', '\trts',
          'sub_sp:', '\tmov.%s @%s,%s1' % ('w' if core == '300' else 'l', sp, 'r' if core == '300' else 'er'), '\trts']
    if core != '300':
        L += ['trap_handler:', '\tmov.b #9,r0l', '\trte',
              'trap_i:', '\tstc ccr,r2l', '\tand.b #0x80,r2l', '\trte']
    if core == 'sx':
        L += ['sub_rtsl1:', '\tpush.l er4', '\tmov.l #0,er4', '\trts/l er4']
        L += ['sub_rtsl:', '\tstm.l er4-er5,@-sp', '\tmov.l #0,er4', '\tmov.l #0,er5', '\tmov.b #3,r0l',
              '\trts/l er4-er5']
    src = os.path.join(out, 'emu.s')
    open(src, 'w').write('\n'.join(L) + '\n')
    obj = os.path.join(out, 'emu.o')
    elf = os.path.join(out, 'emu.elf')
    binf = os.path.join(out, 'emu.bin')
    subprocess.run([os.path.join(TOOLS, 'h8300-elf-as'), src, '-o', obj], check=True)
    subprocess.run([os.path.join(TOOLS, 'h8300-elf-ld'), '-m', emul, '-Ttext=0', '-e', '_start', obj, '-o', elf],
                   check=True)
    subprocess.run([os.path.join(TOOLS, 'h8300-elf-objcopy'), '-O', 'binary', elf, binf], check=True)
    syms = {}
    nm = subprocess.run([os.path.join(TOOLS, 'h8300-elf-nm'), elf], capture_output=True, text=True, check=True).stdout
    for line in nm.splitlines():
        p = line.split()
        if len(p) == 3:
            syms[p[2]] = int(p[0], 16)
    lines = []
    for name, asm, init, expect in tests:
        ret = syms['E_%s' % name]
        # jsr @sub_sp:24 is 4 bytes; the frame is the return address (one word in normal mode)
        retframe = syms['T_%s' % name] + 4 if core != '300' else syms['T_%s' % name] + 4

        ret2 = syms['T_%s' % name] + 2
        ea8000 = {'normal': '8000', 'advanced24': '348000', 'middle': 'ff8000', 'advanced': '12348000',
                  'maximum': '12348000'}[mode]

        def fmt(d, is_expect):
            items = []
            for k, v in d.items():
                k = k.replace('{AA8}', aa8).replace('{AA16NEG}', aa16neg).replace('{EA8000}', ea8000)
                if k == '{FRAMEX}':
                    items += ['m2:%s=500' % ('3ef8' if mode == 'maximum' else '3efa')]
                    continue
                if k == '{FRAME}':
                    if mode == 'normal':
                        items += ['m2:3efe=%x' % ret2, 'm2:3efc=101']
                    elif mode == 'maximum':
                        items += ['m4:3efc=%x' % ret2, 'm2:3efa=100', 'm2:3ef8=0']
                    else:
                        items += ['m4:3efc=%x' % (0x01000000 | ret2)]
                    continue
                if v == '{RETFRAME}':
                    v = retframe
                    k = 'r1' if core == '300' else ('er1' if not normal else 'e1')
                    if normal and core != '300':
                        # mov.l @er7,er1 reads the 2-byte return address and the 2 bytes above
                        items.append('r1=0')
                        items.append('e1=%x' % v)
                        continue
                if k == 'SP':
                    k = sp
                items.append('%s=%x' % (k, v))
            return ','.join(items) if items else '-'
        exp = dict(expect)
        if brk == name:
            k0 = next(iter(exp))
            exp[k0] = exp[k0] + 1 if isinstance(exp[k0], int) else exp[k0]
        lines.append('%s %x %x %s %s' % (name, syms['T_%s' % name], ret, fmt(init, False), fmt(exp, True)))
    open(os.path.join(out, 'emu.txt'), 'w').write('\n'.join(lines) + '\n')
    print('%s: %d tests' % (lang, len(lines)))


if __name__ == '__main__':
    main()
