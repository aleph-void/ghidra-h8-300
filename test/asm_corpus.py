#!/usr/bin/env python3
"""Assembler corpus: every instruction form of a core, written in GNU as syntax with random
operands, assembled by h8300-elf-as (a black box), one instruction per 16-byte slot.

  asm_corpus.py <lang> <outdir> [per-form] [seed]   -> asm.s, asm.bin, asm.txt

<lang> as in emu_tests.py (300, 300h_normal, ..., sx_maximum).  asm.txt lists, per slot, the
table row the line was written from.  The decode tests then compare Ghidra, objdump and the
manual's table on asm.bin, and check that the assembler chose the encoding the manual lists for
the form (an independent check of the code table: the assembler is GNU as, not the table).
"""
import os
import random
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'tools'))
from h8rows import load_rows  # noqa: E402
import h8variants  # noqa: E402
from emu_tests import LANGS, TOOLS  # noqa: E402

SZ = {'B': 1, 'W': 2, 'L': 4}
BREG = ['r%dh' % i for i in range(8)] + ['r%dl' % i for i in range(8)]
WREG = ['r%d' % i for i in range(8)] + ['e%d' % i for i in range(8)]


def gas_operand(row, o, rnd, core, mode, rn=None):
    k, p = o.kind, o.p
    h300 = core == '300'
    ar = (lambda n: 'r%d' % n) if h300 else (lambda n: 'er%d' % n)
    size = row.size
    if k == 'fixedimm':
        return '#%d' % p['v']
    if k == 'imm':
        w = p['w']
        if w == 3 and not row.base.startswith('B') and row.base not in ('TRAPA',):
            v = rnd.randint(1, 7)
        else:
            v = rnd.getrandbits(w)
        if w == 5 and row.base.startswith(('SH', 'ROT')):
            # counts with a dedicated short form (1, 2, 4, 8, 16) are emitted by gas in that form;
            # after a #xx:5 shift, gas 2.45 also gets their register field wrong (GHIDRA-RARE.md)
            while v in (1, 2, 4, 8, 16):
                v = rnd.getrandbits(w)
        if row.base == 'TRAPA':
            return '#%d' % v
        if row.base in ('BFLD', 'BFST'):
            v = v or 1
            return '#0x%x' % v
        if row.base.startswith('B') and w == 3:
            return '#%d' % v
        return '#0x%x:%d' % (v, w)
    if k == 'creg':
        return p['r']
    if k == 'sppost':
        return '@sp+'
    if k == 'sppre':
        return '@-sp'
    if k == 'reglist':
        n = p['n']
        if core == 'sx':
            lo = rnd.randint(0, 7 - n + 1 if n > 1 else 7)
            if row.base.startswith(('RTS', 'RTE')):
                lo = rnd.randint(0, 6 - n + 1 if n > 1 else 6)
        else:
            lo = rnd.choice({2: [0, 2, 4], 3: [0, 4], 4: [0]}[n])   # gas refuses lists that include ER7 (SP)
        return 'er%d' % lo if n == 1 else 'er%d-er%d' % (lo, lo + n - 1)
    if k == 'reg':
        sz = p['sz'] or 'B'
        if row.base in ('DIVXS', 'DIVXU', 'MULXS', 'MULXU') and o is row.operands[-1]:
            sz = {'B': 'W', 'W': 'L'}[size]
        if row.base in ('SHLL', 'SHLR') and len(row.operands) == 2 and o is row.operands[0]:
            sz = 'B'
        if row.base in ('JMP', 'JSR'):
            sz = 'L'
        n = rnd.getrandbits(4) if rn is None else rn
        if sz == 'B':
            return BREG[n]
        if sz == 'W':
            return WREG[n & 7] if h300 else WREG[n]
        return ar(n & 7)
    if k == 'pcidx':
        n = rnd.getrandbits(3)
        return {'B': 'r%dl.b' % n, 'W': 'r%d.w' % n, 'L': 'er%d' % n}[p['ix']]
    n = rnd.getrandbits(3)
    if k == 'ind':
        return '@' + ar(n)
    if k == 'postinc':
        return '@%s+' % ar(n)
    if k == 'postdec':
        return '@%s-' % ar(n)
    if k == 'preinc':
        return '@+%s' % ar(n)
    if k == 'predec':
        return '@-%s' % ar(n)
    if k == 'disp':
        w = p['w']
        if w == 2:
            return '@(%d:2,%s)' % (rnd.randint(1, 3) * SZ[size or 'B'], ar(n))
        if w == 16:
            return '@(0x%x:16,%s)' % (rnd.getrandbits(16), ar(n))
        v = rnd.getrandbits(24 if core in ('300h', 'h8s') else 32)
        return '@(0x%x:%d,%s)' % (v, 24 if core in ('300h', 'h8s') else 32, ar(n))
    if k == 'idx':
        ix = {'B': 'r%dl.b' % n, 'W': 'r%d.w' % n, 'L': 'er%d.l' % n}[p['ix']]
        return '@(0x%x:%d,%s)' % (rnd.getrandbits(p['w']), p['w'], ix)
    if k == 'abs':
        w = p['w']
        if w == 24 and row.base not in ('JMP', 'JSR'):
            w = 32
        v = rnd.getrandbits(min(w, 24) if core in ('300h', 'h8s') and w == 32 else w)
        if core in ('300h', 'h8s') and w == 32:
            return '@0x%x:24' % v
        if row.base in ('JMP', 'JSR'):
            v &= ~1
        return '@0x%x:%d' % (v, w)
    if k == 'memind':
        return '@@0x%x:8' % (rnd.getrandbits(8) & ~1 if mode == 'normal' else rnd.getrandbits(6) * 4)
    if k == 'vecind':
        v = rnd.getrandbits(7)
        return '@@0x%x' % ((0x80 + v) * (2 if mode == 'normal' else 4))
    if k == 'rel':
        w = p['w']
        d = rnd.randint(-60, 60) * 2 if w == 8 else rnd.randint(-15000, 15000) * 2
        return '.%+d:%d' % (d, w)
    if k == 'mova':
        p2 = p['ip']
        if p['ik'] == 'reg':
            nn = rnd.getrandbits(4 if o.bits['reg'][2] == 4 else 3) if rn is None else rn
            inner = (BREG[nn] if p['ix'] == 'B' else WREG[nn]) if o.bits['reg'][2] == 4 else \
                ('r%dl' % nn if p['ix'] == 'B' else 'r%d' % nn)
        else:
            from h8rows import Operand
            io = Operand(o.text)
            io.kind, io.p, io.bits = p['ik'], p2, {}
            fake = type('R', (), {})()
            fake.size, fake.base = p['ix'], 'MOV'
            inner = gas_operand(fake, io, rnd, core, mode)
        return '@(0x%x:%d,%s.%s)' % (rnd.getrandbits(p['w']), p['w'], inner, p['ix'].lower())
    raise ValueError(k)


def main():
    lang, out = sys.argv[1], sys.argv[2]
    per = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    rnd = random.Random(int(sys.argv[4]) if len(sys.argv) > 4 else 1)
    core, mode, directive, emul = LANGS[lang]
    rows = [r for r in load_rows(os.path.join(HERE, '..', 'tools', 'h8sx_codes.json'))
            if h8variants.member('300l' if lang == '300l' else core, r)]
    os.makedirs(out, exist_ok=True)
    L = ['\t' + directive if directive else '', '\t.text', '\t.global _start', '_start:']
    meta = []
    for r in rows:
        if r.rec.get('sx_only') is None and r.rec.get('h8s_form') and core == 'sx':
            continue    # gas emits the H8SX form of these in H8SX mode
        for i in range(per):
            # operands that share one register field (MOVA/x.L @(d,Rn.B),ERn) get the same number
            while True:
                rn = rnd.getrandbits(3)
                ops = []
                for o in r.operands:
                    shared = [p for p in r.operands if p is not o and p.bits.get('reg') and p.bits.get('reg') == o.bits.get('reg')]
                    ops.append(gas_operand(r, o, rnd, core, mode, rn if shared else None))
                # MOVA rows with separate index and destination fields: gas uses the shorter
                # shared-register form when the two register numbers coincide, so draw different
                # ones (for an E index register, @(d,E6.W),ER6, gas 2.45 also silently encodes R6)
                if r.base.startswith('MOVA') and len(ops) == 2:
                    mi = re.search(r',[er](\d)[lh]?\.[bwl]\)$', ops[0])
                    md = re.match(r'er(\d)$', ops[1])
                    if mi and md and mi.group(1) == md.group(1) and \
                            len({tuple(o.bits.get('reg') or ()) for o in r.operands}) == 2:
                        continue
                break
            mn = r.op.lower()
            if core == '300' and mn in ('daa', 'das', 'adds', 'subs'):
                mn = mn
            L.append('\t%s\t%s' % (mn, ','.join(ops)) if ops else '\t%s' % mn)
            L.append('\t.balign 16,0')
            meta.append(r.mn)
    src = os.path.join(out, 'asm.s')
    open(src, 'w').write('\n'.join(L) + '\n')
    obj = os.path.join(out, 'asm.o')
    res = subprocess.run([os.path.join(TOOLS, 'h8300-elf-as'), src, '-o', obj], capture_output=True, text=True)
    if res.returncode:
        print(res.stderr[:3000])
        sys.exit(1)
    elf = os.path.join(out, 'asm.elf')
    # link (at 0) so that operands gas leaves to relocations (@@aa:8, @@vec:7, ...) are filled in
    subprocess.run([os.path.join(TOOLS, 'h8300-elf-ld'), '-m', emul, '-Ttext=0', '-e', '_start', '--no-relax',
                    obj, '-o', elf], check=True)
    subprocess.run([os.path.join(TOOLS, 'h8300-elf-objcopy'), '-O', 'binary', '-j', '.text', elf,
                    os.path.join(out, 'asm.bin')], check=True)
    open(os.path.join(out, 'asm.txt'), 'w').write('\n'.join(meta) + '\n')
    print('%s: %d forms, %d slots' % (lang, len(rows), len(meta)))


if __name__ == '__main__':
    main()
