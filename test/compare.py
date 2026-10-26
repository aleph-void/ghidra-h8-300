#!/usr/bin/env python3
"""Compare slot disassembly: Ghidra (DumpSlots.java) against GNU objdump (slotdis) and, for the
table corpus, against the manual's code table (tools/h8table.py).

  compare.py <core> <mode> <slot.bin> <ghidra.txt> <objdump.txt> > report
  mode: normal | advanced24 | middle | advanced | maximum (sets the program-address width)

Prints one line per difference class with counts and examples, then a summary:
  compared N: exact E, semantic S, both-invalid B, explained X, unexplained U
Exit status 1 when U > 0.
"""
import collections
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'tools'))
from h8rows import load_rows  # noqa: E402
import h8variants  # noqa: E402
from h8table import Matcher, decode_vals, render  # noqa: E402
import explain  # noqa: E402

SLOT = 16


def load(path):
    d = {}
    for line in open(path):
        parts = line.rstrip('\n').split(' ', 2)
        if len(parts) < 2:
            continue
        off = int(parts[0], 16)
        n = int(parts[1])
        t = parts[2] if len(parts) > 2 else ''
        d[off] = (n, t)
    return d


def norm_od(t):
    t = re.sub(r'\s+', ' ', t).strip()
    t = re.sub(r'\.[+-]?\d+ \((0x[0-9a-f]+)\)', r'\1', t)
    t = re.sub(r'0xffffffff([0-9a-f]{8})\b', r'0x\1', t)
    t = re.sub(r'@@(\d+) \((0x[0-9a-f]+)\)', r'@@\2', t)
    return t


def norm_g(t):
    t = re.sub(r'\s+', ' ', t).strip()
    t = re.sub(r'0x0+([0-9a-f])', r'0x\1', t)
    return t


def semantic(t):
    """Spelling-insensitive form: drop operand-size suffixes objdump leaves out."""
    m = t.split(' ', 1)
    mn = m[0]
    mn = re.sub(r'\.[bwl]$', '', mn)
    ops = m[1] if len(m) > 1 else ''
    ops = ops.replace('0x', '')
    return mn + ' ' + ops


def main():
    core, mode, binf, gf, of = sys.argv[1:6]
    expect = None
    if '--expect' in sys.argv:
        expect = [l.rstrip('\n') for l in open(sys.argv[sys.argv.index('--expect') + 1])]
    pmask = {'normal': 0xffff, 'advanced24': 0xffffff, 'middle': 0xffffff, 'advanced': 0xffffff,
             'maximum': 0xffffffff}[mode]
    explain.setup(core, mode)
    data = open(binf, 'rb').read()
    G = load(gf)
    O = load(of)
    rows = [r for r in load_rows(os.path.join(HERE, '..', 'tools', 'h8sx_codes.json')) if h8variants.member(core, r)]
    M = Matcher(rows, core)
    cnt = collections.Counter()
    ex = collections.defaultdict(list)
    tcnt = collections.Counter()
    tex = collections.defaultdict(list)
    cnt2 = collections.Counter()
    ecnt = collections.Counter()
    eex = []
    for off in sorted(G):
        gn, gt = G[off]
        on, ot = O.get(off, (0, '(bad)'))
        slot = data[off:off + SLOT]
        gt = norm_g(gt) if gn else 'BAD'
        ot = norm_od(ot) if on and not ot.startswith('.word') else 'BAD'
        if ot.startswith('(bad)'):
            ot = 'BAD'
        # manual table decode
        row = M.match(slot)
        mt = render(row, decode_vals(row, slot), off + 2 * len(row.units), core, pmask) if row else 'BAD'
        mn = 2 * len(row.units) if row else 0
        if mt != 'BAD':
            mt = norm_g(mt)
        if expect is not None:
            want = expect[off // SLOT] if off // SLOT < len(expect) else None
            if row is not None and want is not None and row.mn == want:
                ecnt['same'] += 1
            else:
                ecnt['different'] += 1
                if len(eex) < 10:
                    eex.append('%08x %s | written as %s | table row %s' % (off, slot.hex(), want, row.mn if row else None))
        # Ghidra vs manual table
        if gt == mt and (gn == mn or gt == 'BAD'):
            tcnt['agree'] += 1
        else:
            key = 'G=%s T=%s' % (gt.split(' ')[0], mt.split(' ')[0])
            tcnt[key] += 1
            if len(tex[key]) < 4:
                tex[key].append('%08x %s | G[%d] %s | T[%d] %s' % (off, slot.hex(), gn, gt, mn, mt))
        # Ghidra vs objdump
        if gt == 'BAD' and ot == 'BAD':
            cnt['both-invalid'] += 1
            continue
        if gt == ot and gn == on:
            cnt['exact'] += 1
            continue
        if gt != 'BAD' and ot != 'BAD' and semantic(gt) == semantic(ot) and gn == on:
            cnt['semantic'] += 1
            k2 = 'semantic: %s / %s' % (gt.split(' ')[0], ot.split(' ')[0])
            if len(ex[k2]) < 1:
                ex[k2].append('%08x %s | G[%d] %s | O[%d] %s' % (off, slot.hex(), gn, gt, on, ot))
            cnt2[k2] += 1
            continue
        explain.explain_off[0] = off
        cls = explain.classify(core, slot, gt, gn, ot, on, row)
        cnt[cls] += 1
        if len(ex[cls]) < 6:
            ex[cls].append('%08x %s | G[%d] %s | O[%d] %s' % (off, slot.hex(), gn, gt, on, ot))
    total = sum(cnt.values())
    unexp = sum(v for k, v in cnt.items() if k.startswith('UNEXPLAINED'))
    print('== Ghidra vs objdump')
    for k, v in sorted(cnt.items(), key=lambda kv: -kv[1]):
        print('%8d  %s' % (v, k))
        for e in ex.get(k, []):
            print('          ' + e)
    print('== semantic matches by spelling')
    for k, v in sorted(cnt2.items(), key=lambda kv: -kv[1]):
        print('%8d  %s   %s' % (v, k, ex[k][0] if ex[k] else ''))
    print('== Ghidra vs manual table')
    for k, v in sorted(tcnt.items(), key=lambda kv: -kv[1]):
        print('%8d  %s' % (v, k))
        for e in tex.get(k, []):
            print('          ' + e)
    tdis = sum(v for k, v in tcnt.items() if k != 'agree')
    if expect is not None:
        print('== assembler encoding vs the manual row the line was written from: %d same, %d different'
              % (ecnt['same'], ecnt['different']))
        for e in eex:
            print('          ' + e)
    print('compared %d: exact %d, semantic %d, both-invalid %d, explained %d, unexplained %d; '
          'manual table: agree %d, differ %d'
          % (total, cnt['exact'], cnt['semantic'], cnt['both-invalid'],
             total - cnt['exact'] - cnt['semantic'] - cnt['both-invalid'] - unexp, unexp,
             tcnt['agree'], tdis))
    sys.exit(1 if unexp or tdis or ecnt['different'] else 0)


if __name__ == '__main__':
    main()
