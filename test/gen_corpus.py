#!/usr/bin/env python3
"""Decode corpora for the H8 differential tests (16-byte slots, zero padded).

  gen_corpus.py <core> <outdir> [seed]
    table.bin  every row of the core's manual code table, several random instances each
               (table.txt: the row each slot was made from, and its expected text)
    fuzz.bin   random slots: half fully random, half starting with a first word taken from the
               table (random field bits) so that prefixed H8SX forms are reached
    enum.bin   every first word 0000-FFFF with two random tails
"""
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'tools'))
from h8rows import load_rows, encode  # noqa: E402
import h8variants  # noqa: E402
from h8table import Matcher, random_vals  # noqa: E402

SLOT = 16


def main():
    core, out = sys.argv[1], sys.argv[2]
    seed = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    rnd = random.Random(seed)
    rows = [r for r in load_rows(os.path.join(HERE, '..', 'tools', 'h8sx_codes.json')) if h8variants.member(core, r)]
    os.makedirs(out, exist_ok=True)
    per = {'300': 24, '300l': 24, '300h': 16, 'h8s': 16, 'sx': 4}[core]
    blob = bytearray()
    meta = []
    for r in rows:
        for k in range(per):
            vals = random_vals(r, rnd, core)
            b = encode(r, vals)
            meta.append(r.mn)
            blob += b + bytes(SLOT - len(b))
    open(os.path.join(out, 'table.bin'), 'wb').write(blob)
    open(os.path.join(out, 'table.txt'), 'w').write('\n'.join(meta) + '\n')
    # first words of the table, with field bits free
    firsts = []
    for r in rows:
        u = r.units[0]
        m, v = u.fixed_mask()
        firsts.append((m, v))
    fz = bytearray()
    for i in range(50000):
        b = bytearray(rnd.getrandbits(8) for _ in range(SLOT))
        if i % 2:
            m, v = rnd.choice(firsts)
            w = (rnd.getrandbits(16) & ~m) | v
            b[0:2] = w.to_bytes(2, 'big')
            if rnd.random() < 0.5 and len(rows) > 0:
                # second word from a row with the same first word
                cands = [r for r in rows if len(r.units) > 1 and r.units[0].kind == 'op'
                         and (w & r.units[0].fixed_mask()[0]) == r.units[0].fixed_mask()[1]
                         and r.units[1].kind == 'op']
                if cands:
                    m2, v2 = rnd.choice(cands).units[1].fixed_mask()
                    w2 = (rnd.getrandbits(16) & ~m2) | v2
                    b[2:4] = w2.to_bytes(2, 'big')
        fz += b
    open(os.path.join(out, 'fuzz.bin'), 'wb').write(fz)
    en = bytearray()
    for w in range(0x10000):
        for t in range(2):
            b = bytearray(rnd.getrandbits(8) for _ in range(SLOT))
            b[0:2] = w.to_bytes(2, 'big')
            en += b
    open(os.path.join(out, 'enum.bin'), 'wb').write(en)
    print('%s: %d table slots (%d rows), 50000 fuzz, %d enum' % (core, len(meta), len(rows), 0x20000))


if __name__ == '__main__':
    main()
