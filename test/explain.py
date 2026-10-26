"""Difference classes between Ghidra and GNU objdump 2.45 that are explained (GHIDRA-RARE.md has
the evidence for each).  classify() returns a class name; unrecognised differences start with
UNEXPLAINED and fail the test.

Ghidra follows the manual's code table (tools/h8sx_codes.json) exactly, so every difference is
checked against that table here:
  * reserved bits: objdump decodes a slot that no table row matches, but a row of the same
    instruction matches when 1-3 bits the table fixes are ignored -> the manual reserves those
    encodings and objdump does not check the bits;
  * not in this core: the slot is a row of the H8SX table that the core's own manual does not
    list (objdump's h8300/h8300h/h8300s modes still decode H8SX instructions);
  * register lists below ER0: objdump prints "er-2-er0" for LDM/RTS/L/RTE/L fields the manual
    leaves undefined;
  * odd 16-bit branch displacement: objdump rejects it, the table lists all 16 bits;
  * branch-address width: Ghidra wraps branch targets to the mode's program-address width
    (16 bits in normal mode, 24 in middle/advanced), objdump prints 32-bit sums.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'tools'))
from h8rows import load_rows  # noqa: E402
import h8variants  # noqa: E402
from h8table import decode_vals, render  # noqa: E402

_ALL = None
_CORE = None
_MODE = None
_PMASK = None


def setup(core, mode):
    global _ALL, _CORE, _MODE, _PMASK
    _CORE, _MODE = core, mode
    _PMASK = {'normal': 0xffff, 'advanced24': 0xffffff, 'middle': 0xffffff, 'advanced': 0xffffff,
              'maximum': 0xffffffff}[mode]
    if _ALL is None:
        rows = [r for r in load_rows(os.path.join(HERE, '..', 'tools', 'h8sx_codes.json'))
                if r.mn not in h8variants.ALIASES]
        _ALL = []
        for r in rows:
            ms = [u.fixed_mask() if u.kind == 'op' else (0, 0) for u in r.units]
            _ALL.append((r, ms))


def _words(slot, n):
    return [int.from_bytes(slot[2 * i:2 * i + 2], 'big') for i in range(n)]


def nearest(slot, mnem, length, otext=None, off=0):
    """Rows with objdump's mnemonic and length that render objdump's text from this slot,
    ordered by how many of their fixed bits the slot breaks; returns the best of those as
    (mismatches, row, bits, True), or the best row by mismatches alone with False."""
    cands = []
    for r, ms in _ALL:
        op = r.op.lower()
        if op != mnem and op.split('.')[0] != mnem:
            continue
        if 2 * len(ms) != length:
            continue
        ws = _words(slot, len(ms))
        diff = []
        for i, (m, v) in enumerate(ms):
            x = (ws[i] & m) ^ v
            for b in range(16):
                if x >> b & 1:
                    diff.append('w%d.b%d' % (i + 1, b))
        cands.append((len(diff), r, diff))
    if not cands:
        return (99, None, None, False)
    cands.sort(key=lambda c: c[0])
    if otext is not None:
        for c in cands:
            try:
                core = _CORE if h8variants.member(_CORE, c[1]) else 'sx'
                t = render(c[1], decode_vals(c[1], slot), off + length, core, _PMASK)
            except Exception:
                continue
            if _same(t, otext):
                return c + (True,)
    return cands[0] + (False,)


def _same(a, b):
    a = re.sub(r'^(\S+?)\.[bwl] ', r'\1 ', a)
    b = re.sub(r'^(\S+?)\.[bwl] ', r'\1 ', b)
    if _CORE in ('300', '300l'):
        a = re.sub(r'\ber(\d)', r'r\1', a)
        b = re.sub(r'\ber(\d)', r'r\1', b)
    if _MODE == 'normal':
        # objdump's @@vec:7 in normal mode: 4-byte vectors (a known objdump bug, see classify)
        ma, mb = re.search(r'@@0x([0-9a-f]+)', a), re.search(r'@@0x([0-9a-f]+)', b)
        if ma and mb and int(mb.group(1), 16) == 2 * int(ma.group(1), 16):
            a, b = a[:ma.start()], b[:mb.start()]
    # a branch displacement whose reserved LSB is set: compare all but the target
    if re.match(r'b(ra|sr)/b[sc] ', a) and a.rsplit(',', 1)[0] == b.rsplit(',', 1)[0]:
        return True
    return a == b


def table_row(slot):
    """Exact match against the full H8SX table (any core)."""
    best = None
    for r, ms in _ALL:
        if 2 * len(ms) > len(slot):
            continue
        ws = _words(slot, len(ms))
        if all((ws[i] & m) == v for i, (m, v) in enumerate(ms)):
            nfix = sum(bin(m).count('1') for m, v in ms)
            if best is None or nfix > best[1]:
                best = (r, nfix)
    return best[0] if best else None


explain_off = [0]


def classify(core, slot, gt, gn, ot, on, row):
    if gt == 'BAD':
        if ot == 'bpt':
            return 'objdump-only "bpt" (7AFF, a GNU simulator breakpoint; not in the manual)'
        m = re.search(r'er(-?\d+)-er(\d+)', ot)
        if m and (int(m.group(1)) < 0 or int(m.group(2)) > 7 or int(m.group(2)) - int(m.group(1)) > 3):
            return 'objdump bug: register list the manual does not define (below ER0, past ER7 or more than four registers)'
        if core in ('300', '300l') and re.search(r'\be[0-7]\b', ot):
            return 'E0-E7 register objdump decodes in h8300 mode (the H8/300 has only R0-R7)'
        if core != 'sx':
            r = table_row(slot)
            if r is not None and not h8variants.member(core, r):
                return 'not in this core: a later core\'s form objdump decodes in %s mode' % core
        if core in ('h8s', '300h') and re.match(r'(ldm|stm)\.l ', ot):
            return 'register list the H8S does not allow (two: ER0-ER1/2-3/4-5/6-7, three: ER0-ER2/4-6, four: ER0-ER3/4-7)'
        res = nearest(slot, ot.split(' ')[0], on, ot, explain_off[0])
        if res[1] is not None and res[3] and 1 <= res[0] <= 8:
            if core != 'sx' and not h8variants.member(core, res[1]):
                return 'not in this core: a later core\'s form (with reserved bits set) objdump decodes in %s mode' % core
            return 'manual-reserved bits objdump ignores: %s %s' % (res[1].mn, ','.join(res[2]))
        return 'UNEXPLAINED objdump-only'
    if ot == 'BAD':
        if row is not None and row.base[0] == 'B' and any(o.kind == 'rel' and o.p['w'] == 16 for o in row.operands):
            return 'odd 16-bit branch displacement (objdump rejects it, the manual lists all 16 bits)'
        if row is not None and row.base in ('BSR', 'MOVSD') and any(o.kind == 'rel' and o.p['w'] == 16 for o in row.operands):
            return 'odd 16-bit branch displacement (objdump rejects it, the manual lists all 16 bits)'
        return 'UNEXPLAINED ghidra-only'
    if gn != on:
        return 'UNEXPLAINED length'
    if _MODE == 'normal' and re.match(r'(jmp|jsr) @@0x', gt) and gt.split('@@')[0] == ot.split('@@')[0]:
        g = int(gt.split('@@')[1], 16)
        o = int(ot.split('@@')[1], 16)
        if o == 2 * g and 0x100 <= g < 0x200:
            return 'objdump bug: @@vec:7 in normal mode uses 4-byte vectors (manual: H\'0100-H\'01FF, 2 bytes each)'
    # branch target width
    gm = re.findall(r'0x[0-9a-f]+', gt)
    om = re.findall(r'0x[0-9a-f]+', ot)
    if len(gm) == len(om) and re.sub(r'0x[0-9a-f]+', 'X', gt) == re.sub(r'0x[0-9a-f]+', 'X', ot):
        pm = {'normal': 0xffff, 'advanced24': 0xffffff, 'middle': 0xffffff, 'advanced': 0xffffff,
              'maximum': 0xffffffff}[_MODE]
        if all(a == b for a, b in zip(gm[:-1], om[:-1])) and int(gm[-1], 16) == (int(om[-1], 16) & pm):
            return 'branch address wrapped to the %s-mode program-address width' % _MODE
    return 'UNEXPLAINED text'
