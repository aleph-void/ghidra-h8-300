"""Decode bytes with the manual's code table (independent of the SLEIGH) and render the result in
GNU objdump's H8 syntax.  Used by the tests as the "manual" oracle."""
import random

from h8rows import Operand

BREG = ['r%dh' % i for i in range(8)] + ['r%dl' % i for i in range(8)]
WREG = ['r%d' % i for i in range(8)] + ['e%d' % i for i in range(8)]
SZ = {'B': 1, 'W': 2, 'L': 4}
KEYS = ('d', 'a', 'x', 'v', 'd_inner', 'd_outer')


def sext(v, w):
    return v - (1 << w) if (v >> (w - 1)) & 1 else v


def random_vals(row, rnd, core):
    vals = {}
    for i, o in enumerate(row.operands):
        v = {}
        for nm in KEYS:
            if nm in o.bits:
                w = o.bits[nm + '_w']
                v[nm] = rnd.getrandbits(w)
                if (o.kind == 'disp' and o.p['w'] == 2 and nm == 'd') or \
                        (o.kind == 'mova' and o.p['ik'] == 'disp' and o.p['ip']['w'] == 2 and nm == 'd_inner'):
                    v[nm] = rnd.randint(1, 3)
                if o.kind == 'imm' and w == 3 and not row.base.startswith('B'):
                    v[nm] = rnd.randint(1, 7)
                if o.kind == 'rel' and w == 16 and nm == 'd':
                    v[nm] &= ~1     # odd 16-bit displacements: see GHIDRA-RARE.md
        if 'reg' in o.bits:
            w = o.bits['reg'][2]
            v['reg'] = rnd.getrandbits(w)
            if core in ('300', '300l') and w == 4 and o.kind == 'reg' and (o.p.get('sz') or 'B') == 'W':
                v['reg'] &= 7
        vals[i] = v
    return vals


def decode_vals(row, data):
    words = [int.from_bytes(data[2 * i:2 * i + 2], 'big') for i in range(len(row.units))]
    vals = {}
    for i, o in enumerate(row.operands):
        v = {}
        for nm in KEYS:
            if nm in o.bits:
                x = 0
                for ui, msb, w in o.bits[nm]:
                    lsb = msb - w + 1
                    x = (x << w) | ((words[ui] >> lsb) & ((1 << w) - 1))
                v[nm] = x
        if 'reg' in o.bits:
            ui, msb, w = o.bits['reg']
            v['reg'] = (words[ui] >> (msb - w + 1)) & ((1 << w) - 1)
        vals[i] = v
    return vals


class Matcher:
    def __init__(self, rows, core='sx'):
        self.core = core
        self.rows = rows
        self.index = {}
        for r in rows:
            ms = [u.fixed_mask() if u.kind == 'op' else (0, 0) for u in r.units]
            m0, v0 = ms[0]
            self.index.setdefault(m0, {}).setdefault(v0, []).append((r, ms, sum(bin(m).count('1') for m, v in ms)))

    def match(self, data):
        best = None
        w0 = int.from_bytes(data[0:2], 'big')
        cands = []
        for m0, byv in self.index.items():
            cands.extend(byv.get(w0 & m0, ()))
        for r, ms, nfix in cands:
            if len(data) < 2 * len(ms):
                continue
            ok = True
            for i, (m, v) in enumerate(ms):
                if m and (int.from_bytes(data[2 * i:2 * i + 2], 'big') & m) != v:
                    ok = False
                    break
            if ok and valid(r, data, self.core) and (best is None or nfix > best[1]):
                best = (r, nfix)
        return best[0] if best else None


def valid(row, data, core='sx'):
    """Field-value restrictions the manuals state in prose."""
    vals = decode_vals(row, data)
    for i, o in enumerate(row.operands):
        v = vals[i]
        if core in ('300', '300l') and 'reg' in v and o.bits['reg'][2] == 4 and v['reg'] >= 8 and \
                (o.kind == 'reg' and (o.p.get('sz') or 'B') == 'W' or
                 row.base in ('DIVXU', 'MULXU') and o is row.operands[-1]):
            return False     # the H8/300 has no E registers
        if o.kind == 'imm' and o.p['w'] == 3 and not row.base.startswith('B') and v.get('x') == 0:
            return False     # #xx:3 is 1-7 (section 2.2: "#x:3(1-7)")
        if o.kind == 'reglist':
            f = v['reg'] & 7
            n = o.p['n']
            lo = f - (n - 1) if o.p.get('field_is_last') else f
            if lo < 0 or lo + n - 1 > 7:
                return False
            if core != 'sx' and n > 1 and lo % (2 if n == 2 else 4) != 0:
                return False     # H8S register lists: ER0-ER1, ..., ER0-ER2, ER4-ER6, ER0-ER3, ER4-ER7
    return True


def render_operand(row, o, v, pc_next, core, pmask=0xffffffff):
    h300 = core in ('300', '300l')
    k, p = o.kind, o.p

    def areg(n):
        return ('r%d' if h300 else 'er%d') % (n & 7)
    if k == 'fixedimm':
        return '#%d' % p['v']
    if k == 'imm':
        return '#0x%x' % v['x']
    if k == 'creg':
        return p['r']
    if k == 'sppost':
        return '@sp+'
    if k == 'sppre':
        return '@-sp'
    if k == 'reglist':
        f = v['reg'] & 7
        n = p['n']
        lo = f - (n - 1) if p.get('field_is_last') else f
        return 'er%d' % lo if n == 1 else 'er%d-er%d' % (lo, lo + n - 1)
    if k == 'reg':
        sz = p['sz'] or 'B'
        if row.base in ('DIVXS', 'DIVXU', 'MULXS', 'MULXU') and o is row.operands[-1]:
            sz = {'B': 'W', 'W': 'L'}[row.size]
        if row.base in ('JMP', 'JSR'):
            sz = 'L'
        if row.base in ('SHLL', 'SHLR') and len(row.operands) == 2 and o is row.operands[0]:
            sz = 'B'
        if sz == 'B':
            return BREG[v['reg']]
        if sz == 'W':
            return WREG[v['reg']]
        return areg(v['reg'])
    if k == 'pcidx':
        n = v['reg'] & 7
        return {'B': 'r%dl.b' % n, 'W': 'r%d.w' % n, 'L': 'er%d' % n}[p['ix']]
    if k == 'ind':
        return '@' + areg(v['reg'])
    if k == 'postinc':
        return '@' + areg(v['reg']) + '+'
    if k == 'postdec':
        return '@' + areg(v['reg']) + '-'
    if k == 'preinc':
        return '@+' + areg(v['reg'])
    if k == 'predec':
        return '@-' + areg(v['reg'])
    if k == 'disp':
        d = v['d']
        if p['w'] == 2:
            d *= SZ[row.size or 'B']
        return '@(0x%x:%d,%s)' % (d, p['w'], areg(v['reg']))
    if k == 'idx':
        n = v['reg'] & 7
        ix = {'B': 'r%dl.b' % n, 'W': 'r%d.w' % n, 'L': 'er%d.l' % n}[p['ix']]
        return '@(0x%x:%d,%s)' % (v['d'], p['w'], ix)
    if k == 'abs':
        return '@0x%x:%d' % (v['a'], p['w'])
    if k == 'memind':
        return '@@0x%x' % v['a']
    if k == 'vecind':
        a = (0x80 + v['v']) * (2 if pmask == 0xffff else 4)
        return '@@0x%x' % a
    if k == 'rel':
        w = o.bits['d_w']
        d = v['d']
        d = sext(d << 1, 8) if w == 7 else sext(d, w)
        return '0x%x' % ((pc_next + d) & pmask)
    if k == 'mova':
        p2 = p['ip']
        if p['ik'] == 'reg':
            if o.bits['reg'][2] == 4:
                s = BREG[v['reg']] if p['ix'] == 'B' else WREG[v['reg']]
            else:
                n = v['reg'] & 7
                s = 'r%dl' % n if p['ix'] == 'B' else 'r%d' % n
        else:
            inner = Operand(o.text)
            inner.kind, inner.p, inner.bits = p['ik'], p2, o.bits
            iv = dict(v)
            if 'd_inner' in v:
                iv['d'] = v['d_inner']
            s = render_operand(row, inner, iv, pc_next, core, pmask)
            if inner.kind == 'disp' and p2['w'] == 2:
                s = '@(0x%x:2,%s)' % (iv['d'] * SZ[p['ix']], areg(v['reg']))
        return '@(0x%x:%d,%s.%s)' % (v['d_outer'], p['w'], s, p['ix'].lower())
    return '?' + k


def render(row, vals, pc_next, core, pmask=0xffffffff):
    ops = [render_operand(row, o, vals.get(i, {}), pc_next, core, pmask) for i, o in enumerate(row.operands)]
    return (row.op.lower() + (' ' + ','.join(ops) if ops else '')).strip()
