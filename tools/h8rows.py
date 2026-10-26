"""Row model for the H8SX instruction-code table (parsed from the Renesas H8SX Family Software
Manual, Table 2.2) and helpers shared by the SLEIGH generator and the tests.

A row is a list of 16-bit units.  Opcode units carry fixed bits and named fields; extension
units (EA extension, immediates) are whole 16-bit words named 'd', 'a' or 'x'.  Each operand of
the mnemonic consumes the bits of one name ('d' displacement, 'a' absolute address, 'x'
immediate, 'v' vector, register names) in unit order.
"""
import json, re

REGNAMES = ('rs', 'rd', 'rn', 'rm', 'r')


class Unit:
    def __init__(self, kind, fields=None, name=None):
        self.kind = kind          # 'op' or 'ext'
        self.fields = fields or []  # [(msb, width, value|name)]
        self.name = name          # ext name

    def fixed_mask(self):
        m = v = 0
        for msb, w, val in self.fields:
            if isinstance(val, int):
                lsb = msb - w + 1
                m |= ((1 << w) - 1) << lsb
                v |= val << lsb
        return m, v


def split_ops(s):
    out, cur, depth = [], '', 0
    for ch in s:
        if ch == '(':
            depth += 1
        if ch == ')':
            depth -= 1
        if ch == ',' and depth == 0:
            out.append(cur)
            cur = ''
        else:
            cur += ch
    if cur:
        out.append(cur)
    return [o.strip() for o in out]


class Operand:
    """One operand of a row.  kind and parameters describe how it decodes and displays."""
    def __init__(self, text):
        self.text = text
        self.kind = None
        self.p = {}
        self.bits = {}   # name -> list of (unit_index, msb, width) consumed, in order

    def __repr__(self):
        return 'Operand(%s %s %s)' % (self.text, self.kind, self.p)


def classify(text, size):
    """Return (kind, params) for an operand text.  size: 'B','W','L' or None."""
    t = text.replace('−', '-')
    m = re.fullmatch(r'#(\d+)', t)
    if m:
        return 'fixedimm', {'v': int(m.group(1))}
    m = re.fullmatch(r'#xx?:(\d+)', t)
    if m:
        return 'imm', {'w': int(m.group(1))}
    if t in ('CCR', 'EXR', 'VBR', 'SBR', 'MACH', 'MACL'):
        return 'creg', {'r': t.lower()}
    if t == '@SP+':
        return 'sppost', {}
    if t == '@-SP':
        return 'sppre', {}
    m = re.fullmatch(r'\(ERn-ERn\+(\d)\)', t)
    if m:
        return 'reglist', {'n': int(m.group(1)) + 1}
    m = re.fullmatch(r'(E?R)([sdnm])(\.[BWL])?', t)
    if m:
        pre, r, sfx = m.groups()
        if sfx:   # BRA Rn.B etc: index register
            return 'pcidx', {'r': 'r' + r, 'ix': sfx[1]}
        if pre == 'ER':
            return 'reg', {'r': 'r' + r, 'sz': 'L'}
        return 'reg', {'r': 'r' + r, 'sz': size}
    m = re.fullmatch(r'@ER([sdnm])', t)
    if m:
        return 'ind', {'r': 'r' + m.group(1)}
    m = re.fullmatch(r'@ER([sdnm])\+', t)
    if m:
        return 'postinc', {'r': 'r' + m.group(1)}
    m = re.fullmatch(r'@ER([sdnm])-', t)
    if m:
        return 'postdec', {'r': 'r' + m.group(1)}
    m = re.fullmatch(r'@\+ER([sdnm])', t)
    if m:
        return 'preinc', {'r': 'r' + m.group(1)}
    m = re.fullmatch(r'@-ER([sdnm])', t)
    if m:
        return 'predec', {'r': 'r' + m.group(1)}
    m = re.fullmatch(r'@\(d:(2|16|32),ER([sdnm])\)', t)
    if m:
        return 'disp', {'w': int(m.group(1)), 'r': 'r' + m.group(2)}
    m = re.fullmatch(r'@\(d:(16|32),E?R([sdnm])\.([BWL])\)', t)
    if m:
        return 'idx', {'w': int(m.group(1)), 'r': 'r' + m.group(2), 'ix': m.group(3)}
    m = re.fullmatch(r'@aa:(8|16|24|32)', t)
    if m:
        return 'abs', {'w': int(m.group(1))}
    if t == '@@aa:8':
        return 'memind', {}
    if t == '@@vec:7':
        return 'vecind', {}
    m = re.fullmatch(r'd:(8|16)(\(.*\))?', t)
    if m:
        return 'rel', {'w': int(m.group(1))}
    m = re.fullmatch(r'@\(d:(16|32),(.*)\.([BW])\)', t)
    if m:   # MOVA: @(d:16,<EA>.B)
        inner_kind, inner_p = classify(m.group(2), None)
        return 'mova', {'w': int(m.group(1)), 'ik': inner_kind, 'ip': inner_p, 'ix': m.group(3)}
    raise ValueError('unknown operand ' + text)


class Row:
    def __init__(self, rec):
        self.rec = rec
        mn = re.sub(r'\s*\(B[A-Z]+ d:\d+\)', '', rec['mn'])
        mn = mn.replace('*', '').strip()
        self.mn = mn
        op, _, args = mn.partition(' ')
        self.op = op
        base, _, sz = op.partition('.')
        self.base = base
        self.size = sz or None
        self.args = split_ops(args) if args else []
        self.units = []
        wc = rec['wordcols']
        for ci, w in zip(wc, rec['words']):
            fl = []
            for f in w:
                f = tuple(f)
                if fl and isinstance(f[2], str) and fl[-1][2] == f[2] and fl[-1][0] - fl[-1][1] == f[0] \
                        and f[2] not in ('d', 'a', 'x', 'v', 'D'):
                    fl[-1] = (fl[-1][0], fl[-1][1] + f[1], f[2])
                else:
                    fl.append(f)
            self.units.append(Unit('op', fl))
            for e in rec['ext'].get(str(ci), []):
                self.units.append(Unit('ext', name=e))
        self.operands = []
        for a in self.args:
            o = Operand(a)
            o.kind, o.p = classify(a, self.size)
            if self.base.split('/')[0] in ('RTS', 'RTE') and o.kind == 'reg':
                o.kind, o.p = 'reglist', {'n': 1}
            if self.base.startswith('MOVA') and o.kind == 'idx':
                o.kind, o.p = 'mova', {'w': o.p['w'], 'ik': 'reg', 'ip': {'r': o.p['r'], 'sz': o.p['ix']},
                                       'ix': o.p['ix']}
            self.operands.append(o)
        self.assign_bits()

    # ------------------------------------------------------------------
    def bitsource(self):
        """Ordered list of (name, unit_index, msb, width) for every named field and ext unit."""
        src = []
        for ui, u in enumerate(self.units):
            if u.kind == 'op':
                for msb, w, v in u.fields:
                    if isinstance(v, str):
                        src.append((v, ui, msb, w))
            else:
                src.append((u.name, ui, 15, 16))
        return src

    def assign_bits(self):
        pool = {}
        for name, ui, msb, w in self.bitsource():
            n = {'D': 'd'}.get(name, name)
            pool.setdefault(n, []).append([ui, msb, w])
        self.pool = pool
        # order in which operands consume 'd', 'a', 'x' bits: src before dst, inner before outer
        # (MOVA), immediates last for ALU immediate-to-memory except where the immediate precedes
        # (MOV #imm,@EA keeps its immediate before the EA: handled by unit order of the pool)
        for name in ('d', 'a', 'x', 'v'):
            need = []
            for o in self.operands:
                for nm, w, key in self.needs(o):
                    if nm == name:
                        need.append((o, w, key))
            if not need:
                continue
            items = pool.get(name, [])
            # sort operands' needs by where their bits are: explicit assignment rules
            self._consume(name, need, items)
        # registers
        for o in self.operands:
            r = o.p.get('r')
            if o.kind == 'reglist':
                lastname = 'rn+%d' % (o.p['n'] - 1)
                if lastname in pool:
                    o.p['field_is_last'] = True
                    o.bits['reg'] = pool[lastname][0]
                    continue
                r = 'rn'
            if o.kind == 'mova':
                r = o.p['ip'].get('r')
            if r and r.startswith('r') and len(r) == 2:
                if r in pool:
                    o.bits['reg'] = pool[r][0]
                elif 'r' in pool:
                    o.bits['reg'] = pool['r'][0]
                elif r == 'rd' and 'rs' in pool and self.base in ('XX',):
                    pass

    def needs(self, o):
        k, p = o.kind, o.p
        if k == 'imm':
            return [('x', p['w'], 'x')]
        if k in ('disp', 'idx', 'rel'):
            return [('d', p['w'], 'd')]
        if k == 'abs':
            return [('a', p['w'], 'a')]
        if k == 'memind':
            return [('a', 8, 'a')]
        if k == 'vecind':
            return [('v', 7, 'v')]
        if k == 'mova':
            inner = Operand(o.text)
            inner.kind, inner.p = p['ik'], p['ip']
            return [(n, w, 'd_inner' if n == 'd' else k2) for n, w, k2 in self.needs(inner)] + [('d', p['w'], 'd_outer')]
        return []

    def _consume(self, name, need, items):
        """Give each operand its bits: fields inside opcode words go to the short forms (d:2, d:8,
        #xx:3..8, aa:8, vec:7, and the top byte of aa:24), whole extension words to the 16/32-bit
        ones; within each group in unit order."""
        opc = [list(c) for c in items if self.units[c[0]].kind == 'op']
        ext = [list(c) for c in items if self.units[c[0]].kind == 'ext']

        def take(pool, w, stop7=False):
            got = []
            have = 0
            while pool and have < w:
                ui, msb, cw = pool[0]
                if stop7 and got and ui != got[-1][0]:
                    break
                if have + cw <= w:
                    got.append((ui, msb, cw))
                    have += cw
                    pool.pop(0)
                else:
                    t = w - have
                    got.append((ui, msb, t))
                    pool[0] = [ui, msb - t, cw - t]
                    have += t
            return got, have
        for o, w, key in need:
            if w == 24:
                g1, h1 = take(opc, 8)
                g2, h2 = take(ext, 16)
                got, have = g1 + g2, h1 + h2
            elif w >= 16:
                got, have = take(ext, w)
            else:
                got, have = take(opc, w, stop7=(o.kind == 'rel'))
            o.bits.setdefault(key, []).extend(got)
            o.bits[key + '_w'] = have
        if opc or ext:
            raise ValueError('%s: unconsumed %s bits %s %s' % (self.mn, name, opc, ext))

    def nunits(self):
        return len(self.units)


def load_rows(path):
    return [Row(r) for r in json.load(open(path))]


# ----------------------------------------------------------------------------------------
# encoding helpers for tests
def put_bits(words, ui, msb, w, val):
    lsb = msb - w + 1
    words[ui] |= (val & ((1 << w) - 1)) << lsb


def encode(row, vals):
    """vals: dict operand-index -> {'reg': n, 'd': v, 'a': v, 'x': v, 'v': v}.  Returns bytes."""
    words = [0] * len(row.units)
    for ui, u in enumerate(row.units):
        if u.kind == 'op':
            m, v = u.fixed_mask()
            words[ui] |= v
    for i, o in enumerate(row.operands):
        ov = vals.get(i, {})
        for name in ('d', 'a', 'x', 'v', 'd_inner', 'd_outer'):
            if name in o.bits and name in ov:
                chunks = o.bits[name]
                total = sum(c[2] for c in chunks)
                val = ov[name]
                shift = total
                for ui, msb, w in chunks:
                    shift -= w
                    put_bits(words, ui, msb, w, val >> shift)
        if 'reg' in o.bits and 'reg' in ov:
            ui, msb, w = o.bits['reg']
            put_bits(words, ui, msb, w, ov['reg'])
    return b''.join(x.to_bytes(2, 'big') for x in words)
