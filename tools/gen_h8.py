#!/usr/bin/env python3
"""Generate the H8 SLEIGH specifications from the instruction-code table of the Renesas H8SX
Family Software Manual (REJ09B0102-0400, Table 2.2), parsed into tools/h8sx_codes.json by
parse_sx_table.py + clean_rows.py.

Every row of the table becomes one SLEIGH constructor whose bit pattern is exactly the row's
code.  The H8/300, H8/300H and H8S cores run a subset of the H8SX codes (the H8SX is object-code
compatible with them); the subsets are the rows listed in each core's own manual (VARIANT_FORMS
below).  Semantics come from the instruction descriptions of the same manuals.

usage: gen_h8.py [outdir]     (default: ../data/languages)
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from h8rows import load_rows, Operand  # noqa: E402
import h8variants  # noqa: E402

SZB = {'B': 1, 'W': 2, 'L': 4}
HMASK = {1: '0xf', 2: '0xfff', 4: '0xfffffff'}
BYTE_REGS = ['r%dh' % i for i in range(8)] + ['r%dl' % i for i in range(8)]
WORD_REGS = ['r%d' % i for i in range(8)] + ['e%d' % i for i in range(8)]
LONG_REGS = ['er%d' % i for i in range(8)]

# core -> (modes, description)
CORES = {
    '300': ['normal'],
    '300l': ['normal'],
    '300h': ['normal', 'advanced'],
    'h8s': ['normal', 'advanced'],
    'sx': ['normal', 'middle', 'advanced', 'maximum'],
}
# mode parameters: address-space size, return-address/vector size, address mask
MODE = {
    'normal': dict(asz=2, ptr=2, amask=0xffff),
    'advanced24': dict(asz=3, ptr=4, amask=0xffffff),
    'middle': dict(asz=3, ptr=4, amask=0xffffff),
    'advanced': dict(asz=4, ptr=4, amask=0xffffffff),
    'maximum': dict(asz=4, ptr=4, amask=0xffffffff),
}


def mode_key(core, mode):
    if mode == 'advanced' and core in ('300h', 'h8s'):
        return 'advanced24'
    return mode


class Gen:
    """Builds one constructor."""

    def __init__(self, g, row):
        self.g = g
        self.row = row
        self.core = g.core
        self.h300 = g.core == '300'
        self.cons = {}      # unit -> list of constraint strings
        self.span_subs = []  # (first, last, subname)
        self.action = []
        self.pre = []
        self.body = []
        self.ntmp = 0
        self.extra_cons = []
        self.lgroups = {}

    # ---------------------------------------------------------------- fields
    def field(self, ui, msb, w, role=''):
        name = 'u%d_%s%d_%d' % (ui + 1, role, msb, msb - w + 1)
        self.g.fields.setdefault(ui, {})[name] = (msb - w + 1, msb, role)
        return name

    def full(self, ui):
        self.g.fields.setdefault(ui, {})['u%d' % (ui + 1)] = (0, 15, '')
        return 'u%d' % (ui + 1)

    def value_expr(self, chunks):
        """Expression (disassembly action) for the concatenation of bit chunks."""
        merged = []
        for c in chunks:
            if merged and merged[-1][0] == c[0] and merged[-1][1] - merged[-1][2] == c[1]:
                merged[-1] = (c[0], merged[-1][1], merged[-1][2] + c[2])
            else:
                merged.append(tuple(c))
        chunks = merged
        units = sorted(set(c[0] for c in chunks))
        if len(units) == 2 and units[1] == units[0] + 1:
            # a value across two units: one field of a 32-bit token, so that values wider than
            # the address space are neither truncated in the display nor in p-code constants
            k = units[0]
            (u0, m0, w0), (u1, m1, w1) = chunks
            assert m0 - w0 + 1 == 0 and m1 == 15, chunks
            hi, lo = 16 + m0, 16 - w1
            name = 'l%d_%d_%d' % (k + 1, hi, lo)
            self.g.lfields.setdefault(k, {})[name] = (lo, hi, '')
            self.lgroups.setdefault(k, set()).add(name)
            return '(%s) + 0' % name
        parts = []
        total = sum(c[2] for c in chunks)
        shift = total
        for ui, msb, w in chunks:
            shift -= w
            if self.row.units[ui].kind == 'ext':
                f = self.full(ui)
            else:
                f = self.field(ui, msb, w)
            parts.append('(%s << %d)' % (f, shift) if shift else f)
        e = ' | '.join(parts)
        return '(%s) + 0' % e if len(parts) == 1 else e

    def valsym(self, name, chunks):
        """A display/p-code symbol for a value: the field itself when the value is one field (an
        action-defined symbol is printed at address-space width, which would cut 32-bit values
        in the 16- and 24-bit languages), else an action variable."""
        e = self.value_expr(chunks)
        m = re.fullmatch(r'\((\w+)\) \+ 0', e)
        if m:
            return m.group(1)
        self.action.append('%s = %s;' % (name, e))
        return name

    def tmp(self, base='t'):
        self.ntmp += 1
        return '%s%d' % (base, self.ntmp)

    # ---------------------------------------------------------------- registers
    def reg(self, o, role):
        ui, msb, w = o.bits['reg']
        if role == 'rl' or role == 'ra' or role == 'rlo' or role == 'rwo':
            # 3-bit register number; the 4th bit (if any) is a fixed bit in the table
            if w == 4:
                msb -= 1
                w = 3
        name = self.field(ui, msb, w, role)
        return name

    # ---------------------------------------------------------------- operands
    def operand(self, i, o, sz):
        """Return dict(disp=display, rd=read-expr, wr=fn(expr)->stmt, ea=addr-expr or None)."""
        k, p = o.kind, o.p
        g = self.g
        ASZ = '$(ASZ)'
        if k == 'fixedimm':
            return dict(disp='"#%d"' % p['v'], rd=str(p['v']), const=p['v'])
        if k == 'imm':
            v = self.valsym('imm%d' % i, o.bits['x'])
            if p['w'] == 3 and not self.row.base.startswith('B'):
                # "#x:3(1-7)": the value 0 is not an immediate of this form
                ch = o.bits['x']
                assert all(c[0] == ch[0][0] for c in ch) and sum(c[2] for c in ch) == 3
                self.extra_cons.append((ch[0][0], '%s!=0' % self.field(ch[0][0], ch[0][1], 3, 'c')))
            return dict(disp='"#"^%s' % v, rd=v, const=None)
        if k == 'creg':
            return dict(disp='"%s"' % p['r'], creg=p['r'])
        if k == 'reg':
            psz = p['sz'] or 'B'
            if self.row.base in ('DIVXS', 'DIVXU', 'MULXS', 'MULXU') and o is self.row.operands[-1]:
                psz = {'B': 'W', 'W': 'L'}[self.row.size]
            if self.row.base in ('SHLL', 'SHLR') and len(self.row.operands) == 2 and o is self.row.operands[0]:
                psz = 'B'   # shift count register: "it should be specified as an 8-bit register"
            role = {'B': 'rb', 'W': 'rw', 'L': 'rl'}[psz]
            if self.row.base in ('JMP', 'JSR'):
                role = 'ra'
            r = self.reg(o, role)
            return dict(disp=r, rd=r, wr=lambda e, r=r: '%s = %s;' % (r, e), reg=r, rsz=SZB[psz])
        if k == 'pcidx':
            role = {'B': 'rlo', 'W': 'rwo', 'L': 'ra'}[p['ix']]
            r = self.reg(o, role)
            sfx = {'B': '".b"', 'W': '".w"', 'L': ''}[p['ix']]
            return dict(disp=r + ('^' + sfx if sfx else ''), rd=r, idx=p['ix'])
        if k == 'reglist':
            ui, msb, w = o.bits['reg']
            pop = self.row.base.split('/')[0] in ('LDM', 'RTS', 'RTE')
            sub = g.reglist_sub(ui, msb, w, p['n'], bool(p.get('field_is_last')), pop, self)
            self.span_subs.append((ui, ui, sub))
            return dict(disp=sub, reglist=sub)
        if k in ('sppost', 'sppre'):
            sp = 'r7' if self.h300 else 'er7'
            return dict(disp='"@%s"' % ('sp+' if k == 'sppost' else '-sp'), sp=sp)
        if k in ('ind', 'postinc', 'postdec', 'preinc', 'predec', 'disp', 'idx'):
            return self.mem_operand(i, o, sz)
        if k in ('abs', 'memind', 'vecind', 'rel'):
            return self.span_operand(i, o, sz)
        if k == 'mova':
            return self.mova_operand(i, o)
        raise ValueError('operand kind ' + k)

    def areg(self, o):
        return self.reg(o, 'ra')

    def mem_operand(self, i, o, sz):
        k, p = o.kind, o.p
        ea = 'ea%d' % i
        if k == 'idx':
            role = {'B': 'rlo', 'W': 'rwo', 'L': 'ra'}[p['ix']]
            r = self.reg(o, role)
        else:
            r = self.areg(o)
        AW = '2' if self.h300 else '4'
        pre = []
        if k == 'ind':
            disp = '"@"^%s' % r
            pre.append('local %s_:%s = %s;' % (ea, AW, r))
        elif k == 'postinc':
            disp = '"@"^%s^"+"' % r
            pre.append('local %s_:%s = %s; %s = %s + %d;' % (ea, AW, r, r, r, sz))
        elif k == 'postdec':
            disp = '"@"^%s^"-"' % r
            pre.append('local %s_:%s = %s; %s = %s - %d;' % (ea, AW, r, r, r, sz))
        elif k == 'preinc':
            disp = '"@+"^%s' % r
            pre.append('%s = %s + %d; local %s_:%s = %s;' % (r, r, sz, ea, AW, r))
        elif k == 'predec':
            disp = '"@-"^%s' % r
            pre.append('%s = %s - %d; local %s_:%s = %s;' % (r, r, sz, ea, AW, r))
        elif k == 'disp':
            dv = 'd%d' % i
            w = p['w']
            if w == 2:
                self.action.append('%s = (%s) * %d;' % (dv, self.value_expr(o.bits['d']).replace(' + 0', ''), sz))
                pre.append('local %s_:%s = %s + %s;' % (ea, AW, r, dv))
            elif w == 16:
                dv = self.valsym(dv, o.bits['d'])
                pre.append('local %s_:%s = %s + sext(%s:2);' % (ea, AW, r, dv)) if not self.h300 else \
                    pre.append('local %s_:%s = %s + %s;' % (ea, AW, r, dv))
            else:
                dv = self.valsym(dv, o.bits['d'])
                pre.append('local %s_:%s = %s + %s;' % (ea, AW, r, dv))
            disp = '"@("^%s^":%d,"^%s^")"' % (dv, w, r)
        elif k == 'idx':
            dv = 'd%d' % i
            w = p['w']
            dv = self.valsym(dv, o.bits['d'])
            sh = {1: 0, 2: 1, 4: 2}[sz]
            ix = {'B': 'zext(%s)' % r, 'W': 'zext(%s)' % r, 'L': r}[p['ix']]
            dpart = 'sext(%s:2)' % dv if w == 16 else dv
            pre.append('local %s_:4 = (%s << %d) + %s;' % (ea, ix, sh, dpart))
            sfx = {'B': '.b', 'W': '.w', 'L': '.l'}[p['ix']]
            disp = '"@("^%s^":%d,"^%s^"%s)"' % (dv, w, r, sfx)
        pre.append('local %s:$(ASZ); DEA(%s, %s_);' % (ea, ea, ea))
        self.pre.extend(pre)
        m = '*:%d %s' % (sz, ea)
        return dict(disp=disp, rd='(%s)' % m, wr=lambda e, m=m: '%s = %s;' % (m, e), ea=ea, mem=True)

    def span_operand(self, i, o, sz):
        """Absolute / PC-relative / memory-indirect operands become subtables over their units."""
        k, p = o.kind, o.p
        g = self.g
        key = {'abs': 'a', 'memind': 'a', 'vecind': 'v', 'rel': 'd'}[k]
        chunks = o.bits[key]
        units = sorted(set(c[0] for c in chunks))
        first, last = units[0], units[-1]
        sig = (k, p.get('w'), sz, tuple((c[0] - first, c[1], c[2]) for c in chunks), self.row.base in ('JMP', 'JSR'))
        sub = g.subtable(sig, first, last, chunks, self)
        self.span_subs.append((first, last, sub))
        if last == first + 1 and g.sub_uses_l.get(sub):
            self.lgroups.setdefault(first, set())
        if k == 'rel':
            return dict(disp=sub, target=sub)
        if k == 'abs' and self.row.base in ('JMP', 'JSR'):
            return dict(disp=sub, target=sub)
        if k in ('memind', 'vecind'):
            return dict(disp=sub, vector=sub)
        return dict(disp=sub, rd=sub, wr=lambda e, s=sub: '%s = %s;' % (s, e), absmem=True)

    def mova_operand(self, i, o):
        p = o.p
        inner = Operand(o.text)
        inner.kind, inner.p = p['ik'], p['ip']
        inner.bits = {}
        for kk, vv in o.bits.items():
            if kk == 'd_inner':
                inner.bits['d'] = vv
            elif kk == 'd_inner_w':
                inner.bits['d_w'] = vv
            elif kk not in ('d_outer', 'd_outer_w'):
                inner.bits[kk] = vv
        isz = SZB[p['ix']]
        if inner.kind == 'reg':
            # register direct index: a 4-bit field names any byte (word) register; the 3-bit
            # short form (MOVA/x.L @(d,Rn.B),ERn) the low byte (word) of ERn
            if inner.bits['reg'][2] == 4:
                role = 'rb' if p['ix'] == 'B' else 'rw'
            else:
                role = 'rlo' if p['ix'] == 'B' else 'rwo'
            r = self.reg(inner, role)
            idisp = r
            ird = r
        else:
            res = self.operand(100 + i, inner, isz)
            idisp = res['disp']
            ird = res['rd']
        dv = 'dO%d' % i
        dv = self.valsym(dv, o.bits['d_outer'])
        return dict(disp='"@("^%s^":%d,"^%s^".%s)"' % (dv, p['w'], idisp, p['ix'].lower()),
                    mova=(ird, isz, dv, p['w']))


class Core:
    def __init__(self, core, rows):
        self.core = core
        self.rows = rows
        self.fields = {}
        self.lfields = {}
        self.sub_uses_l = {}
        self.subs = {}
        self.subdefs = []
        self.ctors = []
        self.maxunits = 0

    def subtable(self, sig, first, last, chunks, gen):
        key = (sig, first)
        if key in self.subs:
            return self.subs[key]
        k, w, sz, rel_chunks, isbranch = sig
        name = '%s%s_%d_%d' % ({'abs': 'ABS', 'memind': 'MIND', 'vecind': 'VIND', 'rel': 'REL'}[k],
                               w or '', first + 1, len(self.subs))
        self.subs[key] = name
        # pattern: units first..last, naming the fields the action reads
        val = gen.value_expr(chunks)
        pat = []
        lm = re.search(r'\bl(\d+)_\d+_\d+\b', val)
        self.sub_uses_l[name] = bool(lm)
        if lm:
            assert int(lm.group(1)) - 1 == first and last == first + 1, (sig, first, last)
            pat.append(lm.group(0))
        else:
            for ui in range(first, last + 1):
                names = sorted(set(m.group(0) for m in re.finditer(r'\bu%d(_\d+_\d+)?\b' % (ui + 1), val)))
                pat.append(' & '.join(names) if names else gen.full(ui))
        ptr = '$(PTR)'
        lines = []
        P = ' & '.join(pat) if len(pat) == 1 else ' ; '.join(pat)

        def nested(disp_w, tgt_expr, export):
            # the address is computed in an inner, undisplayed subtable so the operand can show
            # the raw field the way the manual writes it and still export a constant address
            lines.append('%s_c: tgt is %s [ tgt = %s; ] { export %s; }'
                         % (name, P, tgt_expr.replace('raw', '(%s)' % val.replace(' + 0', '')), export))
            m1 = re.fullmatch(r'\((\w+)\) \+ 0', val)
            if m1:   # one field: display it directly (action symbols print at address width)
                lines.append('%s: "@"^%s^":%d" is (%s) & %s_c { export %s_c; }'
                             % (name, m1.group(1), disp_w, P, name, name))
            else:
                lines.append('%s: "@"^raw^":%d" is (%s) & %s_c [ raw = %s; ] { export %s_c; }'
                             % (name, disp_w, P, name, val, name))
        if k == 'abs':
            if isbranch:
                nested(w, 'raw & $(PMASK)', '*[ram]:$(ASZ) tgt')
            elif w == 8:
                if self.core == 'sx':
                    lines.append('%s: "@"^raw^":8" is %s [ raw = %s; ] { local a:4 = sbr | raw; local ea:$(ASZ); DEA(ea, a); export *[ram]:%d ea; }'
                                 % (name, P, val, sz))
                else:
                    nested(8, '($(AMASK) - 0xff) | raw', '*[ram]:%d tgt' % sz)
            elif w == 16:
                nested(16, '((raw ^ 0x8000) - 0x8000) & $(AMASK)', '*[ram]:%d tgt' % sz)
            else:  # 24/32 data
                nested(w, '(((raw & $(D32LOW)) ^ $(D32SB)) - $(D32SB)) & $(AMASK)', '*[ram]:%d tgt' % sz)
        elif k == 'rel':
            nbits = sum(c[2] for c in chunks)
            if nbits == 7:
                sx = '((((raw << 1) ^ 0x80) - 0x80))'
            elif nbits == 8:
                sx = '((raw ^ 0x80) - 0x80)'
            else:
                sx = '((raw ^ 0x8000) - 0x8000)'
            v0 = '(%s)' % val.replace(' + 0', '')
            lines.append('%s: tgt is %s [ tgt = (inst_next + %s) & $(PMASK); ] { export *[ram]:$(ASZ) tgt; }'
                         % (name, P, sx.replace('raw', v0)))
        elif k == 'memind':
            lines.append('%s: "@@"^raw is %s [ raw = %s; ] { export *[ram]:$(PTR) raw; }'
                         % (name, P, val))
        elif k == 'vecind':
            lines.append('%s: "@@"^tgt is %s [ tgt = (0x80 + (%s)) * $(PTR); ] { export *[ram]:$(PTR) tgt; }'
                         % (name, P, val.replace(' + 0', '')))
        self.subdefs.extend(lines)
        return name

    def reglist_sub(self, ui, msb, w, n, field_is_last, pop, gen):
        key = ('RL', ui, msb, w, n, field_is_last, pop)
        if key in self.subs:
            return self.subs[key]
        name = '%sLIST%d_%d_%d' % ('POP' if pop else 'PUSH', n, ui + 1, len(self.subs))
        self.subs[key] = name
        f = gen.field(ui, msb, w)
        SP = 'r7' if self.core == '300' else 'er7'
        for v in range(1 << w):
            lo = v - (n - 1) if field_is_last else v
            hi = lo + n - 1
            if lo < 0 or hi > 7:
                continue
            if self.core != 'sx' and n > 1 and lo % (2 if n == 2 else 4) != 0:
                continue   # H8S: ER0-ER1, ER2-ER3, ... / ER0-ER2, ER4-ER6 / ER0-ER3, ER4-ER7
            disp = '"er%d-er%d"' % (lo, hi) if n > 1 else '"er%d"' % lo
            body = []
            if pop:
                for r in range(hi, lo - 1, -1):
                    body.append('local s%d:$(ASZ); DEA(s%d, %s); local v%d:4 = *:4 s%d; %s = %s + 4;' % (r, r, SP, r, r, SP, SP))
                    if r != 7:
                        body.append('er%d = v%d;' % (r, r))
            else:
                for r in range(lo, hi + 1):
                    body.append('%s = %s - 4; local s%d:$(ASZ); DEA(s%d, %s); *:4 s%d = er%d;' % (SP, SP, r, r, SP, r, r))
            self.subdefs.append('%s: %s is %s=%d { %s }' % (name, disp, f, v, ' '.join(body)))
        return name

    def token_defs(self):
        out = []
        for ui in sorted(self.fields):
            fl = self.fields[ui]
            defs = []
            for name, (lo, hi, role) in sorted(fl.items()):
                defs.append('\t%s = (%d,%d)' % (name, lo, hi))
            out.append('define token T%d(16)\n%s\n;' % (ui + 1, '\n'.join(defs)))
        for k in sorted(self.lfields):
            defs = ['\t%s = (%d,%d)' % (n, lo, hi) for n, (lo, hi, role) in sorted(self.lfields[k].items())]
            out.append('define token TL%d(32)\n%s\n;' % (k + 1, '\n'.join(defs)))
        # attach
        att = {}
        for ui in sorted(self.fields):
            for name, (lo, hi, role) in self.fields[ui].items():
                if role.startswith('r'):
                    att.setdefault((role, hi - lo + 1), []).append(name)
        for ui in sorted(self.lfields):
            for name, (lo, hi, role) in self.lfields[ui].items():
                if role.startswith('r'):
                    att.setdefault((role, hi - lo + 1), []).append(name)
        for (role, w), names in sorted(att.items()):
            if role == 'rb':
                regs = BYTE_REGS
            elif role == 'rw':
                regs = WORD_REGS if w == 4 else WORD_REGS[:8]
                if self.core == '300':
                    regs = WORD_REGS[:8] + ['_'] * 8
            elif role in ('rl', 'ra'):
                regs = ['r%d' % i for i in range(8)] if self.core == '300' else LONG_REGS
                if w == 4:
                    regs = regs + regs
            elif role == 'rlo':
                regs = ['r%dl' % i for i in range(8)]
            elif role == 'rwo':
                regs = ['r%d' % i for i in range(8)]
            out.append('attach variables [ %s ] [ %s ];' % (' '.join(sorted(names)), ' '.join(regs[:1 << w])))
        return '\n'.join(out)


# ======================================================================== semantics
def cond_expr(cc):
    return {
        'RA': '1', 'RN': '0', 'HI': '(C | Z) == 0', 'LS': '(C | Z) != 0', 'CC': 'C == 0', 'CS': 'C != 0',
        'NE': 'Z == 0', 'EQ': 'Z != 0', 'VC': 'V == 0', 'VS': 'V != 0', 'PL': 'N == 0', 'MI': 'N != 0',
        'GE': 'N == V', 'LT': 'N != V', 'GT': '(Z == 0) && (N == V)', 'LE': '(Z != 0) || (N != V)',
    }[cc]


def build(core, gen, row):
    """Fill gen.body with p-code for row; return display operand string."""
    base, size = row.base.split('/')[0], row.size
    ops = row.operands
    sz = SZB.get(size, 1)
    B = gen.body
    res = []
    # operand size for memory accesses
    for i, o in enumerate(ops):
        osz = sz
        if base in ('LDC', 'STC') and o.kind not in ('reg', 'imm', 'creg'):
            osz = 2 if size in ('W', None) else sz
        if base in ('BFLD', 'BFST', 'TAS') or base.startswith('B') and base not in ('BRA', 'BSR') and o.kind != 'rel':
            osz = 1 if o.kind not in ('reg',) else osz
        if base in ('BRA', 'BSR') and '/' in row.op and o.kind not in ('rel', 'imm'):
            osz = 1
        if base in ('MOVFPE', 'MOVTPE'):
            osz = 1
        if base in ('JMP', 'JSR'):
            osz = 1
        if base in ('PUSH', 'POP', 'LDM', 'STM'):
            osz = sz
        if base == 'MAC':
            osz = 2     # MAC @ERn+,@ERm+ multiplies two words
        res.append(gen.operand(i, o, osz))
    T = 'local'
    S = sz

    def rd(r):
        return r['rd']

    def wr(r, e):
        return r['wr'](e)

    def setNZ(v):
        B.append('N = %s s< 0; Z = %s == 0;' % (v, v))

    if base in ('MOV', 'MOVFPE', 'MOVTPE') and len(ops) == 2:
        s, d = res
        B.append('local v:%d = %s;' % (S, rd(s)))
        setNZ('v')
        B.append('V = 0;')
        B.append(wr(d, 'v'))
    elif base in ('ADD', 'SUB', 'CMP') and len(ops) == 2:
        s, d = res
        B.append('local s:%d = %s;' % (S, rd(s)))
        B.append('local a:%d = %s;' % (S, rd(d)))
        hm = HMASK[S]
        if base == 'ADD':
            B.append('local r:%d = a + s;' % S)
            B.append('C = carry(a, s); V = scarry(a, s); H = ((a & %s) + (s & %s)) > %s;' % (hm, hm, hm))
        else:
            B.append('local r:%d = a - s;' % S)
            B.append('C = a < s; V = sborrow(a, s); H = (a & %s) < (s & %s);' % (hm, hm))
        setNZ('r')
        if base != 'CMP':
            B.append(wr(d, 'r'))
    elif base in ('ADDX', 'SUBX'):
        s, d = res
        hm = HMASK[S]
        B.append('local s:%d = %s;' % (S, rd(s)))
        B.append('local a:%d = %s;' % (S, rd(d)))
        B.append('local c:%d = zext(C);' % S)
        if base == 'ADDX':
            B.append('local t:%d = a + s; local r:%d = t + c;' % (S, S))
            B.append('C = carry(a, s) || carry(t, c); V = ((a ^ r) & (s ^ r)) s< 0;')
            B.append('H = ((a & %s) + (s & %s) + c) > %s;' % (hm, hm, hm))
        else:
            B.append('local t:%d = a - s; local r:%d = t - c;' % (S, S))
            B.append('C = (a < s) || (t < c); V = ((a ^ s) & (a ^ r)) s< 0;')
            B.append('H = (a & %s) < ((s & %s) + c);' % (hm, hm))
        B.append('N = r s< 0; Z = Z && (r == 0);')
        B.append(wr(d, 'r'))
    elif base in ('AND', 'OR', 'XOR') and len(ops) == 2:
        s, d = res
        opc = {'AND': '&', 'OR': '|', 'XOR': '^'}[base]
        B.append('local r:%d = %s %s %s;' % (S, rd(d), opc, rd(s)))
        setNZ('r')
        B.append('V = 0;')
        B.append(wr(d, 'r'))
    elif base in ('ANDC', 'ORC', 'XORC'):
        s, d = res
        opc = {'ANDC': '&', 'ORC': '|', 'XORC': '^'}[base]
        if d['creg'] == 'ccr':
            B.append('local c:1; GETCCR(c); c = c %s %s; SETCCR(c);' % (opc, rd(s)))
        else:
            B.append('exr = (exr %s %s) | 0x78;   # EXR bits 6-3 always read 1' % (opc, rd(s)))
    elif base == 'NOT':
        d = res[-1]
        B.append('local r:%d = ~%s;' % (S, rd(d)))
        setNZ('r')
        B.append('V = 0;')
        B.append(wr(d, 'r'))
    elif base == 'NEG':
        d = res[-1]
        hm = HMASK[S]
        B.append('local a:%d = %s; local r:%d = 0 - a;' % (S, rd(d), S))
        B.append('C = a != 0; V = sborrow(0:%d, a); H = (a & %s) != 0;' % (S, hm))
        setNZ('r')
        B.append(wr(d, 'r'))
    elif base in ('EXTU', 'EXTS'):
        d = res[-1]
        frm = 1 if (S == 2 or (len(ops) == 2)) else 2
        fn = 'zext' if base == 'EXTU' else 'sext'
        B.append('local a:%d = %s; local r:%d = %s(a:%d);' % (S, rd(d), S, fn, frm))
        if base == 'EXTU':
            B.append('N = 0; Z = r == 0;')
        else:
            setNZ('r')
        B.append('V = 0;')
        B.append(wr(d, 'r'))
    elif base in ('INC', 'DEC'):
        d = res[-1]
        n = res[0]['const'] if len(ops) == 2 else 1
        o = '+' if base == 'INC' else '-'
        B.append('local a:%d = %s; local r:%d = a %s %d;' % (S, rd(d), S, o, n))
        B.append('V = %s(a, %d:%d);' % ('scarry' if base == 'INC' else 'sborrow', n, S))
        setNZ('r')
        B.append(wr(d, 'r'))
    elif base in ('ADDS', 'SUBS'):
        n, d = res
        o = '+' if base == 'ADDS' else '-'
        B.append('%s = %s %s %s;' % (d['reg'], d['reg'], o, n['const']))
    elif base in ('SHLL', 'SHLR', 'SHAL', 'SHAR', 'ROTL', 'ROTR', 'ROTXL', 'ROTXR'):
        d = res[-1]
        bits = S * 8
        if len(ops) == 2 and ops[0].kind in ('imm', 'reg'):
            # variable count: #xx:5 or Rn (lower 5 bits)
            cnt = res[0]
            if ops[0].kind == 'imm':
                B.append('local n:%d = %s & 31;' % (S, cnt['rd']))
            else:
                B.append('local n:%d = zext(%s & 31);' % (S, cnt['rd']) if S > 1 else 'local n:1 = %s & 31;' % cnt['rd'])
            B.append('local a:%d = %s;' % (S, rd(d)))
            if base == 'SHLL':
                B.append('local r:%d = a << n; C = ((a >> (%d - n)) & 1) != 0;' % (S, bits))
                B.append('if (n != 0) goto <shdone>; C = 0; <shdone>')
            else:
                B.append('local r:%d = a >> n; C = ((a >> (n - 1)) & 1) != 0;' % S)
                B.append('if (n != 0) goto <shdone>; C = 0; <shdone>')
            setNZ('r')
            B.append('V = 0;')
            B.append(wr(d, 'r'))
        else:
            n = res[0]['const'] if len(ops) == 2 else 1
            B.append('local a:%d = %s;' % (S, rd(d)))
            if base == 'SHLL':
                if n < bits:
                    B.append('local r:%d = a << %d; C = ((a >> %d) & 1) != 0;' % (S, n, bits - n))
                else:
                    B.append('local r:%d = 0; C = (a & 1) != 0;' % S if n == bits else 'local r:%d = 0; C = 0;' % S)
                B.append('V = 0;')
            elif base == 'SHLR':
                if n < bits:
                    B.append('local r:%d = a >> %d; C = ((a >> %d) & 1) != 0;' % (S, n, n - 1))
                else:
                    B.append('local r:%d = 0; C = ((a >> %d) & 1) != 0;' % (S, bits - 1) if n == bits else 'local r:%d = 0; C = 0;' % S)
                B.append('V = 0;')
            elif base == 'SHAL':
                B.append('local r:%d = a << %d; C = ((a >> %d) & 1) != 0;' % (S, n, bits - n))
                B.append('local t:%d = a s>> %d; V = (t != 0) && (t != -1);' % (S, bits - 1 - n))
            elif base == 'SHAR':
                B.append('local r:%d = a s>> %d; C = ((a >> %d) & 1) != 0; V = 0;' % (S, n, n - 1))
            elif base == 'ROTL':
                B.append('local r:%d = (a << %d) | (a >> %d); C = (r & 1) != 0; V = 0;' % (S, n, bits - n))
            elif base == 'ROTR':
                B.append('local r:%d = (a >> %d) | (a << %d); C = r s< 0; V = 0;' % (S, n, bits - n))
            elif base == 'ROTXL':
                B.append('local r:%d = a;' % S)
                for _ in range(n):
                    B.append('local c%d:%d = zext(C); C = r s< 0; r = (r << 1) | c%d;' % (_, S, _))
                B.append('V = 0;')
            elif base == 'ROTXR':
                B.append('local r:%d = a;' % S)
                for _ in range(n):
                    B.append('local c%d:%d = zext(C) << %d; C = (r & 1) != 0; r = (r >> 1) | c%d;' % (_, S, bits - 1, _))
                B.append('V = 0;')
            setNZ('r')
            B.append(wr(d, 'r'))
    elif base == 'DAA' or base == 'DAS':
        d = res[-1]
        B.append('local a:1 = %s; local lo:1 = a & 0xf; local hi:1 = a >> 4;' % rd(d))
        if base == 'DAA':
            B.append('local al:1 = zext((H != 0) || (lo > 9)) * 6;')
            B.append('local ah:1 = zext((C != 0) || (hi > 9) || ((hi == 9) && (lo > 9))) * 0x60;')
            B.append('local r:1 = a + al + ah; C = C || (ah != 0);')
        else:
            B.append('local r:1 = a + zext(H != 0) * 0xfa + zext(C != 0) * 0xa0;')
        setNZ('r')
        B.append(wr(d, 'r'))
    elif base in ('MULXU', 'MULXS'):
        s, d = res
        dsz = S * 2
        fn = 'zext' if base == 'MULXU' else 'sext'
        B.append('local a:%d = %s; local s:%d = %s; local r:%d = %s(a:%d) * %s(s);'
                 % (dsz, rd(d), S, rd(s), dsz, fn, S, fn))
        if base == 'MULXS':
            setNZ('r')
        B.append(wr(d, 'r'))
    elif base in ('DIVXU', 'DIVXS'):
        s, d = res
        dsz = S * 2
        B.append('local a:%d = %s; local s:%d = %s;' % (dsz, rd(d), S, rd(s)))
        B.append('Z = s == 0;')
        if base == 'DIVXU':
            B.append('N = s s< 0;')
            B.append('if (s == 0) goto <dz>;')
            B.append('local q:%d = a / zext(s); local m:%d = a %% zext(s);' % (dsz, dsz))
        else:
            B.append('if (s == 0) goto <dz>;')
            B.append('local q:%d = a s/ sext(s); local m:%d = a s%% sext(s);' % (dsz, dsz))
            B.append('N = q:%d s< 0;' % S)
        B.append(wr(d, '(m << %d) | (q & %s)' % (S * 8, '0xff' if S == 1 else '0xffff')))
        B.append('<dz>')
    elif base in ('MULU', 'MULS', 'DIVU', 'DIVS') or row.op in ('MULU/U.L', 'MULS/U.L'):
        s, d = res
        B.append('local a:%d = %s; local s:%d = %s;' % (S, rd(d), S, rd(s)))
        if row.op == 'MULU/U.L':
            B.append('local w:8 = zext(a) * zext(s); local r:4 = w(4);')
        elif row.op == 'MULS/U.L':
            B.append('local w:8 = sext(a) * sext(s); local r:4 = w(4);')
        elif base == 'MULU' or base == 'MULS':
            B.append('local r:%d = a * s;' % S)
        elif base == 'DIVU':
            B.append('Z = s == 0; N = s s< 0; if (s == 0) goto <dz>; local r:%d = a / s;' % S)
        else:
            B.append('Z = s == 0; N = (a ^ s) s< 0; if (s == 0) goto <dz>; local r:%d = a s/ s;' % S)
        if base == 'MULS':
            setNZ('r')      # MULU and MULU/U leave the flags unchanged (section 2.2.75/76)
        B.append(wr(d, 'r'))
        if base in ('DIVU', 'DIVS'):
            B.append('<dz>')
    elif base == 'TAS':
        d = res[-1]
        B.append('local a:1 = %s;' % rd(d))
        setNZ('a')
        B.append('V = 0;')
        B.append(wr(d, 'a | 0x80'))
    elif base in ('BSET', 'BCLR', 'BNOT', 'BTST', 'BAND', 'BIAND', 'BOR', 'BIOR', 'BXOR', 'BIXOR',
                  'BLD', 'BILD', 'BST', 'BIST', 'BSTZ', 'BISTZ'):
        n, d = res
        if ops[0].kind == 'reg':
            B.append('local n:1 = %s & 7;' % rd(n))
        else:
            B.append('local n:1 = %s;' % rd(n))
        B.append('local a:1 = %s; local b:1 = (a >> n) & 1;' % rd(d))
        cond = row.op.split('/')[1] if '/' in row.op else None
        if base == 'BTST':
            B.append('Z = b == 0;')
        elif base in ('BSET', 'BCLR', 'BNOT'):
            if cond:
                B.append('if (%s) goto <skip>;' % ('Z == 0' if cond == 'EQ' else 'Z != 0'))
            e = {'BSET': 'a | (1 << n)', 'BCLR': 'a & ~(1 << n)', 'BNOT': 'a ^ (1 << n)'}[base]
            B.append(wr(d, e))
            if cond:
                B.append('<skip>')
        elif base in ('BAND', 'BIAND', 'BOR', 'BIOR', 'BXOR', 'BIXOR', 'BLD', 'BILD'):
            bb = 'b' if base in ('BAND', 'BOR', 'BXOR', 'BLD') else '(b ^ 1)'
            e = {'BAND': 'C & %s', 'BIAND': 'C & %s', 'BOR': 'C | %s', 'BIOR': 'C | %s',
                 'BXOR': 'C ^ %s', 'BIXOR': 'C ^ %s', 'BLD': '%s', 'BILD': '%s'}[base] % bb
            B.append('C = %s;' % e)
        else:
            src = {'BST': 'C', 'BIST': 'C ^ 1', 'BSTZ': 'Z', 'BISTZ': 'Z ^ 1'}[base]
            B.append(wr(d, '(a & ~(1 << n)) | (((%s) & 1) << n)' % src))
    elif base in ('BFLD', 'BFST'):
        if base == 'BFLD':
            m, s, d = res
        else:
            r, m, d = res
        iv = m['rd']
        B.append('local mk:1 = %s; local low:1 = mk & (0 - mk);' % iv)
        B.append('local sh0:1 = zext((low & 0xaa) != 0) + zext((low & 0xcc) != 0) * 2 + zext((low & 0xf0) != 0) * 4;')
        if base == 'BFLD':
            B.append('local a:1 = %s; %s = (a & mk) >> sh0;' % (rd(s), d['reg']))
        else:
            B.append('local a:1 = %s; local v:1 = (%s << sh0) & mk;' % (rd(d), r['rd']))
            B.append(wr(d, '(a & ~mk) | v'))
    elif base in ('BRA', 'BSR') and '/' in row.op and row.op.split('/')[1] in ('BS', 'BC'):
        n, s, t = res
        B.append('local a:1 = %s; local b:1 = (a >> %s) & 1;' % (rd(s), rd(n)))
        want = '1' if row.op.split('/')[1] == 'BS' else '0'
        if base == 'BRA':
            B.append('if (b == %s) goto %s;' % (want, t['target']))
        else:
            B.append('if (b != %s) goto inst_next;' % want)
            B.append('PUSHRET(inst_next);')
            B.append('call %s;' % t['target'])
    elif base == 'BRA' and row.op == 'BRA/S':
        t = res[0]
        B.append('delayslot(1);')
        B.append('goto %s;' % t['target'])
    elif (base[0] == 'B' and len(base) == 3 and base[1:] in ('RA', 'RN', 'HI', 'LS', 'CC', 'CS', 'NE', 'EQ', 'VC',
                                                              'VS', 'PL', 'MI', 'GE', 'LT', 'GT', 'LE')) \
            and ops and ops[0].kind == 'rel':
        t = res[0]
        cc = base[1:]
        if cc == 'RA':
            B.append('goto %s;' % t['target'])
        elif cc == 'RN':
            pass
        else:
            B.append('if (%s) goto %s;' % (cond_expr(cc), t['target']))
    elif base in ('BRA', 'BSR') and ops and ops[0].kind == 'pcidx':
        r = res[0]
        AW = '2' if core == '300' else '4'
        # "PC + Rn -> PC" (section 2.2.23, "the branch destination address must be even"); the
        # addressing-mode overview (1.8.9) says Rn is multiplied by 2, the instruction description
        # and the GDB simulator's test (bra.s) do not
        if r['idx'] in ('B', 'W'):
            B.append('local x:%s = zext(%s);' % (AW, r['rd']))
        else:
            B.append('local x:4 = %s;' % r['rd'])
        B.append('local t_:%s = inst_next + x; local t:$(ASZ); PEA(t, t_);' % AW)
        if base == 'BRA':
            B.append('goto [t];')
        else:
            B.append('PUSHRET(inst_next); call [t];')
    elif base == 'BSR':
        t = res[0]
        B.append('PUSHRET(inst_next);')
        B.append('call %s;' % t['target'])
    elif base in ('JMP', 'JSR'):
        t = res[0]
        call = base == 'JSR'
        if 'target' in t:
            if call:
                B.append('PUSHRET(inst_next); call %s;' % t['target'])
            else:
                B.append('goto %s;' % t['target'])
        elif 'vector' in t:
            B.append('local v_ = %s; local t:$(ASZ); PEA(t, v_);' % t['vector'])
            B.append(('PUSHRET(inst_next); call [t];' if call else 'goto [t];'))
        else:
            ea = t.get('ea')
            # @ERn: the address is the register itself
            B.append('local t:$(ASZ); PEA(t, %s);' % ops_reg(gen, row))
            B.append(('PUSHRET(inst_next); call [t];' if call else 'goto [t];'))
            # drop the memory-operand setup
            gen.pre = [p for p in gen.pre if 'ea0' not in p]
    elif base == 'RTS':
        B.append('local t:$(ASZ); POPRET(t); return [t];')
    elif base == 'RTE':
        B.append('local t:$(ASZ); POPEXC(t); return [t];')
    elif base == 'TRAPA':
        n = res[0]
        B.append('local t:$(ASZ); TRAPVEC(t, %s); PUSHEXC(inst_next); I = 1; call [t];' % n['rd'])
    elif base in ('LDC', 'STC'):
        a, b = res
        if base == 'LDC':
            s, c = a, b
            cr = c['creg']
            if cr in ('vbr', 'sbr'):
                B.append('%s = %s & %s;' % (cr, s['rd'], '0xfffff000' if cr == 'vbr' else '0xffffff00'))
            else:
                if s.get('mem') or s.get('absmem'):
                    B.append('local w:2 = %s; local v:1 = w(1);' % s['rd'])
                else:
                    B.append('local v:1 = %s;' % s['rd'])
                B.append('SETCCR(v);' if cr == 'ccr' else 'exr = v | 0x78;')
        else:
            c, d = a, b
            cr = c['creg']
            if cr in ('vbr', 'sbr'):
                B.append('%s = %s;' % (d['reg'], cr))
            else:
                B.append('local v:1;' + (' GETCCR(v);' if cr == 'ccr' else ' v = exr;'))
                if d.get('mem') or d.get('absmem'):
                    B.append(d['wr']('zext(v) << 8'))
                else:
                    B.append(d['wr']('v'))
    elif base == 'PUSH' or base == 'POP':
        r = res[0]
        SP = 'r7' if core == '300' else 'er7'
        if base == 'PUSH':
            B.append('local v:%d = %s; %s = %s - %d; local s:$(ASZ); DEA(s, %s); *:%d s = v;' % (S, r['rd'], SP, SP, S, SP, S))
        else:
            B.append('local s:$(ASZ); DEA(s, %s); local v:%d = *:%d s; %s = %s + %d; %s = v;' % (SP, S, S, SP, SP, S, r['rd']))
        setNZ('v')
        B.append('V = 0;')
    elif base in ('LDM', 'STM'):
        pass   # the register-list subtable does the transfer
    elif base == 'MOVA':
        d = res[1]
        ird, isz, dv, w = res[0]['mova']
        sh = {'B': 0, 'W': 1, 'L': 2}[row.op.split('/')[1][0]]
        dpart = 'sext(%s:2)' % dv if w == 16 else dv
        B.append('local x:%d = %s; %s = (zext(x) << %d) + %s;' % (isz, ird, d['reg'], sh, dpart))
    elif base == 'EEPMOV':
        if size == 'B' or size is None:
            cnt = 'r4l'
        else:
            cnt = 'r4'
        a5, a6 = ('r5', 'r6') if core == '300' else ('er5', 'er6')
        B.append('<top> if (%s == 0) goto <done>;' % cnt)
        B.append('local s:$(ASZ); DEA(s, %s); local d:$(ASZ); DEA(d, %s); *:1 d = *:1 s;' % (a5, a6))
        B.append('%s = %s + 1; %s = %s + 1; %s = %s - 1; goto <top>; <done>' % (a5, a5, a6, a6, cnt, cnt))
    elif base == 'MOVMD':
        B.append('<top> local s:$(ASZ); DEA(s, er5); local d:$(ASZ); DEA(d, er6); *:%d d = *:%d s;' % (S, S))
        B.append('er5 = er5 + %d; er6 = er6 + %d; r4 = r4 - 1; if (r4 != 0) goto <top>;' % (S, S))
    elif base == 'MOVSD':
        t = res[0]
        B.append('<top> local s:$(ASZ); DEA(s, er5); local d:$(ASZ); DEA(d, er6); local v:1 = *:1 s; *:1 d = v;')
        B.append('er5 = er5 + 1; er6 = er6 + 1; r4 = r4 - 1;')
        B.append('if (v == 0) goto %s;' % t['target'])
        B.append('if (r4 != 0) goto <top>;')
    elif base == 'MAC':
        n, m = res
        B.append('local p:4 = sext(%s) * sext(%s); MACACC(p);' % (n['rd'], m['rd']))
    elif base == 'CLRMAC':
        B.append('mac = 0; macv = 0; macn = 0; macz = 1;')
    elif base == 'LDMAC':
        s, c = res
        if c['creg'] == 'mach':
            B.append('mach = (%s << 22) s>> 22;' % s['rd'])
        else:
            B.append('macl = %s;' % s['rd'])
        # N-MULT and Z-MULT describe the MAC contents, which STMAC reports
        B.append('macv = 0; macn = mac s< 0; macz = mac == 0;')
    elif base == 'STMAC':
        c, d = res
        B.append('%s = %s;' % (d['reg'], c['creg']))
        B.append('N = macn; Z = macz; V = macv;')
    elif base == 'SLEEP':
        B.append('sleep();')
    elif base == 'NOP':
        pass
    else:
        raise ValueError('no semantics for ' + row.mn)
    return res


def ops_reg(gen, row):
    o = row.operands[0]
    return gen.reg(o, 'ra')


def SPEA(core):
    return 'spea' if True else None


def emit_pop_list(gen, lst):
    # restored in descending order of register number; ER7 read but not restored
    B = gen.body
    n = lst['n']
    f = lst['field']
    gen.g.need_reglist = True
    if lst.get('field_is_last'):
        B.append('POPLIST%d(%s:1);' % (n, f))
    else:
        B.append('POPLIST%d(%s:1 + %d);' % (n, f, n - 1))


def emit_push_list(gen, lst):
    B = gen.body
    n = lst['n']
    f = lst['field']
    if lst.get('field_is_last'):
        B.append('PUSHLIST%d(%s:1 - %d);' % (n, f, n - 1))
    else:
        B.append('PUSHLIST%d(%s:1);' % (n, f))


# ======================================================================== output
def gen_core(cname, allrows, outdir):
    rows = [r for r in allrows if h8variants.member(cname, r)]
    core = '300' if cname == '300l' else cname    # the H8/300L is an H8/300 without two instructions
    C = Core(core, rows)
    for row in rows:
        g = Gen(C, row)
        res = build(core, g, row)
        # pattern
        for ui, u in enumerate(row.units):
            cl = []
            if u.kind == 'op':
                # merge fixed bits into runs
                runs = []
                for msb, w, v in u.fields:
                    if isinstance(v, int):
                        if runs and runs[-1][0] - runs[-1][1] == msb:
                            pm, pw, pv = runs[-1]
                            runs[-1] = (pm, pw + w, (pv << w) | v)
                        else:
                            runs.append((msb, w, v))
                for msb, w, v in runs:
                    cl.append('%s=0x%x' % (g.field(ui, msb, w), v))
            g.cons[ui] = cl
        for ui, c in g.extra_cons:
            g.cons[ui].append(c)
        # register operand fields must appear in the pattern
        for ui in range(len(row.units)):
            pass
        nunits = len(row.units)
        C.maxunits = max(C.maxunits, nunits)
        # operand symbols used in display
        disp = []
        for r in res:
            disp.append(r['disp'])
        # collect register-field symbols (they are fields) and add them to unit constraints
        used = set()
        for r in res:
            for kk in ('reg', 'disp', 'rd'):
                v = r.get(kk)
                if isinstance(v, str):
                    for m in re.finditer(r'\bu(\d+)_(r[a-z]+)\d+_\d+\b', v):
                        used.add((int(m.group(1)) - 1, m.group(0)))
        for b in g.body + g.pre:
            for m in re.finditer(r'\bu(\d+)_(r[a-z]+)\d+_\d+\b', b):
                used.add((int(m.group(1)) - 1, m.group(0)))
        for a in g.action + disp + g.pre + g.body:
            for m in re.finditer(r'\bu(\d+)(_\d+_\d+)?\b', a):
                used.add((int(m.group(1)) - 1, m.group(0)))
            for m in re.finditer(r'\bl(\d+)_\d+_\d+\b', a):
                g.lgroups.setdefault(int(m.group(1)) - 1, set()).add(m.group(0))
        for ui, name in sorted(used):
            if name not in g.cons[ui] and not any(c.startswith(name + '=') for c in g.cons[ui]):
                g.cons[ui].append(name)
        # units joined into a 32-bit token: rewrite their 16-bit-token fields as fields of it
        for k in sorted(g.lgroups):
            ren = {}

            def mk(m, k=k):
                unit = int(m.group(1)) - 1
                role, a, b = m.group(3) or '', m.group(4), m.group(5)
                if a is None:
                    hi, lo = 15, 0
                else:
                    hi, lo = int(a), int(b)
                if unit == k:
                    hi, lo = hi + 16, lo + 16
                name = 'l%d_%s%d_%d' % (k + 1, role, hi, lo)
                C.lfields.setdefault(k, {})[name] = (lo, hi, role)
                return name
            pat = re.compile(r'\bu(%d|%d)(_([a-z]*)(\d+)_(\d+))?\b' % (k + 1, k + 2))
            for uj in (k, k + 1):
                g.cons[uj] = [pat.sub(mk, c) for c in g.cons[uj]]
            g.action = [pat.sub(mk, a) for a in g.action]
            g.pre = [pat.sub(mk, a) for a in g.pre]
            g.body = [pat.sub(mk, a) for a in g.body]
            disp = [pat.sub(mk, d) for d in disp]
            names = set()
            for c in g.cons[k] + g.cons[k + 1]:
                names.add(c)
            names |= g.lgroups[k]
            for a in g.action:
                for m in re.finditer(r'\bl%d_[a-z]*\d+_\d+\b' % (k + 1), a):
                    names.add(m.group(0))
            for a in g.pre + g.body + disp:
                for m in re.finditer(r'\bl%d_r[a-z]+\d+_\d+\b' % (k + 1), a):
                    names.add(m.group(0))
            g.lcons = getattr(g, 'lcons', {})
            g.lcons[k] = sorted(names, key=lambda x: ('=' not in x and '!' not in x, x))
        seq = []
        spans = {s[0]: s for s in g.span_subs}
        covered = set()
        ui = 0
        while ui < nunits:
            if ui in spans and ui in g.lgroups:
                first, last, sub = spans[ui]
                el = [c for c in g.lcons[ui] if c != sub] + [sub]
                seq.append(' & '.join(el))
                ui = last + 1
                continue
            if ui in spans:
                first, last, sub = spans[ui]
                parts = []
                for uj in range(first, last + 1):
                    parts.append(' & '.join(g.cons[uj]) if g.cons[uj] else g.full(uj))
                if last > first:
                    seq.append('(%s) & %s' % (' ; '.join(parts), sub))
                else:
                    seq.append('%s & %s' % (parts[0], sub) if g.cons[ui] else sub)
                ui = last + 1
                continue
            if ui in g.lgroups and ui + 1 < nunits and ui + 1 not in spans:
                el = g.lcons[ui]
                if not el:
                    el = ['l%d_31_0' % (ui + 1)]
                    C.lfields.setdefault(ui, {})[el[0]] = (0, 31, '')
                seq.append(' & '.join(el))
                ui += 2
                continue
            seq.append(' & '.join(g.cons[ui]) if g.cons[ui] else g.full(ui))
            ui += 1
        mnem = row.op.lower()
        if '/' in mnem:
            a, b = mnem.split('/', 1)
            mnem = '%s^"/%s"' % (a, b)
        dtext = '^","^'.join(disp) if disp else ''
        act = (' [ %s ]' % ' '.join(g.action)) if g.action else ''
        body = '\n\t'.join(g.pre + g.body)
        ctx_variants = [('', None)]
        if core in ('h8s', 'sx') and row.base.split('/')[0] in ('TRAPA', 'RTE'):
            # EXR is saved in the exception frame when it is "valid" (interrupt control mode 2, set
            # in SYSCR): context bit exrvalid, 0 by default
            ctx_variants = [('exrvalid=0', None), ('exrvalid=1', ('EXC(', 'EXCX('))]
        if core in ('h8s', 'sx') and row.base == 'MAC':
            # MAC saturating mode (MACS bit of SYSCR): context bit macsat, 0 by default
            ctx_variants = [('macsat=0', None), ('macsat=1', ('MACACC(', 'MACACCSAT('))]
        for cpat, repl in ctx_variants:
            s0 = ' ; '.join(seq)
            if cpat:
                s0 = cpat + ' & ' + s0
            b0 = body.replace(*repl) if repl else body
            C.ctors.append(':%s %s is %s%s\n{\n\t%s\n}' % (mnem, dtext, s0, act, b0))
    # write
    out = []
    out.append('# Generated by tools/gen_h8.py from the Renesas H8SX Family Software Manual instruction-code table.')
    out.append('# Do not edit; change the generator.')
    out.append('')
    out.append(C.token_defs())
    out.append('')
    out.extend(C.subdefs)
    out.append('')
    out.extend(C.ctors)
    path = os.path.join(outdir, 'h8_%s_insn.sinc' % cname)
    open(path, 'w').write('\n'.join(out) + '\n')
    return len(C.ctors)


SLASPECS = [
    # file, core, mode, ASZ, PTR, AMASK, PMASK, D32X
    ('h8_300', '300', 'normal', 2, 2, '0xffff', '0xffff', 'raw & 0xffff'),
    ('h8_300l', '300l', 'normal', 2, 2, '0xffff', '0xffff', 'raw & 0xffff'),
    ('h8_300h_normal', '300h', 'normal', 2, 2, '0xffff', '0xffff', 'raw & 0xffff'),
    ('h8_300h_advanced', '300h', 'advanced24', 3, 4, '0xffffff', '0xffffff', 'raw & 0xffffff'),
    ('h8s_normal', 'h8s', 'normal', 2, 2, '0xffff', '0xffff', 'raw & 0xffff'),
    ('h8s_advanced', 'h8s', 'advanced24', 3, 4, '0xffffff', '0xffffff', 'raw & 0xffffff'),
    ('h8sx_normal', 'sx', 'normal', 2, 2, '0xffff', '0xffff', 'raw & 0xffff'),
    ('h8sx_middle', 'sx', 'middle', 3, 4, '0xffffff', '0xffffff',
     'middle'),
    ('h8sx_advanced', 'sx', 'advanced', 4, 4, '0xffffffff', '0xffffff', 'raw & 0xffffffff'),
    ('h8sx_maximum', 'sx', 'maximum', 4, 4, '0xffffffff', '0xffffffff', 'raw & 0xffffffff'),
]


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, '..', 'data', 'languages')
    rows = load_rows(os.path.join(HERE, 'h8sx_codes.json'))
    for core in CORES:
        n = gen_core(core, rows, outdir)
        print('%s: %d constructors' % (core, n))
    for fn, core, mode, asz, ptr, amask, pmask, d32x in SLASPECS:
        txt = ('# Generated by tools/gen_h8.py\n'
               '@define CORE "%s"\n@define MODE "%s"\n@define ASZ "%d"\n@define PTR "%d"\n'
               '@define AMASK "%s"\n@define PMASK "%s"\n@define D32LOW "%s"\n@define D32SB "%s"\n\n'
               '@include "h8_common.sinc"\n@include "h8_%s_insn.sinc"\n'
               % ('300' if core == '300l' else core, mode, asz, ptr, amask, pmask, '0xffff' if d32x == 'middle' else '0xffffffff',
                  '0x8000' if d32x == 'middle' else '0', core))
        open(os.path.join(outdir, fn + '.slaspec'), 'w').write(txt)


if __name__ == '__main__':
    main()
