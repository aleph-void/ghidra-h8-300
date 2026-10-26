"""Which rows of the H8SX code table each core executes.

The forms_*.txt lists are the instruction forms (mnemonic and addressing mode) listed in each
core's own manual:
  forms_h8300.txt   H8/300 Programming Manual, Appendix B (instruction set list)
  forms_h8300h.txt  H8/300H Series Software Manual (REJ09B0213), table 2.3 (instruction codes)
  forms_h8s.txt     H8S/2600, H8S/2000 Series Software Manual (REJ09B0139), section 2.4
The H8SX is object-code compatible with all three, so each listed form is a row of the H8SX
table with the same code; normalize() maps the older notation onto the H8SX one.
"""
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
SINGLE = {'NOP', 'RTS', 'RTE', 'SLEEP', 'CLRMAC', 'EEPMOV', 'EEPMOV.B', 'EEPMOV.W'}


def normalize(m, core):
    m = m.replace('–', '-').replace('−', '-').strip()
    m = re.sub(r'\*\d*$', '', m)
    m = re.sub(r'\s*\(B[A-Z]+ d:\d+\)', '', m)
    op, _, args = m.partition(' ')
    base = op.split('.')[0]
    if base in ('ADDX', 'SUBX') and '.' not in op:
        op = base + '.B'
    if base in ('DAA', 'DAS'):
        op = base
    if base in ('LDC', 'STC') and '.' not in op:
        if '#' in args or re.search(r'(^|,)R[sd](,|$)', args):
            op = base + '.B'
        else:
            op = base + '.W'
    if op == 'EEPMOV':
        op = 'EEPMOV.B'
    if op == 'MOV.L':
        args = args.replace('#xx:32,Rd', '#xx:32,ERd')
    if op == 'LDMAC':
        args = args.replace('ERS', 'ERs')
    if op == 'CMP.W' and args == 'Rd,Rd':
        args = 'Rs,Rd'
    args = args.replace('d:24', 'd:32')
    if base not in ('JMP', 'JSR'):
        args = args.replace('@aa:24', '@aa:32')
    if core == '300':
        # H8/300 notation: 16-bit address registers Rn
        args = re.sub(r'@R([sdn])', r'@ER\1', args)
        args = re.sub(r'@\(d:16,R([sd])\)', r'@(d:16,ER\1)', args)
        args = args.replace('@-Rd', '@-ERd')
        if base in ('ADDS', 'SUBS'):
            op = base
            args = args.replace(',Rd', ',ERd')
        if base in ('JMP', 'JSR'):
            args = args.replace('@aa:16', '@aa:24')
        if op == 'POP':
            op, args = 'POP.W', 'Rn'
        if op == 'PUSH':
            op, args = 'PUSH.W', 'Rn'
    return (op + ' ' + args).strip()


_cache = {}


def forms(core):
    if core in _cache:
        return _cache[core]
    fn = {'300': 'forms_h8300.txt', '300h': 'forms_h8300h.txt', 'h8s': 'forms_h8s.txt'}[core]
    out = set()
    for line in open(os.path.join(HERE, fn), encoding='utf-8'):
        line = line.strip()
        if not line or (' ' not in line and line not in SINGLE):
            continue
        if line.startswith(('BF ', 'BT ', 'BHS ', 'BLO ')):
            continue
        out.add(normalize(line, core))
    _cache[core] = out
    return out


def row_key(row):
    return row.mn


# PUSH.W/L Rn and POP.W/L Rn are the manual's other names for MOV Rn,@-SP and MOV @SP+,Rn
# (same codes); the SLEIGH keeps the MOV rows, as GNU objdump does.
ALIASES = {'PUSH.W Rn', 'PUSH.L ERn', 'POP.W Rn', 'POP.L ERn'}


def member(core, row):
    if row.mn in ALIASES:
        return False
    if row.rec.get('sx_only') and core != 'sx':
        return False
    if core == 'sx':
        return True
    if core == '300l':
        # H8/300L Series Software Manual (REJ09B0214), table 1-1: 55 instruction types, the
        # H8/300's 57 without the E-clock transfers MOVFPE and MOVTPE
        return row.base not in ('MOVFPE', 'MOVTPE') and row_key(row) in forms('300')
    return row_key(row) in forms(core)


def unmatched(core, rows):
    keys = set(row_key(r) for r in rows)
    return sorted(f for f in forms(core) if f not in keys)
