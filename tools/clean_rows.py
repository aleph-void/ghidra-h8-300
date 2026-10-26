#!/usr/bin/env python3
"""Clean the rows parsed by parse_sx_table.py:
  * join mnemonics whose operand text was printed on a separate line,
  * drop page notes,
  * apply the manual errata listed in ERRATA (each one confirmed by the regular structure of the
    neighbouring rows and by GNU objdump, see GHIDRA-RARE.md).
usage: clean_rows.py raw.json clean.json
"""
import copy
import json
import sys

rows = json.load(open(sys.argv[1]))
out = []
for r in rows:
    if r['bad']:
        continue
    if r['mn'].startswith(('@', '(')) and not r['words'] and out and ' ' not in out[-1]['mn']:
        out[-1]['mn'] += ' ' + r['mn']
        continue
    if not r['words']:
        print('dropped', r['mn'], file=sys.stderr)
        continue
    out.append(r)

by_mn = {}
for r in out:
    by_mn.setdefault(r['mn'], r)


def bits(*b):
    return [[15 - i, 1, v] for i, v in enumerate(b)]


# --- errata in Table 2.2 of REJ09B0102-0400 ------------------------------------------------
for r in out:
    # p.642: the second word of ADD.B @(d:32,Rs.W),@ERd+ is printed as 6A24 and the destination
    # mode bits as 00000 (@ERd).  Every other @(d:32,Rs.W) source row has 6A2C, and @ERd+ is 10000
    # in every other row; objdump decodes only the regular form.
    if r['page'] == 642 and r['mn'] == 'ADD.B @(d:32,Rs.W),@ERd+':
        good = by_mn['ADD.B @(d:32,Rs.W),@ERd-']
        r['words'] = copy.deepcopy(good['words'])
        w3 = r['words'][2]
        w3[0:3] = [[15, 1, 1], [14, 1, 0], [13, 1, 0]]
        r['erratum'] = 'second word 6A24 -> 6A2C, destination mode 00000 -> 10000'
    # p.673: operand text of AND.B @(d:32,ERs.L),@(d:32,ERd.L) is missing from the row.
    if r['page'] == 673 and r['mn'] == 'AND.B':
        r['mn'] = 'AND.B @(d:32,ERs.L),@(d:32,ERd.L)'
        r['erratum'] = 'operand text missing'

# Rows marked "*": "The instruction codes for the H8S/2600 and H8S/2000 CPUs are also executable"
# (note to Table 2.2).  The H8SX code listed is H8SX-only; the H8S code (H8S/2600 manual,
# section 2.4: 01 00 78 0ers 0 6B 2 0erd disp / 01 00 78 0erd 0 6B A 0ers disp) is added as a row
# of its own, used by every core.
extra = []
for r in out:
    if r['mn'].endswith('*') or '*,' in r['mn']:
        r['sx_only'] = True
        mn = r['mn'].replace('*', '')
        load = mn.startswith('MOV.L @(d:32')
        w1 = bits(0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0)
        w2 = [[15, 4, 7], [11, 4, 8], [7, 1, 0], [6, 3, 'rs' if load else 'rd'], [3, 4, 0]]
        w3 = [[15, 4, 6], [11, 4, 0xb], [7, 4, 2 if load else 0xa], [3, 1, 0], [2, 3, 'rd' if load else 'rs']]
        extra.append({'mn': mn, 'page': r['page'], 'words': [w1, w2, w3], 'wordcols': [0, 1, 2],
                      'ext': {'2': ['d', 'd']}, 'bad': False, 'h8s_form': True})
        if not load:
            # H8S manual, note 2 to the code table: "Bit 7 of the 4th byte of the MOV.L ERs,
            # @(d:32,ERd) instruction can be either 1 or 0" (GNU as sets it)
            w2b = [[15, 4, 7], [11, 4, 8], [7, 1, 1], [6, 3, 'rd'], [3, 4, 0]]
            extra.append({'mn': mn, 'page': r['page'], 'words': [w1, w2b, w3], 'wordcols': [0, 1, 2],
                          'ext': {'2': ['d', 'd']}, 'bad': False, 'h8s_form': True})
out.extend(extra)

for r in out:
    if ' ' not in r['mn'] and r['mn'] not in ('NOP', 'RTS', 'RTE', 'SLEEP', 'CLRMAC', 'EEPMOV.B',
                                             'EEPMOV.W', 'MOVMD.B', 'MOVMD.W', 'MOVMD.L'):
        print('no operands:', r['mn'], r['page'], file=sys.stderr)
json.dump(out, open(sys.argv[2], 'w'))
print(len(out), 'rows', file=sys.stderr)
