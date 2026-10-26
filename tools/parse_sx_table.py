#!/usr/bin/env python3
"""Parse Table 2.2 (List of Instruction Codes) of the H8SX Family Software Manual
(REJ09B0102-0400) from `pdftotext -bbox` output into a JSON list of rows:
  {"mn": "ADD.B @ERs+,@ERd", "page": 637, "words": [[(msb, width, value|name), ...], ...],
   "ext": [...]}
Each opcode word is 16 bits; every field is placed by its x position under the
"15 8 7 0" column header of its word.  Extension words (EA extension, after an
opcode word) are kept as named 16-bit slots ("d", "a", "IMM" ...).
"""
import json, re, sys, html
from collections import defaultdict

src = sys.argv[1]
text = open(src, encoding='utf-8').read()
pages = text.split('<page ')[1:]
WRE = re.compile(r'<word xMin="([\d.]+)" yMin="([\d.]+)" xMax="([\d.]+)" yMax="([\d.]+)">(.*?)</word>')

rows_out = []
problems = []
for pi, ptxt in enumerate(pages):
    words = [(float(a), float(b), float(c), float(d), html.unescape(t)) for a, b, c, d, t in WRE.findall(ptxt)]
    pm = re.search(r'Page (\d+) of 914', ' '.join(w[4] for w in words))
    mn = [w for w in words if w[4] == 'Mnemonic']
    if not mn:
        continue
    hy = mn[0][1]
    mnx = mn[0][0]
    hdr = sorted([w for w in words if abs(w[1] - hy) < 2 and w[4] in ('15', '1', '8', '7', '0')], key=lambda w: w[0])
    seq = [('15' if w[4] == '1' else w[4]) for w in hdr]
    cols = []  # (x15, x0, pitch)
    i = 0
    while i + 3 < len(seq):
        if seq[i:i + 4] == ['15', '8', '7', '0']:
            c15 = (hdr[i][0] + hdr[i][2]) / 2
            c0 = (hdr[i + 3][0] + hdr[i + 3][2]) / 2
            c8 = (hdr[i + 1][0] + hdr[i + 1][2]) / 2
            c7 = (hdr[i + 2][0] + hdr[i + 2][2]) / 2
            cols.append((c15, c8, c7, c0))
            i += 4
        else:
            i += 1
    if not cols:
        problems.append((pi, 'no header'))
        continue
    first_col = cols[0][0] - 12
    # group remaining words into rows by y
    body = [w for w in words if w[1] > hy + 4 and not re.match(r'(Rev\.|REJ09|Section|Page|of|914|Sep\.|18,|2008|\d+\.?$)', w[4]) or (w[1] > hy + 4 and w[0] > first_col)]
    lines = defaultdict(list)
    for w in body:
        key = None
        for k in lines:
            if abs(k - w[1]) < 2.5:
                key = k
                break
        lines[key if key is not None else w[1]].append(w)
    orphans = []
    page_rows = []
    for y in sorted(lines):
        ws = sorted(lines[y], key=lambda w: w[0])
        mnws = [w for w in ws if mnx - 3 <= w[0] < first_col]
        fws = [w for w in ws if w[0] >= first_col]
        if not mnws:
            continue
        if not fws:
            orphans.append((y, ' '.join(w[4] for w in mnws)))
            continue
        mtext = ' '.join(w[4] for w in mnws)
        if mtext.startswith(('Rev.', 'REJ09')):
            continue
        # assign field words to opcode words / extension slots
        slots = []  # list of ('op', idx, tokens) or ('ext', after_idx, tokens)
        perword = defaultdict(list)
        ext = defaultdict(list)
        for w in fws:
            xc = (w[0] + w[2]) / 2
            placed = False
            for ci, (c15, c8, c7, c0) in enumerate(cols):
                pitch = (c0 - c15) / 15.0
                if c15 - pitch * 0.75 <= xc <= c0 + pitch * 0.75:
                    pos = (xc - c15) / pitch  # 0 = bit 15
                    perword[ci].append((pos, w[4]))
                    placed = True
                    break
            if not placed:
                # extension: after the last word whose c0 < xc
                after = max([ci for ci, c in enumerate(cols) if c[3] < xc], default=-1)
                if re.fullmatch(r'[adx]|IMM|disp|abs', w[4]):
                    ext[after].append(w[4])
        words_out = []
        bad = False
        for ci in sorted(perword):
            toks = sorted(perword[ci])
            bits = [None] * 16
            names = []
            # first pass: fixed-width tokens
            pend = []
            for pos, t in toks:
                frac = pos - int(pos + 1e-6) if pos >= 0 else pos
                nearest = round(pos)
                half = abs(pos - nearest) > 0.3
                if re.fullmatch(r'[0-9A-F]', t) and half:
                    start = int(round(pos - 1.5))
                    for b in range(start, start + 4):
                        if 0 <= b < 16 and bits[b] is None:
                            bits[b] = ('h', t, start)
                        else:
                            bad = True
                elif re.fullmatch(r'[01]', t) and not half:
                    if 0 <= nearest < 16 and bits[nearest] is None:
                        bits[nearest] = ('b', t, nearest)
                    else:
                        bad = True
                else:
                    pend.append((pos, t))
            # names: single letters are one bit; register/immediate names are 3 bits when
            # centred on a column, 4 bits when centred between two columns
            for pos, t in pend:
                half = abs(pos - round(pos)) > 0.3
                if len(t) == 1 and not half:
                    cand = [[int(round(pos))]]
                elif half:
                    f = int(pos)
                    cand = [list(range(f - 1, f + 3)), [f, f + 1]]
                else:
                    c = int(round(pos))
                    cand = [list(range(c - 1, c + 2)), [c]]
                ok = False
                for bl in cand:
                    if all(0 <= b < 16 and bits[b] is None for b in bl):
                        for b in bl:
                            bits[b] = ('n', t, bl[0])
                        ok = True
                        break
                if not ok:
                    bad = True
            if any(b is None for b in bits):
                bad = True
            # compress to fields (msb-first positions)
            fields = []
            i = 0
            while i < 16:
                b = bits[i]
                if b is None:
                    fields.append((15 - i, 1, '?'))
                    i += 1
                    continue
                kind, t, start = b
                j = i
                while j + 1 < 16 and bits[j + 1] is not None and bits[j + 1][0] == kind and bits[j + 1][1] == t and (kind != 'b') and bits[j + 1][2] == start:
                    j += 1
                if kind == 'h':
                    fields.append((15 - i, j - i + 1, int(t, 16)))
                elif kind == 'b':
                    fields.append((15 - i, 1, int(t)))
                else:
                    fields.append((15 - i, j - i + 1, t))
                i = j + 1
            words_out.append(fields)
            # attach extension after this word
        out_ext = {str(k): v for k, v in ext.items()}
        # order words so that ext slots know their position
        rec = {'mn': mtext, 'page': int(pm.group(1)) if pm else None, 'words': words_out,
               'wordcols': sorted(perword), 'ext': out_ext, 'bad': bad}
        rec['y'] = y
        page_rows.append(rec)
    for oy, ot in orphans:
        if not ot.startswith(('@', '(')):
            continue
        cands = [r for r in page_rows if ' ' not in r['mn'] and abs(r['y'] - oy) < 12]
        if cands:
            r = min(cands, key=lambda r: abs(r['y'] - oy))
            r['mn'] += ' ' + ot
    for rec in page_rows:
        del rec['y']
        rows_out.append(rec)
        if rec['bad']:
            problems.append((rec['page'], rec['mn']))

json.dump(rows_out, open(sys.argv[2], 'w'), indent=None)
print(len(rows_out), 'rows;', len(problems), 'problems', file=sys.stderr)
for p in problems[:40]:
    print('  ', p, file=sys.stderr)
