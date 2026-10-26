#!/usr/bin/env python3
"""Summarize the decode-test reports (compare.py output) of a decode-tests.sh work directory:
per language the corpus totals, and over all languages the explained difference classes, with
the per-row "manual-reserved bits" and register-list classes grouped.
  summarize.py <decode-workdir>"""
import collections
import glob
import os
import re
import sys

W = sys.argv[1]
tot = collections.defaultdict(lambda: collections.Counter())
classes = collections.Counter()
for f in sorted(glob.glob(os.path.join(W, '*', 'cmp_*.txt')) + glob.glob(os.path.join(W, 'asm', '*', 'cmp.txt'))):
    if '/asm/' in f:
        lang = os.path.basename(os.path.dirname(f))
        corpus = 'asm'
    else:
        m = re.match(r'cmp_(.*)_(table|fuzz|enum)\.txt', os.path.basename(f))
        lang, corpus = m.group(1), m.group(2)
    sect = None
    for line in open(f):
        if line.startswith('== Ghidra vs objdump'):
            sect = 'o'
            continue
        if line.startswith('=='):
            sect = None
        m = re.match(r'^ +(\d+)  (.*)$', line)
        if sect == 'o' and m:
            n, c = int(m.group(1)), m.group(2)
            if c.startswith('manual-reserved bits'):
                c = 'manual-reserved bits objdump ignores (any row)'
            if c.startswith('not in this core'):
                c = 'not in this core'
            if c.startswith('branch address wrapped'):
                c = 'branch address wrapped to the mode\'s program-address width'
            classes[c] += n
            tot[lang][c] += n
        m = re.match(r'^compared (\d+): exact (\d+), semantic (\d+), both-invalid (\d+), explained (\d+), '
                     r'unexplained (\d+); manual table: agree (\d+), differ (\d+)', line)
        if m:
            k = ('compared', 'exact', 'semantic', 'both-invalid', 'explained', 'unexplained', 'table-agree', 'table-differ')
            for kk, v in zip(k, m.groups()):
                tot[lang]['_' + kk] += int(v)
print('%-24s %9s %9s %9s %9s %9s %5s %9s' % ('language', 'slots', 'exact', 'semantic', 'both-inv', 'explained', 'unexp', 'table-ok'))
for lang in sorted(tot):
    t = tot[lang]
    print('%-24s %9d %9d %9d %9d %9d %5d %9d' % (lang, t['_compared'], t['_exact'], t['_semantic'], t['_both-invalid'],
                                                  t['_explained'], t['_unexplained'], t['_table-agree']))
print()
for c, n in classes.most_common():
    if c in ('exact', 'semantic', 'both-invalid'):
        continue
    print('%9d  %s' % (n, c))
