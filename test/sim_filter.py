#!/usr/bin/env python3
"""Drop the GDB simulator test blocks that check simulator behaviour the Renesas manuals
contradict (see GHIDRA-RARE.md); every other block of the file is kept.
  sim_filter.py <in.s> <out.s>   (prints the dropped block labels)
Dropped:
  *abs8*      @aa:8 is H'FF00+aa (H8/300), H'FFFF00+aa (H8/300H, H8S advanced) or SBR+aa with
              SBR's low 8 bits reading 0 (H8SX); the tests store through a low address or an
              unaligned SBR and read back through @aa:8
  *exr*       EXR bits 6-3 always read 1 (H8S and H8SX manuals); the tests expect 0
  jmp_7       @@vec:7 is not VBR-relative ("extended memory indirect is also out of the
              target" of VBR); the test puts the vector at VBR + H'300
  *sbr*, *vbr*  the low 8 (SBR) and 12 (VBR) bits read 0; the tests expect 0xAAAAAAAA back
  shlr *abs16 the operand (after a large H8SX text, above H'8000) is sign-extended to H'FFFFxxxx
  addb abs16/abs32 blocks expect the running total the dropped abs8 blocks added to
"""
import re
import sys

src, dst = sys.argv[1], sys.argv[2]
name = src.rsplit('/', 1)[-1]
drop = re.compile(r'^(\w*abs8\w*|\w*exr\w*|jmp_7|\w*_sbr\w*|\w*_vbr\w*)$')
if name == 'shlr.s':
    drop = re.compile(r'^(\w*abs8\w*|\w*exr\w*|jmp_7|\w*abs16\w*)$')
if name == 'addb.s':
    drop = re.compile(r'^(\w*abs8\w*|\w*exr\w*|add_b_\w*_abs(16|32))$')
out, dropped, skipping = [], [], False
for line in open(src):
    m = re.match(r'^([A-Za-z_]\w*):', line)
    if m and not line.startswith('.'):
        skipping = bool(drop.match(m.group(1)))
        if skipping:
            dropped.append(m.group(1))
    if skipping and re.match(r'^\s*(pass|exit)\b', line):
        skipping = False      # the end of the last test block: keep the pass/exit epilogue
    if skipping and not re.match(r'^\s*\.(if|else|endif|endm|macro)\b', line):
        continue
    out.append(line)
open(dst, 'w').write(''.join(out))
if dropped:
    print('%s: dropped %s' % (name, ' '.join(dropped)))
