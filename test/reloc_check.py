#!/usr/bin/env python3
"""Check Ghidra's H8 ELF relocation handler against GNU ld.
  reloc_check.py <obj.o> <relocdump.txt> <ld> <workdir>
Links <obj.o> with GNU ld, placing every section at the address Ghidra gave it and every
undefined symbol at Ghidra's EXTERNAL address, then compares each relocated section byte for
byte with Ghidra's memory (RelocDump.java).  Prints the counts; exit 1 on any difference."""
import os
import re
import subprocess
import sys


def main():
    obj, dump, ld, work = sys.argv[1:5]
    os.makedirs(work, exist_ok=True)
    blocks, ext = {}, {}
    nrel = bad = 0
    for line in open(dump):
        p = line.split()
        if p[0] == 'block':
            blocks[p[1]] = (int(p[2], 16), bytes.fromhex(p[3]) if len(p) > 3 else b'')
        elif p[0] == 'extsym':
            ext[p[1]] = int(p[2], 16)
        elif p[0] == 'relocations':
            nrel, bad = int(p[1]), int(p[3])
    secs = [n for n in blocks if n.startswith('.')]
    lds = os.path.join(work, 'link.x')
    with open(lds, 'w') as f:
        f.write('SECTIONS {\n')
        for n in secs:
            f.write('  %s 0x%x : { *(%s) }\n' % (n, blocks[n][0], n))
        f.write('  /DISCARD/ : { *(.comment) *(.note*) *(.debug*) }\n}\n')
    out = os.path.join(work, 'linked.elf')
    hdr = open(obj, 'rb').read(0x28)
    mach = (int.from_bytes(hdr[0x24:0x28], 'big') >> 16) & 0xff
    emul = {0x80: 'h8300elf', 0x81: 'h8300helf', 0x82: 'h8300self', 0x83: 'h8300hnelf', 0x84: 'h8300snelf',
            0x85: 'h8300sxelf', 0x86: 'h8300sxnelf'}[mach]
    cmd = [ld, '-m', emul, '-T', lds, '-o', out, obj, '--no-relax']
    for s, a in ext.items():
        cmd.append('--defsym=%s=0x%x' % (s, a))
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stderr[:2000])
        sys.exit(1)
    objcopy = ld.replace('-ld', '-objcopy')
    same = diff = 0
    for n in secs:
        b = os.path.join(work, 'sec.bin')
        subprocess.run([objcopy, '-O', 'binary', '--only-section=' + n, out, b], check=True)
        lb = open(b, 'rb').read()
        gb = blocks[n][1]
        m = min(len(lb), len(gb))
        d = [i for i in range(m) if lb[i] != gb[i]]
        if d or len(lb) != len(gb):
            diff += 1
            print('  %s differs at %d bytes (first %s), sizes %d/%d' % (n, len(d), [hex(blocks[n][0] + i) for i in d[:6]], len(gb), len(lb)))
        else:
            same += 1
    print('%s: %d relocations (%d not applied), %d sections identical to GNU ld, %d different'
          % (os.path.basename(obj), nrel, bad, same, diff))
    sys.exit(1 if diff or bad else 0)


if __name__ == '__main__':
    main()
