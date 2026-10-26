#!/usr/bin/env python3
"""Compare Ghidra's analysed instructions (RealCheck .dis) with `objdump -d` of the same ELF at the
same addresses.  real_compare.py <objdump.txt> <ghidra.dis> [label]
Prints totals and every difference; exit 1 if any instruction differs other than by spelling
(compare.py's semantic form) or by an explained class."""
import re
import sys

from compare import norm_g, norm_od, semantic


def read_od(path):
    out = {}
    for line in open(path, errors="replace"):
        m = re.match(r"^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*\t?(.*)$", line)
        if m:
            txt = re.sub(r"\s*<[^>]*>\s*$", "", m.group(3)).strip()
            out[int(m.group(1), 16)] = (txt, len(m.group(2).split()))
        else:
            # continuation lines of long instructions: more bytes for the previous address
            m2 = re.match(r"^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*$", line)
    return out


def read_ghidra(path):
    out = {}
    for line in open(path):
        p = line.rstrip("\n").split(" ", 2)
        out[int(p[0], 16)] = (p[2] if len(p) > 2 else "", len(p[1]) // 2, p[1])
    return out


def main():
    od, gh = read_od(sys.argv[1]), read_ghidra(sys.argv[2])
    label = sys.argv[3] if len(sys.argv) > 3 else ""
    exact = sem = diff = missing = 0
    shown = 0
    for a in sorted(gh):
        g_txt, g_len, g_hex = gh[a]
        if a not in od:
            missing += 1
            if shown < 20:
                print(f"  no objdump instruction at {a:08x}: ghidra {g_txt}")
                shown += 1
            continue
        o_txt, o_len = od[a]
        g, o = norm_g(g_txt), norm_od(o_txt)
        if g == o:
            exact += 1
        elif semantic(g) == semantic(o):
            sem += 1
        else:
            diff += 1
            if shown < 40:
                print(f"  {a:08x} {g_hex:<18} objdump: {o_txt:<36} ghidra: {g_txt}")
                shown += 1
    print(f"== {label}: {exact + sem + diff + missing} Ghidra instructions: {exact} identical to objdump, "
          f"{sem} same instruction spelled differently, {diff} different, {missing} at addresses objdump did not decode")
    sys.exit(1 if diff or missing else 0)


if __name__ == "__main__":
    main()
