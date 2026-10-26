#!/usr/bin/env bash
# Third-party semantic check: the GDB simulator's H8 test programs (sim/testsuite/h8300 of GDB
# 17.2, GPL-3.0, pinned tarball, never committed), assembled for every machine their header lists
# (h8300, h8300h, h8300s, h8sx) with GNU as/ld, imported through the ELF loader (language from
# the ELF opinion) and run in Ghidra's emulator by SimTests.java. Each program checks its own
# results and reports pass or fail. Blocks that check simulator behaviour the manuals contradict are
# dropped first (sim_filter.py, listed in dropped.txt).
#   test/simtests.sh <workdir>     (GHIDRA_INSTALL_DIR set; H8_TC = h8300-elf toolchain prefix)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mkdir -p "$1" && cd "$1" && pwd)
TC=${H8_TC:-$HOME/.cache/ghidra-rare-scratch/tools/x-h8300-elf}
f=gdb-17.2.tar.xz
cd "$W"
[[ -f $f ]] || curl -fsSL -o $f https://ftp.gnu.org/gnu/gdb/gdb-17.2.tar.xz
echo "1c036c0d72e4b3d1fb5c94c88632add6f9d76f4d7c4d2ea793c12a9f19a3228c  $f" | sha256sum -c --quiet
[[ -d gdb-17.2/sim/testsuite/h8300 ]] || tar xJf $f gdb-17.2/sim/testsuite/h8300
S0=$W/gdb-17.2/sim/testsuite/h8300
S=$W/src
mkdir -p elf src
cp "$S0/testutils.inc" src/
: >dropped.txt
for s in "$S0"/*.s; do python3 "$HERE/sim_filter.py" "$s" "src/$(basename "$s")" >>dropped.txt; done
: >list.txt
declare -A CPU=([h8300]=0 [h8300h]=1 [h8300s]=2 [h8sx]=3)
declare -A EMU=([h8300]=h8300elf [h8300h]=h8300helf [h8300s]=h8300self [h8sx]=h8300sxelf)
for s in "$S"/*.s; do
	n=$(basename "$s" .s)
	machs=$(sed -n 's/^# mach(): *//p' "$s")
	[[ $machs == all ]] && machs="h8300 h8300h h8300s h8sx"
	for m in $machs; do
		o=elf/${n}_$m
		"$TC/bin/h8300-elf-as" -I"$S" --defsym sim_cpu=${CPU[$m]} -o "$o.o" "$s"
		"$TC/bin/h8300-elf-ld" -m ${EMU[$m]} -o "$o.elf" "$o.o"
		echo "$W/$o.elf" >>list.txt
	done
done
echo "$(wc -l <list.txt) programs"
head -c 16 /dev/zero >stub.bin
"$HERE/ghidra-script.sh" raw h8sx:BE:32:advanced stub.bin SimTests.java "$W/list.txt" "$W/out.txt" </dev/null
grep -v ' pass ' out.txt || true
tail -1 out.txt
# Two programs still fail after the filter, at checks that expect the running totals or stored
# values of blocks the filter dropped (addb.s: byte_dest after the abs8 additions; stc.s:
# check_results reads the EXR stores). Anything else failing is an error.
KNOWN='^(addb_h8sx|stc_h8sx)\.elf '
! grep '\.elf .* \(fail\|error\)' out.txt | grep -vE "$KNOWN" | grep -q .
