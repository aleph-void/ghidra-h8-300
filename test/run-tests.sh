#!/usr/bin/env bash
# H8 processor module tests.
#
#   test/run-tests.sh <workdir> [--real]
#
# 1. the generator reproduces the checked-in SLEIGH and spec files (tools/gen_h8.py,
#    tools/gen_specs.py), and the code table JSON is reproducible from the clean step
# 2. every .slaspec compiles (sizes printed); the module is linked into
#    $GHIDRA_INSTALL_DIR/Ghidra/Processors/H8 and lib/H8.jar is built
# 3. decode differential (decode-tests.sh) for all nine languages against GNU objdump and the
#    manual's code table: code table, random and every-first-word corpora plus the assembler
#    corpus; 0 unexplained differences required
# 4. every-entry decode test (CoverageCheck.java) for every language
# 5. emulator tests (emu-tests.sh): hand-computed sequences, and a broken expectation must fail
# 6. with --real: build the real-code binaries (test/real/fetch-and-build.sh) and check them
#    (real-binaries.sh: headless import, decompile, objdump comparison, relocation check), and
#    run the GDB simulator's self-checking H8 test programs in the emulator (simtests.sh)
#
# Environment:
#   GHIDRA_INSTALL_DIR  Ghidra 12.1.x/12.2 to test with
#   H8_TC               h8300-elf toolchain prefix (test/build-toolchain.sh), default
#                       ~/.cache/ghidra-rare-scratch/tools/x-h8300-elf
#   SLOTDIS             slotdis binary; if unset it is built from slotdis.c with BU_SRC/BU_BUILD
#   BU_SRC, BU_BUILD    binutils 2.45 source tree and its h8300-elf build tree
#   JAVA_HOME           a JDK (javac) for lib/H8.jar
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(cd "$HERE/.." && pwd)
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
W=$(mkdir -p "${1:?usage: run-tests.sh <workdir> [--real]}" && cd "$1" && pwd)
REAL=${2:-}
export H8_TC=${H8_TC:-$HOME/.cache/ghidra-rare-scratch/tools/x-h8300-elf}
export H8_TOOLS=$H8_TC/bin
status=0
cd "$W"

echo "== generator reproduces the checked-in files"
rm -rf gen && mkdir -p gen
python3 "$MOD/tools/gen_h8.py" gen >/dev/null
python3 "$MOD/tools/gen_specs.py" gen
for f in gen/*; do
	if ! cmp -s "$f" "$MOD/data/languages/$(basename "$f")"; then
		echo "   differs: $(basename "$f")"; status=1
	fi
done
echo "   $(ls gen | wc -l) files compared"

echo "== compiling SLEIGH"
for s in "$MOD"/data/languages/*.slaspec; do
	"$GHIDRA_INSTALL_DIR/support/sleigh" "$s" 2>&1 | grep -E "^ERROR|^Error" && status=1 || true
done
ls -l "$MOD"/data/languages/*.sla | awk '{print "   " $5, $9}'
P="$GHIDRA_INSTALL_DIR/Ghidra/Processors/H8"
if [[ ! -e $P ]]; then ln -s "$MOD" "$P"; elif [[ $(readlink -f "$P") != "$MOD" ]]; then
	echo "warning: $P exists and is not this module" >&2; fi
"$HERE/build-jar.sh"

if [[ -z ${SLOTDIS:-} ]]; then
	: "${BU_SRC:?set SLOTDIS, or BU_SRC and BU_BUILD to build it}" "${BU_BUILD:?}"
	SLOTDIS=$W/slotdis
	gcc -O2 -include "$BU_BUILD/bfd/config.h" -o "$SLOTDIS" "$HERE/slotdis.c" -I"$BU_BUILD/bfd" \
		-I"$BU_SRC/include" -I"$BU_SRC/bfd" "$BU_BUILD/opcodes/.libs/libopcodes.a" \
		"$BU_BUILD/bfd/.libs/libbfd.a" "$BU_BUILD/libiberty/libiberty.a" \
		"$BU_BUILD/libsframe/.libs/libsframe.a" "$BU_BUILD/zlib/libz.a" -lzstd 2>/dev/null
fi

echo "== decode differential"
"$HERE/decode-tests.sh" "$W/dec" "$SLOTDIS" | tee "$W/dec.log" || status=1

echo "== every-entry decode test"
head -c 64 /dev/zero >zero.bin
for l in h8_300:BE:16:normal h8_300l:BE:16:normal h8_300h:BE:32:normal h8_300h:BE:32:advanced h8s:BE:32:normal \
	h8s:BE:32:advanced h8sx:BE:32:normal h8sx:BE:32:middle h8sx:BE:32:advanced h8sx:BE:32:maximum; do
	t=${l//:/_}
	"$HERE/ghidra-script.sh" raw "$l" zero.bin CoverageCheck.java "$W/cov_$t.txt" 64 </dev/null
	echo "   $l: $(tail -1 "cov_$t.txt")"
	if grep '^unreached' "cov_$t.txt" | head -20; then status=1; fi
done

echo "== p-code emulator tests"
"$HERE/emu-tests.sh" "$W/emu" || status=1

if [[ $REAL == --real ]]; then
	echo "== real binaries"
	"$HERE/real/fetch-and-build.sh" "$W/real"
	"$HERE/real-binaries.sh" "$W/real" "$W/realout" || status=1
	echo "== GDB simulator test programs"
	"$HERE/simtests.sh" "$W/sim" || status=1
fi

echo "== summary"
cat "$W/dec.log"
grep -h "^coverage" "$W"/cov_*.txt
grep -h "emulator tests" "$W"/emu/*/out.txt
exit $status
