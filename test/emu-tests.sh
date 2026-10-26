#!/usr/bin/env bash
# Emulator tests for every language: assemble emu_tests.py's sequences with h8300-elf-as/ld, run
# them with EmuCheck.java, and check that a deliberately broken expectation is reported.
#   test/emu-tests.sh <workdir> [language-filter]
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=$1 FILTER=${2:-}
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
status=0
while read -r key lang brk; do
	[[ -n $FILTER && $key != *$FILTER* ]] && continue
	d=$W/$key
	python3 "$HERE/emu_tests.py" "$key" "$d" >/dev/null
	"$HERE/ghidra-script.sh" raw "$lang" "$d/emu.bin" EmuCheck.java "$d/emu.txt" "$d/out.txt" </dev/null 2>"$d/log.txt" || true
	echo "$lang: $(tail -1 "$d/out.txt")"
	if grep '^FAIL' "$d/out.txt"; then status=1; fi
	# a wrong expectation must be detected
	python3 "$HERE/emu_tests.py" "$key" "$d/broken" --break "$brk" >/dev/null
	"$HERE/ghidra-script.sh" raw "$lang" "$d/broken/emu.bin" EmuCheck.java "$d/broken/emu.txt" "$d/broken/out.txt" </dev/null 2>/dev/null || true
	if grep -q "^FAIL $brk:" "$d/broken/out.txt"; then
		echo "$lang: broken expectation detected ($(grep "^FAIL $brk:" "$d/broken/out.txt"))"
	else
		echo "$lang: broken expectation NOT detected"; status=1
	fi
done <<'X'
300 h8_300:BE:16:normal add_b_overflow
300l h8_300l:BE:16:normal add_b_overflow
300h_normal h8_300h:BE:32:normal add_w_carry
300h_advanced h8_300h:BE:32:advanced add_w_carry
h8s_normal h8s:BE:32:normal mac
h8s_advanced h8s:BE:32:advanced mac
sx_normal h8sx:BE:32:normal sx_movsd
sx_middle h8sx:BE:32:middle sx_movsd
sx_advanced h8sx:BE:32:advanced sx_movsd
sx_maximum h8sx:BE:32:maximum sx_movsd
X
exit $status
