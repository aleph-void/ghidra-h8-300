#!/usr/bin/env bash
# Decode differential: every language against GNU objdump 2.45 (slotdis, built from libopcodes)
# and against the manual's code table, on four corpora: three per core (gen_corpus.py: the code
# table with random fields, random slots, every first word) and one per language (asm_corpus.py:
# every instruction form written in GNU as syntax, assembled and linked by GNU as/ld).
#   test/decode-tests.sh <workdir> <slotdis> [language-filter]
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=$1 SLOTDIS=$2 FILTER=${3:-}
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
mkdir -p "$W"
# language id | core | objdump machine | mode | key (emu_tests.py/asm_corpus.py)
LANGS="h8_300:BE:16:normal 300 h8300 normal 300
h8_300l:BE:16:normal 300l h8300 normal 300l
h8_300h:BE:32:normal 300h h8300hn normal 300h_normal
h8_300h:BE:32:advanced 300h h8300h advanced24 300h_advanced
h8s:BE:32:normal h8s h8300sn normal h8s_normal
h8s:BE:32:advanced h8s h8300s advanced24 h8s_advanced
h8sx:BE:32:normal sx h8300sxn normal sx_normal
h8sx:BE:32:middle sx h8300sx middle sx_middle
h8sx:BE:32:advanced sx h8300sx advanced sx_advanced
h8sx:BE:32:maximum sx h8300sx maximum sx_maximum"
status=0
while read -r lang core mach mode key; do
	[[ -n $FILTER && $lang != *$FILTER* ]] && continue
	d=$W/$core
	if [[ ! -f $d/enum.bin ]]; then python3 "$HERE/gen_corpus.py" "$core" "$d" 1; fi
	tag=${lang//:/_}
	for c in table fuzz enum; do
		rm -f "$d/g_${tag}_$c.txt"
		"$HERE/ghidra-slots.sh" "$lang" "$d/$c.bin" 16 "$d/g_${tag}_$c.txt" </dev/null
		[[ -f $d/o_${mach}_$c.txt ]] || "$SLOTDIS" "$mach" 16 "$d/$c.bin" -e big >"$d/o_${mach}_$c.txt"
		if python3 "$HERE/compare.py" "$core" "$mode" "$d/$c.bin" "$d/g_${tag}_$c.txt" "$d/o_${mach}_$c.txt" \
			>"$d/cmp_${tag}_$c.txt"; then :; else status=1; fi
		echo "$lang $c: $(tail -1 "$d/cmp_${tag}_$c.txt")"
	done
	a=$W/asm/$key
	python3 "$HERE/asm_corpus.py" "$key" "$a" 3 >/dev/null
	rm -f "$a/g.txt"
	"$HERE/ghidra-slots.sh" "$lang" "$a/asm.bin" 16 "$a/g.txt" </dev/null
	"$SLOTDIS" "$mach" 16 "$a/asm.bin" -e big >"$a/o.txt"
	if python3 "$HERE/compare.py" "$core" "$mode" "$a/asm.bin" "$a/g.txt" "$a/o.txt" --expect "$a/asm.txt" \
		>"$a/cmp.txt"; then :; else status=1; fi
	echo "$lang asm: $(tail -1 "$a/cmp.txt"); $(grep '^== assembler' "$a/cmp.txt" | sed 's/^== //')"
done <<<"$LANGS"
exit $status
