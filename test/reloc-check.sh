#!/usr/bin/env bash
# Relocation handler check: import each relocatable object with Ghidra's ELF loader, link it with
# GNU ld at the same addresses and compare the relocated bytes.
#   test/reloc-check.sh <workdir> <obj.o>...   (GHIDRA_INSTALL_DIR set; H8_TC = toolchain prefix)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(readlink -m "$1"); shift
TC=${H8_TC:-$HOME/.cache/ghidra-rare-scratch/tools/x-h8300-elf}
mkdir -p "$W"
status=0
for o in "$@"; do
	n=$(basename "$o" .o)
	"$HERE/ghidra-script.sh" elf-noanalysis - "$o" RelocDump.java "$W/$n.dump" </dev/null
	python3 "$HERE/reloc_check.py" "$o" "$W/$n.dump" "$TC/bin/h8300-elf-ld" "$W/$n" || status=1
done
exit $status
