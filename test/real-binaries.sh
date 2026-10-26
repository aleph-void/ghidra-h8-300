#!/usr/bin/env bash
# Real-code checks on the binaries built by test/real/fetch-and-build.sh:
#   test/real-binaries.sh <built-workdir> <outdir>
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
B=$(readlink -f "$1")/bin; OUT=$(readlink -m "$2")
mkdir -p "$OUT"
status=0
lang_of() {
	case $1 in
	*h8300hn*) echo h8_300h:BE:32:normal ;;
	*h8300h*) echo h8_300h:BE:32:advanced ;;
	*h8sxn*) echo h8sx:BE:32:normal ;;
	*h8sx*) echo h8sx:BE:32:advanced ;;
	*h8sn*) echo h8s:BE:32:normal ;;
	*h8s*) echo h8s:BE:32:advanced ;;
	esac
}
for f in "$B"/*.elf; do
	n=$(basename "$f" .elf)
	echo "## $n"
	"$HERE/real-check.sh" "$f" "$OUT" "$(lang_of "$n")" </dev/null || status=1
done
echo "## relocatable objects"
"$HERE/reloc-check.sh" "$OUT/reloc" "$B"/obj/*.o || status=1
exit $status
