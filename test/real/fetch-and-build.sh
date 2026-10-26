#!/usr/bin/env bash
# Build the real-code test binaries:  test/real/fetch-and-build.sh <workdir>
# H8_TC = h8300-elf toolchain prefix (binutils 2.45, GCC 14.3, newlib 4.5; see GHIDRA-RARE.md),
# default ~/.cache/ghidra-rare-scratch/tools/x-h8300-elf.  Nothing built here is committed.
#   tour_<cfg>.elf     test/real/src/tour.c with newlib (libc + libm), one per CPU/mode
#   zlib_<cfg>_*.elf   zlib 1.3.1 example.c / minigzip.c (pinned tarball, SHA-256 checked)
#   obj/*.o            relocatable zlib objects (relocation handler check)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(readlink -m "$1"); TC=${H8_TC:-$HOME/.cache/ghidra-rare-scratch/tools/x-h8300-elf}
CC=$TC/bin/h8300-elf-gcc
mkdir -p "$W/bin" "$W/src" "$W/obj" "$W/bin/obj"
cd "$W/src"
f=zlib-1.3.1.tar.gz
[[ -f $f ]] || curl -fsSL -o $f https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz
echo "9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23  $f" | sha256sum -c --quiet
[[ -d zlib-1.3.1 ]] || tar xzf $f
S=$HERE/src B=$W/bin O=$W/obj Z=$W/src/zlib-1.3.1
# name | flags
CFGS="h8300h -mh -O2
h8300hn -mh -mn -Os -DSMALL
h8s -ms -O2
h8s_int32 -ms -mint32 -Os
h8sn -ms -mn -Os -DSMALL
h8s2600 -ms -ms2600 -O2
h8sx -msx -O2
h8sx_int32 -msx -mint32 -O2
h8sxn -msx -mn -Os -DSMALL"
while read -r n flags; do
	"$CC" $flags -g -o "$B/tour_$n.elf" "$S/tour.c" -lm
done <<<"$CFGS"
for n in h8300h h8s h8sx; do
	flags="-m${n#h8300}"; [[ $n == h8300h ]] && flags=-mh; [[ $n == h8s ]] && flags=-ms; [[ $n == h8sx ]] && flags=-msx
	mkdir -p "$O/$n"
	for c in adler32 crc32 deflate infback inffast inflate inftrees trees zutil compress uncompr gzclose gzlib gzread gzwrite; do
		"$CC" $flags -mint32 -O2 -g -DHAVE_UNISTD_H -c "$Z/$c.c" -o "$O/$n/$c.o"
	done
	"$CC" $flags -mint32 -O2 -g -o "$B/zlib_${n}_example.elf" -I"$Z" "$Z/test/example.c" "$O/$n"/*.o
	"$CC" $flags -mint32 -O2 -g -o "$B/zlib_${n}_minigzip.elf" -I"$Z" "$Z/test/minigzip.c" "$O/$n"/*.o
done
cp "$O"/h8sx/{deflate,inflate}.o "$B/obj/"
cp "$O"/h8300h/trees.o "$B/obj/"
ls "$B"/*.elf "$B"/obj/*.o
