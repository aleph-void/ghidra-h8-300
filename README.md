# Hitachi H8/300 series processor definition for Ghidra 

Covers the H8/300, H8/300L, H8/300H, H8S/2000, H8S/2600 and H8SX CPUs:

| Language ID | CPU, operating mode |
|---|---|
| `h8_300:BE:16:normal` | H8/300 |
| `h8_300l:BE:16:normal` | H8/300L |
| `h8_300h:BE:32:normal`, `h8_300h:BE:32:advanced` | H8/300H, normal / advanced mode |
| `h8s:BE:32:normal`, `h8s:BE:32:advanced` | H8S/2000 and H8S/2600, normal / advanced mode |
| `h8sx:BE:32:normal`, `middle`, `advanced`, `maximum` | H8SX in its four operating modes |

ELF files from the GNU toolchain (`h8300-elf`) are recognised automatically (`EM_H8_300` and
the CPU in `e_flags`); pick the language by hand for raw images.

This is the [Ghidra-Rare](https://github.com/aleph-void/Ghidra-Rare) fork of the module: the
instruction set is now generated from the code tables of the Renesas manuals and tested against
GNU binutils. See [GHIDRA-RARE.md](GHIDRA-RARE.md) for what was tested and the results, and
[CREDITS.md](CREDITS.md) for the changes.

## Installation

* Download the zip for your Ghidra version from the fork's
  [Releases](https://github.com/aleph-void/ghidra-h8-300/releases) page and install it with
  `File -> Install Extensions...`, or
* build it: `GHIDRA_INSTALL_DIR=/path/to/ghidra gradle buildExtension` (Ghidra 12.1.3, 12.1.4
  and 12.2 are tested) and install the resulting `dist/ghidra_*_H8.zip` the same way.

## Bugs

Probably many! (Original note. The Ghidra-Rare fork fixed the ones its tests found: the H8/300
and H8/300H normal-mode specs did not compile, the compiler specs did not load (issue #1), and
most instructions decoded differently from the manuals. What remains is listed under "Known gaps"
in [GHIDRA-RARE.md](GHIDRA-RARE.md).)

## License

[WTFPL](./COPYING).
