/* This file is part of the H8 processor module for Ghidra (WTFPL, see LICENSE). */
package ghidra.app.util.bin.format.elf.relocation;

/**
 * Hitachi/Renesas H8 ELF relocation types emitted by the GNU toolchain (h8300-elf), with the
 * numbers as GNU readelf names them.
 */
public enum H8_ElfRelocationType implements ElfRelocationType {

	R_H8_NONE(0),
	R_H8_DIR32(1),
	R_H8_DIR16(17),
	R_H8_PCREL16(31),
	R_H8_PCREL8(32),
	R_H8_DIR24A8(61),
	R_H8_DIR24R8(62),
	R_H8_DIR32A16(63),
	R_H8_DISP32A16(64);

	public final int typeId;

	private H8_ElfRelocationType(int typeId) {
		this.typeId = typeId;
	}

	@Override
	public int typeId() {
		return typeId;
	}
}
