/* This file is part of the H8 processor module for Ghidra (WTFPL, see LICENSE). */
package ghidra.app.util.bin.format.elf.relocation;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;

/**
 * ELF relocation handler for the H8 family (EM_H8_300 = 46; all GNU H8 cores use it).
 * <p>
 * The formulas were worked out from the relocation sites in GCC-built objects and checked
 * against GNU ld (test/reloc-check.sh): DIR32, DIR24A8, DIR32A16 and DISP32A16 store S + A in
 * a 32-bit field (the "A8"/"A16" forms only mark fields the linker may relax), DIR16 a 16-bit
 * field, DIR24R8 the low 24 bits of a 32-bit field whose first byte is the opcode (jmp/jsr
 * @aa:24), PCREL8 and PCREL16 the displacement from the end of the field: S + A - (P + 1) and
 * S + A - (P + 2).
 */
public class H8_ElfRelocationHandler
		extends AbstractElfRelocationHandler<H8_ElfRelocationType, ElfRelocationContext<?>> {

	public static final int EM_H8_300 = 46;

	public H8_ElfRelocationHandler() {
		super(H8_ElfRelocationType.class);
	}

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == EM_H8_300;
	}

	@Override
	protected RelocationResult relocate(ElfRelocationContext<?> ctx, ElfRelocation relocation,
			H8_ElfRelocationType type, Address relocationAddress, ElfSymbol elfSymbol,
			Address symbolAddr, long symbolValue, String symbolName)
			throws MemoryAccessException {

		Program program = ctx.getProgram();
		Memory mem = program.getMemory();
		long A = relocation.getAddend();
		long P = relocationAddress.getOffset();

		if (type == H8_ElfRelocationType.R_H8_NONE) {
			return RelocationResult.SKIPPED;
		}
		if (relocation.getSymbolIndex() != 0 && handleUnresolvedSymbol(ctx, relocation, relocationAddress)) {
			return RelocationResult.FAILURE;
		}
		long v = symbolValue + A;
		switch (type) {
			case R_H8_DIR32:
			case R_H8_DIR24A8:
			case R_H8_DIR32A16:
			case R_H8_DISP32A16:
				mem.setInt(relocationAddress, (int) v, true);
				return new RelocationResult(Status.APPLIED, 4);
			case R_H8_DIR16:
				mem.setShort(relocationAddress, (short) v, true);
				return new RelocationResult(Status.APPLIED, 2);
			case R_H8_DIR24R8: {
				Address a = relocationAddress.subtract(1);
				int w = mem.getInt(a, true);
				mem.setInt(a, (w & 0xff000000) | (int) (v & 0xffffff), true);
				return new RelocationResult(Status.APPLIED, 4);
			}
			case R_H8_PCREL16:
				mem.setShort(relocationAddress, (short) (v - (P + 2)), true);
				return new RelocationResult(Status.APPLIED, 2);
			case R_H8_PCREL8:
				mem.setByte(relocationAddress, (byte) (v - (P + 1)));
				return new RelocationResult(Status.APPLIED, 1);
			default:
				markAsUnhandled(program, relocationAddress, type, relocation.getSymbolIndex(),
					symbolName, ctx.getLog());
				return RelocationResult.UNSUPPORTED;
		}
	}
}
