// For a relocatable ELF imported by Ghidra: write the address and bytes of every initialized
// memory block and the address of every symbol in the EXTERNAL block, so test/reloc_check.py can
// link the same object with GNU ld at the same addresses and compare the relocated bytes.
// Script args: <outfile>
//@category Testing

import java.io.PrintStream;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.reloc.Relocation;

public class RelocDump extends GhidraScript {
	@Override
	protected void run() throws Exception {
		PrintStream out = new PrintStream(getScriptArgs()[0]);
		for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
			if (b.getName().equals("EXTERNAL")) {
				out.printf("external %x %x%n", b.getStart().getOffset(), b.getSize());
				continue;
			}
			if (!b.isInitialized() || !b.getStart().getAddressSpace().getName().equals("ram")) {
				continue;
			}
			byte[] d = new byte[(int) b.getSize()];
			b.getBytes(b.getStart(), d);
			StringBuilder sb = new StringBuilder();
			for (byte x : d) {
				sb.append(String.format("%02x", x & 0xff));
			}
			out.printf("block %s %x %s%n", b.getName(), b.getStart().getOffset(), sb);
		}
		for (Symbol s : currentProgram.getSymbolTable().getAllSymbols(false)) {
			MemoryBlock b = currentProgram.getMemory().getBlock(s.getAddress());
			if (b != null && b.getName().equals("EXTERNAL")) {
				out.printf("extsym %s %x%n", s.getName(), s.getAddress().getOffset());
			}
		}
		int bad = 0, n = 0;
		var it = currentProgram.getRelocationTable().getRelocations();
		while (it.hasNext()) {
			Relocation r = it.next();
			n++;
			if (r.getStatus() != Relocation.Status.APPLIED && r.getStatus() != Relocation.Status.APPLIED_OTHER &&
				r.getStatus() != Relocation.Status.SKIPPED) {
				bad++;
				out.printf("reloc-status %x %d %s%n", r.getAddress().getOffset(), r.getType(), r.getStatus());
			}
		}
		out.printf("relocations %d not-applied %d%n", n, bad);
		out.close();
	}
}
