// Runs the GDB simulator's H8 test programs (sim/testsuite/h8300, assembled by simtests.sh) in
// Ghidra's p-code emulator. Each program checks its own results and ends by jumping to
// _write_and_exit with ER1 (R1 on the H8/300) pointing at "pass\n" or "fail\n".
// Script args: <list-file> <outfile>   (list: one ELF path per line)
//@category Testing

import java.io.File;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;

public class SimTests extends GhidraScript {

	private Address sym(Program p, String name) {
		for (Symbol s : p.getSymbolTable().getSymbols(name)) {
			return s.getAddress();
		}
		return null;
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		PrintStream out = new PrintStream(args[1]);
		int pass = 0, fail = 0;
		for (String line : Files.readAllLines(Path.of(args[0]))) {
			if (line.isBlank()) {
				continue;
			}
			File f = new File(line.trim());
			Program p = importFile(f);
			String res;
			try {
				res = runOne(p);
			}
			catch (Exception e) {
				res = "error " + e;
			}
			finally {
				p.release(this);
			}
			if (res.startsWith("pass")) {
				pass++;
			}
			else {
				fail++;
			}
			out.println(f.getName() + " " + p.getLanguageID() + " " + res);
		}
		out.printf("simulator tests: %d passed, %d failed%n", pass, fail);
		out.close();
	}

	private String runOne(Program p) throws Exception {
		Address start = sym(p, "_start");
		Address done = sym(p, "_write_and_exit");
		Address exit = sym(p, "_exit");
		Address passStr = sym(p, "pass_str");
		if (start == null || done == null || passStr == null) {
			return "error: symbols missing";
		}
		EmulatorHelper emu = new EmulatorHelper(p);
		try {
			boolean er = p.getRegister("er0") != null;
			boolean normal = p.getAddressFactory().getDefaultAddressSpace().getSize() == 16;
			emu.writeRegister(er ? "er7" : "r7", normal ? 0xff00 : 0x00fff000L);
			if (p.getRegister("sbr") != null) {
				emu.writeRegister("sbr", 0xffffff00L);
			}
			emu.writeRegister(emu.getPCRegister(), start.getOffset());
			int steps = 0;
			java.util.ArrayDeque<String> hist = new java.util.ArrayDeque<>();
			while (true) {
				Address pc = emu.getExecutionAddress();
				hist.addLast(pc.toString());
				if (hist.size() > 12) {
					hist.removeFirst();
				}
				if (pc.equals(done)) {
					long r1 = emu.readRegister(er ? "er1" : "r1").longValue();
					return (r1 == passStr.getOffset() ? "pass" : "fail (r1=" + Long.toHexString(r1) + ", last pcs " + hist + ")") +
						" " + steps + " instructions";
				}
				if (exit != null && pc.equals(exit)) {
					return "fail: reached _exit (code " + emu.readRegister(er ? "er0" : "r0") + ")";
				}
				if (++steps > 500000) {
					return "fail: no result within 500000 instructions (at " + pc + ")";
				}
				if (!emu.step(monitor)) {
					return "fail: fault at " + pc + ": " + emu.getLastError();
				}
			}
		}
		finally {
			emu.dispose();
		}
	}
}
