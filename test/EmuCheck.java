// Runs the H8 p-code semantic tests produced by emu_tests.py in Ghidra's p-code emulator.
// The program must be emu.bin imported raw at address 0.
// Script args: <tests.txt> <outfile>
//   tests.txt lines: <name> <start-hex> <stop-hex> <init key=val,...|-> <expect key=val,...>
//   keys: register names, or m1:/m2:/m4:<hex address> for 1/2/4-byte big-endian memory
// Before every test all general registers, CCR flags, EXR, VBR and MAC are 0, SP is 3F00 and SBR
// (H8SX) is FFFFFF00.
//@category Testing

import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;

public class EmuCheck extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		PrintStream out = new PrintStream(args[1]);
		int pass = 0, fail = 0;
		for (String line : Files.readAllLines(Path.of(args[0]))) {
			line = line.trim();
			if (line.isEmpty() || line.startsWith("#")) {
				continue;
			}
			String[] f = line.split("\\s+");
			String err = runOne(f);
			if (err == null) {
				pass++;
				out.println("PASS " + f[0]);
			}
			else {
				fail++;
				out.println("FAIL " + f[0] + ": " + err);
			}
		}
		out.printf("emulator tests: %d passed, %d failed%n", pass, fail);
		out.close();
	}

	// context values of the running test; the emulator does not carry them across branches, so
	// they are set again before every step (as the program context does for the disassembler)
	private java.util.List<ghidra.program.model.lang.RegisterValue> ctx = new java.util.ArrayList<>();

	private void setContext(Register r, BigInteger v) throws Exception {
		for (ghidra.program.model.mem.MemoryBlock b : currentProgram.getMemory().getBlocks()) {
			currentProgram.getProgramContext().setValue(r, b.getStart(), b.getEnd(), v);
		}
	}

	private Address addr(long a) {
		return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(a);
	}

	private void put(EmulatorHelper emu, String k, BigInteger v) throws Exception {
		if (k.matches("m[124]:[0-9a-fA-F]+")) {
			int n = k.charAt(1) - '0';
			long a = Long.parseLong(k.substring(3), 16);
			byte[] b = new byte[n];
			for (int i = 0; i < n; i++) {
				b[n - 1 - i] = v.shiftRight(8 * i).byteValue();
			}
			emu.writeMemory(addr(a), b);
		}
		else {
			Register r = currentProgram.getRegister(k);
			if (r.isProcessorContext()) {
				// a context bit (exrvalid, macsat): decode the whole test, including the code
				// reached by branches, with it set (the program context, not just the start)
				setContext(r, v);
				ctx.add(new ghidra.program.model.lang.RegisterValue(r, v));
			}
			else {
				emu.writeRegister(k, v);
			}
		}
	}

	private BigInteger get(EmulatorHelper emu, String k) throws Exception {
		if (k.matches("m[124]:[0-9a-fA-F]+")) {
			int n = k.charAt(1) - '0';
			long a = Long.parseLong(k.substring(3), 16);
			byte[] b = emu.readMemory(addr(a), n);
			BigInteger v = BigInteger.ZERO;
			for (int i = 0; i < n; i++) {
				v = v.shiftLeft(8).or(BigInteger.valueOf(b[i] & 0xff));
			}
			return v;
		}
		Register r = currentProgram.getRegister(k);
		BigInteger mask = BigInteger.ONE.shiftLeft(r.getBitLength()).subtract(BigInteger.ONE);
		return emu.readRegister(r).and(mask);
	}

	private String runOne(String[] f) throws Exception {
		Address start = addr(Long.parseUnsignedLong(f[1], 16));
		Address stop = addr(Long.parseUnsignedLong(f[2], 16));
		ctx.clear();
		for (String c : new String[] { "exrvalid", "macsat" }) {
			Register r = currentProgram.getRegister(c);
			if (r != null) {
				setContext(r, BigInteger.ZERO);
			}
		}
		EmulatorHelper emu = new EmulatorHelper(currentProgram);
		try {
			boolean er = currentProgram.getRegister("er0") != null;
			for (int i = 0; i < 8; i++) {
				emu.writeRegister((er ? "er" : "r") + i, 0);
			}
			for (String fl : new String[] { "I", "UI", "H", "U", "N", "Z", "V", "C", "exr", "vbr",
				"sbr", "mach", "macl", "macn", "macz", "macv" }) {
				if (currentProgram.getRegister(fl) != null) {
					emu.writeRegister(fl, 0);
				}
			}
			if (currentProgram.getRegister("sbr") != null) {
				emu.writeRegister("sbr", 0xffffff00L);
			}
			emu.writeRegister(er ? "er7" : "r7", 0x3f00);
			if (!f[3].equals("-")) {
				for (String kv : f[3].split(",")) {
					String[] p = kv.split("=");
					put(emu, p[0], new BigInteger(p[1], 16));
				}
			}
			emu.writeRegister(emu.getPCRegister(), start.getOffset());
			// step (at most 200000 instructions) until the stop address
			int steps = 0;
			while (!emu.getExecutionAddress().equals(stop)) {
				if (++steps > 200000) {
					return "did not reach " + stop + " within 200000 instructions (at " +
						emu.getExecutionAddress() + ")";
				}
				for (ghidra.program.model.lang.RegisterValue c : ctx) {
					emu.setContextRegister(c);
				}
				if (!emu.step(monitor)) {
					return "did not reach " + stop + " (fault at " + emu.getExecutionAddress() +
						", " + emu.getLastError() + ")";
				}
			}
			StringBuilder bad = new StringBuilder();
			for (String kv : f[4].split(",")) {
				String[] p = kv.split("=");
				BigInteger want = new BigInteger(p[1], 16);
				BigInteger got = get(emu, p[0]);
				if (!want.equals(got)) {
					bad.append(String.format(" %s=%x (want %x)", p[0], got, want));
				}
			}
			return bad.length() == 0 ? null : bad.toString().trim();
		}
		finally {
			emu.dispose();
		}
	}
}
