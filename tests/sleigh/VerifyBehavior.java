// Run vectors from tests/behavior_model.py through the module's p-code in the emulator.
//
// Run by tests/test_behavior.sh under analyzeHeadless. Argument: the vector file.
//
// Each vector sets registers, flags and memory, runs one instruction at word 0x4000, and
// compares the registers, flags, MK, SW, next IC and every memory word the model touched.
//@category MIL1750A

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.Varnode;

public class VerifyBehavior extends GhidraScript {
	private static final int MAX_SHOWN = 200;
	private static final String[] REGISTERS = { "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7",
		"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15" };
	private static final String[] OPERATIONS = { "xio", "vio", "bex", "bif", "breakpoint",
		"fadd32", "fsub32", "fmul32", "fdiv32", "fabs32", "fneg32", "fcmp32", "fix32", "flt32",
		"fadd48", "fsub48", "fmul48", "fdiv48", "fcmp48", "fix48", "flt48" };

	private AddressSpace space;
	private EmulatorHelper emu;

	private Address word(long offset) {
		return space.getTruncatedAddress(offset & 0xFFFF, true);
	}

	/** Must match stub() in tests/behavior_model.py. */
	private class Stub extends BreakCallBack {
		private final long salt;

		Stub(String name) {
			salt = name.chars().sum();
		}

		@Override
		public boolean pcodeCallback(PcodeOpRaw op) {
			MemoryState state = emu.getEmulator().getMemState();
			long[] multipliers = { 3, 5, 7 };
			long total = salt;
			// Input 0 is the operation's index.
			for (int i = 1; i < op.getNumInputs(); i++) {
				total += multipliers[i - 1] * state.getValue(op.getInput(i));
			}
			Varnode output = op.getOutput();
			if (output != null) {
				long mask = output.getSize() >= 8 ? -1L : (1L << (8 * output.getSize())) - 1;
				state.setValue(output, total & mask);
			}
			return true;
		}
	}

	private static byte[] wordBytes(long value) {
		return new byte[] { (byte) (value >> 8), (byte) value };
	}

	private static Map<Long, Long> parseMemory(String text) {
		Map<Long, Long> memory = new TreeMap<>();
		if (!text.equals("-")) {
			for (String pair : text.split(";")) {
				String[] parts = pair.split("=");
				memory.put(Long.parseLong(parts[0], 16), Long.parseLong(parts[1], 16));
			}
		}
		return memory;
	}

	private void setFlags(int flags) {
		emu.writeRegister("CS_C", (flags >> 3) & 1);
		emu.writeRegister("CS_P", (flags >> 2) & 1);
		emu.writeRegister("CS_Z", (flags >> 1) & 1);
		emu.writeRegister("CS_N", flags & 1);
	}

	private int readFlags() {
		return emu.readRegister("CS_C").intValue() << 3 | emu.readRegister("CS_P").intValue() << 2 |
			emu.readRegister("CS_Z").intValue() << 1 | emu.readRegister("CS_N").intValue();
	}

	private String run(String[] f) throws Exception {
		String[] regsBefore = f[2].split(",");
		for (int i = 0; i < 16; i++) {
			emu.writeRegister(REGISTERS[i], Long.parseLong(regsBefore[i], 16));
		}
		setFlags(Integer.parseInt(f[3], 16));
		emu.writeRegister("MK", Long.parseLong(f[4], 16));
		emu.writeRegister("SW", Long.parseLong(f[5], 16));
		for (Map.Entry<Long, Long> entry : parseMemory(f[6]).entrySet()) {
			emu.writeMemory(word(entry.getKey()), wordBytes(entry.getValue()));
		}
		String code = f[1];
		for (int i = 0; i < code.length() / 4; i++) {
			emu.writeMemory(word(0x4000 + i),
				wordBytes(Long.parseLong(code.substring(i * 4, i * 4 + 4), 16)));
		}
		emu.writeRegister("IC", 0x4000);

		if (!emu.step(monitor)) {
			return "emulator stopped: " + emu.getLastError();
		}

		StringBuilder differences = new StringBuilder();
		long next = emu.getExecutionAddress().getAddressableWordOffset();
		long expectedNext = Long.parseLong(f[7], 16);
		if (next != expectedNext) {
			differences.append(String.format(" next %x, expected %x;", next, expectedNext));
		}
		String[] regsAfter = f[8].split(",");
		for (int i = 0; i < 16; i++) {
			long value = emu.readRegister(REGISTERS[i]).longValue();
			long expected = Long.parseLong(regsAfter[i], 16);
			if (value != expected) {
				differences.append(String.format(" %s %x, expected %x;", REGISTERS[i], value, expected));
			}
		}
		int flags = readFlags();
		int expectedFlags = Integer.parseInt(f[9], 16);
		if (flags != expectedFlags) {
			differences.append(String.format(" CS %x, expected %x;", flags, expectedFlags));
		}
		long mk = emu.readRegister("MK").longValue();
		if (mk != Long.parseLong(f[10], 16)) {
			differences.append(String.format(" MK %x, expected %s;", mk, f[10]));
		}
		long sw = emu.readRegister("SW").longValue();
		if (sw != Long.parseLong(f[11], 16)) {
			differences.append(String.format(" SW %x, expected %s;", sw, f[11]));
		}
		for (Map.Entry<Long, Long> entry : parseMemory(f[12]).entrySet()) {
			byte[] bytes = emu.readMemory(word(entry.getKey()), 2);
			long value = (bytes[0] & 0xFFL) << 8 | (bytes[1] & 0xFFL);
			if (value != entry.getValue()) {
				differences.append(String.format(" [%x] %x, expected %x;", entry.getKey(), value, entry.getValue()));
			}
		}
		return differences.toString();
	}

	@Override
	protected void run() throws Exception {
		space = currentProgram.getAddressFactory().getDefaultAddressSpace();
		long vectors = 0;
		long failures = 0;
		int shown = 0;
		Set<String> failed = new TreeSet<>();
		Set<String> seen = new TreeSet<>();
		try (var reader = Files.newBufferedReader(Path.of(getScriptArgs()[0]))) {
			String line;
			while ((line = reader.readLine()) != null) {
				String[] f = line.split("\t");
				vectors++;
				seen.add(f[0]);
				String result;
				// The emulator caches decoded p-code by address, so each vector needs a new one.
				emu = new EmulatorHelper(currentProgram);
				try {
					for (String name : OPERATIONS) {
						emu.registerCallOtherCallback(name, new Stub(name));
					}
					result = run(f);
				}
				catch (Exception e) {
					result = "exception: " + e;
				}
				finally {
					emu.dispose();
				}
				if (!result.isEmpty()) {
					failures++;
					failed.add(f[0]);
					if (failed.size() <= MAX_SHOWN && failed.size() > shown) {
						shown = failed.size();
						println("BEHAVIOR ERROR " + f[0] + " " + f[1] + " before " + f[2] + " cs=" + f[3] + " mem=" + f[6] + ":" + result);
					}
				}
			}
		}
		println("BEHAVIOR " + vectors + " vectors, " + seen.size() + " mnemonics, " + failures + " failed");
		println("BEHAVIOR failing mnemonics: " + failed);
		println(failures == 0 && vectors > 0 ? "BEHAVIOR PASSED" : "BEHAVIOR FAILED");
	}
}
