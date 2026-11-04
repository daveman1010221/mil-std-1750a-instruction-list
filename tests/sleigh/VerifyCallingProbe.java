// Decompile tests/sleigh/calling_probe.s and check what each probe function returns.
//
// Run by tests/test_real_code.sh under analyzeHeadless. Argument: the symbol map from
// assemble_1750.py.
//@category MIL1750A

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;

public class VerifyCallingProbe extends GhidraScript {
	@Override
	protected void run() throws Exception {
		AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
		Map<String, Address> symbols = new HashMap<>();
		boolean inSymbols = false;
		for (String row : Files.readAllLines(Path.of(getScriptArgs()[0]))) {
			if (row.startsWith("# word\tsymbol")) {
				inSymbols = true;
			}
			else if (inSymbols) {
				String[] fields = row.split("\t");
				symbols.put(fields[1], space.getTruncatedAddress(Long.parseLong(fields[0], 16), true));
			}
		}
		for (Address start : symbols.values()) {
			disassemble(start);
			createFunction(start, null);
		}

		DecompInterface decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);
		boolean passed = true;
		passed &= check(decompiler, symbols.get("PROBE_STACK"), "return 7;", true);
		passed &= check(decompiler, symbols.get("PROBE_SAVED"), "return 9;", true);
		passed &= check(decompiler, symbols.get("PROBE_KILLED"), "return 9;", false);
		decompiler.dispose();
		println(passed ? "PROBE PASSED" : "PROBE FAILED");
	}

	private boolean check(DecompInterface decompiler, Address start, String text, boolean wanted) {
		Function function = getFunctionAt(start);
		DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
		String c = results.decompileCompleted() ? results.getDecompiledFunction().getC() : "";
		boolean ok = results.decompileCompleted() && c.contains(text) == wanted;
		println("PROBE " + (ok ? "OK " : "ERROR ") + function.getName() + (wanted ? " has " : " lacks ") +
			text + (ok ? "" : "\n" + c));
		return ok;
	}
}
