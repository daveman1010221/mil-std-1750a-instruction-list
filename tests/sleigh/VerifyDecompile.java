// Decompile every function in the Dhrystone sample and check the recovered prototypes.
//
// Run by tests/test_real_code.sh under analyzeHeadless. Argument: the symbol map from
// assemble_1750.py. Checks the parameter count and whether a value is returned against
// Dhrystone's C prototypes, and that no register is used uninitialized. Prints each
// function's C for a person to read, because this doesn't show the bodies are right.
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
import ghidra.program.model.pcode.FunctionPrototype;

public class VerifyDecompile extends GhidraScript {
	/**
	 * Parameter count from Dhrystone's prototypes; Func_* return a value, Proc_* don't. The
	 * exception is PROC_2: Enum_Loc is uninitialized in the C, and GCC reads it from R3 unset,
	 * so R0-R3 look like inputs.
	 */
	private static final Map<String, Integer> PARAMETERS = Map.ofEntries(
		Map.entry("PROC_1", 1), Map.entry("PROC_2", 4), Map.entry("PROC_3", 1),
		Map.entry("PROC_4", 0), Map.entry("PROC_5", 0), Map.entry("PROC_6", 2),
		Map.entry("PROC_7", 3), Map.entry("PROC_8", 4), Map.entry("FUNC_1", 2),
		Map.entry("FUNC_2", 2), Map.entry("FUNC_3", 1));

	private String prototypeError(Function function, DecompileResults results) {
		Integer expected = PARAMETERS.get(function.getName());
		if (expected == null) {
			return null;
		}
		FunctionPrototype prototype = results.getHighFunction().getFunctionPrototype();
		if (prototype.getNumParams() != expected) {
			return prototype.getNumParams() + " parameters, expected " + expected;
		}
		boolean returnsValue = !prototype.getReturnType().getName().equals("void");
		if (returnsValue != function.getName().startsWith("FUNC_")) {
			return "return type " + prototype.getReturnType().getName();
		}
		return null;
	}

	@Override
	protected void run() throws Exception {
		AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
		long imageEnd = currentProgram.getMemory().getSize() / 2;
		Set<Long> functionStarts = new TreeSet<>();
		boolean symbols = false;
		for (String row : Files.readAllLines(Path.of(getScriptArgs()[0]))) {
			if (row.startsWith("# word\tsymbol")) {
				symbols = true;
				continue;
			}
			if (!symbols) {
				continue;
			}
			String[] fields = row.split("\t");
			long address = Long.parseLong(fields[0], 16);
			if (address < imageEnd) {
				Address start = space.getTruncatedAddress(address, true);
				functionStarts.add(address);
				createLabel(start, fields[1], true);
			}
		}
		disassemble(space.getTruncatedAddress(0, true));
		for (long address : functionStarts) {
			Address start = space.getTruncatedAddress(address, true);
			if (getInstructionAt(start) == null) {
				disassemble(start);
			}
			if (getFunctionAt(start) == null) {
				createFunction(start, null);
			}
		}

		DecompInterface decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);
		int failed = 0;
		int total = 0;
		int prototypes = 0;
		for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
			total++;
			DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
			String c = results.decompileCompleted() ? results.getDecompiledFunction().getC() : "";
			boolean ok = results.decompileCompleted() && !c.contains("halt_unimplemented") &&
				!c.contains("Bad instruction") && !c.contains("unaff_");
			String prototypeError = results.decompileCompleted() ? prototypeError(function, results) : null;
			if (!ok || prototypeError != null) {
				failed++;
				println("DECOMPILE ERROR " + function.getName() + ": " +
					(prototypeError != null ? prototypeError : results.getErrorMessage()));
			}
			prototypes += prototypeError == null && PARAMETERS.containsKey(function.getName()) ? 1 : 0;
			println("DECOMPILE C " + function.getName() + "\n" + c);
		}
		decompiler.dispose();
		println("DECOMPILE " + (total - failed) + " of " + total + " functions decompiled");
		println("DECOMPILE " + prototypes + " of " + PARAMETERS.size() + " prototypes match");
		println(failed == 0 && prototypes == PARAMETERS.size() ? "DECOMPILE PASSED" : "DECOMPILE FAILED");
	}
}
