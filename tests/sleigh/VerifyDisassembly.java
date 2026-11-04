// Disassemble every encoding in the instruction list with the compiled MIL1750A module.
//
// Run by tests/test_sleigh.sh under analyzeHeadless. Arguments: the directory of list
// files, the file of defined first words, and the number of lines to expect.
//
// Checks each line's length, text and control flow, that every other first word fails
// to decode, branch targets near the address wrap, and flow following on a small program.
//@category MIL1750A

import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;

public class VerifyDisassembly extends GhidraScript {
	private static final int MAX_ERRORS = 50;
	private static final long BASE = 0x4000;
	private static final Set<String> RELATIVE = Set.of("BR", "BEZ", "BLT", "BLE", "BGT", "BNZ", "BGE");

	private final ConcurrentLinkedQueue<String> errors = new ConcurrentLinkedQueue<>();
	private final AtomicLong errorCount = new AtomicLong();
	private final AtomicLong lines = new AtomicLong();
	private Language language;
	private AddressSpace space;

	private void error(String message) {
		if (errorCount.incrementAndGet() <= MAX_ERRORS) {
			errors.add(message);
		}
	}

	private Address word(long offset) {
		return space.getTruncatedAddress(offset, true);
	}

	private Instruction decode(long address, byte[] bytes, ProcessorContextImpl context) throws Exception {
		ByteMemBufferImpl buffer = new ByteMemBufferImpl(word(address), bytes, true);
		InstructionPrototype prototype = language.parse(buffer, context, false);
		return new PseudoInstruction(word(address), prototype, buffer, context);
	}

	/** Hex values with no padding and upper case, so column widths don't matter. */
	private static String canonical(String text) {
		StringBuilder out = new StringBuilder(text.length());
		int length = text.length();
		for (int i = 0; i < length;) {
			if (text.startsWith("0x", i)) {
				int start = i + 2;
				int end = start;
				while (end < length && Character.digit(text.charAt(end), 16) >= 0) {
					end++;
				}
				out.append("0x").append(Long.toHexString(Long.parseLong(text.substring(start, end), 16)));
				i = end;
			}
			else {
				out.append(text.charAt(i++));
			}
		}
		return out.toString();
	}

	private static byte[] bytesOf(String hex) {
		byte[] bytes = new byte[hex.length() / 2];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) Integer.parseInt(hex, i * 2, i * 2 + 2, 16);
		}
		return bytes;
	}

	private void checkFlow(String line, String mnemonic, long first, long second, Instruction instruction) {
		int nibble = (int) (first >> 4 & 0xF);
		int rx = (int) (first & 0xF);
		boolean always = nibble == 7 || nibble == 0xF;
		FlowType flow = instruction.getFlowType();
		Address[] flows = instruction.getFlows();
		boolean ok;
		long target = -1;
		switch (mnemonic) {
			case "BR" -> {
				target = BASE + (byte) first & 0xFFFF;
				ok = flow.isJump() && flow.isUnConditional() && !flow.isComputed();
			}
			case "BEZ", "BLT", "BLE", "BGT", "BNZ", "BGE" -> {
				target = BASE + (byte) first & 0xFFFF;
				ok = flow.isJump() && flow.isConditional() && !flow.isComputed();
			}
			case "JC", "JCI" -> {
				boolean computed = mnemonic.equals("JCI") || rx != 0;
				if (!computed && nibble != 0) {
					target = second;
				}
				if (nibble == 0) {
					ok = flow.isFallthrough();
				}
				else {
					ok = flow.isJump() && flow.isComputed() == computed &&
						flow.isConditional() == !always;
				}
			}
			case "JS", "SJS" -> {
				if (rx == 0) {
					target = second;
				}
				ok = flow.isCall() && flow.isComputed() == (rx != 0);
			}
			case "SOJ" -> {
				if (rx == 0) {
					target = second;
				}
				ok = flow.isJump() && flow.isConditional() && flow.isComputed() == (rx != 0);
			}
			case "URS", "LST", "LSTI" -> ok = flow.isTerminal();
			default -> ok = flow.isFallthrough();
		}
		if (!ok) {
			error("wrong flow type " + flow + ": " + line);
		}
		boolean flowOk = target < 0 ? flows.length == 0
				: flows.length == 1 && flows[0].getAddressableWordOffset() == target;
		if (!flowOk) {
			error("wrong flow targets " + Arrays.toString(flows) + ": " + line);
		}
	}

	private void checkLink(String line, Instruction instruction) {
		// The return address must be in words: this instruction is at BASE and two words long.
		for (PcodeOp op : instruction.getPcode()) {
			for (Varnode input : op.getInputs()) {
				if (input.isConstant() && input.getOffset() == BASE + 2) {
					return;
				}
			}
		}
		error("return address is not " + Long.toHexString(BASE + 2) + ": " + line);
	}

	private void checkFile(Path path) {
		ProcessorContextImpl context = new ProcessorContextImpl(language);
		try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.US_ASCII)) {
			String line;
			while ((line = reader.readLine()) != null) {
				lines.incrementAndGet();
				checkLine(line, context);
			}
		}
		catch (Exception e) {
			error(path + ": " + e);
		}
	}

	private void checkLine(String line, ProcessorContextImpl context) {
		int space_ = line.indexOf(' ');
		String hex = line.substring(2, space_);
		byte[] bytes = bytesOf(hex);
		long first = Long.parseLong(hex.substring(0, 4), 16);
		long second = hex.length() == 8 ? Long.parseLong(hex.substring(4), 16) : 0;
		String text = line.substring(space_).stripLeading();
		int mnemonicEnd = text.indexOf(' ');
		String mnemonic = mnemonicEnd < 0 ? text : text.substring(0, mnemonicEnd);

		// The list shows raw displacements. The module shows the address they reach.
		String expected = RELATIVE.contains(mnemonic)
				? mnemonic + " 0x" + Long.toHexString(BASE + (byte) first & 0xFFFF)
				: canonical(text);
		try {
			Instruction instruction = decode(BASE, bytes, context);
			if (instruction.getLength() != bytes.length) {
				error("length " + instruction.getLength() + ": " + line);
			}
			String actual = canonical(instruction.toString());
			if (!actual.equals(expected)) {
				error("decoded as '" + actual + "': " + line);
			}
			checkFlow(line, mnemonic, first, second, instruction);
			if (second == 0x1234 && (mnemonic.equals("JS") || mnemonic.equals("SJS"))) {
				checkLink(line, instruction);
			}
		}
		catch (Exception e) {
			error("failed to decode (" + e.getClass().getSimpleName() + "): " + line);
		}
	}

	private void checkUndefinedWords(Path definedPath) throws Exception {
		Set<Integer> defined = new HashSet<>();
		for (String row : Files.readAllLines(definedPath)) {
			defined.add(Integer.parseInt(row.strip(), 16));
		}
		ProcessorContextImpl context = new ProcessorContextImpl(language);
		int rejected = 0;
		for (int word = 0; word < 0x10000; word++) {
			byte[] bytes = { (byte) (word >> 8), (byte) word, 0x12, 0x34 };
			boolean decoded = true;
			try {
				decode(BASE, bytes, context);
			}
			catch (Exception e) {
				decoded = false;
			}
			if (decoded != defined.contains(word)) {
				error(String.format("first word %04X: decoded=%b, defined=%b", word, decoded,
					defined.contains(word)));
			}
			if (!decoded) {
				rejected++;
			}
		}
		println("VERIFY defined first words: " + defined.size() + ", rejected: " + rejected);
	}

	private void checkAddressWrap() throws Exception {
		ProcessorContextImpl context = new ProcessorContextImpl(language);
		long[][] cases = {
			// address, displacement byte, expected target
			{ 0x0000, 0xFF, 0xFFFF },
			{ 0x0010, 0x80, 0xFF90 },
			{ 0xFFFF, 0x01, 0x0000 },
			{ 0xFFF0, 0x7F, 0x006F },
			{ 0x1234, 0x00, 0x1234 },
		};
		for (long[] test : cases) {
			Instruction instruction = decode(test[0], new byte[] { 0x74, (byte) test[1] }, context);
			Address[] flows = instruction.getFlows();
			if (flows.length != 1 || flows[0].getAddressableWordOffset() != test[2]) {
				error(String.format("BR at %04X disp %02X: got %s", test[0], test[1], Arrays.toString(flows)));
			}
		}
	}

	/** Run the real disassembler over the fixture from tests/test_sleigh.sh. */
	private void checkFlowFollowing() {
		Set<Long> reached = Set.of(0x0L, 0x1L, 0x3L, 0x6L, 0x8L, 0xAL, 0xBL, 0xCL, 0xDL);
		Set<Long> unreached = Set.of(0x4L, 0x5L, 0x9L);
		disassemble(word(0));
		for (long address : reached) {
			if (getInstructionAt(word(address)) == null) {
				error(String.format("fixture: no instruction at word %04X", address));
			}
		}
		for (long address : unreached) {
			if (getInstructionAt(word(address)) != null) {
				error(String.format("fixture: unexpected instruction at word %04X", address));
			}
		}
		Instruction call = getInstructionAt(word(1));
		if (call == null || call.getLength() != 4 || call.getFlows().length != 1 ||
			call.getFlows()[0].getAddressableWordOffset() != 8) {
			error("fixture: SJS at word 1 does not reach word 8");
		}
		println("VERIFY fixture listing:");
		for (long address = 0; address < 14; address++) {
			Instruction instruction = getInstructionAt(word(address));
			if (instruction != null) {
				println(String.format("VERIFY   %s  %s", instruction.getAddress(), instruction));
			}
		}
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		long expectedLines = Long.parseLong(args[2]);
		language = currentProgram.getLanguage();
		space = currentProgram.getAddressFactory().getDefaultAddressSpace();

		checkFlowFollowing();
		checkAddressWrap();
		checkUndefinedWords(Path.of(args[1]));

		List<Path> files;
		try (Stream<Path> listing = Files.list(Path.of(args[0]))) {
			files = listing.sorted().toList();
		}
		files.parallelStream().forEach(this::checkFile);

		if (lines.get() != expectedLines) {
			error("checked " + lines.get() + " lines, expected " + expectedLines);
		}
		for (String message : errors) {
			println("VERIFY ERROR " + message);
		}
		println("VERIFY checked " + lines.get() + " lines in " + files.size() + " files, " +
			errorCount.get() + " errors");
		println(errorCount.get() == 0 ? "VERIFY PASSED" : "VERIFY FAILED");
	}
}
