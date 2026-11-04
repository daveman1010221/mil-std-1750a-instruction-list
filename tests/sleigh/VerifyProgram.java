// Disassemble an assembled test program and compare it with its source listing.
//
// Run by tests/test_real_code.sh under analyzeHeadless. Argument: the directory of
// listings from assemble_1750.py, named after each program.
//
// Follows flow from word 0, then seeds whatever flow couldn't reach (jump table targets
// and uncalled functions). Fails if any instruction differs from the source, if anything
// decodes on a word the source says is data or the middle of an instruction, or if
// Ghidra reports a bad instruction.
//@category MIL1750A

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Instruction;

public class VerifyProgram extends GhidraScript {
	private AddressSpace space;

	private Address word(long offset) {
		return space.getTruncatedAddress(offset, true);
	}

	private static String canonical(String text) {
		StringBuilder out = new StringBuilder();
		for (int i = 0; i < text.length();) {
			if (text.startsWith("0x", i)) {
				int end = i + 2;
				while (end < text.length() && Character.digit(text.charAt(end), 16) >= 0) {
					end++;
				}
				out.append("0x").append(Long.toHexString(Long.parseLong(text.substring(i + 2, end), 16)));
				i = end;
			}
			else {
				out.append(text.charAt(i++));
			}
		}
		return out.toString().strip();
	}

	@Override
	protected void run() throws Exception {
		space = currentProgram.getAddressFactory().getDefaultAddressSpace();
		String name = currentProgram.getName().replaceAll("\\.bin$", "");
		Path listing = Path.of(getScriptArgs()[0], name + ".tsv");

		TreeMap<Long, String[]> rows = new TreeMap<>();
		for (String row : Files.readAllLines(listing)) {
			String[] fields = row.split("\t", -1);
			rows.put(Long.parseLong(fields[0], 16), fields);
		}
		long code = rows.values().stream().filter(row -> row[1].equals("code")).count();

		String first = rows.isEmpty() ? "" : rows.firstEntry().getValue()[1];
		if (first.equals("code")) {
			disassemble(word(0));
		}
		long followed = 0;
		for (Instruction ignored : currentProgram.getListing().getInstructions(true)) {
			followed++;
		}
		List<String> unreached = new ArrayList<>();
		for (Map.Entry<Long, String[]> entry : rows.entrySet()) {
			if (entry.getValue()[1].equals("code") && getInstructionAt(word(entry.getKey())) == null) {
				unreached.add(String.format("%04x %s", entry.getKey(), entry.getValue()[2]));
			}
		}
		for (Map.Entry<Long, String[]> entry : rows.entrySet()) {
			if (entry.getValue()[1].equals("code") && getInstructionAt(word(entry.getKey())) == null) {
				disassemble(word(entry.getKey()));
			}
		}

		List<String> errors = new ArrayList<>();
		long matched = 0;
		for (Instruction instruction : currentProgram.getListing().getInstructions(true)) {
			long address = instruction.getAddress().getAddressableWordOffset();
			String[] row = rows.get(address);
			if (row == null || !row[1].equals("code")) {
				errors.add(String.format("%04x: decoded '%s' on a %s word", address, instruction,
					row == null ? "non-program" : row[1]));
			}
			else if (!canonical(instruction.toString()).equals(canonical(row[2]))) {
				errors.add(String.format("%04x: decoded '%s', source says '%s'", address, instruction, row[2]));
			}
			else {
				matched++;
			}
		}
		for (Map.Entry<Long, String[]> entry : rows.entrySet()) {
			if (entry.getValue()[1].equals("code") && getInstructionAt(word(entry.getKey())) == null) {
				errors.add(String.format("%04x: no instruction for '%s'", entry.getKey(), entry.getValue()[2]));
			}
		}
		int badBookmarks = currentProgram.getBookmarkManager().getBookmarkCount(BookmarkType.ERROR);
		if (badBookmarks > 0) {
			var bookmarks = currentProgram.getBookmarkManager().getBookmarksIterator(BookmarkType.ERROR);
			while (bookmarks.hasNext()) {
				var bookmark = bookmarks.next();
				errors.add(bookmark.getAddress() + ": Ghidra error: " + bookmark.getComment());
			}
		}

		for (String error : errors.subList(0, Math.min(errors.size(), 25))) {
			println("PROGRAM ERROR " + name + " " + error);
		}
		if (name.equals("dhrystone")) {
			println("PROGRAM UNREACHED BY FLOW " + unreached);
		}
		println(String.format("PROGRAM %s %s: %d of %d instructions match; flow alone reached %d; %d errors",
			errors.isEmpty() ? "PASS" : "FAIL", name, matched, code, followed, errors.size()));
	}
}
