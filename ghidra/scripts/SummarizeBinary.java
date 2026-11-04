// Summarize how well the MIL1750A module decodes the current program, without its contents.
//
// The output is safe to review and share if your binary can't be: it has counts and the
// high bytes of undecodable words, and no addresses, code, data, strings or symbols.
// Read it before sharing to confirm that.
//
//   analyzeHeadless <project_dir> <project_name> -import <binary> -loader BinaryLoader \
//     -processor MIL1750A:BE:16:default -scriptPath ghidra/scripts \
//     -postScript SummarizeBinary.java [start_word_in_hex ...] -deleteProject
//
// Disassembly starts at each given word, or word 0 by default. Auto-analysis also runs
// unless you add -noanalysis.
//@category MIL1750A

import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.ProcessorContextImpl;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class SummarizeBinary extends GhidraScript {
	/** Opcodes used by chip extensions the module leaves out. */
	private static final Map<Integer, String> EXTENSIONS = Map.ofEntries(
		Map.entry(0x4D, "GVSC ESQR"), Map.entry(0x4E, "GVSC SQRT"), Map.entry(0x95, "GVSC/MA31750 SFBS"),
		Map.entry(0xAD, "GVSC/MA31750 UAR"), Map.entry(0xAE, "GVSC/MA31750 UA"),
		Map.entry(0xBD, "GVSC/MA31750 USR"), Map.entry(0xBE, "GVSC/MA31750 US"),
		Map.entry(0xCC, "MA31750 LSL"), Map.entry(0xCD, "MA31750 LDL"), Map.entry(0xCE, "MA31750 LEFL"),
		Map.entry(0xDC, "GVSC STE or MA31750 LSS"), Map.entry(0xDD, "GVSC DSTE or MA31750 LDS"),
		Map.entry(0xDE, "GVSC LE or MA31750 LEFS"), Map.entry(0xDF, "GVSC DLE"),
		Map.entry(0xF5, "GVSC UCIM"), Map.entry(0xFC, "GVSC UCR"), Map.entry(0xFD, "GVSC UC"));

	@Override
	protected void run() throws Exception {
		AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
		Memory memory = currentProgram.getMemory();
		String[] args = getScriptArgs();
		if (args.length == 0) {
			disassemble(space.getTruncatedAddress(0, true));
		}
		for (String start : args) {
			disassemble(space.getTruncatedAddress(Long.parseLong(start, 16), true));
		}

		long instructions = 0;
		long codeWords = 0;
		Map<String, Long> mnemonics = new TreeMap<>();
		for (Instruction instruction : currentProgram.getListing().getInstructions(true)) {
			instructions++;
			codeWords += instruction.getLength() / 2;
			mnemonics.merge(instruction.getMnemonicString(), 1L, Long::sum);
		}

		// Words outside the decoded code that don't decode are either data or something
		// the module doesn't know. A cluster of high bytes is a hint, not proof.
		ProcessorContextImpl context = new ProcessorContextImpl(currentProgram.getLanguage());
		long totalWords = 0;
		long undecodable = 0;
		Map<Integer, Long> undecodableHighBytes = new TreeMap<>();
		for (MemoryBlock block : memory.getBlocks()) {
			if (!block.isInitialized()) {
				continue;
			}
			long words = block.getSize() / 2;
			totalWords += words;
			Address address = block.getStart();
			byte[] bytes = new byte[4];
			for (long i = 0; i < words; i++, address = address.add(2)) {
				if (currentProgram.getListing().getInstructionContaining(address) != null) {
					continue;
				}
				if (memory.getBytes(address, bytes, 0, 4) < 2) {
					continue;
				}
				try {
					ByteMemBufferImpl buffer = new ByteMemBufferImpl(address, bytes, true);
					InstructionPrototype ignored = currentProgram.getLanguage().parse(buffer, context, false);
				}
				catch (Exception e) {
					undecodable++;
					undecodableHighBytes.merge(bytes[0] & 0xFF, 1L, Long::sum);
				}
			}
		}

		println("SUMMARY words in initialized memory: " + totalWords);
		println("SUMMARY instructions decoded: " + instructions + " (" + codeWords + " words)");
		println("SUMMARY disassembly errors: " +
			currentProgram.getBookmarkManager().getBookmarkCount(BookmarkType.ERROR));
		println("SUMMARY words outside code that don't decode: " + undecodable);
		println("SUMMARY their high bytes (hex=count): " + format(undecodableHighBytes));
		for (Map.Entry<Integer, String> entry : EXTENSIONS.entrySet()) {
			Long count = undecodableHighBytes.get(entry.getKey());
			if (count != null && count > 0) {
				println(String.format("SUMMARY possible extension %02X (%s): %d words", entry.getKey(), entry.getValue(), count));
			}
		}
		println("SUMMARY mnemonics used: " + mnemonics);
	}

	private static String format(Map<Integer, Long> counts) {
		StringBuilder out = new StringBuilder();
		for (Map.Entry<Integer, Long> entry : counts.entrySet()) {
			out.append(String.format("%02X=%d ", entry.getKey(), entry.getValue()));
		}
		return out.toString().strip();
	}
}
