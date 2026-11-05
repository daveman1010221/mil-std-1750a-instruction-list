# MIL-STD-1750A instruction list generator

`generate_1750a.py` writes every valid MIL-STD-1750A instruction encoding as text, in
the input format of the
[Ghidra Processor Module Generator](https://github.com/oberoisecurity/ghidra-processor-module-generator):

```
0x8100     LR R0,R0
0x4A330042 MIM R3,0x0042
0x80120034 L R1,0x0034,R2
```

The columns are the big-endian opcode, the mnemonic and the operands. The script needs
Python 3 and no other packages.

## Usage

```sh
./generate_1750a.py --count                   # 1137742898 lines
./generate_1750a.py -o 1750a_instructions.txt # about 32 GB in one file
./generate_1750a.py --split-dir split         # one file per high opcode byte
./generate_1750a.py --opcodes 81,A0 -o sub.txt
```

The 32-bit instructions carry a 16-bit address, so the full list is large. It isn't
committed to the repository. The generator's README handles ISAs this size by running
over one file per high byte, which is what `--split-dir` writes.

## Decisions about the output

- **Scope:** the base standard only. GVSC, MA31750 and 1750B extensions and assembler
  aliases are left out.
- **`RX=0`:** the standard defines this as no indexing, so the operand is omitted, giving
  `L R1,0x0034` rather than `L R1,0x0034,R0`.
- **Counts of 1 to 16** (shifts, `LISP`, `INCM` and so on) show the architectural value,
  not the encoded `N-1`. `0x6000` is `SLL R0,0x01`.
- **Branches** show the raw 8-bit displacement, because the generator's combiner mishandles
  signed immediates. `0x7480` is `BR 0x80`, a displacement of -128.
- **`JC` conditions and `XIO` commands** are numeric, so the combiner can merge them into
  a single field.
- **`BIF`** is listed as one word. The standard leaves any additional words user-defined.

## Using the output with the generator

The stock generator needs two changes for this ISA:

1. **Remove `A` and `C` from its `registers.h`, then rebuild.** They are 1750A mnemonics
   (add and compare). Left in, the generator treats them as registers and omits the space
   after them, producing `AR1,...`:

   ```sh
   sed -i '/^    "A",$/d; /^    "C",$/d' registers.h
   ```

2. **Pass the registers it doesn't know about:**

   ```sh
   generator --input-disassembly-dir split \
     --processor-name MIL1750A --processor-family MIL1750 \
     --endian big --alignment 2 --bitness 16 \
     --additional-registers R8 R9 R10 R11 R12 R13 R14 R15 B12 B13 B14 B15
   ```

Then follow its "Usage (4 Byte ISAs)" steps. By the generator's own estimate, a run at
this size takes hours and about 40 GB of RAM.

Some hand edits to the generated `.slaspec` will remain, as the generator's README expects:

- Display `N-1` fields as `N` (the generator prints the raw field).
- Sign-extend and add IC to the branch displacements.
- Account for 1750A addresses being 16-bit word addresses.

## Ghidra processor module

`ghidra/MIL1750A` is a hand-written module with disassembly, p-code and a calling
convention, which replaces the generator route above. It targets the same base instruction
set. To install it:

```sh
cp -r ghidra/MIL1750A "$GHIDRA_INSTALL_DIR/Ghidra/Processors/"
"$GHIDRA_INSTALL_DIR/support/sleigh" \
  "$GHIDRA_INSTALL_DIR/Ghidra/Processors/MIL1750A/data/languages/MIL1750A.slaspec"
```

Then import a raw big-endian binary with the language `MIL1750A:BE:16:default`. Addresses
are 16-bit word addresses, as in the standard. On nix, the Ghidra install is read-only, so
use a writable copy.

What it does:

- **Disassembly:** complete for the base standard. IC-relative branches show their target
  address, not the raw displacement.
- **Integer instructions:** full p-code, including condition status, wrapping register
  pairs (`R15+R0`) and the multi-register instructions. Bit 0 is the most significant.
- **Calling convention:** arguments in R0-R5, results in R0, R0+R1 or R0+R1+R2, R14 and R15
  preserved. The standard defines no convention, so this is inferred from GCC-compiled
  Dhrystone. It may not match other compilers or hand-written code.
- **Symbols:** `RESET` at word 0, and each interrupt's linkage and service pointers.

What it doesn't do:

- **Floating point results.** Float instructions are named operations such as
  `fadd32(a, b)`. The decompiler shows which values they use, but nothing computes them, so
  the emulator stops on them unless a script supplies an implementation.
- **Overflow and interrupts.** Fixed-point overflow, the pending interrupt register and
  interrupt entry aren't modeled. `XIO`, `VIO`, `BEX`, `BIF` and `BPT` are named operations
  that fall through, and any extra words a `BIF` uses will disassemble as instructions.
- **Multi-word memory access across the top of memory**, such as a `DL` at word `0xFFFF`.
- **Division by zero.** The standard raises a fixed-overflow interrupt, which isn't modeled.
- **Overlapping `MOV` registers,** which the standard doesn't define. In the emulator, a
  `MOV` whose source register is also its count never ends.
- **Stack-passed arguments.** Nothing in the samples passes any, so `stackshift` is
  untested. R7-R13 are unclassified because the samples never use them.
- **The optional MMU and chip-specific extensions.** All addresses are in one 64K-word
  space. Branch conditions test one flag where the status has exactly one set, which
  differs only if software loads an unusual status word.

Where the module follows one reading of the standard over another:

- **Carry on signed overflow:** `sim1750` sets carry on overflow. The module uses the real
  carry out, as the standard defines it.
- **Register shifts past the limit** (`SLR`, `DSCR` and so on) change nothing, because the
  standard exits before the shift. `sim1750` marks this case "to be verified" and differs.
- **`NEG` and `DNEG` of the most negative value** write the result and leave CS alone,
  following the order in the standard. `sim1750` updates CS.
- **`ABS` and `DABS` of the most negative value** write the result and set CS. The standard
  says both "exit" and gives a CS row for that result, so it contradicts itself. The module
  takes the CS row, as `sim1750` does.

`samples/` has a small test image built from GCC-compiled Dhrystone. Its
[README](samples/README.md) documents the image layout.

### Checking a binary you can't share

`ghidra/scripts/SummarizeBinary.java` reports how well the module decodes a binary: counts,
a mnemonic histogram and the high bytes of words that don't decode, with no addresses, code,
data, strings or symbols. Ghidra's own log can name your file, so keep only the summary
lines, and read them before sharing:

```sh
mkdir -p /tmp/project
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" /tmp/project summary \
  -import firmware.bin -loader BinaryLoader -processor MIL1750A:BE:16:default \
  -scriptPath "$PWD/ghidra/scripts" -postScript SummarizeBinary.java -deleteProject |
  grep -o 'SUMMARY.*'
```

Add start addresses after the script name, in hex words, if execution doesn't begin at
word 0. High bytes that don't decode, or a high count of them, can point to a chip extension
or to data.

## Validation

```sh
python3 -m unittest discover -s tests                 # quick, about 30 seconds
./generate_1750a.py --split-dir split && tests/validate_output.py split/op_*.txt
GHIDRA_INSTALL_DIR=/path/to/ghidra tests/test_sleigh.sh        # module, about 1 minute
GHIDRA_INSTALL_DIR=/path/to/ghidra FULL=1 tests/test_sleigh.sh # every encoding
GHIDRA_INSTALL_DIR=/path/to/ghidra tests/test_real_code.sh     # samples and decompiling
GHIDRA_INSTALL_DIR=/path/to/ghidra tests/test_behavior.sh      # what instructions do
tests/e2e_generator.sh                                # builds the generator, needs Ghidra
tests/compare_as1750.sh                               # builds as1750
```

The last two build third-party code and haven't been run yet.

| Layer | What it shows |
|---|---|
| `validate_output.py` | Re-encodes every line through format boxes extracted from the standard, sharing no code with the generator. With strictly increasing opcodes and exact per-opcode counts, this proves the file is exactly the set of valid encodings. |
| `test_generator.py` | Hand-worked golden lines, plus corrupted output (dropped lines, swapped operands, off-by-one counts and more) that the validator must reject. |
| `test_references.py` | Compares the table with the standard's text and, read as plain text, with `as1750` and `dism1750` from [milstd1750tools](https://github.com/okellogg/milstd1750tools). Also applies the generator's tokenizer and register rules to the output. |
| `test_sleigh.sh` | Compiles the module and decodes the list with it, checking each encoding's length, text and flow type and targets. Also checks that every first word the standard doesn't define fails to decode, branch targets across the address wrap, and flow following on a small program. |
| `test_behavior.sh` | Runs random vectors for all 197 mnemonics through the p-code in Ghidra's emulator and compares registers, status, memory and next address with `tests/behavior_model.py`, a separate reading of the standard's register transfers. Both readings are mine, so this finds slips, not shared misreadings. Float operations are stubbed, so only their wiring is checked. |
| `test_real_code.sh` | Assembles the sample code from milstd1750tools, including GCC-compiled Dhrystone, with `tests/sleigh/assemble_1750.py`, then compares Ghidra's disassembly with the source. Fails on any differing instruction, data decoded as code, or Ghidra error. Then decompiles Dhrystone with auto-analysis, checking each function's parameters and return against the C prototypes, and decompiles `calling_probe.s`, whose results change if the stack adjustment or saved registers are wrong. Runs nothing from that repo. |
| `e2e_generator.sh` | Runs the real generator, SLEIGH compiler and generator-validator on a subset. |
| `compare_as1750.sh` | Compares the test assembler's output with the real `as1750`, using `compare_tekhex.py`. |

`dism1750.c` disagrees with the standard on three instruction lengths, which
`test_references.py` records: it decodes `LUBI` and `LLBI` as one-word register forms, and
gives `BIF` a data word.

## License

GNU General Public License, version 2. See [LICENSE](LICENSE).
