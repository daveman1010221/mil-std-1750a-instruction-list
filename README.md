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

`ghidra/MIL1750A` is a hand-written disassembly module, which replaces the generator
route above. It targets the same base instruction set. To install it:

```sh
cp -r ghidra/MIL1750A "$GHIDRA_INSTALL_DIR/Ghidra/Processors/"
"$GHIDRA_INSTALL_DIR/support/sleigh" \
  "$GHIDRA_INSTALL_DIR/Ghidra/Processors/MIL1750A/data/languages/MIL1750A.slaspec"
```

Then import a raw big-endian binary with the language `MIL1750A:BE:16:default`. Addresses
are 16-bit word addresses, as in the standard. On nix, the Ghidra install is read-only, so
use a writable copy.

What this stage does and doesn't do:

- **Disassembly:** complete for the base standard, with branch and call targets resolved
  and followed. IC-relative branches show their target address, not the raw displacement.
- **Decompiler output can't be trusted yet.** Only control-flow instructions have p-code.
  The rest are `unimpl`, and nothing sets the condition status that branches test.
- **Data references:** none yet, because they come from p-code. Memory operands display
  as plain numbers.
- **Not modeled:** the optional MMU, chip-specific extensions, and a real calling
  convention (the `.cspec` is a placeholder). `BEX` and `BIF` are treated as falling
  through, and any extra words a `BIF` uses will disassemble as instructions.

## Validation

```sh
python3 -m unittest discover -s tests                 # quick, about 30 seconds
./generate_1750a.py --split-dir split && tests/validate_output.py split/op_*.txt
GHIDRA_INSTALL_DIR=/path/to/ghidra tests/test_sleigh.sh        # module, about 1 minute
GHIDRA_INSTALL_DIR=/path/to/ghidra FULL=1 tests/test_sleigh.sh # every encoding
tests/e2e_generator.sh                                # needs a compiler and Ghidra
```

| Layer | What it shows |
|---|---|
| `validate_output.py` | Re-encodes every line through format boxes extracted from the standard, sharing no code with the generator. With strictly increasing opcodes and exact per-opcode counts, this proves the file is exactly the set of valid encodings. |
| `test_generator.py` | Hand-worked golden lines, plus corrupted output (dropped lines, swapped operands, off-by-one counts and more) that the validator must reject. |
| `test_references.py` | Compares the table with the standard's text and, read as plain text, with `as1750` and `dism1750` from [milstd1750tools](https://github.com/okellogg/milstd1750tools). Also applies the generator's tokenizer and register rules to the output. |
| `test_sleigh.sh` | Compiles the module and decodes the list with it, checking each encoding's length, text and flow type and targets. Also checks that every first word the standard doesn't define fails to decode, branch targets across the address wrap, and flow following on a small program. Behavior beyond control flow is not tested. |
| `e2e_generator.sh` | Runs the real generator, SLEIGH compiler and generator-validator on a subset. |

`dism1750.c` disagrees with the standard on three instruction lengths, which
`test_references.py` records: it decodes `LUBI` and `LLBI` as one-word register forms, and
gives `BIF` a data word.
