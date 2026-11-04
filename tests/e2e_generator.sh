#!/usr/bin/env bash
# Run the real toolchain on a subset of the ISA: build the generator, turn the list
# into a processor module, compile it with SLEIGH, and disassemble the list again.
#
#   GHIDRA_SUPPORT=/path/to/ghidra/support tests/e2e_generator.sh [workdir]
#
# Needs git, g++, make and Boost. This downloads and builds third-party code.
# A0 covers the A/C register collision and a full 16M-line long opcode, so allow
# several GB of RAM. Without GHIDRA_SUPPORT the SLEIGH step is skipped.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${1:-$(mktemp -d)}"
OPCODES="${OPCODES:-81,74,77,7F,60,82,00,40,4F,FF,A0}"
GENERATOR_REV="$(sed -n 's/^GENERATOR_REV = "\(.*\)"/\1/p' "$REPO_ROOT/tests/test_references.py")"
EXTRA_REGISTERS=(R8 R9 R10 R11 R12 R13 R14 R15 B12 B13 B14 B15)
echo "Working in $WORK"

if [ ! -d "$WORK/generator" ]; then
    git clone https://github.com/oberoisecurity/ghidra-processor-module-generator "$WORK/generator"
    git -C "$WORK/generator" checkout "$GENERATOR_REV"
fi
sed -i '/^    "A",$/d; /^    "C",$/d' "$WORK/generator/registers.h"
make -C "$WORK/generator" -j"$(nproc)" generator

python3 "$REPO_ROOT/generate_1750a.py" --opcodes "$OPCODES" -o "$WORK/subset.txt"
python3 "$REPO_ROOT/tests/validate_output.py" --opcodes "$OPCODES" "$WORK/subset.txt"

cd "$WORK"
report="$(./generator/generator --input-disassembly subset.txt --print-registers-only \
    --additional-registers "${EXTRA_REGISTERS[@]}")"
echo "$report"
registers="$(grep 'Found registers:' <<<"$report")"
for name in A C; do
    if grep -qw "$name" <<<"$registers"; then
        echo "FAIL: $name was classified as a register" >&2
        exit 1
    fi
done
for number in 0 15; do
    grep -qw "R$number" <<<"$registers" || { echo "FAIL: R$number not found" >&2; exit 1; }
done

./generator/generator --input-disassembly subset.txt \
    --processor-name MIL1750A --processor-family MIL1750 \
    --endian big --alignment 2 --bitness 16 \
    --additional-registers "${EXTRA_REGISTERS[@]}"
echo "Generated module in $WORK/MIL1750"

if [ -z "${GHIDRA_SUPPORT:-}" ]; then
    echo "GHIDRA_SUPPORT not set: skipping the SLEIGH compile"
    exit 0
fi
"$GHIDRA_SUPPORT/sleigh" -a MIL1750/
echo "SLEIGH compile passed. To compare disassembly, build generator-validator and run:"
echo "  generator-validator --input-file subset.txt --sla-file MIL1750/data/languages/MIL1750A.sla --output-file output.txt"
echo "Expect differences only in N-1 fields and branch displacements (see README)."
