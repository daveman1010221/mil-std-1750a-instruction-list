#!/usr/bin/env bash
# Check the module on real programs: the sample code from milstd1750tools, including
# GCC-compiled Dhrystone. The sources are read as text and assembled by assemble_1750.py.
# Nothing from that repository is built or run, and no assembled program is executed.
#
#   GHIDRA_INSTALL_DIR=/path/to/ghidra tests/test_real_code.sh [workdir]
#
# Files using as1750 features the test assembler doesn't support are skipped and listed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mkdir -p "${1:-$(mktemp -d)}" && cd "${1:-.}" && pwd)"
PYTHON="${PYTHON:-python3}"
TOOLS_REV="$(sed -n 's/^TOOLS_REV = "\(.*\)"/\1/p' "$REPO_ROOT/tests/test_references.py")"
ASSEMBLE="$REPO_ROOT/tests/sleigh/assemble_1750.py"
echo "Working in $WORK"
. "$REPO_ROOT/tests/sleigh/setup_ghidra.sh"

TOOLS="$WORK/milstd1750tools"
if [ ! -d "$TOOLS" ]; then
    git clone --quiet https://github.com/okellogg/milstd1750tools "$TOOLS"
fi
git -C "$TOOLS" checkout --quiet "$TOOLS_REV"
SOURCES="$TOOLS/as1750/tests"

BINARIES="$WORK/programs"
LISTINGS="$WORK/listings"
rm -rf "$BINARIES" "$LISTINGS" "$WORK/project"
mkdir -p "$BINARIES" "$LISTINGS" "$WORK/project"

"$PYTHON" "$ASSEMBLE" -o "$BINARIES/dhrystone.bin" -l "$LISTINGS/dhrystone.tsv" -m "$WORK/dhrystone.map" \
    "$SOURCES/dhry.s" "$SOURCES/__main.s" "$SOURCES/bcopy.s"
skipped=()
for source in "$SOURCES"/*.s; do
    name="$(basename "$source" .s)"
    [ "$name" = dhry ] && continue
    if ! "$PYTHON" "$ASSEMBLE" -o "$BINARIES/$name.bin" -l "$LISTINGS/$name.tsv" "$source" >/dev/null 2>"$WORK/skip.txt"; then
        skipped+=("$name: $(sed "s#$SOURCES/##" "$WORK/skip.txt" | cut -c1-70)")
        rm -f "$BINARIES/$name.bin"
    elif [ ! -s "$BINARIES/$name.bin" ]; then
        rm -f "$BINARIES/$name.bin"
    fi
done
echo "Assembled $(find "$BINARIES" -name '*.bin' | wc -l) programs; skipped ${#skipped[@]}:"
printf '  %s\n' "${skipped[@]}"

LOG="$WORK/programs.log"
"$GHIDRA/support/analyzeHeadless" "$WORK/project" programs \
    -import "$BINARIES"/*.bin -loader BinaryLoader \
    -processor MIL1750A:BE:16:default -noanalysis -deleteProject \
    -scriptPath "$REPO_ROOT/tests/sleigh" \
    -postScript VerifyProgram.java "$LISTINGS" 2>&1 | tee "$LOG" | grep -E 'PROGRAM (PASS|FAIL|ERROR)' |
    sed -E 's/^.*> PROGRAM/PROGRAM/; s/ \(GhidraScript\).*//' || true

expected="$(find "$BINARIES" -name '*.bin' | wc -l)"
passed="$(grep -c 'PROGRAM PASS' "$LOG" || true)"
echo "$passed of $expected programs passed"
[ "$passed" = "$expected" ]

# With auto-analysis on, as a person would import it, decompile every Dhrystone function.
DECOMPILE_LOG="$WORK/decompile.log"
rm -rf "$WORK/project"
mkdir -p "$WORK/project"
timeout -k 30 "${TIMEOUT:-1h}" "$GHIDRA/support/analyzeHeadless" "$WORK/project" decompile \
    -import "$BINARIES/dhrystone.bin" -loader BinaryLoader \
    -processor MIL1750A:BE:16:default -deleteProject \
    -scriptPath "$REPO_ROOT/tests/sleigh" \
    -postScript VerifyDecompile.java "$WORK/dhrystone.map" > "$DECOMPILE_LOG" 2>&1 || true
grep -E 'DECOMPILE (ERROR|PASSED|FAILED|[0-9]+ of)' "$DECOMPILE_LOG" |
    sed -E 's/^.*> DECOMPILE/DECOMPILE/; s/ \(GhidraScript\).*//' || true
grep -q 'DECOMPILE PASSED' "$DECOMPILE_LOG"

# Dhrystone restores R15 from a frame pointer, which hides a wrong stack adjustment.
PROBE_LOG="$WORK/probe.log"
"$PYTHON" "$ASSEMBLE" -o "$WORK/calling_probe.bin" -l "$WORK/calling_probe.tsv" -m "$WORK/calling_probe.map" \
    "$REPO_ROOT/tests/sleigh/calling_probe.s"
rm -rf "$WORK/project"
mkdir -p "$WORK/project"
timeout -k 30 "${TIMEOUT:-1h}" "$GHIDRA/support/analyzeHeadless" "$WORK/project" probe \
    -import "$WORK/calling_probe.bin" -loader BinaryLoader \
    -processor MIL1750A:BE:16:default -noanalysis -deleteProject \
    -scriptPath "$REPO_ROOT/tests/sleigh" \
    -postScript VerifyCallingProbe.java "$WORK/calling_probe.map" > "$PROBE_LOG" 2>&1 || true
grep -E 'PROBE (OK|ERROR|PASSED|FAILED)' "$PROBE_LOG" | sed -E 's/^.*> PROBE/PROBE/; s/ \(GhidraScript\).*//' || true
grep -q 'PROBE PASSED' "$PROBE_LOG"
