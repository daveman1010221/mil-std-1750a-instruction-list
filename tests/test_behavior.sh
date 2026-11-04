#!/usr/bin/env bash
# Check what instructions do: run vectors from tests/behavior_model.py through the
# module's p-code in Ghidra's emulator.
#
#   GHIDRA_INSTALL_DIR=/path/to/ghidra tests/test_behavior.sh [workdir]
#
# Set COUNT to change the number of vectors per mnemonic (default 300). A p-code loop that
# never ends would otherwise hang forever, so the run stops after TIMEOUT (default 1h).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mkdir -p "${1:-$(mktemp -d)}" && cd "${1:-.}" && pwd)"
PYTHON="${PYTHON:-python3}"
echo "Working in $WORK"
. "$REPO_ROOT/tests/sleigh/setup_ghidra.sh"

"$PYTHON" "$REPO_ROOT/tests/behavior_model.py" --count "${COUNT:-300}" > "$WORK/vectors.tsv"
# The emulator needs memory to run in, so give it a blank 64K word program.
head -c 131072 /dev/zero > "$WORK/blank.bin"

LOG="$WORK/behavior.log"
rm -f "$LOG"
rm -rf "$WORK/project"
mkdir -p "$WORK/project"
timeout -k 30 "${TIMEOUT:-1h}" "$GHIDRA/support/analyzeHeadless" "$WORK/project" behavior \
    -import "$WORK/blank.bin" -loader BinaryLoader \
    -processor MIL1750A:BE:16:default -noanalysis -deleteProject \
    -scriptPath "$REPO_ROOT/tests/sleigh" \
    -postScript VerifyBehavior.java "$WORK/vectors.tsv" 2>&1 | tee "$LOG" | grep -E 'BEHAVIOR|ERROR|Exception' |
    sed -E 's/^.*> BEHAVIOR/BEHAVIOR/; s/ \(GhidraScript\).*//' || true
grep -q 'BEHAVIOR PASSED' "$LOG"
