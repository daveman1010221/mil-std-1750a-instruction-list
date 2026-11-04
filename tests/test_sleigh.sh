#!/usr/bin/env bash
# Compile the module and check it against the instruction list.
#
#   GHIDRA_INSTALL_DIR=/path/to/ghidra tests/test_sleigh.sh [workdir]
#
# By default this checks every 16-bit encoding plus one long opcode of each layout.
# Set FULL=1 for all 1.14 billion, which needs about 32 GB of free disk in workdir.
# Ghidra is copied into workdir, so the install and your Ghidra settings are untouched.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mkdir -p "${1:-$(mktemp -d)}" && cd "${1:-.}" && pwd)"
PYTHON="${PYTHON:-python3}"
echo "Working in $WORK"

. "$REPO_ROOT/tests/sleigh/setup_ghidra.sh"

LIST="$WORK/list"
rm -rf "$LIST" "$WORK/project"
mkdir -p "$WORK/project"
if [ "${FULL:-0}" = 1 ]; then
    "$PYTHON" "$REPO_ROOT/generate_1750a.py" --split-dir "$LIST"
    EXPECTED="$("$PYTHON" "$REPO_ROOT/generate_1750a.py" --count)"
else
    SHORT="$("$PYTHON" - "$REPO_ROOT" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
import generate_1750a as g
print(",".join(f"{op:02X}" for op in range(256) if 0 < g.line_count(op) <= 256))
PY
)"
    OPCODES="$SHORT,4A,7D,7C,70,71,72,73,7E,80,A3,50,F0"
    "$PYTHON" "$REPO_ROOT/generate_1750a.py" --split-dir "$LIST" --opcodes "$OPCODES"
    EXPECTED="$("$PYTHON" "$REPO_ROOT/generate_1750a.py" --count --opcodes "$OPCODES")"
fi
"$PYTHON" "$REPO_ROOT/tests/list_first_words.py" > "$WORK/first_words.txt"

# Word offset: instruction. Words 4, 5 and 9 are only reachable by falling through
# something that doesn't fall through, so flow following must skip them.
#   0 LISP R0,0x01
#   1 SJS R15,0x0008
#   3 BR 0x0006
#   4 BPT, 5 BPT
#   6 JC 0x7,0x000A
#   8 URS R15
#   9 NOP
#   A LR R2,R0
#   B BNZ 0x000A
#   C NOP
#   D BPT
"$PYTHON" -c '
import sys
words = [0x8200, 0x7EF0, 0x0008, 0x7403, 0xFFFF, 0xFFFF, 0x7070, 0x000A,
         0x7FF0, 0xFF00, 0x8120, 0x7AFF, 0xFF00, 0xFFFF]
sys.stdout.buffer.write(b"".join(w.to_bytes(2, "big") for w in words))
' > "$WORK/fixture.bin"

LOG="$WORK/verify.log"
"$GHIDRA/support/analyzeHeadless" "$WORK/project" mil1750a \
    -import "$WORK/fixture.bin" -loader BinaryLoader \
    -processor MIL1750A:BE:16:default -noanalysis -deleteProject \
    -scriptPath "$REPO_ROOT/tests/sleigh" \
    -postScript VerifyDisassembly.java "$LIST" "$WORK/first_words.txt" "$EXPECTED" 2>&1 | tee "$LOG" |
    grep -E 'VERIFY|ERROR|Exception' || true
grep -q 'VERIFY PASSED' "$LOG"
