#!/usr/bin/env bash
# Assemble the milstd1750tools samples with the real as1750 and compare the encodings
# with tests/sleigh/assemble_1750.py. This closes the gap that the test assembler and the
# module both come from one reading of the standard.
#
#   tests/compare_as1750.sh [workdir]
#
# Needs git, gcc and make. This downloads and builds third-party code.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mkdir -p "${1:-$(mktemp -d)}" && cd "${1:-.}" && pwd)"
PYTHON="${PYTHON:-python3}"
TOOLS_REV="$(sed -n 's/^TOOLS_REV = "\(.*\)"/\1/p' "$REPO_ROOT/tests/test_references.py")"
echo "Working in $WORK"

TOOLS="$WORK/milstd1750tools"
if [ ! -d "$TOOLS" ]; then
    git clone --quiet https://github.com/okellogg/milstd1750tools "$TOOLS"
fi
git -C "$TOOLS" checkout --quiet "$TOOLS_REV"
make -C "$TOOLS/as1750" CFLAGS="-g -O1 -w -std=gnu89 -DAS1750 -DHAVE_UTYPES -DSTRCASECMP -DSTRNCASECMP"
AS1750="$TOOLS/as1750/as1750"

OUT="$WORK/compare"
rm -rf "$OUT"
mkdir -p "$OUT"
cd "$TOOLS/as1750/tests"
passed=0
failed=0
skipped=0
for source in *.s; do
    name="${source%.s}"
    if ! "$PYTHON" "$REPO_ROOT/tests/sleigh/assemble_1750.py" -o "$OUT/$name.bin" -l "$OUT/$name.tsv" \
            -m "$OUT/$name.map" "$source" >/dev/null 2>&1; then
        skipped=$((skipped + 1))
        continue
    fi
    if ! "$AS1750" -o "$OUT/$name.hex" "$source" >"$OUT/$name.log" 2>&1 || [ ! -s "$OUT/$name.hex" ]; then
        echo "$name: as1750 rejected it, usually an undefined symbol"
        skipped=$((skipped + 1))
        continue
    fi
    if result="$("$PYTHON" "$REPO_ROOT/tests/compare_tekhex.py" "$OUT/$name.hex" "$OUT/$name.tsv" "$OUT/$name.map" "$OUT/$name.bin")"; then
        echo "$name: $result"
        passed=$((passed + 1))
    else
        echo "$name: DIFFERS"
        echo "$result"
        failed=$((failed + 1))
    fi
done
echo "$passed match, $failed differ, $skipped skipped"
[ "$failed" = 0 ]
