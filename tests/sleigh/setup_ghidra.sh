# Sourced by the module tests. Makes a private copy of Ghidra with the module compiled
# into it, so the install and your Ghidra settings are untouched. Sets $GHIDRA.
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR to a Ghidra installation}"
# A generous heap: analyzeHeadless otherwise caps it at a fraction of what threads need.
export MAXMEM="${MAXMEM:-8G}"
export XDG_CONFIG_HOME="$WORK/config" XDG_CACHE_HOME="$WORK/cache"

GHIDRA="$WORK/ghidra"
if [ ! -d "$GHIDRA" ]; then
    cp -r --no-preserve=mode "$GHIDRA_INSTALL_DIR" "$GHIDRA"
    find "$GHIDRA/support" "$GHIDRA/Ghidra/Features/Decompiler/os" -type f -exec chmod +x {} +
fi
# On nix, launch.sh is a compiled wrapper hard-coded to run the original install.
if [ -f "$GHIDRA/support/.launch.sh-wrapped" ]; then
    mv "$GHIDRA/support/.launch.sh-wrapped" "$GHIDRA/support/launch.sh"
fi
MODULE="$GHIDRA/Ghidra/Processors/MIL1750A"
rm -rf "$MODULE"
cp -r "$REPO_ROOT/ghidra/MIL1750A" "$MODULE"
"$GHIDRA/support/sleigh" "$MODULE/data/languages/MIL1750A.slaspec"
