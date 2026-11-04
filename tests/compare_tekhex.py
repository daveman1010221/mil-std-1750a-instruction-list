#!/usr/bin/env python3
"""Compare as1750's output with this repo's test assembler, for one source file.

    compare_tekhex.py as1750.hex program.tsv program.map program.bin

as1750 and assemble_1750.py lay programs out differently, so this compares instructions
in order and skips second words that depend on a symbol's address. as1750 puts Init then
Normal at word 0x100; the listing and map give the same code for the test assembler.
"""
import sys


def read_tekhex(path):
    """Return {word address: value} from an extended Tektronix hex file."""
    octets = {}
    with open(path, encoding="ascii") as source:
        for line in source:
            line = line.strip()
            # %, 2 length, 1 type, 2 checksum, 1 address length, address, data
            if not line.startswith("%") or line[3] != "6":
                continue
            length = int(line[6], 16)
            address = int(line[7:7 + length], 16)
            data = line[7 + length:]
            for i in range(0, len(data), 2):
                octets[address + i // 2] = int(data[i:i + 2], 16)
    words = {}
    for address, value in octets.items():
        if address % 2 == 0:
            words[address // 2] = value << 8 | octets.get(address + 1, 0)
    return words


def read_code(listing_path, map_path):
    """Return [(listing word, kind, text, symbolic)] for Init then Normal, in as1750's order."""
    sections = {}
    with open(map_path, encoding="ascii") as source:
        for row in source:
            if row.startswith("# word\tsymbol"):
                break
            if not row.startswith("#"):
                address, name = row.rstrip("\n").split("\t")
                sections[name] = int(address, 16)
    rows = []
    with open(listing_path, encoding="ascii") as source:
        for row in source:
            fields = row.rstrip("\n").split("\t")
            rows.append((int(fields[0], 16), fields[1], fields[2], fields[3] if len(fields) > 3 else ""))
    init = [r for r in rows if sections["init"] <= r[0] < sections["final return"]]
    normal = [r for r in rows if sections["normal"] <= r[0] < sections["stubs"]]
    return init + normal


def compare(tek_words, code, binary):
    """Return (words compared, words skipped, mismatch messages)."""
    compared = skipped = 0
    mismatches = []
    for offset, (address, kind, text, symbolic) in enumerate(code):
        theirs = tek_words.get(0x100 + offset)
        if kind == "data":
            skipped += 1
        elif kind == "cont" and symbolic:
            skipped += 1
        elif theirs != binary[address]:
            mismatches.append(f"word {address:04x} ({text or kind}): ours {binary[address]:04x}, "
                              f"as1750 {'none' if theirs is None else format(theirs, '04x')}")
        else:
            compared += 1
    return compared, skipped, mismatches


def main():
    tek_path, listing_path, map_path, binary_path = sys.argv[1:5]
    with open(binary_path, "rb") as source:
        data = source.read()
    binary = [int.from_bytes(data[i:i + 2], "big") for i in range(0, len(data), 2)]
    compared, skipped, mismatches = compare(read_tekhex(tek_path), read_code(listing_path, map_path), binary)
    for message in mismatches[:20]:
        print(message)
    print(f"{compared} words match, {skipped} skipped, {len(mismatches)} differ")
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
