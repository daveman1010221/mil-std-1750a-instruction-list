#!/usr/bin/env python3
"""Extract instruction formats from the text of MIL-STD-1750A section 5.

Writes the table the validator checks against, so the validator's knowledge of
the ISA comes from the standard and not from generate_1750a.py.

    extract_spec_table.py mil-std-1750a.txt > reference_opcodes.tsv
"""
import re
import sys

MODES = "IMX|IM|DX|D|IX|I|R|ISP|ISN|ICR|BX|B|S"
ENTRY = re.compile(rf"^\s+({MODES})\s+([A-Z]+)\b\s*(.*)$")
FIELD = re.compile(
    r"^(?:[0-9A-F]{1,2}|DO|EO|RA|RB|RX|N|N-1|C|D|BR'|DSPL|ADDR|LABEL|DATA|CMD|0000|Op\. Ex\.)$"
)
# The scanned text renders the opcodes D0 and E0 with a letter O.
OCR_FIXES = {"DO": "D0", "EO": "E0"}


def box_fields(line):
    if "|" not in line:
        return None
    parts = [part.strip() for part in line[line.index("|"):].split("|")]
    fields = [OCR_FIXES.get(part, part) for part in parts if FIELD.match(part)]
    return fields or None


def extract(lines):
    """Return {mnemonic: (mode, operand syntax, [fields])}."""
    table = {}
    for number, line in enumerate(lines):
        match = ENTRY.match(line)
        if not match:
            continue
        mode, mnemonic, rest = match.groups()
        fields = next(filter(None, map(box_fields, lines[number:number + 3])), None)
        if fields is None:
            continue
        syntax = re.split(r"\s{2,}|\||-{3,}", rest.strip())[0].strip()
        if mnemonic == "BIF":
            syntax = "OPEX"
            fields = ["4F", "OPEX"]
        # The indexed line comes last and has the fullest syntax, so keep it.
        table[mnemonic] = (mode, syntax, fields)
    return table


def main():
    with open(sys.argv[1], encoding="latin-1") as source:
        table = extract(source.read().splitlines())
    for mnemonic, (mode, syntax, fields) in sorted(table.items()):
        print(f"{mnemonic}\t{mode}\t{syntax}\t{' '.join(fields)}")


if __name__ == "__main__":
    main()
