#!/usr/bin/env python3
"""Check generated disassembly against the table extracted from MIL-STD-1750A.

Deliberately imports nothing from generate_1750a.py. Each line's operand text
is re-encoded through the standard's format box and compared with column one.
Together, these checks prove the output is exactly the set of valid encodings:

  * every line re-encodes to its own opcode, so every line is valid and correct
  * opcodes strictly increase, so no encoding appears twice
  * each high byte has exactly the number of lines its fields can produce, so
    no encoding is missing

    validate_output.py 1750a_instructions.txt
    validate_output.py split/op_*.txt
"""
import argparse
import multiprocessing
import os
import re
import sys
from collections import Counter, namedtuple

REFERENCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reference_opcodes.tsv")
MAX_ERRORS = 20

Instruction = namedtuple("Instruction", "mnemonic mode pattern layout")

FIELD_WIDTHS = {
    "RA": 4, "RB": 4, "RX": 4, "N": 4, "N-1": 4, "C": 4, "0000": 4,
    "BR'": 2, "DSPL": 8, "D": 8, "OPEX": 8,
    "ADDR": 16, "LABEL": 16, "DATA": 16, "CMD": 16,
}
REGISTER = r"R(?:1[0-5]|[0-9])"
LINE = re.compile(r"(0x[0-9A-F]{4} {5}|0x[0-9A-F]{8} )([A-Z]+)(?: (.*))?")


def _hex(digits):
    return rf"0x[0-9A-F]{{{digits}}}"


def _operand_pattern(name, fields):
    if name in ("RA", "RB"):
        return rf"(?P<{name}>{REGISTER})"
    if name == "BR":
        return r"(?P<BR>B1[2-5])"
    if name == "N":
        return rf"(?P<N>{_hex(2 if 'N-1' in fields else 1)})"
    if name == "C":
        return rf"(?P<C>{_hex(1)})"
    if name == "DSPL":
        return rf"(?P<DSPL>{_hex(2)})"
    if name == "OPEX":
        return rf"(?P<OPEX>{_hex(2)})"
    if name == "LABEL" and "D" in fields:
        return rf"(?P<D>{_hex(2)})"
    # The box for SIM labels its DATA field ADDR, so use the box's own name.
    box_name = next(f for f in fields if FIELD_WIDTHS.get(f) == 16)
    return rf"(?P<{box_name}>{_hex(4)})"


def _build_pattern(syntax, fields):
    names = syntax.split(",") if syntax else []
    # RX=0 means no index, so the standard writes those forms without the operand.
    index = names[-1] == "RX" if names else False
    required = names[:-1] if index else names
    text = ",".join(_operand_pattern(name, fields) for name in required)
    if index:
        text += r"(?:,(?P<RX>R(?:1[0-5]|[1-9])))?"
    return re.compile(text)


def _resolve_fields(mode, fields):
    """Return [(name, width, literal)], with literal set for fixed bit patterns.

    Boxes print fixed values and field names in the same column, and a hex digit
    like C or D reads the same as a field name, so position decides which it is.
    """
    layout = []
    for position, field in enumerate(fields):
        fixed_digit = (
            (mode in ("B", "BX") and position < 2)
            or (mode == "BX" and position == 3)
            or (fields[0] == "4A" and position == 2)
        )
        if fixed_digit:
            width = 2 if position == 1 else 4
            layout.append((field, width, int(field, 16)))
        elif field == "0000":
            layout.append((field, 4, 0))
        elif field in FIELD_WIDTHS:
            layout.append((field, FIELD_WIDTHS[field], None))
        else:
            layout.append((field, 4 * len(field), int(field, 16)))
    return layout


def load_reference(path=REFERENCE):
    table = {}
    with open(path, encoding="ascii") as source:
        for row in source:
            mnemonic, mode, syntax, fields = row.rstrip("\n").split("\t")
            fields = fields.split()
            table[mnemonic] = Instruction(mnemonic, mode, _build_pattern(syntax, fields),
                                          _resolve_fields(mode, fields))
    return table


def _field_value(field, operands):
    if field == "BR'":
        return int(operands["BR"][1:]) - 12
    if field == "N-1":
        count = int(operands["N"], 16)
        if not 1 <= count <= 16:
            raise ValueError(f"N out of range: {count}")
        return count - 1
    if field in ("RA", "RB", "RX"):
        value = operands.get(field)
        return int(value[1:]) if value else 0
    return int(operands[field], 16)


def encode(instruction, operands):
    """Assemble an instruction from its operand text. Returns (value, bit width)."""
    value = bits = 0
    for field, width, literal in instruction.layout:
        part = _field_value(field, operands) if literal is None else literal
        value = value << width | part
        bits += width
    return value, bits


def word_count(instruction):
    return sum(width for _, width, _ in instruction.layout) // 16


def high_byte(instruction):
    """The instruction's first opcode byte, with any base register bits clear."""
    value = bits = 0
    for _, width, literal in instruction.layout:
        if bits == 8:
            break
        value = value << width | (literal or 0)
        bits += width
    return value


def expected_counts(reference):
    """Lines each high opcode byte must have, computed only from the format boxes."""
    expected = Counter()
    for instruction in reference.values():
        free_bits = sum(width for field, width, literal in instruction.layout
                        if literal is None and field != "BR'")
        if instruction.mode in ("B", "BX"):
            high_bytes = [high_byte(instruction) | br for br in range(4)]
        else:
            high_bytes = [high_byte(instruction)]
        for value in high_bytes:
            expected[value] += 1 << free_bits
    return expected


def check_file(path, reference=None):
    """Return (per-high-byte counts, first opcode, last opcode, errors)."""
    reference = reference or load_reference()
    counts = Counter()
    errors = []
    first = previous = None

    def report(number, message, line):
        if len(errors) < MAX_ERRORS:
            errors.append(f"{path}:{number}: {message}: {line.rstrip()!r}")

    line = ""
    number = 0
    with open(path, encoding="ascii", newline="\n") as source:
        for number, line in enumerate(source, 1):
            match = LINE.fullmatch(line[:-1])
            if not match:
                report(number, "malformed line", line)
                continue
            column, mnemonic, operand_text = match.groups()
            instruction = reference.get(mnemonic)
            if instruction is None:
                report(number, "mnemonic not in the standard", line)
                continue
            operands = instruction.pattern.fullmatch(operand_text or "")
            if operands is None:
                report(number, "operands do not match the standard's syntax", line)
                continue
            try:
                value, bits = encode(instruction, operands.groupdict())
            except ValueError as error:
                report(number, str(error), line)
                continue
            opcode = column.rstrip()
            if opcode != f"0x{value:0{bits // 4}X}":
                report(number, f"re-encodes to 0x{value:0{bits // 4}X}", line)
                continue
            if previous is not None and opcode <= previous:
                report(number, f"not strictly after {previous}", line)
            previous = opcode
            first = first or opcode
            counts[int(opcode[2:4], 16)] += 1
    if line and not line.endswith("\n"):
        report(number, "file does not end in a newline, so the generator drops this line", line)
    return counts, first, previous, errors


def validate(paths, high_bytes=None, jobs=None):
    """Return a list of errors. high_bytes limits the completeness check to a subset."""
    reference = load_reference()
    paths = sorted(paths)
    if len(paths) == 1:
        results = [check_file(paths[0], reference)]
    else:
        with multiprocessing.Pool(jobs) as pool:
            results = pool.map(check_file, paths)

    errors = []
    totals = Counter()
    previous = None
    for path, (counts, first, last, file_errors) in zip(paths, results):
        errors.extend(file_errors)
        totals.update(counts)
        if first is None:
            errors.append(f"{path}: no instructions")
            continue
        if previous is not None and first <= previous:
            errors.append(f"{path}: starts at {first}, overlapping the previous file ({previous})")
        previous = last

    expected = expected_counts(reference)
    wanted = set(expected) if high_bytes is None else set(high_bytes)
    for high_byte in sorted(wanted | set(totals)):
        want = expected[high_byte] if high_byte in wanted else 0
        if totals[high_byte] != want:
            errors.append(f"high byte {high_byte:02X}: {totals[high_byte]} lines, expected {want}")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="+")
    parser.add_argument("--opcodes", help="expect only these comma-separated hex high bytes")
    parser.add_argument("-j", "--jobs", type=int)
    args = parser.parse_args()
    high_bytes = [int(item, 16) for item in args.opcodes.split(",")] if args.opcodes else None
    errors = validate(args.paths, high_bytes, args.jobs)
    for error in errors:
        print(error)
    if errors:
        print(f"FAILED: {len(errors)} error(s) reported")
        return 1
    print(f"OK: {sum(os.path.getsize(path) for path in args.paths):,} bytes in {len(args.paths)} file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
