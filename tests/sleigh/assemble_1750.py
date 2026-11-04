#!/usr/bin/env python3
"""Assemble as1750-style source into a raw binary, for testing the Ghidra module.

Encodes through tests/reference_opcodes.tsv, the table extracted from the standard,
and shares nothing with the module. This handles what the milstd1750tools samples
use and is not a full replacement for as1750.

    assemble_1750.py -o program.bin -l program.tsv [-m program.map] a.s b.s

The listing has one row per word: address, then "code" and the expected disassembly,
"cont" for the rest of a two-word instruction, or "data". A "cont" row has "symbolic" in
its last column if its value depends on where a symbol landed. Symbols nothing defines
become stub functions. If there is a main, a startup stub at word 0 calls the INIT
section (startup code from the compiler), then main. A return ends INIT and the image,
so that the last instruction in a file can't fall off the end.
"""
import argparse
import math
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import validate_output

STACK_TOP = 0xF000
CONDITIONS = {
    "LT": 1, "LZ": 1, "EQ": 2, "EZ": 2, "LE": 3, "LEZ": 3, "GT": 4, "GTZ": 4,
    "NE": 5, "NZ": 5, "GE": 6, "GEZ": 6, "ALL": 7, "CY": 8, "CLT": 9, "CEQ": 10,
    "CEZ": 10, "CLE": 11, "CGT": 12, "CNZ": 13, "CGE": 14, "UC": 15,
}
ALIASES = {"J": "BR", "JEZ": "BEZ", "JLE": "BLE", "JGT": "BGT", "JNZ": "BNZ",
           "JGE": "BGE", "JLT": "BLT", "BEQ": "BEZ", "BNE": "BNZ"}
IGNORED = {"NAME", "NOLIST", "LIST", "INCLUDE", "GLOBAL", "PAGE", "TITLE"}
TERM = re.compile(r"\s*([-+]?)\s*('.'|16#[0-9A-F]+#|#[0-9A-F]+|\d+|[A-Z_.$][A-Z0-9_.$]*)")


class AsmError(Exception):
    pass


def load_table():
    syntax = {}
    with open(validate_output.REFERENCE, encoding="ascii") as source:
        for row in source:
            mnemonic, _, text, _ = row.rstrip("\n").split("\t")
            syntax[mnemonic] = text.split(",") if text else []
    return validate_output.load_reference(), syntax


def split_operands(text):
    """Split on commas outside character constants."""
    parts, current, quoted = [], "", False
    for char in text:
        if char == "'":
            quoted = not quoted
        if char == "," and not quoted:
            parts.append(current.strip())
            current = ""
        else:
            current += char
    if current.strip():
        parts.append(current.strip())
    return parts


def strip_comment(line):
    quoted = False
    for position, char in enumerate(line):
        if char == "'":
            quoted = not quoted
        elif char == ";" and not quoted:
            return line[:position]
    return line


def float_words(value, mantissa_bits):
    """MIL-STD-1750A float: 2's complement fraction, then an 8-bit 2's complement exponent."""
    fraction, exponent = math.frexp(value)
    if fraction == -0.5:
        fraction, exponent = -1.0, exponent - 1
    if value == 0:
        exponent = 0
    mantissa = round(fraction * (1 << (mantissa_bits - 1))) & ((1 << mantissa_bits) - 1)
    high = mantissa >> (mantissa_bits - 24)
    words = [high >> 8, (high & 0xFF) << 8 | (exponent & 0xFF)]
    if mantissa_bits == 40:
        words.append(mantissa & 0xFFFF)
    return words


def expand_macro(name, args):
    """The macros from as1750's ms1750.inc that the samples use."""
    if name == "UCIM.M":
        first, value = int(args[0]), args[1]
        return [("PSHM", [f"R{first}", f"R{first + 3}"]), ("LR", [f"R{first + 1}", f"R{first}"]),
                ("XORR", [f"R{first}", f"R{first}"]), ("XORR", [f"R{first + 2}", f"R{first + 2}"]),
                ("LIM", [f"R{first + 3}", value]), ("DCR", [f"R{first}", f"R{first + 2}"]),
                ("POPM", [f"R{first}", f"R{first + 3}"])]
    if name == "EFLR.M":
        dest, source = int(args[0]), int(args[1])
        third = ("LR", [f"R{dest + 2}", f"R{source + 2}"])
        pair = ("DLR", [f"R{dest}", f"R{source}"])
        if dest >= source or dest + 2 < source:
            return [third, pair]
        return [pair, third, ("DLR", [f"R{dest}", f"R{dest}"])]
    raise AsmError(f"unsupported macro {name}")


class Program:
    def __init__(self):
        self.reference, self.syntax = load_table()
        self.sections = {"NORMAL": [], "KONST": [], "INIT": []}
        self.labels = {}  # (scope, name) or (None, name) -> (section, index)
        self.commons = {}
        self.exports = set()
        self.values = {}

    def add_file(self, path):
        scope = path
        section = "NORMAL"
        constants = {}
        pending = []
        with open(path, encoding="latin-1") as source:
            lines = source.read().splitlines()
        exports = set()
        for line in lines:
            match = re.match(r"\s+GLOBAL\s+([A-Z0-9_.$]+)", strip_comment(line).upper())
            if match:
                exports.add(match.group(1))
        self.exports |= exports
        for number, raw in enumerate(lines, 1):
            line = strip_comment(raw).rstrip().upper() if "'" not in raw else self._upper_outside_quotes(strip_comment(raw).rstrip())
            if not line.strip():
                continue
            fields = line.split(None, 1) if line[0].isspace() else None
            label = None
            if fields is None:
                parts = line.split(None, 1)
                label = parts[0].rstrip(":")
                fields = parts[1].split(None, 1) if len(parts) > 1 else []
            if not fields:
                pending.append(self._key(scope, label, exports))
                continue
            op = fields[0]
            rest = fields[1] if len(fields) > 1 else ""
            where = f"{path}:{number}"
            if op in ("SET", "EQU"):
                constants[label] = rest.strip()
                self.values[(scope, label)] = rest.strip()
                continue
            if label:
                pending.append(self._key(scope, label, exports))
            if op in ("NORMAL", "KONST", "INIT"):
                section = op
                continue
            if op == "STATIC":
                section = "KONST"
                continue
            if op == "END":
                break
            if op in IGNORED:
                continue
            if op == "COMMON":
                name, size = split_operands(rest)
                self.commons[name] = max(self.commons.get(name, 0), int(size))
                continue
            items = self._statement(op, rest, scope, where)
            target = self.sections[section]
            for key in pending:
                self.labels[key] = (section, len(target))
            pending = []
            target.extend(items)
        for key in pending:
            self.labels[key] = (section, len(self.sections[section]))

    @staticmethod
    def _upper_outside_quotes(line):
        return re.sub(r"('.')|([^']+)", lambda m: m.group(1) or m.group(2).upper(), line)

    @staticmethod
    def _key(scope, name, exports):
        return (None, name) if name in exports else (scope, name)

    def _statement(self, op, rest, scope, where):
        args = split_operands(rest)
        if op in ("DATA", "DATAC"):
            return [("data", arg, scope, where) for arg in args]
        if op == "DATAL":
            return [("data32", half, arg, scope, where) for arg in args for half in (16, 0)]
        if op in ("DATAF", "DATAEF", "DATAE"):
            bits = 24 if op == "DATAF" else 40
            return [("word", word) for arg in args for word in float_words(float(arg), bits)]
        if op in ("RES", "BLOCK"):
            return [("word", 0)] * int(args[0])
        if op.endswith(".M"):
            return [item for name, operands in expand_macro(op, args)
                    for item in self._instruction(name, operands, scope, where)]
        return self._instruction(ALIASES.get(op, op), args, scope, where)

    def _instruction(self, op, args, scope, where):
        if op not in self.reference:
            raise AsmError(f"{where}: unknown mnemonic {op}")
        words = validate_output.word_count(self.reference[op])
        return [("insn", op, args, scope, where)] + [("cont",)] * (words - 1)

    def resolve(self, name, scope):
        for key in ((scope, name), (None, name)):
            if key in self.addresses:
                return self.addresses[key]
        if (scope, name) in self.values:
            return self.evaluate(self.values[(scope, name)], scope)
        self.undefined.add(name)
        return self.stubs.get(name, 0)

    def evaluate(self, text, scope):
        position = 0
        total = 0
        text = text.strip()
        while position < len(text):
            match = TERM.match(text, position)
            if not match:
                raise AsmError(f"can't parse expression {text!r}")
            sign, term = match.groups()
            if term[0] == "'":
                value = ord(term[1])
            elif term.startswith("16#"):
                value = int(term[3:-1], 16)
            elif term[0] == "#":
                value = int(term[1:], 16)
            elif term[0].isdigit():
                value = int(term)
            else:
                value = self.resolve(term, scope)
            total += -value if sign == "-" else value
            position = match.end()
        return total

    def layout(self, stub_names=()):
        start = self.startup_words()
        self.stubs = {}
        self.addresses = {}
        address = start
        bases = {}
        bases["NORMAL"] = address
        address += len(self.sections["NORMAL"])
        for name in sorted(stub_names):
            self.stubs[name] = address
            address += 1
        bases["KONST"] = address
        address += len(self.sections["KONST"])
        bases["INIT"] = address
        address += len(self.sections["INIT"]) + 1
        for key, (section, index) in self.labels.items():
            self.addresses[key] = bases[section] + index
        self.init_base = bases["INIT"]
        self.bases = bases
        self.image_end = address
        for name, size in sorted(self.commons.items()):
            self.addresses[(None, name)] = address
            address += size
        if address > STACK_TOP:
            raise AsmError("program does not fit below the stack")

    def has_main(self):
        return (None, "MAIN") in self.labels

    def startup_words(self):
        """LIM, SJS to INIT if it has code, SJS to main, then a branch to itself."""
        if not self.has_main():
            return 0
        return 7 if self.sections["INIT"] else 5

    def register(self, text):
        match = re.fullmatch(r"[RB](\d+)", text)
        if not match or int(match.group(1)) > 15:
            raise AsmError(f"bad register {text!r}")
        return int(match.group(1))

    @staticmethod
    def names_symbol(arg):
        if re.fullmatch(r"[RB]\d+", arg) or arg in CONDITIONS:
            return False
        return any(match.group(2)[0] in "ABCDEFGHIJKLMNOPQRSTUVWXYZ_.$" for match in TERM.finditer(arg))

    def encode(self, op, args, scope, where, address):
        names = self.syntax[op]
        if len(args) != len(names) and not (names and names[-1] == "RX" and len(args) == len(names) - 1):
            raise AsmError(f"{where}: {op} takes {names}, got {args}")
        operands = {}
        text = []
        layout = self.reference[op].layout
        fields = [field for field, _, literal in layout if literal is None]
        for name, arg in zip(names, args):
            if name in ("RA", "RB", "RX"):
                number = self.register(arg)
                operands[name] = number
                if name != "RX" or number:
                    text.append(f"R{number}")
            elif name == "BR":
                number = self.register(arg)
                if number < 12:
                    raise AsmError(f"{where}: bad base register {arg}")
                operands["BR'"] = number - 12
                text.append(f"B{number}")
            elif name == "C":
                value = CONDITIONS.get(arg)
                value = self.evaluate(arg, scope) if value is None else value
                operands["C"] = value
                text.append(f"0x{value:x}")
            elif name == "N":
                value = self.evaluate(arg, scope)
                operands["N-1" if "N-1" in fields else "N"] = value - 1 if "N-1" in fields else value
                text.append(f"0x{value:x}")
            elif name == "LABEL" and "D" in fields:
                target = self.evaluate(arg, scope) & 0xFFFF
                displacement = target - address
                if not -128 <= displacement <= 127:
                    raise AsmError(f"{where}: branch out of range")
                operands["D"] = displacement & 0xFF
                text.append(f"0x{target:x}")
            elif name in ("DSPL", "OPEX"):
                value = self.evaluate(arg, scope)
                operands[name] = value
                text.append(f"0x{value:x}")
            else:
                field = next(f for f in fields if validate_output.FIELD_WIDTHS[f] == 16)
                value = self.evaluate(arg, scope) & 0xFFFF
                operands[field] = value
                text.append(f"0x{value:x}")
        encoded = 0
        for field, width, literal in layout:
            value = literal if literal is not None else operands.get(field, 0)
            if not 0 <= value < 1 << width:
                raise AsmError(f"{where}: {field}={value} out of range in {op}")
            encoded = encoded << width | value
        count = validate_output.word_count(self.reference[op])
        words = [encoded >> 16, encoded & 0xFFFF] if count == 2 else [encoded]
        symbolic = any(self.names_symbol(arg) for arg in args)
        return words, f"{op} {','.join(text)}".rstrip(), symbolic

    def build(self):
        self.undefined = set()
        self.layout()
        self._emit()
        self.layout(self.undefined)
        words, listing = self._emit()
        return words, listing

    def _emit(self):
        words = []
        listing = []

        def put(word, kind, text="", symbolic=False):
            listing.append((len(words), kind, text, "symbolic" if symbolic else ""))
            words.append(word & 0xFFFF)

        if self.has_main():
            main = self.addresses[(None, "MAIN")]
            put(0x85F0, "code", f"LIM R15,0x{STACK_TOP:x}")
            put(STACK_TOP, "cont")
            if self.sections["INIT"]:
                put(0x7EF0, "code", f"SJS R15,0x{self.init_base:x}")
                put(self.init_base, "cont")
            put(0x7EF0, "code", f"SJS R15,0x{main:x}")
            put(main, "cont")
            put(0x7400, "code", f"BR 0x{len(words):x}")
        for section in ("NORMAL", "stubs", "KONST", "INIT"):
            if section == "stubs":
                for _ in self.stubs:
                    put(0x7FF0, "code", "URS R15")
                continue
            for item in self.sections[section]:
                if item[0] == "insn":
                    _, op, args, scope, where = item
                    encoded, text, symbolic = self.encode(op, args, scope, where, len(words))
                    put(encoded[0], "code", text)
                    for extra in encoded[1:]:
                        put(extra, "cont", symbolic=symbolic)
                elif item[0] == "data":
                    _, arg, scope, _ = item
                    put(self.evaluate(arg, scope), "data")
                elif item[0] == "data32":
                    _, shift, arg, scope, _ = item
                    put(self.evaluate(arg, scope) >> shift, "data")
                elif item[0] == "word":
                    put(item[1], "data")
        put(0x7FF0, "code", "URS R15")
        return words, listing


def write_map(path, program):
    """Section addresses, in words, then exported symbols."""
    bases = program.bases
    rows = [(0, "startup"), (bases["NORMAL"], "normal"),
            (bases["NORMAL"] + len(program.sections["NORMAL"]), "stubs"),
            (bases["KONST"], "konst"), (bases["INIT"], "init"),
            (bases["INIT"] + len(program.sections["INIT"]), "final return"),
            (program.image_end, "common (not in the image)")]
    with open(path, "w", encoding="ascii") as out:
        out.write("# word\tsection\n")
        for address, name in rows:
            out.write(f"{address:04x}\t{name}\n")
        out.write("# word\tsymbol\n")
        symbols = [(address, key[1]) for key, address in program.addresses.items() if key[0] is None]
        symbols += [(address, f"{name} (stub)") for name, address in program.stubs.items()]
        for address, name in sorted(symbols):
            out.write(f"{address:04x}\t{name}\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("sources", nargs="+")
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("-l", "--listing", required=True)
    parser.add_argument("-m", "--map", help="also write section and symbol addresses")
    args = parser.parse_args()
    program = Program()
    try:
        for path in args.sources:
            program.add_file(path)
        words, listing = program.build()
    except AsmError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    with open(args.output, "wb") as out:
        out.write(b"".join(word.to_bytes(2, "big") for word in words))
    with open(args.listing, "w", encoding="ascii") as out:
        for address, kind, text, symbolic in listing:
            out.write(f"{address:x}\t{kind}\t{text}\t{symbolic}\n")
    if args.map:
        write_map(args.map, program)
    code = sum(1 for row in listing if row[1] == "code")
    print(f"{len(words)} words, {code} instructions, stubbed: {sorted(program.stubs)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
