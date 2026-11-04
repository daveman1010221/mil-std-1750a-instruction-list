"""Compare our table with sources written by other people.

Files are read as plain text and never compiled or run. They are downloaded at a
pinned revision into tests/.refs/, and these tests skip when they can't be fetched.
"""
import os
import re
import sys
import unittest
import urllib.request

TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TESTS)
sys.path.insert(0, os.path.dirname(TESTS))

import extract_spec_table
import generate_1750a
import validate_output

GENERATOR_REV = "cc27e0ef5aa0ecbbc60d4f142a0d04e0802a00d3"
TOOLS_REV = "5d3ad01bc70e8ddea103f0654996c3a9b8a4e7dc"
GENERATOR_URL = f"https://raw.githubusercontent.com/oberoisecurity/ghidra-processor-module-generator/{GENERATOR_REV}"
TOOLS_URL = f"https://raw.githubusercontent.com/okellogg/milstd1750tools/{TOOLS_REV}"
SOURCES = {
    "mil-std-1750a.txt": "https://www.mssl.ucl.ac.uk/swift/om/sw/mil-std-1750a.txt",
    "as1750.c": f"{TOOLS_URL}/as1750/as1750.c",
    "dism1750.c": f"{TOOLS_URL}/sim1750/src/dism1750.c",
    "registers.h": f"{GENERATOR_URL}/registers.h",
    "8048.txt": f"{GENERATOR_URL}/examples/8048.txt",
}
CACHE = os.path.join(TESTS, ".refs")

# Registers we pass with --additional-registers.
ADDITIONAL_REGISTERS = {f"R{n}" for n in range(8, 16)} | {f"B{n}" for n in range(12, 16)}
# Mnemonics the generator's stock registers.h treats as registers. See the README.
REGISTER_COLLISIONS = {"A", "C"}

# as1750 entries that are not in MIL-STD-1750A: aliases, and GVSC, MA31750 or 1750B extensions.
AS1750_EXTRAS = {
    "J", "JEZ", "JLE", "JGT", "JNZ", "JGE", "JLT", "STZ",
    "SFBS", "UAR", "UA", "USR", "US", "UCIM", "UCR", "UC",
    "STE", "DSTE", "LE", "DLE",
}
AS1750_TWO_WORD = {"as_mem", "as_addr", "as_xmem", "as_im_0_15", "as_im_1_16",
                   "as_im_ocx", "as_jump", "as_xio"}
DISM_TWO_WORD = {"dis_ra_addr_rx", "dis_ra_caddr_rx", "dis_n_addr_rx", "dis_n1_addr_rx",
                 "dis_ra_cmd_rx", "dis_c_caddr_rx", "dis_addr_rx", "dis_bif"}
# Places dism1750.c disagrees with the standard's format boxes on instruction length:
# it decodes LUBI and LLBI as 1-word register forms, and always gives BIF a data word.
DISM_KNOWN_ERRORS = {"LUBI", "LLBI", "BIF"}


def fetch(name):
    path = os.path.join(CACHE, name)
    if not os.path.exists(path):
        os.makedirs(CACHE, exist_ok=True)
        try:
            with urllib.request.urlopen(SOURCES[name], timeout=60) as response:
                data = response.read()
        except OSError as error:
            raise unittest.SkipTest(f"can't fetch {name}: {error}")
        with open(path, "wb") as out:
            out.write(data)
    with open(path, encoding="latin-1") as source:
        return source.read()


def split_line(line):
    """Port of splitDisassemblyLine() in the generator's parser.cpp."""
    tokens = []
    current = ""
    for char in line:
        if char in ",@()[]{}+-# *!\t\r\n":
            if current:
                tokens.append(current)
                current = ""
            if char not in " \t\r\n":
                tokens.append(char)
        else:
            current += char
    if current:
        tokens.append(current)
    return tokens


def is_immediate(token):
    return token[:2] in ("0x", "0X") and len(token) > 2 or token[0].isdigit()


class TestStandard(unittest.TestCase):
    def test_reference_table_is_what_the_standard_says(self):
        table = extract_spec_table.extract(fetch("mil-std-1750a.txt").splitlines())
        rows = [f"{name}\t{mode}\t{syntax}\t{' '.join(fields)}\n"
                for name, (mode, syntax, fields) in sorted(table.items())]
        with open(validate_output.REFERENCE, encoding="ascii") as source:
            self.assertEqual(rows, source.readlines())


class TestAs1750(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        text = fetch("as1750.c")
        cls.optab = {name: (int(opcode, 16), handler) for name, opcode, handler in re.findall(
            r'\{ "([A-Z]+)",\s*0x([0-9A-F]{4}), (as_\w+) \}', text)}
        cls.reference = validate_output.load_reference()

    def test_same_instruction_set(self):
        self.assertEqual(set(self.optab) - set(self.reference), AS1750_EXTRAS)
        self.assertEqual(set(self.reference) - set(self.optab), set())

    def test_same_opcodes(self):
        for name, instruction in self.reference.items():
            with self.subTest(name):
                self.assertEqual(self.optab[name][0] >> 8, validate_output.high_byte(instruction))

    def test_same_lengths(self):
        for name, instruction in self.reference.items():
            with self.subTest(name):
                words = 2 if self.optab[name][1] in AS1750_TWO_WORD else 1
                self.assertEqual(words, validate_output.word_count(instruction))


class TestDism1750(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = fetch("dism1750.c")
        cls.entries = {}
        for name, handler, opcode in re.findall(
                r'\{ "([A-Z]+)",\s*(dis_\w+) \},\s*/\* ([0-9A-F]{2}) \*/', cls.text):
            cls.entries.setdefault(name, (int(opcode, 16), handler))
        cls.reference = validate_output.load_reference()

    def test_opcode_map_agrees(self):
        for name, instruction in self.reference.items():
            if name in self.entries and name != "NOP":
                with self.subTest(name):
                    self.assertEqual(self.entries[name][0], validate_output.high_byte(instruction))

    def test_lengths_agree_except_known_errors(self):
        disagreements = set()
        for name, instruction in self.reference.items():
            if name in self.entries and name != "NOP":
                words = 2 if self.entries[name][1] in DISM_TWO_WORD else 1
                if words != validate_output.word_count(instruction):
                    disagreements.add(name)
        self.assertEqual(disagreements, DISM_KNOWN_ERRORS)

    def test_extended_opcode_tables_agree(self):
        indexed = re.search(r"start_4x\[16\] =\s*\{(.*?)\}", self.text, re.S).group(1)
        self.assertEqual(tuple(re.findall(r'"(\w+)"', indexed)),
                         generate_1750a.BASE_RELATIVE_INDEXED)
        immediate = re.search(r"start_4a\[16\] =\s*\{(.*?)\}", self.text, re.S).group(1)
        names = re.findall(r'"([\w?]+)"', immediate)
        self.assertEqual({i: name for i, name in enumerate(names) if "?" not in name},
                         generate_1750a.IMMEDIATE_EXTENDED)


class TestGeneratorParserRules(unittest.TestCase):
    """Apply the generator's tokenizer and classifier rules without running it."""

    @classmethod
    def setUpClass(cls):
        cls.registers = set(re.findall(r'^\s*"([^"]+)",\s*$', fetch("registers.h"), re.M))
        cls.mnemonics = set(validate_output.load_reference())

    def lines(self):
        for opcode in range(0x100):
            if not generate_1750a.is_defined(opcode):
                continue
            if generate_1750a.line_count(opcode) <= 0x100:
                for chunk in generate_1750a._high_byte_chunks(opcode):
                    yield from chunk.splitlines()
            else:
                for chunk in generate_1750a._high_byte_chunks(opcode):
                    yield from chunk[:200].splitlines()[:2]
                    yield from chunk[-200:].splitlines()[-2:]
                    break

    def test_tokenizer_port_reads_the_generators_own_example(self):
        for line in fetch("8048.txt").splitlines():
            tokens = split_line(line)
            self.assertTrue(is_immediate(tokens[0]), line)
            self.assertGreater(len(tokens), 1, line)

    def test_only_the_documented_mnemonics_collide_with_registers(self):
        self.assertEqual(self.mnemonics & self.registers, REGISTER_COLLISIONS)

    def test_every_line_tokenizes_as_the_generator_needs(self):
        registers = (self.registers | ADDITIONAL_REGISTERS) - REGISTER_COLLISIONS
        seen_registers = set()
        for line in self.lines():
            if len(line.split(" ", 1)[0]) not in (6, 10):
                self.fail(f"bad opcode width: {line}")
            tokens = split_line(line)
            self.assertLessEqual(len(tokens), 26, line)
            self.assertTrue(is_immediate(tokens[0]), line)
            self.assertIn(tokens[1], self.mnemonics, line)
            self.assertNotIn(tokens[1], registers, line)
            for token in tokens[2:]:
                if token == ",":
                    continue
                if token in registers:
                    seen_registers.add(token)
                else:
                    self.assertTrue(is_immediate(token), f"{token!r} in {line}")
        self.assertEqual(seen_registers - self.registers, ADDITIONAL_REGISTERS)


if __name__ == "__main__":
    unittest.main()
