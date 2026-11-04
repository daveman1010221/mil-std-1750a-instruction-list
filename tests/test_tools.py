"""Tests for the test assembler and the as1750 comparison, without running as1750."""
import os
import subprocess
import sys
import tempfile
import unittest

TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TESTS)

import compare_tekhex

ASSEMBLER = os.path.join(TESTS, "sleigh", "assemble_1750.py")
SOURCE = """\
\tname sample
\tglobal start
start
\tlr r1,r2
\tlim r3,table
\tlim r4,16#00FF#
\tl r5,table,r6
\tjc nz,start
\tbr start
table
\tdata 1,2
\tinit
\tlim r0,table
\tnormal
\tend
"""


def tek_line(word_address, words):
    """Format a data block as tekhex.c does. The parser doesn't check the checksum."""
    data = "".join(f"{w:04X}" for w in words)
    body = f"6!!5{word_address * 2:05X}{data}"
    return f"%{len(body) + 2:02X}{body}\n"


class CompareTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        path = self.path("sample.s")
        with open(path, "w") as out:
            out.write(SOURCE)
        subprocess.run([sys.executable, ASSEMBLER, "-o", self.path("sample.bin"), "-l", self.path("sample.tsv"),
                        "-m", self.path("sample.map"), path], check=True, capture_output=True)
        with open(self.path("sample.bin"), "rb") as source:
            data = source.read()
        self.binary = [int.from_bytes(data[i:i + 2], "big") for i in range(0, len(data), 2)]
        self.code = compare_tekhex.read_code(self.path("sample.tsv"), self.path("sample.map"))

    def path(self, name):
        return os.path.join(self.directory.name, name)

    def compare_with(self, change=None):
        words = [self.binary[row[0]] for row in self.code]
        if change:
            change(words)
        with open(self.path("as1750.hex"), "w") as out:
            out.write("%1F3AA5sectionsymbolblock\n")
            out.write(tek_line(0x100, words))
        return compare_tekhex.compare(compare_tekhex.read_tekhex(self.path("as1750.hex")), self.code, self.binary)

    def test_code_is_init_then_normal(self):
        texts = [row[2] for row in self.code if row[1] == "code"]
        self.assertTrue(texts[0].startswith("LIM R0,"))
        self.assertEqual(texts[1], "LR R1,R2")

    def test_matching_output_passes(self):
        compared, _, mismatches = self.compare_with()
        self.assertGreater(compared, 0)
        self.assertEqual(mismatches, [])

    def test_symbolic_addresses_are_skipped_and_literals_are_not(self):
        kinds = {row[2]: row for row in self.code}
        rows = {i: row for i, row in enumerate(self.code)}
        symbolic = [i for i, row in rows.items() if row[1] == "cont" and row[3]]
        literal = [i for i, row in rows.items() if row[1] == "cont" and not row[3]]
        self.assertEqual(len(literal), 1)
        self.assertEqual(self.binary[rows[literal[0]][0]], 0x00FF)
        self.assertGreater(len(symbolic), 0)
        self.assertIn("LR R1,R2", kinds)
        # A different address for a symbol is expected, because the layouts differ.
        _, _, mismatches = self.compare_with(lambda words: words.__setitem__(symbolic[0], 0x1234))
        self.assertEqual(mismatches, [])

    def test_different_opcode_is_reported(self):
        def change(words):
            words[2] ^= 0x0010
        _, _, mismatches = self.compare_with(change)
        self.assertEqual(len(mismatches), 1)

    def test_different_literal_is_reported(self):
        literal = next(i for i, row in enumerate(self.code) if row[1] == "cont" and not row[3])
        _, _, mismatches = self.compare_with(lambda words: words.__setitem__(literal, 0x1234))
        self.assertEqual(len(mismatches), 1)

    def test_missing_output_is_reported(self):
        _, _, mismatches = self.compare_with(lambda words: words.__delitem__(slice(1, None)))
        self.assertGreater(len(mismatches), 0)


if __name__ == "__main__":
    unittest.main()
