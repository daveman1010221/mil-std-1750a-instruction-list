"""Fast tests: run with `python3 -m unittest discover -s tests`."""
import os
import subprocess
import sys
import tempfile
import unittest

TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TESTS)
sys.path.insert(0, os.path.dirname(TESTS))

import generate_1750a
import validate_output

# Every 16-bit-only high byte, plus one 32-bit opcode of each operand layout.
SUBSET = [op for op in range(0x100) if generate_1750a.line_count(op) <= 0x100]
LONG_SAMPLES = [0x4A, 0x7D]

# Worked by hand from the format boxes in section 5 of the standard.
GOLDEN = {
    "0x8100     LR R0,R0",
    "0x81AB     LR R10,R11",
    "0x0000     LB B12,0x00",
    "0x0312     LB B15,0x12",
    "0x0534     DLB B13,0x34",
    "0x4000     LBX B12",
    "0x4315     DLBX B15,R5",
    "0x40EF     ANDX B12,R15",
    "0x6000     SLL R0,0x01",
    "0x60F3     SLL R3,0x10",
    "0x8200     LISP R0,0x01",
    "0x832F     LISN R2,0x10",
    "0x5137     SBR 0x3,R7",
    "0x7480     BR 0x80",
    "0x770C     BEX 0xC",
    "0x7F50     URS R5",
    "0xEC70     XBR R7",
    "0x4F2A     BIF 0x2A",
    "0xFF00     NOP",
    "0xFFFF     BPT",
    "0x4A330042 MIM R3,0x0042",
    "0x4AF9FFFF XORM R15,0xFFFF",
    "0x7D001234 LST 0x1234",
    "0x7C0F1234 LSTI 0x1234,R15",
}
GOLDEN_LONG = {
    "0x80120034 L R1,0x0034,R2",
    "0x80100034 L R1,0x0034",
    "0x48012000 XIO R0,0x2000,R1",
    "0x7071ABCD JC 0x7,0xABCD,R1",
    "0xA3F00001 INCM 0x10,0x0001",
    "0xB3020001 DECM 0x01,0x0001,R2",
    "0x50A10002 SB 0xA,0x0002,R1",
    "0xD0120003 DV R1,0x0003,R2",
    "0xE0120003 OR R1,0x0003,R2",
    "0x8D340005 LUBI R3,0x0005,R4",
    "0xA0120003 A R1,0x0003,R2",
    "0xF0120003 C R1,0x0003,R2",
}


class GeneratorTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.short_path = os.path.join(cls.directory.name, "short.txt")
        generate_1750a.write_opcodes(cls.short_path, SUBSET)
        cls.long_path = os.path.join(cls.directory.name, "long.txt")
        generate_1750a.write_opcodes(cls.long_path, [0x4A])
        with open(cls.short_path) as source:
            cls.short_lines = source.read().splitlines()

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def mutated(self, transform):
        """Write a copy of the short output with transform applied to its lines."""
        path = os.path.join(self.directory.name, "mutated.txt")
        lines = transform(list(self.short_lines))
        with open(path, "w", newline="\n") as out:
            out.write("".join(line + "\n" for line in lines))
        return validate_output.validate([path], SUBSET)


class TestOutput(GeneratorTestCase):
    def test_short_instructions_match_the_standard(self):
        self.assertEqual(validate_output.validate([self.short_path], SUBSET), [])

    def test_long_instructions_match_the_standard(self):
        for opcode in LONG_SAMPLES:
            with self.subTest(opcode=f"{opcode:02X}"):
                path = os.path.join(self.directory.name, f"{opcode:02X}.txt")
                generate_1750a.write_opcodes(path, [opcode])
                self.assertEqual(validate_output.validate([path], [opcode]), [])

    def test_golden_lines(self):
        lines = set(self.short_lines)
        with open(self.long_path) as source:
            lines.update(source.read().splitlines())
        for opcode in (0x7C, 0x7D):
            path = os.path.join(self.directory.name, "golden.txt")
            generate_1750a.write_opcodes(path, [opcode])
            with open(path) as source:
                lines.update(source.read().splitlines())
        self.assertEqual(GOLDEN - lines, set())

    def test_golden_long_lines(self):
        # Long opcodes are 16M lines each, so stop at the chunk holding the line.
        for line in sorted(GOLDEN_LONG):
            with self.subTest(line):
                first_word = line[:6]
                for chunk in generate_1750a._high_byte_chunks(int(line[2:4], 16)):
                    if chunk.startswith(first_word):
                        self.assertIn(line + "\n", chunk)
                        break
                else:
                    self.fail(f"{first_word} was not generated")

    def test_generator_and_standard_agree_on_every_line_count(self):
        expected = validate_output.expected_counts(validate_output.load_reference())
        actual = {op: generate_1750a.line_count(op) for op in range(0x100)}
        self.assertEqual({op: n for op, n in actual.items() if n}, dict(expected))

    def test_every_mnemonic_in_the_standard_is_generated(self):
        reference = set(validate_output.load_reference())
        generated = {mnemonic for mnemonic, _ in generate_1750a.OPCODES.values()}
        generated |= set(generate_1750a.BASE_RELATIVE)
        generated |= set(generate_1750a.BASE_RELATIVE_INDEXED)
        generated |= set(generate_1750a.IMMEDIATE_EXTENDED.values())
        generated |= {"NOP", "BPT"}
        self.assertEqual(generated, reference)

    def test_command_line_output_matches_library_output(self):
        path = os.path.join(self.directory.name, "cli.txt")
        script = os.path.join(os.path.dirname(TESTS), "generate_1750a.py")
        subprocess.run([sys.executable, script, "--opcodes", "81", "-o", path], check=True,
                       capture_output=True)
        self.assertEqual(validate_output.validate([path], [0x81]), [])

    def test_split_files_validate_together(self):
        directory = os.path.join(self.directory.name, "split")
        script = os.path.join(os.path.dirname(TESTS), "generate_1750a.py")
        subprocess.run([sys.executable, script, "--opcodes", "81,74,00", "--split-dir", directory],
                       check=True, capture_output=True)
        paths = [os.path.join(directory, name) for name in os.listdir(directory)]
        self.assertEqual(len(paths), 3)
        self.assertEqual(validate_output.validate(paths, [0x81, 0x74, 0x00]), [])


class TestValidatorCatchesBadOutput(GeneratorTestCase):
    """A validator that can't fail proves nothing, so corrupt the output on purpose."""

    def assert_rejected(self, transform):
        self.assertNotEqual(self.mutated(transform), [])

    def replace(self, old, new):
        def transform(lines):
            lines[lines.index(old)] = new
            return lines
        return transform

    def test_unmodified_output_passes(self):
        self.assertEqual(self.mutated(lambda lines: lines), [])

    def test_missing_line(self):
        self.assert_rejected(lambda lines: lines[:100] + lines[101:])

    def test_duplicate_line(self):
        self.assert_rejected(lambda lines: lines[:100] + [lines[100]] + lines[100:])

    def test_duplicate_replacing_a_missing_line(self):
        # The line count stays right, so only the ordering check can catch this.
        self.assert_rejected(lambda lines: lines[:100] + [lines[100], lines[100]] + lines[102:])

    def test_out_of_order(self):
        self.assert_rejected(lambda lines: lines[:100] + [lines[101], lines[100]] + lines[102:])

    def test_wrong_mnemonic(self):
        self.assert_rejected(self.replace("0x8100     LR R0,R0", "0x8100     AR R0,R0"))

    def test_unknown_mnemonic(self):
        self.assert_rejected(self.replace("0x8100     LR R0,R0", "0x8100     FOO R0,R0"))

    def test_swapped_registers(self):
        self.assert_rejected(self.replace("0x81AB     LR R10,R11", "0x81AB     LR R11,R10"))

    def test_shift_count_off_by_one(self):
        self.assert_rejected(self.replace("0x6000     SLL R0,0x01", "0x6000     SLL R0,0x00"))

    def test_shift_operands_swapped(self):
        self.assert_rejected(self.replace("0x60F3     SLL R3,0x10", "0x60F3     SLL R15,0x04"))

    def test_wrong_base_register(self):
        self.assert_rejected(self.replace("0x0000     LB B12,0x00", "0x0000     LB B13,0x00"))

    def test_r0_written_as_an_index(self):
        self.assert_rejected(self.replace("0x4000     LBX B12", "0x4000     LBX B12,R0"))

    def test_undefined_opcode(self):
        self.assert_rejected(lambda lines: lines + ["0xFFFE     BPT"])

    def test_lowercase_hex(self):
        self.assert_rejected(self.replace("0x81AB     LR R10,R11", "0x81ab     LR R10,R11"))

    def test_broken_column_alignment(self):
        self.assert_rejected(self.replace("0x8100     LR R0,R0", "0x8100 LR R0,R0"))

    def test_trailing_text(self):
        self.assert_rejected(self.replace("0x8100     LR R0,R0", "0x8100     LR R0,R0 ; comment"))

    def test_missing_final_newline(self):
        path = os.path.join(self.directory.name, "no_newline.txt")
        with open(path, "w", newline="\n") as out:
            out.write("0x8100     LR R0,R0")
        self.assertTrue(validate_output.check_file(path)[3])


if __name__ == "__main__":
    unittest.main()
