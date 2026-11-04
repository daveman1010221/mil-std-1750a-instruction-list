#!/usr/bin/env python3
"""Generate behavior test vectors from a model of the standard's register transfers.

Shares no code with the SLEIGH module. tests/sleigh/VerifyBehavior.java runs each vector
through the module's p-code in Ghidra's emulator and compares the result. This is one
reading of the standard checked against another written separately, not an independent
implementation, so it finds slips rather than misreadings.

Floating point and I/O are named operations, so the model and the emulator both use the
stub below. That checks which values reach each operation and where the result goes,
not the arithmetic itself.

Not generated, because the standard leaves the result undefined or the module doesn't
model it: division by zero and division overflow, and multi-word memory operands that
cross the top of memory.

    behavior_model.py [--count N] [--seed N] > vectors.tsv
"""
import argparse
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import validate_output

BASE = 0x4000
INTERESTING = (0, 1, 2, 0x7FFF, 0x8000, 0x8001, 0xFFFF, 0xFFFE, 0x00FF, 0xFF00, 0x0100)
M16 = 0xFFFF
M32 = 0xFFFFFFFF
BITS16 = {"RA", "RB", "RX", "N", "N-1", "C"}


class Reject(Exception):
    """This random state hits a case the test excludes; draw another."""


def signed(value, bits):
    value &= (1 << bits) - 1
    return value - (1 << bits) if value >> (bits - 1) else value


def stub(name, inputs, out_bytes):
    """Must match stub() in VerifyBehavior.java."""
    salt = sum(map(ord, name))
    multipliers = (3, 5, 7)
    total = salt + sum(m * value for m, value in zip(multipliers, inputs))
    return total & ((1 << (8 * out_bytes)) - 1)


def truncating_div(a, b):
    quotient = abs(a) // abs(b)
    return -quotient if (a < 0) != (b < 0) else quotient


class State:
    def __init__(self, rng, words):
        self.rng = rng
        self.instruction = {BASE + i: w for i, w in enumerate(words)}
        self.r = [self.value() for _ in range(16)]
        self.c = rng.randrange(2)
        self.p = self.z = self.n = 0
        setattr(self, rng.choice("pzn"), 1)
        self.mk = rng.randrange(0x10000)
        self.sw = rng.randrange(0x10000)
        self.mem = {}
        self.initial = {}
        self.written = set()
        self.next = BASE + len(words)

    def value(self):
        if self.rng.random() < 0.4:
            return self.rng.choice(INTERESTING)
        return self.rng.randrange(0x10000)

    def rd(self, address):
        address &= M16
        if address in self.instruction:
            raise Reject
        if address not in self.mem:
            self.mem[address] = self.initial[address] = self.value()
        return self.mem[address]

    def wr(self, address, value):
        address &= M16
        if address in self.instruction:
            raise Reject
        self.rd(address)
        self.mem[address] = value & M16
        self.written.add(address)

    def rd_n(self, address, words):
        address &= M16
        if address + words > 0x10000:
            raise Reject
        value = 0
        for i in range(words):
            value = value << 16 | self.rd(address + i)
        return value

    def wr_n(self, address, words, value):
        address &= M16
        if address + words > 0x10000:
            raise Reject
        for i in range(words):
            self.wr(address + i, value >> (16 * (words - 1 - i)))

    def get(self, reg, words):
        value = 0
        for i in range(words):
            value = value << 16 | self.r[(reg + i) & 15]
        return value

    def put(self, reg, words, value):
        for i in range(words):
            self.r[(reg + i) & 15] = (value >> (16 * (words - 1 - i))) & M16

    def cs(self, value, bits, carry=0):
        value = signed(value, bits)
        self.c = carry
        self.z, self.n, self.p = int(value == 0), int(value < 0), int(value > 0)

    def compare(self, left, right):
        self.c = 0
        self.z, self.n, self.p = int(left == right), int(left < right), int(left > right)

    def test_bit(self, value, n):
        bit = (value >> (15 - n)) & 1
        self.c = 0
        self.z, self.n, self.p = int(not bit), int(bit and n == 0), int(bit and n != 0)


def derived_address(s, v, mode):
    """The address of the operand, for the memory and base relative modes."""
    if mode in ("B", "BX"):
        base = s.r[12 + v["BR'"]]
        return (base + (v["DSPL"] if mode == "B" else (s.r[v["RX"]] if v["RX"] else 0))) & M16
    address = (v["ADDR"] + (s.r[v["RX"]] if v.get("RX") else 0)) & M16
    return s.rd(address) if mode in ("I", "IX") else address


def operand(s, v, mode, words=1):
    """The derived operand, for instructions with a value source."""
    if mode == "R":
        return s.get(v["RB"], words)
    if mode == "ISP":
        return v["N-1"] + 1
    if mode == "ISN":
        return -(v["N-1"] + 1) & M16
    if mode == "IM":
        return v["ADDR"]
    if mode == "IMX":
        return (v["ADDR"] + (s.r[v["RX"]] if v["RX"] else 0)) & M16
    return s.rd_n(derived_address(s, v, mode), words)


def accumulator(v, mode, double=False):
    """B and BX have fixed accumulators: R2 for single precision, R0 and R1 otherwise."""
    if mode in ("B", "BX"):
        return 0 if double else 2
    return v["RA"]


def shift_left(value, n, bits):
    return (value << n) & ((1 << bits) - 1)


def rotate_left(value, n, bits):
    n %= bits
    mask = (1 << bits) - 1
    return ((value << n) | (value >> (bits - n))) & mask


def shift_right_arithmetic(value, n, bits):
    return (signed(value, bits) >> n) & ((1 << bits) - 1)


def shift_by_register(s, v, words, kind):
    bits = 16 * words
    n = signed(s.r[v["RB"]], 16)
    value = s.get(v["RA"], words)
    if abs(n) > bits:
        return  # overflow, then exit: nothing changes
    if kind == "cyclic":
        value = rotate_left(value, n % bits, bits)
    elif n >= 0:
        value = shift_left(value, n, bits)
    elif kind == "logical":
        value >>= -n
    else:
        value = shift_right_arithmetic(value, -n, bits)
    s.put(v["RA"], words, value)
    s.cs(value, bits)


def conditional_jump(s, v, indirect):
    c = v["C"]
    address = (v["ADDR"] + (s.r[v["RX"]] if v["RX"] else 0)) & M16
    target = s.rd(address) if indirect and c else address
    flags = s.c << 3 | s.p << 2 | s.z << 1 | s.n
    if c in (7, 15) or c & flags:
        s.next = target


def relative(s, v):
    return (BASE + signed(v["D"], 8)) & M16


SINGLE_LOADS = {"LR", "LB", "LBX", "LISP", "LISN", "L", "LIM", "LI"}
DOUBLE_LOADS = {"DLR", "DLB", "DLBX", "DL", "DLI"}
SINGLE_STORES = {"ST", "STB", "STBX", "STI"}
DOUBLE_STORES = {"DST", "DSTB", "DSTX", "DSTI"}
ADD = {"AR", "AB", "ABX", "AISP", "A", "AIM"}
SUB = {"SR", "SBB", "SBBX", "SISP", "S", "SIM"}
MUL16 = {"MSR", "MISP", "MISN", "MS", "MSIM"}
MUL32 = {"MR", "MB", "MBX", "M", "MIM"}
DIV16 = {"DVR", "DISP", "DISN", "DV", "DVIM"}
DIV32 = {"DR", "DB", "DBX", "D", "DIM"}
OR = {"ORR", "ORB", "ORBX", "OR", "ORIM"}
AND = {"ANDR", "ANDB", "ANDX", "AND", "ANDM"}
XOR = {"XORR", "XOR", "XORM"}
NAND = {"NR", "N", "NIM"}
COMPARE = {"CR", "CB", "CBX", "CISP", "CISN", "C", "CIM"}
FLOAT_OPS = {
    "FAR": "fadd", "FAB": "fadd", "FABX": "fadd", "FA": "fadd", "EFAR": "fadd", "EFA": "fadd",
    "FSR": "fsub", "FSB": "fsub", "FSBX": "fsub", "FS": "fsub", "EFSR": "fsub", "EFS": "fsub",
    "FMR": "fmul", "FMB": "fmul", "FMBX": "fmul", "FM": "fmul", "EFMR": "fmul", "EFM": "fmul",
    "FDR": "fdiv", "FDB": "fdiv", "FDBX": "fdiv", "FD": "fdiv", "EFDR": "fdiv", "EFD": "fdiv",
}
FLOAT_COMPARES = {"FCR", "FCB", "FCBX", "FC", "EFCR", "EFC"}
BRANCHES = {
    "BEZ": lambda f: f == 2, "BLT": lambda f: f == 1, "BLE": lambda f: f in (1, 2),
    "BGT": lambda f: f == 4, "BNZ": lambda f: f in (1, 4), "BGE": lambda f: f in (2, 4),
}


def execute(s, name, v, mode):
    if name in SINGLE_LOADS:
        value = operand(s, v, mode)
        reg = accumulator(v, mode)
        s.r[reg] = value
        s.cs(value, 16)
    elif name in DOUBLE_LOADS:
        value = operand(s, v, mode, 2)
        s.put(accumulator(v, mode, True), 2, value)
        s.cs(value, 32)
    elif name == "LM":
        address = (v["ADDR"] + (s.r[v["RX"]] if v["RX"] else 0)) & M16
        for i in range(v["N"] + 1):
            s.r[i] = s.rd(address + i)
    elif name == "EFL":
        value = operand(s, v, "DX", 3)
        s.put(v["RA"], 3, value)
        s.cs(value, 48)
    elif name in ("LUB", "LUBI"):
        s.r[v["RA"]] = (s.r[v["RA"]] & 0xFF00) | (operand(s, v, mode) >> 8)
        s.cs(s.r[v["RA"]], 16)
    elif name in ("LLB", "LLBI"):
        s.r[v["RA"]] = (s.r[v["RA"]] & 0xFF00) | (operand(s, v, mode) & 0xFF)
        s.cs(s.r[v["RA"]], 16)
    elif name == "POPM":
        ra, rb = v["RA"], v["RB"]
        order = range(ra, rb + 1) if ra <= rb else list(range(ra, 16)) + list(range(0, rb + 1))
        for reg in order:
            if reg != 15:
                s.r[reg] = s.rd(s.r[15])
            s.r[15] = (s.r[15] + 1) & M16
    elif name == "PSHM":
        ra, rb = v["RA"], v["RB"]
        if ra <= rb:
            order = [rb - i for i in range(rb - ra + 1)]
        else:
            order = [rb - i for i in range(rb + 1)] + [15 - i for i in range(15 - ra + 1)]
        for reg in order:
            s.r[15] = (s.r[15] - 1) & M16
            s.wr(s.r[15], s.r[reg])
    elif name in SINGLE_STORES:
        s.wr(derived_address(s, v, mode), s.r[accumulator(v, mode)])
    elif name in ("STC", "STCI"):
        s.wr(derived_address(s, v, mode), v["N"])
    elif name in DOUBLE_STORES:
        s.wr_n(derived_address(s, v, mode), 2, s.get(accumulator(v, mode, True), 2))
    elif name == "SRM":
        address = derived_address(s, v, mode)
        mask = s.r[(v["RA"] + 1) & 15]
        s.wr(address, (s.rd(address) & ~mask) | (s.r[v["RA"]] & mask))
    elif name == "STM":
        address = (v["ADDR"] + (s.r[v["RX"]] if v["RX"] else 0)) & M16
        for i in range(v["N"] + 1):
            s.wr(address + i, s.r[i])
    elif name == "EFST":
        s.wr_n(derived_address(s, v, "DX"), 3, s.get(v["RA"], 3))
    elif name in ("STUB", "SUBI"):
        address = derived_address(s, v, mode)
        s.wr(address, (s.rd(address) & 0x00FF) | (s.r[v["RA"]] & 0xFF) << 8)
    elif name in ("STLB", "SLBI"):
        address = derived_address(s, v, mode)
        s.wr(address, (s.rd(address) & 0xFF00) | (s.r[v["RA"]] & 0xFF))
    elif name == "MOV":
        ra, rb, count = v["RA"], v["RB"], (v["RA"] + 1) & 15
        if rb in (ra, count):
            raise Reject  # the standard doesn't define these overlaps
        while s.r[count]:
            s.wr(s.r[ra], s.rd(s.r[rb]))
            s.r[ra] = (s.r[ra] + 1) & M16
            s.r[rb] = (s.r[rb] + 1) & M16
            s.r[count] -= 1
    elif name in ADD:
        reg = accumulator(v, mode)
        total = s.r[reg] + operand(s, v, mode)
        s.r[reg] = total & M16
        s.cs(total, 16, total >> 16)
    elif name in SUB:
        reg = accumulator(v, mode)
        value = operand(s, v, mode)
        carry = int(s.r[reg] >= value)
        s.r[reg] = (s.r[reg] - value) & M16
        s.cs(s.r[reg], 16, carry)
    elif name == "INCM":
        address = derived_address(s, v, mode)
        total = s.rd(address) + v["N-1"] + 1
        s.wr(address, total)
        s.cs(total, 16, total >> 16)
    elif name == "DECM":
        address = derived_address(s, v, mode)
        old, count = s.rd(address), v["N-1"] + 1
        s.wr(address, old - count)
        s.cs(old - count, 16, int(old >= count))
    elif name in ("DAR", "DA"):
        total = s.get(v["RA"], 2) + operand(s, v, mode, 2)
        s.put(v["RA"], 2, total)
        s.cs(total, 32, total >> 32)
    elif name in ("DSR", "DS"):
        left, right = s.get(v["RA"], 2), operand(s, v, mode, 2)
        s.put(v["RA"], 2, left - right)
        s.cs(left - right, 32, int(left >= right))
    elif name == "ABS":
        value = abs(signed(s.r[v["RB"]], 16)) & M16
        s.r[v["RA"]] = value
        s.cs(value, 16)
    elif name == "DABS":
        value = abs(signed(s.get(v["RB"], 2), 32)) & M32
        s.put(v["RA"], 2, value)
        s.cs(value, 32)
    elif name == "NEG":
        value = -s.r[v["RB"]] & M16
        exits = s.r[v["RB"]] == 0x8000  # overflow, then exit before CS
        s.r[v["RA"]] = value
        if not exits:
            s.cs(value, 16)
    elif name == "DNEG":
        value = -s.get(v["RB"], 2) & M32
        exits = s.get(v["RB"], 2) == 0x80000000
        s.put(v["RA"], 2, value)
        if not exits:
            s.cs(value, 32)
    elif name in MUL16:
        product = signed(s.r[v["RA"]], 16) * signed(operand(s, v, mode), 16)
        s.r[v["RA"]] = product & M16
        s.cs(product, 16)
    elif name in MUL32:
        reg = accumulator(v, mode)
        product = signed(s.r[reg], 16) * signed(operand(s, v, mode), 16)
        s.put(reg, 2, product)
        s.cs(product, 32)
    elif name in ("DMR", "DM"):
        product = signed(s.get(v["RA"], 2), 32) * signed(operand(s, v, mode, 2), 32)
        s.put(v["RA"], 2, product)
        s.cs(product, 32)
    elif name in DIV16:
        dividend, divisor = signed(s.r[v["RA"]], 16), signed(operand(s, v, mode), 16)
        if divisor == 0 or (dividend == -0x8000 and divisor == -1):
            raise Reject
        quotient = truncating_div(dividend, divisor)
        s.r[v["RA"]] = quotient & M16
        s.r[(v["RA"] + 1) & 15] = (dividend - quotient * divisor) & M16
        s.cs(quotient, 16)
    elif name in DIV32:
        reg = accumulator(v, mode)
        dividend, divisor = signed(s.get(reg, 2), 32), signed(operand(s, v, mode), 16)
        if divisor == 0 or (dividend == -0x80000000 and divisor == -1):
            raise Reject
        quotient = truncating_div(dividend, divisor)
        s.r[reg] = quotient & M16
        s.r[(reg + 1) & 15] = (dividend - quotient * divisor) & M16
        s.cs(s.r[reg], 16)
    elif name in ("DDR", "DD"):
        dividend, divisor = signed(s.get(v["RA"], 2), 32), signed(operand(s, v, mode, 2), 32)
        if divisor == 0 or (dividend == -0x80000000 and divisor == -1):
            raise Reject
        quotient = truncating_div(dividend, divisor)
        s.put(v["RA"], 2, quotient)
        s.cs(quotient, 32)
    elif name in OR | AND | XOR | NAND:
        reg = accumulator(v, mode)
        value = operand(s, v, mode)
        if name in OR:
            result = s.r[reg] | value
        elif name in AND:
            result = s.r[reg] & value
        elif name in XOR:
            result = s.r[reg] ^ value
        else:
            result = ~(s.r[reg] & value) & M16
        s.r[reg] = result
        s.cs(result, 16)
    elif name in COMPARE:
        s.compare(signed(s.r[accumulator(v, mode)], 16), signed(operand(s, v, mode), 16))
    elif name in ("DCR", "DC"):
        s.compare(signed(s.get(v["RA"], 2), 32), signed(operand(s, v, mode, 2), 32))
    elif name == "CBL":
        address = derived_address(s, v, mode)
        limits = s.rd_n(address, 2)
        lower, upper = signed(limits >> 16, 16), signed(limits & M16, 16)
        value = signed(s.r[v["RA"]], 16)
        s.c = int(lower > upper)
        s.n = int(not s.c and value < lower)
        s.p = int(not s.c and value > upper)
        s.z = int(not s.c and lower <= value <= upper)
    elif name in ("SBR", "RBR", "SVBR", "RVBR"):
        n = s.r[v["RA"]] & 15 if name.endswith("VBR") else v["N"]
        mask = 0x8000 >> n
        s.r[v["RB"]] = s.r[v["RB"]] | mask if name[0] == "S" else s.r[v["RB"]] & ~mask & M16
    elif name in ("SB", "SBI", "RB", "RBI"):
        address = derived_address(s, v, mode)
        mask = 0x8000 >> v["N"]
        s.wr(address, s.rd(address) | mask if name[0] == "S" else s.rd(address) & ~mask)
    elif name == "TBR":
        s.test_bit(s.r[v["RB"]], v["N"])
    elif name in ("TB", "TBI"):
        s.test_bit(operand(s, v, mode), v["N"])
    elif name == "TSB":
        address = derived_address(s, v, mode)
        s.test_bit(s.rd(address), v["N"])
        s.wr(address, s.rd(address) | 0x8000 >> v["N"])
    elif name == "TVBR":
        s.test_bit(s.r[v["RB"]], s.r[v["RA"]] & 15)
    elif name in ("SLL", "SRL", "SRA", "SLC"):
        n, value = v["N-1"] + 1, s.r[v["RB"]]
        result = {"SLL": shift_left(value, n, 16), "SRL": value >> n,
                  "SRA": shift_right_arithmetic(value, n, 16), "SLC": rotate_left(value, n, 16)}[name]
        s.r[v["RB"]] = result
        s.cs(result, 16)
    elif name in ("DSLL", "DSRL", "DSRA", "DSLC"):
        n, value = v["N-1"] + 1, s.get(v["RB"], 2)
        result = {"DSLL": shift_left(value, n, 32), "DSRL": value >> n,
                  "DSRA": shift_right_arithmetic(value, n, 32), "DSLC": rotate_left(value, n, 32)}[name]
        s.put(v["RB"], 2, result)
        s.cs(result, 32)
    elif name in ("SLR", "SAR", "SCR", "DSLR", "DSAR", "DSCR"):
        words = 2 if name[0] == "D" else 1
        kind = {"L": "logical", "A": "arithmetic", "C": "cyclic"}[name[-2]]
        shift_by_register(s, v, words, kind)
    elif name == "XBR":
        s.r[v["RA"]] = rotate_left(s.r[v["RA"]], 8, 16)
        s.cs(s.r[v["RA"]], 16)
    elif name == "XWR":
        s.r[v["RA"]], s.r[v["RB"]] = s.r[v["RB"]], s.r[v["RA"]]
        s.cs(s.r[v["RA"]], 16)
    elif name in FLOAT_OPS:
        extended = name.startswith("EF")
        words = 3 if extended else 2
        reg = accumulator(v, mode, True)
        op = FLOAT_OPS[name] + ("48" if extended else "32")
        result = stub(op, [s.get(reg, words), operand(s, v, mode, words)], 2 * words)
        s.put(reg, words, result)
        s.cs(result, 16 * words)
    elif name in FLOAT_COMPARES:
        extended = name.startswith("EF")
        words = 3 if extended else 2
        reg = accumulator(v, mode, True)
        op = "fcmp48" if extended else "fcmp32"
        result = stub(op, [s.get(reg, words), operand(s, v, mode, words)], 1)
        s.compare(signed(result, 8), 0)
    elif name in ("FABS", "FNEG"):
        result = stub("fabs32" if name == "FABS" else "fneg32", [s.get(v["RB"], 2)], 4)
        s.put(v["RA"], 2, result)
        s.cs(result, 32)
    elif name == "FIX":
        result = stub("fix32", [s.get(v["RB"], 2)], 2)
        s.r[v["RA"]] = result
        s.cs(result, 16)
    elif name == "FLT":
        result = stub("flt32", [s.r[v["RB"]]], 4)
        s.put(v["RA"], 2, result)
        s.cs(result, 32)
    elif name == "EFIX":
        result = stub("fix48", [s.get(v["RB"], 3)], 4)
        s.put(v["RA"], 2, result)
        s.cs(result, 32)
    elif name == "EFLT":
        result = stub("flt48", [s.get(v["RB"], 2)], 6)
        s.put(v["RA"], 3, result)
        s.cs(result, 48)
    elif name == "XIO":
        s.r[v["RA"]] = stub("xio", [s.r[v["RA"]], operand(s, v, "IMX")], 2)
    elif name in ("VIO", "BIF", "BEX", "NOP", "BPT"):
        pass  # no architectural effect the module models
    elif name == "BR":
        s.next = relative(s, v)
    elif name in BRANCHES:
        if BRANCHES[name](s.p << 2 | s.z << 1 | s.n):
            s.next = relative(s, v)
    elif name == "JC":
        conditional_jump(s, v, False)
    elif name == "JCI":
        conditional_jump(s, v, True)
    elif name == "JS":
        target = derived_address(s, v, "DX")
        s.r[v["RA"]] = s.next
        s.next = target
    elif name == "SOJ":
        target = derived_address(s, v, "DX")
        s.r[v["RA"]] = (s.r[v["RA"]] - 1) & M16
        s.cs(s.r[v["RA"]], 16)
        if s.r[v["RA"]]:
            s.next = target
    elif name == "SJS":
        target = derived_address(s, v, "DX")
        s.r[v["RA"]] = (s.r[v["RA"]] - 1) & M16
        s.wr(s.r[v["RA"]], s.next)
        s.next = target
    elif name == "URS":
        s.next = s.rd(s.r[v["RA"]])
        s.r[v["RA"]] = (s.r[v["RA"]] + 1) & M16
    elif name in ("LST", "LSTI"):
        address = derived_address(s, v, mode)
        s.mk = s.rd(address)
        s.sw = s.rd(address + 1)
        s.next = s.rd(address + 2)
        s.c, s.p, s.z, s.n = (s.sw >> 15) & 1, (s.sw >> 14) & 1, (s.sw >> 13) & 1, (s.sw >> 12) & 1
    else:
        raise ValueError(f"no model for {name}")


def normalize_field(field):
    """Give the fields whose names vary between format boxes one name."""
    return {"LABEL": "ADDR", "DATA": "ADDR", "CMD": "ADDR", "OPEX": "BYTE"}.get(field, field)


def draw(rng, instruction):
    """Pick random values for the free fields, then encode. Returns (words, values)."""
    values = {}
    encoded = bits = 0
    for field, width, literal in instruction.layout:
        if literal is not None:
            value = literal
        else:
            if width == 16 and rng.random() < 0.3:
                value = rng.choice(INTERESTING)
            else:
                value = rng.randrange(1 << width)
            values[normalize_field(field)] = value
        encoded = encoded << width | value
        bits += width
    if bits == 32:
        return [encoded >> 16, encoded & M16], values
    return [encoded], values


def effective_mode(instruction):
    """Direct and indexed forms behave alike, as do the two immediate-long boxes."""
    mode = instruction.mode
    return {"S": "R"}.get(mode, mode)


def format_memory(memory):
    return ";".join(f"{a:x}={memory[a]:x}" for a in sorted(memory)) or "-"


def format_state(s):
    flags = s.c << 3 | s.p << 2 | s.z << 1 | s.n
    return f"{','.join(f'{r:x}' for r in s.r)}\t{flags:x}\t{s.mk:x}\t{s.sw:x}"


def vector(rng, name, instruction):
    words, values = draw(rng, instruction)
    s = State(rng, words)
    if name == "MOV":
        s.r[(values["RA"] + 1) & 15] = rng.randrange(5)  # keep the copy short
    # Random values almost never land on these limits, where the behavior changes.
    elif name in ("SLR", "SAR", "SCR", "DSLR", "DSAR", "DSCR") and rng.random() < 0.5:
        limit = 32 if name[0] == "D" else 16
        s.r[values["RB"]] = rng.choice((-limit - 1, -limit, -limit + 1, limit - 1, limit, limit + 1)) & M16
    elif name in ("ABS", "NEG") and rng.random() < 0.25:
        s.r[values["RB"]] = 0x8000
    elif name in ("DABS", "DNEG") and rng.random() < 0.25:
        s.put(values["RB"], 2, 0x80000000)
    before = format_state(s)
    execute(s, name, values, effective_mode(instruction))
    # Guard words beside each write catch writes to the wrong size or address.
    for address in list(s.written):
        for neighbor in (address - 1, address + 1):
            neighbor &= M16
            if neighbor not in s.mem and neighbor not in s.instruction:
                s.mem[neighbor] = s.initial[neighbor] = s.value()
    code = "".join(f"{w:04x}" for w in words)
    return (f"{name}\t{code}\t{before}\t{format_memory(s.initial)}\t"
            f"{s.next:x}\t{format_state(s)}\t{format_memory(s.mem)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--count", type=int, default=300, help="vectors per mnemonic")
    parser.add_argument("--seed", type=int, default=1750)
    args = parser.parse_args()
    rng = random.Random(args.seed)
    for name, instruction in sorted(validate_output.load_reference().items()):
        made = 0
        attempts = 0
        while made < args.count:
            attempts += 1
            if attempts > args.count * 200:
                raise SystemExit(f"{name}: too many rejected vectors")
            try:
                print(vector(rng, name, instruction))
                made += 1
            except Reject:
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
