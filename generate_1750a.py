#!/usr/bin/env python3
"""Generate every valid MIL-STD-1750A instruction encoding as disassembly text.

Output is the input format of the Ghidra Processor Module Generator
(https://github.com/oberoisecurity/ghidra-processor-module-generator):

    0x8100     LR R0,R0
    0x80120034 L R1,0x0034,R2

Column one is the big-endian hex encoding, column two the mnemonic, column
three the operands. Field layouts come from section 5 of MIL-STD-1750A.
"""
import argparse
import os
import sys

# Operand layouts. "16" fields are the second instruction word.
RA_RB = "RA,RB"
N_RB = "N,RB"  # bit number, encoded as-is
RB_N1 = "RB,N1"  # shift count 1..16, encoded as N-1
RA_N1 = "RA,N1"  # short immediate 1..16, encoded as N-1
ICR = "ICR"  # 8-bit IC-relative displacement
BEX_N = "BEX_N"  # 77 0 N
RA_ONLY = "RA"  # op RA 0
OP_EX = "OP_EX"  # BIF 8-bit opcode extension
RA_16 = "RA,16"  # RA,ADDR[,RX]
N_16 = "N,16"  # N,ADDR[,RX], N encoded as-is
N1_16 = "N1,16"  # N,ADDR[,RX], N is 1..16 encoded as N-1
C_16 = "C,16"  # condition code,LABEL[,RX]
ADDR_16 = "16"  # op 0 RX: ADDR[,RX]


def _table(layout, entries):
    return {opcode: (mnemonic, layout) for mnemonic, opcode in entries}


# Primary opcodes whose whole high byte selects one mnemonic.
OPCODES = {
    **_table(RA_RB, [
        ("SVBR", 0x5A), ("RVBR", 0x5C), ("TVBR", 0x5E),
        ("SLR", 0x6A), ("SAR", 0x6B), ("SCR", 0x6C),
        ("DSLR", 0x6D), ("DSAR", 0x6E), ("DSCR", 0x6F),
        ("LR", 0x81), ("DLR", 0x87), ("POPM", 0x8F),
        ("MOV", 0x93), ("PSHM", 0x9F),
        ("AR", 0xA1), ("ABS", 0xA4), ("DABS", 0xA5), ("DAR", 0xA7),
        ("FAR", 0xA9), ("EFAR", 0xAB), ("FABS", 0xAC),
        ("SR", 0xB1), ("NEG", 0xB4), ("DNEG", 0xB5), ("DSR", 0xB7),
        ("FSR", 0xB9), ("EFSR", 0xBB), ("FNEG", 0xBC),
        ("MSR", 0xC1), ("MR", 0xC5), ("DMR", 0xC7), ("FMR", 0xC9), ("EFMR", 0xCB),
        ("DVR", 0xD1), ("DR", 0xD5), ("DDR", 0xD7), ("FDR", 0xD9), ("EFDR", 0xDB),
        ("ORR", 0xE1), ("ANDR", 0xE3), ("XORR", 0xE5), ("NR", 0xE7),
        ("FIX", 0xE8), ("FLT", 0xE9), ("EFIX", 0xEA), ("EFLT", 0xEB), ("XWR", 0xED),
        ("CR", 0xF1), ("DCR", 0xF7), ("FCR", 0xF9), ("EFCR", 0xFB),
    ]),
    **_table(N_RB, [("SBR", 0x51), ("RBR", 0x54), ("TBR", 0x57)]),
    **_table(RB_N1, [
        ("SLL", 0x60), ("SRL", 0x61), ("SRA", 0x62), ("SLC", 0x63),
        ("DSLL", 0x65), ("DSRL", 0x66), ("DSRA", 0x67), ("DSLC", 0x68),
    ]),
    **_table(RA_N1, [
        ("LISP", 0x82), ("LISN", 0x83), ("AISP", 0xA2), ("SISP", 0xB2),
        ("MISP", 0xC2), ("MISN", 0xC3), ("DISP", 0xD2), ("DISN", 0xD3),
        ("CISP", 0xF2), ("CISN", 0xF3),
    ]),
    **_table(ICR, [
        ("BR", 0x74), ("BEZ", 0x75), ("BLT", 0x76), ("BLE", 0x78),
        ("BGT", 0x79), ("BNZ", 0x7A), ("BGE", 0x7B),
    ]),
    **_table(BEX_N, [("BEX", 0x77)]),
    **_table(RA_ONLY, [("URS", 0x7F), ("XBR", 0xEC)]),
    **_table(OP_EX, [("BIF", 0x4F)]),
    **_table(RA_16, [
        ("XIO", 0x48), ("VIO", 0x49),
        ("JS", 0x72), ("SOJ", 0x73), ("SJS", 0x7E),
        ("L", 0x80), ("LI", 0x84), ("LIM", 0x85), ("DL", 0x86), ("DLI", 0x88),
        ("EFL", 0x8A), ("LUB", 0x8B), ("LLB", 0x8C), ("LUBI", 0x8D), ("LLBI", 0x8E),
        ("ST", 0x90), ("STI", 0x94), ("DST", 0x96), ("SRM", 0x97), ("DSTI", 0x98),
        ("EFST", 0x9A), ("STUB", 0x9B), ("STLB", 0x9C), ("SUBI", 0x9D), ("SLBI", 0x9E),
        ("A", 0xA0), ("DA", 0xA6), ("FA", 0xA8), ("EFA", 0xAA),
        ("S", 0xB0), ("DS", 0xB6), ("FS", 0xB8), ("EFS", 0xBA),
        ("MS", 0xC0), ("M", 0xC4), ("DM", 0xC6), ("FM", 0xC8), ("EFM", 0xCA),
        ("DV", 0xD0), ("D", 0xD4), ("DD", 0xD6), ("FD", 0xD8), ("EFD", 0xDA),
        ("OR", 0xE0), ("AND", 0xE2), ("XOR", 0xE4), ("N", 0xE6),
        ("C", 0xF0), ("CBL", 0xF4), ("DC", 0xF6), ("FC", 0xF8), ("EFC", 0xFA),
    ]),
    **_table(N_16, [
        ("SB", 0x50), ("SBI", 0x52), ("RB", 0x53), ("RBI", 0x55),
        ("TB", 0x56), ("TBI", 0x58), ("TSB", 0x59),
        ("LM", 0x89), ("STC", 0x91), ("STCI", 0x92), ("STM", 0x99),
    ]),
    **_table(N1_16, [("INCM", 0xA3), ("DECM", 0xB3)]),
    **_table(C_16, [("JC", 0x70), ("JCI", 0x71)]),
    **_table(ADDR_16, [("LSTI", 0x7C), ("LST", 0x7D)]),
}

# Base relative: 6-bit opcode, 2-bit BR (R12..R15), 8-bit displacement.
BASE_RELATIVE = (
    "LB", "DLB", "STB", "DSTB", "AB", "SBB", "MB", "DB",
    "FAB", "FSB", "FMB", "FDB", "ORB", "ANDB", "CB", "FCB",
)
# Base relative indexed: 0x40 | BR, then a 4-bit opcode extension and RX.
BASE_RELATIVE_INDEXED = (
    "LBX", "DLBX", "STBX", "DSTX", "ABX", "SBBX", "MBX", "DBX",
    "FABX", "FSBX", "FMBX", "FDBX", "CBX", "FCBX", "ANDX", "ORBX",
)
# Immediate long with opcode extension: 4A RA ext DATA.
IMMEDIATE_EXTENDED = {
    0x1: "AIM", 0x2: "SIM", 0x3: "MIM", 0x4: "MSIM", 0x5: "DIM", 0x6: "DVIM",
    0x7: "ANDM", 0x8: "ORIM", 0x9: "XORM", 0xA: "CIM", 0xB: "NIM",
}

HEX16 = [f"{value:04X}" for value in range(0x10000)]


def _short(word, text):
    return f"0x{word:04X}     {text}\n"


def _long_form(first_word, prefix, index):
    """Emit all 65536 second-word values. RX=0 means no index in the standard."""
    head = f"0x{first_word:04X}"
    suffix = f",R{index}" if index else ""
    return "".join([f"{head}{data} {prefix}0x{data}{suffix}\n" for data in HEX16])


def _high_byte_chunks(opcode):
    if opcode < 0x40:
        mnemonic = BASE_RELATIVE[opcode >> 2]
        br = 12 + (opcode & 3)
        yield "".join(
            _short(opcode << 8 | dspl, f"{mnemonic} B{br},0x{dspl:02X}")
            for dspl in range(0x100)
        )
    elif opcode <= 0x43:
        br = 12 + (opcode & 3)
        for ext, mnemonic in enumerate(BASE_RELATIVE_INDEXED):
            for rx in range(16):
                suffix = f",R{rx}" if rx else ""
                yield _short(opcode << 8 | ext << 4 | rx, f"{mnemonic} B{br}{suffix}")
    elif opcode == 0x4A:
        for ra in range(16):
            for ext, mnemonic in IMMEDIATE_EXTENDED.items():
                word = opcode << 8 | ra << 4 | ext
                yield _long_form(word, f"{mnemonic} R{ra},", 0)
    elif opcode == 0xFF:
        yield _short(0xFF00, "NOP")
        yield _short(0xFFFF, "BPT")
    elif opcode in OPCODES:
        yield from _layout_chunks(opcode, *OPCODES[opcode])


def _layout_chunks(opcode, mnemonic, layout):
    base = opcode << 8
    if layout == ICR or layout == OP_EX:
        for value in range(0x100):
            yield _short(base | value, f"{mnemonic} 0x{value:02X}")
    elif layout == BEX_N:
        for n in range(16):
            yield _short(base | n, f"{mnemonic} 0x{n:X}")
    elif layout == RA_ONLY:
        for ra in range(16):
            yield _short(base | ra << 4, f"{mnemonic} R{ra}")
    elif layout == ADDR_16:
        for rx in range(16):
            yield _long_form(base | rx, f"{mnemonic} ", rx)
    else:
        for high in range(16):
            for low in range(16):
                word = base | high << 4 | low
                if layout == RA_RB:
                    yield _short(word, f"{mnemonic} R{high},R{low}")
                elif layout == N_RB:
                    yield _short(word, f"{mnemonic} 0x{high:X},R{low}")
                elif layout == RB_N1:
                    yield _short(word, f"{mnemonic} R{low},0x{high + 1:02X}")
                elif layout == RA_N1:
                    yield _short(word, f"{mnemonic} R{high},0x{low + 1:02X}")
                elif layout == RA_16:
                    yield _long_form(word, f"{mnemonic} R{high},", low)
                elif layout == N_16:
                    yield _long_form(word, f"{mnemonic} 0x{high:X},", low)
                elif layout == N1_16:
                    yield _long_form(word, f"{mnemonic} 0x{high + 1:02X},", low)
                elif layout == C_16:
                    yield _long_form(word, f"{mnemonic} 0x{high:X},", low)
                else:
                    raise ValueError(f"unknown layout {layout}")


def is_defined(opcode):
    return opcode < 0x44 or opcode in OPCODES or opcode in (0x4A, 0xFF)


def line_count(opcode):
    """Number of lines emitted for a high opcode byte, without generating them."""
    if opcode < 0x40:
        return 0x100
    if opcode <= 0x43:
        return 0x100
    if opcode == 0x4A:
        return 16 * len(IMMEDIATE_EXTENDED) * 0x10000
    if opcode == 0xFF:
        return 2
    if opcode not in OPCODES:
        return 0
    layout = OPCODES[opcode][1]
    if layout in (ICR, OP_EX):
        return 0x100
    if layout in (BEX_N, RA_ONLY):
        return 16
    if layout == ADDR_16:
        return 16 * 0x10000
    if layout in (RA_RB, N_RB, RB_N1, RA_N1):
        return 0x100
    return 0x100 * 0x10000


def write_opcodes(path, opcodes):
    """Write through a .part file so an interrupted run can't look complete."""
    partial = f"{path}.part"
    with open(partial, "w", encoding="ascii", newline="\n") as out:
        for opcode in opcodes:
            for chunk in _high_byte_chunks(opcode):
                out.write(chunk)
    os.replace(partial, path)


def parse_opcodes(text):
    opcodes = sorted({int(item, 16) for item in text.split(",")})
    undefined = [f"{opcode:02X}" for opcode in opcodes if not is_defined(opcode)]
    if undefined:
        raise argparse.ArgumentTypeError(f"undefined opcodes: {','.join(undefined)}")
    return opcodes


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("-o", "--output", default="1750a_instructions.txt",
                        help="single output file (default: %(default)s)")
    parser.add_argument("--split-dir",
                        help="write one file per high opcode byte instead, as the "
                             "generator's 4-byte ISA workflow requires")
    parser.add_argument("--opcodes", type=parse_opcodes,
                        help="comma-separated hex high bytes to emit, e.g. 81,A0")
    parser.add_argument("--count", action="store_true",
                        help="print the line count and exit")
    args = parser.parse_args(argv)

    opcodes = args.opcodes or [op for op in range(0x100) if is_defined(op)]
    total = sum(line_count(op) for op in opcodes)
    if args.count:
        print(total)
        return 0

    print(f"Writing {total:,} instructions", file=sys.stderr)
    if args.split_dir:
        os.makedirs(args.split_dir, exist_ok=True)
        for opcode in opcodes:
            write_opcodes(os.path.join(args.split_dir, f"op_{opcode:02X}.txt"), [opcode])
    else:
        write_opcodes(args.output, opcodes)
    return 0


if __name__ == "__main__":
    sys.exit(main())
