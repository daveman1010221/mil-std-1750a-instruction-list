#!/usr/bin/env python3
"""Print every first instruction word the standard defines, one hex value per line."""
import itertools
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import validate_output


def first_words(instruction):
    """Expand the free fields of an instruction's first 16 bits."""
    parts = []
    bits = 0
    for field, width, literal in instruction.layout:
        if bits == 16:
            break
        values = [literal] if literal is not None else range(1 << width)
        parts.append((width, values))
        bits += width
    for choice in itertools.product(*(values for _, values in parts)):
        word = 0
        for (width, _), value in zip(parts, choice):
            word = word << width | value
        yield word


def main():
    words = set()
    for instruction in validate_output.load_reference().values():
        words.update(first_words(instruction))
    for word in sorted(words):
        print(f"{word:04X}")


if __name__ == "__main__":
    main()
