#!/usr/bin/env python3

import re
from pathlib import Path


MASK64 = (1 << 64) - 1
N = 32 * 64

taps = [0, 1, 3, 7, 13, 22, 28, 31]
rots = [(i * 3) % 64 for i in range(32)]


def shl(word, k):
    if k <= 0:
        return word
    if k >= 64:
        return [0] * 64
    return [0] * k + word[: 64 - k]


def shr(word, k):
    if k <= 0:
        return word
    if k >= 64:
        return [0] * 64
    return word[k:] + [0] * k


def rotl(word, r):
    r %= 64
    if r == 0:
        return word
    return word[-r:] + word[:-r]


def rotr(word, r):
    r %= 64
    if r == 0:
        return word
    return word[r:] + word[:r]


def wxor(a, b):
    return [x ^ y for x, y in zip(a, b)]


def wxor3(a, b, c):
    return [x ^ y ^ z for x, y, z in zip(a, b, c)]


def rng_step(state):
    new_val = [0] * 64
    for i in taps:
        val = state[i]
        mixed = wxor3(val, shl(val, 11), shr(val, 7))
        mixed = rotl(mixed, rots[i])
        new_val = wxor(new_val, mixed)

    last = state[-1]
    new_val = wxor(new_val, wxor(shr(last, 13), shl(last, 5)))

    next_state = state[1:] + [new_val]

    out = [0] * 64
    for idx, word in enumerate(next_state):
        out = wxor(out, word if idx % 2 == 0 else rotr(word, 2))
    return next_state, out


def gauss_solve(rows, nvars):
    rows = rows[:]
    piv = [-1] * nvars
    row_idx = 0

    for col in range(nvars):
        bit = 1 << col
        pivot = -1
        for i in range(row_idx, len(rows)):
            if rows[i] & bit:
                pivot = i
                break
        if pivot == -1:
            continue

        if pivot != row_idx:
            rows[row_idx], rows[pivot] = rows[pivot], rows[row_idx]

        piv[col] = row_idx
        pivot_row = rows[row_idx]
        for i in range(row_idx + 1, len(rows)):
            if rows[i] & bit:
                rows[i] ^= pivot_row

        row_idx += 1
        if row_idx == len(rows):
            break

    rhs_bit = 1 << nvars
    for row in rows:
        if (row & ((1 << nvars) - 1)) == 0 and (row & rhs_bit):
            raise SystemExit("inconsistent system")

    sol = 0
    for col in range(nvars - 1, -1, -1):
        pivot_row = piv[col]
        if pivot_row == -1:
            continue

        row = rows[pivot_row]
        rhs = (row >> nvars) & 1
        higher = row & ~((1 << (col + 1)) - 1)
        rhs ^= (higher & sol).bit_count() & 1
        if rhs:
            sol |= 1 << col

    return sol


def main():
    output_path = Path(__file__).with_name("output.txt")
    outputs = list(map(int, re.findall(r"\d+", output_path.read_text())))
    if len(outputs) != 60:
        raise SystemExit(f"expected 60 outputs, got {len(outputs)}")

    state = []
    for word_index in range(32):
        bits = [0] * 64
        base = word_index * 64
        for bit_index in range(64):
            bits[bit_index] = 1 << (base + bit_index)
        state.append(bits)

    rows = []
    for out_word in outputs:
        state, out_masks = rng_step(state)
        for bit in range(64):
            rhs = (out_word >> bit) & 1
            rows.append(out_masks[bit] | (rhs << N))

    sol = gauss_solve(rows, N)

    words = [(sol >> (i * 64)) & MASK64 for i in range(32)]
    seed_bytes = b"".join(word.to_bytes(8, "big") for word in words)
    content = seed_bytes.rstrip(b"\x00").decode()

    print(f"0xfun{{{content}}}")


if __name__ == "__main__":
    main()
