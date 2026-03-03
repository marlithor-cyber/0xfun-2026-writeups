#!/usr/bin/env python3

import re
from hashlib import sha256
from pathlib import Path

from Cryptodome.Cipher import AES, DES
from Cryptodome.Util.Padding import unpad
from Cryptodome.Util.number import long_to_bytes


def parse_output(text: str):
    p = int(re.search(r"p\s*=\s*(\d+)", text).group(1))
    a = int(re.search(r"a\s*=\s*(\d+)", text).group(1))
    b = int(re.search(r"b\s*=\s*(\d+)", text).group(1))
    px = int(re.search(r"Px\s*=\s*(\d+)", text).group(1))
    py = int(re.search(r"Py\s*=\s*(\d+)", text).group(1))
    qx = int(re.search(r"Qx\s*=\s*(\d+)", text).group(1))
    qy = int(re.search(r"Qy\s*=\s*(\d+)", text).group(1))
    ciphertext = re.search(r"ciphertext\s*=\s*([0-9a-f]+)", text).group(1)
    return p, a, b, (px, py), (qx, qy), bytes.fromhex(ciphertext)


def point_add(p: int, a: int, p1, p2):
    if p1 is None:
        return p2, 0
    if p2 is None:
        return p1, 0

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and (y1 + y2) % p == 0:
        return None, 0

    if p1 == p2:
        slope = ((3 * x1 * x1 + a) * pow((2 * y1) % p, -1, p)) % p
    else:
        slope = ((y2 - y1) * pow((x2 - x1) % p, -1, p)) % p

    x3 = (slope * slope - x1 - x2) % p
    y3 = (slope * (x1 - x3) - y1) % p
    return (x3, y3), slope


def augmented_add(p: int, a: int, left, right):
    p1, acc1 = left
    p2, acc2 = right
    p3, slope = point_add(p, a, p1, p2)
    return p3, (acc1 + acc2 + slope) % p


def augmented_mul(p: int, a: int, k: int, point):
    result = (None, 0)
    base = (point, 0)
    while k:
        if k & 1:
            result = augmented_add(p, a, result, base)
        base = augmented_add(p, a, base, base)
        k >>= 1
    return result


def scalar_mul(p: int, a: int, k: int, point):
    result = None
    base = point
    while k:
        if k & 1:
            result, _ = point_add(p, a, result, base)
        base, _ = point_add(p, a, base, base)
        k >>= 1
    return result


def main() -> None:
    text = Path(__file__).with_name("output.txt").read_text(encoding="utf-8")
    p, a, _b, p_point, q_point, ciphertext = parse_output(text)

    _, alpha = augmented_mul(p, a, p, p_point)
    _, beta = augmented_mul(p, a, p, q_point)
    d = (beta * pow(alpha, -1, p)) % p

    if scalar_mul(p, a, d, p_point) != q_point:
        raise SystemExit("recovered discrete log does not verify")

    k = long_to_bytes(d)
    aes_key = sha256(k + b"MeOwl::AES").digest()[:16]
    des_key = sha256(k + b"MeOwl::DES").digest()[:8]

    aes_iv = bytes.fromhex("7d0e47bb8d111b626f0e17be5a761a14")
    des_iv = bytes.fromhex("86fd0c44751700d4")

    inner = DES.new(des_key, DES.MODE_CBC, iv=des_iv).decrypt(ciphertext)
    plaintext = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv).decrypt(unpad(inner, 8))
    print(unpad(plaintext, 16).decode())


if __name__ == "__main__":
    main()
