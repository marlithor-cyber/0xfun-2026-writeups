#!/usr/bin/env python3

from hashlib import sha256
from pathlib import Path

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
except Exception:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.Padding import unpad


def main() -> None:
    lines = Path(__file__).with_name("output.txt").read_text(encoding="utf-8").splitlines()

    iv_hex = lines[0].split('"')[1]
    enc_hex = lines[1].split('"')[1]
    sk_expr = lines[3].split("sk = ", 1)[1].strip()

    key = sha256(sk_expr.encode()).digest()
    pt = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv_hex)).decrypt(bytes.fromhex(enc_hex))
    print(unpad(pt, 16).decode())


if __name__ == "__main__":
    main()
