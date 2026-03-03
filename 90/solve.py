#!/usr/bin/env python3

from pathlib import Path


TOKENS = [
    ("<>", "0"),
    ("><", "X"),
    ("LL", "F"),
    ("]", "U"),
    ("Z", "N"),
    ("{", "{"),
    (">-", "Y"),
    ("()", "O"),
    ("]", "U"),
    ("|", "_"),
    ("_V_", "K"),
    ("Z", "N"),
    ("<>", "0"),
    ("3|", "W"),
    ("¯¯", "7"),
    ("[--", "T"),
    ("V\\|", "S"),
    ("W", "_"),
    ("_", "E"),
    ("+", "4"),
    ("[/]", "S"),
    (">-", "Y"),
    ("}", "}"),
]


def main() -> None:
    cipher = Path(__file__).with_name("cipher.txt").read_text(encoding="utf-8").strip()
    rebuilt = "".join(token for token, _ in TOKENS)
    plaintext = "".join(char for _, char in TOKENS)

    if rebuilt != cipher:
        raise SystemExit("tokenization does not match cipher.txt")

    print(plaintext)


if __name__ == "__main__":
    main()
