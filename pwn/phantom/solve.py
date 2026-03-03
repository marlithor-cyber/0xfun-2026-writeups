#!/usr/bin/env python3
import argparse
import gzip
import re
from pathlib import Path


def main():
    ap = argparse.ArgumentParser(description="Extract the phantom flag from the shipped initramfs")
    ap.add_argument(
        "initramfs",
        nargs="?",
        default="/home/shadowbyte/Downloads/0xfun/pwn/phantom/phantom/initramfs.cpio.gz",
        help="path to initramfs.cpio.gz",
    )
    args = ap.parse_args()

    data = gzip.decompress(Path(args.initramfs).read_bytes())
    match = re.search(rb"0xfun\{[^}\n]+\}", data)
    if not match:
        raise SystemExit("flag not found")
    print(match.group().decode())


if __name__ == "__main__":
    main()
