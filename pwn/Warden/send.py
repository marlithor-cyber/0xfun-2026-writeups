#!/usr/bin/env python3
import re
import socket
import sys


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else 'chall.0xfun.org'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 31450
    payload_path = sys.argv[3] if len(sys.argv) > 3 else 'solve.py'

    with open(payload_path, 'rb') as f:
        payload = f.read()
    if not payload.endswith(b"\n"):
        payload += b"\n"

    with socket.create_connection((host, port), timeout=10) as s:
        s.sendall(payload)
        s.shutdown(socket.SHUT_WR)

        out = bytearray()
        s.settimeout(10)
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            out += chunk

    sys.stdout.buffer.write(out)

    m = re.search(rb"0xfun\{[^}]+\}", out)
    if m:
        sys.stderr.write("\nFLAG: " + m.group(0).decode(errors='ignore') + "\n")

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
