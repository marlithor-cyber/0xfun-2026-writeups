#!/usr/bin/env python3
import re
import socket

from z3 import BitVec, BitVecVal, LShR, Solver, sat


HOST = "chall.0xfun.org"
PORT = 36880

MASK64 = (1 << 64) - 1
A = 2862933555777941757
C = 3037000493
JUMP = 100000
A_JUMP = pow(A, JUMP, 1 << 64)
C_JUMP = 8391006422427229792

USE_JUMPS_FOR_PREDICTION = False


def nxt_py(state: int) -> int:
    return (A * state + C) & MASK64


def jmp_py(state: int) -> int:
    return (A_JUMP * state + C_JUMP) & MASK64


def solve_seed_from_glimpses(g1: int, g2: int, g3: int) -> int:
    seed = BitVec("seed", 64)
    a64 = BitVecVal(A, 64)
    c64 = BitVecVal(C, 64)
    aj = BitVecVal(A_JUMP, 64)
    cj = BitVecVal(C_JUMP, 64)

    def nxt(x):
        return a64 * x + c64

    def jmp(x):
        return aj * x + cj

    solver = Solver()

    s1 = nxt(seed)
    solver.add(LShR(s1, 32) == BitVecVal(g1, 32))

    t1 = jmp(s1)
    s2 = nxt(t1)
    solver.add(LShR(s2, 32) == BitVecVal(g2, 32))

    t2 = jmp(s2)
    s3 = nxt(t2)
    solver.add(LShR(s3, 32) == BitVecVal(g3, 32))

    if solver.check() != sat:
        raise RuntimeError("no solution found")

    return solver.model()[seed].as_long()


def main() -> None:
    sock = socket.create_connection((HOST, PORT), timeout=10)
    io = sock.makefile("rwb", buffering=0)

    glimpses = []
    while True:
        line = io.readline()
        if not line:
            break

        text = line.decode(errors="ignore").strip()
        if re.fullmatch(r"\d+", text):
            glimpses.append(int(text))

        if b"Predict the next 5" in line and len(glimpses) >= 3:
            break

    g1, g2, g3 = glimpses[:3]
    seed = solve_seed_from_glimpses(g1, g2, g3)

    s1 = nxt_py(seed)
    s1 = jmp_py(s1)
    s2 = nxt_py(s1)
    s2 = jmp_py(s2)
    cur = nxt_py(s2)

    outputs = []
    for _ in range(5):
        if USE_JUMPS_FOR_PREDICTION:
            cur = jmp_py(cur)
        cur = nxt_py(cur)
        outputs.append(cur)

    io.write((" ".join(map(str, outputs)) + "\n").encode())
    response = io.read(4096)
    print(response.decode(errors="ignore"))


if __name__ == "__main__":
    main()
