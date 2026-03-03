# 67 Revenge

## Summary

The challenge is a 16-slot heap note manager with `create`, `delete`, `read`, and `edit`.
The binary has full RELRO, stack canary, NX, and PIE, so the intended route is a heap exploit.

The bug is in `edit_note`: it reads up to the stored size, then unconditionally appends a trailing
NUL byte at `notes[idx][nread]`.

```c
ssize_t nread = read(0, notes[idx], sizes[idx]);
if (nread >= 0) {
    notes[idx][nread] = '\0';
}
```

If `read()` returns exactly `sizes[idx]`, that trailing NUL lands one byte past the chunk.
For a large heap chunk, that clears the low byte of the next chunk's size field and gives a classic
off-by-null primitive.

## Exploit Plan

1. Leak a heap pointer from a largebin chunk by reallocating it and reading the leftover
   `fd_nextsize`/`bk_nextsize` pointers.
2. Build a fake chunk inside chunk `A`, then use the off-by-null on chunk `B.size` to trigger
   House of Einherjar style backward consolidation into the fake chunk.
3. Reallocate from the overlapped region and prepare two tcache chunks that will later be poisoned.
4. Leak libc from the unsorted bin `bk` pointer.
5. Tcache-poison a `0x400` chunk to `environ - 0x18`, then read back the saved stack pointer.
6. Tcache-poison a `0x3e0` chunk to the saved `rbp` / return address area on the stack.
7. Write an ORW ROP chain that opens `flag.txt`, reads it, writes it to stdout, then exits.

## Why ORW

The binary installs seccomp before entering the menu. The shipped filter allows the syscalls needed
for file I/O (`read`, `write`, `open`, `openat`, `close`, `fstat`, `mmap`, `mprotect`, `brk`,
`exit`, `exit_group`) but not `execve`, so a shell is unnecessary and unreliable anyway.

## Notes

- The checked-in exploit is calibrated for the provided glibc 2.42 bundle.
- `UNSORTED_BK_OFF`, `HDR_A_FROM_LARGEBIN_LEAK`, and `RET_FROM_ENVIRON` are runtime-specific
  offsets recovered from the shipped files.
- `solve.py` expects `chall`, `libc.so.6`, and `ld-linux-x86-64.so.2` next to it when run locally.

## Local Verification

Running the exploit against the bundled files succeeds and prints the local placeholder flag:

```text
0xfun{LOCAL_TEST_FLAG}
```

That local flag comes from the provided `flag.txt`, so it only proves the exploit chain against the
shipped binary and libc. The same script can be pointed at the remote service with:

```bash
python3 solve.py REMOTE=1 HOST=chall.0xfun.org PORT=42443
```
