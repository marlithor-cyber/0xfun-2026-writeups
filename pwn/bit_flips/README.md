# bit_flips

## Summary

The binary prints several useful leaks and then allows exactly three arbitrary single-bit flips:

- `&main` gives the PIE base.
- `&system` gives the libc base.
- `&address` leaks a stack slot inside `vuln`.
- `sbrk(NULL)` leaks the current program break.

At first glance three flips are not enough to do much, but the loop counter in `vuln` is itself on
the stack right next to the leaked `address` variable.

## Bug

`vuln` stores the loop counter as a signed `int` at `rbp-0x14` and the leaked `address` variable at
`rbp-0x10`. Since the program prints `&address`, we immediately know where the counter lives too:

- `counter = &address - 4`
- the sign bit lives at `&address - 1`, bit `7`

If we flip that sign bit during the first iteration, the counter becomes a huge negative value.
After each call to `bit_flip()` the program increments it, but it will still satisfy `i <= 2` for a
very long time, so the “three flips” limit is gone.

## Exploit Plan

1. Flip the sign bit of the loop counter at `&address - 1`, bit `7`.
2. Use the `&system` leak to recover the libc base and compute `_IO_2_1_stdin_`.
3. Use the `sbrk(NULL)` leak to reconstruct the heap `FILE *` returned by `fopen("./commands")`.
   For the shipped setup, `f == sbrk(NULL) - 0x20cf0`.
4. Use repeated bit flips to change the global `f` pointer at `pie + 0x4050` from the commands
   file stream to libc `stdin`.
5. Flip bit `3` of the saved return address at `&address + 0x18` so the return target changes from
   `main+0x1422` to `cmd+1` at `0x142a`.
6. Flip the counter sign bit back once its low bits are already greater than `2`, so the loop exits.
7. When control returns into `cmd+1`, it now reads commands from our socket instead of `./commands`.
   Send `cat flag` and close stdin.

## Why `cmd+1`

`cmd` starts with `push rbp`. Returning straight to `cmd` would perturb the stack layout inherited
from the `vuln -> main` return path. Returning to `cmd+1` skips that `push` and lands on
`mov rbp, rsp`, which keeps the stack aligned for the later `system()` calls.

## Notes

- The shipped `solve.py` in the challenge folder only demonstrates the smaller trick of flipping the
  saved RIP to `cmd+1`. That reaches the hidden command runner, but with the bundled harmless
  `commands` file it only prints:

```text
Did you pwn me?
```

- The full exploit is to redirect the global `FILE *f` to `stdin` first, then return into `cmd+1`.

## Local Verification

Running the checked-in solver against the provided local files prints:

```text
0xfun{local_test_flag}
```

That confirms the exploit path end to end with the shipped binary, libc, and placeholder local flag.
Use `--dir` to point the solver at the extracted challenge files when running it from this repo.
