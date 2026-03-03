# Warden

## Summary

`warden` is not the vulnerable target by itself. It is a seccomp-user-notify supervisor that:

- runs one child command as uid/gid `1000`
- allows exactly the initial `execve` used to launch the jailed program
- intercepts `open/openat`, `mmap/mprotect`, and `exec*`
- blocks networking, ptrace, seccomp, process_vm, `memfd_create`, `userfaultfd`, and `mount`

The real bug chain is:

1. escape the Python AST jail in `jail.py`
2. use that code execution to call `os.open`
3. bypass the Warden's path filter with relative `openat` paths from a `dirfd` opened on `/`

## Bug 1: Python Jail Escape

`jail.py` tries to block dangerous Python features by:

- banning `import`
- banning direct attribute syntax for names starting with `_`
- banning string literals containing `__`
- replacing `__builtins__` with a restricted dictionary

That is not enough because all of those checks are syntax-based.

The payload constructs `"__"` dynamically:

```python
d='_'*2
```

Then it uses `getattr()` instead of dotted attribute syntax:

```python
subs=getattr(object,d+'subclasses'+d)()
```

From there it walks class initializers until it finds a function with a real `__globals__`,
pulls out the actual `__builtins__`, and recovers the real import primitive:

```python
rb = g['__builtins__']
imp = rb['__import__']
os = imp('os')
```

At that point the sandboxed Python code has the real `os` module, which is enough to open files,
list directories, stat entries, and read candidate flag paths.

## Bug 2: Naive Path Filter

The Warden's `openat` handler only reads the pathname string from the traced process and checks
whether it starts with one of these blocked prefixes:

- `/flag`
- `/root`
- `/etc/shadow`
- `/etc/gshadow`
- `/proc/self/mem`
- `/proc/self/exe`
- `/proc/self/root`

It never resolves `dirfd + relative path` into a canonical absolute path.

So this is blocked:

```python
os.open('/flag', os.O_RDONLY)
```

but this is allowed:

```python
root = os.open('/', os.O_RDONLY)
fd = os.open('flag', os.O_RDONLY, dir_fd=root)
```

The supervisor only sees the string `"flag"`, which does not start with `"/flag"`, even though the
kernel resolves it to the same file.

The shipped payload abuses exactly that idea:

- open `/` as a directory fd
- try common relative names like `flag`, `root/flag`, `home/ctf/flag`, `tmp/flag`
- fall back to a shallow recursive directory scan using `os.listdir`, `os.stat`, and `os.open`

## Exploit Flow

1. Submit the jail payload in [`solve.py`](/home/shadowbyte/Downloads/0xfun/crypto/pwn/Warden/solve.py).
2. The payload escapes the AST restrictions and imports `os`.
3. It opens `/` once, then uses relative `openat` paths to bypass the Warden's prefix check.
4. It reads likely flag locations and prints the first buffer containing `0xfun{`.
5. [`send.py`](/home/shadowbyte/Downloads/0xfun/crypto/pwn/Warden/send.py) is a thin remote wrapper
   that sends the payload, shuts down the write side to signal EOF, and prints the server output.

## Local Verification

I verified the jail-escape payload locally against `jail.py` by planting a fake `/tmp/flag`:

```bash
printf '0xfun{local_test_flag}\n' > /tmp/flag
python3 jail.py < solve.py
```

That prints:

```text
0xfun{local_test_flag}
```

I could not fully validate the native `warden` wrapper end to end inside this sandbox because its
single allowed `execve` collides with the outer environment's restrictions here, so the checked-in
`output.txt` records the verified `jail.py` path instead of a fake full remote transcript.
