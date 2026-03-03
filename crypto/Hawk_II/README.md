# Hawk_II

## Files

- `output.txt`
- `solve.py`

## Solve

This challenge is supposed to leak only partial information about the secret
key:

- `pk`
- `leak_data`

But the real bug is much simpler. The handout also prints the full secret key:

```python
print("sk = ", sk)
```

The AES key is derived as:

```python
key = sha256(str(sk).encode()).digest()
```

So there is no need to recover anything from the public key or the split leaks.
We can just:

1. extract the exact `sk` string from `output.txt`
2. hash it with SHA-256
3. decrypt the provided AES-CBC ciphertext

Because the challenge already gives the same printed `str(sk)` representation
that was hashed during encryption, this works directly.

## Flag

```text
0xfun{tOO_LLL_256_B_kkkkKZ_t4e_f14g_F14g}
```
