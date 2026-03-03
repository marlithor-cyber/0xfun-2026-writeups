# BitStorm

## Files

- `output.txt`
- `solve.py`

## Solve

The bug is that the custom RNG is completely linear over `GF(2)`.

In `chall.py`, every state update uses only:

- XOR
- left/right shifts
- bit rotations

All of those are linear bit operations, so every output bit is a linear combination of the original 2048 seed bits.

The flag content is padded to `256` bytes, converted to one big integer, then split into `32` words of `64` bits:

```python
content_bytes = content.encode().ljust(256, b"\0")
seed_int = int.from_bytes(content_bytes, "big")
```

That means the unknown seed has exactly:

```text
32 * 64 = 2048 bits
```

The challenge gives `60` output words, so we get:

```text
60 * 64 = 3840 linear equations
```

That is more than enough to recover the whole seed with Gaussian elimination over `GF(2)`.

## Attack

Model each initial seed bit as one symbolic variable.

For word `i` and bit `j`, assign variable:

```text
x_(i,j)
```

Then simulate the RNG symbolically:

- shifts just move bit positions
- rotations permute bit positions
- XOR combines masks with XOR

So instead of storing 64-bit integers, the solver stores 64 masks describing which seed bits affect each output bit.

For each observed output word:

1. advance the symbolic state
2. get the symbolic mask for each of the `64` output bits
3. append one linear equation per bit

Finally solve the `3840 x 2048` system over `GF(2)`, rebuild the original `256` seed bytes, strip the trailing zero padding, and wrap the result back into the flag format.

## Flag

```text
0xfun{L1n34r_4lg3br4_W1th_Z3_1s_Aw3s0m3}
```
