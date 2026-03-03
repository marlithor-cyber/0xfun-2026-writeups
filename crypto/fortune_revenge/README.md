# fortune_revenge

## Files

- `fortune_revenge.py`
- `solve.py`

## Solve

This challenge reuses the same 64-bit LCG from `fortune`:

```python
state = (A * state + C) % 2**64
```

and still leaks only the upper 32 bits after a `next()` call:

```python
return full >> 32
```

The difference is the extra jump inserted between the leaks:

```python
state = (A_JUMP * state + C_JUMP) % 2**64
```

with:

```python
JUMP = 100000
A_JUMP = pow(A, JUMP, 2**64)
C_JUMP = 8391006422427229792
```

So the three observed values correspond to:

```text
s1 = next(seed)
s2 = next(jump(s1))
s3 = next(jump(s2))
```

## Attack

The jump does not add any non-linearity. It is still just another affine map
modulo `2^64`, so we can encode the whole chain directly in Z3:

1. create a 64-bit symbolic `seed`
2. apply one `next()` and constrain its high 32 bits to `g1`
3. apply `jump()`, then `next()`, and constrain to `g2`
4. apply `jump()`, then `next()`, and constrain to `g3`
5. ask Z3 for the seed

After recovering the seed, replay the generator to the exact post-`g3` state and
predict the next five outputs required by the service.

That is exactly what the checked-in solver does.

## Recovery Flow

The solver uses these transitions:

```python
s1 = nxt(seed)
t1 = jmp(s1)
s2 = nxt(t1)
t2 = jmp(s2)
s3 = nxt(t2)
```

with the constraints:

```python
s1 >> 32 == g1
s2 >> 32 == g2
s3 >> 32 == g3
```

Once `seed` is known, it replays:

```python
s1 = nxt(seed)
s1 = jmp(s1)
s2 = nxt(s1)
s2 = jmp(s2)
s3 = nxt(s2)
```

and then predicts the next five full outputs.

## Notes

The local folder only contains the source and the remote solver, not a saved
challenge transcript or the final returned flag. So this writeup documents the
method and includes the actual exploit script, but does not record the flag.

The checked-in solver depends on Python `z3-solver`. That module is not
installed in the local Python environment here, so I did not run the full remote
solve locally during verification.
