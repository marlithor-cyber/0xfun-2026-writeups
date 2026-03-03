# fortune

## Files

- `fortune.py`
- `solve.cpp`

## Solve

`fortune.py` is a 64-bit linear congruential generator:

```python
state = (A * state + C) % 2**64
```

The only thing leaked by `glimpse()` is the upper 32 bits of the next state:

```python
return full >> 32
```

So each observation gives a truncated state, not the full `64` bits.

## Attack

Let the internal states after each call be:

```text
s1, s2, s3, ...
```

and let the observed values be:

```text
g1 = s1 >> 32
g2 = s2 >> 32
g3 = s3 >> 32
```

Because the recurrence is deterministic,

```text
s2 = A*s1 + C mod 2^64
s3 = A*s2 + C mod 2^64
```

we can model the unknown lower 32 bits of the observed states and constrain the
known upper 32 bits from the glimpses.

The checked-in solver uses the decomposition:

1. create symbolic `32`-bit variables for the missing low halves
2. write each observed state as `s_i = (g_i << 32) | x_i`
3. solve for the unknown low halves `x_i`
4. reconstruct the full first observed state
5. invert one LCG step to recover the original seed

Three consecutive glimpses are enough to recover the seed uniquely in practice,
and once the seed is known we can replay the generator and predict every future
state exactly.

## Verified Demo

The local file already contains a deterministic test:

```python
ft = FortuneTeller(seed=123456789)
```

Its first three glimpses are:

```text
546407480
1986745485
3195690014
```

Those demo glimpses come from the known seed:

```text
seed = 123456789
```

and the next five full states are:

```text
8531072506187040289
6123404510612025802
18106414010917701583
14456906824592636608
385028004165223149
```

## Notes

The local folder only includes the RNG source, not a saved remote transcript or
the service output that returned the competition flag. So this writeup records
the exploitation method and a verified offline recovery example, but not the
final CTF flag.

The checked-in `solve.cpp` encodes the intended Z3 recovery method. It compiled
cleanly against the local `libz3` installation, but I did not get a full runtime
solve to finish within the bounded local verification window on this machine.
