# meowel

## Files

- `output.txt`
- `solve.py`

## Solve

This is not a generic hard ECDLP instance.

For the curve:

```text
E: y^2 = x^3 + 19 over F_p
```

the group order is:

```text
#E(F_p) = p
```

So the curve is anomalous, and Smart/Semaev-style anomalous-curve attacks
apply.

## Attack

Instead of using `p`-adic lifts directly, the checked-in solver uses the
augmented-addition trick.

Define an augmented point as:

```text
[P, λ]
```

and when adding two augmented points, also accumulate the line slope used by
the elliptic-curve addition formula:

```text
[P1, a1] (+) [P2, a2] = [P1 + P2, a1 + a2 + slope(P1, P2)]
```

On an anomalous curve, multiplying by `p` sends every group element to the point
at infinity, but the accumulated slope value still carries the discrete-log
information.

If:

```text
p * [P, 0] = [O, alpha]
p * [Q, 0] = [O, beta]
```

and `Q = dP`, then:

```text
d = beta * alpha^{-1} mod p
```

After recovering `d`, the challenge key derivation is direct:

```python
k = long_to_bytes(d)
aes_key = sha256(k + b"MeOwl::AES").digest()[:16]
des_key = sha256(k + b"MeOwl::DES").digest()[:8]
```

Then decrypt:

1. DES-CBC outer layer
2. AES-CBC inner layer

## Flag

```text
0xfun{n0n_c4n0n1c4l_l1f7s_r_c00l}
```
