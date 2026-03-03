# Back in the 90's

## Files

- `cipher.txt`

## Solve

The challenge title is the clue: the text is meant to be read as a 90-degree rotation.

The ciphertext is an `LSPK90 Clockwise` string, where each plaintext character is represented by a small ASCII-art fragment that looks correct once you mentally rotate it.

Useful tells:

- `>-` decodes to `Y`
- `[/]` decodes to `S`
- `<>` decodes to `0`
- `><` decodes to `X`

One valid segmentation of the ciphertext is:

```python
["<>", "><", "LL", "]", "Z", "{", ">-", "()", "]", "|", "_V_", "Z", "<>", "3|", "¯¯", "[--", "V\\|", "W", "_", "+", "[/]", ">-", "}"]
```

Reading those groups as LSPK90 glyphs gives:

```python
["0", "X", "F", "U", "N", "{", "Y", "O", "U", "_", "K", "N", "0", "W", "7", "T", "S", "_", "E", "4", "S", "Y", "}"]
```

## Flag

```text
0XFUN{YOU_KN0W7TS_E4SY}
```

## Reference

- https://www.dcode.fr/lspk90-cw-leet-speak-90-degrees-clockwise
