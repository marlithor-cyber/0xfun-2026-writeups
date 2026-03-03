# phantom

## Summary

This one did not need a kernel exploit at all.

The bundle ships the full boot environment:

- `bzImage`
- `initramfs.cpio.gz`
- `phantom.ko`
- `run.sh`

If you unpack the initramfs and read `init`, the flag is hardcoded there:

```sh
echo "0xfun{phys1c4l_m3m0ry_c0rrupt10n_1s_g0d_m0d3}" > /flag
```

So the fastest solve is just: extract `initramfs.cpio.gz`, inspect `init`, and copy the flag.

## Quick Path

```bash
gzip -dc initramfs.cpio.gz | strings | grep '0xfun{'
```

That prints:

```text
echo "0xfun{phys1c4l_m3m0ry_c0rrupt10n_1s_g0d_m0d3}" > /flag
```

## Notes

- `run.sh` boots a QEMU kernel with `kaslr`, `smep`, and `smap`.
- `interface.h` exposes two ioctls, `CMD_ALLOC` and `CMD_FREE`.
- `phantom.ko` looks like the intended kernel attack surface, but it is unnecessary once the
  initramfs already contains the real flag.

## Flag

```text
0xfun{phys1c4l_m3m0ry_c0rrupt10n_1s_g0d_m0d3}
```
