# phantom_pwn

## Summary

This is the real exploit for the `phantom` kernel module.

The local bundle is configured like a normal kernel pwn challenge:

- `kaslr`
- `smep`
- `smap`
- unprivileged shell as uid `1000`

So the solve avoids kernel ROP entirely. It uses a data-only page-table attack to overwrite
`modprobe_path`, then triggers the kernel to copy `/flag` into `/tmp/flag`.

## Bug

The `phantom` device exposes two ioctls:

- `CMD_ALLOC`
- `CMD_FREE`

From the module logic:

1. `CMD_ALLOC` allocates a small kernel state object and one physical page.
2. The device `mmap` handler maps that page into userspace with `remap_pfn_range`.
3. `CMD_FREE` frees the page, but the userspace mapping stays valid and the kernel state object
   still exists.

That leaves a stale userspace mapping to a freed physical page: a classic UAF on page-backed memory.

## Exploit Plan

1. Open `/dev/phantom`, call `CMD_ALLOC`, and `mmap` the page.
2. Call `CMD_FREE` so the backing page returns to the page allocator, while the userspace mapping
   still points to it.
3. Map a 512MB region aligned inside one PUD and touch an address inside it to force creation of a
   PMD page.
4. Hope the freed `phantom` page gets recycled as that PMD page. The stale userspace mapping then
   becomes a writeable view of the PMD entries.
5. Fill the PMD page with 2MB hugepage entries that map physical memory into userspace.
6. Read `/proc/sys/kernel/modprobe` to learn the current string, then scan the physical mapping for
   that buffer and overwrite it with `/tmp/x`.
7. Write `/tmp/x` as a helper script that copies `/flag` to `/tmp/flag`, then execute a dummy file
   with invalid format to trigger the kernel modprobe path.
8. Read `/tmp/flag`.

## Why This Works

- `SMEP` and `SMAP` do not matter because the exploit never pivots execution into userspace.
- `KASLR` does not need to be defeated with symbol leaks because the exploit scans physical memory
  for the existing `modprobe_path` string instead of calculating its address directly.
- The stale mapping is powerful enough because page tables are just memory. Once the freed page is
  reused as a PMD page, userspace can rewrite those PMD entries through the dangling mapping.

## Files

- `exploit.c` is the libc-free static payload that runs inside the initramfs shell.
- `solve.py` uploads/builds that payload and retries fresh remote instances until the page reuse
  race lands.

## Local Caveat

The shipped initramfs contains:

```text
0xfun{fake_flag_for_testing}
```

in [`flag`](/home/shadowbyte/Downloads/0xfun/pwn/phantom_pwn/phantom_FILES/initramfs_root/flag), so
the real remote flag is not recoverable from the local archive alone. The writeup and solver here
document the real exploit path, not a local static flag leak.
