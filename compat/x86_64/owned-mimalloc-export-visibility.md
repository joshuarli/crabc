# Owned mimalloc shared-export boundary

`libc/src/c_abi/x86_64/owned_mimalloc_hidden.list` is the exact 424-name
contract for bundled `libmimalloc-sys` 0.1.49/mimalloc v3 definitions that may
remain global in the selected static `libc.a` member but must be local in the
owned `libc.so`. It contains 172 names declared by the bundled upstream
`mimalloc/v3/include/mimalloc.h` and 252 names from its implementation surface.
The installed crabc headers declare none of them. This is a visibility decision
for the selected shared product; it does not claim that the upstream header is
part of crabc's installed C ABI.

`scripts/build_x86_64_owned_dynamic_sysroot.py` verifies the physical list,
its SHA-256 and its sorted 424-member roster, then materializes an `ld.lld`
version script with one `local:` rule per name. The option is passed only to the
owned shared-libc link. The static sysroot builder and its `libc.a` remain
unchanged. Musl's byte-pinned `owned_dynamic.list`, including its eight malloc
interposition exceptions and data exceptions, stays separate from this list.
No prefix/glob visibility policy or archive-wide exclusion is permitted.

`run_libc_mimalloc_export_visibility.sh PRECHANGE_ABI_REPORT PRECHANGE_LIBC_SO`
builds fresh static and dynamic products, checks their source-bound metadata,
and compares their dynsym against the retained pre-change product. The only
allowed shared dynsym removal is the exact contract list: the original 475
extra exports become the reviewed 51 atomic/runtime/compiler entries. The
runner also proves that all 424 definitions remain in the sole selected static
allocator member, then reuses the owned C allocation-interposition and mimalloc
startup/errno lifecycle components with the fresh dynamic product.

This is component evidence only. It does not qualify the native runtime,
allocator, product campaign, or public x86 support.
