# crabc-ldso

A Rust `no_std` dynamic linker for crabc's selected Linux runtime profile.
Native little-endian x86-64 on Linux 5.10+ is the active development target;
public x86-64 support remains unqualified. The supported AArch64 route is
paused and must be preserved without running or emulating it.

## Native x86-64 product

The sole x86 Cargo feature is `x86_64-owned-dynamic-runtime`. It selects the
initial graph, lifecycle, TLS and RuntimeV1 handoff together. The installed
product builder combines loader and libc into one shared image, installed
with the `/lib/ld-crabc-x86_64.so.1` interpreter entry. Building this crate
alone is not an installed sysroot or a qualification result.

The loader owns ELF admission, mapping, relocation, symbol scope, loader TLS
and dynamic-object lifecycle. libc retains its C ABI and process state;
checked private startup records connect the two owners. Initial graph
publication follows complete relocation, protection and callback preflight.
Runtime loading retains admitted mappings after `dlclose`, while failed
admission rolls back its unpublished objects, matching the pinned musl
profile. No registry reference may span application callbacks.

The selected behavior and evidence are described in:

- [General relocation](../compat/x86_64/general_relocations.md): symbol scope,
  relocation destinations, COPY and TLS forms.
- [Initial lifecycle](../compat/x86_64/general_loader_lifecycle.md): dependency
  and main-image callbacks, CRT handoff and installed-product evidence.
- [Runtime loader](../compat/x86_64/runtime-dynamic-loader.md): `dlopen`,
  introspection, mapping lifetime and conventional CRT startup.
- [Runtime ownership](../docs/design/architecture.md): libc, loader, CRT and
  private RuntimeV1 boundaries, including required hardening.

## Development commands

Type-check the active loader inside the pinned native x86 image:

```sh
scripts/lanes/rust-check.sh cargo check -q --locked -p crabc-ldso --features x86_64-owned-dynamic-runtime
```

The installed product is built and exercised through
`./scripts/dev-x86_64.sh materialized-dynamic-sysroot --work NEW_DIR`.
`--prepare` stops after preparation; `--resume WORK --next`, `--case PRODUCT CASE`
and `--finish` drive its existing resumable evidence. Use a fresh directory
under `.work/`, the selected C allocator backend, and the pinned native image.
See the [native harness](../compat/x86_64/README.md) and dispatcher `--help`
for prerequisites and the [qualification chain](../compat/x86_64/qualification-chain.md)
for the distinction between a product case and full correctness acceptance.

## Paused AArch64 route

`src/loader.rs` retains the AArch64 loader, TLS_ABOVE_TP and TLSDESC handling.
Its startup vectors have no fixed argv/envp/auxv limits, and failed dependency
closures roll back DSO mappings. Secure execution ignores and removes
`LD_LIBRARY_PATH` and `LD_PRELOAD`; the current directory is never an implicit
library search path. Its runtime loader lock is recursive, and `dlerror`
storage is per thread; allocation failure yields no pending error rather
than another thread's message.

Cross-thread TLS reclamation uses `__rc_tls_block_size_for(fs_base)` and
`__rc_tls_base_offset_for(fs_base)`; parameterless compatibility helpers describe
the caller/process default. The [CRT contract](../docs/design/crt-and-sysroot.md)
records this target's separate startup conventions.

## License

MIT OR Apache-2.0
