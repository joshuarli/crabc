# Owned CRT/sysroot evidence

`compat/sysroot/` proves the installed Linux/AArch64 crabc application
sysroot. It rejects musl CRT objects, GCC `crtbegin`/`crtend`, `libgcc`,
`libatomic`, `libssp`, compiler-rt target archives, and ambient target
sysroots. The canonical host command is:

```bash
./scripts/dev.sh sysroot
python3 -m unittest discover -s compat/sysroot/tests -p 'test_*.py'
```

`scripts/build_owned_sysroot.py` performs two independent clean production
builds and invokes the standard-library-only assembler/driver tool,
[`scripts/crabc_sysroot.py`](../../scripts/crabc_sysroot.py). The completed
trees are `target/crabc-sysroot/` and `target/crabc-sysroot-repro/`.

## Installed contract

The primary tree contains `bin/crabc-cc`, canonical
`lib/ld-crabc-aarch64.so.1`, the relative musl-name compatibility alias,
public headers, the five Rust-produced CRT objects, `libc.so`, `libc.a`,
`libcrabc-builtins.a`, deliberate C-library aliases, and
`share/crabc/{manifest,purity}.json`. It also retains hash-bound producer
records as `share/crabc/crt.{provenance,commands}.json` and
`share/crabc/libcrabc-builtins.{provenance,commands}.json`.

Useful driver introspection is:

```bash
target/crabc-sysroot/bin/crabc-cc --print-sysroot
target/crabc-sysroot/bin/crabc-cc --crabc-print-manifest
target/crabc-sysroot/bin/crabc-cc --crabc-print-link-plan hello.c -o hello
```

The driver finds the tree from its own location, seals target search variables,
and refuses a caller-provided `--sysroot` or dynamic interpreter override.

## Evidence retained

The report is atomically written to `compat/reports/sysroot/latest.json`. It
records source/dependency/link/artifact purity, raw resolved linker traces,
header traces, all driver modes, ELF properties, canonical kernel execution,
initial process vectors, stack guard, TLS/pthread, lifecycle ordering,
dynamic loading, static-PIE relocation behavior, `/proc/<pid>/maps` hashes,
and the reproducibility comparison. The compiler-helper record specifically
requires the locked, source-built pinned `compiler_builtins` lane: its exact
Rust source and build-script input hashes, `c`/`mem` exclusion, no native build
command or prebuilt target archive, a sealed Cargo build log, a hash-bound
producer-command record, and a fully resolved helper-archive closure. CRT
records likewise bind each object byte hash to its direct pinned-rustc command
and emitted AArch64 early-entry machine audit.

The map witness waits until a dynamic process has both owned loader and libc
mapped. It then records their hashes rather than relying on paths alone. The
canonical loader is staged only if absent in the disposable container and is
removed only after its hash is verified.

`crt_sysroot_pure_rust` is the completed CRT/sysroot result. The report keeps
`full_runtime_pure_rust` separate and currently marks it
`blocked_by_native_allocator` while libc still depends on `libmimalloc-sys`.
