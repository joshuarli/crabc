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
`share/crabc/libcrabc-builtins.{provenance,commands}.json`, plus the static
runtime records `share/crabc/libc-static.{provenance,commands}.json`.

The raw Cargo `libc.a` is not installed directly. The builder reconstructs it
deterministically from exactly one Rust libc root object and the documented
native mimalloc exception, then binds that exact member list, member hashes,
symbols, exclusions, commands, and build flags to the static-runtime records.
Stock compiler-builtins and compiler-rt C/assembly members are excluded from
`libc.a`; the independently source-built `libcrabc-builtins.a` provides the
approved compiler helper surface.

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
That narrowly recorded exception includes only the pinned allocator source and
its direct pinned `cc` compiler-discovery build helper; another native
production dependency is a harness failure.

## Failure taxonomy

| Class | Typical signal | Required response |
| --- | --- | --- |
| Source or dependency purity | unexpected native source/build dependency | remove it or document a new scoped contract before it can be admitted |
| Artifact purity | foreign archive member, mismatched provenance, or compiler-rt object | repair the producer/reconstruction path; do not mask it in the report |
| Link or driver isolation | ambient header/library, injected sysroot/interpreter, or foreign trace input | tighten `crabc-cc` and retain a focused rejection test |
| CRT or runtime behavior | startup, TLS, lifecycle, loader, or static-PIE failure | add the smallest native regression and repair the owning runtime boundary |
| Reproducibility | normalized installed trees differ | identify the nondeterministic producer input; do not accept one tree as evidence |

The runner retains raw command output, traces, provenance, and hashes in the
report so failures can be classified without recreating a different build.
