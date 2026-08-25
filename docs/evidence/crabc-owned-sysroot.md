# Owned CRT/sysroot evidence

Run the native proof with:

```bash
./scripts/dev.sh sysroot
```

The dispatcher builds two clean installed trees,
`target/crabc-sysroot/` and `target/crabc-sysroot-repro/`, then writes
`compat/reports/sysroot/latest.json`. The report passes only when the two trees
match after normalized provenance, the CRT/sysroot purity audit passes, and
the native harness passes all supported driver and runtime contracts.

The evidence includes:

- archive/ELF inventory and source/dependency/link-input purity accounting;
- a locked, source-built `compiler_builtins` lane for AArch64 binary128
  compiler helpers, including source/build-script hashes, exact features, a
  sealed no-native-build log audit, hash-bound producer commands, and a
  no-external-runtime archive-closure audit;
- CRT object hashes bound to direct pinned-rustc commands and emitted AArch64
  entry-machine checks, including `rcrt1.o`'s no-pre-relocation GOT/TLS
  relocation boundary;
- `crabc-cc` plans and actual linker traces for all supported modes;
- canonical interpreter, RELRO/NOW, no-text-relocation, and no-executable
  stack checks;
- dynamic process-map hashes for the owned loader and libc, after startup has
  completed rather than from a loader-only early snapshot;
- initial stack/auxv, constructor/destructor (including executable and DSO
  finalizer bypass through `_Exit`), `atexit`/`__cxa_finalize`, TLS, stack
  guard, dynamic loading, and static-PIE relocation witnesses; and
- two-clean-build reproducibility.

## Current artifact record

The current native run is recorded at
`compat/reports/sysroot/latest.json`. Its two production builds agree on these
target runtime byte hashes:

| Artifact | SHA-256 |
| --- | --- |
| `libc.a` | `89cfdf33e3b1770fbec6bd8205a762ffd0d7ae2cc3137a2ffbf7bfd7fb3c4308` |
| `libc.so` | `182b499031ef249f76da72d6dc7ddab80fc19dbd5f08a890da92864105da0621` |
| `libldso.so` | `0414d8d1698e4cfb77d7cae28bd2ffbabbd46bee1daf49b8607b8d36bb6eed34` |

The report's `purity.static_runtime` record binds `libc.a` to exactly two ELF
members: the Rust libc root and the documented mimalloc exception. Its
`artifact_purity`, link traces, and static provenance reject compiler-rt
C/assembly and stock compiler-builtins members in `libc.a`; the separately
source-built `libcrabc-builtins.a` is the only compiler-helper archive.

## Tool and input boundary

The host-side proof accepts only the pinned Docker Linux/AArch64 environment,
Clang/lld, pinned Rust `rustc`/Cargo and rust-src, Python's standard-library
runner, and LLVM archive/ELF inspection tools. These are build and inspection
tools, not target runtime inputs.

| Rejected target input | Enforcement point |
| --- | --- |
| musl CRT or target library | archive/ELF and resolved-link-input audits |
| GCC `crtbegin`/`crtend`, `libgcc`, `libatomic`, or `libssp` | wrapper plan and resolved-link-input audits |
| compiler-rt target archive, C object, or assembly object | static-runtime provenance, archive inventory, and link audit |
| ambient target sysroot/header/library path | sealed `crabc-cc` driver and header/link traces |

The sole recorded full-runtime exception is `libmimalloc-sys` 0.1.49's pinned
`static.c`, plus its direct `cc` 1.4.3 compiler-discovery build helper. The
dependency audit hash-binds both and rejects every other native production
input.

## Mode and application witnesses

| Witness | Result required by the report |
| --- | --- |
| Compile, preprocess, assembly, and relocatable output | installed driver owns target include and tool inputs |
| Shared DSO | owned startup/library ordering and no foreign runtime input |
| Dynamic PIE and non-PIE | canonical `/lib/ld-crabc-aarch64.so.1` and owned maps |
| Static non-PIE | no interpreter or dynamic dependencies |
| Static PIE | genuine `ET_DYN`, self-relocation, ASLR, and fail-closed malformed table/target checks |
| Pinned Lua 5.4.8 | source build, extension loading, and execution through `crabc-cc` |

`./scripts/dev.sh lua` is the application-level witness. Its separate musl
lane remains a behavior oracle, not a target-runtime fallback or CRT claim.

The canonical loader is staged only when absent in the disposable Docker
container and is hash-checked before removal. This makes ordinary kernel
`exec` evidence possible without modifying a persistent host filesystem.

The report distinguishes `crt_sysroot_pure_rust` from
`full_runtime_pure_rust`. The former is the completed scope. The latter stays
`blocked_by_native_allocator` until the separately owned mimalloc port replaces
the current native allocator dependency.
