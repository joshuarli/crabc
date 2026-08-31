# Compiler-helper source provenance

`libcrabc-builtins.a` is assembled from Rust source only. `build.py` records
the exact hashes of every selected upstream Rust file in its adjacent
provenance JSON; this document explains the durable source boundary.

| Surface | Source oracle | License | crabc production path | Intentional difference |
| --- | --- | --- | --- | --- |
| `__muldc3` | LLVM compiler-rt 22.1.3, `lib/builtins/muldc3.c` | Apache-2.0 WITH LLVM-exception | `src/lib.rs::multiply_complex_double` | Direct Rust translation preserves the four-product and NaN/infinity recovery sequence; Rust `f64` classification methods replace C macros. |
| x86 private `math.complex` `__mulsc3`/`__muldc3`/`__mulxc3` support | LLVM compiler-rt 22.1.3, `lib/builtins/{mulsc3,muldc3,mulxc3}.c` | Apache-2.0 WITH LLVM-exception | `compat/x86_64/complex_mul_support.c` is translated into local symbols in `libc/src/c_abi/x86_64/math_complex_complete_musl_x86_64.S` | Direct C source translation retains the four-product and NaN/infinity recovery sequence. The generated symbols are local implementation details of the x86 static `math.complex` leaf; this does not link a compiler-runtime archive or add a production dependency. |
| Existing `__int128`, byte, and bit helpers | narrow crabc-owned Rust implementations in `src/lib.rs` | MIT OR Apache-2.0 | direct `rustc --emit=obj` object | These preserve the pre-existing explicit AAPCS64 two-word representation and do not use a prebuilt compiler runtime. |
| AArch64 binary128 arithmetic, comparison, and conversion helpers | `compiler_builtins` 0.1.160 in the pinned `nightly-2026-07-24` rust-src component: `compiler-builtins/src/float/{add,cmp,conv,div,extend,mul,pow,sub,trunc}.rs` and their Rust support modules | MIT AND Apache-2.0 WITH LLVM-exception AND (MIT OR Apache-2.0) | fresh `-Zbuild-std=core,compiler_builtins` source build, then only `compiler_builtins-*.o` members are installed | No C fallback is selected. The `c` and `mem` features are rejected, as are native build commands and a prebuilt target `compiler_builtins` archive. |

The upstream package still declares `links = "compiler-rt"` because Rust can
optionally build compiler-rt C fallbacks. In this sysroot that metadata is an
audited exception, not authority to compile or link native runtime code:
`build.py` requires `c` to be absent, records an empty native-build-command
set, and proves the final archive closure has no external runtime undefined
symbols.

The source build is Cargo `--locked`; its record binds the pinned Rust
library lock plus both `compiler-builtins/build.rs` and its imported
`libm/configure.rs`. Those build-script inputs select Rust cfgs, so they are
part of the provenance rather than an implicit toolchain detail. The selected
Rust math sources may use established AArch64 inline assembly, but this path
never selects a C, C++, or external `.S` target input.

The source-built `core` lane is compiler context for `compiler_builtins`; no
`core` object member is copied into `libcrabc-builtins.a`. The archive's own
member list, ELF inspection, symbol inventory, and LLD whole-archive closure
are the installed-artifact evidence.

The adjacent command record is part of that evidence: it records the sealed
Cargo source build, extraction of only `compiler_builtins-*.o`, deterministic
`llvm-ar rcsD` construction, and archive-surface audit. The provenance file
stores the command record's exact filename and SHA-256, so an assembler cannot
declare a substituted archive verified by presenting only a feature summary.
