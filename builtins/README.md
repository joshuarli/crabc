# crabc compiler helpers

`crabc-builtins` creates `libcrabc-builtins.a`, the C-linkable compiler-helper
archive for the Linux/AArch64 little-endian sysroot. It is all Rust target
code, but it is not a repackaged rustup target artifact.

`build.py` makes two Rust objects sets in fresh temporary roots:

```text
crabc `src/lib.rs`                         -> one owned compatibility object
pinned rust-src compiler_builtins 0.1.160 -> source-built Rust object members
                                              (`core` is source-built as its compiler context)
                                              with `c` and `mem` disabled
                                             -> deterministic libcrabc-builtins.a
```

The source-built upstream lane is needed for the native AArch64 `long double`
ABI. Clang emits binary128 arithmetic, comparison, and conversion helpers for
ordinary C expressions; a hand-picked `__netf2` fallback is not sufficient.
The archive therefore contains the pinned Rust implementations of the `tf`
family, including `__addtf3`, `__subtf3`, `__multf3`, `__divtf3`, comparisons,
and `f32`/`f64` conversions, alongside crabc's `__muldc3` and existing
integer helpers.

The builder invokes Cargo with `--locked -Zbuild-std=core,compiler_builtins`
and keeps the final target members only from the fresh `compiler_builtins`
rlib. Its provenance records the pinned rust-src lock, the build script and
its `libm/configure.rs` input, every target dep-info Rust source hash, the
selected feature set, archive members, full symbol inventory, member ELF
facts, closure resolution, and SHA-256. It rejects the upstream `c` and `mem`
features, native build commands, prebuilt compiler-builtins input, memory
intrinsic exports, outline-atomic exports, unwind sections, absolute build
paths, and an archive closure with an unresolved runtime symbol.

The disposable source-build probe has its own deterministic no-dependency
`Cargo.lock`, while the pinned rust-src library lock remains the authority for
the source-built standard components. Cargo runs in a sealed environment that
does not inherit caller C compilers, C flags, target linkers, or Rust flags.
The adjacent `.commands.json` records each producer and audit operation; its
SHA-256 is embedded in the adjacent provenance JSON and copied into the
installed sysroot.

`compiler_builtins` keeps upstream `links = "compiler-rt"` metadata for its
optional C fallback. That metadata is not a target link input here: the
recorded source-build contract rejects the `c` feature and verifies that no C,
C++, or external-assembly object is produced or installed. Some selected
upstream Rust sources use Rust inline assembly for established AArch64 math
instructions; that remains auditable Rust source, not an external `.S` input.

Build inside the pinned Linux/AArch64 development container:

```text
python3 builtins/build.py --output target/crabc-sysroot/usr/lib/libcrabc-builtins.a \
  --verify-reproducible
```

The sealed driver passes `-mno-outline-atomics`, links `libc` before this
archive, and audits resolved LLD inputs. Thus public libc math symbols remain
owned by `libc`; the archive is selected only for compiler-generated helpers.
