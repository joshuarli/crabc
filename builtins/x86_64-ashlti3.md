# Private x86-64 `__ashlti3` helper proof

`builtins/run_x86_64_ashlti3.sh` records one narrow native C ABI boundary for
the existing Rust-only archive: unsigned `__int128` left shift through
`__ashlti3` and its signed 32-bit raw count. It is private evidence for the
bounded archive only. It is not a complete compiler runtime, installed public
sysroot, libc capability, CRT startup, or dynamic-loader support.

## Source closure

`builtins/src/lib.rs::__ashlti3` passes its `i32` count through `as u32` to
`Uint128::shl`. `Uint128::shl` returns zero for counts at least 128, moves the
low word into the high word for counts from 64 through 127, preserves the value
for zero, and otherwise carries low-word bits into the high word. A negative
raw `i32` becomes a large `u32`, so this source-specific helper returns zero.
`Uint128` is `#[repr(C)]` with low then high 64-bit words, which makes the
selected x86-64 C `unsigned __int128` value ABI explicit.

The runner rebuilds the existing `builtins/build_x86_64.py` one-member archive
twice, checks byte reproducibility, and requires the archive provenance to
name `__ashlti3` while retaining its existing private x86 scope. This is
crabc-owned Rust source, not a copied musl helper. The pinned musl 1.2.6 x86
toolchain supplies the native C execution baseline; its separate reference arm
performs an unsigned C shift only after guarding the count into the C-defined
range.

## Native boundary

The candidate C object declares and calls `__ashlti3` directly. Its static link
must fail without the fresh archive and name that missing symbol. It must also
have no other undefined helper boundary before the archive is supplied. With
the archive, the runner rejects ambient CRT/compiler-runtime inputs, an
interpreter, dynamic dependency, TLS segment, and unresolved symbols; it also
requires the final static `ET_EXEC` to retain and transfer control to
`__ashlti3` (a direct call or optimized tail jump).

The cases cover counts 0, 1, 63, 64, 65, and 127 across the low/high-word
boundary, then prove the selected zero result for 128, 129, and -1. The latter
three are a raw helper contract derived from `Uint128::shl`, not ordinary C
shift semantics. The right and arithmetic shift helpers are not selected.

Run the runner inside the pinned native x86 evidence image after ensuring it
exists with `./scripts/dev-x86_64.sh image`:

```sh
bash /workspace/builtins/run_x86_64_ashlti3.sh
```

The runner stays standalone while the shared x86 dispatcher is in active stdio
integration. This leaf does not promote public x86 support or alter archive
admission.
