# Private x86-64 `__ashrti3` helper proof

`builtins/run_x86_64_ashrti3.sh` records one narrow native C ABI boundary for
the existing Rust-only archive: a two-word `Uint128` arithmetic right shift
through `__ashrti3` and its signed 32-bit raw count. It is private evidence for
the bounded archive only. It is not a complete compiler runtime, installed
public sysroot, libc capability, CRT startup, or dynamic-loader support.

## Source closure

`builtins/src/lib.rs::__ashrti3` passes its `i32` count through `as u32` to
`Uint128::sar`. `Uint128::sar` preserves the value for zero, sign-fills the
high word for in-range shifts, moves a signed high word into the low word for
counts from 64 through 127, and returns all ones or zero for counts at least
128 according to the original top bit. A negative raw `i32` becomes a large
`u32`, so this source-specific helper returns all ones for a negative bit
pattern and zero for a non-negative one. `Uint128` is `#[repr(C)]` with low
then high 64-bit words, which makes the selected x86-64 C `unsigned __int128`
value ABI an explicit bit carrier rather than a public C declaration.

The runner rebuilds the existing `builtins/build_x86_64.py` one-member archive
twice, checks byte reproducibility, and requires the archive provenance to
name `__ashrti3` while retaining its existing private x86 scope. This is
crabc-owned Rust source, not a copied musl helper. The pinned musl 1.2.6 x86
toolchain supplies the native C execution baseline; its separate reference arm
reconstructs `Uint128::sar` using defined unsigned word operations, not
ordinary C signed-right-shift semantics or out-of-range C shift expressions.

## Native boundary

The candidate C object declares and calls `__ashrti3` directly. Its static link
must fail without the fresh archive and name that missing symbol. It must also
have no other undefined helper boundary before the archive is supplied. With
the archive, the runner rejects ambient CRT/compiler-runtime inputs, an
interpreter, dynamic dependency, TLS segment, and unresolved symbols; it also
requires the final static `ET_EXEC` to retain and transfer control to
`__ashrti3` (a direct call or optimized tail jump).

The cases cover a negative two-word bit pattern at counts 0, 1, 63, 64, 65,
and 127, then prove its all-ones source result for 128, 129, and -1. They also
prove zero for the same out-of-range counts on a positive bit pattern. These
are raw helper cases derived from `Uint128::sar`, not general C arithmetic
shift semantics. Logical and left-shift helpers are not selected.

Run the runner inside the pinned native x86 evidence image after ensuring it
exists with `./scripts/dev-x86_64.sh image`:

```sh
bash /workspace/builtins/run_x86_64_ashrti3.sh
```

The runner stays standalone while the shared x86 dispatcher is in active stdio
integration. This leaf does not promote public x86 support or alter archive
admission.
