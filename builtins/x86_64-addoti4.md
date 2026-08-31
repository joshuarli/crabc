# Private x86-64 `__addoti4` helper proof

`builtins/run_x86_64_addoti4.sh` records one narrow native C ABI boundary for
the existing Rust-only archive: signed `__int128` addition through
`__addoti4`, including its caller-owned `int` overflow result slot.  It is
private evidence for the bounded archive only.  It is not a complete compiler
runtime, installed public sysroot, libc capability, CRT startup, or
dynamic-loader support.

## Source closure

`builtins/src/lib.rs::__addoti4` calls `Uint128::add` for the two-word wrapped
result and computes signed overflow from the result and operand sign bits.  It
then writes one ABI-compatible `i32` through the caller-owned overflow pointer.
`builtins/src/lib.rs::Uint128` is `#[repr(C)]` with low then high 64-bit words,
which makes the selected x86-64 C `__int128` value ABI explicit.

The runner rebuilds the existing `builtins/build_x86_64.py` one-member archive
twice, checks byte reproducibility, and requires the archive provenance to
name `__addoti4` while retaining its existing private x86 scope.  This is
crabc-owned Rust source, not a copied musl helper.  The pinned musl 1.2.6 x86
toolchain supplies the native C execution baseline; a separate reference arm
uses its GCC checked-add builtin rather than `__addoti4` itself.

## Native boundary

The candidate C object declares and calls `__addoti4` directly.  Its static
link must fail without the fresh archive and name that missing symbol.  With
the archive, the runner rejects ambient CRT/compiler-runtime inputs, an
interpreter, dynamic dependency, TLS segment, and unresolved symbols; it also
requires the final static `ET_EXEC` to retain and transfer control to
`__addoti4` (a direct call or optimized tail jump).

The cases cover a large non-overflowing signed value, both signed-addition
overflow directions with their wrapped results, and a mixed-extrema addition
without overflow.  They use a valid writable overflow pointer only; null or
invalid pointer behavior is outside the helper's documented unsafe contract.

Run the runner inside the pinned native x86 evidence image after ensuring it
exists with `./scripts/dev-x86_64.sh image`:

```sh
bash /workspace/builtins/run_x86_64_addoti4.sh
```

The runner stays standalone while the shared x86 dispatcher is in active
stdio integration.  This leaf does not promote public x86 support, alter
archive admission, or select `__suboti4` or `__muloti4`.
