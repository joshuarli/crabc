# Private x86-64 `__udivmodti4` helper proof

`builtins/run_x86_64_udivmodti4.sh` records one narrow native C ABI boundary
for the existing Rust-only archive: unsigned `__int128` division through
`__udivmodti4`, including its returned quotient and caller-owned unsigned
`__int128` remainder slot. It is private evidence for the bounded archive only.
It is not a complete compiler runtime, installed public sysroot, libc
capability, CRT startup, or dynamic-loader support.

## Source closure

`builtins/src/lib.rs::__udivmodti4` delegates to
`Uint128::divmod_unsigned`, returns its quotient, and sends its remainder to
`write_remainder`. `write_remainder` documents and performs the one writable
`Uint128` output slot write. `Uint128` is `#[repr(C)]` with low then high
64-bit words, which makes the selected x86-64 C `unsigned __int128` value ABI
explicit.

The runner rebuilds the existing `builtins/build_x86_64.py` one-member archive
twice, checks byte reproducibility, and requires the archive provenance to
name `__udivmodti4` while retaining its existing private x86 scope. This is
crabc-owned Rust source, not a copied musl helper. The pinned musl 1.2.6 x86
toolchain supplies the native C execution baseline; a separate reference arm
uses ordinary unsigned C `/` and `%` rather than `__udivmodti4` itself.

## Native boundary

The candidate C object declares and calls `__udivmodti4` directly. Its static
link must fail without the fresh archive and name that missing symbol. With the
archive, the runner rejects ambient CRT/compiler-runtime inputs, an
interpreter, dynamic dependency, TLS segment, and unresolved symbols; it also
requires the final static `ET_EXEC` to retain and transfer control to
`__udivmodti4` (a direct call or optimized tail jump).

The cases cover high-word quotient/remainder behavior, numerator-smaller-than-
denominator behavior, a quotient/remainder pair crossing the 64-bit word
boundary, and `UINT128_MAX` by a high-word denominator. They use only nonzero
denominators and a valid writable remainder pointer. Division by zero and null
or invalid output pointers are outside this helper's documented unsafe
contract; the signed `__divmodti4` sibling is not selected.

Run the runner inside the pinned native x86 evidence image after ensuring it
exists with `./scripts/dev-x86_64.sh image`:

```sh
bash /workspace/builtins/run_x86_64_udivmodti4.sh
```

The runner stays standalone while the shared x86 dispatcher is in active stdio
integration. This leaf does not promote public x86 support or alter archive
admission.
