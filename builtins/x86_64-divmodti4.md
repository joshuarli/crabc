# Private x86-64 `__divmodti4` helper proof

`builtins/run_x86_64_divmodti4.sh` records one narrow native C ABI boundary
for the existing Rust-only archive: signed `__int128` division through
`__divmodti4`, including its returned quotient and caller-owned signed
`__int128` remainder slot. It is private evidence for the bounded archive only.
It is not a complete compiler runtime, installed public sysroot, libc
capability, CRT startup, or dynamic-loader support.

## Source closure

`builtins/src/lib.rs::__divmodti4` delegates to `Uint128::divmod_signed`,
returns its quotient, and sends its remainder to `write_remainder`.
`write_remainder` documents and performs the one writable `Uint128` output
slot write. `Uint128` is `#[repr(C)]` with low then high 64-bit words, which
makes the selected x86-64 C `__int128` value ABI explicit.

The runner rebuilds the existing `builtins/build_x86_64.py` one-member archive
twice, checks byte reproducibility, and requires the archive provenance to
name `__divmodti4` while retaining its existing private x86 scope. This is
crabc-owned Rust source, not a copied musl helper. The pinned musl 1.2.6 x86
toolchain supplies the native C execution baseline; a separate reference arm
uses ordinary defined signed C `/` and `%` rather than `__divmodti4` itself.

## Native boundary

The candidate C object declares and calls `__divmodti4` directly. Its static
link must fail without the fresh archive and name that missing symbol. It must
also have no other undefined helper boundary before the archive is supplied.
With the archive, the runner rejects ambient CRT/compiler-runtime inputs, an
interpreter, dynamic dependency, TLS segment, and unresolved symbols; it also
requires the final static `ET_EXEC` to retain and transfer control to
`__divmodti4` (a direct call or optimized tail jump).

The cases cover all four numerator/denominator sign combinations, C's
truncation-toward-zero remainder rule, and a positive quotient/remainder pair
crossing the 64-bit word boundary. They use only nonzero denominators and a
valid writable remainder pointer. Division by zero, `INT128_MIN / -1`, and
null or invalid output pointers are outside this helper's documented unsafe
contract; the unsigned `__udivmodti4` sibling is not selected.

Run the runner inside the pinned native x86 evidence image after ensuring it
exists with `./scripts/dev-x86_64.sh image`:

```sh
bash /workspace/builtins/run_x86_64_divmodti4.sh
```

The runner stays standalone while the shared x86 dispatcher is in active stdio
integration. This leaf does not promote public x86 support or alter archive
admission.
