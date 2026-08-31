# Private x86-64 signed `__int128` helper proof

`builtins/run_x86_64_signed_int128.sh` records one deliberately narrow native
ABI boundary: a freestanding Linux/x86-64 C object whose defined signed
`__int128` division and remainder expressions require `__divti3` and
`__modti3`, respectively.  It is evidence for the existing bounded private
archive only; it is not a complete compiler runtime, an installed public
sysroot, a libc capability, CRT startup, or dynamic-loader support.

## Source closure

The owned implementation is `builtins/src/lib.rs::Uint128`, whose `#[repr(C)]`
two-word `{ lo, hi }` representation is the explicit selected-ABI form.
`builtins/src/lib.rs::__divti3` and `builtins/src/lib.rs::__modti3` each call
`Uint128::divmod_signed` and return its quotient or remainder.  The runner
uses the existing `builtins/build_x86_64.py` deterministic one-member archive
builder, then reads its provenance record to require the x86 target, the
private scope wording, the `crabc-builtins.o` membership, both symbols, and a
byte-reproducible rebuild.

This helper pair is crabc-owned Rust source rather than a copied musl helper.
The pinned musl 1.2.6 x86 toolchain is the native C/ABI execution baseline: it
runs the same defined C quotient/remainder cases before the freestanding
candidate.  It does not make musl an implementation fallback or an ownership
claim for the helper algorithm.

## Native boundary

The C fixture makes both operands volatile and keeps `/` and `%` in separate
`noinline` functions.  The runner proves that the resulting native object has
undefined references to both exact helpers, that an otherwise identical
freestanding static link fails without the fresh archive and names each
missing symbol, and that the archive-backed `ET_EXEC` retains and calls both
definitions.  It rejects an interpreter, dynamic runtime dependency, TLS
segment, and unresolved symbol before running the pinned-musl reference and
candidate images.

The cases cover signs on a value above 64 bits and C's truncation-toward-zero
remainder rule for mixed signs.  They deliberately exclude division by zero
and `INT128_MIN / -1`, which do not provide a defined signed-C result.

Run the runner inside the pinned native x86 evidence image after ensuring it
exists with `./scripts/dev-x86_64.sh image`:

```sh
bash /workspace/builtins/run_x86_64_signed_int128.sh
```

The runner is intentionally standalone while `scripts/dev-x86_64.sh` is in an
active stdio integration.  This leaf does not promote public x86 support,
alter archive admission, or select adjacent signed helpers such as
`__divmodti4`.
