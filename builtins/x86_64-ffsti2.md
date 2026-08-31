# Private x86-64 `__ffsti2` helper proof

`builtins/run_x86_64_ffsti2.sh` records one narrow native C ABI boundary for
the existing Rust-only archive: a two-word `Uint128` first-set-bit count through
`__ffsti2`. It is private evidence for the bounded archive only. It is not a
complete compiler runtime, installed public sysroot, libc capability, CRT
startup, or dynamic-loader support.

## Source closure

`builtins/src/lib.rs::__ffsti2` returns zero for the all-zero bit pattern.
Otherwise it returns `__ctzti2(value) + 1`, so the first low bit is one and the
top high bit is 128. `__ctzti2` is a source-owned export in the same one-member
archive; the candidate proof requires its retained definition after resolving
the direct `__ffsti2` call. `Uint128` is `#[repr(C)]` with low then high 64-bit
words, so the selected x86-64 C `unsigned __int128` value ABI is an explicit
bit carrier rather than a public C declaration.

The runner rebuilds the existing `builtins/build_x86_64.py` one-member archive
twice, checks byte reproducibility, and requires the archive provenance to
name `__ffsti2` while retaining its existing private x86 scope. This is
crabc-owned Rust source, not a copied musl helper. The pinned musl 1.2.6 x86
toolchain supplies the native C execution baseline; its separate reference arm
reconstructs the selected zero and trailing-zero-plus-one source branches with
defined unsigned-word operations rather than invoking a C builtin or another
compiler runtime.

## Native boundary

The candidate C object declares and calls `__ffsti2` directly. Its static link
must fail without the fresh archive and name that missing symbol. It must also
have no other undefined helper boundary before the archive is supplied. With
the archive, the runner rejects ambient CRT/compiler-runtime inputs, an
interpreter, dynamic dependency, TLS segment, and unresolved symbols; it also
requires the final static `ET_EXEC` to retain and transfer control to
`__ffsti2` (a direct call or optimized tail jump) and retain the source-owned
`__ctzti2` definition it uses.

The cases cover zero, low-word first-set-bit counts 1, 2, and 64, and the
high-word boundary counts 65, 66, and 128. They are raw helper cases derived
from `__ffsti2`, not a general public C first-set-bit contract. The leading-
zero, standalone trailing-zero, population-count, and parity helpers are not
selected.

Run the runner inside the pinned native x86 evidence image after ensuring it
exists with `./scripts/dev-x86_64.sh image`:

```sh
bash /workspace/builtins/run_x86_64_ffsti2.sh
```

The runner stays standalone while the shared x86 dispatcher is in active stdio
integration. This leaf does not promote public x86 support or alter archive
admission.
