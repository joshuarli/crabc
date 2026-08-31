# Private x86-64 `__clzti2` helper proof

`builtins/run_x86_64_clzti2.sh` records one narrow native C ABI boundary for
the existing Rust-only archive: a two-word `Uint128` leading-zero count through
`__clzti2`. It is private evidence for the bounded archive only. It is not a
complete compiler runtime, installed public sysroot, libc capability, CRT
startup, or dynamic-loader support.

## Source closure

`builtins/src/lib.rs::__clzti2` calls `u64::leading_zeros` on a nonzero high
word. When that word is zero, it returns `64 +` the low-word count instead.
This makes the all-zero bit pattern return `128` in this crabc-owned helper.
`Uint128` is `#[repr(C)]` with low then high 64-bit words, so the selected
x86-64 C `unsigned __int128` value ABI is an explicit bit carrier rather than
a public C declaration.

The runner rebuilds the existing `builtins/build_x86_64.py` one-member archive
twice, checks byte reproducibility, and requires the archive provenance to
name `__clzti2` while retaining its existing private x86 scope. This is
crabc-owned Rust source, not a copied musl helper. The pinned musl 1.2.6 x86
toolchain supplies the native C execution baseline; its separate reference arm
counts bits with a defined unsigned-word loop rather than invoking a C
leading-zero builtin or relying on another compiler runtime.

## Native boundary

The candidate C object declares and calls `__clzti2` directly. Its static link
must fail without the fresh archive and name that missing symbol. It must also
have no other undefined helper boundary before the archive is supplied. With
the archive, the runner rejects ambient CRT/compiler-runtime inputs, an
interpreter, dynamic dependency, TLS segment, and unresolved symbols; it also
requires the final static `ET_EXEC` to retain and transfer control to
`__clzti2` (a direct call or optimized tail jump).

The cases cover the all-zero result, the high-word leading positions that
produce 0, 1, and 63, and the low-word boundary that produces 64, 65, and 127.
They are raw helper cases derived from `__clzti2`, not a general public C
leading-zero contract. The trailing-zero, first-set-bit, population-count, and
parity helpers are not selected.

Run the runner inside the pinned native x86 evidence image after ensuring it
exists with `./scripts/dev-x86_64.sh image`:

```sh
bash /workspace/builtins/run_x86_64_clzti2.sh
```

The runner stays standalone while the shared x86 dispatcher is in active stdio
integration. This leaf does not promote public x86 support or alter archive
admission.
