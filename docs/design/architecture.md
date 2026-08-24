# Runtime ownership architecture

`crabc` has six runtime-development/evidence layers with deliberately narrow ownership
boundaries.

1. `crabc-core` owns stateless typed Linux/AArch64 kernel and vDSO operations.
   It has no process-global runtime owner.
2. `libc` owns the public C ABI: `errno`, `FILE`, pthread and locale state,
   C layouts, compatibility translation, and other libc process state.
3. `ldso` is the one production dynamic linker. It owns ELF loading,
   relocation, symbol scope, loader TLS, and loader process state.
4. `crabc-mimalloc` is the incomplete pinned, errno-free allocator engine. It
   consumes `crabc-core` and reviewed focused cryptographic primitives, but
   never libc; after promotion, `libc` owns its C ABI adaptation and lifecycle
   integration. The existing C backend remains production until then.
5. `crabc-rs` is the idiomatic Rust facade. It consumes `crabc-core` directly
   for typed native operations and never treats the C ABI as its syscall API.
6. `compat`, `tests`, and `libc-test-harness` are executable evidence. They
   validate contracts but are not runtime dependencies.

The normal dependency direction is toward narrower boundaries: `crabc-rs`,
`crabc-mimalloc`, and `libc` may consume `crabc-core`; `libc` may consume
`crabc-mimalloc` after its promotion; evidence may exercise every runtime
layer before promotion.
`ldso` stays independently bootstrappable because it starts before ordinary
runtime services are available. Neither `crabc-core` nor `crabc-rs` may own
libc or loader singleton state.

The one intentional bridge is `crabc_core::runtime::RuntimeV1`. It is a
versioned, data-only private wire ABI. `libc` exposes the table and `ldso`
registers its loader-owned callbacks, allowing optional Rust facade features
to reach process singleton services without confusing a separately linked
copy of Rust statics for shared process state. It is neither an installed C
interface nor permission to move loader or libc ownership into `crabc-core`.

C ABI adaptation ends in `libc` export modules: C arguments, sentinel values,
layouts, weak/linkage behavior, and TLS `errno` remain there. Typed native
operations begin in `crabc-core` and are shaped by `crabc-rs`; direct native
errors remain values rather than C `errno` side effects.

Within `libc`, `libc/src/lib.rs` is only the crate's target and linkage
composition root. `libc/src/c_abi.rs` owns the shared C layouts, TLS errno,
stdio, pthread, locale, and process runtime state that cannot safely cross a
C ABI boundary as typed native code. Leaf C ABI domains with independent
state are ordinary private modules with explicit imports: syscall adapters,
fenv, DNS expansion, random, select, timer helpers, small compatibility
exports, and linkage-adjacent leaves are representative examples.

`c_abi.rs` is deliberately a lexical C-ABI namespace rather than a second
composition root: its compatibility fragments directly share private layouts,
TLS state, and helper routines. Independently owned C-ABI leaves remain normal
private modules with named imports. Three cohesive lexical families have an
additional, specific rationale: `math_family.rs` keeps musl-derived numerical
ports beside their private bit and floating-environment helpers;
`encoding_tables.rs` is literal iconv data shared by the conversion
implementation; and `c_abi/aarch64/{atomic,memory}.rs` contains
linkage-sensitive AArch64 assembly. These inclusions never cross the public
crate root, which stays a small target and linkage composition boundary.

[`COMPATIBILITY.md`](../../COMPATIBILITY.md) reports generated measurements.
The exact native capability classification lives in
[`compat/crabc-rs/coverage.toml`](../../compat/crabc-rs/coverage.toml), and
harness-local READMEs describe each evidence runner.
