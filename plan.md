# Current plan

## Active future goal: native Linux/x86-64 runtime parity

Implement the native Linux/x86-64 program defined in
[`x86-64.md`](x86-64.md). The goal is full parity with the current
Linux/AArch64 runtime capability boundary across `crabc-core`, `crabc-libc`,
`crabc-ldso`, CRT/sysroot artifacts, and `crabc-rs`; it is not allocator-only
or symbol-count parity.

Work in native-x86 vertical capability slices: establish the syscall, ELF,
TLS, atomic/futex, signal, CRT, and loader foundation, then complete the
supported libc and Rust-facade families with focused native ABI and behavioral
evidence. Keep public support documentation AArch64-only until every promotion
gate in `x86-64.md` passes.

## Paused: fixed Rust mimalloc parity

All new mimalloc implementation, source-map or ledger expansion, C/Rust
differential lanes, performance work, backend integration, and AArch64
production-port work are paused. Retain the existing implementation and private
native x86-64 allocator evidence; the technical handoff is
[`native-mimalloc.md`](native-mimalloc.md). Resume that program only after an
explicit reprioritization.
