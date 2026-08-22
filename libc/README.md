# crabc-libc

A `no_std` Rust implementation of the libc ABI for crabc's focused modern
runtime profile. It produces `libc.so` and `libc.a` for running selected
unmodified musl-linked ELF binaries on Linux AArch64.

## Compatibility profile

Crabc targets Linux AArch64 (`aarch64-unknown-linux-musl`) on Linux kernel
versions 5.10 and newer. Its musl-compatible ABI is a modern Unix runtime
profile, not a promise of complete historical musl or glibc breadth; exported
symbols may exist for ABI compatibility without making every historical libc
subsystem a project priority. Locale, system-database, cryptographic, and
allocation behavior remain intentionally bounded by that profile.

## Usage

This crate is not intended for direct use as a Rust library. It produces C-compatible shared/static libraries:

- `libc.so` — dynamic library
- `libc.a` — static library

Build with:
```bash
cargo build -p crabc-libc
```

Output is in `target/debug/libc.so` and `target/debug/libc.a`.

## Features

- Implements ~350+ C library functions (stdio, stdlib, string, math, pthread, etc.)
- `no_std` — no Rust standard library dependency
- Targets the musl ABI for Linux AArch64
- Supports long double via `f128` on aarch64

## License

MIT OR Apache-2.0
