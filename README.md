# crabc

A small Rust `no_std` Unix runtime: a libc, a dynamic linker, owned
application CRT and compiler helpers, and `crabc-rs`, an idiomatic Rust facade
over the same OS mechanisms.

The goal is exact modern Unix behavior without an unlimited historical libc
surface. musl 1.2.6 is the compatibility oracle; glibc is neither an oracle
nor a fallback. Filesystem, process, signal, thread/TLS, socket, memory,
stdio, resolver and loader semantics are meant to be rigorous. The Rust facade
exposes useful OS capabilities rather than a wrapper for every C symbol.

## Current work

The [campaign](plan.md) prioritizes radical non-allocator simplification.
All allocator development and native-mimalloc promotion are frozen; the accepted
C backend remains unchanged. The cost targets are no extra syscalls and at most
10% more retired user instructions than musl under a matched LLVM backend,
without weakening correctness or hardening. These are acceptance requirements,
not achieved performance claims or already-implemented gates.

## Support

| Target | Status |
| --- | --- |
| Linux/AArch64, little-endian, kernel 5.10+ | Supported |
| Linux/x86-64, little-endian, kernel 5.10+ | In development, not yet supported |

Nothing else is a target: no other architectures, no 32-bit or big-endian,
no non-Linux libc.

## What you get

- `libc.so` and `libc.a` implementing the musl-compatible C ABI for the
  selected profile, plus the dynamic loader, CRT objects and compiler helpers
  that make up an owned sysroot.
- `crabc-rs`: a `no_std`-at-core Rust crate with typed, ownership-aware access
  to the same mechanisms, independent of the C ABI. Its `std` and `alloc`
  features add standard-library integration.

The allocator is the upstream C mimalloc implementation. The source-faithful
Rust port of mimalloc v3.5.0 is retained but its development and qualification
are paused under the [allocator freeze](plan.md#allocator-freeze).

## Runtime hardening

Native x86-64 hardening remains required before qualification and public
promotion: a separately built hardened profile will require PIE, non-executable
stacks, page-level W^X, effective RELRO, eager binding, and explicit library
search rules. Existing compatibility products retain their selected behavior.
This is a completion requirement, not a claim that the profile has shipped.
The [compatibility profile](COMPATIBILITY-PROFILE.md#runtime-hardening-profiles)
defines the restrictions; [plan.md](plan.md#runtime-hardening) owns sequencing.
Simplification does not waive this requirement or resume release qualification.

## Compatibility

- [COMPATIBILITY-PROFILE.md](COMPATIBILITY-PROFILE.md) states the intentional
  limits: locales (`C`, `POSIX`, `C.UTF-8`), encodings, system databases, DNS,
  cryptography, and what is deliberately unsupported.
- [COMPATIBILITY.md](COMPATIBILITY.md) is the generated, measured ABI and
  behavior status. It is evidence, not an unconditional completeness claim.
- Experimental sysroot snapshots are commit-pinned and make no cross-version
  ABI, API, header or layout guarantee.

## Contributing

Developer documentation starts at [AGENTS.md](AGENTS.md).

## License

MIT OR Apache-2.0
