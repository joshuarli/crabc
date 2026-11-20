# crabc

A small Rust `no_std` Unix runtime: a libc, a dynamic linker, owned
application CRT and compiler helpers, and `crabc-rs`, an idiomatic Rust facade
over the same OS mechanisms.

The goal is exact modern Unix behavior without an unlimited historical libc
surface. The compatibility oracle is the exact `[musl_native]` snapshot in
[`compat/upstreams.toml`](compat/upstreams.toml); glibc is neither an oracle
nor a fallback.

## Current work

The [active plan](plan.md) records development and qualification status.

## Support

| Target | Status |
| --- | --- |
| Linux/AArch64, little-endian, kernel 5.10+ | Supported; converging onto the native runtime on branches |
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

## Runtime hardening

A separately built hardened profile (PIE, non-executable stacks, W^X, RELRO,
eager binding, explicit library search) is a completion requirement, not a
shipped feature. The [compatibility profile](COMPATIBILITY-PROFILE.md#runtime-hardening-profiles)
defines it.

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
[Build and install the owned products](docs/build-and-install.md).

## License

MIT OR Apache-2.0
