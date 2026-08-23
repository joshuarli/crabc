# Rust-subsumption evidence

This note records the narrow native Rust contracts behind the capability
ledger's `rust-subsumed` entries and the separately tracked allocator scope
exception.
The companion test in
`crabc-rs/tests/subsumed.rs` exercises the observations without calling a
public crabc C symbol or reading C `errno`.

The claims are intentionally smaller than the exported C groups:

* `abort` is the immediate process-termination operation exposed by
  `std::process::abort`.
* Ordinary byte copies, fills, comparisons, and searches are operations on
  typed slices. The test keeps the byte ownership and bounds visible.
* Byte-string observations use `CStr::to_bytes` and slice searches. Mutable
  destination strings, token state, and ownership-returning C copies remain
  deferred.
* Scalar integer operations and `qsort`'s non-callback ordering are represented
  by typed arithmetic and `slice::sort`.
* Hash-table ownership and traversal use `std::collections::HashMap`.
* Growing formatted output uses `format_args!` and an owned `String`. Bounded
  `snprintf`/`vsnprintf` semantics are not included: truncation, required-size
  reporting, and destination-buffer contracts remain deferred native work.

The complete public malloc family is the sole `scope-exception`, versioned
as `allocator-mimalloc-libc-boundary` v1 in
`compat/crabc-rs/coverage.toml`. The project policy keeps `malloc`, `calloc`,
`realloc`, `free`, all aligned variants, and `malloc_usable_size` at the libc
boundary while crabc-rs uses ordinary Rust allocation facilities. This is a
mimalloc-backed scope decision, not Rust subsumption and not ABI-only
classification; it makes no claim that Rust allocation reproduces the public
C allocator ABI or usable-size observation.

Likewise, the public AArch64 C `long double` is IEEE-754 binary128
(`include/float.h`, `LDBL_MANT_DIG == 113`). Rust `f32`/`f64` primitive methods
therefore do not subsume the elementary `*l` symbols; those symbols are
tracked as C ABI compatibility machinery rather than a native Rust math
backlog.

The immutable IPv6 values `in6addr_any` and `in6addr_loopback` are precisely
the all-zero and final-octet-one addresses. `core::net::Ipv6Addr::UNSPECIFIED`
and `core::net::Ipv6Addr::LOCALHOST` carry those values without creating a C
global-object or pointer-identity contract. `net::ethers::{IN6ADDR_ANY,
IN6ADDR_LOOPBACK, Ipv6Constants}` gives the correspondence an explicit,
searchable native spelling; `ethers` checks the octets and the no-std
probe keeps the value path independent of C address helpers.

## Scope-reset interpretation

These observations preserve completed capability-accounting evidence; they do not widen the
future platform or API contract. `crabc` remains Linux/AArch64 with Linux
kernel MSRV 5.10. An optional macOS/AArch64 backend belongs only to
`crabc-rs`, through libSystem and a separate implementation boundary.

The evidence is complete when the ledger accounts for the profile rather than
demanding a Rust wrapper around every C symbol. The current machine-readable
ledger, rather than this prose note, owns the exact group counts and statuses.
The allocator exception remains at the libc boundary;
Rust-native callers use ordinary Rust allocation. Future work must keep the
bounded C/POSIX/C.UTF-8 locale profile, UTF-8-first text model, conventional
file-backed user/host/service/protocol lookup without NSS, small DNS resolver,
system-supplied timezone data, and no gettext framework. Crabc does not
implement cryptography, async runtimes, process supervisors, or security-policy
frameworks. Existing codec or compatibility evidence remains factual without
creating an obligation to expand those legacy domains.
