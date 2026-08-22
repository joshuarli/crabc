# Compatibility profile

This document makes `crabc`'s intentional compatibility boundary explicit.
It is the operational profile for the doctrine in [`SCOPE.md`](SCOPE.md), not
a claim that correct existing code outside the minimum profile must be removed.
Generated measurements live in [`COMPATIBILITY.md`](COMPATIBILITY.md).

## Platform baseline

- **Operating system and architecture:** Linux on AArch64 little-endian only.
  No x86_64, RISC-V, 32-bit, big-endian, or non-Linux `crabc` target is active.
- **Kernel MSRV:** Linux **5.10**. Kernel-facing code may use facilities
  available there and must not add pre-5.10 fallbacks. An interface requiring a
  newer kernel documents that fact; only a deliberate central decision raises
  the MSRV.
- **Rust facade:** `crabc-rs` is an idiomatic OS/runtime layer, not a C-wrapper
  generator. A future macOS/AArch64 libSystem backend would be separately
  scoped and exposes real platform differences rather than emulation.

## Capability classes

Every planned capability is classified before implementation.

| Class | Treatment |
|---|---|
| Core Unix runtime | High-rigor implementation and behavioral evidence. Includes filesystems, fds, pipes, signals, fork/exec, pthread/TLS, sockets, mmap, time, stdio basics, resolver behavior in this profile, dynamic linking, errno, and ABI. |
| Useful POSIX/runtime functionality | Implement idiomatically when it benefits Rust or normal Unix software. |
| C ABI compatibility machinery | May exist for C/Rust-std ABI reasons, but is not necessarily a first-class `crabc-rs` API. |
| Rust-subsumed | Account for it without duplicating a better Rust facility (for example `printf`, `qsort`, or basic string/memory helpers). |
| Deliberately unsupported legacy | Record the precise limitation and do not turn an expected profile limit into an accidental failure. |

For `crabc-rs`, full coverage means **semantic accounting of every underlying
capability**, not a Rust wrapper for every exported C symbol.

## Text, locale, and system data

- Supported locales are `C`, `POSIX`, and `C.UTF-8`. Cheap unambiguous UTF-8
  aliases may normalize to `C.UTF-8`; unsupported locale names fail according
  to the API contract. `C`/`POSIX` remain byte-oriented and are not silently
  made UTF-8.
- Rust-facing text is UTF-8. C compatibility supports ASCII, UTF-8,
  UTF-16LE/BE, and UTF-32LE/BE where mechanically required. Historical
  code-page and legacy-charset databases are excluded.
- There is no NSS or identity-provider plugin stack. Conventional
  `/etc/passwd`, `/etc/group`, `/etc/hosts`, `/etc/services`, and
  `/etc/protocols` files are the supported system sources.
- Resolver scope is `/etc/hosts` and `/etc/resolv.conf`, A/AAAA/CNAME,
  search domains, normal `getaddrinfo`/`getnameinfo`, UDP DNS, required TCP
  fallback, and basic retry/failover. DNSSEC, DoH, DoT, mDNS/service-discovery
  frameworks, and IDNA/punycode policy are excluded.
- Time zones use `TZ`, POSIX TZ syntax, tzfile parsing, and system zoneinfo.
  `crabc` does not bundle or maintain tzdata.
- `gettext`, message catalogs, and localization-resource frameworks are not
  native subsystems. Small ABI shims, when needed, are compatibility machinery.

## Allocation and cryptography

- Allocation implementation is intentionally external to project research.
  The C allocation ABI is integrated against the chosen mature allocator
  strategy (currently mimalloc) and remains observable-boundary test work.
  `crabc-rs` uses normal Rust allocation rather than exposing C allocation APIs.
- `crabc` does not implement cryptographic hashes, password hashing, TLS,
  X.509, certificate validation, PRNG/DRBGs, or public-/symmetric-key
  algorithms. OS entropy such as `getrandom` is in scope. A compatibility API
  needing crypto uses a proven focused Rust dependency or remains explicitly
  limited; cryptography is never hand-rolled here. The bounded C `crypt`
  compatibility decision and RustCrypto dependency review are recorded in
  [`compat/crabc-rs/crypt-profile.md`](compat/crabc-rs/crypt-profile.md).

## Deliberate non-framework boundaries

`crabc` does not provide a general locale database, plugin/provider registry,
async runtime, process supervisor, security-policy language, or portability
facade. It exposes low-level mechanisms where useful—nonblocking descriptors,
poll/epoll, process primitives, signals, credentials, namespaces, and resource
controls—without turning them into policy frameworks. POSIX regex/glob/fnmatch
remain compatibility facilities, not a competing Rust regex ecosystem.

## Dependencies and performance

Small, mature, focused Rust dependencies are welcome when they are safer and
more auditable than a local replacement (for example optimized text or crypto
primitives). Every production dependency records the provided primitive, why
`core`/`alloc` is insufficient, normal transitive dependencies, proc-macros,
build scripts/native code, allocation/global state, `no_std` suitability, and
LTO implications. Prefer LLVM-visible Rust code, simple inlineable call graphs,
and verified focused SIMD kernels; scalar semantics remain canonical.

## Evidence and exceptions

Musl is the C compatibility authority. The project validates work through
vertical slices: inventory, implementation, ABI/direct-boundary proof,
focused observable tests, musl differential or relevant external tests, then
verified status. A failing supported behavior is a bug. A profile exclusion is
documented here and in the relevant capability ledger/test as a deliberate
limitation. Do not hide either by weakening tests or by using glibc as an
oracle.
