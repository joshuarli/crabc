# Compatibility profile

This document makes `crabc`'s intentional compatibility boundary explicit.
It is the operational profile for the doctrine in [`SCOPE.md`](SCOPE.md), not
a claim that correct existing code outside the minimum profile must be removed.
Generated measurements live in [`COMPATIBILITY.md`](COMPATIBILITY.md).

## Platform baseline

- **Operating system and architecture:** Public `crabc` support remains Linux
  on AArch64 little-endian only. A staged native Linux/x86-64 little-endian
  implementation program is active under [`x86-64.md`](x86-64.md), but is not
  a supported target until its promotion gates pass. RISC-V, 32-bit,
  big-endian, and non-Linux targets remain inactive.
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

- Allocator invention remains outside project scope. The one fixed exception
  is a provenance-preserving Rust semantic port of mimalloc v3.5.0 for
  Linux/AArch64 little-endian, governed by
  [`docs/design/allocator.md`](docs/design/allocator.md). This is compatibility
  work: upstream algorithms and observable behavior remain authoritative, the
  exact pinned C implementation remains the differential oracle, and any
  algorithmic divergence requires written design, differential, and
  performance evidence. The C allocation ABI remains observable-boundary test
  work owned by `crabc-libc`; `crabc-rs` uses normal Rust allocation rather
  than exposing C allocation APIs.
- The fixed allocator program also has an explicitly reopened native
  Linux/x86-64 little-endian parity profile. It is evidence-only: it does not
  make x86-64 a supported `crabc` platform, does not provide public x86
  allocator integration or default-backend promotion, and must run on native
  x86-64 Linux rather than through AArch64 emulation. Its ledgers and reports
  remain architecture-specific and must not be merged into the AArch64
  public-support contract.
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
controls—without turning them into policy frameworks. The POSIX regex/glob/fnmatch
C ABIs remain compatibility facilities, not a competing Rust regex ecosystem;
crabc-rs additionally provides the bounded native `pattern::glob` and
`pattern::glob_at` operations with explicit roots, owned byte results, and no
hidden CWD traversal policy.

## Process credential mutation

The C `setreuid`, `setregid`, `seteuid`, and `setegid` entry points are an
explicit profile limitation: they return `-1` with `errno == EOPNOTSUPP` and
leave the real, effective, and saved-set IDs unchanged. This is a libc-profile
unsupported result, not a claim that Linux lacks the underlying syscall or
returns `ENOSYS`. A musl-compatible process-wide transition needs an
all-thread credential rendezvous that crabc does not yet own. The native
calling-task `setresuid`/`setresgid` operations remain separately scoped and do
not satisfy this C process-wide contract.

## Named, anonymous temporary files, and file handles

The native `fs::NamedTempFile` contract covers the safe `mkstemp` family only:
it uses an explicit directory authority, a 96-bit `getrandom` basename,
exclusive `openat` creation with `O_CLOEXEC` and mode `0600`, and owned
descriptor-relative unlink-on-drop cleanup. `mktemp`, `tempnam`, and `tmpnam`
remain racy or ambient C pathname facilities. Linux `name_to_handle_at` and
`open_by_handle_at` remain authority-bearing file-handle operations and are
documented C-only here; crabc-rs does not provide a generic file-handle or
filesystem-confinement framework.

The native `fs::TempFile` contract is separate: it opens an anonymous regular
file with Linux `O_TMPFILE | O_RDWR | O_CLOEXEC` relative to an explicit
directory and never creates a directory entry. Filesystems without
`O_TMPFILE` support return `EOPNOTSUPP`; no named-file fallback is attempted.

## Dependencies and performance

Small, mature, focused Rust dependencies are welcome when they are safer and
more auditable than a local replacement (for example optimized text or crypto
primitives), and these dependencies have standing approval without a separate
permission round trip. Framework-scale, native-code, unusually broad, or
otherwise difficult-to-audit dependencies still require consultation. Every
production dependency records the provided primitive, why
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
