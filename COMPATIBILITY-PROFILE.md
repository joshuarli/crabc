# Compatibility profile

This file defines deliberate observable limits, not implementation progress.
[AGENTS.md](AGENTS.md) owns engineering policy; [plan.md](plan.md) owns the
active completion contract. [COMPATIBILITY.md](COMPATIBILITY.md) contains
generated measurements. A scope restriction does not require deleting correct
existing functionality merely because it exceeds the minimum.

## Platform and semantic boundary

Public support remains Linux/AArch64 little-endian, kernel **5.10 or newer**.
Native Linux/x86-64 is active but not public until its runtime promotion passes.
AArch64 implementation/qualification are paused. Other architectures, 32-bit,
big-endian and non-Linux libc remain inactive. A future macOS/AArch64
libSystem backend for `crabc-rs` would be separately scoped.

Core Unix behavior is not approximate: filesystems, descriptors/pipes,
signals, fork/exec, pthread/TLS, sockets, mappings, time, stdio, the bounded
resolver, dynamic linking, errno, and ABI require full selected semantics.
Musl 1.2.6 is the C compatibility oracle; glibc is neither oracle nor fallback.
Newer-kernel requirements are explicit; there are no pre-5.10 fallback goals.

Capabilities are accounted as core Unix, useful POSIX/runtime, C ABI machinery,
Rust-subsumed, or deliberately unsupported. Full Rust-facade coverage means
semantic accounting, not a Rust wrapper for every C symbol. Native
`pattern::glob`/`glob_at` retain explicit roots and owned byte results, not a
hidden process-CWD traversal policy.

## Deliberate limits

| Area | Selected profile |
| --- | --- |
| Locale | `C`, `POSIX`, `C.UTF-8`; cheap unambiguous UTF-8 aliases may normalize. C/POSIX stay byte-oriented. Unsupported names fail; no general locale database or language/collation packs. |
| Encoding | Rust-facing UTF-8; C compatibility ASCII, UTF-8, UTF-16LE/BE and UTF-32LE/BE where required. No historical code-page catalog. |
| Identity and system data | Conventional passwd/group, hosts, services and protocols files; no NSS/PAM/provider plugins. |
| DNS | Hosts/resolv.conf, A/AAAA/CNAME, search, ordinary getaddrinfo/getnameinfo, UDP with required TCP fallback, retry/failover. No DNSSEC, DoH/DoT, mDNS/service discovery or IDNA policy. |
| Time zones | `TZ`, POSIX TZ syntax, tzfile and system zoneinfo. No bundled tzdata. |
| Localization | At most small gettext-compatible ABI entries; no catalog/resource framework. |
| Regex and frameworks | Selected POSIX regex/glob/fnmatch compatibility, not a competing Rust regex ecosystem. Synchronous OS mechanisms, not an async runtime, process supervisor, security-policy language, plugin registry or portability emulation. |
| Allocation | Faithful fixed mimalloc v3.5.0 Rust port; no allocator invention. Native x86 integration and default promotion require the plan's gates. Rust APIs use normal Rust allocation. AArch64's selected backend stays unchanged. |
| Cryptography | OS entropy and surrounding state machines are allowed. Cryptographic primitives come from reviewed focused dependencies, never local implementations; otherwise the feature is explicitly limited. The bounded C crypt profile is recorded in [crypt-profile.md](compat/crabc-rs/crypt-profile.md). |
| Legacy PRNG | Only the provenance-preserving musl 1.2.6 `random`/`srandom`/`initstate`/`setstate` semantic port, including recurrence, seeding and state switching. Never security-sensitive randomness, entropy or allocator hardening. |

Allocator evidence alone cannot establish runtime/public-platform support.
Keep exact C-v3.5.0 source as the native-engine oracle, preserve architecture-
qualified evidence, and do not equate the currently accepted C provider with
that oracle. Algorithmic changes require explicit source, differential and
performance justification under the engineering policy.

## Process credential mutation

The C `setreuid`, `setregid`, `seteuid`, and `setegid` interfaces return `-1`
with `errno == EOPNOTSUPP` and leave real/effective/saved IDs unchanged. This
is a libc-profile limit, not Linux `ENOSYS`. Their process-wide musl contract
needs an all-thread credential rendezvous not currently owned here. Native
calling-task `setresuid`/`setresgid` remain separate and do not satisfy it.

## Temporary files and file handles

`fs::NamedTempFile` uses an explicit directory, a 96-bit OS-random basename,
exclusive `openat` with `O_CLOEXEC`/`0600`, and descriptor-relative
unlink-on-drop ownership. The C `mkstemp`/`mkostemp`/`mkstemps`/`mkostemps`/
`mkdtemp` entries preserve musl template/flag semantics and caller-owned
cleanup. Historical C `mktemp`, `tempnam`, and `tmpnam` stay racy/ambient name
facilities; they are not safe native object-creation APIs.

`fs::TempFile` is distinct: anonymous Linux `O_TMPFILE | O_RDWR | O_CLOEXEC`
relative to an explicit directory, no directory entry, and `EOPNOTSUPP` on
unsupported filesystems without a named-file fallback. `name_to_handle_at`
and `open_by_handle_at` remain authority-bearing C-only operations, not a
native generic file-handle or filesystem-confinement framework.

## Evidence

A failing supported behavior is a bug; a named limitation is tested and
accounted as such. Neither may be hidden by weakening a test, silently
normalizing a differential, borrowing an ambient implementation, or counting
unsupported behavior as verified. Dependency selection and audit are delegated
under AGENTS.md; this file adds no separate approval ceremony.
