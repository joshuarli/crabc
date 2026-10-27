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
The exact `[musl_native]` snapshot in `compat/upstreams.toml` is the active
x86-64 C compatibility oracle. Paused AArch64 retains released musl 1.2.6.
Glibc is neither oracle nor fallback.
Newer-kernel requirements are explicit; there are no pre-5.10 fallback goals.

Capabilities are accounted as core Unix, useful POSIX/runtime, C ABI machinery,
Rust-subsumed, or deliberately unsupported. Full Rust-facade coverage means
semantic accounting, not a Rust wrapper for every C symbol. Native
`pattern::glob`/`glob_at` retain explicit roots and owned byte results, not a
hidden process-CWD traversal policy.

For native x86-64, `CPU_ISSET` and `CPU_ISSET_S` return zero or one, with
type `int` in C and `bool` in C++, matching the selected oracle headers.

Basic regular expressions reject a backreference until its referenced group
has closed, matching the native musl parser.

## Runtime hardening profiles

Native x86-64 has two required product contracts. **Compatibility** preserves
the selected musl comparison behavior, including existing static and dynamic
non-PIE products and deferred `RTLD_LAZY` semantics. **Hardened** is an
explicitly selected, separately built sysroot/interpreter/CRT profile with the
restrictions below. These are requirements to implement and qualify;
[plan.md](plan.md#runtime-hardening) records progress. They do not change the
paused AArch64 profile or claim current hardened-product support.

The hardened selection is fixed in product identity and build provenance.
Environment variables and direct-interpreter options cannot disable it.
Installed link specifications select the matching interpreter and CRT; owned
products must detect a conflicting profile rather than silently downgrade.
This is one bounded build distinction, not a runtime policy language.
Product selection is independent of the qualification runner's
`correctness`/`full` modes.

| Boundary | Hardened contract |
| --- | --- |
| Main executable | Admit dynamic PIE (`ET_DYN`); reject dynamic `ET_EXEC` through both kernel-interpreted and direct-loader entry. Owned static executable products use static PIE and its CRT; the hardened link interface rejects non-PIE requests. Determine image identity from validated ELF/auxv facts, not `argv[0]` or a nonzero load address. |
| Stack and executable mappings | Require one valid `PT_GNU_STACK` without `PF_X` on admitted main images and DSOs; reject missing, duplicate or executable-stack declarations. Enforce W^X at actual page granularity, including overlapping load ranges and relevant aliases, and preserve non-executable main and thread stacks. |
| Relocation | Preserve existing rejection of `DT_TEXTREL`/`DF_TEXTREL`. Validate every relocation write's full width and writable destination, including RELA, RELR and supported TLS relocations; absence of a textrel tag does not authorize writes to executable/read-only storage. |
| Binding and RELRO | Resolve required imports before guest initialization, treating `RTLD_LAZY` as eager in this profile. Reject unresolved required symbols; retain normal weak-symbol semantics. Protect all relocation-only binding storage read-only before publication/callbacks and never reopen committed RELRO for deferred binding. Require RELRO coverage for GLOB_DAT, JUMP_SLOT, DTPMOD64, DTPOFF64 and TPOFF64 destinations, and for symbol-bearing 64 and PC32 destinations, including ambiguous destinations that may be ordinary mutable data. An object with neither a declared PLTGOT nor any of these binding relocations may omit RELRO. |
| Library search | No implicit current-directory search or relative search directories from environment, interpreter options, RPATH/RUNPATH or configured system paths. Slash-containing dependency, preload and `dlopen` paths must be absolute. Bare library names use the admitted search roots. `$ORIGIN` may expand only from a validated absolute origin, subject to existing secure-execution restrictions; it must never fall back to the current directory. An absolute path alone is not a claim of trusted ownership or symlink confinement. |
| Privileged execution | Preserve auxv/credential-derived secure execution and its environment/preload/origin filtering. The hardened profile cannot weaken these rules, and process-controlled strings cannot override the cached secure state. |
| Failure | An initial violation terminates before application initialization. A rejected `dlopen` returns the existing failure/error interface without running the rejected graph's constructors or leaving graph/TLS publication, handles, mappings or permissions partially changed. If restoring a safe state is impossible, terminate rather than continue with weakened protection. |

Checks apply to the kernel-mapped main image, direct interpreter entry, startup
dependencies and preloads, and runtime `dlopen` as appropriate. Owned static
PIE has no interpreter: its build and CRT must establish the corresponding
invariants themselves. A loader cannot police unrelated static executables,
foreign interpreters, arbitrary application syscalls, or host ASLR settings.
W^X here governs admitted images and loader transitions, not a process-wide
ban on JITs or later application `mprotect` calls.

Memory-safety and malformed-input fixes apply to both products where relevant.
Intentional policy rejections use this contract, not an expectation that musl
must also reject the fixture. Keep positive compatibility controls and report
both products distinctly in existing evidence. All core requirements retain
the Linux 5.10 baseline. MDWE, irreversible mapping sealing and hardware control
flow protections are separate future enhancements, not implicit core gates.

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
| Allocation | Faithful fixed mimalloc v3.5.0 Rust port; no allocator invention. Native x86 feature integration is active; default promotion waits for the later release phase. Rust APIs use normal Rust allocation. AArch64's selected backend stays unchanged. |
| Cryptography | OS entropy and surrounding state machines are allowed. Cryptographic primitives come from reviewed focused dependencies, never local implementations; otherwise the feature is explicitly limited. The bounded C crypt profile is recorded in [crypt-profile.md](compat/crabc-rs/crypt-profile.md). |
| Legacy PRNG | Only the provenance-preserving musl 1.2.6 `random`/`srandom`/`initstate`/`setstate` semantic port, including recurrence, seeding and state switching. Never security-sensitive randomness, entropy or allocator hardening. |

Allocator evidence alone cannot establish runtime/public-platform support.
In native x86 allocator products, a `realloc` operation that terminally retains
ownership terminates the process after runtime cleanup. Ordinary failure still
returns null with the original client live and unchanged; terminal retention
cannot grant that client back to the caller.
Keep exact C-v3.5.0 source as the native-engine oracle, preserve architecture-
qualified evidence, and do not equate the currently accepted C provider with
that oracle. Algorithmic changes require explicit source, differential and
performance justification under the engineering policy.

## Process credential mutation

Linux credential syscalls change only the calling task. The installed x86
C setters `setuid`, `setgid`, `seteuid`, `setegid`, `setreuid`, `setregid`,
`setresuid`, `setresgid`, and `setgroups` follow musl's process-wide
contract: each runs its syscall on every thread through musl's `__synccall`
signal rendezvous, and a failure after another thread has already changed
kills the process. The frozen private x86 archive and paused AArch64 keep
their earlier profile: `setreuid`, `setregid`, `seteuid`, and `setegid`
return `-1` with `errno == EOPNOTSUPP` and leave IDs unchanged (a
libc-profile limit, not Linux `ENOSYS`), and the direct setters affect only
the calling task. `crabc-rs` credential operations remain explicit
calling-task operations.

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
