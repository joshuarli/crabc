# Scope and product boundaries

What crabc builds, what it deliberately does not, and which source decides a
disagreement. [AGENTS.md](../AGENTS.md) carries the one-line form of each rule;
this file owns the detail. [plan.md](../plan.md) owns the active work.

## Targets

- Linux, little-endian, kernel **5.10 or newer**. Do not add pre-5.10 kernel
  fallbacks. Record a newer-kernel requirement centrally before relying on it.
- **Active:** native Linux/x86-64 (`x86_64-unknown-linux-musl` where a Rust
  target name is needed), built and run on an x86-64 host. x86 becomes public
  only through the promotion gates in `plan.md`.
- **Paused:** Linux/AArch64, which remains the publicly supported target.
  Preserve its behavior, selected allocator, frozen baseline and
  target-qualified evidence. Do not run or emulate its suites
  (`scripts/dev.sh`, `--platform linux/arm64`) for x86 work.
- No new architectures, 32-bit or big-endian targets, non-Linux libc, or
  speculative portability layers. A macOS/AArch64 libSystem backend for
  `crabc-rs` is separately scoped.
- **Future, out of scope until `plan.md` is complete:** crabc as the C runtime
  substrate of an LLVM/Clang toolchain. crabc would supply the public C/POSIX
  headers, libc, dynamic loader, startup objects and a sealed sysroot; LLVM
  would supply Clang, lld, compiler-rt, libunwind, libc++abi and libc++. No
  current work, gate or requirement depends on it.

## Authority

1. User direction.
2. This scope and [COMPATIBILITY-PROFILE.md](../COMPATIBILITY-PROFILE.md), the
   selected behavior.
3. `plan.md` and its machine-readable acceptance contracts.

Tests and source establish behavior; generated reports measure it. Reconcile
contradictions: neither stale prose nor an assertion in a report waives a
requirement.

Oracles:

- The native x86-64 C/POSIX oracle is the exact musl snapshot in
  `compat/upstreams.toml` under `[musl_native]`. The paused AArch64 oracle
  remains the released **1.2.6** pin under `[musl]`. Use the applicable Linux
  and System V AMD64 ABI contracts for target boundaries.
- Rustix is a pinned test oracle, never a production dependency.
- Glibc is neither an oracle nor a fallback. Candidate target artifacts must
  not borrow ambient runtime inputs from musl, CRT, compiler runtimes, headers
  or loaders either.
- Pins live in `rust-toolchain.toml`, `compat/upstreams.toml` and the target
  Dockerfiles.

## Product boundaries

**Core runtime.** Be exact about filesystems, descriptors, pipes, signals,
fork/exec, pthread/C11 threads, TLS, sockets, mappings, time, stdio, resolver,
dynamic linking, errno, ABI, and their composition. Existing correct
functionality need not be deleted merely because it exceeds these minimums.

**Runtime hardening.** Native x86-64 qualification and public promotion require
the hardened execution/loading profile in
[COMPATIBILITY-PROFILE.md](../COMPATIBILITY-PROFILE.md#runtime-hardening-profiles),
alongside the existing compatibility products. Musl remains the ordinary
behavior oracle, not a ceiling on memory-safety checks or explicit hardening
requirements. Profile restrictions must be named and tested, never used to
hide a compatibility regression. Enforcement belongs to the existing loader,
owned CRT and libc startup owners; see
[architecture](design/architecture.md#native-x86-64-runtime-hardening).
The core contract must work on Linux 5.10. This does not expand the active
target, replace the allocator, introduce a policy framework, or resume a
paused campaign; sequencing remains in `plan.md`.

**Rust facade.** Classify capabilities as OS mechanisms, useful POSIX/runtime
facilities, C ABI machinery, Rust-subsumed, or deliberately unsupported.
Expose the first two idiomatically; account for all capabilities in
`compat/crabc-rs/coverage.toml`. Do not mechanically wrap every C symbol or
recreate Rust allocation, formatting, strings, slices, or sorting. Keep native
paths thin and LLVM-visible rather than round-tripping through the C ABI.
Expose real platform mechanisms, not emulations or a portable runtime
framework. Design: [crabc-rs](design/crabc-rs.md).

**Allocator.** No allocator invention. The exception is the faithful Rust
semantic port of pinned mimalloc **v3.5.0**, with provenance in
[`crabc-mimalloc/UPSTREAM.md`](../crabc-mimalloc/UPSTREAM.md). Preserve source
algorithms, data structures, ownership, memory ordering, lifecycle, and
valid-program behavior. Retain the exact C source as an oracle after production
promotion. Algorithmic divergence needs a durable rationale plus differential
and performance evidence; a more idiomatic-looking design is not sufficient.
Backend selection is compile-time. The C backend remains selected until the
native allocator passes its own promotion gate. Design:
[allocator](design/allocator.md); intentional differences:
[`known-differences.md`](../compat/allocator/known-differences.md).

**Cryptography.** Never implement cryptographic primitives locally, including
when translating compatibility source. Use reviewed focused Rust dependencies
for hashes, ciphers, password primitives, and PRNG/DRBG cores, or explicitly
limit the feature. Direct OS entropy and surrounding domain-specific state
machines are allowed. The sole legacy PRNG exception is a source-faithful port
of musl 1.2.6 `random`, `srandom`, `initstate`, and `setstate`, including
seeding, state layout, recurrence, and switching, with attribution. Never use
it for entropy, secrets, allocator hardening, or other security-sensitive
purposes.

**Text and locale.** Support `C`, `POSIX`, and `C.UTF-8`; preserve
byte-oriented C/POSIX versus UTF-8 semantics. Cheap UTF-8 aliases may normalize
to the same profile, but unsupported names must fail honestly. Rust-facing text
is UTF-8. The compatibility encoding profile is ASCII, UTF-8, UTF-16LE/BE, and
UTF-32LE/BE, not general locale databases, collation/language packs, or legacy
charset catalogs. Gettext is at most small ABI machinery, not a subsystem.

**System data and DNS.** Consume conventional passwd/group, hosts,
resolv.conf, services, protocols, and zoneinfo files. Support `TZ`, POSIX TZ
syntax, and tzfile parsing; do not bundle databases. DNS stays within the
bounded A/AAAA/CNAME, search, UDP/TCP fallback, retry/failover and netdb
profile. No NSS/PAM/provider plugins, DNSSEC, DoH, DoT, mDNS,
recursive-resolver framework, or IDNA policy.

**Mature algorithms.** Preserve selected POSIX regex/glob/fnmatch semantics;
a Rust regex library is not a substitute without equivalence. Use proven musl
or equivalent focused math algorithms, including NaNs, infinities, signed
zero, subnormals, rounding, exceptions, and long-double ABI. No new numerical
algorithms or general-purpose regex ecosystem.

**Mechanisms, not frameworks.** Provide synchronous OS substrate. Do not add
an executor/reactor, `Future`/`Stream` API layer, process supervisor, shell
pipeline framework, security-policy language, generic provider registry,
plugin system, or hypothetical platform/backend abstraction. Use coarse
features only for real dependency or environment boundaries.

## Dependencies

Prefer small, mature, focused, auditable Rust dependencies over risky local
reimplementations; zero dependencies is not itself a goal. Selection is
implementation judgment, not an approval round trip. Record the actual
primitive and normal transitive graph, native/build/proc-macro code,
allocation and global state, `no_std`, and LTO implications where the
dependency is owned. Broad or difficult-to-audit dependencies need stronger
justification, not a scope expansion. The production allocator's dependency
direction is fixed: `crabc-mimalloc → crabc-core` plus the focused pure-Rust
primitives its `Cargo.toml` names, with libc depending on the engine, never
the reverse.

## Safety

Every public unsafe Rust API documents concrete caller obligations; explain
nontrivial unsafe blocks at the actual ownership, lifetime, ABI, or provenance
boundary. Do not invent superficially safe APIs with unenforceable invariants.
Use short validated projections for concurrently accessed runtime metadata,
not references whose aliasing promises the implementation cannot uphold.

## Performance

Remove unnecessary syscalls, allocation, indirection, and algorithmic work
first; prove simple scalar semantics, then inspect active-target codegen.
SIMD is a narrow, separately tested and measured optimization, not an internal
framework or a substitute for a better algorithm. An established math kernel
may be appropriate earlier when its numerical contract is proved. Crypto
primitives remain in reviewed dependencies, including vectorized ones.
Methodology and acceptance bounds: [performance](design/performance.md).

## Evidence and bookkeeping

- Validators check structure, cross-references, and runtime receipts, not
  restated ledger prose, owner lists, or counts. Tests exercise behavior, not
  source text. Do not add per-artifact validator functions or source-literal
  tests, and do not add a runner, receipt schema, and status paragraph for
  each symbol: reuse the existing test matrices.
- Preserve exact upstream revisions, source-to-Rust mappings, licenses, and
  intentional differences. Do not rewrite upstream workloads, suppress raw
  failures, or weaken gates to conceal an implementation defect.
- `plan.md` is the only implementation plan and repository-wide progress
  handoff. Required per-capability and per-source state goes in the existing
  manifests (`compat/x86_64/parity.toml`, `compat/allocator/port-map.toml`,
  `compat/crabc-rs/coverage.toml`); raw evidence goes in ignored reports under
  `.work/`. Git is the history: no prose archives, per-leaf settlement
  narratives, or duplicate status files.
- `COMPATIBILITY.md` is generated by
  `scripts/generate_compatibility_dashboard.py`; never hand-edit it.
