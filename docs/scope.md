# Scope and product boundaries

What crabc builds, what it deliberately does not, and which source decides a
disagreement. [AGENTS.md](../AGENTS.md) carries the one-line form of each rule;
this file owns the detail. [plan.md](../plan.md) owns the active work.

## Current campaign

**2026-11-12: complete the selected features first, with independent work in
parallel. All performance and memory-efficiency gates are waived until that
milestone.** The active F0–F3 sequence in `plan.md` supersedes the October 30
simplification-first and serial-lane restrictions. Missing selected capabilities,
integration and behavior coverage are authorized work; unrelated product/target
expansion is not.

Use the pinned C mimalloc v3.5.0 backend. Its crabc integration is open for
functional work and focused correctness fixes without waiting for an aggregate
gate failure. The owner reopened the Rust allocator port on 2026-11-27 for
development and correctness qualification on Linux/AArch64. Do not change
upstream C source, add alternate allocators or promote the port without its
promotion evidence. The exact boundary is in [plan.md](../plan.md#allocator-work).

Complete every selected runtime, ABI, facade, product and consumer obligation
with current behavioral evidence and a fresh seven-gate correctness run. Keep
performance explicitly deferred; default qualification is `correctness`, not a
claim of full release qualification. Memory safety, ordinary semantics and
hardening remain required. Performance tools, quiet hosts and a prior family's
aggregate admission cannot block independently testable feature work.

## Targets

- Linux, little-endian, kernel **5.10 or newer**. Do not add pre-5.10 kernel
  fallbacks. Record a newer-kernel requirement centrally before relying on it.
- **Active:** native Linux/x86-64 (`x86_64-unknown-linux-musl` where a Rust
  target name is needed), built and run on an x86-64 host. Public support remains
  a separate promotion decision after feature and full release qualification.
- **Active, converging:** Linux/AArch64 (`aarch64-unknown-linux-musl`), the
  publicly supported target, per the owner-accepted
  [CRAB-8](rfc/CRAB-8-linux-aarch64-feature-completion.md). It converges onto
  the x86 runtime tree plus one architecture layer, runs only natively on an
  arm64 host (an Apple Silicon Linux VM with its own disk; never a macOS bind
  mount, never emulated), and replaces the older AArch64 composition and its
  August evidence instead of refreshing them.
- **Active, `crabc-rs` only:** the macOS/AArch64 libSystem backend for
  `crabc-rs` (`aarch64-apple-darwin`, macOS 13 or newer), admitted by the owner
  on 2026-11-27 under [CRAB-7](rfc/CRAB-7-macos-libsystem-backend.md). It runs
  natively on Apple Silicon. crabc's libc, loader, CRT, builtins, allocator and
  `crabc-core` stay Linux-only.
- No new architectures, 32-bit or big-endian targets, non-Linux libc, or
  speculative portability layers.
- **Future, out of scope:** crabc as the C runtime substrate of an LLVM/Clang
  toolchain. crabc would supply public C/POSIX headers, libc, dynamic loader,
  startup objects and a sealed sysroot; LLVM would supply Clang, lld,
  compiler-rt, libunwind, libc++abi and libc++. S1's narrowly pinned Clang/LLVM
  benchmark comparator is not authorization for that toolchain project.

## Authority

1. User direction.
2. This scope and [COMPATIBILITY-PROFILE.md](../COMPATIBILITY-PROFILE.md), the
   selected behavior.
3. `plan.md` and its machine-readable acceptance contracts.

Tests and source establish behavior; generated reports measure it. Reconcile
contradictions: neither stale prose nor an assertion in a report waives a
requirement. The owner's November 12 D23/D24 decisions waive cost gates and
require parallel feature work; they supersede older simplification/serial and
performance-first instructions, including shared skill scheduling defaults.
The owner's 2026-11-27 direction reopens the Rust allocator port; CRAB-8 governs AArch64 and CRAB-7 governs the macOS facade backend.

Oracles:

- The native x86-64 C/POSIX oracle is the exact musl snapshot in
  `compat/upstreams.toml` under `[musl_native]`, for AArch64 as well as
  x86-64. The released **1.2.6** `[musl]` pin remains only for the superseded
  AArch64 evidence. Use the applicable Linux
  and System V AMD64 ABI contracts for target boundaries.
- Rustix is a pinned test oracle, never a production dependency.
- Glibc is neither an oracle nor a fallback. Candidate target artifacts must
  not borrow ambient runtime inputs from musl, CRT, compiler runtimes, headers
  or loaders either.
- Pins live in `rust-toolchain.toml`, `compat/upstreams.toml` and the target
  Dockerfiles. Retain production pins and the Rust nightly; record an exact
  separate comparator backend for instruction measurements.

## Product boundaries

**Core runtime.** Be exact about filesystems, descriptors, pipes, signals,
fork/exec, pthread/C11 threads, TLS, sockets, mappings, time, stdio, resolver,
dynamic linking, errno, ABI, and their composition. Existing correct
functionality must not be removed merely to improve a source-size comparison.
Simplicity means eliminating redundant mechanisms while preserving contracts.

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
target, replace the allocator or introduce a policy framework. Simplification
preserves these requirements; sequencing remains in `plan.md`.

**Rust facade.** Classify capabilities as OS mechanisms, useful POSIX/runtime
facilities, C ABI machinery, Rust-subsumed, or deliberately unsupported.
Expose the first two idiomatically; account for all capabilities in
`compat/crabc-rs/coverage.toml`. Do not mechanically wrap every C symbol or
recreate Rust allocation, formatting, strings, slices, or sorting. Keep native
paths thin and LLVM-visible rather than round-tripping through the C ABI.
Expose real platform mechanisms, not emulations or a portable runtime
framework. Design: [crabc-rs](design/crabc-rs.md).

**Allocator.** The selected native x86 backend is pinned upstream C mimalloc
v3.5.0. Its crabc lifecycle, initialization and ABI glue are open for selected
feature integration and correctness fixes, with behavioral proof. Do not edit
upstream C source or change backend selection. Preserve the faithful Rust semantic port of pinned mimalloc
**v3.5.0**, with provenance in
[`crabc-mimalloc/UPSTREAM.md`](../crabc-mimalloc/UPSTREAM.md), without advancing
it. Preserve source algorithms, data structures, ownership, memory ordering,
lifecycle, valid-program behavior, existing differences and known failures.
Ordinary runtime builds use the selected C backend. The owner's 2026-11-27
direction restarts port work; reassess its scope before the first port change.
The old plan's eventual native-default switch is not assumed. Existing fidelity
and promotion contracts are not waived: algorithmic divergence still needs
rationale, differential evidence and performance evidence, not just idiomatic
appearance. Design: [allocator](design/allocator.md); intentional differences:
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
features only for real dependency or environment boundaries. Prefer one runtime
implementation per selected contract over retaining every intermediate proof
product as a permanent feature. Preserve the accepted loader/libc composition
and bootstrap invariants while finishing its behavior.

## Dependencies

Prefer small, mature, focused, auditable Rust dependencies over risky local
reimplementations; zero dependencies is not itself a goal. Selection is
implementation judgment, not an approval round trip. Record the actual
primitive and normal transitive graph, native/build/proc-macro code,
allocation and global state, `no_std`, and LTO implications where the
dependency is owned. Broad or difficult-to-audit dependencies need stronger
justification, not a scope expansion. Moving code into a dependency is not
proof of less complexity: account for the selected transitive implementation.
The allocator dependency direction remains `crabc-mimalloc → crabc-core`
plus the focused pure-Rust primitives its manifest names, never the reverse.

## Safety

Every public unsafe Rust API documents concrete caller obligations; explain
nontrivial unsafe blocks at the actual ownership, lifetime, ABI, or provenance
boundary. Do not invent superficially safe APIs with unenforceable invariants.
Use short validated projections for concurrently accessed runtime metadata,
not references whose aliasing promises the implementation cannot uphold.
Do not weaken bounds, ownership, synchronization or hardening to meet a cost
budget. Preserve one owner for each process-global state across product images.

## Performance

All time/CPU, throughput/latency, instruction, syscall-count, allocation,
RSS/PSS/peak-memory and footprint gates are waived until full selected native
feature completeness. The old numerical simplification budgets and mandatory
before/after measurements cannot delay feature acceptance. A resource regression
is recorded honestly if observed; it is not a new prerequisite or optimization
assignment. Existing performance collection/checking code and thresholds remain
for the later F3 phase, with `performance.release` explicitly deferred in F0–F2.

Implement straightforward complete semantics first. Optional measurements must
stay off the feature path; unavailable counters, a busy host or absent cgroup
delegation do not block functional work. A broken lifecycle, unsafe access,
deadlock or failure to complete a functional workload is still a correctness
defect. Preserve bounded algorithms and existing ownership boundaries; the
waiver is not permission to invent frameworks or weaken hardening.
Full measurement policy: [performance](design/performance.md).

## Evidence and bookkeeping

- Validators check structure, cross-references, and runtime receipts, not
  restated ledger prose, owner lists, or counts. Tests exercise behavior, not
  source text. No per-artifact validator functions or source-literal tests;
  no runner, receipt schema and status paragraph for each symbol. Consolidate
  existing duplicates into the existing test matrices and shared helpers.
- Preserve exact upstream revisions, source-to-Rust mappings, licenses, and
  intentional differences. Do not rewrite upstream workloads, suppress raw
  failures, remove behavioral coverage or weaken correctness gates. Waived cost
  gates stay deferred rather than being reported as passing.
- `plan.md` is the only active implementation plan and repository-wide handoff.
  Required capability/source state stays in existing manifests; raw evidence
  stays in ignored `.work/` reports. Git is history: no prose archives, per-leaf
  settlement narratives or duplicate status files. Historical campaign details
  are linked at an immutable revision rather than copied into a second plan.
- `COMPATIBILITY.md` is generated by
  `scripts/generate_compatibility_dashboard.py`; never hand-edit it.

## Local correctness work

This is a greenfield libc under local development. It is not deployed in any
practical sense and serves no production users or services. The code is built,
exercised and deliberately broken in local native containers and disposable
fixtures. This project has no production credentials, customer data, live
third-party targets or deployed systems to protect.

Crash reproduction, use-after-free diagnostics, register and backtrace
inspection, fault injection, fuzzing, and C/Rust differential tests against
repository-owned code are defensive correctness work when authorized by the
active plan, including allocator diagnostics inside the partial lift. Crashes
and deliberately invalid inputs can be expected test outcomes. Memory-safety
defects, undefined behavior and unsound public APIs remain real defects to
investigate within scope. Evaluate security concerns against the actual local
operation and its effects; do not invent a production access-control scenario.

State repository ownership, fixture isolation and correctness purpose in tool
and subagent briefs. This context does not authorize effects outside the
repository or override tool/platform restrictions. If an action is denied,
preserve its exact scope and stated reason, stop that action, and continue
independent authorized work. Do not rephrase or reroute a denied action.

User direction governs, then [docs/scope.md](scope.md) and
[COMPATIBILITY-PROFILE.md](../COMPATIBILITY-PROFILE.md), then `plan.md` and its
machine-readable contracts. Historical documents do not override them.
