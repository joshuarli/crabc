# crabc

Build a small, auditable modern Unix runtime, not every historical libc
subsystem: a Rust `no_std` libc, dynamic linker, owned CRT/compiler builtins,
and an idiomatic `crabc-rs` facade. Narrow scope must not weaken ordinary Unix
semantics.

## Scope and authority

- Linux, little-endian, kernel **5.10 or newer**. Public support remains
  AArch64. Native x86-64 runtime parity and fixed-mimalloc completion are active
  under `plan.md`; x86 becomes public only through its promotion gates.
  AArch64 implementation and qualification are paused: preserve its behavior,
  selected allocator, frozen baseline, and target-qualified evidence. Do not
  run or emulate its suites for the x86 goal.
- No new architectures, 32-bit/big-endian targets, non-Linux libc, speculative
  portability layers, or CI-workflow work in the active campaign. A future
  macOS/AArch64 libSystem backend for `crabc-rs` is separately scoped.
  Downstream LLVM/C++ SDK notes do not extend the active runtime goal or
  authorize ambient compiler-helper or unwinder inputs.
- Pinned musl **1.2.6** is the C/POSIX compatibility oracle. Use the applicable
  Linux and System V AMD64 ABI contracts for target boundaries. Rustix is a
  pinned test oracle, never a production dependency. Glibc is neither an oracle
  nor a fallback; candidate target artifacts must not borrow ambient runtime
  inputs from musl, CRT, compiler runtimes, headers, or loaders either.
- Read this file and `plan.md` to start. Consult the selected behavior in
  `COMPATIBILITY-PROFILE.md`, the relevant executable contracts, pinned source,
  and code-adjacent guidance as needed—not the entire documentation tree.
  User direction governs, followed by this scope and the compatibility profile,
  then `plan.md` and its machine-readable acceptance contracts. Tests and source
  establish behavior; generated reports measure it. Reconcile contradictions;
  neither stale prose nor an assertion in a report waives a requirement.

## Product boundaries

**Core runtime.** Be exact about filesystems, descriptors, pipes, signals,
fork/exec, pthread/C11 threads, TLS, sockets, mappings, time, stdio, resolver,
dynamic linking, errno, ABI, and their composition. Do not add pre-5.10 kernel
fallbacks. Record newer-kernel requirements centrally before relying on them.
Existing correct functionality need not be deleted merely because it exceeds
these minimums.

**Rust facade.** Classify capabilities as OS mechanisms, useful POSIX/runtime
facilities, C ABI machinery, Rust-subsumed, or deliberately unsupported.
Expose the first two idiomatically; account for all capabilities in
`compat/crabc-rs/coverage.toml`. Do not mechanically wrap every C symbol or
recreate Rust allocation, formatting, strings, slices, or sorting. Keep native
paths thin and LLVM-visible rather than round-tripping through the C ABI.
Expose real platform mechanisms, not emulations or a portable runtime framework.

**Allocator.** No allocator invention. The exception is the faithful Rust
semantic port of pinned mimalloc **v3.5.0**, with provenance in
`crabc-mimalloc/UPSTREAM.md`. Preserve source algorithms, data structures,
ownership, memory ordering, lifecycle, and valid-program behavior. Retain the
exact C source as an oracle after production promotion. Algorithmic divergence
needs a durable rationale plus differential and performance evidence; a more
idiomatic-looking design is not sufficient. Backend selection is compile-time.
The C backend remains selected until the native x86 promotion gates pass.

**Cryptography.** Never implement cryptographic primitives locally, including
when translating compatibility source. Use reviewed focused Rust dependencies
for hashes, ciphers, password primitives, and PRNG/DRBG cores, or explicitly
limit the feature. Direct OS entropy and surrounding domain-specific state
machines are allowed. The sole legacy PRNG exception is a source-faithful port
of musl 1.2.6 `random`, `srandom`, `initstate`, and `setstate`, including seeding,
state layout, recurrence, and switching, with attribution. Never use it for
entropy, secrets, allocator hardening, or other security-sensitive purposes.

**Text and locale.** Support `C`, `POSIX`, and `C.UTF-8`; preserve byte-oriented
C/POSIX versus UTF-8 semantics. Cheap UTF-8 aliases may normalize to the same
profile, but unsupported names must fail honestly. Rust-facing text is UTF-8.
The compatibility encoding profile is ASCII, UTF-8, UTF-16LE/BE, and
UTF-32LE/BE—not general locale databases, collation/language packs, or legacy
charset catalogs. Gettext is at most small ABI machinery, not a subsystem.

**System data and DNS.** Consume conventional passwd/group, hosts,
resolv.conf, services, protocols, and zoneinfo files. Support `TZ`, POSIX TZ
syntax, and tzfile parsing; do not bundle databases. DNS stays within the
bounded A/AAAA/CNAME, search, UDP/TCP fallback, retry/failover and netdb profile.
No NSS/PAM/provider plugins, DNSSEC, DoH, DoT, mDNS, recursive-resolver framework,
or IDNA policy.

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

## Dependencies, safety, and performance

Prefer small, mature, focused, auditable Rust dependencies over risky local
reimplementations; zero dependencies is not itself a goal. Selection is
implementation judgment, not a routine approval round trip. Record the actual
primitive and normal transitive graph, native/build/proc-macro code, allocation
and global state, `no_std`, and LTO implications where the dependency is owned.
Broad or difficult-to-audit dependencies need stronger justification, not a
scope expansion. Production allocator restrictions in `plan.md` still apply.

Every public unsafe Rust API documents concrete caller obligations; explain
nontrivial unsafe blocks at the actual ownership, lifetime, ABI, or provenance
boundary. Do not invent superficially safe APIs with unenforceable invariants.
Use short validated projections for concurrently accessed runtime metadata,
not references whose aliasing promises the implementation cannot uphold.

Remove unnecessary syscalls, allocation, indirection, and algorithmic work
first; prove simple scalar semantics, then inspect active-target codegen.
SIMD is a narrow, separately tested and measured optimization, not an internal
framework or a substitute for a better algorithm. An established math kernel
may be appropriate earlier when its numerical contract is proved. Crypto
primitives remain in reviewed dependencies, including vectorized ones.

## Working rules

- Implement coherent behavior with focused regressions and real boundary
  evidence. Reproduce bugs before fixing them; prose or behavior-neutral edits
  do not need artificial failing tests. Reuse existing test matrices rather
  than adding a runner, receipt schema, and status paragraph for each symbol.
- Preserve exact upstream revisions, source-to-Rust mappings, licenses, and
  intentional differences. Do not rewrite upstream workloads, suppress raw
  failures, or weaken gates to conceal an implementation defect.
- Keep unrelated dirty work. Do not run broad formatters, linters, pre-commit
  hooks, or push a remote unless the user explicitly requests them.
- Keep new worktrees, scratch, caches, extracted sources, and build state
  inside the owning checkout's ignored `.work/` boundary. Honor stricter
  launcher paths and existing ignored report locations. No external scratch,
  symlink escapes, or shared mutable build outputs.
- Use `.claude/skills/lanes` and `.claude/agents/crabc-lane.md` for parallel
  lane work; current user orchestration instructions still govern models.
  Parallelize useful independent implementation in isolated worktrees; give
  shared state one owner and integrate continuously. Do not invent work to
  fill slots or require a scheduling board, handoff schema, or wave ceremony.
  Run at most 16 concurrent lane agents; do not throttle builds within a lane;
  qualifying benchmarks need an uncontended host.
- Validators check structure, cross-references, and runtime receipts, not
  restated ledger prose, owner lists, or counts; tests exercise behavior,
  not source text. Do not add per-artifact validator functions or
  source-literal tests.
- `plan.md` is the only implementation plan and repository-wide progress
  handoff. Update its small Progress status section in place when the frontier
  changes. Put required per-capability/source state in existing manifests and
  raw evidence in ignored reports. Git is the history; do not add prose
  archives, per-leaf settlement narratives, or duplicate status files.

## Code and command map

| Boundary | Location |
| --- | --- |
| C ABI and libc-owned state | `libc/`; target root `src/lib.rs`, shared ABI translation `src/c_abi.rs` |
| Loader and private runtime wire boundary | `ldso/`; `src/lib.rs` and `src/loader.rs` |
| Owned application CRT and compiler helpers | `crt/`, `builtins/` |
| Shared typed primitives and Rust facade | `crabc-core/`, `crabc-rs/` |
| Fixed allocator port and source provenance | `crabc-mimalloc/`, `compat/allocator/` |
| Public headers and integration fixtures | `include/`, `tests/` |
| Native campaign and frozen parity contracts | `compat/x86_64/` |
| Compatibility, corpus, std/LTO, and performance evidence | `compat/`, `libc-test-harness/` |
| Pins | `rust-toolchain.toml`, `compat/upstreams.toml`, target Dockerfiles |

Use `./scripts/dev-x86_64.sh --help` and `campaign-status` for active runtime
work; use `./compat/allocator/run-x86_64.sh` for the separate allocator lane.
Direct Cargo belongs inside the relevant pinned native environment. The
AArch64 `scripts/dev.sh` route is paused, and `scripts/local-ci.sh` is not a
substitute for native qualification. Harness READMEs own detailed options;
`docs/README.md` is an optional reference index. `COMPATIBILITY.md` is generated,
never hand-edited.
