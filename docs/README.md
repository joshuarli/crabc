# Documentation router

This directory owns durable cross-cutting design, evidence, roadmaps, and
history. Keep executable runner instructions beside the harness that owns
them; this router should explain ownership, not duplicate command contracts.

## Governing project contract

- [Scope](../SCOPE.md) — public Linux/AArch64 profile, staged native x86-64
  program, and non-goals.
- [Compatibility profile](../COMPATIBILITY-PROFILE.md) — supported and
  intentionally limited behavior.
- [Project status](../STATUS.md) — current completion state and roadmap router.
- [Combined native Linux/x86-64 completion goal](../plan.md), [runtime parity](../x86-64.md),
  and [native mimalloc](../native-mimalloc.md) — active target-specific
  implementation and promotion contracts; not current public support.
- [Private x86-64 owned static sysroot evidence](../compat/x86_64/owned-static-sysroot.md)
  — reproducible installed static artifact and real pthread/TLS consumer;
  neither sysroot-family completion nor public support.
- [Owned filesystem mechanism evidence](../compat/x86_64/owned-filesystem-mechanisms.md)
  — source-mapped installed filesystem C ABI slice across owned products;
  neither POSIX-family completion nor public support.
- [Owned POSIX filesystem composition](../compat/x86_64/owned-posix-filesystem.md)
  — source-mapped stat, directory, traversal, temporary-name, and file-handle
  providers with manifest-bound one-object receipt evidence across owned
  products; neither POSIX-family completion nor public support.
- [Owned Linux/filesystem/terminal mechanism evidence](../compat/x86_64/owned-unix-mechanisms.md)
  — source-mapped installed Unix C ABI slice across owned products;
  neither POSIX-family completion nor public support.
- [Installed residual POSIX process-control evidence](../compat/x86_64/owned-process-control.md)
  — source-mapped 31-name C ABI workload across owned products; its 44-name
  process-control accounting remains composite and non-promoting.
- [Owned C11 quick-termination evidence](../compat/x86_64/owned-quick-exit.md)
  — fixed-capacity `at_quick_exit`/`quick_exit` behavior across the installed
  native products; neither runtime-family completion nor public support.
- [Owned legacy time and clock-adjustment evidence](../compat/x86_64/owned-legacy-time.md)
  — source-mapped `times`, interval-timer, and seccomp-contained
  clock-adjustment behavior across installed native products; neither
  runtime-family completion nor public support.
- [Owned POSIX family acceptance proposal](../compat/x86_64/owned-posix-runtime.md)
  — checked frozen scope, product matrix, and remaining behavior obligations.
- [Owned classic host and service lookup](../compat/x86_64/owned-classic-netdb.md)
  — conventional local files and bounded DNS through owned products, with
  explicit remaining resolver cancellation and parser-order obligations.
- [Owned C filename-pattern evidence](../compat/x86_64/owned-pattern.md)
  — source-mapped `fnmatch`/`glob` C ABI slice across owned products; neither
  pattern-family completion nor public support.
- [Runtime ownership architecture](design/architecture.md) — layer ownership,
  dependency direction, and the private runtime wire boundary.
- [Agent/project handoff](../AGENTS.md) — code map, source precedence, and
  canonical development commands.
- [Generated compatibility dashboard](../COMPATIBILITY.md) — current measured
  status; generated only, never hand-edited.

## Current design

- [Native `crabc-rs` design](design/crabc-rs.md) — typed facade architecture,
  ownership, safety, and runtime-state boundary.
- [Performance design](design/performance.md) — measurement methodology,
  optimization doctrine, and current cost model.
- [Fixed mimalloc semantic-port design](design/allocator.md) — provenance,
  dependency direction, integration ownership, and promotion boundary for the
  paused AArch64 allocator record and active native x86-64 compatibility program.
- [Owned CRT/sysroot design](design/crt-and-sysroot.md) — application startup,
  sealed driver, purity boundary, and runtime ownership.
- [Source-build design](design/source-build.md) — completed Lua gate through
  the installed sysroot and its musl-oracle boundary.
- [Rust-subsumption evidence](evidence/crabc-rs-subsumption.md) — why selected
  C groups have no native Rust wrapper.
- [Owned CRT/sysroot evidence](evidence/crabc-owned-sysroot.md) — completed
  native sysroot/reproducibility proof and allocator-purity distinction.
- [Lua source-build evidence](evidence/lua-source-build.md) — completed Lua
  owned-sysroot integration proof.
- [`compat/crabc-rs/coverage.toml`](../compat/crabc-rs/coverage.toml) — exact
  machine-readable capability accounting.

## Detailed acceptance contracts

- [Performance completion](roadmap/performance-completion.md) — active
  scorecard and release proof.
- [Software-corpus validation](roadmap/software-corpus-validation.md) —
  sequenced C0–C4 real-software and native-application program after the
  focused scorecard passes.
- [Source-build progression](roadmap/source-build.md) — future CPython
  acceptance contract on the completed owned-sysroot boundary.

## Historical rationale and naming provenance

- [Runtime delivery record](history/runtime-plan.md) — concise delivery
  provenance and the governing superseded-direction decisions.
- [`crabc-rs` delivery record](history/crabc-rs-delivery-plan.md) — concise
  facade architecture and capability-accounting provenance.
- [Archived project status](history/project-status-2026-09-04.md) and
  [paused AArch64 allocator handoff](history/native-mimalloc-aarch64.md) —
  preserved implementation details and exact-revision evidence, not live queues.
- [Semantic migration record](history/semantic-migration.md) — original blob
  IDs, loss-prevention ledger, and milestone-to-semantic rename map.

Historical records never override root policy, [`STATUS.md`](../STATUS.md),
machine-readable contracts, or generated evidence.

Keep live documents short: each fact has one owning contract, design note, or
report. Guides link to those owners instead of repeating per-leaf scope and
commit narratives. Archive useful old detail; never relabel it as current
qualification or append history to an execution plan.

## Code-adjacent guides

- C runtime and dynamic loader: [`libc/README.md`](../libc/README.md),
  [`ldso/README.md`](../ldso/README.md), and
  [`compat/ldso/README.md`](../compat/ldso/README.md).
- ABI and loader inventory: [`compat/abi/README.md`](../compat/abi/README.md)
  and [`compat/loader/README.md`](../compat/loader/README.md).
- Compatibility runners: [`libc-test-harness/README.md`](../libc-test-harness/README.md)
  and the nearest `compat/*/README.md`.
- Rust `std`, Rustix, and LTO evidence: [`compat/rust-std/README.md`](../compat/rust-std/README.md),
  [`compat/rustix/`](../compat/rustix/), and [`compat/lto/README.md`](../compat/lto/README.md).
- Performance runner mechanics: [`compat/perf/README.md`](../compat/perf/README.md).
- Allocator source/oracle/differential mechanics:
  [`compat/allocator/README.md`](../compat/allocator/README.md) and
  [`crabc-mimalloc/UPSTREAM.md`](../crabc-mimalloc/UPSTREAM.md).

The joint POSIX process-state workload is described in
[`owned-posix-composition.md`](../compat/x86_64/owned-posix-composition.md).
