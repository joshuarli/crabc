# Documentation router

This directory owns durable cross-cutting design, evidence, roadmaps, and
history. Keep executable runner instructions beside the harness that owns
them; this router should explain ownership, not duplicate command contracts.

## Governing project contract

- [Scope](../SCOPE.md) — Linux/AArch64 doctrine and non-goals.
- [Compatibility profile](../COMPATIBILITY-PROFILE.md) — supported and
  intentionally limited behavior.
- [Active TODO](../TODO.md) — the sole living prioritized work list.
- [Agent/project handoff](../AGENTS.md) — code map, source precedence, and
  canonical development commands.
- [Generated compatibility dashboard](../COMPATIBILITY.md) — current measured
  status; generated only, never hand-edited.

## Current design

- [Native `crabc-rs` design](design/crabc-rs.md) — typed facade architecture,
  ownership, safety, and runtime-state boundary.
- [Performance design](design/performance.md) — measurement methodology,
  optimization doctrine, and current cost model.
- [Source-build adapter-sysroot design](design/source-build.md) — completed Lua
  gate and the permanent adapter boundary.
- [Rust-subsumption evidence](evidence/crabc-rs-subsumption.md) — why selected
  C groups have no native Rust wrapper.
- [Lua source-build evidence](evidence/lua-source-build.md) — completed Lua
  isolation proof and its toolchain boundary.
- [`compat/crabc-rs/coverage.toml`](../compat/crabc-rs/coverage.toml) — exact
  machine-readable capability accounting.

## Detailed acceptance contracts

- [Performance completion](roadmap/performance-completion.md) — active
  scorecard and release proof; it does not replace `TODO.md` priority.
- [Software-corpus validation](roadmap/software-corpus-validation.md) —
  sequenced C0–C4 real-software and native-application program after the
  focused scorecard passes.
- [Source-build progression](roadmap/source-build.md) — future CPython
  adapter-sysroot and later crabc-owned CRT/sysroot acceptance stages.

## Historical rationale and naming provenance

- [Runtime delivery record](history/runtime-plan.md) — concise delivery
  provenance and the governing superseded-direction decisions.
- [`crabc-rs` delivery record](history/crabc-rs-delivery-plan.md) — concise
  facade architecture and capability-accounting provenance.
- [Semantic migration record](history/semantic-migration.md) — original blob
  IDs, loss-prevention ledger, and milestone-to-semantic rename map.

Historical records never override root policy, `TODO.md`, machine-readable
contracts, or generated evidence.

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
