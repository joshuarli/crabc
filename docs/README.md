# Documentation router

This directory contains durable cross-cutting design, evidence, and historical
records. Keep executable-harness instructions beside the harness that owns
them; do not duplicate their command contracts here.

## Current project contract

- [Project scope](../SCOPE.md) — governing Linux/AArch64 doctrine and
  non-goals.
- [Compatibility profile](../COMPATIBILITY-PROFILE.md) — public support and
  limitation boundary.
- [Active TODO](../TODO.md) — the only living backlog.
- [Generated compatibility dashboard](../COMPATIBILITY.md) — current measured
  status; never edit it by hand.
- [Agent/project handoff](../AGENTS.md) — code map, development commands, and
  document precedence.

## Design and evidence

- [Native `crabc-rs` design](design/crabc-rs.md) — current Rust-facade
  architecture and boundary rules.
- [Rust-subsumption evidence](evidence/crabc-rs-subsumption.md) — why selected
  C groups have no native Rust wrapper.
- [`compat/crabc-rs/coverage.toml`](../compat/crabc-rs/coverage.toml) — exact,
  machine-readable capability accounting.

## Historical records

- [Runtime delivery plan](history/runtime-plan.md) — M0–M12 chronology and
  historical evidence.
- [`crabc-rs` delivery plan](history/crabc-rs-delivery-plan.md) — facade
  architecture/milestone history.

Historical records preserve rationale but may say “next”, “remaining”, or
“deferred” in their contemporaneous context. They never override `TODO.md`,
the scope/profile, executable contracts, or generated evidence.

## Code-adjacent guides

- C runtime and dynamic loader: [`libc/README.md`](../libc/README.md),
  [`ldso/README.md`](../ldso/README.md), and [`compat/ldso/README.md`](../compat/ldso/README.md).
- ABI and loader inventory: [`compat/abi/README.md`](../compat/abi/README.md)
  and [`compat/loader/README.md`](../compat/loader/README.md).
- Compatibility runners: [`libc-test-harness/README.md`](../libc-test-harness/README.md)
  and the nearest `compat/*/README.md`.
- Rust `std`, Rustix, and LTO evidence: [`compat/rust-std/README.md`](../compat/rust-std/README.md),
  [`compat/rustix/`](../compat/rustix/), and [`compat/lto/README.md`](../compat/lto/README.md).
- Performance method and active optimization frontier:
  [`design/performance.md`](design/performance.md) and [`compat/perf/README.md`](../compat/perf/README.md).
