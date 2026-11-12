# crabc plan

This file is the only active plan. It holds the current sequence, the rules
that bind it and the owner decisions still in force. Git holds everything
else: the S0–S5 simplification runbook, its baseline tables, rejected attempts
and per-step results are in `plan.md` at `6a1761f84`.

## Goal

A small, auditable Linux runtime with ordinary Unix semantics and musl-like
economy: few mechanisms, one owner per piece of process state, thin C ABI
adapters, direct syscall/vDSO paths, and the selected hardening. Semantics, C
ABI/interposition, cancellation, TLS, errno and hardening are never traded for
cost.

## Status

S0–S5 are accepted on structure, correctness and hardening (S5 at
`1faf5ab6f`). R0 rebuilt the products. R1 closed under D21 without code
changes. R2 is in progress: D20 removed the duplicate `mem*` bodies
(`6c0debc0b`) and D22 removed the per-symbol ABI selection engine
(`257426f20`); the fresh correctness run follows the export-delta change.

## Sequence

1. **R2 — qualification correctness.** Run
   `./scripts/dev-x86_64.sh qualification-candidate --work DIR --profile correctness`
   on a clean commit in the pinned image. Its seven gates must pass. Iteration
   may resume across commits that leave the product-input set
   (`compat/x86_64/source_seal.py`) unchanged; acceptance needs one complete
   run whose summary is `fresh: true`. A correctness receipt is not a
   full-chain result.
2. **R3 — performance.** On a quiet host, run the `perf-c` roster and
   `perf-native --mode full`; `perf-c check` must report no release blocker
   under the [cost contract](#cost-contract). Before R3 the owner sets the
   relaxed CPU and memory bound (D21). Re-run the counts rows on the same tip
   and report every row, including `allocator-attributed` calls.
3. **R4 — full qualification.** Run the full chain on the R2/R3 tip. All eight
   gates must pass before promotion or public-support claims, which remain
   separate owner decisions.

A track that needs frozen allocator work, a pin change or AArch64 work is
parked and reported. A deferred, failed or unavailable gate is never a pass.

## Allocator freeze

**Partially lifted (2026-11-08).** The crabc integration around the accepted C
backend is open: lifecycle, initialization, option and wrapper code in `libc/`
around pinned upstream mimalloc v3.5.0 (`[mimalloc]` in
`compat/upstreams.toml`). Work there needs a failure or allocator-attributed
cost that an R1–R4 gate reports. The upstream C source stays unedited.

| Open | Still frozen |
| --- | --- |
| Investigating, reproducing, profiling and fixing allocator failures and allocator-attributed costs that an R1–R4 gate reports | The Rust mimalloc port under `crabc-mimalloc/`, the `compat/allocator/` harness, its receipts and milestone tooling |
| Changing the crabc glue around the C backend, with behavior tests | Editing the upstream C source; any version change beyond v3.5.0; changing the native/default backend selection |
| Allocator-attributed counts rows and the focused tests that cover them | Alternate allocators, native-shadow products, promotion, merging parked allocator branches |
| Building and linking the C backend in ordinary products and regression suites | Allocator benchmarks, including the `allocator_live` and `allocator_after_ready` perf modes |

Allocator-attributed rows and syscalls stay labeled `allocator-attributed` in
every report and are judged like every other row. The old G2, A0–A5, M1–M10,
T4, allocator P0, O3/O4 and allocator part of C0/C1 stay parked.

## Cost contract

[docs/design/performance.md](docs/design/performance.md) owns measurement.

| Dimension | Rule |
| --- | --- |
| Syscalls | Candidate <= musl per row, per operation and whole process. Reference zero requires zero. Every per-name difference is explained; an explanation never waives an extra call. |
| Instructions | `ratio_insn <= 1.10` per operation and for startup, counting vDSO and all threads. `startup`, `dlopen_graph` and `loader_dynamic_tls_growth` are reported, not gated (D21). |
| Matched backend | Reference musl is built by clang with the same LLVM major as the pinned rustc; otherwise the row is `unmatched` and diagnostic. |
| Determinism | Single-threaded counts repeat within 0.01 %. Scheduling-dependent rows use repeated pairs and a one-sided 95 % bound. |
| CPU and memory | Relaxed bound set by the owner before R3 (D21); measured only on a quiet host. |

Fewer calls or instructions than musl are always fine; never add work to reach
equality.

## Runtime hardening

PIE, non-executable stacks, page-level W^X, effective RELRO, eager binding and
explicit library search rules stay mandatory, as defined in
[COMPATIBILITY-PROFILE.md](COMPATIBILITY-PROFILE.md#runtime-hardening-profiles)
and [architecture](docs/design/architecture.md#native-x86-64-runtime-hardening).
A change runs the hardening cases for its area. A cost win that weakens
hardening is rejected.

## Rules for every agent

1. **Keep semantics, delete mechanisms.** Moving, renaming or splitting code is
   not a reduction.
2. **Never weaken a check to pass.** If a test is wrong, show why; the
   coordinator decides.
3. **Checks test behavior (D22).** A reader that only asserts ELF forms,
   seals or another receipt's structure is deleted, not repaired. No new
   runner framework, receipt format, schema, validator or per-symbol proof.
4. **One writer per file set.** Edit only the files your brief allows.
5. **Native x86-64 only.** Never run, emulate or modify AArch64 paths or the
   frozen inputs of `compat/x86_64/aarch64_frozen_baseline.json`.
6. **Pins stay.** `rust-toolchain.toml`, `compat/upstreams.toml` and the Alpine
   base digest do not change. Do not run `./scripts/dev-x86_64.sh image`
   unless a step says so; a rebuild deletes the pinned image and must be
   followed by a re-pin of `compat/x86_64/core_image.py` in its own commit.
7. **Nothing outside the repository.** No host changes, release or publication.
8. **Honest status.** Missing counters, failing tests and unbuilt products are
   `blocked` or `unavailable`, never `pass`.

## Standard procedures

### P1 — Change runtime code

Pin the touched contract with a behavior test run against the unchanged code
first (a bug fix's test fails first). Measure affected rows with P2 before and
after; no row may get worse except under D21. Re-run the area's behavior and
hardening tests. Forbidden shortcuts: blanket `#[inline(always)]`, unchecked
access for speed, weaker atomics, SIMD dispatch frameworks, skipped
cancellation points, raw-syscall replacements of POSIX entry points, disabled
hardening.

### P2 — Measure a row

Use `perf-c counts` ([compat/perf/README.md](compat/perf/README.md)). Compile
the workload once and link it against both runtimes in the same mode. Count
`instructions:u` at `N1` and `N2 = 2·N1` (and `3·N1` for linearity, within
0.5 %); per-operation cost is the difference quotient. Count syscalls with
`strace -f` in a separate run. Never take best-of-N; never mix counters,
`strace` and timing in one process.

### P3 — Delete a mechanism

Find every consumer (`rg` the name and each file stem, including dispatcher
arms, `parity.toml`, docs and `scripts/lanes/`). A consumer either dies with
the mechanism, or needs a behavior that another test covers, or needs a
behavior with no other test: move that behavior into the family's existing
test first and run it on the current code. Delete in one commit with no stub
or shim; the body lists lines removed and added and the checks run.

### P4 — Stop and escalate

Stop and report when a required command fails for a reason your change does not
explain, when you would need a file outside your brief, frozen allocator,
AArch64 or pin work, or a weakened check, or when a tool denies an action
(record the exact command and message; do not retry it in another form).

## Preserved checkpoint and holds

- POSIX `math/pow` and C-ABI admission stay held under the
  [October 25 decisions](https://github.com/joshuarli/crabc/blob/fe7f1874289d7f54ef27af4fb639cf307104540f/plan.md#decision-log)
  (raw evidence in `.work/tmp/pow-discriminator-ad7e18d35`). Do not
  trim the libc-test aggregate, change backends or invent an exception.
- Unmerged `archive/*`, `cohort/*`, `integration/*`, `lane/*`, `parked/*`,
  `proof/*`, `recovery/*` and `review/*` branches stay parked; never merge
  allocator branches.
- Nothing under `.work/retained/`, `.work/allocator-x86_64/`,
  `.work/x86_64/kache` or `.work/tmp/pow-discriminator-*` is removed by an
  agent. `git worktree list` is authoritative for worktrees.

## Owner decisions in force

- **D1/D9 — allocator labels.** Allocator start-up and arena calls are labeled
  `allocator-attributed` in every row and reported, never hidden.
- **D2 — generated musl assembly.** The ≈81k lines of `.S` generated from musl
  C and their generators are left alone.
- **D4/D5 — matched backend.** Same LLVM major as the pinned rustc; the
  reference musl is built in a digest-pinned `alpine:edge` builder stage until
  stable Alpine ships that clang.
- **D14 — quiet host.** CPU and memory are accepted only under the host-load
  policy; runs under load are diagnostic.
- **D17 — structure budgets.** libc features 25, ldso features 2, ldso x86
  product lines 11,161, dispatcher commands 720 and 11,000 lines,
  `compat/x86_64` Python 566 files and 270,000 lines, startup syscalls 14
  dynamic and 9 static. Budgets only tighten.
- **D20 — one definition of each `mem*` symbol in `libc.so`.** The loader's
  private `memcpy`, `memset`, `memmove`, `memcmp` and `bcmp` copies, left from
  the split-image era, are removed; the loader uses libc's definitions.
  Self-relocation makes no `mem*` call.
- **D21 — hardening outranks the startup instruction ratio.** Eager binding
  and every loader hardening check stay. `startup`, `dlopen_graph` and
  `loader_dynamic_tls_growth` instruction ratios are reported, not gated; the
  CPU and memory bounds are relaxed to a bound the owner sets before R3. The
  syscall rule and the 1.10 ratio for every other row stand.
- **D22 — qualification checks behavior, not linker output.** R2 machinery is
  cut to checks a caller would notice; form-only readers are deleted rather
  than repaired and replaced by a behavior test where none exists. The frozen
  `compat/allocator/` harness is excluded.

## Results

| Step | Commit | Result |
| --- | --- | --- |
| S5 | `1faf5ab6f` | Accepted on structure (7/7 budgets), correctness (231/231 dynamic cases, static 72-path, 28/28 consumers) and hardening. |
| R0 | `068c22ebd` | Products rebuilt in pinned image `91e0733b…438bb`. |
| R1 | none | Closed by D21: exact traces showed no hardened design reaches 1.10 for startup (38–43k savings vs 54k needed) and TLS growth is allocator initialization ([note](docs/evidence/x86-d16-relocation-transaction.md)). Ratios 1.89, 1.60, 2.57. |
| R2 | pending | In progress. |

## Non-goals

Frozen allocator work; new capabilities, platforms or public surface; AArch64
execution or emulation; weakening semantics, safety, hardening or tests; a new
validation framework; whole-toolchain integration.
