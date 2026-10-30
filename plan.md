# Radically simplify crabc before resuming qualification

**Owner direction: 2026-10-30. Simplification first; all allocator work frozen.**
The active scope is the non-allocator runtime, its build/evidence machinery,
and early musl-relative cost measurement. The previous qualification and
native-mimalloc promotion campaign is parked. Do not resume its allocator
lanes, complete one last allocator fix, or continue its broad feature work.

This is a campaign reset, not evidence that simplification, performance parity,
or qualification has been achieved. No runtime or gate implementation changes
are made by the reset itself. The current code still has legacy syscall bounds
and no mandatory retired-instruction gate; S1 must change that honestly.

Start with S0 below, using the accepted C allocator. `campaign-status` describes
existing capability evidence; it does not override this work authorization.
The old plan, decisions, detailed task definitions and campaign log remain in
[Git at the reset baseline](https://github.com/joshuarli/crabc/blob/fe7f1874289d7f54ef27af4fb639cf307104540f/plan.md).
They are historical context, not a second active plan. Do not create an archive
copy or another status/receipt framework to implement this reset.

## Goal

A small, auditable Linux runtime whose required semantics are implemented with
musl-like economy: fewer independent mechanisms, one owner for each mutable
runtime state, thin C ABI adapters, and direct LLVM-visible native operations.
Simplicity, syscall cost, retired instructions and linked footprint are separate
acceptance dimensions. Source bytes alone prove none of the others.

For equivalent selected workloads and a matched LLVM backend, require no more
kernel entries than musl and at most 1.10 times its retired user instructions.
Fewer calls/instructions are welcome; do not add work to obtain literal equality.
Retain the existing CPU and memory no-regression requirements. Preserve ordinary
Unix semantics, C ABI/interposition, cancellation, TLS, hardening and safety.

## Allocator freeze

Until S5 has passed and a separate restart decision has been recorded, all
malloc/allocator development is stopped. This includes the Rust mimalloc port,
C-backend changes or upgrades, alternate allocators, source convergence,
lifecycle repairs, optimization, dedicated profiling/benchmarking, new allocator
tests, allocator-only dead-code cleanup, milestone/receipt tooling, shadow
integration, native promotion and merging parked allocator branches. Calling
such work simplification, a prerequisite, or a correctness follow-up does not
make it authorized.

Keep the accepted C backend and its configuration selected. Freeze
`crabc-mimalloc/`, `compat/allocator/`, allocator-only tests and integration
modules, and the native/default-backend selection. Preserve their source,
licenses, known differences, failures, retained reports and parked work.
Ordinary runtime builds/tests may use malloc through the unchanged accepted C
backend, and existing regression checks may detect allocator failures. Recording
such a failure is allowed; starting an allocator investigation is not. S0 may
count the frozen trees separately, without opening a port/codegen campaign.

A runtime change that would require an allocator/lifecycle rewrite must be
reduced to an independent change or parked. Do not silently weaken checks,
replace the allocator, or hide its contribution to a whole-process measurement.
Allocator-only failures remain named blockers for any whole-runtime claim.
They do not become prerequisites for completing non-allocator simplification.

The old G2, A0–A5, M1–M10, T4, allocator P0, O3/O4, D5 and allocator portion
of C0/C1 are parked. Their old dependency edges and automatic-escalation rules
are inactive. Passing S5 does not silently reactivate them: reassess the port's
scope and complexity in a fresh, separately authorized restart plan first.

## Charter

- **Delete mechanisms, not semantics.** Remove superseded product roots,
  duplicated implementations, unnecessary indirection and evidence machinery.
  Do not remove correct supported behavior, safety checks, licensing, or
  behavioral coverage to achieve a size target. Moving code, stripping comments,
  externalizing a dependency or relocating tests is not a simplification win.
- **Measure before growing.** Establish the baseline and lightweight cost checks
  first. Each touched mechanism gets focused correctness and before/after cost
  evidence before merging. Full release qualification remains a later obligation,
  not a prerequisite to discovering or removing needless work.
- **No expansion campaign.** No new public surface, targets, platform abstraction,
  provider system, optional backend matrix or framework. Fix a non-allocator
  defect only when needed to preserve the touched contract or unblock a named
  simplification check. Preserve other findings without spawning more lanes.
- **Small scope, one writer.** Use one implementation owner per mechanism and
  an independent reviewer. Parallelize only demonstrably independent reductions;
  an idle agent slot is not a defect. Read-only work is still subject to the
  allocator freeze. Follow [docs/lanes.md](docs/lanes.md).
- **Keep evidence small.** Reuse one runtime driver, declarative case matrices,
  existing report formats and shared provenance/validation helpers. No new
  runner, validator, receipt, feature or prose narrative per symbol/artifact.
  Do not replace many special cases with a generic framework of comparable size.
- **Preserve boundaries.** Linux/x86-64 native only; no AArch64 execution or
  emulation. Keep frozen AArch64 inputs, source pins and the Rust nightly.
  A separately pinned Clang/LLVM comparator may be added for S1; do not upgrade
  production pins or silently pretend incompatible backends are matched.
- **Respect holds.** A denied action stays stopped at its exact scope; no retry
  or rerouting. No host-policy changes, rentals, reboot, destructive cleanup,
  releases or publication. The owner's explicit authorization permits this
  campaign-documentation commit directly to `main`, not unattended future pushes.
- **Honest status.** Missing counters, failing tests, old receipts and missing
  artifacts are unavailable/blocked, not passing. A corrected upstream comparator
  is explicitly separate from the pristine pin. Never tune inputs or thresholds
  after seeing failures to manufacture a pass.

## Sequence

All items below are **not yet executed by this reset**. The order is S0, then
S1 and independent S2 work, followed by measured S3/S4 reductions and S5 review.
Do not make a full old qualification cohort the admission barrier for S0–S4.
Focused behavioral checks for each affected path are mandatory throughout.

### S0 — Baseline and choose what to remove

Use the current accepted-C x86 products and exact `[musl_native]` source.
Record the commit, product/features, toolchain, link modes and runnable checks.
Inventory these categories separately: shipping non-allocator implementation;
inline and external tests; generated tables/assembly; evidence/build tooling;
frozen allocator; frozen AArch64; third-party source. Do not compare a whole
Rust tree containing tests with a stripped C runtime and call it code expansion.

In one compact table here, record per subsystem: handwritten non-comment source
and bytes, production modules/feature variants, independent mutable-state owners,
runtime bridges, bespoke runners/readers, and linked `.text`/`.rodata`/`.data`/
`.bss`. Include all runtime images and compiler helpers actually shipped. Inspect
minimal hello, syscall, stdio, pthread and dynamic-loader consumers with link
maps; report reachable footprint separately from archive and whole-tree size.

Compare like-for-like musl components, then identify the largest avoidable
mechanisms. Establish explicit before/after reduction budgets for the selected
non-allocator areas before editing them; justify budgets by concrete duplicates
and obsolete paths, not a blanket language line-count ratio. Do not quietly
relax a budget later. The first inventory is bounded work, not a new accounting
product or an excuse to enumerate every symbol again.

**Done:** a measured baseline, a ranked deletion/consolidation list, numerical
budgets and a small set of reproducing commands exist. Old sizes or throughput
numbers whose raw data was deleted are historical leads only, never this baseline.

### S1 — Make the cost contract executable early

Extend the existing runtime performance machinery rather than creating a parallel
benchmark platform. Provide focused development measurements without a full
qualification receipt, clearly distinct from release evidence. Keep correctness
admission for actual release claims. A smoke must not be relabeled qualification.

Implement and test the [cost contract](#cost-contract): change the explicit
runtime syscall ceiling from 2R to R, preserve zero-reference behavior, and add
retired-user-instruction measurement and a 1.10 ceiling. Update the existing
producer, reader, release gate and their tests together; explain and migrate old
reports rather than silently accepting reports without the new fields. A single
shared definition should drive these limits. Preserve CPU/memory gates.

First cover thin descriptor/process wrappers, vDSO clocks, memory/string routines,
uncontended synchronization, stdio batching and loader startup/lookup. Grow the
same declarative matrix to resolver and representative real consumers as the
changed paths require. Do not launch allocator benchmarks. Whole-runtime rows
using the accepted C allocator remain visible and correctly attributed.

**Done:** tests reject an extra syscall, zero-to-one syscall regression,
`instructions_ratio > 1.10`, absent counters and toolchain mismatch; legitimate
reductions pass after correctness/difference review. At least a focused real
native comparison exercises collection through readback. Unavailable hardware
is a named blocker to instruction-parity claims, not fabricated evidence.

### S2 — Shrink the build and evidence machinery

Consolidate `scripts/dev-x86_64.sh`, repeated `compat/x86_64` readers, product
builders and per-artifact glue into the smallest existing shared mechanisms.
Keep the dispatcher thin. Keep declarative input/case tables, shared process
execution, shared provenance checking and a small number of report readers.
Separate build, run and compare sufficiently to reproduce a failure directly.
Avoid a new plugin/task/receipt framework. Leave frozen allocator tooling alone.

Before removing a runner, check feature selection, glob discovery, subprocess
calls and manual documented consumers. Port its behavioral cases to the common
matrix and compare outcomes, including negative/error cases. Keep real malformed
ELF, TLS, cancellation, errno, interposition and lifecycle tests; delete redundant
source-literal and prose-count checks, not the behavior they were meant to prove.
Preserve clean-commit/artifact/source binding for release evidence while making
ordinary development independent of receipt bookkeeping.

**Done:** selected runner/reader and handwritten-tooling budgets decrease, the
retained case inventory is accounted for, commands remain reproducible, and
focused tests plus the non-allocator merged-tree checks pass. Raw failed reports
are retained. No new per-artifact proof system replaces the removed one.

### S3 — Simplify runtime composition and linked footprint

Review `libc`, `ldso`, `crt`, `crabc-core` and `crabc-rs` against their equivalent
musl mechanisms. Retire obsolete private/fixed-graph product roots once their
behavioral cases run through the real product. Share architecture-neutral logic
where this actually removes duplication, keeping architecture assembly/layout
leaves explicit. Do not grow a generic platform layer or alter paused AArch64.

Keep one process owner each for errno, TLS/thread lifecycle, stdio and loader
state. Keep raw syscall and vDSO operations direct, and C sentinel/errno adaptation
at the C boundary. Do not route direct native Rust operations through C just to
reduce a source-file count. Remove adapters, allocations, locks, scans and copies
that exist only to connect duplicate internal representations.

Evaluate a **single installed loader/libc ELF image** with internal Rust modules
against the current split images/RuntimeV1 arrangement. This is an experiment,
not an instruction to smash crates together or delete bootstrap invariants.
Prove early relocation without ordinary TLS/allocator services, one owner of
process state, startup/finalizer order, symbol interposition, static/static-PIE
and dynamic products, `dlopen`/TLS and hardened loading. Keep a unified product
only if it demonstrably removes bridges, mappings and maintenance/code cost.
Otherwise retain the simpler measured split and record the specific necessity;
no second permanent backend or runtime dispatch option. Any required allocator
change parks that experiment rather than lifting the freeze.

Audit archive-member granularity, export retention, linker GC, LTO boundaries,
bootstrap duplication and panic/unwind dependencies using final link maps. Do
not mistake a stripped file-size win for less executed work or remove a required
ABI symbol to make a tiny test smaller.

**Done:** the selected composition and source/footprint budgets have measured
reductions, obsolete mechanisms are removed rather than renamed, one-owner
invariants and affected behavioral/hardening cases hold, and no allocator or
paused-target change is hidden in the patch.

### S4 — Remove residual work by mechanism

Use S1's per-operation and startup measurements to rank the remaining gaps.
For each, compare the musl algorithm and emitted machine code; remove redundant
syscalls, allocation, conversion, locking, scanning and indirection before adding
specialized code. Preserve musl-compatible error and cancellation behavior; a
raw syscall-only stand-in is not a fair implementation of a POSIX entry point.

Keep each patch small, with before/after dynamic instruction and syscall counts,
linked footprint and focused semantic tests. Inline or specialize only where
measurement earns it. Do not apply blanket `inline(always)`, unchecked pointer
operations, SIMD dispatch or weakened atomic orderings to chase a percentage.
List allocator-attributed failures without opening allocator work.

**Done:** all selected deterministic non-allocator rows satisfy the syscall and
instruction bounds under matched inputs; broader and hardened-profile results
remain separately visible. No aggregate average hides a failing selected row.

### S5 — Simplification acceptance and restart boundary

Require S0–S4 evidence on the integrated revision: actual eliminated runtime
mechanisms and repeated evidence machinery, the precommitted reduction budgets,
one-owner composition review, final linked footprint, focused correctness and
matched cost results. A cleaner directory layout, more declarations of ownership,
fewer comments/tests or a smaller plan is not proof that the runtime is simple.

Run the retained relevant non-allocator suites through the unchanged accepted-C
runtime. Preserve all open correctness/hardening failures and show test coverage
before/after. A fresh review must find no new redundant layer added to replace a
removed one. Write one concise result table here: measured changes, commands,
source/artifact identities and blockers. No per-leaf status narratives.

Do not require native allocator milestones to close this non-allocator phase.
Conversely, a frozen-allocator or unsupported-counter row cannot be called a
pass or used to claim whole-runtime performance. Full x86 qualification and
public support remain separate future work. Only after S5 passes may a separate
owner decision reopen malloc work with an intentionally smaller restart scope.

## Cost contract

[Performance methodology](docs/design/performance.md) owns measurement details.
These are mandatory targets for the active non-allocator campaign, **not claims
that the current tools already enforce them**:

| Dimension | Required comparison |
| --- | --- |
| Kernel entries | Candidate <= musl in each equivalent deterministic hot region and whole-process workload; musl zero means candidate zero. Explain every per-syscall/errno difference; classification does not waive extra calls. |
| Retired instructions | Candidate/musl <= 1.10 for measured user-mode work per operation and separately for startup. Faster/smaller than 0.90 is not a failure. Include all participating threads; do not hide extra worker work. |
| CPU and memory | Retain existing per-row no-regression bounds and release statistical requirements. Instructions do not substitute for latency, CPU, RSS/PSS or peak memory. |
| Footprint and structure | Meet S0's explicit reduction budgets; report final linked sections, all runtime images, and handwritten implementation separately from tests/generated/frozen source. |

Build the musl runtime itself with pinned Clang using a backend matched to
rustc's LLVM revision/configuration; matching only the application compiler or
LLVM major version is insufficient. Record exact tools/versions/revisions,
patch differences, CPU/ISA features, optimization/LTO, codegen units, TLS,
relocation, visibility/interposition, panic/unwind and hardening settings.
Clang and rustc remain different frontends; matching LLVM does not promise
identical instruction sequences. Unmatched comparisons are diagnostic only.
Keep same-algorithm C-vs-Rust tests separate from whole-runtime comparisons.

Compile each C workload object once and link it through both owned products
with equivalent link mode and inputs. Use external-call/no-builtin controls for
libc microbenchmarks so the compiler cannot erase the tested operation; measure
normal application optimization separately. Do not substitute GCC-built musl
and label the result matched LLVM.

Count hardware **retired user instructions**, not disassembly length, LLVM IR
operations or elapsed time. Count the entire selected region, including vDSO and
participating threads. Retain counter event/privilege scope, availability,
time-enabled/time-running, affinity and raw values; reject unsupported or
unreliable/multiplexed measurements for parity claims. Keep kernel instruction
counts separately labeled. Run tracing, counters and timing in separate passes.

Measure steady-state cost with bounded counters or multiple iteration counts
`I(N) = I_fixed + N * I_operation`; validate the fit and retain raw measurements.
Do not let common application/loop overhead dilute a libc regression. Measure
empty startup, first-use and teardown separately. Tiny paths also need absolute
deltas and assembly review; a rounding allowance cannot silently waive 1.10.
Use stable repeated paired measurements and confidence bounds, not best samples.

Use controlled inputs/schedules for retries, signals, resolver traffic and
threading. Uncontrolled futex scheduling is not an exact syscall-count oracle;
retain it as a separately labeled stress diagnostic, not a fabricated parity
pass. Compare equivalent hardening profiles or explicitly report the policy
mismatch. Never disable safety to obtain parity. Markers/harness work must be
accounted for symmetrically and never erase startup cost.

## Runtime hardening

The October 26 hardening requirement remains mandatory before any future x86
qualification/public-support claim. Keep the compatibility products and the
separately identified hardened profile: PIE, non-executable stacks, page-level
W^X, effective RELRO, eager binding and explicit library search rules, as defined
in [COMPATIBILITY-PROFILE.md](COMPATIBILITY-PROFILE.md#runtime-hardening-profiles)
and [architecture](docs/design/architecture.md#native-x86-64-runtime-hardening).
The old [SEC0–SEC3 tasks](https://github.com/joshuarli/crabc/blob/fe7f1874289d7f54ef27af4fb639cf307104540f/plan.md#runtime-hardening)
remain completion requirements, not authority to restart an expansion campaign.
Simplify existing owners and run their relevant security regressions throughout.

## Qualifying a revision

Full release qualification remains parked until simplification review. Focused
checks never change capability, support or native-default claims. For a future
qualification, use one clean immutable commit and detached cohort worktree;
rehash sources/products and rerun receipts for that commit. Lane evidence does
not prove a merged tip. No copied status field supplies missing physical evidence.
Keep `COMPATIBILITY.md` generated and the complete behavior/ABI requirements in
[docs/completion-requirements.md](docs/completion-requirements.md).

## Preserved checkpoint and holds

At the October 28 pause, the last accepted source was `44451281a`. The matched
`4d3b9091a` cohort and resolver family passed, but the dynamic Lua receipt reader
timed out and the qualification chain was incomplete. No promotion was made.
These are historical observations, not current-source qualification.

The Lua replay needs a cause and focused repair if it blocks a simplification
check; do not weaken receipt validation. POSIX `math/pow` and C-ABI admission
remain held under the
[October 25 decisions](https://github.com/joshuarli/crabc/blob/fe7f1874289d7f54ef27af4fb639cf307104540f/plan.md#decision-log):
24 oracle versus ten candidate diagnostics, with the fourteen finite subnormal
exponent-one diagnostics accounting for the difference. Raw evidence is at
`.work/tmp/pow-discriminator-ad7e18d35`. Do not trim the complete libc-test
aggregate, change backends, invent an exception or credit incomplete admission.
The allocator diagnostic denial remains parked, additionally subject to the
new freeze. No new diagnostic is authorized solely by restating an old failure.

All unmerged branches, including `archive/*`, `cohort/*`, `integration/*`,
`lane/*`, `parked/*`, `proof/*`, `recovery/*` and `review/*`, remain parked.
Reconcile non-allocator work with `git cherry main BRANCH`, tests and the old
campaign log before any integration. Preserve allocator branches without merging.

Remaining `.work/wt/*` checkouts may contain parked source or unique physical
evidence; their cleanup audit is incomplete. Previously denied cache removal in
`combined-profile` and `abi-owner-proof-fixed` remains parked. Automatic review
also rejected removal of `.work/allocator-x86_64/target/x86_64-unknown-linux-musl`,
`.work/allocator-x86_64/target/miri` and `.work/allocator-x86_64/target/debug`;
the filesystem denied removal of `.work/x86_64/kache`. Do not retry or reroute.

Ordinary worktree removal was refused under `.work/wt/`. Git reported
`Directory not empty` for `abi-math-graph-replay`, `hardened-profile`,
`tool-structural-fixtures`, `mold-oracle-traces`, `pthread-clock-resume`,
`stdio-plt-proof`, `abi-signal-replay` and `musl-upstream-refresh`; it reported
`Permission denied` for `abi-component-proof`, `abi-crt-locale-proof`,
`abi-declaration-symbol-rows`, `abi-main-consumer`, `abi-math-feature-proof`,
`abi-bootstrap-math-proof`, `abi-private-member-visibility`, `verify`,
`campaign-verification`, `campaign-integration`, `dynamic-loop`,
`compiler-helper-trace`, `entropy-static-owner`, `fmemopen-oracle`,
`calendar-zone-oracle`, `clock-gap`, `feature-proof`, `native-tool-readers`,
`static-authority-mold`, `native-build-tools`, `wordexp-oracle-refresh`,
`r1-daemon-order`, `r7-builtins-visibility`, `stdio-oracle-refresh`,
`syslog-resume`, `resolver-alias`, `posix-ipc-resume`, `runtime-pthread-resume`,
`runtime-resolver-resume`, `runtime-text-resume`, `runtime-facade-proof`,
`lua-static-metadata`, `lua-static-relro`, `resolver-complete-readability-proof`,
`resolver-readability-proof`, `lua-static-got`, `lua-static-resume`,
`unwinder-tool-readers`, `cache-dependency-trace`, `protocol-oracle`,
`locale-null-base`, `oracle-shared-link`, `abi-selector-proof`,
`abi-vfork-private-member`, `abi-mold-repairs`, `abi-witness-surface`,
`abi-private-visibility`, `resume-arena`, `resume-secure`,
`timer-creator-cancellation` and `m7-visitation-commands`. Preserve these paths
without retrying or routing around the refusals; Git unregistered all except
`abi-component-proof` despite leaving the directories. `Permission denied` also
prevented removal of `.work/wt/feature-alias-receipts`,
`.work/wt/lua-linked-cohort` and `.work/wt/combined-child-drain`.

Failed runs and diagnostic logs moved during cleanup are in `.work/retained/`,
grouped by original checkout. Moved source-bound receipts cannot be replayed at
their old paths; regenerate before relying on them. At closeout 45 worktrees
remained registered and 109 checkout directories remained on disk. This reset
neither removes these artifacts nor resolves their custody/refusal boundaries.

## Reference

### Fixed contracts

Linux/x86-64 little-endian, kernel >= 5.10; exact `[musl_native]` oracle;
AArch64 and its frozen manifests unchanged. Preserve `dlclose`'s retained-object
behavior, failed-load rollback, interposition, pthread/cancellation/TLS and
selected error conventions. The runtime leaves process THP policy unchanged.
Accepted C `libmimalloc-sys` 0.1.49 (mimalloc v3.3.2) is distinct from the frozen
v3.5.0 port oracle. No allocator upgrade or redesign is selected by this plan.

The frozen AArch64 baseline is
`compat/x86_64/aarch64_frozen_baseline.json` and its three digested inputs:
`compat/crabc-rs/coverage.toml`,
`compat/abi/musl-1.2.6/aarch64/manifest.json` and
`compat/abi/musl-1.2.6/aarch64/headers.tsv`. Never refresh them to absorb drift.
Keep upstream licenses, pins, corrections and the reviewed unwinder dependency
graph; consult the existing design documents rather than expanding them here.

### Completion requirements

[Scope](docs/scope.md), [selected behavior](COMPATIBILITY-PROFILE.md),
[completion requirements](docs/completion-requirements.md),
[qualification chain](compat/x86_64/qualification-chain.md),
[architecture](docs/design/architecture.md),
[allocator design (frozen)](docs/design/allocator.md) and
[performance methodology](docs/design/performance.md) retain their contracts.
Historical allocator requirements are not authorization to work during the freeze.

## Allocator lifecycle recovery

Parked in full. The prior recovery checkpoint, reproductions, upstream errata
and ownership investigations remain in
[the baseline plan](https://github.com/joshuarli/crabc/blob/fe7f1874289d7f54ef27af4fb639cf307104540f/plan.md#allocator-lifecycle-recovery)
and their original files. Do not resume them under the former escalation rules.

## Optimization and promotion

S1/S4 permit focused non-allocator simplification measurements now. Old O1/O2
qualification/public support and O3/O4 allocator promotion are not active work.
No release claim is authorized by reducing source, passing an isolated benchmark
or completing this documentation change.

## Acceptance

S5 is the non-allocator simplification gate. Public qualification and allocator
restart are distinct decisions with distinct evidence; neither is inferred from
S5. The old D1–D6 schedule is superseded, not marked completed.

## Decisions

### Decision log

- 2026-10-30: owner requires radical simplification before further malloc work.
  Freeze every allocator workstream, keep the accepted C backend unchanged, and
  replace the expansion-first/cleanup-last sequence with S0–S5. Require syscall
  ceiling R and retired-instruction ceiling 1.10 under matched LLVM, retaining
  CPU/memory and correctness/hardening obligations. Narrow independent changes
  replace fill-every-slot orchestration. Old evidence/history remains in Git and
  retained artifacts; no new code, measurements or qualification is claimed here.

## Campaign log

Only the latest concise S0–S5 result/blocker table belongs here. Older narrative
history stays in Git at the linked reset baseline. **No S0–S5 results yet.**

## Non-goals

Allocator work; new capabilities or platforms; AArch64 execution/emulation;
weakening semantics, safety, hardening or evidence; a new validation framework;
whole-toolchain integration; physical NUMA/huge-page qualification; automatic
publication; or treating documentation reduction as runtime simplification.

## For the owner afterwards

Review measured S5 results before choosing the next scope. The native allocator
is not presumed to be the next task or eventual default merely because the old
campaign planned its promotion.
