# Performance methodology

This document owns measurement policy and optimization doctrine. Harness
commands and report layout live in
[`compat/perf/README.md`](../../compat/perf/README.md); active sequencing and
work authorization live in [`plan.md`](../../plan.md). Results are local
evidence, never a universal performance claim for crabc or musl.

Native Linux/x86-64 is active. Use the exact `[musl_native]` snapshot in
`compat/upstreams.toml` for its C runtime oracle. The paused AArch64 route
retains `[musl]` 1.2.6 and its historical contract; do not run or alter that
lane for this campaign. Rustix is the separate native-facade comparison input,
not a substitute for a musl C-libc comparison. Glibc is neither an oracle nor
a fallback.

## Current authorization and implementation status

**2026-10-30: non-allocator simplification first; all allocator work frozen.**
Do not launch allocator engine benchmarks, port qualification, tuning or
promotion. Whole-runtime tests may use the unchanged accepted C backend and
must report, not hide, its contribution. Frozen allocator failures are recorded
without opening a development campaign. Existing allocator design/milestone
contracts remain preserved, not waived or activated by this document.

The owner now requires syscall ceiling **R**, not 2R, and retired-user-instruction
ceiling **1.10R** under a matched LLVM backend. S1 must implement collection,
producer/reader checks and release gates together. The release gate and the
syscall reader now enforce R and 1.10; no producer writes instruction fields
yet, so every runtime row reads as unavailable until S1.3 lands. Per-syscall classification already rejects unresolved
differences, but that is not the permanent numerical no-extra-calls contract.
An old passing report therefore cannot establish the new requirements.

Focused development checks are required early, with the relevant behavioral
checks, rather than after complete qualification. Full release evidence still
requires its correctness admission. Missing PMU access or a blocked qualification
chain is reported explicitly; neither becomes a passing instruction result.

## Measurement contract

The existing active entry points are `./scripts/dev-x86_64.sh perf-c` and
`perf-native`; see the harness README for actual flags. S1 supplies the focused
development path through existing machinery. Do not invent command support or
relax a smoke's budget label to make it appear qualified.

For the x86 C supplied-product adapter, compile each unchanged C application/DSO
source into an object **once**, then link those exact objects through each
provider's driver/CRT/runtime with equivalent link mode and inputs. Keep the
object, headers, command, source hash, linker trace, build ID, `PT_INTERP`,
`DT_NEEDED` and complete staged runtime identity. Provider CRT/runtime bytes
may differ by design; their cost must not disappear from whole-process results.
Do not confuse this with the paused AArch64 interpreter-patching route.

`perf-native` compares direct `crabc-rs` and Rustix operations. Keep its compiler,
feature/dependency graph and shared fixture recorded. It proves neither C ABI
parity nor whole-runtime performance against musl. Do not use facade wins to
compensate for failing C runtime rows.

Full x86 performance runs require the current source's validated correctness
profile through `capability.accounting`, not a status assertion or a receipt
for another revision. Retain source/product/artifact identities and raw logs,
recompute derived results, and distinguish development, smoke and release runs.
A later full-profile receipt must not silently replace the correctness receipt
that admitted an earlier measurement. Preserve these properties while S2
consolidates duplicated readers and bookkeeping.

Reports and raw samples remain ignored local evidence in the existing work/report
locations. Compare only matching fixture, host, product and sampling contracts.
Keep one shared result format per genuine measurement boundary, not a new schema
or receipt reader for each symbol.

## Acceptance bounds

These are required active-x86 bounds. They must be implemented and tested in S1
before a report can claim compliance; the AArch64 contract remains unchanged.

| Metric | Requirement |
| --- | --- |
| Syscalls | Candidate <= reference for each equivalent deterministic marked region and whole-process workload. Reference zero requires candidate zero. Retain per-syscall calls/errors and explain every difference. |
| Retired user instructions | Candidate/reference <= 1.10 for the actual measured operation and separately for startup/first-use. Lower is better; there is no 0.90 lower acceptance floor. |
| CPU | Retain per-row one-sided 95% upper ratio <= 1.00, with 0.90 reported only as a non-gating target. |
| PSS and `memory.peak` | Retain per-row one-sided 95% upper ratio <= 1.00, with raw totals and the existing collection protocol. |
| Linked footprint/structure | Report final linked sections and all runtime images; meet the explicit S0 simplification budgets independently of instruction/CPU results. |

No geomean offsets a failing selected runtime row. Reference/candidate error
or behavior differences need semantic investigation; fewer calls are accepted
only with retained semantics. Classifying an extra call does not exempt it from
the R ceiling. Policy/hardening mismatches are separate labeled comparisons,
never a silent relaxation of the compatibility target.

Gate ownership remains the existing `compat/perf/x86_64_evidence.py`,
`compat/x86_64/performance_release_gate.py`, producer and their tests. Consolidate
limits into shared definitions rather than duplicating constants. Migrate old
report versions explicitly; absent instruction data is unavailable, not zero.
Required regressions include zero-to-one syscall failure, an extra nonzero call,
a ratio above 1.10, missing/unreliable counters and backend mismatch, plus valid
reductions and boundary values. Preserve raw rejected inputs.

Frozen allocator promotion bounds and source-fidelity obligations remain in
`compat/allocator/`; do not modify them while implementing runtime bounds.
Allocator-only failures cannot be presented as passes or erased from full-runtime
reports, but do not make native allocator milestones prerequisites for S5.

## Matched compiler backend

Build **musl itself** with a clang whose LLVM major version equals the pinned
rustc's (`rustc -vV`), using musl's own `configure` optimization defaults.
Exact revision equality is not required: rustc ships its own LLVM fork and no
clang release is built from it. A different major, or a musl GCC wrapper, makes
the comparison `unmatched` and diagnostic only. Record rustc verbose
version, Clang/LLVM versions and source revisions/patches, linker identity,
target triple/CPU/ISA features, optimization/LTO, TLS and relocation models,
visibility/interposition, panic/unwind, hardening and final link settings.
The frontends remain different: common LLVM does not guarantee identical IR or
machine code. Unresolved backend differences make the result diagnostic only.

Keep production Rust/upstream pins unchanged. A separately pinned comparator
compiler/image may be added under S1; do not silently update the runtime or
start a whole-toolchain project. Record any unavoidable backend limitation.
Compare equivalent product configurations and algorithms; whole-runtime musl
comparisons and same-algorithm C/Rust studies answer different questions.

For C microbenchmarks, retain external-call/no-builtin controls so the compiler
cannot fold away the libc operation. Keep fixture LTO from selectively absorbing
one backend. Measure ordinary optimized application builds separately. The fixed
Rust release choices are O3, fat LTO, one codegen unit, panic abort and stripping;
record the actual artifact settings and equivalent C settings, not just intended
Cargo profiles. Build choices cannot compensate for redundant kernel calls or
state machines. Never apply blanket inlining/unchecked access for a score.

## Retired-instruction accounting

Use hardware retired-instruction counters (`perf_event_open`/perf), not static
disassembly length, LLVM IR counts, wall time or source lines. The primary
comparison is **user-mode** work; include vDSO execution and every participating
thread in the selected region. For process/worker cases, define inheritance and
aggregation explicitly. Kernel instructions, when available, are a separately
labeled diagnostic rather than mixed into the user count.

Retain the event identity, privilege scope, CPU affinity, availability,
`time_enabled`, `time_running` and raw samples. Unsupported PMUs, denied access,
counter loss, uncontrolled multiplexing or mismatched scope do not establish
parity. Do not silently substitute simulated counts. Run counter collection
separately from syscall tracing and normal timing.

User-mode instruction counts of a single-threaded row are deterministic: on the
reference host, repeated runs agree to within a few instructions. Require three
runs within 0.01 % and compare them directly; a row outside that spread is
`nondeterministic` and cannot pass. Multi-threaded or scheduling-dependent rows
use repeated paired observations and the one-sided 95 % upper ratio. Never use
the lowest observed sample. When a wrapper (`unshare`, `chroot`, the harness
launcher) runs inside the counted process, subtract the count of the same
wrapper executing a static exit-only binary.

The wrapper and the target must not add value-dependent work to the counted
process. The native timing launcher therefore encodes its raw `wait4(2)` record
with a fixed-cost decimal writer instead of `snprintf`: the same instruction
count is retired whether a field is zero, three digits, or six. Formatting the
child's variable rusage digits inside the counted supervisor moved a trial by
about 20 instructions, more than the 0.01 % allowance. That cost is harness
behaviour, not runtime behaviour; removing it is not a tolerance change.

Measure the selected operation with three iteration counts `N1`, `2·N1` and
`3·N1` (the step procedure is P2 in [`plan.md`](../../plan.md#p2--measure-a-row)):

```text
I(N) = I_fixed + N * I_operation
```

Keep raw counts, validate the fit and account for common loop/harness overhead
symmetrically. A large common application workload must not dilute a libc
regression. Measure minimal startup, first use and teardown independently.
For tiny functions, inspect absolute deltas and emitted assembly as well as
ratios; no implicit rounding allowance waives the 1.10 requirement.

## Syscall accounting

Run a separate fresh `strace -f -qq` process and retain raw calls/errors.
Account for marker operations symmetrically, with distinct whole-process and
marked-region totals and completed-operation denominators. A zero-syscall vDSO
or uncontended synchronization path must stay zero. Startup/loader/finalizer
calls cannot be hidden by reporting only a hot loop.

Use deterministic inputs and controlled schedules for retries, failures,
signals, resolver traffic and synchronization. Uncontrolled contended futex
counts fluctuate with scheduling; keep those runs as stress diagnostics rather
than fabricating an exact equality test. Preserve deterministic uncontended and
controlled-path coverage. Missing or nondeterministic evidence is explicitly
unavailable for exact-count claims, not an excuse to remove inconvenient rows.

Startup rows count the client process only. The launcher parent's own
post-execve `poll`/`wait4`/`write`/exit lines are harness overhead, and their
in-flight `poll` start can interleave on either side of the client's `execve`
line; including them would move a raw total by one between runs without any
runtime change. Loop rows keep the whole-process trace, where the per-op
quotients cancel the same parent lines.

Startup rows also separate the frozen C backend's allocator-attributed calls
(D1) from the judged comparison. The counts route recognises exactly five
signatures by name and identifying arguments: `sysinfo`; the two allocator
option probes (`/proc/sys/vm/overcommit_memory` and
`/sys/kernel/mm/transparent_hugepage/enabled`); the backend's 2.25 MiB
`MAP_NORESERVE` reservation; and its 32-byte `GRND_NONBLOCK` `getrandom`. The
record lists them under `allocator_attributed` and judges the remaining
per-name calls, and their total, against the reference. A same-name call with a
different argument is not attributed and remains an extra judged call.
Instructions stay on the total (D8): the allocator calls are reported, not
subtracted from `ratio_insn`.

## Timing and memory

- Pin a process to an appropriate CPU and record CPU model, kernel, image digest,
  governor/frequency information when available, tool versions, revision,
  commands, environment allowlist, inputs and artifact hashes. Use quiet windows;
  CPU time and instruction counts under load are not automatically clean proof.
- Interleave reference/candidate sample order from a recorded seed. Retain the
  existing full C protocol: at least 31 valid fresh-process pairs after three
  warm-ups, deterministic 10,000-resample one-sided 95% bounds, and three clean
  collector attempts. Keep rejected samples and reasons. Warm is not cold unless
  cache eviction was actually controlled.
- Retain wall time, `wait4` user/system CPU, peak RSS, faults and context switches.
  Keep strace, perf, allocation profiling and memory polling outside timed samples.
  Validate fixture outputs independently of anti-DCE sinks.
- Preserve ready/high-water/continue memory barriers, concurrent RSS/PSS/private
  mapping attribution, a fresh delegated cgroup-v2 `memory.peak`, and its
  post-ready-allocation self-test. No cgroup delegation means unsupported memory
  qualification, not a PSS substitute or a zero value.
- Compare raw PSS/peak totals without subtracting payload, image bytes, page-cache
  charge or accounting batches. Zero reference or nonpositive candidate memory
  cannot qualify. Preserve deterministic paired-bootstrap reconstruction of
  memory bounds and exact raw values.

The existing host-load policy and release protocol remain implemented in the
shared evidence module. S1/S2 may simplify their implementation, not loosen them
to select favorable outcomes. Three clean invocations must pass; a budget label,
report field or green reader test does not substitute for the actual execution.

## Source and linked-footprint accounting

Report shipping implementation, inline/external tests, generated assembly/tables,
third-party code, build/evidence machinery and frozen allocator/AArch64 separately.
Count final `.text`, `.rodata`, `.data`, `.bss`, mapped images and minimal consumer
closure, not just an archive or a stripped ELF. Include startup/helpers actually
linked. Check section GC, archive granularity, exports and LTO boundaries with
link maps. Moving code, renaming modules or deleting tests/comments is not less
runtime complexity. Treat historical deleted-raw-data measurements as leads only.

## Optimization doctrine

For each failing in-scope row, remove redundant syscalls, allocations, locking,
conversion, scanning, mapping, indirection and C-ABI round trips first. Then
choose and prove the simplest scalar representation/algorithm with boundary,
error, alignment and guard-page evidence and active-x86 assembly inspection.
Only a measured residual gap justifies a narrowly scoped specialization/SIMD
path. Do not build a dispatch framework or remove cancellation/errno semantics.

Preserve established math contracts: NaNs, infinities, signed zero, subnormals,
rounding, exceptions, errno and ABI. Cryptographic primitives remain focused
reviewed dependencies; never hand-roll them for performance. Hardening and
ownership/aliasing invariants cannot be weakened to meet a cost budget.

## Standard-library and paused comparisons

Rust-native stock-std, build-std and external dynamic-libc boundaries must be
labeled accurately. Record exact `-Z build-std` invocations, panic strategy,
feature graph and artifacts; a facade LTO witness does not prove optimization
through an opaque dynamic libc. Cargo bench's unwind-capable standard-library
closure is distinct from dependency-free `std,panic_abort` experiments.

The paused AArch64 commands and earlier results remain documented in the
existing harnesses and
[the pre-reset methodology](https://github.com/joshuarli/crabc/blob/fe7f1874289d7f54ef27af4fb639cf307104540f/docs/design/performance.md).
They are preserved history, not work authorized by this x86 simplification phase.
