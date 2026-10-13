# Performance methodology

This document owns the measurement policy and optimization doctrine. Harness
commands, workload rosters and report layout live in
[`compat/perf/README.md`](../../compat/perf/README.md); the numeric acceptance
bounds live in code (see [Acceptance bounds](#acceptance-bounds)). Results are
local, ignored reports, never a universal performance claim for crabc or musl.
Musl 1.2.6 is the C runtime oracle; Rustix 1.1.4 is the native-facade
comparison input. Glibc is not measured or used as a fallback. Native x86-64 is
the active target and uses the supplied-product adapter; the AArch64 lane is
paused.

## Measurement contract

The commands in this section are the paused AArch64 route; the active x86-64
equivalents are `./scripts/dev-x86_64.sh perf-c` and `perf-native`. The
contract itself applies to both.

`./scripts/dev.sh perf --label NAME` builds the current release C runtime and
runs one musl-compiled application under staged musl and crabc loaders/libcs.
Only `PT_INTERP` and staged runtime bytes differ. Every timed process is fresh:
the parent captures elapsed wall time and isolated `wait4(2)` user/system CPU,
peak RSS, faults, and context switches. RSS/PSS plus grouped `smaps` mapping
attribution are separately sampled while a 32-MiB allocation set is live. A
fresh delegated cgroup-v2 leaf records `memory.peak` after exit and a second
after-ready probe proves its high-water collector sees post-barrier allocation;
without that delegation the memory row is explicitly unsupported. `strace` is
a separate `timing: false` diagnostic, never a timed sample. Schema-5 reports
keep non-marker whole-process calls separate from calls between the
descriptor-only `CRABC_PERF_BEGIN`/`CRABC_PERF_END` markers; only the latter
describes the selected hot region, with exact calls/errors per operation.

`./scripts/dev.sh perf-native --label NAME` runs the same Rustybench fixture
against direct `crabc-rs` and Rustix routes. It records Rustybench timing,
allocation, `getrusage`, and procfs resource data. It batches 1,000 operations
per sample and repeats five complete runner invocations. This is a direct
native-facade comparison, not a musl C-libc benchmark.

Full x86-64 performance runs require a passing correctness-profile chain
receipt for the current source through `capability.accounting`. The host
reader replays the retained case roster, source runners, completion markers,
and raw logs, then binds the admission record to that receipt, source identity,
and seven-gate prefix. It always selects the correctness-profile receipt, so
the later full-profile receipt does not change earlier performance evidence.
Smoke runs remain available without that admission.

Reports are ignored local evidence under `compat/reports/perf/`; compare only
runs with matching host provenance, fixture hash, sample contract, and runtime
artifact hashes. The detailed harness contract lives in
[`compat/perf/README.md`](../../compat/perf/README.md).

## Acceptance bounds

Workload-specific rows and open work are tracked in [`plan.md`](../../plan.md).
The numeric bounds are owned by code, not restated here:

- Active x86-64 C scorecard CPU bounds, syscall and memory limits, the
  31-sample/3-warm-up
  protocol, the 10,000-resample bootstrap, the three-attempt collector and the
  host-load policy: `compat/perf/x86_64_evidence.py` (`CPU_RELEASE_BOUND`,
  `CPU_TARGET_BOUND`, `CPU_RESAMPLES`,
  `FULL_SAMPLE_COUNT`, `COLLECTOR_ATTEMPTS`, `HOST_LOAD_POLICY`, the memory
  comparison helper) and `compat/x86_64/performance_release_gate.py`
  (`RUNTIME_CPU_UPPER_MAX`, `RUNTIME_SYSCALL_FACTOR`).
- Allocator promotion bounds: `compat/x86_64/performance_release_gate.py`
  (`ALLOCATOR_*`) and `compat/allocator/perf_engine_x86_64.py`.

For the active x86-64 C scorecard, the CPU upper-95% bound gates at `1.00`;
each row also reports `0.90` as a target. That target is informative and does
not affect qualification. The paused AArch64 contract remains unchanged.

## Release measurement rules

### Fixed allocator-port measurements

Allocator design remains out of scope. The narrow exception is a
provenance-preserving Rust semantic port of pinned mimalloc v3.5.0;
[`allocator.md`](allocator.md) owns that boundary. The C `libmimalloc-sys`
0.1.49 backend (bundling mimalloc v3.3.2) remains the runtime default until
promotion; it is not the exact v3.5.0 oracle. The separately built exact pinned
C v3.5.0 archive is the mandatory differential and performance baseline for
the port.

The ordinary musl–crabc rows continue to measure the runtime as users receive
it. They do not establish Rust-port parity. A port candidate must instead be
compared with the exact pinned C v3.5.0 archive under the same configuration,
fixture, build profile, machine provenance, and measurement contract. Compare
throughput, latency, resident memory, virtual mappings, and startup cost; do
not change a configuration, allocation policy, or fixture to make the Rust
translation look better. `compat/allocator/` owns the detailed differential
evidence and known-difference record.

Only a measured Rust/C divergence is an optimization lead. Preserve the
upstream algorithm until a written design note, deterministic differential
evidence, and performance evidence justify a change. The C implementation
remains the oracle even after it leaves the production dependency graph.

### Isolation, equivalence, and statistical decision

- Compile each C fixture exactly once. The lanes may differ only in staged
  interpreter and runtime bytes, and record SHA-256, `PT_INTERP`, dynamic
  dependencies, and build ID.
- Pin the benchmark process to one available CPU. Record CPU model, kernel,
  Docker image digest, governor/frequency information when readable,
  toolchain versions, revision, command line, environment allowlist, fixture
  inputs, and runtime artifact hashes.
- Interleave reference and candidate sample order from a recorded seed. Use at
  least 31 valid fresh-process C samples per lane after warm-up, retain every
  rejected sample and reason, and never represent a warm run as cold unless a
  controlled host actually evicted the relevant cache.
- Keep `strace`, `perf`, allocation profilers, and memory polling outside
  timed samples. They are diagnostics with `timing: false`; observable fixture
  results remain validated independently of black-box/volatile anti-DCE sinks.
- Publish raw samples plus median, p05, p95, maximum, and deterministic
  bootstrap seed. The release decision is the 10,000-resample one-sided 95%
  upper bound of the median CPU ratio, not a rounded table cell.
- Run the full suite in at least three clean Docker invocations. Every run
  must pass; variance is a failed gate, not permission to select a favorable
  run. Machine-readable reports are versioned, atomically written, and reject
  mismatched fixture, toolchain, host, or artifact provenance unless explicitly
  diagnostic.

### Syscall and memory accounting

- A separate fresh `strace -f -qq` process records per-syscall calls and
  errors. Whole-process totals remain useful for startup; marked steady-state
  regions report both total and calls per completed operation. A reference
  zero in a marked loop remains candidate zero.
- Every nonzero syscall difference is classified as required kernel behavior,
  required compatibility behavior, or removable work. Only the former two may
  remain, with proof beside the workload contract.
- High-water memory uses the ready/high-water/continue barrier, concurrent
  PSS/RSS/private-page sampling, and a fresh delegated cgroup-v2
  `memory.peak` leaf with a self-test showing a post-barrier allocation changes
  the result. PSS-only evidence is diagnostic when cgroup collection is
  unsupported; it is never silently promoted to a release memory result.
- Preserve `ru_maxrss`, faults, context switches, runtime image sizes, and
  virtual mappings as diagnostics. They do not substitute for the peak-memory
  boundary.

### Native measurements and build profile

Rustybench is a reusable native benchmark component rather than an uncontrolled
shell timer. Its reports retain `getrusage` CPU, faults, context switches,
RSS/PSS, allocation metrics, and separate syscall diagnostics. Its remaining
methodology work is deterministic raw-sample/provenance comparison, an explicit
process/cgroup high-water adapter, marker-bounded syscall diagnostics, and
optional unsupported-when-unavailable hardware counters. Counters guide work;
they never replace CPU time or disappear silently.

The C candidate uses the fixed root release profile (also set as
`[profile.bench]` in the isolated Rust-native fixture, because `cargo bench`
does not consume the root release profile):

```toml
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "abort"
strip = true
```

Compare a proposed win with the immediately prior profile under identical
source, fixture, toolchain, and measurement conditions. Fat LTO, one codegen
unit, and stripping are build choices, not replacements for removing a syscall
or fixing an algorithm. For standard-library-aware applications, record exact
`-Z build-std=std -Z build-std-features=` invocations and artifacts. The
dependency-free native-facade LTO proof is bounded evidence only; the
Rustybench dependency-bearing route uses the same unwind-capable build-std
closure and records it as a separate measurement lane.

## Optimization doctrine

For each failing row, first remove redundant syscalls, allocation, locking,
conversion, scanning, mapping, indirection, and C-ABI round trips. Then choose
and prove the best scalar representation and algorithm, including boundary,
error, alignment, and guard-page evidence and AArch64 assembly inspection.
Only a measured residual gap may justify a narrow SIMD path, which must earn
its complexity across the full size, alignment, and page-boundary matrix.

This makes vDSO dispatch and indexed loader lookup structural work rather than
SIMD candidates. Crabc has one AArch64 baseline: it does not inherit an x86
ifunc hierarchy. ASIMD is a later option; SVE needs separate capability,
fallback, and dispatch-cost evidence. Any optimized NUL-string load must be
proved not to cross an unmapped page, and guard-page regressions are mandatory.

Math may use an established vector kernel earlier only when its numerical
contract is fully proved; musl edge behavior, bits, rounding, exceptions,
`errno`, and ABI remain acceptance criteria. Cryptography is never hand-rolled
for performance. A supported crypto primitive uses an approved focused,
audited dependency after the `AGENTS.md` review, never an improvised vector
implementation.

## Standard-library builds

The dependency-free native-facade stock-`std` fixture is the paused AArch64
`std,panic_abort` fat-LTO proof (`opt-level=3`, one codegen unit, embedded
bitcode, dynamic crabc runtime): `./scripts/dev.sh lto-native-facade`.

Rustybench’s proc-macro Cargo benchmark graph supports `-Z build-std` when the fixture leaves `profile.bench.panic` unset. A bench
profile `panic = "abort"` is ignored for the benchmark executable but caused
Cargo to compile both abort and unwind `core` units for the dependency graph,
which then failed with duplicate `core` lang items. `perf-native --build-std`
therefore records dependency-bearing build-std timing with the benchmark
profile's default unwind strategy. This is tooling configuration evidence, not
a crabc runtime compatibility result.
