# Performance goal — soundly outperform musl on Linux/AArch64

## Decision and scope

`crabc` will become the demonstrably better Linux/AArch64 runtime for the
bounded, supported runtime surface. The release gate is intentionally harder
than a pleasing benchmark screenshot:

1. **CPU:** `crabc` uses at most **0.90×** musl's user-plus-system CPU time.
2. **Peak memory:** `crabc` uses at most **0.90×** musl's peak resident memory.
3. **Syscalls:** `crabc` performs at most **2.00×** musl's syscall count.
4. **Correctness:** no ABI, loader, POSIX, capability-ledger, or selected
   real-program evidence regresses in order to obtain a performance result.

The comparison target is the pinned musl release in
[`compat/upstreams.toml`](compat/upstreams.toml), on Linux/AArch64
little-endian with the project's Linux 5.10 kernel baseline. Glibc is neither
a comparator nor a fallback. The governing scope in [`SCOPE.md`](SCOPE.md)
continues to apply: x86_64 and other architectures remain out of scope;
mimalloc remains the selected allocation strategy; and optimizations may not
weaken observable musl-compatible behavior.

“All fronts” has a precise operational meaning here: every row of the release
scorecard below must meet every applicable gate. It does **not** mean a claim
about arbitrary programs, arbitrary hardware, or every historical C symbol
outside the supported profile. No row may be omitted because it is currently
unfavorable.

This is a forward-looking goal document. [`TODO.md`](TODO.md) remains the
current work list until its items are promoted or completed; the performance
work described here is the contract for that promotion.

## Acceptance scorecard

Each eligible workload runs in two C-runtime lanes:

- **Reference:** the fixture compiled once with the pinned musl toolchain and
  launched with staged musl `PT_INTERP` and libraries.
- **Candidate:** the exact same fixture bytes except for staged crabc
  `PT_INTERP` and runtime libraries.

The runner must retain all raw samples and provenance. A scorecard result is
`pass`, `fail`, or `unsupported`; `unsupported` is never a pass. Rows are
added only with a contract explaining which supported behavior they represent.

| Metric | Per-row release requirement | Why it is the gate |
| --- | --- | --- |
| CPU time | One-sided 95% bootstrap upper bound for `median(crabc user + system CPU) / median(musl user + system CPU)` is **≤ 0.90**. | CPU time includes kernel work caused by the runtime and is less host-noisy than wall time. |
| Peak memory | Both protocol-controlled peak PSS and cgroup-v2 `memory.peak` ratio are **≤ 0.90**. | PSS exposes attributable process memory; cgroup high-water usage catches resident peaks missed by an instantaneous read. |
| Syscalls | For a reference count `R > 0`, candidate calls are **≤ 2R**. For `R = 0` inside a marked hot region, candidate must also be zero. | A small fixed startup difference must not mask a per-operation syscall regression. |
| Syscall errors | Candidate introduces no uncontracted error, retry, or fallback syscall. | Fewer calls are not a win if error semantics change. |
| Wall time | Candidate median and p95 are reported; a wall-time regression requires investigation even if CPU passes. | Scheduler and frequency noise make it diagnostic, not the primary gate. |
| Faults / context switches | Candidate medians and p95 are reported; material regressions require explanation. | They identify paging, allocation, and lock path costs. |
| Correctness | All fixture outputs, direct boundary tests, ABI inventory, loader tests, and selected compatibility suites pass. | Performance cannot purchase a changed contract. |

The CPU and memory goals are deliberately **per workload**, not a geometric
mean. A fast `getpid` may not compensate for a slow clock, loader, or string
primitive. A row that has no meaningful syscall activity still has CPU and
memory gates; a row with no stable peak plateau must first gain one.

### What counts as peak memory

Peak memory is the memory used by the launched program, its loader, and its
runtime dependencies—not just bytes requested from `malloc`.

1. The fixture enters an explicit ready/high-water/continue protocol after it
   has reached the intended live set. The harness samples
   `/proc/<pid>/smaps_rollup` at the high-water barrier for PSS, RSS, and
   private pages.
2. The child is placed in a fresh delegated cgroup-v2 leaf. The harness reads
   `memory.peak` after it exits, with no unrelated process in that leaf.
3. The PSS and cgroup samples must agree directionally. If the cgroup records
   unavailable delegated state, the row is `unsupported`, not silently
   reduced to post-exit RSS.
4. The report preserves raw values; it never subtracts a candidate-specific
   baseline, ignores loader mappings, or turns virtual-address reservations
   into a peak-resident claim.

The existing 32-MiB live allocation measurement is therefore a real blocker:
crabc presently records 48,284 KiB PSS versus musl's 33,864 KiB. It is about
1.43×, not close to the 0.90× goal. We first audit crabc's mimalloc
integration, configuration, duplicate mappings, and unnecessary retained
runtime state. We will not write a new allocator or hide this row. If the
approved mimalloc strategy cannot satisfy the universal memory target after
that bounded integration work, the goal is blocked until the user explicitly
chooses one of these scope changes:

- approve a different mimalloc configuration/version or a focused integration
  change;
- exempt allocator-dominated rows from the universal peak-memory target; or
- reopen allocator design as project scope.

## Mandatory workload families

The release scorecard starts with the current performance fixture, then grows
until each in-scope subsystem has at least one representative, reproducible
cost path. A workload is a behavioral contract, not a hand-written loop that
happens to favor one implementation.

| Family | Required rows and invariants | Current state |
| --- | --- | --- |
| Dynamic startup | Minimal PIE, constructor/destructor PIE, and a realistic dependency graph. Count loader setup and relocation work. | Minimal startup exists; constructor and dependency graph rows need addition. |
| Time and identity | `clock_gettime` for supported clocks, `gettimeofday`, and `getpid`; run marked steady-state loops after startup. | `clock_gettime` and `getpid` exist. |
| Files and descriptors | `open`/`close`, read/write, stat, descriptor flags, and small buffered I/O with deterministic local files. | `open`/`close` exists; the remaining rows need addition. |
| Dynamic loading | `dlsym` at 1, 128, and 1,024+ symbols; `dlopen`/`dlclose`; dependency and TLS resolution. Verify interposition/version behavior. | 128-symbol `dlsym` exists. |
| Memory primitives | `memcpy`, `memset`, `strlen`, `memchr`, `strstr`, and `memmem` across empty, short, cache-resident, cache-spanning, aligned, unaligned, and guard-page boundaries. | A single selected size exists; complete size/alignment/guard matrix is required. |
| Allocation integration | Small-object churn, medium live set, 32-MiB plateau, free/reuse, and thread-local allocation paths. Measure total process peak, not allocator counters alone. | Small/4-KiB throughput and 32-MiB plateau exist. |
| Stdio and parsing | Buffered file input/output, `printf`, scanning, and seek/ungetc paths that have selected compatibility tests. | Needs deterministic fixtures. |
| Threads and TLS | Create/join, uncontended and contended mutex/condition paths, TLS access, and loader TLS growth. | Needs isolated fixtures and a declared contention protocol. |
| Networking and resolver | Local loopback socket I/O and a hermetic local DNS/hosts resolver scenario. No public network or ambient resolver state. | Needs hermetic fixtures. |
| Native facade companion | Direct `crabc-rs` routes versus pinned Rustix: time, identity, file descriptor, allocation-avoiding buffer APIs, and errors. | Time, identity, and open/close exist; this is supporting evidence, not a musl C-ABI claim. |

The first four current red rows are concrete rather than hypothetical:

| Route | Present crabc/musl CPU evidence | Immediate cause to remove |
| --- | ---: | --- |
| C `clock_gettime` ×200,000 | 4.53× | Direct syscall instead of vDSO dispatch. |
| `strstr` / `strlen` / `memchr` / `memmem` | 5.20× / 4.85× / 3.60× / 3.23× | Scalar or asymptotically weaker AArch64 paths. |
| `dlsym`, 128 symbols ×5,000 | 1.93×; 15,010 vs 18 traced calls | Linear lookup and lock-owner `gettid` work. |
| Startup | 1.14×; 48 vs 10 traced calls | Excess setup, mappings, and loader work. |

No performance completion is declared while any currently selected red row or
mandatory family fails, is omitted, or is unsupported.

## Optimization ladder — remove work before adding vectors

The order of optimization is part of the goal. A vectorized routine cannot
compensate for an avoidable syscall, a linear lookup, a needless allocation,
or an incorrect data structure. For each failing row, use this escalation
order and stop when the scorecard passes:

1. **Remove work:** eliminate redundant syscalls, allocations, locks,
   conversions, scans, mappings, indirection, and C-ABI round trips.
2. **Choose the right scalar algorithm and representation:** retain lookup
   indexes, avoid repeated comparisons, keep hot data local, and make the
   compiler-visible call path simple enough for the release profile and LTO.
3. **Prove the ordinary implementation:** establish differential, boundary,
   error, alignment, and guard-page tests; inspect generated AArch64 assembly
   for obviously missed inlining or bounds work.
4. **Use narrowly targeted SIMD only when the preceding steps leave a measured
   gap:** the optimized path must earn its complexity against the full size,
   alignment, and page-boundary matrix, not one favorable microbenchmark.

This order applies particularly to the current P0/P1 gaps: vDSO time dispatch
and hash-indexed loader lookup are structural fixes, not SIMD candidates. It
also prevents the project from becoming a collection of architecture-specific
tricks where a small algorithmic repair would have been safer and faster.

SIMD is still a valuable final tool for foundational primitives. The FreeBSD
Foundation's [SIMD libc project](https://freebsdfoundation.org/project/simd-enhanced-freebsd-libc-functions/)
illustrates why carefully selected string and memory routines can benefit a
wide range of programs, while also calling out dispatch, transition-cost, and
page-boundary concerns. Crabc has one active AArch64 baseline, so it must not
copy an x86 multi-level/ifunc scheme wholesale. Baseline ASIMD paths may be
considered after the scalar proof; optional extensions such as SVE require a
separate capability check, a safe fallback, and evidence that dispatch itself
does not erase the gain.

An optimized load may inspect bytes beyond the logical end of a NUL-terminated
string only when it is proven not to cross into an unmapped page and preserves
the C function's observable result. Guard-page regressions are mandatory; no
performance result justifies a speculative fault or an out-of-contract read.

### Math and cryptography exception

Math may reach the fourth step earlier than ordinary glue code when a
well-established vector kernel is the only credible way to meet an important
numerical workload's target. That is an exception to ordering, not permission
to invent algorithms: preserve musl's specified edge behavior and port its
proven numerical algorithm where it is the oracle. Bit patterns, rounding
modes, exceptional values, `errno`/floating-point exceptions, and the
Linux/AArch64 ABI remain acceptance tests before a vector path is enabled.

Cryptographic primitives are different from general libm. They are never
hand-rolled for a performance target. When a supported crypto path needs a
fast constant-time implementation, prefer the approved RustCrypto family and
its audited, portable kernels; any new production dependency still receives
the dependency review required by `SCOPE.md`. RustCrypto is not a substitute
for musl-derived general mathematical routines. The goal is to borrow proven
building blocks where they fit, not to force a crypto crate into unrelated
libc math.

## Sound measurement protocol

The existing [`compat/perf/README.md`](compat/perf/README.md) contract is the
starting point. Before using the scorecard as a release gate, the harness must
provide the following stronger properties.

### Isolation and equivalence

- Compile each C fixture exactly once. The two lanes may differ only in the
  staged interpreter and runtime bytes. Record each artifact's SHA-256,
  `PT_INTERP`, dynamic dependencies, and build ID.
- Pin the benchmark process to one available CPU. Record CPU model, kernel,
  Docker image digest, governor/frequency information when readable, toolchain
  versions, git revisions, command line, environment allowlist, fixture input
  hashes, and musl/crabc artifact hashes.
- Interleave reference and candidate sample order from a recorded random seed;
  never run all musl samples before all crabc samples. Use at least 31 valid
  fresh-process samples per C lane after warm-up. Report every rejected sample
  and its reason.
- Keep warm-cache and cold-start modes distinct. A cold-cache result is valid
  only on a controlled host that can evict the relevant cache without affecting
  other work; otherwise report only the warm mode and do not label it cold.
- Keep `strace`, `perf`, allocation profilers, and memory polling outside timed
  samples. Their reports are diagnostics with `timing: false`.
- Make fixture results observable and validate them. Use volatile/black-box
  sinks only to prevent dead-code elimination, never to change the workload's
  C ABI or semantics.

### Statistical decision

- Pair samples by interleaved run order where possible; retain independent raw
  samples where pairing is impossible.
- Publish median, p05, p95, max, and the deterministic bootstrap seed. The
  release decision uses a 10,000-resample one-sided 95% bootstrap upper bound
  of the median CPU ratio, not a rounded table cell.
- Repeat the entire suite on at least three clean Docker invocations. A row
  passes only when every invocation passes. Inconclusive variance is a failed
  gate, not a reason to choose the best run.
- The default report is machine-readable, versioned, and atomically written.
  A comparison tool must refuse mismatched fixture, toolchain, host, or
  artifact provenance unless explicitly operating in diagnostic mode.

### Syscall accounting

- Trace a separate fresh process with `strace -f -qq`, preserving per-syscall
  call and error counts. The current whole-process trace remains useful for
  startup; steady-state rows add an explicit marker protocol so initialization
  calls cannot hide loop costs.
- Report both totals and calls per completed operation. For hot loops, a
  reference zero must remain candidate zero; an equivalent vDSO path is the
  expected solution for time rather than a large allowance.
- Categorize nonzero differences as required kernel behavior, required
  compatibility behavior, or removable work. Only the first two may remain;
  their proof lives next to the workload contract.

### Memory accounting

- Add the cgroup-v2 high-water collector described above and a harness
  self-test that proves an allocation after the ready barrier changes the
  recorded high-water value.
- Preserve PSS, RSS, private clean/dirty pages, `ru_maxrss`, minor/major
  faults, and context switches. `ru_maxrss` is supporting evidence, not a
  substitute for the cgroup or barrier measurement.
- Record runtime image sizes and virtual mappings separately. They are useful
  diagnostics, but neither is substituted for peak resident memory.

### Rustybench's role

Rustybench is the reusable native benchmark component, not a source of
uncontrolled shell measurements. Its schema now records `getrusage` CPU,
faults, context switches, RSS/PSS snapshots, allocation metrics, and separate
`syscalls` diagnostics. The next Rustybench work is to add:

1. raw-sample/provenance fields and deterministic comparison/threshold output;
2. a process or cgroup high-water memory adapter with explicit supported,
   unsupported, and not-applicable states;
3. marker-bounded syscall diagnostics for steady-state benchmark regions;
4. optional `perf_event_open` cycles, instructions, branch misses, and cache
   misses as diagnostics when permissions permit.

Hardware counters guide optimization but do not replace the CPU-time gate.
They must never be synthesized or silently dropped: unavailable counters are
reported as unsupported.

## Build and optimization contract

The root release profile is fixed as follows and is the candidate profile for
every C scorecard run:

```toml
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "abort"
strip = true
```

Before claiming an optimization win, compare it against the immediately prior
profile with the same source revision, fixture, toolchain, and measurement
protocol. Fat LTO, one codegen unit, and `strip` are build choices, not
substitutes for removing a syscall or replacing a linear algorithm. Retain
artifact size and build time as secondary diagnostics; do not trade away a
runtime contract merely to improve them.

For complete Rust applications, measure a distinct standard-library-aware
lane after the C and native baseline is stable:

```bash
cargo build --release \
  -Z build-std=std \
  -Z build-std-features=
```

Cargo documents that `-Z build-std` rebuilds the standard library in the
application profile, requires nightly Cargo/rustc and `rust-src`, and that an
explicit empty `build-std-features` overrides the default `backtrace` and
`panic-unwind` feature set. See the [Cargo unstable-feature
reference](https://doc.rust-lang.org/cargo/reference/unstable.html#build-std).
Record the exact effective rustc invocations and standard-library artifact
hashes. The existing dependency-free M12 proof passes; the Rustybench
dependency-bearing route currently reports Cargo's duplicate-`core` lang-item
failure as unsupported. Resolve that integration limitation before using it to
make a build-std timing claim.

## Implementation order

The sequence is chosen to eliminate systemic costs before hand tuning. Each
stage begins with a narrow failing performance regression and correctness
tests, ends with a scorecard update, and makes no new production dependency
without the required review in `SCOPE.md`.

### P0 — make the scorecard a trustworthy release gate

- Implement the isolation, interleaving, provenance, statistical comparison,
  cgroup high-water, and marker-bounded syscall requirements above.
- Add the mandatory workload skeletons with correctness checks before timing
  them. Do not optimize an unverified fixture.
- Establish an immutable pre-change baseline report and publish comparison
  commands in the harness documentation.

**Exit:** every mandatory row has a valid contract and a baseline, even though
it is expected to fail the numerical targets initially.

### P1 — eliminate time syscalls

- Parse the Linux auxiliary vector/vDSO ELF safely in `crabc-core`.
- Resolve the correct `__vdso_clock_gettime` symbol with bounded validation;
  call it for supported clock IDs and retain direct-syscall fallback for
  absent, malformed, or rejected vDSO data.
- Route both the C ABI and `crabc-rs::time` through the same typed dispatch.
- Test vDSO success, forced fallback, malformed metadata, error propagation,
  and all supported clock semantics against musl/POSIX evidence.

**Exit:** time rows meet the CPU, zero-steady-state-syscall, memory, and
correctness gates. No direct time syscall may remain in a vDSO-success hot
loop.

### P2 — make dynamic symbol lookup scale

- Retain GNU and SYSV hash metadata rather than reading it only to derive a
  symbol count. Implement musl-compatible hash lookup, preserving scope,
  interposition, visibility, version, TLS, and malformed-object behavior.
- Remove `gettid` from every uncontended loader lock transition through a
  sound ownership representation. Preserve recursion and multi-threaded
  loader correctness.
- Add 1/128/1,024+/large dependency graph fixtures plus loader stress and
  correctness regressions.

**Exit:** all dynamic-loader rows meet the three numeric targets with no
loader semantic regression.

### P3 — fix scalar hot primitives, then apply measured AArch64 SIMD

- Start with musl's relevant algorithmic structure for `strlen`, `memchr`,
  `strstr`, and `memmem`; preserve scalar Rust behavior as the semantic oracle.
  Eliminate repeated comparison and other algorithmic losses before proposing
  vector instructions.
- Prefer small, locally auditable Rust or assembly paths. SIMD/assembly is a
  last-resort, measured optimization after differential tests cover alignment,
  zero length, page boundaries, read-only output constraints, randomized
  content, and guard pages.
- Inspect generated AArch64 assembly for unneeded bounds handling, calls, and
  missed inlining before adding explicit SIMD. Revisit `memcpy` and `memset`
  only if their expanded matrix fails the target.

**Exit:** every size/alignment row passes, including adversarial needles and
guard-page cases; no fast path reads beyond a permitted page boundary.

### P4 — reduce startup and resident footprint without semantic shortcuts

- Attribute every excess startup syscall, mapping, allocation, and relocation
  to a required contract or a removable implementation choice.
- Eliminate redundant TCB/TLS setup, metadata retention, mapping protection
  churn, and failed discovery paths only where the loader's self-relocation,
  TLS, `dlopen`, and error semantics remain proved.
- Audit mimalloc integration before considering allocator design. Look for
  duplicated allocation domains, eager commitment, retained pages caused by
  crabc wrappers, and unneeded long-lived runtime allocations.

**Exit:** startup and allocation-integration rows meet the numeric targets, or
the explicit allocator scope decision above is made. There is no silent
exception.

### P5 — finish the supported-surface scorecard

- Add and optimize the files/descriptors, stdio, pthread/TLS, networking, and
  resolver rows in order of measured cost.
- Use hermetic fixtures for filesystem and network state; do not make public
  network availability part of a benchmark.
- Address root causes only after a focused regression shows the gap. Retain
  differential behavior tests for every optimization.

**Exit:** every mandatory family has passing rows and no supporting diagnostic
shows an unexplained material regression.

### P6 — prove end-to-end and standard-library-aware results

- Re-run the full scorecard from clean Docker invocations, then repeat on a
  second compatible AArch64 machine class when available.
- Run the dependency-free M12 standard-library-aware lane, then the resolved
  Rustybench build-std lane, using the exact command above and a no-LTO control
  build. Attribute improvements rather than assuming them.
- Verify artifacts, ABI dashboard, libc-test selection, loader stress,
  corpus, Rustix, and real-program evidence at the candidate revision.

**Exit:** all release rows pass on every required run. The final report lists
the workload inventory, raw data/provenance, confidence bounds, syscall
tables, memory peaks, exclusions (which must be none among mandatory rows),
and exact reproduction commands.

## Non-negotiable review rules

- Do not optimize by weakening validation, returning a different error,
  dropping cancellation/TLS/loader behavior, bypassing C ABI obligations, or
  using glibc.
- Do not call a diagnostic run a benchmark. `strace`, `perf`, allocation
  profiling, and memory polling remain outside timing samples.
- Do not compare mismatched runtime artifacts, hosts, compiler revisions, or
  fixture inputs as if they were an A/B result.
- Do not discard high variance, failed runs, negative results, or allocator
  rows. Record them and fix the test only when its contract—not its outcome—is
  invalid.
- Do not add opaque native libraries or broad frameworks merely to get a
  number. Preserve `no_std`, auditability, direct Rust-native call paths, and
  LTO visibility. A focused dependency still needs user approval.
- Do not make a universal claim before P6. Until then, describe results as
  selected Linux/AArch64 workload evidence.

## Definition of done

This goal is complete only when a clean, reproducible release report proves
that every mandatory Linux/AArch64 scorecard row is at most **0.90×** musl for
CPU and peak resident memory, at most **2.00×** musl for syscalls, and passes
all semantic evidence. The report must be independently rerunnable from the
repository with pinned inputs and without undocumented host state.

At that point crabc can accurately claim that it soundly beats musl on the
defined, supported runtime scorecard—not merely that several microbenchmarks
look good.
