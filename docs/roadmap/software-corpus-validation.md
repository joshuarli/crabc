# Software-corpus validation roadmap

## Status, activation, and ownership

**Status:** sequenced future work. It is not active until
[`performance-completion.md`](performance-completion.md) has a credible,
passing focused scorecard for every mandatory row.

`TODO.md` remains the only prioritized work list. This roadmap owns the
detailed C0–C4 corpus acceptance contract; it does not turn existing
compatibility cases into performance claims or create a second backlog.

## Position in the roadmap

[`performance-completion.md`](performance-completion.md) comes first. It closes the known structural performance
gaps and establishes a trustworthy musl comparison scorecard for the core
runtime. This second goal begins only after that scorecard is credible and
passing for its mandatory rows.

Goal 2 then asks the harder practical question:

> Does crabc remain correct, CPU-efficient, memory-efficient, and syscall-
> efficient when unmodified real software and realistic `crabc-rs`
> applications exercise many runtime subsystems together?

It is a Linux/AArch64-only validation program. Musl remains the C-runtime
oracle. Rustix remains a pinned native-facade comparator, not a production
dependency. Glibc is never an oracle or fallback. The scope, allocator, crypto,
and dependency rules in [`SCOPE.md`](../../SCOPE.md) remain in force.

This goal is deliberately a **second** phase. It must not delay a clear fix to
the current vDSO, loader, string-search, startup, or integration-footprint
gaps. It prevents a later mistake: treating narrow wins as proof that ordinary
software benefits similarly.

## What exists today

Crabc already has a meaningful compatibility base:

- 34 exact-output Alpine AArch64 package cases, 12 of them stateful, spanning
  coreutils, text processing, archives/compression, SQLite, curl, OpenSSL,
  SSH configuration, Git, and Python. See
  [`compat/corpus/README.md`](../../compat/corpus/README.md).
- A stock Rust `std` application that exercises allocation, files,
  directories, environment, clocks, TCP/UDP/DNS, threads, synchronization,
  process spawning, a child pipe, and stdio; plus a dependency-bearing Rust
  application with async local TCP, synchronization, filesystem state,
  subprocess handling, and an error path. See
  [`compat/rust-std/README.md`](../../compat/rust-std/README.md).
- Synthetic loader, ABI, POSIX, libc-test, differential, and stress suites
  that isolate semantics which package applications can obscure. The generated
  status is in [`COMPATIBILITY.md`](../../COMPATIBILITY.md).

That evidence is strong for compatibility, but it is not enough for the
performance claim in [`performance-completion.md`](performance-completion.md): many corpus commands are brief; several are
version/configuration probes; and they currently compare raw outputs rather
than CPU, high-water memory, and syscall budgets. The native-facade evidence
also lacks several independent applications written directly against
`crabc-rs`.

## Completion claim

Goal 2 is complete only when the expanded corpus has reproducible, comparable
evidence that no representative supported subsystem regresses outside the
[`performance-completion.md`](performance-completion.md) performance gates under realistic composition:

- each mandatory workload preserves its musl-equivalent observable behavior;
- each C-runtime workload passes the same per-workload CPU, peak-memory, and
  syscall rules defined in [`performance-completion.md`](performance-completion.md);
- each native application has a separately stated Rustix comparison and does
  not depend on Rustix, `libc`, or `nix` in production;
- all results retain inputs, artifacts, commands, host/toolchain provenance,
  raw samples, and explicit exclusions.

This is not a promise to benchmark every Alpine package or all historical C
APIs. It means every in-scope subsystem has at least one workload which uses it
in composition with other ordinary runtime behavior, and no workload is
discarded because it is unfavorable.

## Corpus design

### Three complementary layers

| Layer | Purpose | Required properties |
| --- | --- | --- |
| Focused scorecard | Attribute a regression to one runtime route. | Small deterministic inputs, direct correctness witness, independent CPU/PSS/syscall measurements. |
| Real C software corpus | Validate loader/libc behavior under ordinary package dependency graphs and sustained work. | Unmodified pinned Alpine package binary where practical; same executable under musl/crabc overlays; deterministic local state. |
| Native application corpus | Validate `crabc-rs` as an application-facing runtime rather than a group of wrappers. | Normal Rust applications use `crabc-rs` directly, no production Rustix/libc/nix; a matching Rustix build exists only where comparison is meaningful. |

No layer replaces another. A synthetic loader fixture can prove an unusual ELF
rule better than a large program; a real package can reveal costly interaction
between loader, stdio, allocation, filesystem, and dependencies that a unit
fixture never reaches.

### Operating modes

Each workload declares which of these modes it supports:

| Mode | Answers | Measurement boundary |
| --- | --- | --- |
| Fresh process | Is startup, relocation, initial allocation, and first-use behavior competitive? | One new process per timed sample; separate whole-process syscall trace. |
| Steady state | Is repeated useful work competitive after initialization? | Explicit start/end markers; syscall counts normalized per completed operation. |
| Live high-water | Does the runtime retain too much resident memory at useful peak load? | Ready/high-water/continue barrier, PSS/RSS/private pages, and cgroup-v2 `memory.peak`. |
| Concurrency | Do locks, TLS, I/O, and allocator integration remain efficient under a declared number of threads? | Fixed affinity/thread count, start barrier, per-operation result validation, contention protocol in the workload contract. |

Public network state, ambient DNS, wall-clock-dependent output, and randomly
generated unrecorded inputs are prohibited. Local loopback servers, fixture
files, seeded generated repositories, and pinned archives are allowed.

## Initial mandatory C software workloads

Every workload begins as a pinned manifest entry with setup, operation,
semantic result witness, expected output/state, resource dimensions, and a
reason it belongs in the corpus. Start with these tasks—not broad package
collection for its own sake.

| Workload | Real program / operation | Runtime behavior exercised |
| --- | --- | --- |
| Text scan and transform | `grep` over multi-MiB deterministic text; `sed` transform with an output hash. | `mmap`/read, memory search, buffered stdio, allocation, files. |
| Archive pipeline | `tar` create/extract many files with varied path lengths and fixed tree hash. | Filesystem metadata, directories, buffered I/O, string handling, allocation. |
| Compression | `gzip` and `zstd` compress/decompress fixed incompressible and compressible inputs. | Streaming I/O, allocation, memory copies, CPU time, dynamic dependencies. |
| SQLite | Bulk insert in one transaction, indexed queries, ordered scan, and deterministic database checksum. | Allocation, files, locking, mmap/IO, stdio, error paths. |
| Python | Parse/process a deterministic source/data corpus; directory traversal and controlled subprocess. | Large application startup, allocation, dynamic loading, Unicode/string paths, files, process APIs. |
| Git | Create a fixed repository tree, `add`, `status`, and a local log/read operation. | Many small files, directory traversal, environment, subprocesses, text processing. |
| Local network client | `curl` against a harness-owned loopback HTTP endpoint; body and header hashes asserted. | DNS/hosts policy, sockets, polling, resolver, read/write, allocation. |
| SSH configuration | `ssh -G` over a generated large deterministic configuration. | Parser/string workload, files, environment, error behavior. |
| Crypto consumer | OpenSSL digest of a fixed large file, used only as an unmodified libc consumer. | File I/O, buffering, allocation, loader interactions; no crypto implementation claim. |

The first implementation should scale inputs gradually and retain both a fast
developer size and a release size. Inputs must be large enough that the
selected runtime route is observable, but not so large that application
algorithm changes swamp all libc/loader evidence. The report records input
size, operation count, and each program's non-libc DSO graph.

The existing version/configuration probes remain useful compatibility smoke
cases. They are not counted as sustained-performance workloads.

## Initial mandatory crabc-rs applications

Direct `crabc-rs` adoption needs application-level proof separate from Rust
`std` running on crabc's C ABI. These normal Rust applications use `crabc-rs`
for their OS boundary; they may use small ordinary Rust dependencies only after
the dependency review required by `SCOPE.md`.

| Application | Direct crabc-rs capabilities | Rustix comparison shape |
| --- | --- | --- |
| Descriptor pipeline | Explicit-root filesystem walk, caller-buffered reads/writes, pipes/splice where appropriate, and descriptor ownership cleanup. | Same source or a small backend adapter for comparable Rustix operations. |
| Local service/client | TCP or Unix socket listener/client, poll/epoll, vectored I/O, timeouts, and a bounded local resolver path. | Direct Rustix backend for syscall-like operations; separate semantics where crabc-rs intentionally differs. |
| Thread/TLS worker | Fixed worker pool using synchronization, thread-local state, file work, and a deterministic result reduction. | Rustix only for overlapping primitives; do not pretend its non-overlap is comparable. |
| Process/signal tool | Spawn/pipe/wait, `signalfd` or signal masking, deterministic child lifecycle, and cleanup. | Compare shared overlapping process/wait APIs; explicitly mark crabc-rs extensions. |
| Filesystem state tool | Named/anonymous temporary files, atomic descriptor-relative updates, directory enumeration, and explicit error handling. | Direct Rustix comparison for the overlapping fd/open/read/write/stat surface. |

Each application has a hermetic functional test before any performance test.
Its normal build must prove the absence of production `rustix`, `libc`, and
`nix` dependencies. The benchmark backend is a separate test-only build input.

## Measurement and acceptance

This roadmap uses the sound measurement rules of
[`performance-completion.md`](performance-completion.md), not ad hoc command
timing:

- C software runs as a single original package executable in symmetric musl
  and crabc runtime overlays. Only the interpreter/runtime bytes differ.
- Rust applications use a locked toolchain and dependency graph. Where a
  Rustix comparator is meaningful, source and inputs are shared through a
  narrowly defined backend boundary.
- Every timed run is separate from tracing/profiling. CPU time is user plus
  system time; high-water PSS and cgroup peak are measured at a declared
  plateau; syscall tracing is a separate diagnostic.
- Reference/candidate samples are interleaved, all samples are retained, and
  comparison rejects mismatched binary/input/host provenance.
- Each real workload is run in fresh-process and steady-state modes where its
  operation permits. The report never converts a total startup count into a
  misleading per-operation steady-state number.

The [`performance-completion.md`](performance-completion.md) gates apply per
workload, not as an average across packages:

```text
CPU upper confidence-bound ratio        <= 0.90
peak PSS ratio                          <= 0.90
cgroup-v2 memory.peak ratio             <= 0.90
syscalls, reference R > 0               <= 2 * R
syscalls, reference R = 0 in hot region == 0
```

The native Rustix comparison is supporting performance evidence rather than a
musl equivalence claim. It uses the same discipline—raw samples, allocations,
resources, and syscall diagnostics—and establishes an explicit target for the
chosen native operation before it can be called a win.

## Delivery sequence

### C0 — promote the existing corpus into a measurable substrate

- Reuse the pinned Alpine manifest and exact raw-output comparison machinery.
- Add a performance wrapper rather than polluting correctness runs with
  `strace` or memory polling.
- Introduce a compact workload schema: operation mode, input generator/hash,
  output/state witness, expected DSO graph, operation count, and resource
  marker protocol.
- Add tests for manifest validation, overlay equivalence, marker parsing,
  report provenance, and result comparison.

**Exit:** existing real software can be measured without weakening its
byte-for-byte correctness contract.

### C1 — establish sustained C workload baselines

- Add the mandatory C workloads one at a time, beginning with text,
  compression, archive, and SQLite operations.
- Preserve fast/small developer inputs plus recorded release-scale inputs.
- Capture musl baselines before changing crabc and record the cost attribution
  hypothesis for every failure.

**Exit:** each selected C family has at least one fresh, steady, or high-water
baseline with raw musl/crabc evidence.

### C2 — close cross-subsystem performance gaps

- Investigate failures using the focused scorecard first, then verify the fix
  against the real workload which exposed it.
- Prefer structural and scalar fixes; SIMD remains the last measured step
  except for fully proved established math kernels, exactly as
  [`performance-completion.md`](performance-completion.md) and `SCOPE.md`
  require.
- Keep package semantics and output checks green through every optimization.

**Exit:** every mandatory C workload passes the
[`performance-completion.md`](performance-completion.md) gates or has a
documented, user-approved scope change. There is no “real corpus is
informational” escape hatch at completion.

### C3 — add native application evidence

- Implement the five bounded `crabc-rs` applications above in a test-only
  corpus package, with direct functional tests and a separate Rustix backend
  where meaningful.
- Run stock Rust `std`, dependency-bearing Rust `std`, direct `crabc-rs`, and
  Rustix lanes independently. Do not attribute C-runtime behavior to native
  facade code without the appropriate lane.
- Extend the native Rustybench report with corpus-level provenance and the
  required high-water/syscall diagnostics once its `build-std` limitation is
  resolved.

**Exit:** several independent applications—not merely API microbenchmarks—use
crabc-rs as their OS interface and have reproducible performance/semantic
evidence.

### C4 — release evidence and maintenance

- Run the full corpus on three clean Docker invocations and on a second
  compatible AArch64 machine class when available.
- Publish a generated corpus dashboard: workload matrix, behavior result, CPU
  confidence bound, peak memory values, syscall ratio, provenance, and
  exclusions.
- Keep a small smoke subset for ordinary development and schedule the full
  release-scale corpus separately. A benchmark suite must remain useful rather
  than becoming an unrun ritual.

**Exit:** all mandatory workloads pass, the report is independently
reproducible, and future regressions have a clear row to fail.

## Guardrails

- Do not make the corpus a generic distribution test, web crawler, or public
  network benchmark. Inputs and state stay hermetic and pinned.
- Do not benchmark cryptographic implementation quality through OpenSSL; it is
  only a demanding unmodified consumer of the C runtime.
- Do not make an application crate a new crabc runtime dependency. Corpus
  dependencies are test-only and still audited for size, native code, globals,
  and reproducibility.
- Do not reward a workload that hides all runtime cost in an application
  algorithm. Pair it with focused rows that attribute the relevant route.
- Do not replace targeted loader, ABI, or POSIX tests with “Python passed.”
  Broad programs complement isolation; they do not prove every edge condition.
- Do not declare Goal 2 complete if an unfavorable workload has merely been
  removed, shrunk, or reclassified without an explicit contract reason.

## Definition of done

After [`performance-completion.md`](performance-completion.md) is complete,
software-corpus validation is complete when the C and native corpus
above provides reproducible, behavior-preserving, measured evidence across
all mandatory families; every C workload meets the 0.90× CPU/peak-memory and
2.00× syscall limits; native applications have honest Rustix comparisons; and
the full result is a maintained, independently rerunnable release artifact.
