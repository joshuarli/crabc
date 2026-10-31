# musl–crabc performance evidence

Active x86 work uses the [supplied-product C adapter](#native-x86-64-supplied-product-adapter)
and the [Rust-facade companion](native/x86_64.md) through
`./scripts/dev-x86_64.sh perf-c` and `perf-native`. The AArch64 commands below
are preserved reference paths while that architecture's work is paused.

`run.py` is the project’s controlled Linux/AArch64 performance matrix. It is
not a replacement for the correctness suites and it does not turn a single
machine’s result into a release gate. Its job is to give an optimization
decision reproducible, comparable evidence.

The runner compiles `fixtures/workload.c` once with the pinned musl toolchain.
The musl and crabc lanes then run that same application and same inputs. The
only intended differences are its `PT_INTERP` path and the staged loader/libc
bytes. That prevents compiler, source, and C-ABI differences from masquerading
as a runtime comparison.

Run it through the native development entry point after a release build:

```bash
./scripts/dev.sh perf --label baseline
```

To produce a bounded report for named rows rather than the whole matrix, repeat
`--workload`. The selector records the exact requested names in schema-5
report input provenance and rejects an unknown or duplicate name:

```bash
./scripts/dev.sh perf --label scalar-matrix \
  --workload memcpy_64_aligned \
  --workload memcpy_64_unaligned
```

The generated JSON is `compat/reports/perf/baseline.json` by default. Reports
are intentionally ignored by Git. Use a distinct label for a configuration
experiment, such as `--label release-fat-lto`; reports include artifact hashes,
the exact `[profile.release]` source settings, pinned musl provenance, and a
CPU-info hash.

`native/run.py` is a separate Rust-native comparison, not a C-libc benchmark.
It runs the same Rustybench fixture against direct `crabc-rs` and the pinned
local Rustix checkout. Its process-resource and Rust allocation metrics come
from Rustybench; use `./scripts/dev.sh perf-native --label baseline`. Rustybench
syscall collection remains a separate `timing: false` diagnostic by contract.
The native runner batches 1,000 operations per timed sample by default because
single direct syscalls are below a useful timer-resolution boundary.

After a regular and fat-LTO native report exist, `--build-std` adds the pinned
nightly `-Z build-std=std -Z build-std-features=` experiment to the same
fixture. Rustybench uses Cargo's benchmark harness, which needs the default
unwind-capable standard-library closure; the existing native-facade LTO proof
retains its separately validated `std,panic_abort` route. The native fixture
uses an explicit empty `CARGO_ENCODED_RUSTFLAGS` so the repository's
symbol-accounting `link-dead-code` setting cannot alter its timed loops. The
dependency-free native-facade fixture remains the project’s separate clang/lld,
`std,panic_abort`, bitcode, and fat-LTO Linux/AArch64 proof.

## Native x86-64 supplied-product adapter

`run_x86_64.py` is the native Linux/x86-64 supplied-product adapter. It keeps
the historical AArch64 `run.py` lane and its interpreter-patching rule intact.
The x86 adapter instead accepts an already materialized installed, second, or
extracted dynamic product through `--dynamic-product`. It compiles each
unchanged application or DSO source exactly once with that product's installed
headers and the fixed C11/O3/PIE-or-PIC/anti-builtin policy, then separately
links those exact objects through the installed `bin/crabc-cc-dynamic` and the
pinned `/usr/local/bin/crabc-x86_64-musl-gcc` reference compiler. It never
patches the musl candidate's `PT_INTERP`, bypasses the installed driver, or
rebuilds a supplied product.

The adapter retains source, header, object, link, product, image-tool, staged
root, input, command, raw-ELF, raw-trace, `smaps`, and cgroup observations.
Host-side `check REPORT` replays those identities without requiring a host
native compiler or musl installation. The five-DSO graph preserves its graph:
only direct roots reach either executable's `DT_NEEDED`; the installed-driver
receipt records the complete schema-3 closure and the musl link resolves it
only through `-Wl,-rpath-link`.

The dispatcher runs the pinned native image (`compat/x86_64/core_image.py`;
override with `CRABC_X86_64_CORE_IMAGE`). Its performance-tool manifest binds
the pinned musl compiler, loader and libc, readelf and strace; changing the
image identity does not transfer earlier qualification:

```bash
./scripts/dev-x86_64.sh perf-c-test
```

`perf-c plan`, `perf-c run`, `perf-c collect`, and `perf-c check` are the
roster, attempt, collector, and retained-evidence surfaces. Every attempt runs
the same complete route: one build of all 114 rows, interleaved timed pairs,
the separate `strace` diagnostic, the live 32-MiB probe with its post-ready
`memory.peak` self-test, and one observer/cgroup envelope per row. The budget
is the only difference. A full attempt uses 31 fresh paired samples after three
warm-ups and a deterministic 10,000-resample one-sided 95% bootstrap;
`--implementation-smoke` uses one pair and no warm-up. A roster records its
budget, and each of its three attempts must use that budget, every canonical
row, and syscall diagnostics.

`perf-c collect --attempt-roster ROSTER --work-dir NEW` replays the three
attempts from raw evidence and writes `collector.json` with a per-workload
scorecard. Each attempt records the CPU median ratio and upper bound, raw PSS
and `memory.peak` totals, marked and whole-process syscall totals, and
wall/fault/context-switch/RSS medians. The collector derives paired PSS and
`memory.peak` median ratios and one-sided 95% upper bounds from the three
attempt totals. A row passes only if its per-attempt CPU and syscall gates all
pass and both memory upper bounds meet the release limit; no row or attempt
compensates for another. `perf-c check REPORT` independently replays a
collector or a single attempt, recomputes the scorecard, and prints it with
every release blocker. Qualification is exactly an empty blocker list.

Each attempt retains raw host-wide `/proc/loadavg` and `/proc/stat`
snapshots before its build and after its last measurement. The collector
derives the `uncontended_host` record the `performance.release` gate reads:
`uncontended` only when every snapshot has a one-minute load average of at
most 1.0 and at most two runnable tasks (`HOST_LOAD_POLICY` in
`x86_64_evidence.py`, which owns these numbers), otherwise `contended` with a named release blocker.
A full-budget attempt refuses to start on a contended host; `check` rederives
the record from the raw files. The Rust-facade companion's report carries the
same record under the same policy, and its full mode fails closed likewise.

Correctness admission requires the current source's validated correctness
profile receipt through `capability.accounting`. Host admission invokes the
tracked `qualification-manifest --validate-receipt PATH --json` command, so the
owning reader rechecks the receipt's captured tool and runtime identities,
case roster, runner and manifest hashes, completion markers, and retained logs
inside the pinned image. The image reader returns the validated receipt
object. The host safely opens the selected file without following symlinked
components, requires its parsed record to match the image result, and binds
admission to that file identity, source identity, and seven passed gates. The
in-image performance runner uses the same strict reader directly. Admission
selects only the correctness-profile receipt, so a later full-profile receipt
does not change earlier performance evidence. A roster records the reader's
result and cannot assert it. Full runs require admission before benchmark
setup or timed children. Smoke rosters run and collect regardless, and their
scorecards always carry the budget blocker. An owned-dynamic-qualification
receipt binds the supplied product; its absence is also a named blocker.

```bash
P=$PWD/.work/x86_64/<dynamic-product>
W=$PWD/.work/x86_64/<fresh-roster>
./scripts/dev-x86_64.sh perf-c plan \
  --implementation-smoke --dynamic-product "$P" --work-dir "$W"
for i in 1 2 3; do
  ./scripts/dev-x86_64.sh perf-c run \
    --implementation-smoke --dynamic-product "$P" --work-dir "$W/attempt-$i" \
    --attempt-roster "$W/attempt-roster.json" --attempt-index "$i"
done
./scripts/dev-x86_64.sh perf-c collect \
  --dynamic-product "$P" --work-dir "$W/collector" --attempt-roster "$W/attempt-roster.json"
./scripts/dev-x86_64.sh perf-c check "$W/collector/collector.json"
```

For final qualification, use the same `plan`, ordered three `run` commands,
`collect`, and `check` commands above with `--implementation-smoke` removed
and fresh work paths. Supply the current cohort's installed dynamic product
and its `--dynamic-qualification` receipt to `plan`; the collector replays
that prerequisite from the immutable roster.
The predecessor gates and full-budget host admission must pass first; smoke
reports cannot satisfy these prerequisites. Keep the image identity, supplied
product, source revision and ordered roster unchanged across all three attempts.

The final sequence, with `P` and `Q` set to that cohort's product and validated
dynamic qualification receipt, is:

```bash
W=$PWD/.work/x86_64/runtime-c-performance-final
./scripts/dev-x86_64.sh perf-c plan \
  --dynamic-product "$P" --dynamic-qualification "$Q" --work-dir "$W"
for i in 1 2 3; do
  ./scripts/dev-x86_64.sh perf-c run \
    --dynamic-product "$P" --work-dir "$W/attempt-$i" \
    --attempt-roster "$W/attempt-roster.json" --attempt-index "$i"
done
./scripts/dev-x86_64.sh perf-c collect \
  --dynamic-product "$P" --work-dir "$W/collector" --attempt-roster "$W/attempt-roster.json"
./scripts/dev-x86_64.sh perf-c check "$W/collector/collector.json"
```

`perf-c counts` is the S1 development instruction/syscall route (P2). It
reuses the same compile-once/dual-link/stage path, then counts retired user
instructions (`perf stat -e instructions:u`, three separate trials) and
syscalls (`strace -f -qq -o`, separate runs) around the existing static timing
launcher command. N1 scales so the reference loop covers at least 10^6
instructions; N2=2*N1, N3=3*N1; per-operation values are difference quotients.
A static exit-only calibrator is subtracted for startup rows only. Reference
selection prefers `/opt/musl-clang-*` whose `.clang-version` major matches the
`rustc -vV` LLVM major (`matched-llvm-<major>`), else the GCC musl
(`unmatched (gcc musl)`). One JSON report per invocation carries a
`kind: development` header (never release evidence) with source revision,
image ID, compiler versions, reference label, CPU model and kernel; each row
records raw counts, per-op/startup values, the per-syscall breakdown,
`instructions:{ratio_insn,delta_insn}`, `reference_label` and `status`.

The counted supervisor writes its result with a fixed-cost decimal encoder.
Its rusage formatting therefore retires the same instruction count whether a
field is zero, three digits, or six, so the launcher, the fixture and the
static `nop` calibrator binaries contribute a constant to each of the three
trials.

Every counts row separates the accepted C backend's five allocator-attributed
calls from its judged whole-process remainder. A call is attributed only when
it matches the exact name and identifying arguments: `sysinfo`; `open` of
`/proc/sys/vm/overcommit_memory`; `open` of
`/sys/kernel/mm/transparent_hugepage/enabled`; the frozen backend's 2.25 MiB
(2359296-byte) `MAP_NORESERVE` `mmap`; and a 32-byte `GRND_NONBLOCK`
`getrandom`. The record keeps `syscalls.cand.whole`, lists the attributed
signatures under `syscalls.cand.allocator_attributed`, and judges
`syscalls.cand.judged` against `syscalls.ref` by name and total. Loop rows
judge the N1 whole count this way; their per-op comparison stays on the raw
per-op counts, where the constant start-up calls cancel. An allocator call
with any other argument, or any additional non-allocator call, stays in the
judged set and fails when it exceeds the reference. `ratio_insn` stays on the
total instructions (D8); the attributed calls have no instruction exemption
the harness cannot measure.

Counts traces include only the client process. The launcher parent's
post-execve wait/poll/write/exit lines are harness overhead, and their
in-flight `poll` start can interleave before or after the client's `execve`
line; including them would move a whole total by one between runs and a
per-op quotient by one over the N2-N1 step.

```bash
P=$PWD/.work/s1/dynamic/installed
W=$PWD/.work/x86_64/<fresh-counts>
./scripts/dev-x86_64.sh perf-c counts \
  --dynamic-product "$P" --work "$W" --row getpid --row clock_gettime
```

Seed run (`matched-llvm-23`, report `.work/x86_64/s1-counts5/counts.json`):
`getpid` per-op 13.0 ref vs 14.0 cand instructions (ratio 1.077), whole-process
syscalls 200016 vs 200030 → `fail` on the split-loader/allocator startup
delta; `clock_gettime` per-op 110.0 vs 111.0 (ratio 1.009), whole-process 16
vs 30 → `fail` on the same delta. Both rows deterministic and linear.

Startup row (`matched-llvm-23`). Before the fixed-cost supervisor encoder, the
three `perf` trials read 85,712 / 85,731 / 85,730 for musl (19 instructions,
0.022 %, over the 0.01 % allowance) and 266,432 / 266,431 / 266,432 for crabc;
the shift tracks the child's rusage digit split, not the runtime. The S5 tip
reads 86,934 / 86,934 / 86,934 (musl) and 268,159 / 268,159 / 268,156 (crabc)
with the encoder. The client trace is 11 musl calls and 13 crabc calls; the
five attributed calls are `sysinfo`, two `open` probes, the 2359296-byte
`MAP_NORESERVE` `mmap`, and the 32-byte `GRND_NONBLOCK` `getrandom`. The
judged remainder is 8 vs 11 with no excess, so the syscall comparison passes;
the row still fails on `ratio_insn` 3.585 (D8, S4 instruction work).

Loop-row acceptance (`matched-llvm-23`, report `.work/x86_64/s5-counts2/counts.json`):
`getpid` judged whole 200008 vs 200011, `open_close` 75008 vs 75011,
`memcpy_16k_aligned` 8 vs 11 and `strlen_64_aligned` 8 vs 11 each carry five
attributed calls, no per-name excess, and pass; their per-op values are 1.0 vs
1.0, 3.0 vs 3.0, 0.0 vs 0.0 and 0.0 vs 0.0. `stdio_format_parse` totals pass
(6012 vs 6222, per-op 6.0 vs 6.014) but the per-name check fails on the
runtime's `openat` 1000 and `madvise` 2, which the reference does not make; the
row reports `fail` with those names. The `startup` row passes its syscall
comparison and still fails on `ratio_insn` 3.585.

Object receipt replay compares the complete compile invocation with the fixed
profile, including its final input/output operands. Additional compiler inputs
or overriding flags cannot be appended to an otherwise matching recipe.

The native profile defines the full 114-row roster: the unchanged 74 rows plus
supported clock selections, 4-MiB/32-MiB live sets, free/refill/reuse,
worker-local allocation, TCP/UDP loopback, hermetic hosts/DNS, and
empty/sub-64/guard primitive dispositions. Every row also has a separately
linked memory observer with its fixed main-state and plateau R/C checkpoints.

A full scorecard requires every workload's CPU upper-95% to meet the
no-regression gate `<= 1.00` across 31 paired fresh processes. Each row reports
the CPU target `0.90`, which does not gate qualification. PSS and `memory.peak`
use a paired one-sided 95% upper bound over the three collector attempts and
also gate at `1.00`; each row reports `0.90` as a non-gating target. Schema 2
collector rows retain the derived memory bounds, seeds, and resample count so
the reader can reconstruct them from the three attempt totals. Marked-route
and whole-process syscall totals must also be at most `R` candidate calls
(or zero when the reference is zero), with no unexplained error, retry,
fallback, or unclassified per-syscall difference. No native syscall-difference
classification exists, so every per-syscall difference is currently an
explicit failure. Three consecutive clean Docker invocations must pass one
immutable roster on an uncontended host.

The aggregate fields live at `scorecard.rows[ROW].memory.pss_kib` and
`scorecard.rows[ROW].memory.memory_peak_bytes`. Each contains
`median_ratio`, `one_sided_95_upper`, `resamples`, `seed`, `release_bound`,
`target_bound`, and `release_gate`; each attempt keeps the unmodified
`reference` and `candidate` totals used to reconstruct that summary.

Memory comparisons retain complete PSS and `memory.peak` totals: no payload,
image size, file-cache charge, or accounting batch is subtracted. A zero
reference or nonpositive candidate cannot qualify. The collector computes
each row's paired median ratio and one-sided upper bound from its three
retained attempts using the same deterministic 10,000-resample algorithm as
CPU; memory release gates use the upper bound, and targets never gate.

`perf-c-memory-smoke` is a separate bounded native collector test. It uses a
fresh supplied product/work directory, seven selected rows across all six
observer artifacts, private cgroup-v2 leaves, pre-`execve` ptrace migration,
raw proc snapshots, and ordered R/C checkpoints. It is implementation-only
and never produces a scorecard or promotion claim:

```bash
./scripts/dev-x86_64.sh perf-c-memory-smoke \
  /workspace/.work/x86_64/<dynamic-product> \
  /workspace/.work/x86_64/<fresh-memory-smoke-work>
```

## What is measured

Every timed sample is a fresh child process. The default matrix retains 31
samples per lane/workload after warm-up. A separately sealed static
`x86_64_timing_launcher` prepares its contained root, file descriptors, and
working directory before it forks; only the direct client `execve` is measured
by its raw `wait4(2)` result. The adapter replays that raw result into elapsed
wall time, user/system CPU time, peak RSS, page faults, and
voluntary/involuntary context switches. Parent setup cost is neither charged
to a lane nor estimated and subtracted. Timed samples do not run under
`strace`, a profiler, or an allocator wrapper. The runner pins itself and
every child to one allowed Linux CPU, then runs adjacent
musl/crabc sample pairs in a recorded deterministic order. Each report records
a 10,000-resample paired bootstrap one-sided 95% upper CPU-ratio bound; its
CPU gate is not inferred from a rounded median.

The workloads deliberately cover distinct cost domains:

| Family | Workloads |
| --- | --- |
| Startup/loader | Minimal `startup`, constructor/destructor `startup_constructor_destructor`, and startup-linked five-DSO `startup_dependency_graph` PIEs; 100,000 `dlsym_1`, late-symbol `dlsym_128`, and `dlsym_1024` lookups against 1-, 128-, and 1,025-export DSOs; a five-DSO `dlopen_graph` relocation/call/close slice |
| Syscall path | `clock_gettime`, `gettimeofday`, `getpid`, `open_close`; `fd_file_4k` validates `O_CLOEXEC`, `F_GETFD`, `fstat`, `pwrite`, `pread`, and `close` against one staged 4-KiB file; `stdio_file_4k` reads that file, seeks, and validates `fgetc`/`ungetc`; `stdio_format_parse` recreates a lane-private formatted record, flushes and rewinds it, scans integer/string fields, and proves the unread tail remains ordered |
| Threads/TLS | `pthread_create_join_tls` repeatedly creates and joins one worker; static TLS must start from its initializer in the worker, remain independent in the parent, and agree with a worker-local pthread key; `loader_dynamic_tls_growth` starts a worker before loading eight TLS DSOs, then proves every per-thread image and `dlclose` lifecycle; `pthread_mutex_uncontended` proves a normal-mutex protected counter across 2,000,000 successful lock/unlock pairs; `pthread_mutex_cond_ping_pong` alternates one parent and one worker through a mutex/condition turn protocol |
| C hot primitives | Legacy 16-KiB/4-KiB rows plus explicit 64-byte, 16-KiB, 256-KiB, and 128-MiB aligned/unaligned rows for `memcpy`, `memset`, `strlen`, `memchr`, `strstr`, and `memmem` |
| Allocator integration | Legacy 64-byte and 4-KiB allocate/touch/free loops plus separate 4-MiB and 32-MiB live sets, even-slot free/refill/preservation, and worker-local 64-byte/4-KiB ownership rows; `operations` records the actual repeated allocation count where it differs from outer epochs |
| Process memory | Every one of the 114 rows has a separate observer envelope with main-state/declared-plateau PSS and raw `smaps` attribution; fresh private cgroup-v2 `memory.peak` records the complete observer process, including the 32-MiB live plateau |

`dlopen_graph` stages a generated five-DSO fan-out: the root depends on two
middle DSOs, each middle DSO depends on one leaf, and the root export must
return the value composed through both branches. The report records every DSO
hash, so the graph is an auditable loader/relocation contract rather than a
bare `dlopen` timing loop.

The constructor/destructor startup PIE proves that its constructor runs before
`main`, then its destructor observes the state established by `main` after
`main` returns. The startup-linked graph PIE links once against the same
five-DSO fan-out used by `dlopen_graph`; its startup relocation must resolve
the root's two leaf branches and return `31`. Each application is compiled
once, then only its interpreter path is patched per lane. Their marker-bounded
regions cover the selected `main` route, while the whole-process diagnostic
retains the constructor, destructor, loader, and relocation cost that the
startup scorecard must judge.

The local-file rows receive distinct identical 4-KiB copies of a deterministic
`0..255` byte pattern in each lane. `fd_file_4k` verifies each descriptor's
close-on-exec flag, file size, and one offset-dependent write/read round trip.
`stdio_file_4k` verifies a complete buffered `fread`, an absolute `fseek`, and
an `ungetc` round trip. These checks make the measured paths observable without
sharing a mutable file between the reference and candidate processes.

`stdio_format_parse` recreates its formatted input for each operation with a
`w+` stream at its own lane-private path, never the 4-KiB read fixture, so no
row's input depends on which rows or memory observers ran before it. It checks `fprintf`/`fflush`/`fseek`/`fscanf` for signed, unsigned,
hexadecimal, and bounded string fields; then consumes the preserved literal tail
with `fgetc` and independently checks bounded `snprintf`/`sscanf`. The direct
musl differential uses the same contract, exercises the scalar scanner with a
one-byte FILE buffer, separately forces the staged `%n` fallback through its
seek-back route, and proves an unbuffered read invalidates a prior seek position
before another scan. The performance row therefore cannot trade away the
scanner's observable stream position.

`pthread_create_join_tls` creates a pthread key once per process, then performs
one create/join lifecycle per operation. The child must observe static TLS at
its initializer, publish a sequence-derived key value, and return it through
`pthread_join`; the parent must retain its distinct static TLS value. The shared
header is hashed in report provenance and the direct musl differential runs 513
lifetimes, exceeding the fixed thread-slot capacity to prove reclamation.

`pthread_mutex_uncontended` initializes one normal mutex and increments an
exact protected counter while holding it for every operation. Both lock and
unlock results, destruction, and the final count are checked. Its shared
contract header is also hashed in report provenance; the selected path is
intentionally single-threaded, so a marked syscall would be a regression rather
than part of the route being measured.

`pthread_mutex_cond_ping_pong` creates one worker and alternates parent/worker
turns under the same mutex. Each side increments one protected counter and
signals the other while holding the lock; the final value is exactly twice the
round count. This is the declared contended condition protocol: no sleeps,
timeouts, or ambient competitors determine progress. The fixed pre-futex spin
was removed only after this direct differential and the broad pthread stress
suite proved the normal release/retry protocol remains sound.

`loader_dynamic_tls_growth` compiles one `-O3` TLS DSO source eight times, with
initializer values `100` through `107`. Its worker begins before every
`dlopen`; the parent then writes its own `1000`-series values, releases the
worker, and verifies that the worker first sees the initializers and changes
only its own `2000`-series instances. The parent values must survive before all
handles are closed. The optimized direct musl differential catches a stale
worker that misses any intermediate TLS image. The separate optimized,
4-KiB-aligned `ldso_dynamic_tls` regression forces replacement and catches an
AArch64 TLSDESC resolver that fails to refresh the ABI's cached
thread-pointer route. The report hashes the shared contract and each staged
DSO independently.

The scalar-matrix row name is its input contract: for example,
`memcpy_256k_unaligned` runs the `memcpy_matrix` fixture mode with a 262,144
byte copy, a source offset of one byte, and a destination offset of three
bytes from distinct explicitly 64-byte-aligned backing arrays. The aligned
copy row uses zero offsets. `memset` uses offset three in its unaligned rows;
the string/range rows use offset three. The row iteration counts hold total
work approximately constant within each primitive family. Correctness belongs
to the direct musl-differential fixtures; these rows measure only inputs that
those fixtures already prove valid.

Schema 5 retains the pinned benchmark CPU's Linux sysfs data/unified cache
topology under `host.cache_topology`. It classifies every fixed scalar-matrix
size and the 128-MiB span size against the first reported cache that can
contain it. The 128-MiB rows are `span_matrix` rows: every selected lane gets
its own deterministic aligned and three-byte-offset source files, each with a
128-MiB `a...a` window, `needle` at the tail, and a terminating NUL immediately
after it. `memchr` looks for the absent byte `z`; `strstr` and `memmem` must
return that tail needle; `strlen` must return exactly 128 MiB. `memcpy` and
`memset` use a lane-local destination mapped `MAP_PRIVATE`, so their writes
cannot alter another process's input or another lane's backing file.

Those files are staged only when a selected workload needs a span row. They
are ordinary warm-page-cache inputs, not a cold-cache experiment; the report
does not label them cold. A `cache_span_size_class` of
`exceeds-largest-reported-data-cache` is the evidence boundary for saying the
row exceeds the recorded CPU cache hierarchy. The direct boundary regressions
remain the correctness proof for the 0–256-KiB bands; span-row result checks
make the 128-MiB operational contract observable.

For each workload/lane, the report retains all samples plus min/median/p95/max
summaries. `strace -f` runs once in a separate diagnostic lane and records
per-syscall calls/errors. Schema 5 gives that diagnostic a descriptor-only
marker protocol: every C fixture writes `CRABC_PERF_BEGIN` immediately before
its selected route and `CRABC_PERF_END` immediately after it. The report retains
both non-marker whole-process totals and the calls strictly between those
markers, including exact calls/errors per completed operation. Each scope
keeps a summed-total `R`/reference-zero verdict; per-syscall records are
diagnostics that must still explain every call or error difference. Marker
writes are excluded from the whole-process totals. The protocol is absent
from timed children and the diagnostic remains explicitly marked `timing:
false`.

The supplemental `x86_64_clock_allocator_workload`,
`x86_64_network_workload`, and `x86_64_primitive_boundary_workload` artifacts
admit their common arguments and optional observer environment before `BEGIN`.
They emit it before mode dispatch or route setup, then emit `END` only after a
successful route has completed its source-owned cleanup and before its real
`puts("ok")`. Their ordinary artifact remains the diagnostic artifact; the
marker descriptor is absent from timed children.

## Boundaries and interpretation

This measures the project’s current C dynamic runtime against the pinned musl
oracle. It does not benchmark a host glibc, allocator implementations in
isolation, or cross-architecture performance. The resident-memory probe gives
the process footprint of the selected allocator integration.

Allocator invention remains outside crabc’s scope. The narrowly approved work
is a provenance-preserving Rust semantic port of fixed mimalloc v3.5.0. Native
x86-64 work is active under that separate contract; the AArch64 port work is
paused. These musl–crabc rows are not sufficient evidence for either port: its
candidate must be compared against the exact pinned C v3.5.0 implementation
with matching configuration, fixture, artifact, host, and sample provenance.
The separate contract and difference register live in
[`compat/allocator/README.md`](../allocator/README.md) and
[`compat/allocator/known-differences.md`](../allocator/known-differences.md).
Do not alter this fixture, an allocation policy, or a configuration merely to
improve a Rust/C comparison.

The memory probe creates a fresh delegated cgroup-v2 leaf for each lane, moves
only the probe child into it before `exec`, and reads `memory.peak` after exit.
It also runs a second fixture that allocates only after its ready barrier and
requires that leaf's high-water value to increase. `/proc/<pid>/smaps` groups
the concurrent PSS/RSS/private-page snapshot by stable mapping name, so virtual
reservations and runtime images cannot be misreported as live allocator pages.
If the environment cannot create that leaf, the row is `unsupported`; PSS-only
evidence is retained for diagnosis but is not a release memory result.

The report is evidence, not a score. Compare medians and tails only between
runs with the same host provenance and workload contract. A result should lead
to source/assembly inspection and a focused regression measurement before it
becomes an optimization priority.

Pure parser tests need no Docker, Rust, musl, or AArch64 host:

```bash
python3 -m unittest discover -s compat/perf/tests -p 'test_*.py'
python3 -m unittest discover -s compat/perf/native/tests -p 'test_*.py'
```
