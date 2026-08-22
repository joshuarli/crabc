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
1.43×, not close to the 0.90× goal. The bounded audit now establishes both the
source and the hard limit. `libc/src/allocator_mimalloc.rs` owns one direct
mimalloc allocation domain, without the override feature or programmatic
options; the pinned `libmimalloc-sys` v3 defaults reserve 1 GiB of virtual
arena address space but do not make that reservation a resident-memory claim.
The `allocator-cgroup-contract-audit` diagnostic attributes about 47.3 MiB of
crabc PSS to anonymous mappings versus 33.3 MiB for musl. Its cgroup result is
correctly `unsupported` in the current Docker environment because its cgroup-v2
mount is read-only; it does not silently substitute a post-exit RSS value.

This fixture cannot satisfy the universal PSS gate under any allocator
configuration: it writes all 32 MiB (32,768 KiB) of payload, while 90% of the
observed musl process PSS is only about 30,470 KiB. Even a candidate with zero
runtime or allocator overhead would fail. We will not write a new allocator or
hide this row. The goal is blocked on a user scope decision; choose one of:

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
| Dynamic startup | Minimal PIE, constructor/destructor PIE, and a realistic dependency graph. Count loader setup and relocation work. | All three rows exist. `startup-contract-matrix-31` establishes two separately compiled PIE contracts: the constructor/destructor row proves ordering across `main` and has a red 1.2346× CPU upper bound with 39 crabc vs 9 musl whole-process calls. The startup-linked five-DSO graph proves its root resolves to `31`; `startup-resolution-cache-matrix-31` reduces that row from 95 to 80 candidate calls versus musl's 50 by reusing only an exact bare name that had resolved through the immutable initial `LD_LIBRARY_PATH`, but its 1.1811× CPU upper bound remains red. Their marked `main` regions are complete (one output write for the constructor row; an output operation in each lane for the graph), while startup gates judge retained whole-process loader, constructor, destructor, and relocation work. |
| Time and identity | `clock_gettime` for supported clocks, `gettimeofday`, and `getpid`; run marked steady-state loops after startup. | `clock_gettime`, `gettimeofday`, and `getpid` now have marked C loops. Three CPU-pinned `clock-zero-status-{matrix,repeat,repeat2}` reports place the monotonic `clock_gettime` route at a still-red 1.0388×–1.0432× upper-bound range with zero marked calls: the two selected C IDs enter the cached validated vDSO route without repeating its generic eligibility screen, and its exact zero-or-negative-errno status contract keeps success on a single zero test. `gettimeofday` validates null output and canonical microseconds against musl; its bounded `__kernel_gettimeofday` vDSO lookup passes at a 0.8915× CPU upper bound with zero marked hot-region calls. |
| Files and descriptors | `open`/`close`, read/write, stat, descriptor flags, and small buffered I/O with deterministic local files. | `fd_file_4k` and `stdio_file_4k` use distinct staged 4-KiB deterministic files. They cover close-on-exec, stat, offset write/read, buffered `fread`, seek, and `ungetc`. AArch64's no-argument `fcntl(F_GETFD/F_GETFL)` entry now bypasses Rust's variadic register-save area and tail-branches all other commands to the typed decoder. Three 31-sample `fcntl-noarg-entry-matrix-31` reports reduce `fd_file_4k` to 0.9205×–0.9365× CPU upper bounds, but it remains red; `stdio_file_4k` is 1.05×. Existing syscall counts pass, and the current cgroup memory row is unsupported. |
| Dynamic loading | `dlsym` at 1, 128, and 1,024+ symbols; `dlopen`/`dlclose`; dependency and TLS resolution. Verify interposition/version behavior. | Three CPU-pinned, interleaved `dlsym-handle-local-cache-matrix-31` reports pass all 1/128/1,025-symbol CPU rows at 0.7413×–0.7569× / 0.7534×–0.7725× / 0.7166×–0.7680×. The cache contains only direct handle-local definitions and verifies copied current C-string bytes, preserving mutable-name and global-interposition behavior. Its 49 vs 18 whole-process syscall row remains red. The five-DSO `dlopen`/call/`dlclose` graph remains CPU-red while its syscall row passes. |
| Memory primitives | `memcpy`, `memset`, `strlen`, `memchr`, `strstr`, and `memmem` across empty, short, cache-resident, cache-spanning, aligned, unaligned, and guard-page boundaries. | Direct musl-differential regressions cover all six over fixed empty-to-256-KiB size bands, all 16 byte alignments, 0–64-byte protected tails, and deterministic randomized misalignment. `memcpy` additionally checks non-overlap return/source/canary invariants. Its AArch64 entry tail-branches to musl 1.2.6's GPR-only short/medium/long schedule in `libc/src/aarch64_memory.rs`; three 31-sample 128-MiB aligned/unaligned runs record 0.9600×–0.9682× / 1.0498×–1.0694×. Scan/search rows pass at 0.5909×–0.7914×, while copy/fill remain red. |
| Allocation integration | Small-object churn, medium live set, 32-MiB plateau, free/reuse, and thread-local allocation paths. Measure total process peak, not allocator counters alone. | Small/4-KiB throughput and 32-MiB plateau exist. |
| Stdio and parsing | Buffered file input/output, `printf`, scanning, and seek/ungetc paths that have selected compatibility tests. | `stdio_format_parse` recreates one formatted record per operation, verifies `fprintf`/flush/rewind/`fscanf` for signed/unsigned/hex/string fields, preserves and reads its literal tail, and checks bounded `snprintf`/`sscanf`. Its direct test differentials the whole contract against pinned musl, forces the scanner's seek-back route through a one-byte FILE buffer, and proves an unbuffered read invalidates a prior seek position before another scan. `stdio-format-cached-seek-matrix-31` records a successful seek's exact kernel position only until subsequent I/O invalidates it, avoiding the immediately following scanner's redundant `SEEK_CUR` probe. The row improves to 1.0452× CPU and 7.003 vs 6.211 marked calls/op, but remains red. |
| Threads and TLS | Create/join, uncontended and contended mutex/condition paths, TLS access, and loader TLS growth. | `pthread_create_join_tls` is the first isolated row: each operation creates and joins one worker, proves that the worker sees the static TLS initializer and its own pthread-key value, and proves the parent TLS value is unchanged. Its direct pinned-musl differential recycles 513 lifetimes. The fresh `pthread-create-inline-atomics-matrix-31` report is red at a 1.1594× CPU upper bound despite 9.000 crabc vs 11.977 musl marked calls/op; separate stack/TLS mappings and thread-start setup remain the candidate work. `pthread_mutex_uncontended` proves two million normal-mutex protected increments with exact final state and zero marked syscalls in both lanes. Inline AArch64 `ldaxr`/`stlxr` compare-exchange and exchange primitives remove LLVM's outlined LSE capability probe, and its direct Musl differential now also proves a busy `trylock`; the upper bound falls from 1.3906× to a red 1.0095×. `pthread_mutex_cond_ping_pong` declares one parent/worker turn protocol: each round has two protected increments and condition signals, ending at exactly twice the round count. Its sequence and waiter counters use the same verified inline AArch64 fetch-add loop, removing LLVM's per-transition LSE dispatcher, while signal and broadcast retain their musl-matched relaxed advisory waiter hint. `pthread_cond_wait` selects the private inline timed-wait implementation rather than the interposable timed-wait PLT entry, so its known null timeout emits the direct futex wait; the public weak/default-visible timed-wait ABI, mutex release/acquire, and sequence-futex synchronization edge remain intact. Three reports record a still-red 1.0084×–1.0103× with 6.0009–6.0029 crabc vs 6.0014–6.0026 musl marked calls/op. `loader_dynamic_tls_growth` starts one worker before loading eight distinct `-O3` TLS DSOs; each worker image must retain its initializer and remain isolated from the parent's write before `dlclose`. The direct regression suite proves intermediate images are not skipped, a parent/child `DT_NEEDED` TLS graph initializes both modules, the AArch64 TLSDESC path refreshes a migrated cached TP, and a deliberately no-RELRO packed-`DT_RELR` DSO remains valid after another `dlopen`. Its per-allocation capacity/TP guard initializes ordinary fitting images in place, and the musl-matched initial `libc.so` short name eliminates redundant dependent-libc probes without loosening general runtime identity matching. The lowest `PT_LOAD` maps the complete file span before later segments overlay it, reducing the dynamic-TLS diagnostic from 25 to 17 candidate `mmap`s (18 musl) and to 8.125 versus 13.125 marked calls/op. Runtime relocation and RELRO now operate only on the new dependency-graph suffix, independent of RELRO presence, so in-place packed relocations cannot replay and earlier objects are not rescanned. Three current CPU-pinned reports span a still-red 1.2802×–1.3813× upper bound. |
| Networking and resolver | Local loopback socket I/O and a hermetic local DNS/hosts resolver scenario. No public network or ambient resolver state. | `./scripts/dev.sh resolver-network` runs one C fixture against pinned musl and crabc in a `--network none` container. It installs and restores a private resolver file only in that isolated container, uses fixed loopback DNS roles, compares exact status/stdout/stderr, and requires server-side evidence for A/AAAA/CNAME, NXDOMAIN/NODATA, malformed and wrong-ID packets, UDP truncation followed by TCP retry, search, and configured-order fallback. The same fixture covers loopback TCP/UDP IPv4/IPv6, ancillary data, readiness, shutdown, bounded I/O, EINTR, and nonblocking errors. `m11_resolver_system` and `m11_resolver_transport` add caller-owned `/etc/hosts` precedence, snapshot parsing, ndots/search ordering, and bounded native transport proofs. |
| Native facade companion | Direct `crabc-rs` routes versus pinned Rustix: time, identity, file descriptor, allocation-avoiding buffer APIs, and errors. | Time, identity, and open/close exist; this is supporting evidence, not a musl C-ABI claim. |

The Threads/TLS family table's `pthread-create-release-store-*-31` measurement
is historical. Three current `pthread-create-tsd-loader-publish-*-31` reports
establish a still-red 0.9195×–0.9541× CPU upper-bound range. Creators claim a
free slot before detached-worker reclamation, reset it only after a successful
claim, and allocate stack/TLS once. The combined block keeps TLS above the
downward-growing stack and refreshes a migrated TLS pointer before reclamation.
Exit skips the fixed TSD destructor scan when no destructor-bearing value
exists, while an exact non-null bitset clears only occupied slots before reuse.
The loader's private multi-thread transition is published once before the first
`clone` through the inline AArch64 compare-exchange loop; later creates must not
call the callback again. The direct differential now covers 513 lifetimes, a
rearming destructor through `PTHREAD_DESTRUCTOR_ITERATIONS`, a no-destructor
slot-reuse case, and all `PTHREAD_KEYS_MAX` null-destructor reservations;
dynamic-TLS differentials, broad pthread stress, and the loader suite retain
lifecycle evidence.

The current red rows are concrete rather than hypothetical:

| Route | Present crabc/musl CPU evidence | Immediate cause to remove |
| --- | ---: | --- |
| C `clock_gettime` ×200,000 | 1.0406×–1.0699× CPU upper bounds across three 31-sample reports; no marked-hot-loop `clock_gettime` syscall | Realtime/monotonic C calls now bypass the generic eligibility screen before their cached validated vDSO invocation. Fresh-process cost and the remaining indirect dispatch keep the CPU row red. |
| C `gettimeofday` ×200,000 | 0.8915× CPU upper bound; 41 vs 10 non-marker calls and zero marked-region calls | bounded Linux/AArch64 `__kernel_gettimeofday` lookup eliminates the intermediate `clock_gettime` conversion and passes the CPU gate. |
| Scalar primitive matrix, 64 B / 16 KiB / 256 KiB, aligned and unaligned | 31-sample CPU upper bounds: `memcpy` 1.0500×–1.5891×; `memset` 1.0956×–1.8702×; `strlen` 0.5062×–0.8293×; `memchr` 0.8392×–0.8944×; `strstr` 0.2250×/0.2763×, 0.6524×/0.6700×, and 0.6683×/0.6666×; `memmem` 0.3780×–0.8529×. Every row has 41 crabc vs 10 musl fresh-process calls. | Direct C fixtures now cover all six primitives over fixed empty-to-256-KiB size bands, all 16 byte alignments, 0–64-byte protected tails, and deterministic randomized misalignment. The musl 1.2.6 GPR `memcpy` schedule improves every cache-resident copy row without runtime capability dispatch, but `memcpy`/`memset` still have no CPU-passing matrix row. `strlen`, `memchr`, `strstr`, and `memmem` pass every row. For `strlen`, the page-safe zero-byte mask’s little-endian lowest bit identifies the first terminator without a byte-at-a-time end-word scan. For `strstr`, one page-safe scalar zero-byte screen over `byte & (byte ^ target)` admits every NUL or target byte and confirms possible matches bytewise; it replaces the former separate target and NUL word predicates without widening a read. For `memmem`, a first byte at the only remaining needle-sized suffix permits direct bounded equality rather than the generic late-suffix loop. The syscall row is loader/startup work, not an inner-loop syscall. Schema-4 cache provenance proves these rows fit L1/L2; the separately reported 128-MiB rows exceed the recorded 64-MiB L3. |
| Cache-spanning primitive matrix, 128 MiB aligned and unaligned | Three 31-sample CPU upper bounds for `memcpy`: 0.9600×–0.9682× / 1.0498×–1.0694×; `memset` 1.1889×/1.2951×; `strlen` 0.7611×/0.7465×; `memchr` 0.7873×/0.7911×; `strstr` 0.5909×/0.6007×; `memmem` 0.7889×/0.7914×. Every row has 51 crabc vs 22 musl diagnostic calls. | Schema-4 classifies 128 MiB as exceeding benchmark CPU 0's reported 64-MiB L3. Source data is deterministic and lane-private; the copy/fill destination is `MAP_PRIVATE`. The scan/search rows pass; copy and fill remain red. The warm-page-cache fixture is not a cold-cache claim, and its report is `partial` only because the cgroup peak collector is unsupported. |
| `dlsym`, 1 / 128 / 1,025 symbols ×100,000 | 0.7413×–0.7569× / 0.7534×–0.7725× / 0.7166×–0.7680× CPU upper bounds; 49 vs 18 traced calls | Immutable GNU/SysV metadata and the bounded per-thread direct-definition cache pass every CPU row. The cache compares copied current C-string bytes rather than an address identity, and stores no global or fallback resolution, so mutable names and later global interposition retain the existing result. The whole-process syscall count remains red. |
| Five-DSO `dlopen_graph` | 1.22×–1.25× CPU upper bound; 98 vs 50 traced calls | Reusing the validated inode identity removes six duplicate mapper `fstat`s and passes the graph syscall gate, but CPU remains red. |
| Minimal PIE startup | CPU median quantizes at the current one-operation workload; 44 vs 10 traced calls | Retained ASLR reservations and file-first/anonymous-tail mappings each removed two calls; separate-image loading and eager allocator initialization remain. |
| Constructor/destructor PIE startup | 1.2346× CPU upper bound; 39 vs 9 whole-process calls; both marked `main` routes make exactly one output write | Constructor-before-`main` and destructor-after-`main` ordering are now proven without hiding their cost. Remove only loader or runtime work not required by that lifecycle. |
| Startup-linked five-DSO graph | 1.1811× CPU upper bound; 80 vs 50 whole-process calls; marked regions contain one reference `ioctl`/`writev` output path and two candidate writes | An initial-graph cache removes 15 repeated same-path probes without applying to aliases, `$ORIGIN`, or runtime `dlopen`. The shared graph still has a red whole-process CPU result, although its syscall gate passes. |
| C `stdio_format_parse` ×1,000 | 1.0452× CPU upper bound; 7.003 vs 6.211 marked calls/op | A successful `fseek` records its exact kernel position until I/O invalidates it, so the immediately following buffer-empty scanner avoids a redundant `SEEK_CUR` probe while other streams retain their seekability route. The direct-musl-differential contract also forces a one-byte-buffer seek-back path and invalidates the cache with an unbuffered read. The remaining read-ahead-to-EOF and stream setup keep both selected gates red. |
| C `pthread_create_join_tls` ×1,000 | 0.9195×–0.9541× CPU upper bounds across three 31-sample `pthread-create-tsd-loader-publish-*-31` reports; 7.000 vs 11.977–11.990 marked calls/op | One page-aligned mapping places TLS above the downward-growing stack; candidate marked `mmap`/`munmap` match musl at one each. Exit fast-returns when no live key owns a destructor, and an exact occupancy bitset clears only TSD values that need clearing before slot reuse. The loader callback's one-way transition runs once before the first `clone` through inline AArch64 compare-exchange. The direct static-TLS/pthread-key/create-join differential covers 513 lifetimes, a rearming destructor, no-destructor slot reuse, and all `PTHREAD_KEYS_MAX` null-destructor keys; dynamic-TLS regressions, pthread stress, and loader cases pass. Candidate syscalls pass, but CPU remains red. |
| C `loader_dynamic_tls_growth` ×8 | 1.2802×–1.3813× CPU upper bounds across three 31-sample `loader-relocation-suffix-*-31` reports; 8.125 vs 13.125 marked calls/op | The direct matched eight-DSO contract proves a worker predating all loads receives every initialized image and its writes are thread-local; the adjacent optimized parent/child graph proves one `dlopen` initializes every TLS module in a `DT_NEEDED` closure, while the 4-KiB-aligned regression proves TLSDESC migration refreshes its cached TP. `tests/ldso_no_relro_relocation.rs` differentials a no-RELRO packed-`DT_RELR` DSO against musl and proves a second load does not replay its in-place relocation. Runtime relocation and RELRO operate only on the appended dependency-graph suffix, so that correctness boundary also removes prior-object scans. Reusing a fitting allocation removes repeated block swaps, and the musl-matched initial `libc.so` short name removes redundant dependent-libc opens/stats without changing general runtime identity matching. The initial lowest-`PT_LOAD` file mapping covers the final span before later fixed overlays, removing eight anonymous reservations: the trace records 17 candidate mappings versus 18 musl. The marked syscall gate passes; CPU remains red. |
| C `pthread_mutex_uncontended` ×2,000,000 | 0.6066×–0.6109× CPU upper bounds across three 31-sample `pthread-mutex-release-store-*-31` reports; zero marked calls in both lanes | Inline AArch64 `ldaxr`/`stlxr` compare-exchange retains the acquisition contract. Normal unlock reads its advisory waiter count without an acquire barrier and emits one release `stlr` when it observes no waiter; any observed waiter retains the prior exchange-and-wake path. Direct Musl differentials, the condition handoff regression, and broad pthread stress preserve the waiter retry/wake protocol. The CPU gate passes. |
| C `pthread_mutex_cond_ping_pong` ×10,000 | 1.0084×–1.0103× CPU upper bounds across three 31-sample `pthread-cond-direct-wait-*-31` reports; 6.0009–6.0029 vs 6.0014–6.0026 marked calls/op | The direct-matched parent/worker protocol proves each handoff's two protected increments. The condition sequence and waiter counters retain the inline AArch64 acquire/release fetch-add exclusive loop instead of LLVM's outlined LSE capability dispatch; signal and broadcast retain their musl-matched relaxed advisory waiter hint. `pthread_cond_wait` selects the private inline timed-wait implementation rather than `pthread_cond_timedwait@plt`, so the known null timeout is a direct futex wait; the weak/default-visible timed-wait ABI and mutex/sequence synchronization edge remain unchanged. The futex boundary and 10-iteration pthread-stress result are unchanged. The CPU gate remains red. |

The preceding `memset` matrix cells are historical. Three current
`memset-gpr-scalar-schedule-*-31` reports supersede them: the 64-B/16-KiB/
256-KiB aligned/unaligned cells range from 1.1615×–1.1801×,
1.1186×–1.1469×, and 0.9163×–1.6508×; the 128-MiB cells range from
1.1315×–1.1922× aligned and 1.1947×–1.2334× unaligned. The musl 1.2.6
generic bounded head/tail schedule now uses explicit AArch64 GPR stores, so
LLVM cannot substitute NEON before a separately proven SIMD decision. Every
fill CPU row remains red.

The Threads/TLS family table's earlier `pthread_mutex_uncontended` result is
historical. Three current `pthread-mutex-release-store-*-31` reports establish
a 0.6066×–0.6109× CPU upper-bound range, passing the CPU gate with zero marked
syscalls in both lanes. The normal unlock fast path uses an unordered atomic
waiter hint only to select its release store; a waiter that races the store
cannot sleep on the replaced signed value, while any observed waiter retains
the exchange-and-wake path. Direct Musl differentials, the condition handoff
regression, and ten pthread-stress iterations preserve that state machine.

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

**Status:** Schema-5 C reports retain non-marker whole-process syscall totals
and a marker-bounded hot-region summary with exact calls/errors per completed
operation. `marker-clock-schema5-smoke` proves both musl and crabc have zero marked
`clock_gettime` calls while preserving their 10/41 non-marker whole-process totals;
`marker-getpid-schema5-smoke` proves the same boundary records exactly one `getpid`
call per operation in both lanes. `startup-marker-schema5-smoke` proves the
constructor/destructor and startup-graph PIEs also emit one complete marker
pair without excluding their loader lifecycle from the whole-process totals.
The cgroup peak requirement remains
unsupported in the current read-only Docker mount, and several mandatory
workload families still need contracts and baselines.

- Implement the isolation, interleaving, provenance, statistical comparison,
  cgroup high-water, and marker-bounded syscall requirements above.
- Add the mandatory workload skeletons with correctness checks before timing
  them. Do not optimize an unverified fixture.
- Establish an immutable pre-change baseline report and publish comparison
  commands in the harness documentation.

**Exit:** every mandatory row has a valid contract and a baseline, even though
it is expected to fail the numerical targets initially.

### P1 — eliminate time syscalls

**Status:** The bounded vDSO implementation and shared C/Rust dispatch are
complete. The marked hot loop has no direct `clock_gettime` syscall. Three
31-sample `clock-zero-status-{matrix,repeat,repeat2}` reports place the direct
realtime/monotonic C branch at a still-red 1.0388×–1.0432× CPU upper-bound
range; its zero-or-negative-errno status boundary returns successful vDSO
calls after one zero test. Fresh-process work and the remaining indirect vDSO
dispatch are still counted by the release gates.

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

**Status:** `ldso` decodes immutable GNU-hash metadata once while it registers
each object, selects the GNU/SysV index by object format, and keeps
owner/error state in the loader TCB to remove per-lookup `gettid`. Three
CPU-pinned, interleaved 31-sample runs cover 1/128/1,025 symbols at 95%
bootstrap upper bounds of 0.7413×–0.7569× / 0.7534×–0.7725× /
0.7166×–0.7680× CPU. A bounded per-thread cache retains only a successful
definition in the requested handle and compares copied current C-string bytes,
so it does not make mutable names, global fallback, or interposition stale.
All lookup CPU rows now pass, while their 49 versus 18 whole-process syscall
row remains red. The five-DSO graph is 1.22×–1.25× CPU and 98 versus 50 calls;
its CPU row remains a measured gap, not missing data.

- Retain GNU and SYSV hash metadata rather than reading it only to derive a
  symbol count. Implement musl-compatible hash lookup, preserving scope,
  interposition, visibility, version, TLS, and malformed-object behavior.
- Remove `gettid` from every uncontended loader lock transition through a
  sound ownership representation. Preserve recursion and multi-threaded
  loader correctness.
- Use the five-DSO graph trace to remove only non-contract setup calls, and
  retain its dependency/TLS/interposition correctness regressions.

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
