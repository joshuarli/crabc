# Performance completion roadmap

## Status, activation, and ownership

**Status:** active acceptance contract. The current selected results include
both passing and red rows; no performance-completion claim is available while a
mandatory row is red, omitted, or unsupported.

`TODO.md` remains the sole prioritized work list. This roadmap owns the
detailed release scorecard, its evidence requirements, and the ordered
completion work; it does not create a competing backlog. Stable measurement
semantics and the current cost model live in
[`docs/design/performance.md`](../design/performance.md), while detailed runner
mechanics live in [`compat/perf/README.md`](../../compat/perf/README.md).

The roadmap activates only through a selected `TODO.md` performance item and
must preserve the scoped Linux/AArch64, Linux 5.10, musl-oracle, allocator, and
dependency boundaries. It is not a universal performance claim, an allocator
research program, or permission to weaken correctness evidence.

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
[`compat/upstreams.toml`](../../compat/upstreams.toml), on Linux/AArch64
little-endian with the project's Linux 5.10 kernel baseline. Glibc is neither
a comparator nor a fallback. The governing scope in [`SCOPE.md`](../../SCOPE.md)
continues to apply: x86_64 and other architectures remain out of scope;
mimalloc remains the selected allocation strategy; and optimizations may not
weaken observable musl-compatible behavior.

“All fronts” has a precise operational meaning here: every row of the release
scorecard below must meet every applicable gate. It does **not** mean a claim
about arbitrary programs, arbitrary hardware, or every historical C symbol
outside the supported profile. No row may be omitted because it is currently
unfavorable.

This is a forward-looking acceptance contract. [`TODO.md`](../../TODO.md)
remains the current work list until its items are promoted or completed; this
document specifies the proof required for that promotion.

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

### Provisional P0 time gate

The final release scorecard above remains the only basis for a claim that
crabc outperforms musl. To make completed structural time-route work visible
without weakening that claim, the current P0 time tranche has one narrow,
planning-only progress gate: C `clock_gettime` may be recorded as
**provisionally accepted** when its one-sided CPU upper bound is at most
**1.05x** musl, the marked steady-state region has zero `clock_gettime`
syscalls in both lanes, and all direct vDSO/fallback/error boundaries remain
green. This gate does not change the `<= 0.90x` CPU release requirement, does
not apply to any other workload, and does not relax memory, syscall, or
correctness evidence.

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
hide this row. The user selected the retained mimalloc strategy: do not change
its configuration, version, or integration, and do not reopen allocator design.
This resolves the implementation-scope decision, not the measurement: the row
remains visible and non-passing, and `crabc` cannot claim all-front performance
completion while it is selected. Reopening allocator work requires explicit new
user direction.

## Mandatory workload families

The release scorecard starts with the current performance fixture, then grows
until each in-scope subsystem has at least one representative, reproducible
cost path. A workload is a behavioral contract, not a hand-written loop that
happens to favor one implementation.

| Family | Required rows and invariants | Current state |
| --- | --- | --- |
| Dynamic startup | Minimal PIE, constructor/destructor PIE, and a realistic dependency graph. Count loader setup and relocation work. | All three rows exist. The `kernel-main-image-{matrix,repeat,repeat2}-31` reports consume Linux's already mapped main PIE through its validated `AT_PHDR`/`AT_PHENT`/`AT_PHNUM`/`AT_ENTRY` layout rather than reopening and remapping it, while `AT_EXECFN` supplies the bounded main `$ORIGIN`. The direct pinned-musl regression proves exactly one executable mapping. The minimal row falls to 30 crabc vs 10 musl calls (still-red 1.1908×–1.2958 CPU upper bounds); the constructor/destructor contract still proves ordering across `main` at 29 vs 9 (1.1502×–1.1809); and the startup-linked five-DSO graph still resolves its root to `31` at 65 vs 50 (1.1687×–1.2205). The graph syscall gate passes, while every startup CPU row remains red. Their marked `main` regions are complete (one output write for the constructor row; an output operation in each lane for the graph), while startup gates judge retained whole-process loader, constructor, destructor, and relocation work. |
| Time and identity | `clock_gettime` for supported clocks, `gettimeofday`, and `getpid`; run marked steady-state loops after startup. | `clock_gettime`, `gettimeofday`, and `getpid` now have marked C loops. Linux 5.10's AArch64 vDSO performs the exact `clock_gettime` syscall when it cannot serve an ID from its data page, so the cached validated C/core route calls it for every public ID rather than repeating a user-space eligibility screen. Three CPU-pinned `clock-universal-vdso-{matrix,repeat,repeat2}-31` reports place monotonic `clock_gettime` at 1.0278×–1.0332× with zero marked calls: provisionally accepted under the scoped P0 `<= 1.05x` gate, but final-release red against `<= 0.90x`. The direct vDSO boundary proves process CPU time and invalid-ID `EINVAL`; missing or malformed metadata remains cached as the typed direct syscall. `gettimeofday` validates null output and canonical microseconds against musl; its bounded `__kernel_gettimeofday` vDSO lookup passes at a 0.8915× CPU upper bound with zero marked hot-region calls. |
| Files and descriptors | `open`/`close`, read/write, stat, descriptor flags, and small buffered I/O with deterministic local files. | `fd_file_4k` and `stdio_file_4k` use distinct staged 4-KiB deterministic files. They cover close-on-exec, stat, offset write/read, buffered `fread`, seek, and `ungetc`. AArch64's no-argument `fcntl(F_GETFD/F_GETFL)` entry now bypasses Rust's variadic register-save area and tail-branches all other commands to the typed decoder. Three 31-sample `fcntl-noarg-entry-matrix-31` reports reduce `fd_file_4k` to 0.9205×–0.9365× CPU upper bounds, but it remains red; three `stdio-current-cancel-{31,repeat-31,repeat2-31}` reports place `stdio_file_4k` at a still-red 0.9865×–1.0168×. Existing syscall counts pass, and the current cgroup memory row is unsupported. |
| Dynamic loading | `dlsym` at 1, 128, and 1,024+ symbols; `dlopen`/`dlclose`; dependency and TLS resolution. Verify interposition/version behavior. | Three CPU-pinned, interleaved `dlsym-handle-local-cache-matrix-31` reports pass all 1/128/1,025-symbol CPU rows at 0.7413×–0.7569× / 0.7534×–0.7725× / 0.7166×–0.7680×. The cache contains only direct handle-local definitions and verifies copied current C-string bytes, preserving mutable-name and global-interposition behavior. Its 49 vs 18 whole-process syscall row remains red. Three `loader-path-pthread-followup-{,repeat,repeat2}` reports put the five-DSO `dlopen`/call/`dlclose` graph at a still-red 1.1769×–1.2326× CPU upper bound. The immutable initial `LD_LIBRARY_PATH` cache records at most 16 nonempty components and otherwise takes the existing bytewise scan, without extending to parent RUNPATH/RPATH, `$ORIGIN`, or direct names. The prior lifecycle diagnostic remains 65 vs 50 whole-process calls and 35 vs 40 marked calls because crabc avoids a non-contract main-image probe while musl applies per-DSO `FD_CLOEXEC`. The direct pinned-musl self-image regression proves an explicit executable pathname maps a separate object, while `dlopen(NULL)` remains the distinct global-handle path. |
| Memory primitives | `memcpy`, `memset`, `strlen`, `memchr`, `strstr`, and `memmem` across empty, short, cache-resident, cache-spanning, aligned, unaligned, and guard-page boundaries. | Direct musl-differential regressions cover all six over fixed empty-to-256-KiB size bands, all 16 byte alignments, 0–64-byte protected tails, and deterministic randomized misalignment. Long zero and nonzero `memset` fills additionally range every 0–63-byte gap before a protected page. `memcpy` additionally checks non-overlap return/source/canary invariants. Its AArch64 entry tail-branches to musl 1.2.6's GPR-only short/medium/long schedule in `libc/src/aarch64_memory.rs`; three 31-sample 128-MiB aligned/unaligned runs record 0.9600×–0.9682× / 1.0498×–1.0694×. Scan/search rows pass at 0.5909×–0.7914×, while copy/fill remain red. |
| Allocation integration | Small-object churn, medium live set, 32-MiB plateau, free/reuse, and thread-local allocation paths. Measure total process peak, not allocator counters alone. | Small/4-KiB throughput and 32-MiB plateau exist. |
| Stdio and parsing | Buffered file input/output, `printf`, scanning, and seek/ungetc paths that have selected compatibility tests. | `stdio_format_parse` recreates one formatted record per operation, verifies `fprintf`/flush/rewind/`fscanf` for signed/unsigned/hex/string fields, preserves and reads its literal tail, and checks bounded `snprintf`/`sscanf`. Its direct test differentials the whole contract against pinned musl, exercises the no-length scalar stream scanner with one-byte FILE storage, separately forces staged `%n` seek-back, and proves an unbuffered read invalidates a prior seek position before another scan. The direct scanner retains only one local delimiter before restoring it through `ungetc`, eliminating its staged EOF probe. Five `stdio-direct-local-lookahead-{matrix,repeat,repeat2,final,final2}-31` reports place the row at 1.0328×–1.0585× CPU and 6.003 vs 6.211 marked calls/op; the marked syscall gate passes, while CPU remains red. |
| Threads and TLS | Create/join, uncontended and contended mutex/condition paths, TLS access, and loader TLS growth. | `pthread_create_join_tls` is the first isolated row: each operation creates and joins one worker, proves that the worker sees the static TLS initializer and its own pthread-key value, and proves the parent TLS value is unchanged. Its direct pinned-musl differential recycles 513 lifetimes. Three current `pthread-tls-single-tcb-init-{matrix,repeat,repeat2}-31` reports remain red at 0.8911×–0.9171× with 6.000 crabc versus 11.966 musl marked calls/op. Normal `pthread_join` waits on `CLONE_CHILD_CLEARTID`; because its next iteration already checks cancellation after a futex return, it removes the redundant adjacent `pthread_testcancel` call. The pinned-musl stress regression cancels a joiner while its target remains blocked, then proves a later join receives the target result. `pthread_timedjoin_np` records one-way interest in the same `detach_state` futex word before sleeping; ordinary worker exits therefore skip the unused wake without losing a timed-join notification. The bridge materializes fresh variable images before copying the parent ABI TCB, then writes allocation and logical-thread metadata once rather than initializing and immediately overwriting a fresh TCB. Normal slots retain their original bridge TP to bypass per-join layout lookups, while the existing refreshed dynamic-TLS path remains. `pthread_mutex_uncontended` proves two million normal-mutex protected increments with exact final state and zero marked syscalls in both lanes. Inline AArch64 `ldaxr`/`stlxr` compare-exchange and exchange primitives remove LLVM's outlined LSE capability probe, and its direct Musl differential now also proves a busy `trylock`; the upper bound falls from 1.3906× to a red 1.0095×. `pthread_mutex_cond_ping_pong` declares one parent/worker turn protocol: each round has two protected increments and condition signals, ending at exactly twice the round count. Its sequence and waiter counters use the same verified inline AArch64 fetch-add loop, removing LLVM's per-transition LSE dispatcher, while signal and broadcast retain their musl-matched relaxed advisory waiter hint. `pthread_cond_wait` enters its private timed-wait route, then invokes private exact mutex lock/unlock helpers rather than the public mutex PLT entries; the weak/default-visible public ABI and sequence-futex synchronization edge remain intact. Three `pthread-cond-direct-mutex-{matrix,repeat,repeat2}-31` reports lower the still-red CPU upper bound to 1.0035×–1.0052× with 6.0007–6.0021 crabc versus 6.0022–6.0052 musl marked calls/op. `loader_dynamic_tls_growth` starts one worker before loading eight distinct `-O3` TLS DSOs; each worker image must retain its initializer and remain isolated from the parent's write before `dlclose`. The direct regression suite proves intermediate images are not skipped, a parent/child `DT_NEEDED` TLS graph initializes both modules, the AArch64 TLSDESC path refreshes a migrated cached TP, and a deliberately no-RELRO packed-`DT_RELR` DSO remains valid after another `dlopen`. Its per-allocation capacity/TP guard initializes ordinary fitting images in place, while its loader-private TCB records the append-only initialized-module frontier: a later generation mismatch copies only the absent suffix and preserves all earlier thread-private writes. The musl-matched initial `libc.so` short name eliminates redundant dependent-libc probes without loosening general runtime identity matching. The lowest `PT_LOAD` maps the complete file span before later segments overlay it, reducing the dynamic-TLS diagnostic from 25 to 17 candidate `mmap`s (18 musl) and to 8.125 versus 13.125 marked calls/op. Runtime relocation and RELRO now operate only on the new dependency-graph suffix, independent of RELRO presence, so in-place packed relocations cannot replay and earlier objects are not rescanned. Three current `tls-module-frontier-*-31` reports span a still-red 1.3184×–1.3977× upper bound; the matched 101-sample candidate/baseline pair is 1.3193×/1.3412×. |
| Networking and resolver | Local loopback socket I/O and a hermetic local DNS/hosts resolver scenario. No public network or ambient resolver state. | `./scripts/dev.sh resolver-network` runs one C fixture against pinned musl and crabc in a `--network none` container. It installs and restores a private resolver file only in that isolated container, uses fixed loopback DNS roles, compares exact status/stdout/stderr, and requires server-side evidence for A/AAAA/CNAME, NXDOMAIN/NODATA, malformed and wrong-ID packets, UDP truncation followed by TCP retry, search, and configured-order fallback. The same fixture covers loopback TCP/UDP IPv4/IPv6, ancillary data, readiness, shutdown, bounded I/O, EINTR, and nonblocking errors. `resolver_system` and `resolver_transport` add caller-owned `/etc/hosts` precedence, snapshot parsing, ndots/search ordering, and bounded native transport proofs. |
| Native facade companion | Direct `crabc-rs` routes versus pinned Rustix: time, identity, file descriptor, allocation-avoiding buffer APIs, and errors. | Time, identity, and open/close exist; this is supporting evidence, not a musl C-ABI claim. |

The Threads/TLS family table's `pthread-conditional-exit-wake-*-31`
measurement is historical. Three current
`pthread-tls-single-tcb-init-{matrix,repeat,repeat2}-31` reports establish a
still-red 0.8911×–0.9171× CPU upper-bound range and 6.000 crabc versus 11.966
musl marked calls/op. Normal `pthread_join` waits on `CLONE_CHILD_CLEARTID`; an
ordinary worker therefore no longer wakes the unrelated `detach_state` futex.
The next loop iteration already tests cancellation after every join futex
return, so the redundant adjacent `pthread_testcancel` call is removed. The
new pinned-musl stress regression cancels a joiner while its target remains
blocked, then proves a later join returns that target's result. A timed join
records one-way interest in the same futex word before sleeping, so exit either
sees the marker and wakes it or changes the expected word before the wait can
enter the kernel. Creators still claim a free slot before detached-worker
reclamation, retain the original bridge TP for direct combined-allocation
cleanup, and use the existing exact dynamic-TLS cleanup after migration. The
direct 513-lifetime differential, dynamic-TLS tests, ten-iteration pthread
stress, and loader suite retain lifecycle evidence.

The preceding `stdio_file_4k` 1.05× result is historical. Three current
`stdio-current-cancel-{31,repeat-31,repeat2-31}` reports establish a still-red
0.9865×–1.0168× CPU upper-bound range. `fdopen` initializes only its complete
observable `FILE` state rather than zeroing the trailing I/O buffer; read and
write paths initialize that buffer before consuming it. `__stdio_read` checks
its already-published current pthread slot at its cancellation points, avoiding
public lazy registration for a caller that cannot yet have a crabc cancellation
request. Public `pthread_testcancel` remains unchanged. The direct pinned-musl
differential covers `O_CLOEXEC`, descriptor ownership after `fclose`,
write/flush/seek, buffered reads, and `ungetc`; ten-iteration pthread stress
retains deferred/asynchronous stdio cancellation. The marked syscall smoke
remains 5.03 crabc versus 8.00 musl calls/op.

### Handoff — `stdio_format_parse`

The next local lead is `VfscanfFastReader::get` in `libc/src/lib.rs`: the
selected scalar `vfscanf` route keeps its delimiter locally but invokes the
public `fgetc` entry for every source byte. Release AArch64 currently shows
`fscanf`/`vfscanf` entering the shared scanner at `0x2c560`, while the public
`fgetc` entry begins at `0x51154` and carries its full C-ABI prologue. Before
editing, trace whether those calls remain in the scanner's release path. A
candidate may factor the exact `fgetc` state machine into a private helper for
the scanner and public entry, but must retain EOF/error/read-callback behavior
and the single-delimiter `ungetc` restoration. Run
`stdio_format_parse_regression`, including its one-byte and staged cases,
inspect release assembly, then collect three 31-sample performance reports;
do not retain or document a result without all of that evidence.

The current red rows are concrete rather than hypothetical:

| Route | Present crabc/musl CPU evidence | Immediate cause to remove |
| --- | ---: | --- |
| C `clock_gettime` ×200,000 | 1.0278×–1.0332× CPU upper bounds across three 31-sample `clock-universal-vdso-{matrix,repeat,repeat2}-31` reports; no marked-hot-loop `clock_gettime` syscall | Linux 5.10's AArch64 vDSO owns the direct-syscall fallback for IDs it cannot serve, so the C wrapper reaches the cached validated function without an eligibility branch chain. The direct CPU-clock and invalid-ID boundary preserves that delegation. The remaining indirect dispatch keeps the CPU row red. |
| C `gettimeofday` ×200,000 | 0.8915× CPU upper bound; 41 vs 10 non-marker calls and zero marked-region calls | bounded Linux/AArch64 `__kernel_gettimeofday` lookup eliminates the intermediate `clock_gettime` conversion and passes the CPU gate. |
| Scalar primitive matrix, 64 B / 16 KiB / 256 KiB, aligned and unaligned | 31-sample CPU upper bounds: `memcpy` 1.0500×–1.5891×; `memset` 1.0956×–1.8702×; `strlen` 0.5062×–0.8293×; `memchr` 0.8392×–0.8944×; `strstr` 0.2250×/0.2763×, 0.6524×/0.6700×, and 0.6683×/0.6666×; `memmem` 0.3780×–0.8529×. Every row has 41 crabc vs 10 musl fresh-process calls. | Direct C fixtures now cover all six primitives over fixed empty-to-256-KiB size bands, all 16 byte alignments, 0–64-byte protected tails, and deterministic randomized misalignment. The musl 1.2.6 GPR `memcpy` schedule improves every cache-resident copy row without runtime capability dispatch, but `memcpy`/`memset` still have no CPU-passing matrix row. `strlen`, `memchr`, `strstr`, and `memmem` pass every row. For `strlen`, the page-safe zero-byte mask’s little-endian lowest bit identifies the first terminator without a byte-at-a-time end-word scan. For `strstr`, one page-safe scalar zero-byte screen over `byte & (byte ^ target)` admits every NUL or target byte and confirms possible matches bytewise; it replaces the former separate target and NUL word predicates without widening a read. For `memmem`, a first byte at the only remaining needle-sized suffix permits direct bounded equality rather than the generic late-suffix loop. The syscall row is loader/startup work, not an inner-loop syscall. Schema-4 cache provenance proves these rows fit L1/L2; the separately reported 128-MiB rows exceed the recorded 64-MiB L3. |
| Cache-spanning primitive matrix, 128 MiB aligned and unaligned | Three 31-sample CPU upper bounds for `memcpy`: 0.9600×–0.9682× / 1.0498×–1.0694×; `memset` 1.1889×/1.2951×; `strlen` 0.7611×/0.7465×; `memchr` 0.7873×/0.7911×; `strstr` 0.5909×/0.6007×; `memmem` 0.7889×/0.7914×. Every row has 51 crabc vs 22 musl diagnostic calls. | Schema-4 classifies 128 MiB as exceeding benchmark CPU 0's reported 64-MiB L3. Source data is deterministic and lane-private; the copy/fill destination is `MAP_PRIVATE`. The scan/search rows pass; copy and fill remain red. The warm-page-cache fixture is not a cold-cache claim, and its report is `partial` only because the cgroup peak collector is unsupported. |
| `dlsym`, 1 / 128 / 1,025 symbols ×100,000 | 0.7413×–0.7569× / 0.7534×–0.7725× / 0.7166×–0.7680× CPU upper bounds; 49 vs 18 traced calls | Immutable GNU/SysV metadata and the bounded per-thread direct-definition cache pass every CPU row. The cache compares copied current C-string bytes rather than an address identity, and stores no global or fallback resolution, so mutable names and later global interposition retain the existing result. The whole-process syscall count remains red. |
| Five-DSO `dlopen_graph` | 1.1769×–1.2326× CPU upper bounds across three 31-sample `loader-path-pthread-followup-{,repeat,repeat2}` reports; prior lifecycle diagnostic: 65 vs 50 whole-process calls and 35 vs 40 marked calls | The bounded immutable initial `LD_LIBRARY_PATH` component cache removes repeated delimiter scanning without changing parent RUNPATH/RPATH, `$ORIGIN`, direct-name, or identity rules. The ordinary graph avoids the non-contract `/proc/self/exe` open/fstat/close probe. A direct pinned-musl regression proves that an explicit path to the main executable is nevertheless a distinct dlopen mapping; `argv[0]` remains introspection metadata rather than generic loader identity. CPU remains red. |
| Minimal PIE startup | 1.1908×–1.2958× CPU upper bounds across three 31-sample `kernel-main-image-*-31` reports; 30 vs 10 traced calls | Linux maps the PIE before `PT_INTERP`; consume its validated `AT_PHDR`/`AT_PHENT`/`AT_PHNUM`/`AT_ENTRY` layout in place instead of retaining a second mapping. The direct musl differential proves one executable mapping. Separate-image loading and eager allocator initialization remain. The pinned `libmimalloc-sys` 0.1.49 build interface exposes no `MI_NO_AUTOMATIC_INIT` control, so deferring `mi_process_attach` would require a patched allocator integration rather than a supported mimalloc configuration. |
| Constructor/destructor PIE startup | 1.1502×–1.1809× CPU upper bounds across three 31-sample `kernel-main-image-*-31` reports; 29 vs 9 whole-process calls; both marked `main` routes make exactly one output write | Constructor-before-`main` and destructor-after-`main` ordering remain proven without hiding their cost. The direct main-image regression and complete loader suite preserve the startup boundary. Remove only loader or runtime work not required by that lifecycle. |
| Startup-linked five-DSO graph | 1.1687×–1.2205× CPU upper bounds across three 31-sample `kernel-main-image-*-31` reports; 65 vs 50 whole-process calls; marked regions contain one reference `ioctl`/`writev` output path and two candidate writes | The initial-graph cache still removes repeated same-path probes without applying to aliases, `$ORIGIN`, or runtime `dlopen`; consuming the kernel main image removes its duplicate map/open/read lifecycle. The whole-process CPU result remains red, although its syscall gate passes. |
| C `stdio_format_parse` ×1,000 | 1.0328×–1.0585× CPU upper bounds across five `stdio-direct-local-lookahead-{matrix,repeat,repeat2,final,final2}-31` reports; 6.003 vs 6.211 marked calls/op | A successful `fseek` records its exact kernel position until I/O invalidates it, so a generic staged scanner retains its existing seekability route. The ordinary no-length scalar grammar now parses directly from `FILE`, keeps one local delimiter, and restores it through `ungetc` instead of reading ahead to EOF. The direct-musl-differential contract exercises that path with a one-byte buffer, separately forces staged `%n` seek-back, and invalidates the cache with an unbuffered read. The marked syscall gate passes; CPU remains red. |
| C `stdio_file_4k` ×100 | 0.9865×–1.0168× CPU upper bounds across three 31-sample `stdio-current-cancel-{31,repeat-31,repeat2-31}` reports; 5.03 vs 8.00 marked calls/op | `fdopen` clears its complete `FILE` state but not the trailing buffer that its read/write paths initialize before consumption. `__stdio_read` checks only its already-published current pthread slot at its cancellation points, while public `pthread_testcancel` retains lazy foreign-thread registration. The direct pinned-musl lifecycle regression and ten-iteration pthread stress prove `O_CLOEXEC`, descriptor ownership after `fclose`, write/flush/seek, buffered reads, `ungetc`, and deferred/asynchronous stdio cancellation. The syscall gate passes, but CPU remains red. |
| C `pthread_create_join_tls` ×1,000 | 0.8911×–0.9171× CPU upper bounds across three 31-sample `pthread-tls-single-tcb-init-{matrix,repeat,repeat2}-31` reports; 6.000 vs 11.966 musl marked calls/op | One page-aligned mapping places TLS above the downward-growing stack; candidate marked `mmap`/`munmap` match musl at one each. Normal `pthread_join` checks cancellation once after each futex return, rather than again at the next loop boundary. The new pinned-musl stress regression cancels a blocked joiner and then proves a later join returns its target's result. Ordinary worker exit still skips the independent `detach_state` wake, while a timed join marks interest in that futex word before waiting so exit either wakes it or changes its expected value first. The 513-lifetime static-TLS/pthread-key differential, dynamic-TLS regressions, ten-iteration pthread stress, and loader cases pass. Candidate syscalls pass, but CPU remains red. |
| C `loader_dynamic_tls_growth` ×8 | 1.3184×–1.3977× CPU upper bounds across three 31-sample `tls-module-frontier-*-31` reports; the matched 101-sample candidate/baseline pair is 1.3193×/1.3412×; 8.125 vs 13.125 marked calls/op | The direct matched eight-DSO contract proves a worker predating all loads receives every initialized image and its writes are thread-local; the adjacent optimized parent/child graph proves one `dlopen` initializes every TLS module in a `DT_NEEDED` closure, while the 4-KiB-aligned regression proves TLSDESC migration refreshes its cached TP. Each TCB allocation records the append-only module frontier it has initialized, so growth touches only the missing suffix rather than repeatedly scanning the preserved prefix. `tests/ldso_no_relro_relocation.rs` differentials a no-RELRO packed-`DT_RELR` DSO against musl and proves a second load does not replay its in-place relocation. Runtime relocation and RELRO operate only on the appended dependency-graph suffix, so that correctness boundary also removes prior-object scans. Reusing a fitting allocation removes repeated block swaps, and the musl-matched initial `libc.so` short name removes redundant dependent-libc opens/stats without changing general runtime identity matching. The initial lowest-`PT_LOAD` file mapping covers the final span before later fixed overlays, removing eight anonymous reservations: the trace records 17 candidate mappings versus 18 musl. The marked syscall gate passes; CPU remains red. |
| C `pthread_mutex_uncontended` ×2,000,000 | 0.6066×–0.6109× CPU upper bounds across three 31-sample `pthread-mutex-release-store-*-31` reports; zero marked calls in both lanes | Inline AArch64 `ldaxr`/`stlxr` compare-exchange retains the acquisition contract. Normal unlock reads its advisory waiter count without an acquire barrier and emits one release `stlr` when it observes no waiter; any observed waiter retains the prior exchange-and-wake path. Direct Musl differentials, the condition handoff regression, and broad pthread stress preserve the waiter retry/wake protocol. The CPU gate passes. |
| C `pthread_mutex_cond_ping_pong` ×10,000 | 0.9963×–1.0043× CPU upper bounds across three 31-sample `pthread-cond-current-cancel-{,repeat,repeat2}` reports; 6.0007–6.0021 vs 6.0022–6.0052 marked calls/op | The direct-matched parent/worker protocol proves each handoff's two protected increments. The condition sequence and waiter counters retain the inline AArch64 acquire/release fetch-add exclusive loop instead of LLVM's outlined LSE capability dispatch; signal and broadcast retain their musl-matched relaxed advisory waiter hint. `pthread_cond_wait` uses private exact mutex lock/unlock helpers after its private timed-wait route, and its cancellation points inspect the already-published current pthread slot without entering the public lazy-registration route. A caller with no slot cannot have a crabc cancellation request; pthread-created waiters publish their slot before user code. The public cancellation ABI, weak/default-visible C ABI, mutex/sequence synchronization edge, futex boundary, and 10-iteration pthread-stress result are unchanged. The CPU gate remains red. |

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

## Measurement and optimization method

Stable isolation, provenance, statistical, syscall, memory, build-profile, scalar-first, SIMD, math, and crypto rules live in [`docs/design/performance.md`](../design/performance.md) and [`compat/perf/README.md`](../../compat/perf/README.md). This roadmap owns the changing scorecard, red/unsupported rows, completion sequence, and release gates.

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
complete. Linux 5.10's AArch64 vDSO owns the exact direct-syscall fallback for
IDs it cannot serve from its data page, so every public clock ID reaches the
cached validated function without an eligibility branch chain. The marked hot
loop has no direct `clock_gettime` syscall. Three 31-sample
`clock-universal-vdso-{matrix,repeat,repeat2}` reports place the monotonic C
route at 1.0278×–1.0332× CPU upper bound: this satisfies the scoped P0
provisional `<= 1.05x` gate, while remaining red against the final `<= 0.90x`
release gate. Process CPU time, invalid-ID `EINVAL`, missing metadata, and
malformed metadata remain direct boundaries. Fresh-process work and the
remaining indirect vDSO dispatch are still counted by the release gates.

- Parse the Linux auxiliary vector/vDSO ELF safely in `crabc-core`.
- Resolve the correct `__vdso_clock_gettime` symbol with bounded validation;
  call it for supported clock IDs and retain direct-syscall fallback for
  absent, malformed, or rejected vDSO data.
- Route both the C ABI and `crabc-rs::time` through the same typed dispatch.
- Test vDSO success, forced fallback, malformed metadata, error propagation,
  and all supported clock semantics against musl/POSIX evidence.

**Provisional exit:** the `clock_gettime` route meets the scoped `<= 1.05x`
CPU gate, has zero marked steady-state syscalls, and retains all direct
vDSO/fallback/error evidence. No direct time syscall may remain in a
vDSO-success hot loop.

**Release exit:** time rows meet the final CPU, memory, syscall, and
correctness gates. The final CPU requirement remains `<= 0.90x` musl.

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
row remains red. Three `loader-path-pthread-followup-{,repeat,repeat2}`
reports place the five-DSO graph at 1.1769×–1.2326× CPU after caching the
immutable initial `LD_LIBRARY_PATH` components through a bounded 16-entry
fast path. The cache falls back to bytewise scanning and does not apply to
parent RUNPATH/RPATH, `$ORIGIN`, or direct names. The prior lifecycle
diagnostic remains 65 versus 50 whole-process calls, with 35 versus 40 marked
calls because only musl applies `FD_CLOEXEC` to each DSO. The direct self-image
differential keeps an explicit executable path distinct from `dlopen(NULL)`.
Its CPU row remains a measured gap, not missing data.

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
- Run the dependency-free native-facade standard-library-aware lane, then the resolved
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
