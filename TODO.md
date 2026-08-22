# Active TODO — Linux/AArch64

This is the living, scope-filtered work list for `crabc`. It replaces the
chronological “next” language in [the historical delivery records](docs/history/)
as the planning source. The exact machine-readable capability state remains
[`compat/crabc-rs/coverage.toml`](compat/crabc-rs/coverage.toml): this document
is its reviewed, human-oriented projection.

Current scope is Linux/AArch64 little-endian with Linux 5.10 as the kernel
baseline. Every item below needs a narrow contract, observable tests,
Linux/AArch64 direct-boundary or ABI evidence where applicable, and musl/POSIX
evidence appropriate to its C behavior. Do not start several broad families
at once.

## Current status

M0–M12 are complete. Current ledger validation records 171 verified native
seams, no deferred native capability groups, and 52 documented non-native
boundaries. The current generated dashboard records 1,647/1,647 required musl
dynamic exports, no ABI metadata mismatch, 34/34 measured Alpine corpus cases,
and no current libc-test missing-symbol blocker. The current full libc-test
report records 405/420 passing cases, 15 documented skips, and no failures.
These measurements are
evidence, not a claim of complete historical libc breadth.

The C `setreuid`, `setregid`, `seteuid`, and `setegid` success stubs are now
an explicitly tested `-1/EOPNOTSUPP` profile limitation; full musl-compatible
process-wide credential synchronization is an explicitly documented non-native
boundary.

Since this ledger was created, `getpagesize` and `_SC_PAGE_SIZE` have been
made `AT_PAGESZ`-driven (including an 8 KiB synthetic-startup regression), and
the AArch64 loader has a focused `AT_BASE` self-relocation runtime case. They
are retained here as completed scope records, not active work.

The M11 loader introspection row is now verified: `LoadedImageSnapshot` and
`Library::information` copy bounded records through the append-only runtime
bridge without exposing `link_map` or invoking callbacks while ldso is locked.

The named temporary-file row is now verified as `fs::NamedTempFile`; it uses
exclusive descriptor-relative creation, 96-bit `getrandom` suffixes,
`O_CLOEXEC`, and owned unlink-on-drop cleanup. The anonymous `fs::TempFile` row
is also verified through Linux `O_TMPFILE`, with no named-file fallback.
`mktemp`/`tempnam`/`tmpnam` and Linux file-handle operations remain documented
C-only or authority-bearing boundaries rather than a generic native filesystem
API.

The caller-owned resolver row is now verified as `ResolverConfig`: bounded
`/etc/resolv.conf` and `/etc/hosts` snapshots, explicit hosts-before-DNS
precedence, ndots/search candidate ordering, A/AAAA lookup, bounded CNAME
completion, and the existing configured-order retry/failover transport. It
does not discover NSS providers or add DNSSEC, DoH/DoT, mDNS, or IDNA policy.

## Measured performance frontier

The scoped C and native measurement matrix is now available through
`./scripts/dev.sh perf --label NAME` and `./scripts/dev.sh perf-native --label
NAME`. It compares the same musl-compiled C workload under staged musl/crabc
runtimes and direct `crabc-rs` calls against Rustix, respectively. Timing,
isolated user/system CPU, RSS/PSS, faults, context switches, Rust allocation
accounting, and separate syscall diagnostics are retained in ignored local
reports. Read [`docs/design/performance.md`](docs/design/performance.md) before
changing one of these routes; it records the complete selected evidence,
interpretation boundary, and harness contract.

[`goal.md`](goal.md) is the performance completion contract: it defines the
per-workload CPU, peak-memory, syscall, correctness, and evidence gates needed
before crabc can claim to outperform musl on its supported scorecard. It does
not supersede this living work list.

[`goal2.md`](goal2.md) is deliberately subsequent: it expands the successful
focused scorecard into a measured corpus of real Alpine software and direct
`crabc-rs` applications. Do not let it delay the current focused performance
frontier.

[`pregoal.md`](pregoal.md) is now a permanent completed gate: its isolated Lua
5.4.8 source build, shared interpreter runtime, extension loading, bytecode,
and candidate-loader mapping evidence pass through `./scripts/dev.sh lua`.
It remains the evidence and failure taxonomy for promoting an adapter-sysroot
CPython 3.14.3 source build; retain it while starting `goal.md` work.

| Priority | Exact work still left | Evidence boundary |
| --- | --- | --- |
| P0 | Carry the validated Linux/AArch64 vDSO time routes through the release scorecard. The cached bounded-ELF resolver, C ABI, and `crabc-rs` now share one direct-syscall fallback route. | Schema-5 adds a descriptor-only marker protocol to the separate `strace` diagnostic. `marker-clock-schema5-smoke` proves zero marked-hot-region `clock_gettime` calls in both lanes while preserving 10 musl versus 41 crabc non-marker whole-process calls; `marker-getpid-schema5-smoke` proves the same boundary reports one syscall per operation for a syscall-bearing loop. The C ABI now sends its common realtime/monotonic IDs straight to the validated cached vDSO entry rather than repeating the generic eligibility screen: three `clock-known-vdso-*-31` reports lower its CPU upper bound to a still-red 1.0406×–1.0699×. The musl-differential `gettimeofday` C boundary test and `gettimeofday-direct-vdso-matrix-31` now pass the realtime CPU gate at 0.8915× with zero marked calls and 41 vs 10 non-marker whole-process calls. Its bounded ELF lookup validates Linux/AArch64 `__kernel_gettimeofday` and caches the typed direct-syscall fallback. Native `crabc-rs`/Rustix record 18/19 ns. Preserve forced-fallback and malformed-vDSO tests. |
| P1 | Carry indexed GNU/SYSV loader lookup and TCB-cached error/lock ownership through the release scorecard. Preserve interposition semantics while removing the remaining fixed lookup cost. | Three CPU-pinned, interleaved, 31-sample `dlsym-handle-local-cache-matrix-31` reports now pass their CPU gates at 0.7413×–0.7569× / 0.7534×–0.7725× / 0.7166×–0.7680× musl CPU for 1/128/1,025 exports. A bounded per-thread cache records only a direct definition from the requested handle and validates copied current C-string bytes, so mutable symbol arrays and later global interposition retain their existing behavior. The mutable-name direct musl differential and full loader suite cover that boundary. The 49 vs 18 whole-process syscall row remains red. The five-DSO graph is 1.22×–1.25× CPU; its 98 vs 50 calls pass the syscall gate. |
| P1 | Remove scalar work from the measured primitive rows before proposing SIMD. | Direct C regressions cover all six primitives over fixed empty-to-256-KiB bands, every 0–15-byte starting offset, 0–64-byte guarded tails, and deterministic randomized misalignment. The 31-sample matrix adds 64-byte/16-KiB/256-KiB aligned and unaligned CPU rows. Schema-4 cache provenance records 128 KiB L1 data, 12 MiB L2, and 64 MiB L3 for CPU 0; lane-private 128-MiB aligned/unaligned rows exceed the recorded L3. `strstr` now combines its page-safe target/NUL screen with `byte & (byte ^ target)`: either relevant byte makes that byte zero, and bytewise confirmation makes other zero-producing values harmless. Three repeated 31-sample reports put the formerly red 16-KiB unaligned row at 0.6435×–0.6459×; the fresh full cache-resident matrix passes every `strstr` row at 0.2250×–0.6700×, and the 128-MiB rows pass at 0.5909×/0.6007×. The pinned musl 1.2.6 GPR `memcpy` schedule in `libc/src/aarch64_memory.rs` improves every cache-resident copy row to 1.0500×–1.5891× and records 0.9600×–0.9682× aligned / 1.0498×–1.0694× unaligned at 128 MiB; no copy row passes yet. `memset` remains red at 1.0956×–1.8702× cache-resident and 1.1889×/1.2951× cache-spanning. Two-word scans bring cache-resident `memchr` to 0.8392×–0.8944×; using the little-endian low bit of the page-safe zero-byte mask brings every `strlen` row to 0.5062×–0.8293×. Recognizing the only possible terminal `memmem` candidate avoids the generic late-suffix loop and passes all of its rows at 0.3780×–0.8529×. The span diagnostic is 51 vs 22 whole-process calls and the report is partial only for the unsupported cgroup peak collector. SIMD/assembly remains an independently verified optimization. |
| P1 | Reduce verified local file-descriptor and buffered-I/O work without relaxing their C boundary checks. | `stdio-file-readv` adds staged deterministic 4-KiB inputs. `fd_file_4k` validates `O_CLOEXEC`, `F_GETFD`, `fstat`, `pwrite`, `pread`, and close. AArch64's `fcntl` entry handles the two no-argument commands before Rust must spill a variadic register-save area, then tail-branches every argument-bearing/unknown command to the existing typed decoder. Three fresh 31-sample `fcntl-noarg-entry-matrix-31` reports reduce the `fd_file_4k` CPU upper bound to 0.9205×–0.9365×, but it remains red; `stdio_file_4k` validates `fread`/seek/`ungetc` at 1.05×. `stdio-format-cached-seek-matrix-31` preserves the direct-musl-differential formatted-record contract: `fprintf`/flush/rewind/`fscanf`, bounded `snprintf`/`sscanf`, and the ordered unread tail. A successful `fseek` records its exact kernel position only until a read or write invalidates it, so the immediately following buffer-empty scanner avoids a redundant `SEEK_CUR` probe while all other streams retain the existing route. The direct fixture forces its seek-back fallback through a one-byte FILE buffer and proves an unbuffered read invalidates the cache before another scan. The row improves to 1.0452× CPU and 7.003 vs 6.211 marked calls/op, but both gates remain red; the next source frontier is the scanner's deliberate EOF read. |
| P1 | Reduce measured pthread/TLS and loader-TLS growth work without relaxing their lifecycle contracts. | `pthread-slot-publication-matrix-31` creates and joins one worker per operation. Its three 31-sample reports improve the CPU upper bound to 1.1089×–1.1364× while retaining 9.000 versus 11.977 musl marked calls/op. A normal creator claims a free slot before scanning for completed detached workers, and a released slot publishes only `tid == -1`: the next successful claimant alone resets private fields and the fixed TSD array. The shared direct-musl-differential contract proves the child static-TLS initializer, child pthread-key value, join result, and untouched parent static TLS across 513 lifetimes; broad pthread stress preserves detached-slot reclamation. Separate stack/TLS mappings and thread-start work remain the CPU frontier. `pthread-mutex-fast-lock-unlock-matrix-31` adds 2,000,000 normal-mutex protected increments per process: both marked regions make zero syscalls, and inline AArch64 `ldaxr`/`stlxr` compare-exchange and exchange primitives remove LLVM's per-operation outlined LSE probe. The direct Musl differential proves both acquisition and a busy `trylock`; broad pthread stress and the condition handoff regression preserve its failure/retry and wake semantics. The CPU upper bound falls from 1.3906× to a still-red 1.0095×. `pthread-cond-inline-atomics-matrix-31` applies the same verified atomic primitives to the 10,000-round parent/worker condition protocol: after the earlier fixed-spin removal, its upper bound falls further from 1.0372× to a red 1.0167× with matched 6.0021 vs 6.0030 marked calls/op. `loader-dynamic-tls-libc-shortname-matrix-31` loads eight optimized TLS DSOs after a worker already exists. Its direct musl differential proves all missing images are initialized exactly once; the adjacent optimized parent/child test proves one `dlopen` initializes every TLS module in its `DT_NEEDED` graph, and the 4-KiB-aligned TLS regression proves its AArch64 TLSDESC resolver refreshes a migrated TP while the assembly stub preserves the descriptor ABI's `x2` route. Reusing an allocation only when its recorded capacity and TP placement still fit removes repeated block replacement. Mirroring musl's initial `libc.so` short name for that exact `DT_NEEDED` edge removes redundant dependent-libc opens/stats without extending general runtime alias reuse. The lowest `PT_LOAD` now maps the complete file span and later segments overlay it, removing the separate anonymous reservation from every small DSO: the dynamic-TLS trace falls from 25 candidate mappings to 17 versus 18 musl and 8.125 versus 13.125 marked calls/op. Three CPU-pinned 31-sample reports range from 1.2876× to 1.3901×, still red. Inspect remaining relocation and close work rather than weakening the eight-image lifecycle. Direct and broad pthread stress evidence preserve the release/retry and wake semantics. |
| P2 | Account for and reduce non-essential loader startup mappings/syscalls. | Retained ASLR reservations removed two `munmap` calls, and file-first/anonymous-tail `PT_LOAD` mapping removed two redundant overlays: the minimal PIE remains 44 candidate calls versus 10 musl calls. `startup-contract-matrix-31` extends that audit to the required constructor/destructor PIE (39 vs 9 calls; 1.2346× CPU upper bound). In `startup-resolution-cache-matrix-31`, the startup-linked five-DSO graph falls from 95 to 80 calls versus musl's 50 (1.1811× CPU): a direct trace proves one staged `libc.so` open rather than repeated open/`fstat`/close probes. The cache is limited to the exact bare name that first resolved through the immutable initial `LD_LIBRARY_PATH`; alias identity, parent RUNPATH/RPATH, direct paths, and runtime `dlopen` retain inode matching. All schema-5 marker regions are complete, so the remaining whole-process cost is loader lifecycle rather than a missing fixture boundary. Separate ldso/libc image loading and mimalloc's upstream eager process constructor remain the concrete suspects. |
| Scope decision | Resolve the universal allocator-plateau memory gate without starting allocator research. | The bounded audit finds one direct mimalloc domain and no duplicate wrapper allocation state. `smaps` attributes about 47.3 MiB of crabc PSS to anonymous mappings versus 33.3 MiB for musl, but a fully touched 32-MiB payload alone exceeds 90% of musl's total PSS. The fresh-cgroup `memory.peak` collector is explicitly unsupported under Docker's read-only cgroup mount. A user must choose the allocator scope change in `goal.md`; no configuration can make this fixture meet the present universal PSS target. |
| Tooling | Resolve Rustybench’s dependency-bearing `-Z build-std` duplicate-`core` limitation before using it for build-std timing. | The dependency-free M12 `std,panic_abort` fat-LTO application proof is green; the Rustybench route records explicit unsupported evidence rather than a false measurement. |

The pthread/TLS table's earlier `pthread-slot-publication-matrix-31` range is
historical. `pthread-combined-stack-tls-create-matrix-31` records the current
0.9441×–1.0258× CPU upper-bound range across three runs, with 7.000 versus
11.977 musl marked calls/op. A page-aligned combined allocation leaves dynamic
TLS above the downward-growing stack and reduces the normal lifecycle to one
`mmap`/`munmap`; cleanup refreshes a worker's current TLS block after late
`dlopen` migration. The 513-lifetime direct differential, dynamic-TLS cases,
and broad pthread stress pass, but the CPU gate remains red.

## Core runtime capability work

| Ledger group | Exact work still left | Do not repeat |
| --- | --- | --- |
| _(none)_ | The currently scoped core runtime slices are complete. | Select a new bounded contract only after updating the ledger and evidence plan. |

## Useful POSIX/runtime capability work

| Ledger group | Exact work still left | Boundary |
| --- | --- | --- |

## Evidence and maintenance frontiers

These are not hidden feature commitments. Promote one only when it helps a
selected scoped capability.

- Expand static-link evidence beyond the existing static pthread/TLS lifecycle
  case; a full static libc-test matrix remains unmeasured.
- Decide whether exhaustive static-archive ABI comparison and broader
  header-feature/layout probing are worth their cost. The current selected ABI
  probe is green but intentionally not exhaustive.
- Use focused fuzzing/property/failure-path testing for high-value parsers and
  ownership state machines when changing them.
- Expand the selected performance matrix only when a design or regression
  requires a new route. Preserve M12’s bounded LTO/build-std proof; raw
  one-shot LTO timings are not a benchmark substitute.
- Extend POSIX, loader, or real-program evidence only in response to a defined
  contract. Existing selected suites are not claims of full standards or
  arbitrary Alpine DSO-graph coverage.

## Not TODO

The 52 `documented` ledger groups are accounted boundaries, not a hidden
backlog. They include C ABI-only machinery, Rust-subsumed operations, internal
runtime exports, and the mimalloc allocator exception. Their exact rationale
is in [`compat/crabc-rs/coverage.toml`](compat/crabc-rs/coverage.toml).

The following are deliberately outside project scope unless the user changes
it explicitly: x86_64, RISC-V, 32-bit, big-endian, and non-Linux `crabc`;
glibc as an oracle or fallback; allocator research; hand-rolled cryptography;
general locale/charset databases; NSS/plugins; bundled tzdata; gettext;
DNSSEC, DoH, DoT, mDNS, and IDNA policy; async runtimes; process-management
frameworks; security-policy frameworks; and a portability abstraction layer.

The bounded native netdb slice is complete for immutable owned snapshots,
lookups, and source-order enumeration of `/etc/hosts`, `/etc/services`, and
`/etc/protocols`. The C static-buffer netdb ABI, `/etc/networks`, and
NSS/provider systems remain outside that slice. Resolver integration is the
separate caller-owned `ResolverConfig` slice described above.

The bounded native glob slice is complete for explicit root path or directory
descriptor expansion. Results own raw pathname bytes and are sorted
lexicographically; no-match returns an empty vector, while root and directory
read errors remain typed. The C `glob`/`globfree` ABI and hidden CWD traversal
policy remain outside this native contract.

The first native IPC slice is complete for owned POSIX named message queues:
open/create, unlink, attributes, priorities, caller buffers, nonblocking
behavior, and absolute realtime deadlines. `mq_notify`, SysV IPC, named
semaphores, AIO, and aggregate IPC frameworks remain outside scope.

The bounded native PTY/session slice is complete for an owned master/slave
`PtyPair`, caller-buffered or owned `ptsname` results, and an explicitly
unsafe Linux session/controlling-terminal handoff. `forkpty`, `login_tty`,
and `vhangup` remain C-only historical helpers because they require process
supervision, prepared-exec, or hangup-authority contracts; `isastream` has no
Linux PTY meaning.

The remaining historical C regex, process-control, credential, environment,
signal, pthread/C11, calendar/clock, and kernel-administration families have
been reviewed against `SCOPE.md`. Their useful native seams are already
separately verified; the rest are C ABI behavior, explicitly constrained
compatibility, or out-of-scope frameworks rather than native crabc-rs work.
The ledger records each rationale and evidence. In particular, process-wide
credential mutation remains the tested C `EOPNOTSUPP` limitation rather than
an unsafe per-thread facade, and global `TZ`/locale/time-control behavior does
not become a native policy layer.

## Choosing the next slice

Start with a single ledger row. Write the ownership/state contract and focused
regression first, then implement against Linux 5.10, prove the boundary, and
update the ledger, this TODO, nearby documentation, and the relevant report.
If the work would need a new dependency, perform the dependency review in
[`SCOPE.md`](SCOPE.md) and obtain the required user approval before adding it.
