# Performance evidence and optimization frontier

This document records selected, reproducible Linux/AArch64 evidence. It is not
a universal performance claim for either crabc or musl. Musl 1.2.6 is the C
runtime oracle; Rustix 1.1.4 is the native-facade comparison input. Glibc is
not measured or used as a fallback.

## Measurement contract

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

Reports are ignored local evidence under `compat/reports/perf/`; compare only
runs with matching host provenance, fixture hash, sample contract, and runtime
artifact hashes. The detailed harness contract lives in
[`compat/perf/README.md`](../../compat/perf/README.md).

## Current selected results

The 2026-08-21 fat-LTO baseline used 15 fresh C processes per lane and
workload. The clock rows are superseded by the 2026-08-22
`vdso-dispatch-hotpath` diagnostic, loader CPU rows by three 2026-08-22
`loader-interleaved-pinned-31` reports, and startup by paired 2026-08-22
`loader-file-first-tail` reports. The scalar rows are superseded by paired
15-sample 2026-08-22 `strstr-two-way-safe` and
`memmem-word-prefilter` reports after the loader's bootstrap `strlen` was
hidden from public lookup. The scalar rows are further superseded by the
2026-08-22 31-sample `scalar-matrix-31` report and, for copy/fill, by the
2026-08-22 `musl-aarch64-memcpy-kernel-matrix-31` report. CPU ratios are candidate/musl
median user+system CPU time; scalar matrix cells below are one-sided 95% upper
bounds in the order 64-byte aligned/unaligned, 16-KiB aligned/unaligned, then
256-KiB aligned/unaligned.

| Route | Evidence | Interpretation | Priority |
| --- | ---: | --- | --- |
| C `clock_gettime` ×200,000 | 1.0388×–1.0432× one-sided CPU upper bounds across three 31-sample `clock-zero-status-{matrix,repeat,repeat2}` reports; zero `clock_gettime` calls in the marked hot loop | realtime/monotonic C calls bypass the generic seven-ID eligibility check and enter the validated cached vDSO route directly. Its exact zero-or-negative-errno status contract sends successful calls through one zero test before return. The CPU gate remains red; fresh-process cost and the remaining indirect vDSO dispatch are still measured | P0 |
| C `gettimeofday` ×200,000 | 0.8915× one-sided CPU upper bound; 41 crabc vs 10 musl non-marker calls and zero marked-region calls | bounded lookup of Linux/AArch64 `__kernel_gettimeofday` avoids `clock_gettime` result conversion and passes the CPU gate | no selected gap |
| Native `clock_gettime` ×1,000/sample | 18 ns crabc-rs vs 19 ns Rustix | the shared core route now reaches the selected native target | no selected gap |
| C `memcpy` scalar matrix | 1.1550×/1.1562×; 1.0670×/1.5891×; 1.0500×/1.2220× | pinned musl 1.2.6's GPR-only short/medium/long copy schedule replaces the compiler's generic copy loop; every row improves but remains CPU-red | P1 |
| C `memset` scalar matrix | 1.1788×–1.1801× / 1.1615×–1.1743×; 1.1186×–1.1469× / 1.7185×–1.7955×; 0.9163×–1.0589× / 1.2883×–1.6508× across three 31-sample runs | musl 1.2.6's generic bounded head/tail schedule now uses explicit AArch64 GPR stores, preventing LLVM from silently changing the scalar route into NEON. All CPU bounds remain red; unaligned medium/large fills are still the largest gap | P1 |
| C `strlen` scalar matrix | 0.8293×/0.5062×; 0.7785×/0.8165×; 0.7828×/0.7939× | the page-safe zero-byte mask’s little-endian low bit identifies the first terminator without a byte-at-a-time end-word scan; every row passes | no selected gap |
| C `memchr` scalar matrix | 0.8856×/0.8392×; 0.8944×/0.8918×; 0.8740×/0.8920× | the exact-range two-word scan passes every row | no selected gap |
| C `strstr` scalar matrix | 0.2250×/0.2763×; 0.6524×/0.6700×; 0.6683×/0.6666× | one page-safe scalar zero-byte screen over `byte & (byte ^ target)` covers both a target-byte match and NUL, then confirms candidates bytewise; every row passes | no selected gap |
| C `memmem` scalar matrix | 0.4187×/0.3780×; 0.7821×/0.8078×; 0.8529×/0.8310× | a first byte beginning the only needle-sized suffix has one legal candidate, so direct bounded equality avoids the generic late-suffix loop; every row passes | no selected gap |
| C 128-MiB cache-span matrix | `memcpy` 0.9600×–0.9682× / 1.0498×–1.0694× across three 31-sample runs; `memset` 1.1315×–1.1922× / 1.1947×–1.2334×; `strlen` 0.7611×/0.7465×; `memchr` 0.7873×/0.7911×; `strstr` 0.5909×/0.6007×; `memmem` 0.7889×/0.7914× | the named input exceeds the recorded 64-MiB L3. The scan/search rows pass, while copy/fill remain red; each row records 51 crabc versus 22 musl whole-process diagnostic calls | P1 |
| C `fd_file_4k` ×5,000 | 0.9205×–0.9365× one-sided CPU upper bounds across three 31-sample `fcntl-noarg-entry-matrix-31` reports; 30,041 crabc calls vs 35,010 musl | an AArch64 no-argument `fcntl(F_GETFD/F_GETFL)` entry avoids Rust's variadic register-save area and tail-branches all other commands to the typed decoder. The syscall gate passes, but every CPU upper bound remains above 0.90× | P1 |
| C `stdio_file_4k` ×100 | 1.05× one-sided CPU upper bound; 544 crabc calls vs 810 musl | musl-shaped `readv` lookahead, buffered `fread`, seek, and `ungetc` preserve the selected C contract; the syscall gate passes but CPU remains red | P1 |
| C `stdio_format_parse` ×1,000 | 1.0452× one-sided CPU upper bound; 7.003 crabc vs 6.211 musl marked calls/op | lane-private formatted records prove `fprintf`/flush/rewind/`fscanf`, bounded memory formatting/scanning, and ordered unread-tail preservation. A successful seek records its kernel position until I/O invalidates it, removing the immediately following scanner's redundant `SEEK_CUR` probe; the direct differential forces the seek-back fallback with a one-byte FILE buffer and proves an unbuffered read invalidates the cache before another scan. CPU and the syscall gate remain red because the scanner still performs a deliberate EOF probe | P1 |
| C `pthread_create_join_tls` ×1,000 | 0.9195×–0.9541× one-sided CPU upper bounds across three 31-sample `pthread-create-tsd-loader-publish-*-31` reports; 7.000 crabc vs 11.977–11.990 musl marked calls/op | one page-aligned mapping places the TLS block above the downward-growing stack, matching musl at one marked `mmap` and `munmap` per operation. Exit skips an empty destructor pass and recycles only exact occupied TSD slots; the loader's one-way transition runs once through inline AArch64 compare-exchange before the first `clone`. The direct musl differential proves 513 lifetimes, a rearming destructor, no-destructor slot reuse, and all `PTHREAD_KEYS_MAX` null-destructor keys; dynamic-TLS regressions, pthread stress, and loader cases pass. CPU remains red | P1 |
| C `loader_dynamic_tls_growth` ×8 | 1.3184×–1.3977× one-sided CPU upper bounds across three 31-sample `tls-module-frontier-*-31` reports; the matched 101-sample candidate/baseline pair is 1.3193×/1.3412×; 8.125 crabc vs 13.125 musl marked calls/op | one worker predates eight literal-path TLS DSOs; every worker image must retain its initializer and remain isolated from the parent's write before all handles close. Each allocation now records its append-only module frontier in loader-private TCB storage, so a generation mismatch materializes only the absent suffix and never rescans or reinitializes the written prefix. Per-allocation capacity/TP checks still initialize fitting images in place, and the initial `libc.so` short-name reuse eliminates redundant dependent-libc probing. The lowest `PT_LOAD` supplies the complete initial file mapping and later segments overlay it, reducing the diagnostic from 25 to 17 candidate `mmap`s (18 musl). A no-RELRO packed-`DT_RELR` direct musl differential proves that a later load does not replay an earlier object's in-place relocations; relocation and RELRO now operate only on the newly appended graph suffix. The marked syscall gate passes, but mapping/relocation CPU remains red. The direct optimized TLS regression suite also proves parent/child `DT_NEEDED` TLS graphs and TLSDESC refresh of a migrated cached thread pointer | P1 |
| C `pthread_mutex_uncontended` ×2,000,000 | 0.6066×–0.6109× one-sided CPU upper bounds across three 31-sample `pthread-mutex-release-store-*-31` reports; zero marked calls in both lanes | inline AArch64 `ldaxr`/`stlxr` compare-exchange retains the acquisition contract. For an unordered zero waiter hint, normal unlock now uses one release `stlr`; an observed waiter retains the established exchange-and-wake path. The direct Musl differentials, condition handoff regression, and 10-iteration pthread stress preserve the retry/wake protocol. The CPU gate passes | no selected gap |
| C `pthread_mutex_cond_ping_pong` ×10,000 | 1.0035×–1.0052× one-sided CPU upper bounds across three 31-sample `pthread-cond-direct-mutex-{matrix,repeat,repeat2}-31` reports; 6.0007–6.0021 crabc vs 6.0022–6.0052 musl marked calls/op | two protected increments and condition handoffs per round prove deterministic contention; the sequence and waiter increments use the inline AArch64 acquire/release fetch-add exclusive loop rather than LLVM's outlined LSE capability dispatcher. `pthread_cond_wait` uses private exact mutex lock/unlock helpers after its existing private timed-wait route, matching musl's internal binding and removing the two public mutex PLT calls per wait; the weak/default-visible C ABI, sequence futex, advisory waiter hint, and 10-iteration pthread stress remain unchanged. The result stays above the 0.90× gate | P1 |
| `dlsym` against 1 / 128 / 1,025 symbols ×100,000 | 0.7413×–0.7569× / 0.7534×–0.7725× / 0.7166×–0.7680× CPU upper bounds; 49 crabc calls vs 18 musl | immutable GNU/SysV metadata and a bounded per-thread cache close all three CPU rows. It caches only a direct definition in the requested handle and verifies copied current C-string bytes, preserving mutable-name and global-interposition behavior. The whole-process syscall gate remains red | P1 |
| Five-DSO `dlopen_graph` | 1.2334×–1.2695× CPU upper bounds across three 31-sample `main-self-identity-*-31` reports; 65 crabc vs 50 musl whole-process calls, 35 vs 40 marked calls | ordinary dynamic loads no longer probe the main image; the pinned-musl self-image differential proves an explicit executable path still maps a separate object, while `dlopen(NULL)` retains the global handle. Dependency-graph CPU still fails | P1 |
| Constructor/destructor startup PIE | 1.1502×–1.1809× CPU upper bounds across three 31-sample `kernel-main-image-*-31` reports; 29 crabc calls vs 9 musl, with one marked application-output write each | lifecycle ordering is proven before/after `main`; Linux's already mapped PIE is consumed through validated auxv program-header/entry metadata, and the direct pinned-musl regression proves no second executable mapping. The marker isolates `main`, while whole-process calls retain startup/destructor cost and still fail the syscall gate | P2 |
| Startup-linked five-DSO graph PIE | 1.1687×–1.2205× CPU upper bounds across three 31-sample `kernel-main-image-*-31` reports; 65 crabc calls vs 50 musl, with complete marked output regions | startup relocation proves the root resolves both graph branches to `31`; the initial-graph exact-name cache remains bounded, and consuming the kernel main image removes its duplicate map/open/read lifecycle. The whole-process syscall gate passes, but CPU remains red | P2 |
| Loader startup | 1.1908×–1.2958× CPU upper bounds across three 31-sample `kernel-main-image-*-31` reports; 30 crabc calls vs 10 musl | `AT_PHDR`/`AT_PHENT`/`AT_PHNUM`/`AT_ENTRY` describe the live Linux kernel mapping, and `AT_EXECFN` supplies the bounded executable `$ORIGIN`; the residual is separate image loading and mimalloc's eager constructor | P2 |
| Live 32-MiB allocator probe | 48.3 MiB crabc PSS vs 33.9 MiB musl; 47.3 MiB vs 33.3 MiB is anonymous | the fresh-cgroup `memory.peak` row is unsupported in the current read-only Docker cgroup mount. Independently, a 32-MiB touched payload exceeds 90% of musl's total PSS, so no mimalloc configuration can satisfy this universal fixture gate | user scope decision |
| `getpid`, direct native | 108 ns for each crabc-rs and Rustix | no native gap in this selected route | no action |
| Native open/close | 441 ns crabc-rs vs 450 ns Rustix | no native gap in this selected route | no action |

Every `scalar-matrix-31` row completes its timed samples and separate syscall
diagnostic, but reports 41 crabc fresh-process calls versus 10 musl calls. The
scalar hot loops make no syscalls; that count is shared loader/startup work and
remains a P2 release-gate failure rather than evidence for a primitive-specific
syscall workaround. Schema-5 `marker-clock-schema5-smoke` proves the new hot-region
diagnostic reports zero `clock_gettime` calls in both lanes while preserving
those non-marker whole-process totals. The report itself is `partial` only
because its cgroup-v2 memory high-water diagnostic is unsupported under the
read-only Docker mount.

The current release profile is intentionally explicit:

```toml
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "abort"
strip = true
```

The same contract is set as `[profile.bench]` in the isolated Rust-native
fixture, because `cargo bench` does not consume the root release profile.
The profile experiment improved several C operations but cannot remove a vDSO
omission, linear lookup, or an asymptotically weaker string algorithm; only a
source-level fix can do that.

## Work to close selected gaps

1. The Linux/AArch64 vDSO resolver and typed `clock_gettime` dispatch now live
   in `crabc-core/src/vdso.rs`; both the C ABI and `crabc-rs::time` share it.
   Realtime and monotonic C calls enter the validated cached branch directly,
   while arbitrary public IDs retain the generic eligibility check. The
   resolver validates bounded ELF/SysV-hash metadata and caches either the
   kernel entry or a direct-syscall fallback. Preserve its malformed-metadata,
   forced-fallback, error, and marked-hot-loop regressions while P2 removes
   the remaining fresh-process CPU and syscall cost.
2. `ldso` now decodes and retains GNU-hash metadata for dynamic-symbol lookup
   at object registration, selects SysV tables for legacy objects, and keeps
   its loader-owner token plus dlerror cache in the
   loader-owned TCB. The 1,025-export cross-format fixture and thread/TLS
   regressions preserve lookup and recursive-lock semantics. The 1/128/1,025
   rows now use CPU-pinned, deterministic interleaved pairs and a 10,000-
   resample one-sided bootstrap bound. The five-DSO fan-out `dlopen_graph`
   validates dependency relocation and invocation. Three
   `main-self-identity-*-31` reports record 65 versus 50 whole-process calls
   and a still-red 1.2334×–1.2695× CPU upper-bound range. Its 35 versus 40
   marked calls avoid the prior non-contract main-image probe, while musl sets
   `FD_CLOEXEC` on each DSO. The direct self-image differential preserves the
   distinct explicit-path and `dlopen(NULL)` contracts. Continue removing only
   process-startup calls required by no loader contract. For late TLS images, `expand_thread_tls` retains a
   generation mismatch as its synchronization trigger, while the private TCB
   records the append-only module frontier already initialized by that
   allocation. It materializes only the absent suffix when its recorded
   capacity and TP offset still match; larger layouts or stronger AArch64
   alignment retain allocation replacement.
   The initial `libc.so` short-name exception mirrors musl for conventional
   `DT_NEEDED libc.so` edges while general runtime aliases retain inode-based
   matching. The eight-DSO `loader_dynamic_tls_growth` contract, including
   optimized TLSDESC access records a red 1.3184×–1.3977× CPU upper-bound
   range across three `tls-module-frontier-*-31` runs; the matched 101-sample
   candidate/baseline pair is 1.3193×/1.3412×. A no-RELRO
   packed-`DT_RELR` differential also proves each runtime relocation pass is
   limited to the newly appended graph suffix, so an earlier in-place
   relocation cannot replay. Its lowest `PT_LOAD` supplies the complete
   initial file mapping, then later segments overlay it; the diagnostic
   therefore records 17 candidate mappings versus 18 musl and 8.125 versus
   13.125 marked calls per load.
3. `strlen` and `memchr` use bounded word scans, `strstr` is a page-safe
   raw-pointer translation of musl 1.2.6's two-way algorithm, and `memmem`
   reuses the bounded first-byte scan before its two-way/hybrid route. Their
   direct C regressions, together with the `memcpy`/`memset` fixture, compare
   all six primitives with musl across fixed empty-to-256-KiB bands, every
   0–15-byte starting offset, 0–64-byte tails against a protected page, and
   deterministic randomized misalignment. The `memcpy` cases stay within its
   non-overlap contract and check the returned destination, source
   preservation, and destination canaries. These tests prevent an
   implementation from trading boundary safety for the selected CPU result.
   The 31-sample `scalar-matrix-31` report now measures 64-byte, 16-KiB, and
   256-KiB aligned/unaligned rows for all six primitives. Its bounds identify
   concrete scalar CPU gaps in `memcpy`, `memset`, and 16-KiB unaligned
   `strstr`; two-word scans close all `memchr` rows, zero-byte-mask indexing
   closes every `strlen` row, length-specialized short `strstr` windows close
   every other `strstr` matrix row, and a bounded terminal-candidate check
   closes every `memmem` matrix row. Schema-4 cache provenance records 128
   KiB L1 data, 12 MiB L2 unified, and 64 MiB L3 unified cache for benchmark
   CPU 0: 64 bytes and 16 KiB fit L1, while 256 KiB fits L2. The new named
   128-MiB aligned/three-byte-offset `span_matrix` rows exceed that recorded
   L3. They stage equal deterministic, lane-private source files with a tail
   needle and terminating NUL, use a `MAP_PRIVATE` destination for copy/fill,
   and validate each primitive result. The paired 31-sample
   `musl-aarch64-memcpy-kernel-span-matrix-31` reports record the pinned musl
   GPR copy schedule at 0.9600×–0.9682× aligned and 1.0498×–1.0694×
   unaligned. Three `memset-gpr-scalar-schedule-*-31` reports record the
   generic musl schedule's explicit GPR stores at 1.1315×–1.1922× aligned and
   1.1947×–1.2334× unaligned; it remains red, while `strlen`, `memchr`, `strstr`, and
   `memmem` pass at 0.5909×–0.7914×. Its 51 versus 22 syscall diagnostic is
   whole-process setup and input mapping, not an inner-loop syscall claim. The
   report remains `partial` only because cgroup-v2 peak collection is
   unavailable. Do not call the warm-page-cache mode cold. Inspect generated
   AArch64 paths and remove scalar work before proposing SIMD.
4. `fd_file_4k`, `stdio_file_4k`, and `stdio_format_parse` give
   files/descriptors, buffered input, and formatted scanning reproducible local
   inputs. `__stdio_read` follows musl's two-iovec lookahead shape, while
   cancellation retains its direct semantic checks. The formatted row retains
   scanner read-ahead in the `FILE` buffer when it fits, proving its unread tail
   before the next `fgetc`; its remaining seekability probe is explicit in the
   trace. Inspect only `fopen`/`fread`/`fseek`/`fclose`/scanner work that has a
   corresponding C-boundary regression rather than weakening their file or
   cancellation contract.
5. Trace each startup row's excess syscalls/mappings and reduce only work not
   required for loader correctness. Startup wall-clock values are not alone a
   regression threshold; syscall class, CPU, and correctness must agree.
6. The bounded mimalloc-integration audit found one allocation domain, no
   override feature or programmatic option setting, and 1-GiB virtual arena
   reservation without a resident-memory claim. The 14-MiB anonymous excess is
   allocator-owned, but even zero excess cannot fit the current universal
   0.90× PSS gate: the touched 32-MiB payload alone is larger than 90% of musl's
   whole-process PSS. Do not turn this into allocator research; obtain the
   scope decision recorded in `goal.md` before changing the selected strategy.

## Standard-library optimization evidence

The dependency-free M12 stock-`std` fixture successfully builds the current
`std,panic_abort`, AArch64 fat-LTO lane with `opt-level=3`, one codegen unit,
embedded bitcode, and dynamic crabc runtime; its musl/crabc raw-output runtime
comparison passes. Run it with `./scripts/dev.sh lto-m12`.

Rustybench’s proc-macro Cargo benchmark graph currently cannot combine with
`-Z build-std` on this native musl host: Cargo produces duplicate `core` lang
items while compiling its host proc-macro dependency. `perf-native --build-std`
records this explicitly as unsupported evidence rather than inventing a result.
That is a Rustybench integration limitation to close before using Rustybench
for dependency-bearing build-std timing; it is not evidence of a crabc runtime
regression.
