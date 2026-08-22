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
peak RSS, faults, and context switches. RSS/PSS is separately sampled while a
32-MiB allocation set is live. `strace` is a separate `timing: false`
diagnostic, never a timed sample.

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

The 2026-08-21 fat-LTO release report used 15 fresh C processes per lane and
workload. CPU ratios below are candidate/musl median user+system CPU time;
positive ratios identify the selected gaps, not a score for all libc calls.

| Route | Evidence | Interpretation | Priority |
| --- | ---: | --- | --- |
| C `clock_gettime` ×200,000 | 4.53× CPU; 200,048 crabc traced calls vs 10 musl | crabc always enters the kernel while musl uses vDSO where available | P0 |
| Native `clock_gettime` ×1,000/sample | 138 ns crabc-rs vs 18 ns Rustix (7.67×) | the same direct-core time route lacks Rustix’s vDSO dispatch | P0 |
| C `strstr` ×10,000 | 5.20× CPU | scalar search remains far behind musl’s selected AArch64 path | P1 |
| C `strlen` ×25,000 | 4.85× CPU | scalar byte scanning needs a musl-derived AArch64 implementation | P1 |
| C `memchr` ×25,000 | 3.60× CPU | same hot-primitives frontier | P1 |
| C `memmem` ×10,000 | 3.23× CPU | repeated scalar comparison is a distinct algorithmic gap | P1 |
| `dlsym` against 128 symbols ×5,000 | 1.93× CPU; 15,010 crabc calls vs 18 musl | linear symbol scans plus `gettid` on loader locks | P1 |
| Loader startup | 48 crabc calls vs 10 musl; 1.14× CPU | excess initialization/mapping remains, though wall time is host-noisy | P2 |
| Live 32-MiB allocator probe | 48,284 KiB crabc PSS vs 33,864 KiB musl | mimalloc integration footprint is measurable; allocator design remains out of scope | accept/track |
| `getpid`, direct native | 108 ns for each crabc-rs and Rustix | no native gap in this selected route | no action |
| Native open/close | 441 ns crabc-rs vs 450 ns Rustix | no native gap in this selected route | no action |

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

1. Add a Linux/AArch64 vDSO resolver and typed `clock_gettime` dispatch in
   `crabc-core`, with a direct-syscall fallback for unavailable/invalid vDSO
   data. Route both the C ABI and `crabc-rs::time` through it. Preserve a
   forced-fallback regression so vDSO use never changes kernel semantics.
2. Retain and use GNU/SYSV hash metadata in `ldso`; replace linear dynamic
   symbol scans with the musl-compatible lookup path. Cache the loader’s
   current thread identity inside lock ownership rather than issuing `gettid`
   for every uncontended `dlsym` lock transition. Keep interposition/version
   lookup semantics and add a many-symbol DSO regression.
3. Port and independently validate musl’s selected AArch64 `strlen`, `memchr`,
   `strstr`, and `memmem` algorithms. Scalar behavior remains the oracle;
   optimized code must share differential, boundary, alignment, and guard-page
   tests before replacing it. Re-evaluate `memcpy`/`memset` after that work:
   their current selected gap is much smaller.
4. Trace the 38 additional startup syscalls/mappings and reduce only work not
   required for loader correctness. Startup wall-clock values are not alone a
   regression threshold; syscall class, CPU, and correctness must agree.
5. Keep allocator throughput and resident footprint visible in the matrix, but
   do not turn the mimalloc exception into allocator research. Address wrapper
   overhead only when a focused result remains after the selected runtime work.

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
