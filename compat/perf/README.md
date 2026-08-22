# musl–crabc performance evidence

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
unwind-capable standard-library closure; the existing M12 application proof
retains its separately validated `std,panic_abort` route. The native fixture
uses an explicit empty `CARGO_ENCODED_RUSTFLAGS` so the repository's
symbol-accounting `link-dead-code` setting cannot alter its timed loops. The
dependency-free M12 fixture remains the project’s separate clang/lld,
`std,panic_abort`, bitcode, and fat-LTO Linux/AArch64 proof.

## What is measured

Every timed sample is a fresh child process. The parent records elapsed wall
time around that child and uses `wait4(2)` for isolated user/system CPU time,
peak RSS, page faults, and voluntary/involuntary context switches. Timed
samples do not run under `strace`, a profiler, or an allocator wrapper.

The workloads deliberately cover distinct cost domains:

| Family | Workloads |
| --- | --- |
| Startup/loader | `startup`, late-symbol `dlsym_128` against a 128-export DSO |
| Syscall path | `clock_gettime`, `getpid`, `open_close` |
| C hot primitives | `memcpy`, `memset`, `strlen`, `memchr`, `strstr`, `memmem` |
| Allocator integration | 64-byte and 4-KiB allocate/touch/free loops |
| Process memory | RSS/PSS snapshot while 32 MiB is concurrently live |

For each workload/lane, the report retains all samples plus min/median/p95/max
summaries. `strace -f` runs once in a separate diagnostic lane and records
per-syscall calls/errors. It is explicitly marked `timing: false`; syscall
counts must never be read as a timing sample.

## Boundaries and interpretation

This measures the project’s current C dynamic runtime against the pinned musl
oracle. It does not benchmark a host glibc, allocator implementations in
isolation, or cross-architecture performance. The resident-memory probe gives
the process footprint of the selected allocator integration; allocator design
itself remains outside crabc’s scope.

The report is evidence, not a score. Compare medians and tails only between
runs with the same host provenance and workload contract. A result should lead
to source/assembly inspection and a focused regression measurement before it
becomes an optimization priority.

Pure parser tests need no Docker, Rust, musl, or AArch64 host:

```bash
python3 -m unittest discover -s compat/perf/tests -p 'test_*.py'
python3 -m unittest discover -s compat/perf/native/tests -p 'test_*.py'
```
