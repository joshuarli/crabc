# AArch64 local multithread allocator scaling smoke

`run.py` is a deliberately narrow early architecture smoke for the contract in
[`native-mimalloc.md`](../../../native-mimalloc.md): once a thread owns an
already-initialized page, local allocation and free must not serialize through
a process-global scheduler or a PageMap mutation lease. It measures only
independent, thread-local `mi_malloc(64)` / touch / `mi_free` work.

The harness is evidence-only. It does not select the Rust allocator as a libc
backend, export `mi_*`, establish allocator parity, or qualify release
performance. Its scope is recorded in [`manifest.json`](manifest.json) and in
every JSON report.

## Invocation

Run this directly inside a qualified native Linux/AArch64 environment:

```sh
CRABC_EXECUTION_MODE=native CRABC_HOST_ARCH=aarch64 \
  python3 compat/allocator/multithread-perf-aarch64/run.py --smoke --offline
```

The attestation is intentional. An AArch64 Docker guest is not performance
evidence when it is emulated; an unattested or non-native host produces an
`"unavailable"` JSON report and exits successfully without compiling or
running the workload. The report records its host facts, selected CPU affinity,
and every available worker scale from `1`, `2`, `4`, and `8`; it never claims a
scale larger than the caller's allowed affinity mask.

Each worker is assigned a distinct allowed CPU with `pthread_setaffinity_np`.
The fixture starts workers behind a two-stage barrier and reports total local
operations divided by the slowest worker's own timed loop. Per-scale report
data contains both throughput scaling relative to one worker and parallel
efficiency. A scale that delivers no more than `1.25×` the one-worker median is
explicitly marked `"flat-throughput-signature"`: a diagnostic indication of
possible global serialization, not a promotion threshold.

## C and Rust lanes

The default `pinned_c` lane is compiled in an isolated `/tmp` build directory
from the SHA-256-verified, pinned mimalloc v3.5.0 source archive. It uses no
crabc production allocator integration.

The checked-in `crabc-mimalloc-test-adapter` has an explicit one-thread ABI, so
this harness never passes it to pthread workers. Instead, the checked-in Rust
fixture invokes the existing documentation-hidden
`crabc_mimalloc::__crabc_runtime` friend boundary used by the allocator's
direct native tests. It is built with the root workspace's locked dependency
graph into the same isolated `/tmp` output directory, then compiled with
`rustc`; it adds no production dependency or allocator API.

An independently built replacement fixture may be passed explicitly:

```sh
CRABC_EXECUTION_MODE=native CRABC_HOST_ARCH=aarch64 \
  python3 compat/allocator/multithread-perf-aarch64/run.py \
  --smoke --offline --rust-fixture /absolute/path/to/rust-local-scaling
```

The Rust fixture must accept exactly `--workers N --iterations N --cpus C0,C1`
and emit the seven newline-delimited records emitted by
[`fixture.c`](fixture.c), followed by `ok`. The runner then records C/Rust
throughput ratios at every common worker scale. Supplying a wrapper around the
one-thread adapter would violate this suite's contract. A Rust fixture build
or workload limitation is preserved as an unavailable Rust lane, while the
pinned-C measurement remains available as an isolated baseline.

## Tests

```sh
python3 -m unittest compat/allocator/multithread-perf-aarch64/tests/test_run.py
```

The tests cover qualification, worker-scale selection, the fixture grammar,
serialization-signature accounting, the report no-promotion contract, and the
machine-readable manifest. They do not claim an AArch64 measurement.
