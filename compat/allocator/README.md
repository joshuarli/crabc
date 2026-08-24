# Allocator-port evidence contract

This directory owns the reproducible source, inventory, C-oracle, and later
Rust/C evidence for the Linux/AArch64 little-endian semantic port of pinned
mimalloc v3.5.0. It does not authorize allocator
invention, a cross-platform abstraction, or a runtime allocator-selection
system. The immutable source and licensing record are in
[`crabc-mimalloc/UPSTREAM.md`](../../crabc-mimalloc/UPSTREAM.md); the design
boundary is in [`docs/design/allocator.md`](../../docs/design/allocator.md).

The workspace crate currently contains source-mapped foundations, the private
regular Linux mapping and futex-lock boundaries, bounded nonallocating support
kernels, the allocation-free recursive once protocol, page-queue intrusive
metadata kernels (without theap accounting), pure page geometry,
and a fixed-capacity `cfg(miri)` mapping model. It exposes no
allocator operation and makes no allocator-readiness or parity claim. The
pinned image does not currently contain Miri, so forced-`cfg(miri)` execution
is smoke evidence only and is never reported as a Miri pass.

## Canonical commands

Run the harness through the pinned Linux/AArch64 development image:

```sh
./scripts/dev.sh allocator --quick
./scripts/dev.sh allocator --full
./scripts/dev.sh allocator-perf --smoke
./scripts/dev.sh allocator-perf --full
```

`allocator --quick` is the current ordinary development gate. It verifies the
annotated tag and archive identities, regenerates the checked-in contracts in
memory, checks them and the source-map ratchet, and builds all five exact C
oracle profiles. Its ignored report is
`compat/reports/allocator/latest.json`; profile artifacts and layout probes
are under `compat/reports/allocator/oracle/`. The gate runs the complete
`crabc-mimalloc` library unit suite with a marked Rust machine record and
rejects any mismatch in the currently ported configuration constants,
page/memory-ID layout, queue block-size table, or bin-selection boundary
vectors.

`allocator --full` and both performance modes deliberately return exit status
3 with an `UNMET MILESTONE` explanation until their real Rust adapter,
differential, stress, integration, and comparison lanes exist. That explicit
failure is not a skip and must not be converted into a successful placeholder.

Maintainer-only contract operations run directly on the host and require a
review of their diffs:

```sh
python3 compat/allocator/run.py --check --offline
python3 compat/allocator/run.py --generate-contracts --offline
python3 compat/allocator/run.py --snapshot-ratchet
python3 -m unittest compat/allocator/tests/test_runner.py
```

The verified archive and tag attestation live in the ignored
`compat/allocator/.cache/`. Once they are present, `--offline` performs no
network access. Contract or source-map changes require an explicit ratchet
snapshot after review; the normal gate never updates its own baseline.

## Checked-in contracts

| Path | Contract |
| --- | --- |
| `api-v3.5.0.json` | Deterministic, source-audited public-header inventory. It separates external C declarations, static inlines, types, enum options, macros, override macros, and C++ conveniences; every item records its Linux/AArch64 classification, reason, profile, C-oracle release-symbol disposition, and crabc-libc export policy. |
| `upstream-tests-v3.5.0.json` | Exact pinned upstream test/support-file inventory and current execution status. |
| `port-map.toml` | Source-unit and meaningful-item translation/verification ledger with separate monotonic status fields. |
| `ratchet-v3.5.0.json` | Reviewed inventory hashes, counts, and non-regression baseline. |
| `known-differences.md` | Sole register for observed, pending, accepted, or rejected Rust/C differences. |

Generated reports are measurements and remain ignored. The checked-in
contracts are review inputs; linking a symbol, parsing a declaration, or
building a C profile does not make a Rust feature implemented or verified.

The v3.5.0 API contract currently records 194 external C declarations, seven
header-only static-inline helpers, 16 typedefs, and 52 exact
`mi_option_e` enumerators. The normal pinned release profile defines 190
`mi_*` symbols: `mi_collect_reduce` and `mi_stats_merge` are stale
header-only declarations, while `mi_malloc_size` and `mi_malloc_usable_size`
are provided only by the opt-in upstream override translation unit. The
oracle gate fails on any other header/symbol discrepancy. `mi_wdupenv_s` is
present in the C oracle symbol set but deliberately unsupported by crabc's
Linux/AArch64 ABI; no inventory item permits a crabc-libc `mi_*` export.
The C++-only `mi_decl_new` and `mi_decl_new_nothrow` macros remain explicitly
source-only C++ conveniences. The five legacy `mi_option_*` aliases remain
separate deprecated inventory entries (rather than duplicate engine options),
distinct from the explicit `mi_option_deprecated_*` enumerators.

## Baselines and oracles

The exact pinned C v3.5.0 source archive is the mandatory differential oracle
for engine behavior, layout/configuration probes, upstream tests, and
performance. It is a separately built oracle: the current production
`libmimalloc-sys` 0.1.49 backend bundles mimalloc v3.3.2, so it cannot stand in
for the v3.5.0 comparison. That current backend remains the default until a
promotion gate passes. Musl remains the C/POSIX ABI oracle at the
`crabc-libc` boundary; glibc is never an oracle or fallback. Keep those roles
distinct.

The C backend may be selected by a build or test configuration as a shadow
backend until promotion. Production must not choose its allocator at runtime.

## Separate completion tracks

Record these outcomes independently:

| Track | Required question |
| --- | --- |
| libc allocator readiness | Can the Rust engine back crabc's `malloc` family while preserving the existing C ABI, interposition, `errno`, failure, alignment, zero-size, and output-preservation rules? |
| mimalloc v3.5.0 parity | Is every public Linux/AArch64-applicable `mi_*` API and compile-time mode derived from the pinned headers, symbols, declarations, and upstream tests accounted for? |

Passing the first track does not assert the second, and basic malloc/free tests
do not pass either track by themselves.

## Required evidence

Each vertical slice records the pinned source revision and configuration, then
adds focused invariants, exact-C layout/configuration probes, deterministic
differential traces, and minimally adapted upstream tests. Cross-thread free,
atomic protocols, process/thread initialization, teardown, fork, fault
injection, corruption/wrong-use isolation, pthread/TLS, ABI/interposition, and
real-program/corpus cases all require direct evidence before promotion.

Performance evidence compares Rust and exact pinned C under matching
configuration, fixture, build profile, artifact hashes, host provenance, and
sample contract. It covers throughput, latency, RSS, virtual mappings,
startup, and allocation-path behavior. The ordinary musl–crabc performance
matrix is complementary integration evidence, not a substitute; see
[`compat/perf/README.md`](../perf/README.md).

Do not change an upstream algorithm, configuration, allocation policy, or
fixture merely to make the Rust port look better. A measured divergence may be
investigated only under the design-note, differential, and performance rule in
[`docs/design/allocator.md`](../../docs/design/allocator.md).

## Difference register

[`known-differences.md`](known-differences.md) is the single durable register
for accepted or pending Rust/C differences. A missing entry is not permission
to deviate. The register currently records no differences because no Rust
allocator implementation exists.
