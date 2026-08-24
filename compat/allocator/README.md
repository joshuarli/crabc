# Allocator-port evidence contract

This directory owns the reproducible source, inventory, C-oracle, and later
Rust/C evidence for the Linux/AArch64 little-endian semantic port of pinned
mimalloc v3.5.0. It does not authorize allocator
invention, a cross-platform abstraction, or a runtime allocator-selection
system. The immutable source and licensing record are in
[`crabc-mimalloc/UPSTREAM.md`](../../crabc-mimalloc/UPSTREAM.md); the design
boundary is in [`docs/design/allocator.md`](../../docs/design/allocator.md).

The workspace crate currently contains source-mapped foundations, immutable
Linux memory policy, regular/aligned mapping ownership, a live two-level page
map, ordinary and binned caller-owned bitmap views, an in-place external-arena
substrate, the private futex-lock boundary, bounded nonallocating support
kernels, the allocation-free recursive once protocol, pure page geometry, and
the allocator random context over RustCrypto's original-ChaCha primitive. A
private explicit single-thread slice now binds a pinned default theap to a
caller-managed arena and page map and exercises ordinary small, medium, large,
and singleton allocation, exact generic candidate/full retention, local free,
retirement, full-span unregister-before-release, checked counted allocation,
ordinary and aligned reallocation, live aligned/offset-aligned allocation,
separately owned OS-aligned singleton mappings below 256 MiB, and failure
rollback with allocation-free retry ownership after terminal unmap failure. A
frozen-default external-arena purge slice schedules unpinned releases for four
seconds, claims free-bitmap ownership during forced non-owning decommit, skips
pinned backing, and preserves both external mapping ownership and immediate
retry state on failure. Two bounded Milestone 5 substrates are also present:
the AArch64 versioned TLS key/caller-owned slot contract and the source low-bit
live-page remote-free publication/owner-collection protocol. They are not yet
wired into allocation/free, abandonment, compiler TLS, process, thread,
teardown, or page-release lifecycle. A
standalone test-only package exposes 16 `crabc_test_*` C symbols around one
creating-thread context; it exports neither standard allocation names nor
`mi_*` names. It is not a public allocator API and makes no
allocator-readiness or whole-port parity claim. Its fixed-capacity `cfg(miri)`
model covers current mapping and page-map ownership. The pinned image does not
currently contain Miri, so forced-`cfg(miri)` execution is smoke evidence only
and is never reported as a Miri pass.

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
vectors. The release profile additionally runs independent C and Rust small-
allocation traces and requires the exact same 378-key logical record: every
one of 62 good-size transition requests, usable size, pointer-distinctness and
alignment observation, payload preservation, zeroing, and a 96-block repeated
fill/free permutation. Raw addresses are deliberately excluded. The gate also
records a separate 51-key exact-C baseline for page-kind, calloc, realloc,
aligned/offset-aligned, usable-size, preservation, and invalid-size OOM
behavior. The same library run emits an independent 51-key Rust record and
requires exact equality with that pinned C baseline. This proves the bounded
single-thread engine's fundamental operation slice; it is not a production C
adapter, process lifecycle, or whole-allocator parity claim. A
default-off `test-adapter` feature now owns one allocation-backed, creating-
thread-only context with root-last initialization, exact outstanding-block
accounting, and explicit retryable page-map/arena teardown. It exists only to
support the standalone prefixed C evidence adapter and is not a production
allocator API. The gate also
traverses Cargo metadata for the
fixed `aarch64-unknown-linux-musl` target and rejects any selected allocator
dependency package, version, source, edge, build script, or proc macro outside
the audited `chacha20`/`zeroize` graph. Target-conditional packages retained
only in `Cargo.lock` do not satisfy or fail that selected-graph judge.

`allocator --full` extends that gate by building and auditing the standalone
static and shared test adapter, including its exact 16-symbol export boundary,
native link tail, and dynamic dependencies. It applies the reviewed patch to
the hash-pinned upstream `test/test-api.c` without checking in a source fork,
then runs both the existing crabc allocator fixture and 33 selected upstream
API checks. After that passing Milestone 4 adapter lane it deliberately returns
exit status 3 with an `UNMET MILESTONE` explanation until Milestone 5 supplies
integrated remote-free routing, abandonment/adoption, thread/TLS lifecycle,
Loom protocols, and pthread stress. The bounded live-page remote protocol and
caller-owned TLS slot substrate do not satisfy that lifecycle gate. Both
performance modes likewise remain explicitly unavailable; these status-3
results are not skips and must not become successful placeholders.

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
| `adapted-tests-v3.5.0.json` | Reviewed M4 selection, omissions, source hashes, patch identity, prefixed symbol inventory, and native link contract for pinned upstream `test-api.c`. |
| `adapted/test-api-m4.patch` | Minimal source adaptation applied to the exact extracted upstream file; no copied upstream source fork is stored. |
| `test-adapter/` | Standalone default-off Rust staticlib/cdylib, private C header, and checked-in wrapper for the existing allocator fixture. |
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
to deviate. The register currently records no differences. The bounded small-
allocation slice has exact logical-trace parity, but its deliberately absent
lifecycle and API regions are incomplete scope rather than claimed
differences.
