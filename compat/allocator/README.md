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
the exact `mi_random_ctx_t` image stored in `Theap::random` over RustCrypto's
original-ChaCha primitive. The random slice includes direct `getrandom`,
error/short-read weak continuation, source counter/nonce/output clearing, and
in-place address-identity splitting; its dependency-owned replacement for the
source-local weak shuffle is recorded in `known-differences.md`. Five private
compiler-TLS roots now preserve the pinned initial images and teardown values,
while the selected Linux/AArch64 thread identity reads `TPIDR_EL0` directly. A
process-static private metadata owner now ports the successful detached-Malloc
paths in `src/subproc.c:19-88`: it directly maps its page map and external
arena before publishing one detached theap, never touches compiler-TLS roots,
and uses a must-use owner-bound capability for source-ordered replacement and
serialized cross-thread release. Its detached heap/TLD/theap and its
pre-publication-bound registry/published arena name the same deliberately
bounded process-main identity as the current-thread TLD checkpoint; it does
not claim general subprocess destruction or public allocation routing. A narrow unsafe
current-thread-only owner now uses that metadata prerequisite for regular
dynamic TLS backing: it retains the typed Malloc capability, follows the
source 16/double/+1024/least-index/65535 growth rule, publishes a fully
initialized flexible header before the dynamic root, validates live header
provenance, and frees before clearing only that root. It deliberately has no
TLD/theap attachment, allocator-backed global key registry, or actual
process/pthread lifecycle hook; an internal consumption-ambiguous metadata
error clears the root and terminally poisons the owner instead of offering an
unjustified retry capability. A second unsafe current-thread-only owner now
creates one full source-ordered `mi_tld_t` image with `subproc.rs`'s bounded
process-main owner. It issues the old relaxed total-thread-count ticket before
choosing storage; ticket zero uses the real static main-TLD branch without
touching metadata, while later tickets use an exact fresh direct-zeroed
metadata capability. Only the fully initialized TLD converts its ticket into a
live-count lease, so a metadata failure still consumes the sequence but does
not leak a live count. The generic TLD checkpoint records direct `TPIDR_EL0`,
Linux NUMA, the exact Unix non-threadpool result, the same main-subprocess
pointer as detached metadata bootstrap state, and a null theap list. Its
metadata path remains **subprocess-attached, no-theap**. Process bootstrap must
explicitly choose whether this generic owner or `main_theap.rs` owns that
`MainSubprocess` ticket zero; generic-first consumption makes later static
attachment terminally reject, and shared process-init selection authority is
deferred. The static branch attaches that exact TLD to cache-aligned,
address-stable `Heap` and default `Theap` slots within one process-static
owner. It preflights the immutable empty dynamic root plus empty default/cached
and null fast roots before consuming the ticket; does not touch metadata or
mapping; uses kind-only `_mi_memid_create(MI_MEM_STATIC)` provenance for the
main heap and concrete static image memids for its TLD/Theap; links TLD then
heap lists; and publishes the default root before the fast root. Cached stays
empty and dynamic stays the immutable empty image. A busy freshly owned
TLD/heap-list attach, later attachment error, or post-mutation private unlock
error terminally retains static TLD storage/live registration and returns no
teardown owner; the injected pre-publication TLD-list failure leaves roots
pristine. Those errors require invalid concurrency or a kernel/private-lock
failure outside the valid one-owner contract; C locks do not return them.
After exact root ownership validation, bounded teardown requires zero pages as
a Rust pre-mutation invariant, so a page-count rejection preserves every live
root/list/image/registration. Once that check passes, `_mi_thread_done`
(`src/init.c:448-481`) clears fast before `mi_thread_theaps_done` resets
default/cached and detaches: the valid path is fast, then default/cached, then
heap/TLD lists (Release-clearing `theap.heap`). It clears terminal Theap state,
invalidates and quiesces the TLD, then releases its live count and terminally
retires static TLD storage. A fallible private lock/list boundary after root
reset is also terminal invalid-owner handling, retaining storage and
registration rather than claiming teardown; source heap-busy retry remains
absent. Dynamic TLD/Theap allocation, cached-root refcounts, allocator-backed
key registry, page routing/abandonment integration, pthread/process hooks,
complete subprocess layout/lifecycle, and C pthread-mutex layout claims
remain absent. A
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
retry state on failure. The other bounded Milestone 5 substrates are also present:
the AArch64 versioned TLS key, caller-owned slot, and locked global-key registry
contract; the private compiler-TLS roots; the source low-bit
live/abandoned-page remote-free head transitions;
and one queue-detached, stable page's mapped/unmapped abandonment/adoption
protocol, including failed-reader restoration and clear-once-set quiescence.
A default-off Loom model exercises four exact shared head protocols: two
live-owner publishers, owner collection racing publication, bitmap adoption
racing an abandoned producer, and abandoned unown racing publication.
Deterministic native regressions separately cover the bitmap-field
quiescence, abandonment publication, adoption versus a remote producer, and
ownership-release races. These pieces are not yet wired into allocation/free
routing, integrated allocator TLS/process/thread teardown, terminal page
release, or metadata reuse. The compiler-TLS codegen probe proves hidden
initial-exec AArch64 root access and direct thread-pointer identity without a
TLS resolver, but production integration must still apply that per-crate model
and audit the final linked ELF. A
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
./scripts/dev.sh allocator-tls
./scripts/dev.sh allocator-perf --smoke
./scripts/dev.sh allocator-perf --full
./scripts/dev.sh test -p crabc-mimalloc --lib --features loom remote_free::loom_tests -- --test-threads=1
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
only in `Cargo.lock` do not satisfy or fail that selected-graph judge. It then
runs the four test-only Loom schedules over the shared production remote-head
publication/detach and abandoned owner-claim/unown loops and records their
exact pass count separately from the
ordinary unit suite.

The quick gate also invokes the dedicated allocator compiler-TLS judge. It
builds one default-off probe codegen unit with
`-Ztls-model=initial-exec`, requires all five roots to be hidden `STT_TLS`
objects in the appropriate initialized/uninitialized TLS sections, and rejects
resolver-based or dynamic TLS relocation forms. A negative-control build must
show that the pinned compiler default emits TLSDESC, keeping the production
model requirement explicit. `allocator-tls` runs this judge alone and writes
`compat/reports/allocator/tls-codegen.json`.

`allocator --full` extends that gate by building and auditing the standalone
static and shared test adapter, including its exact 16-symbol export boundary,
native link tail, and dynamic dependencies. It applies the reviewed patch to
the hash-pinned upstream `test/test-api.c` without checking in a source fork,
then runs both the existing crabc allocator fixture and 33 selected upstream
API checks. After that passing Milestone 4 adapter lane it deliberately returns
exit status 3 with an `UNMET MILESTONE` explanation until Milestone 5 supplies
integrated remote-free routing, abandonment/adoption, thread/TLS lifecycle, the
remaining applicable Loom protocols, and pthread stress. The bounded page
protocols and caller-owned TLS registry do not satisfy that lifecycle gate.
Loom 0.7.2 is an exact, defaults-disabled dev-dependency: its allocation-backed
`std` scheduler, `generator` build script, and tracing support stack exist only
in tests. The generator's external assembly path is not selected on AArch64,
and Cargo's production-graph judge excludes the entire Loom graph. Both
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
