# Project status

The general Linux/AArch64 little-endian runtime profile is closed. One active,
narrowly scoped compatibility program is open: the provenance-preserving Rust
semantic port of fixed mimalloc v3.5.0 defined by
[`docs/design/allocator.md`](docs/design/allocator.md) and measured through
[`compat/allocator/README.md`](compat/allocator/README.md). It does not reopen
allocator invention or another platform. [`COMPATIBILITY.md`](COMPATIBILITY.md)
remains the generated record of current compatibility evidence and
measurements; it is not edited by hand.

The allocator program currently has one bounded executable vertical slice:
an explicit pinned default theap can allocate, reallocate, and locally free
small, medium, large, singleton, aligned, and offset-aligned blocks from a
caller-managed external arena and page map. Large alignments use separately
owned OS singleton mappings below the source's 256 MiB metadata limit, with
allocation-free retry ownership when an injected terminal unmap fails. The
slice includes checked counted allocation, full-page retention, retirement,
unregister-before-release, and injected rollback. Unpinned external arenas now
schedule the pinned 4-second `purge_decommits=1` path before slice reuse;
forced collection claims the free bitmap while applying a non-owning
decommit, preserves the external mapping owner, and retains retry state after
an injected decommit failure. The ordinary allocator gate
matches 447 Rust-owned layout/configuration values, 378 address-independent
small-allocation trace values, and 51 fundamental-operation values against
exact pinned C v3.5.0. A standalone default-off test package now exports 16
strictly prefixed `crabc_test_*` symbols, passes the existing crabc allocator
fixture, and passes 33 reviewed checks from pinned upstream `test-api.c` in an
explicit creating-thread lifecycle. It exports no `malloc`, `mi_*`, or other
production allocator symbol. Separately, the bounded production metadata-owner
prerequisite from `src/subproc.c:19-88` now has one process-static detached
theap backed by direct OS page-map and external-arena bootstrap state. It
requires a caller-supplied frozen `MemoryConfig`, checks a live AArch64 thread
pointer before its private lock, preserves `MemoryId::Malloc` owner-bound
capabilities, and leaves compiler-TLS roots untouched. It supports zeroed and
aligned zeroed allocation, source-ordered replacement, and serialized
cross-thread free, with deterministic retryable and retained initialization
failure states. It neither attaches a live TLD/theap nor implements the
source's null/needs-no-free/non-Malloc release paths. This is not a production
backend or readiness claim. Milestone 5 now has six bounded foundations: the
exact AArch64 16-bit-index/48-bit-generation TLS key and caller-owned slot
contract; five private compiler-TLS roots with direct `TPIDR_EL0` identity;
live-owner and abandoned-page remote-free head transitions; a one-page
mapped/unmapped abandonment/adoption protocol with failed-reader bitmap
restoration and clear-once-set quiescence; plus an unsafe current-thread-only
regular TLS backing owner. The owner uses the process-static metadata allocator
for the exact flexible `mi_thread_locals_t` request, source growth rule,
header-before-root publication, generation-checked regular slots, and
free-before-dynamic-root-null teardown. It leaves fast/default/cached roots
alone and becomes terminal after an internal metadata error whose consumption
cannot be distinguished, rather than claiming a false retry capability. It has
no TLD/theap attachment, global allocator-backed key registry, pthread or
process lifecycle hook, or production ELF integration. Separately, an unsafe
current-thread TLD owner now retains one full source-ordered `mi_tld_t`-shaped
direct-zeroed metadata allocation. Its sequence is supplied as the old value
from a future source-shaped total-thread counter rather than invented here; it
records direct `TPIDR_EL0`, Linux NUMA, the exact Unix non-threadpool result,
an initialized private lock, null subprocess/theap-list fields, and exact
Malloc provenance. It exposes only the unattached checkpoint: no subprocess
count, process-main static TLD, theap/default/cached/fast root, list
attachment, pthread/process hook, or C pthread-mutex size claim. Its teardown
invalidates the TLD identity before attempting metadata free and terminally
poisons on an internal consumption-ambiguous error. An audited future owner
may connect `Unattached -> Attached -> Detached`; no such transition exists
yet. Separately, the exact source-layout `mi_random_ctx_t` image now lives
directly in `Theap::random`: it preserves source input/output word order,
counter carries, consumed-output clearing, direct random-field-address nonce
identity, and in-place split. It calls direct Linux `getrandom` and continues
weakly on an error or short read, then retries only while weak. The source
local `_mi_random_shuffle` core is deliberately replaced by one
domain-separated approved RustCrypto expansion of transparent weak
observations; this non-entropy-adding degraded-path difference is recorded in
`compat/allocator/known-differences.md`. It is not attached to a live theap,
TLS root, or metadata teardown owner yet. Four bounded Loom
schedules execute the shared live-owner and abandoned owner-claim/unown head
transitions. The compiler-TLS evidence proves private initial-exec AArch64 code
generation in a
dedicated crate probe and proves that the pinned compiler default would instead
emit TLSDESC; production integration must still apply the required per-crate
model and audit the final linked ELF. The last protocol requires stable,
queue-detached metadata and deliberately performs no terminal page release or
reuse. None of these pieces is integrated into allocation routing, actual
process/thread lifecycle hooks, full teardown, or reusable page lifetime.
Process state,
integrated allocator TLS lifecycle, heap/theap attachment, integrated
remote-free routing, complete concurrency modeling and stress, libc
integration, the remaining upstream
suites, and performance promotion gates remain open.

Future acceptance contracts are deliberately specific:

- [`docs/roadmap/performance-completion.md`](docs/roadmap/performance-completion.md)
  governs performance completion.
- [`docs/roadmap/software-corpus-validation.md`](docs/roadmap/software-corpus-validation.md)
  governs real-software and native-application validation.
- [`docs/roadmap/source-build.md`](docs/roadmap/source-build.md) governs
  source-build and sysroot progression.

Historical documents preserve provenance only; they are never an active
backlog. No chronological microtask list is a project authority. Read the
governing scope and compatibility profile before selecting work, then use the
relevant roadmap or machine-readable contract for its acceptance boundary.
