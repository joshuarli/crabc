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
backend or readiness claim. Milestone 5 currently includes the exact AArch64
16-bit-index/48-bit-generation TLS key and caller-owned slot contract, its
older caller-storage registry substrate, and one allocator-owned process-global
regular-key registry; five private compiler-TLS roots with direct `TPIDR_EL0`
identity; live-owner and
abandoned-page remote-free head transitions; a one-page mapped/unmapped
abandonment/adoption protocol with failed-reader bitmap restoration and
clear-once-set quiescence; an unsafe current-thread-only regular TLS backing
owner; and one ticket-zero process-static main heap/default-Theap attachment.
The regular owner uses the process-static metadata allocator for the exact
flexible `mi_thread_locals_t` request, source growth rule, header-before-root
publication, generation-checked regular slots, and free-before-dynamic-root-
null teardown. It leaves fast/default/cached roots alone and becomes terminal
after an internal metadata error whose consumption cannot be distinguished,
rather than claiming a false retry capability. The allocator-owned registry
uses the selected main subprocess's aligned Malloc metadata route for one
retained typed bitmap image (plus one temporary replacement while locked),
grows by 1,024 bits through the 64,512-bit/63-block source ceiling, and keeps
`BitmapView` transient under its private registry lock. Ordinary claim uses
`tseq = 0`, advances generation
only after a one-bit claim, and copy growth preserves old claims before marking
only the appended range free. Linear leases require explicit release; bounded
shutdown refuses live leases and late access without writing compiler TLS or
attaching a key to a thread. Allocation failure before commit preserves state;
typed-image invariant or post-commit ownership ambiguity terminally poisons
with retained process-static ownership. This is not the source's full process
shutdown, fast-key management, or key-to-thread integration. Separately,
`subproc.rs` holds
one bounded process-static main-subprocess identity: only relaxed
`thread_total_count`, relaxed live `thread_count`, and the real first static
TLD slot—not full `mi_subproc_t`, its heaps/arenas/stats, or a process-init
API. The unsafe current-thread TLD owner issues its own old-counter-value
ticket before it chooses storage: ticket zero uses the static `MemoryKind::Static`
source branch without metadata, while later tickets use the typed direct-zeroed
metadata route. Metadata failure consumes a sequence but never a live
registration. The generic TLD image records the same main identity as detached
metadata bootstrap state and its selected arena registry/published arena,
direct `TPIDR_EL0`, Linux NUMA, the exact Unix non-threadpool result, a null
theap list, and exact provenance. It remains **subprocess-attached, no-theap**.

`main_theap.rs` is the sole static-TLD exception. It owns one private,
process-static owner whose aligned/address-stable `Heap` and default `Theap`
field slots are current-thread-only (`!Send`/`!Sync`). Process bootstrap must
select it before any generic TLD owner consumes the same `MainSubprocess`
ticket zero; shared process-init selection authority remains deferred. It
preflights dynamic as its immutable empty image, fast as null, and
default/cached as the empty Theap before it consumes ticket zero; rejection
therefore does not advance the counter or touch metadata/mapping. Its main
`Heap` uses kind-only `_mi_memid_create(MI_MEM_STATIC)` provenance (zero
union/flags); the TLD and Theap retain concrete pinned/committed static image
memids. It preserves `_mi_theap_init`'s
copy/TLD/refcount/subprocess/options/TLD-list/random-cookie/Release-heap/
heap-list order, then publishes default followed by fast. Cached and dynamic
remain empty. A busy freshly owned TLD/heap list, subsequent list-attachment
failure, or post-mutation private unlock error is terminal
initialization-invalid-owner handling: the already registered static TLD and
live count remain in process-static storage, roots remain pristine when the
TLD-list attach fails before publication, and no teardown owner is returned.
After exact live-root ownership validation, teardown checks zero pages as a
Rust pre-mutation invariant; that rejection preserves every live
root/list/image and registration. After that check passes, the valid path
matches `_mi_thread_done`'s `src/init.c:448-481` call order: it clears fast
through `_mi_thread_locals_thread_done`, then clears default/cached and
detaches heap then TLD lists under their locks, Release-clearing `theap.heap`,
clears links/TLD/random/cookie/subprocess,
invalidates and quiesces the TLD, then releases live registration and
terminally retires the static TLD slot. A post-root-reset private lock/list
failure, including a post-mutation unlock error, requires invalid concurrency
or a kernel/private-lock failure outside the valid owner contract. It is a
terminal invalid-owner state that retains process-static storage and its live
registration rather than retrying or claiming completed teardown. The
represented `Heap` ends at the source `memid`; its abandoned/arena regions are
valid zero/deferred fields, not a full C-size or heap API claim. Dynamic
TLD/Theap, registry-to-thread integration, cached-root refcounting, remote-free
routing, page routing or abandonment integration, full heap/Theap/arena/
subprocess APIs, pthread/fork/process shutdown, stats/options/callbacks, and
public ABI remain open.

Separately, the exact source-layout `mi_random_ctx_t` image now lives directly
in `Theap::random`: it preserves source input/output word order, counter
carries, consumed-output clearing, direct random-field-address nonce identity,
and in-place split. It calls direct Linux `getrandom` and continues weakly on
an error or short read, then retries only while weak. The source local
`_mi_random_shuffle` core is deliberately replaced by one domain-separated
approved RustCrypto expansion of transparent weak observations; this
non-entropy-adding degraded-path difference is recorded in
`compat/allocator/known-differences.md`. The static main-Theap slice initializes
this exact image; dynamic Theap and metadata-owner attachment remain absent.
Four bounded Loom
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
integrated allocator TLS lifecycle, dynamic heap/theap attachment, integrated
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
