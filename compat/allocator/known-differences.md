# Pinned mimalloc Rust/C known differences

This is the register of observable or algorithmic differences between the
`crabc-mimalloc` Rust port and exact pinned mimalloc v3.5.0 C. The source pin
is defined in [`crabc-mimalloc/UPSTREAM.md`](../../crabc-mimalloc/UPSTREAM.md).

## Register

Entries are `### \`CRABC-MI-*\` — <status>` sections, parsed by
`compat/allocator/source_convergence.py` and read by
`compat/allocator/divergence_evidence.py`; the status is `observed`, `pending`,
`accepted`, or `rejected`. Each entry records one difference, its reproducer or
differential, and the decision and conditions for removing it; the
[entry requirements](#entry-requirements) at the end list what each must state
and how a port-map row carries it. The register covers both the paused
AArch64 production record and the native x86 port; figures quoted in an entry
are tied to the target it names.

### `CRABC-MI-HEAP-RETIREMENT` — accepted upstream semantic correction

- **Port map:** `src/heap.c:child-thread-empty-non-main-heap-lifecycle`, `src/heap.c:main-subprocess-non-main-heap-lifecycle`

Pinned `src/heap.c:mi_heap_free_theaps` can leave queued OS Pages naming a
freed Heap and cached Theaps naming a reused Heap address. The Rust retirement
path applies upstream `b85f2d0`, `4192c77` and `23a5db4` together: detach each
Theap, drain every queue through `BIN_FULL`, then release-clear its Heap
identity before merging statistics and dropping the Heap reference. Empty
Pages are released. Live Pages enter the retiring Heap's arena or OS registry.
The dynamic TLS key is released and zeroed before Heap-wide Page migration or
destruction. `mi_heap_delete` moves all surviving Pages to the subprocess main
Heap. A final remote free during OS Page migration releases the empty claimed
Page from that main Heap's list and statistics before releasing its mapping.
These are engine semantics. The C ABI and source pins are unchanged.

The Rust production tests in `subproc_main_heaps.rs` cover same-address Heap
reuse for delete and destroy, live arena and OS Page migration, an attached
worker's full OS queue with a queued remote free, and a final remote free at
the OS move's unown CAS. The local OS identity and unown-CAS tests fail before
the correction and pass after it. `source_heap_api.rs` checks aligned survivor
membership and final free after owner exit. `heap_lifecycle.rs` covers child
Heap teardown and abandoned OS Page migration.

`allocator-heap-destroy-stale-theap` preserves the pristine v3.5.0 cache-reuse
failure and compares it with a separately extracted C tree containing only
`4192c77`'s identity invalidation. That corrected C comparison proves the cache
transition alone. It does not qualify the combined Page handoff. The pinned C
owner-exit failures remain recorded in `plan.md`; no corrected C build replaces
the pristine oracle.

The correction removes the retained-deleted-Heap registry and its extra Theap
references and special free route. It adds no persistent allocator state.
Native performance and promotion gates remain open. The bounded production
regressions establish correctness, not performance qualification. Remove this
erratum only when a separately reviewed source pin includes these corrections.

### `CRABC-MI-LIVE-PAGE-ASSERTION-CUSTODY` — failure ownership boundary

Pinned `src/theap.c:62,100` validates each queued Page before collection while
the source owner-exit traversal holds its TLD list lock. The Rust engine
observes the same Page in source order and transports a failed assertion as an
exact typed task. Before releasing the list lock, it marks that task's actual
Heap/Theap graph against retirement; it tries the Heap lock without waiting
under the TLD lock, so a concurrent Heap destroyer cannot create a lock cycle.
An unpublishable refusal retains terminal state and stops the process.

The `src/theap.c:126` prefix also validates original Heap/Theap linkage, every
Page including full Pages, visited counts and all source queues before
selecting the deferred callback or advancing its heartbeat. A header or
empty-queue failure retains the complete original graph even when it has no
selected Page. The same predicate applies to the initial empty owner and the
refused-size retry without materializing a page engine or reserving another
arena.

Diagnostic delivery begins only after Page, engine, member and source-list
projections and locks end. The original issuer, PageMap and backing remain
retained throughout delivery; a callback may use an independently valid Heap
but cannot reopen the failed owner. Successful collection returns a linear
thread/sequence completion token, and the original diagnostic admission ends
before the token authorizes attachment metadata teardown. Source fast-TLS
clearing still precedes traversal.

Ordinary legal allocation and collection algorithms are unchanged. Debug checks
use copied scalar assertion observations and legal callback/auxiliary-Heap
clients; invalid-memory behavior parity with C is not claimed.

### `CRABC-MI-DEBUG-ALIGNED-OFFSET-LIVE-CLIENT` — accepted valid-program correction

- **Port map:** `src/free.c:debug-aligned-offset-live-client-validation`

Pinned `src/free.c:172-178` rejects non-word-aligned client addresses when
`MI_DEBUG >= 1` and guarded-precise mode is disabled, yet its own successful
aligned-offset allocation can return such addresses. A pinned 81-byte
allocation with alignment 128 and offset 11 shows it: release and statistics
profiles report usable storage and preserve the payload across reallocation;
the debug profile reports usable size zero, loses the copied payload and
diagnoses the live pointer as invalid. This is a valid-program difference, not
invalid-input hardening.

The native entry accepts that exact live client after its stable PageMap
registration and canonical block geometry are projected. Callers must retain
the exact client and exclude registration and lifetime changes; registration
alone never authenticates an arbitrary interior or stale pointer. Padding
checks, failed-reallocation ownership, aligned reuse policy and
unregistered-pointer diagnostics are unchanged. The correction covers free,
usable-size and ordinary, Heap and Theap reallocation, including a live client
transferred after its owner thread joins.

The operation-profile differential keeps the original source debug condition as
a negative control: its valid-client oracle selects `MI_DEBUG=1`, `MI_GUARDED=0`
and `mi_option_guarded_precise=1` for C only, and the preprocessed source must
show that option has exactly one executable use, the faulty word-alignment
validation. Unchanged source debug failures are compared against their exact
diagnostics and outcomes. Calls that violate separate source assertion
preconditions (null `mi_reallocarr` output, zero-size `mi_reallocarr`,
non-power-of-two aligned reallocation, invalid aligned-offset reallocation) run
in isolated processes; debug assertions and native returning-error behavior,
including preserved client ownership, are checked separately.

### `CRABC-MI-NATIVE-CHILD-SOURCE-OWNER-REPAIR` — accepted integration boundary

- **Port map:** `src/init.c:private-no-page-process-pthread-runtime-lifecycle`, `src/alloc.c:nondefault-crabc-libc-native-mimalloc-shadow-ordinary-boundary`

Pinned mimalloc has no Linux atfork handler which retires vanished Theap/TLD
owners. The native runtime child continuation is therefore an explicit crabc
transition, not a translation of a C fork algorithm. After exclusive child
quiescence it reuses the source collect-abandon, list-removal, metadata-free
and static-storage rules, and does not invoke a foreign deferred-free callback
for a vanished thread. The current thread keeps its exact owner and becomes the
child's initial descriptor; a vanished initial attachment becomes detached
without unmapping its static storage or removing the canonical process Heap. An
unprepared raw copy repairs nothing; from a worker it retains the copied
initial descriptor so later prepared-fork or terminal writers in that child
refuse.

The native-shadow libc `fork` drains every owner after all libc fork locks and
repairs the child before any allocation. Two observable differences from musl
follow. `fork` fails with `EAGAIN`, after running parent handlers, when a
prepared preflight refuses: another thread is inside a foreign allocator
diagnostic or deferred-free callback (which may need a libc lock this fork
holds), or an owner is retained. Musl's `fork` has no such refusal. `_Fork` and
non-VM `clone` copy an unprepared image, like musl, so a multithreaded caller's
child keeps only async-signal-safe operations; unlike musl, a later `fork` in
that child from a worker-origin copy fails with `EAGAIN`. The contract is in
`docs/design/allocator.md`; the installed check is
`./scripts/dev-x86_64.sh owned-native-allocator-fork`.

### `CRABC-LIBC-APPLICATION-ALLOCATOR-REPLACEMENT` — accepted integration boundary

- **Port map:** `src/alloc-override.c`

The native-shadow libc, and the default C-backend wrapper
(`libc/src/allocator_mimalloc.rs`) in the owned x86 static product, follow
musl 1.2.6's replacement contract: a program may replace `malloc`, `free` and
`realloc`, and optionally `calloc`, the aligned entries and
`malloc_usable_size`. Libc's derived entries then reach the replacement through
the public symbols: `calloc` allocates with public `malloc` and zeroes,
`reallocarray` calls public `realloc`, `posix_memalign` and `memalign` call
public `aligned_alloc`, and `valloc` calls public `memalign`. Libc's own
`aligned_alloc` refuses with `ENOMEM` once `malloc` is replaced. Musl refuses
only in dynamic processes (a static musl program with a replaced `malloc` still
gets an internal mallocng pointer its `free` cannot own); the owned static
archives refuse there too, so no backend pointer reaches an application
allocator.

The native-shadow static archive binds the malloc family weak, because its
entries share one object where musl uses separate archive members. The
C-backend static archive gives each entry its own member with musl's binding.
libc.so keeps musl's bindings. Checked by
`./scripts/dev-x86_64.sh owned-allocator-override` (native shadow) and
`./scripts/dev-x86_64.sh owned-static-replacement` (default static product).

### `CRABC-MI-METADATA-RELEASE-EXCLUSIVE-ARENA-THEAP` — accepted integration boundary

- **Port map:** `src/theap.c:requested-parent-arena-theap-prefix-lifecycle`, `src/subproc.c:metadata-free-kinds-child-ownership-and-deterministic-overlap`

Pinned `src/subproc.c:29-81` returns Malloc IDs for every ordinary metadata
allocation or replacement; static main TLD/Theap/subprocess images take its
no-free branch. The only freeing non-Malloc producer is `src/theap.c:318-325`:
an exclusive-arena Heap allocates its Theap through `_mi_arenas_alloc` with a
non-null requested arena, which forbids both fresh-arena reservation and OS
fallback (`src/arena.c:549,578`), so the result is Arena or failure. OS,
huge-OS and remapped-OS metadata release is not reachable in this profile.

The isolated `cfg(test)` dynamic attachment model retains that exact arena
and process policy. It has no production caller in the fixed x86-64 profile.
`DynamicTheapStorage` owns either the ordinary Malloc capability or
`ExclusiveArenaTheapStorage`; both use the regular TLS key, cached reference,
TLD/Heap lists, heap-local arena-page image and `DynamicTheapPageSession`. The
page engine derives the required arena from the session. Constructor failure
after arena exhaustion or disabled arena allocation releases the already-created
TLD/TLS/key state without publishing a Theap or substituting another arena or
OS allocation. A nonnegative NUMA observation admits the source second
requested-parent search pass. Teardown removes roots and lists before clearing
and releasing the exact Arena Theap slice; a failed final release retains
terminal provenance rather than granting a second release.

Ordinary dynamic abandonment, concurrent heap force-destruction and public
heap APIs are outside this entry.

Checked by `m2_metadata_arena_x86_64.c` (pinned producer: live pages, forced
collection preserving clients, final Theap-slice reuse, requested-arena
exhaustion) against the two Rust `dynamic_theap` tests, which print the same
fourteen measured keys; `allocator-m2` requires them equal. Also
`m2_metadata_ownership_x86_64.c` and
`meta::ownership_tests::emit_native_metadata_ownership_trace` compare the
`_mi_meta_free` no-free predicate for every memory kind, the Arena branch, a
non-main subprocess whose image and metadata Theap are parent metadata, and one
deterministic allocation/release overlap. In the overlap a thread holds
`theap_meta_lock` until an arena-growing allocation waits on it, then a third
thread releases a published Malloc block. The source release is a lock-free
remote `mi_free` and completes inside that window; the Rust release reaches the
metadata backing lock the allocation already holds and completes after it. Only
facts common to both are compared.

### `CRABC-LIBC-SHADOW-ABI-REALLOC-NULL-ZERO-ALIGNMENT` — accepted public-C ABI boundary

- **Port map:** `src/alloc.c:nondefault-crabc-libc-native-mimalloc-shadow-ordinary-boundary`
- **Backends:** `libc/src/allocator_mimalloc.rs:realloc` through the ordinary
  `libmimalloc-sys` 0.1.49 C-backed artifact, compared with
  `libc/src/allocator_native_mimalloc.rs:realloc` under the nondefault
  `native-mimalloc-shadow` feature. This is not a Rust-port versus pinned
  mimalloc engine differential.
- **Difference:** in the ordinary `libc.so`, `realloc(NULL, 0)` returns a
  freeable zero-size result that is not 16-byte aligned; the native-shadow
  artifact returns a freeable 16-byte-aligned one. Both preserve the incoming
  errno. The 16-byte alignment is the owned libc's own C ABI requirement, which
  the native shadow meets and the ordinary wrapper does not.
- **Check:** `compat/allocator/shadow-abi-matrix/run.py` with
  `compat/allocator/shadow-abi-matrix-v1.json` and
  `tests/fixtures/native_mimalloc_shadow_backend_matrix_test.c`. It accepts only
  `ordinary-c-mimalloc = freeable-misaligned-preserves-errno` and
  `native-rust-mimalloc-shadow = freeable-aligned-preserves-errno`; any other
  outcome is a harness failure.
- **Removal:** change only with an explicit C-ABI decision, a default-backend
  implementation change and musl evidence. A passing matrix does not make the
  two artifacts equivalent.

### `CRABC-MI-SCOPED-REGULAR-AND-FULL-REMOTE-PRODUCER` — accepted bounded routing boundary

- **Port map:** `src/free.c:live-owner-remote-free-push-and-collection-protocol`, `src/page.c:non-abandoning-full-page-remote-free-collection`
- **Upstream/Rust:** `src/free.c:mi_free_block_mt` and `src/page.c:mi_page_thread_free_collect`,
  `mi_page_queue_find_free_ex`, `mi_page_to_full`, `mi_theap_collect_full_pages`,
  represented by `single_thread::RemoteFreeProducer` and
  `SingleThreadAllocator::begin_remote_free`.
- **Scope:** private routing and lifetime boundary; no C ABI surface.
- **Difference:** mimalloc admits remote frees from general allocation routes
  and collects them under its full lifecycle. This port admits one
  caller-proved current allocation from a live same-Theap/same-thread page only
  when it is an active `BIN_FULL` member or an active matching regular non-huge
  member. The regular candidate scan (including a small direct-cache miss)
  consumes the publication before extension/full classification; the full scan
  consumes it before unfull/release. A linear `Send`/`!Sync` token holds the
  exclusive allocator borrow while a scoped worker may only publish the
  canonical block or cancel to the original client pointer. The caller proves
  join/quiescence before queue collection because the queue helpers borrow page
  metadata.

  The nondefault native libc shadow has one further bounded route: static state
  retains only A's compiler-TLS slot/generation, B proves one exact C address
  against A's private ledger and completes `PARKED -> BUSY -> PARKED` with the
  process PageMap lease before the same atomic push; A's next ordinary
  operation or all-free drain collects the head, and A claims or removes the
  static handoff before every TLS access.

  Detached sessions, a producer registry, concurrent queue collection, general
  owner exit, general pthread lifecycle, multiple independently published A
  routes and general asynchronous or public free routing are absent. Unlike the
  infallible C collection calls, a Rust owner-side collection error permanently
  poisons this private allocator and retains the exact page, error and any
  locally popped block; allocation, inspection, free, producer preparation and
  collection then reject. The raw local-list substrate implements the source
  force-only append and rejects a malformed local cycle before relinking.
- **Check:** `single_thread::tests::` `full_page_false_collection_reclaims_a_joined_remote_block_for_ordinary_reuse`,
  `full_page_false_collection_releases_a_joined_remotely_empty_page`,
  `regular_generic_remote_publication_is_collected_before_full_classification`,
  `small_direct_remote_publication_retries_the_direct_page_before_full_transition`,
  `page_to_full_collects_a_remote_publication_after_the_enqueue`,
  `page_to_full_collection_failure_permanently_retains_the_popped_block`,
  `remote_producer_rejects_an_unlinked_regular_page_without_mutation` and
  `full_page_remote_producer_cancellation_restores_the_original_interior_client`;
  `crabc-mimalloc/tests/native_live_remote_free.rs` with
  `tests/fixtures/native_mimalloc_live_remote_free_test.c` and
  `tests/fixtures/native_mimalloc_live_remote_from_parked_worker_test.c` (the
  A-live B/C handoff, including B already holding a parked session);
  `crabc-mimalloc/tests/native_parallel_local_workers.rs` (a second parked
  worker's local-only lifecycle is not rejected).
- **Removal:** when producer lifetime registration, queue-safe concurrent
  collection and general allocation/free routing are ported. It does not
  authorize an unbounded `Send` page handle, raw-pointer ownership
  reconstruction or a general remote-free API.

### `CRABC-MI-OWNED-TLS-KEY-REGISTRY-INVALID-OWNER` — accepted private terminal boundary

- **Port map:** `src/threadlocal.c:allocator-owned-process-global-regular-tls-key-registry`
- **Upstream/Rust:** `src/threadlocal.c:221-315` (`mi_thread_local_create_expand`,
  `_mi_thread_locals_done`) and `owned_tls_key_registry::OwnedThreadLocalKeyRegistry`
  with its typed bitmap boundary in `meta.rs`.
- **Scope:** private invalid-owner and incomplete-shutdown handling; no C ABI
  surface.
- **Difference:** the process-global registry uses fallible private locks,
  typed-image validation and linear `MetaAllocation` release where C exposes no
  equivalent error. A failed allocation before replacement commit is retryable
  and preserves the old image and generation. An impossible published-image or
  provenance projection, an absent appended-range result, or an error after
  new-image commit while freeing the old capability is terminal: the registry
  is poisoned and retains its process-static typed state rather than
  reinterpreting uncertain ownership. Shutdown rejects live leases and late
  release/claim; it does not implement the source's full `_mi_thread_locals_done`,
  fast-key deletion or lock destruction.
- **Check:** `owned_tls_key_registry::tests::failed_first_or_expansion_allocation_preserves_bitmap_and_generation`,
  `shutdown_requires_quiescence_then_rejects_late_claim_and_release_without_bitmap_access`,
  `meta::tests::selected_aligned_main_metadata_projects_only_an_exact_transient_bitmap_image`.
  Exact C comparison is inapplicable to impossible private-lock or provenance
  failures.
- **Removal:** when a full process initialization/shutdown and key-to-thread
  lifecycle can distinguish every release outcome without retrying ambiguous
  ownership. It does not authorize raw capability reconstruction, persistent
  bitmap views, lock stealing, silent `Drop` release or a false live-lease
  decrement.

### `CRABC-MI-MAIN-STATIC-LOCK-POISON` — accepted invalid-owner teardown boundary

- **Port map:** `src/init.c:ticket-zero-process-static-main-heap-default-theap-attachment`
- **Upstream/Rust:** `src/theap.c:_mi_tld_detach_theaps`, `src/init.c:mi_thread_theaps_done`,
  `main_theap::MainStaticTheapAttachment::teardown`.
- **Scope:** private invalid-owner lifecycle handling; no C ABI surface.
- **Difference:** after owned roots are reset in source order, any fallible
  private-lock or intrusive-list failure is terminal invalid-owner handling. C
  locks return no error here, and this port does not implement the source
  heap-busy retry. The private futex lock must not wait, steal a lock or
  continue after an unexpected alias, so heap-busy before list mutation, later
  list failures and the post-detach TLD quiescence failure poison the static
  attachment before registration release. The process-static storage and live
  registration remain; no completed teardown is claimed. Root mismatch and
  nonzero-page rejection occur before root mutation and preserve every
  live/foreign root and list before terminal poison.
- **Check:** `main_theap::tests::busy_heap_lock_after_root_reset_poison_retains_lists_and_live_registration`,
  `main_theap::tests::post_detach_busy_tld_lock_poison_retains_the_live_registration`;
  the normal static-attachment test covers successful quiescence and release.
  Exact C comparison is inapplicable: a valid C lifecycle reaches teardown with
  no held private lock.
- **Removal:** when a complete private-lock and shutdown design proves a
  source-faithful destruction path without aliasing risk. It does not authorize
  retries, lock stealing or counter decrements after a failed quiescence check.

### `CRABC-MI-MAIN-STATIC-INIT-POISON` — accepted invalid-owner initialization boundary

- **Port map:** `src/init.c:ticket-zero-process-static-main-heap-default-theap-attachment`
- **Upstream/Rust:** `src/theap.c:_mi_theap_init`, `src/init.c:_mi_thread_init_with_heap`,
  `main_theap::MainStaticTheapAttachment::begin_after_heap_foundation`,
  `types::Theap::initialize_main_static`.
- **Scope:** private invalid-owner lifecycle handling; no C ABI surface.
- **Difference:** the process-static attachment is entitled to freshly
  initialized, uncontended TLD and heap lists, so Rust uses a non-blocking
  private-lock boundary for those one-owner attachments. A busy fresh list
  proves an invalid alias; a private unlock error after list mutation, or a
  later heap-list error, requires invalid concurrency or a lock failure outside
  the valid owner contract. C mutex operations return none of these. Once the
  static TLD is completed and registered there is no rollback: process-static
  storage is poisoned, the static TLD and its live registration are retained
  and no teardown owner is returned. A failure before root publication leaves
  dynamic/default/cached/fast roots pristine and the heap list empty.
- **Check:** `main_theap::tests::busy_tld_list_during_initial_attachment_poison_retains_static_tld_registration`.
  Exact C comparison is inapplicable: a valid C lifecycle does not begin from
  an aliased or failed private lock.
- **Removal:** when complete private-lock and teardown ownership can prove
  source-faithful cleanup without aliasing. It does not authorize retry, lock
  stealing, registration decrement or a fabricated teardown capability after a
  partial initialization.

### `CRABC-MI-BOUNDED-PROCESS-MAIN-INITIALIZATION` — accepted incomplete process lifecycle

- **Port map:** `src/init.c:bounded-source-main-process-initialization-order`
- **Upstream/Rust:** `src/init.c:108-118,151-214,236-250,305-360,536-592`
  (`mi_heap_main_init_once`, detached `mi_tld_init`, `_mi_thread_init_with_heap`,
  `mi_process_init_once`, including `:196-198`'s kind-only `memid` -> Release
  `heap_main` -> `_mi_heap_init` order), `src/heap.c:102-126`,
  `src/theap.c:228-296,343`, `src/random.c`, `src/options.c:161-162`,
  `src/libc.c:115-140` (`_mi_atomic_once_enter/_release`),
  `src/subproc.c:29-81,84-101,141-148,249-251` and
  `include/mimalloc/atomic.h:446-472`; represented by
  `process_init::ProcessMainInitializationStorage`, `once::AllocatorOnce`,
  `main_theap::MainStaticHeapFoundation`, `meta::MetaAllocator::prepare_for_main_subprocess`,
  `bootstrap::ExclusiveTheapBootstrap::bind_detached_for_main_subprocess`,
  `types::ThreadLocalData` detached-initialization helpers,
  `types::Theap::{set_detached_main_metadata_static_memid,bind_exclusive_detached}`,
  `random::TheapRandomImage::{initialize,next}`,
  `process_page_map::ProcessPageMapStorage` and the `subproc::MainSubprocess`
  main-Heap and metadata-Theap publication methods.
- **Scope:** crate-private startup boundary; no C ABI surface.
- **Difference:** the Rust coordinator proves the central source order (static
  Heap, static detached metadata-image binding without backing, one-way
  detached-Theap identity publication, global PageMap, then ticket-zero
  TLD/Theap/default/fast roots) but accepts a frozen `MemoryConfig` instead of
  running source option/OS initialization.
  - C forms `mi_process_theap_meta` during main-heap initialization with a
    kind-only `MI_MEM_STATIC` memid and takes metadata backing on demand; Rust
    binds its pinned detached image before the global PageMap.
  - For the canonical static main Heap, Rust reserves a pointer-free
    `MainSubprocess` state before mutating the candidate Heap, writes the
    kind-only `MemoryId`, Release-publishes its final-slot identity, completes
    the remaining Heap fields, and only then exposes an opaque comparison-ready
    identity. A failed reservation leaves the candidate COLD with
    `MemoryKind::None`. This is narrower than C's dereference-capable
    `_mi_subproc_heap_main`: the ready identity never yields a Heap reference.
  - For the detached TLD input (same subprocess, empty head, non-threadpool),
    Rust preserves the kind-only provenance fields and the frozen
    `page_reclaim_on_free = 0` result, initializes the possibly-weak random
    image and derives an odd cookie before Release publication. C first locks
    and inserts into the TLD list, then chooses normal initialization or a head
    snapshot with `_mi_random_split`; Rust rejects a nonempty head, mismatched
    subprocess or thread-pool input before mutation instead of modelling those
    routes. C applies the detached non-abandoning and retain-two fields after
    `_mi_theap_init` publishes; Rust writes its final image first because it
    does not model those lists.
  - `MetaAllocator` Release-CASes the bound Theap address into a private
    `MainSubprocess` atomic; COLD direct `zalloc`, aligned `zalloc` and
    `rezalloc(None)` reject with `TheapMetaUnpublished` before any metadata
    lock, mapping or capability. `MainSubprocess::is_metadata_page(Option<&Page>)`
    maps `_mi_meta_is_meta_page` with one Acquire-loaded pointer comparison and
    takes no lock; its Release/Acquire slot is a Rust safety representation,
    not C field-memory-order parity. Selected direct `zalloc`, aligned `zalloc`
    and `rezalloc` replacement hold `MainSubprocess::lock_metadata_theap` inside
    the backing lock; the selected Malloc branch of `_mi_meta_free` does not
    take `theap_meta_lock`, and Rust serializes exact-owner free with the
    backing lock only.
  - The production binding uses `MetaAllocator::bind_process_backing` and
    `ProcessMetadataPageAllocator` with the shared PageMap and process
    arena/OS policy; historical explicit-config fixtures use a private
    direct-OS PageMap and external-arena backing.
  - `MetaAllocation::into_source_retained_theap` / `into_source_retained_tld`
    consume typed Malloc capabilities into the source images; their unsafe
    inverses require proof of the earlier transfer, unchanged memory ID, the
    same metadata allocator, exclusive quiescent ownership and no surviving
    wrapper. Neither frees an image or mutates registration or lists.
  - `initialize` holds the once gate through terminal publication; recursive
    owner entry returns a typed `Initializing` refusal, a foreign caller waits.
    A Rust-only allocation-free preflight may cancel before source selection; a
    preflight rejection stays cold, and a failure after static selection is
    terminally retained. C's static empty PageMap root remains absent.
  - Not modelled: actual `mi_subproc_t` layout or pthread-lock semantics, Page
    lifetime or abandonment, other `theap_meta_lock` uses (`src/free.c:744-778`,
    `src/init.c:524-530`) and its init/done lifecycle, the rest of
    `_mi_theap_init`, mutable option/OS processing, TLD/Heap list locking,
    guarded initialization, statistics, random-split parity, pthread/TLS-key
    initialization, concurrent startup, generic non-Malloc metadata release and
    process teardown.
- **Check:** `types::tests::emit_m2_detached_tld_static_preimage_c_rust_trace`
  with the pinned-C fixture in `./scripts/dev.sh allocator-m2` compares the
  detached preimage, kind-only memid predecessor and detached `mi_tld_init`
  writes (field-relational, not an allocation trace). Rust-side:
  `bootstrap::tests::detached_binding_initializes_the_static_image_before_issuing_its_one_session`,
  `types::tests::detached_exclusive_binding_rejects_an_invalid_fresh_tld_checkpoint_before_mutation`,
  `process_init::tests::process_main_initialization_orders_heap_metadata_map_then_ticket_zero_roots`,
  `process_main_binds_metadata_before_global_page_map_failure`,
  `process_main_defers_private_metadata_backing_until_first_demand`,
  `process_main_once_blocks_a_distinct_racer_until_release_and_refuses_reentry`,
  `cancelled_pre_body_claim_handoffs_a_waiter_to_the_reopened_once`,
  `main_theap::tests::static_heap_foundation_precedes_ticket_zero_tld_theap_and_tls_roots`,
  `static_heap_foundation_makes_the_canonical_main_heap_identity_ready_last`,
  `subproc::tests::selected_static_bootstrap_cannot_issue_ticket_zero_before_heap_foundation`,
  and `meta::tests::cold_direct_metadata_demand_requires_prepared_theap_publication`,
  `bound_subprocess_metadata_page_query_is_exact_without_backing`,
  `bound_subprocess_theap_meta_lock_serializes_direct_allocation_phase`,
  `typed_malloc_release_retains_a_live_capability_after_recursive_entry_rejection`.
  The C companion `compat/allocator/m2_metadata_x86_64.c` and
  `meta::tests::process_metadata_cross_thread_publication_and_replacement_trace`
  compare concurrent direct/aligned allocation, cross-thread transfer,
  oversized replacement refusal retaining the old allocation, grow/shrink
  prefix copying, zeroed growth and typed release (C clears the failed
  replacement's output memory ID; the test saves the old one separately,
  matching Rust retaining the old capability).
- **Removal:** when complete `_mi_theap_init`, source options/OS and TLS-key
  stages, the C empty-root policy, concurrent thread and map startup, automatic
  arena policy, routing, shutdown and fork repair have their own proved owners.
  It does not make this coordinator a complete process initializer or public
  startup API.

### `CRABC-MI-NORMAL-TLD-DIRECT-HELPER` — accepted M2 direct-helper differential boundary

- **Port map:** `src/init.c:normal-tld-direct-helper-post-ticket-sequence-seven`
- **Upstream/Rust:** `src/init.c:155-157,236-250` with the local zero
  initializer (`include/mimalloc/internal.h:104-110`), TLD/subprocess counters
  (`include/mimalloc/types.h:288-297,670-701`), lock and increment operations
  (`include/mimalloc/atomic.h:90-97,446-471`), thread identity
  (`include/mimalloc/prim-tls.h:185-190`) and the false thread-pool result
  (`src/prim/unix/prim.c:1059-1061`); represented by
  `types::{ThreadLocalData::normal_tld_init_preimage,
  ThreadLocalData::initialize_normal_tld_field_prefix_after_direct_preimage_with_numa_source,
  NormalTldInitWriteTrace}` and the test-only `subproc::ThreadRegistrationTicket`.
- **Scope:** private direct file-static helper; neither `mi_tld_create` nor a
  static-main or metadata caller lifecycle.
- **Difference:** the pinned-C fixture direct-includes `src/init.c` and starts
  from a fresh all-zero local TLD plus an address-only zero subprocess in a
  post-ticket context (total `8`, sequence `7`, live `0`, full `MI_MEM_NONE`),
  injecting the source-valid NUMA result `3` (not OS discovery). C dynamically
  observes lock, NUMA, thread ID, false threadpool, live-count increment; plain
  assignments are covered by source anchoring and poststate; the return is
  `&tld`. The helper accepts only a validated `LiveThreadId`, so it has no
  invalid-identity branch or ticket consumption. The Rust field-prefix helper
  records all eight field/counter effects with registration last, keeps the
  input as the in-place TLD but returns a lease, not a TLD reference, and
  leaves `MemoryId::none()` unchanged. A busy lock or preimage refusal is a
  Rust-only safety strengthening before any mutation and returns the unconsumed
  ticket; ordinary ticketed allocation failure remains sequence-consuming.
- **Check:** `subproc::tests::normal_tld_init_direct_preimage_refuses_busy_lock_then_registers_sequence_seven`
  and `subproc::tests::emit_m2_normal_tld_direct_c_rust_trace` (31
  address-independent relations against the pinned-C `compat/allocator/run.py`
  fixture); `main_theap::tests::ticket_zero_static_tld_uses_fixed_numa_wrapper_after_static_memid`
  (production static path registers while CLAIMED, before Release publication).
- **Removal:** when a caller owns C ticket issuance, `mi_tld_create` storage,
  `_mi_subproc_main_init`, option/NUMA execution, Theap/list/TLS/root
  publication, teardown, pthread ABI, races and allocator integration. No raw
  pointer, layout, thread-ID value or primitive invocation timing is compared.

### `CRABC-MI-STATIC-FIRST-TLD-CREATE-DIRECT` — accepted M2 selected static-success differential boundary

- **Port map:** `src/init.c:static-first-tld-create-direct-success-arm`
- **Upstream/Rust:** `src/init.c:155-157,253-272` with `src/subproc.c:12-15,95-101`
  (excluding `_mi_subproc_main_init`, `src/subproc.c:316-322`),
  `include/mimalloc/internal.h:167-180,1316-1344`,
  `include/mimalloc/types.h:288-339,651-701`,
  `include/mimalloc/atomic.h:87-99,446-471`, `include/mimalloc/prim-tls.h:185-190`,
  `src/prim/unix/prim.c:1059-1061`, and `src/os.c:860-898` only for the
  fixture's normalized NUMA `3`; represented by the static attachment path in
  `main_theap`, `subproc` and `types` with the test-only `StaticFirstTldCreateTrace`.
- **Scope:** one direct first-main/static-TLD `mi_tld_create` success arm; not
  a complete process, main-subprocess, metadata or static-owner lifecycle.
- **Difference:** the pinned-C fixture direct-includes `src/init.c` and calls
  file-static `mi_tld_create(_mi_subproc_main())` once on the source
  main-subprocess/static-TLD identities with zero counts and an inert nonnull
  `theap_meta`; it never calls `_mi_subproc_main_init()`. C validates its
  fetch-add, main predicate, static memid, lock, NUMA, ID, pool, live, return
  sequence and observes no `_mi_meta_zalloc` call. Rust enters its ticket-zero
  static-slot attachment after `reserve_static_bootstrap` and
  `MainStaticHeapFoundation`, so selector and foundation precede ticket issue;
  the compared record starts at ticket zero, then concrete static memid, shared
  normal field body, live registration, `MAIN_TLD_LIVE` Release. C's predicate,
  caller, preflight and return timing are therefore not common relations. C
  invokes the thread-ID primitive after NUMA; Rust validates identity before
  issuing a ticket. C's return observer after live registration and Rust's
  following Release are a semantic visibility correspondence, not the same
  publication primitive. C's zero-initialized global and Rust's `MaybeUninit`
  storage are not compared byte-for-byte; both records reduce static
  provenance to address-independent relations (static kind, self-base,
  own-TLD-size, pinned, initially committed, initially-zero false). Rust's
  `MainSubprocess` is test-selected, not the C `_mi_subproc_main()` object.
- **Check:** `main_theap::tests::emit_m2_static_first_tld_create_c_rust_trace`
  (real selection/foundation/attachment path, then teardown) against the
  pinned-C fixture in `compat/allocator/run.py`: 36 shared address-independent
  relations.
- **Removal:** separate owner-bearing C/Rust evidence for static storage
  layout, `_mi_subproc_main_init`, Theap/metadata initialization, generic and
  failed arms, list/TLS/root publication, teardown, pthread layout, races,
  NUMA policy and allocator integration.

### `CRABC-MI-STAGED-INITIAL-OWNER` — accepted staged ownership and evidence boundary

- **Port map:** `src/init.c:bounded-source-main-process-initialization-order`
- **Upstream/Rust:** `src/init.c:305-360,536-592` installs the default Theap
  before key setup and startup reservations. Rust represents the
  allocation-ready subset with `ProcessMainAllocationLease`, then moves the
  owner into `RuntimeProcessStorage` before `ProcessMainStartup` performs the
  remaining reservations and diagnostic post-init. `arena_selection.rs` keeps
  the shared `mi_forall_suitable_arenas` traversal; initial and later native
  owners use `ProcessMainBackingBinding` for one canonical registry.
- **Difference:** final process-ready authority is distinct from early
  initial-thread allocation admission. Another thread cannot acquire the staged
  subset; an outstanding mutable page-owner projection refuses nested entry and
  callbacks run after it ends; an unfinished continuation retains the published
  owner instead of replaying source initialization. These borrow boundaries
  are not `MI_TLS_RECURSE_GUARD` (disabled in the pinned Linux release
  profile). `CurrentDefaultTheapRandom` looks up compiler TLS before each draw
  and briefly projects the initialized random field; no owner or random
  reference survives into VM operations or diagnostic callbacks.
- **Limits:** the simulated early diagnostic does not establish C
  startup-warning delivery timing, and mixed regular/simulated registry
  traversal does not establish huge-page or NUMA hardware success. The
  explicit-worker C/Rust recursion receipt is a separate scope.
- **Check:** the staged-owner regression (live client before and after startup)
  and the delayed-output regression (real `OutputOwner::post_init` callback,
  request rejection and recovery, nested borrow refusal, later canonical owner).

### `CRABC-MI-PROCESS-PAGE-MAP-COLD-ROOT` — accepted cold-root representation boundary

- **Port map:** `src/page-map.c:mi-page-map-init-once-process-publication`
- **Upstream/Rust:** `src/page-map.c:228-365` (`mi_page_map_empty`,
  `__mi_page_map`, `mi_page_map_init_once`, `_mi_page_map_init`) and
  `src/subproc.c:253-255`; `process_page_map::ProcessPageMapStorage`,
  `ProcessPageMapRoot`, `ProcessPageMapMutationLease` over `page_map::PageMap`.
- **Scope:** private process-initialization and page-owner boundary; no C ABI
  surface.
- **Difference:** C begins with a non-null static empty page map so early
  `free(NULL)` lookup is valid, then its once body swaps in the mapped root.
  After a failed once body the sentinel remains and a later call reports
  success, but the sentinel only gives null lookup its safe-null result; it is
  not a valid map for registration or mutation. The Rust owner begins cold
  with no root and no free/lookup route; it freezes one `MemoryConfig` and
  `MainSubprocess`, constructs the map in its final slot and Release-publishes
  the root once. Consumers (typed ticket-zero and later-thread page engines)
  hold `ProcessPageMapMutationLease`, a nonrecursive private lock for one
  engine and joined scoped-producer lifetime, so no second Rust route may
  overlap plain map entries. Valid-program startup matches C: the top-level
  extent is mapped through the `_mi_os_alloc_aligned` sequence (a failed direct
  map warns, falls back to aligned over-allocation, trims and initializes);
  when the whole reservation fails the once body is consumed without replay and
  every allocation fails (`CRABC-MI-STARTUP-PAGE-MAP-FAILURE`). Only the
  storage owner's representation differs: it records the consumed body as a
  typed poison instead of C's lookup-only sentinel, and dropping an unfinished
  mutation lease poisons the root.
- **Check:** `process_page_map::tests::process_map_publishes_one_stable_root_for_its_selected_main_subprocess`,
  `concurrent_process_map_initializers_share_the_one_release_published_root`,
  `page_lifecycle_is_exclusive_and_an_unfinished_owner_poisoned_the_root`, the
  three mapping/commit-failure regressions, and
  `process_page_map::tests::emit_m2_page_map_cold_init_failure_rust_trace` with
  its pinned-C producer in `./scripts/dev.sh allocator-m2` (one injected first
  PageMap failure: the body fails once, no map publishes, no replay; C's static
  root and later success are recorded separately from Rust's absent root and
  typed poison). Also `emit_m2_page_map_first_map_fallback_c_rust_trace` with
  `m2_page_map_first_map_fallback_x86_64.c` (startup output, initialization, VM
  statistics, first allocation), `process_init::tests::rejected_page_map_after_heap_and_metadata_retains_ticket_zero_without_tls_publication`,
  `main_static_page::tests::unfinished_static_page_engine_poison_retains_the_page_and_process_map_owner`
  and `main_heap_page::tests::unfinished_later_page_engine_poison_retains_the_attachment_and_process_map`.
- **Removal:** a public C allocator ABI or complete process lifecycle that needs
  cold `free(NULL)` semantics must reopen this with a cold-sentinel owner, a
  lookup-only API and lifecycle tests. It does not authorize a null-root
  lookup, a retryable global mapping owner, a private alternate map for shared
  threads, or page-bearing integration beyond the ticket-zero and sequential
  later-thread slices.

### `CRABC-MI-PAGE-MAP-HEADER-AND-ROOT-OWNER` — accepted M2 success and lazy-commit differential boundary

- **Port map:** `src/page-map.c:mapped-two-level-page-map-lifecycle`
- **Upstream/Rust:** `src/page-map.c:228-457,236-269,386-427` (`mi_page_map_t`,
  `mi_page_map_init_once`, `mi_page_map_commit_entries`,
  `mi_page_map_ensure_committed`, `mi_page_map_ensure_submap_at`,
  `mi_page_map_set_range`, `_mi_page_map_unsafe_destroy`); `page_map::PageMapHeader`,
  `PageMap`, `PageMapRoot`.
- **Scope:** Linux/AArch64 source-private success-path evidence plus one
  lazy-commit failure differential; no C ABI effect.
- **Difference:** under the pinned Linux/musl fixture C embeds its 40-byte
  `pthread_mutex_t` `mi_lock_t` in an 88-byte PageMap header; the `no_std` Rust
  port embeds a 4-byte `PrivateLock` in a 56-byte header. Because the sizing
  formula includes the header, C records `reserved/initial-committed =
  524790/16886` and Rust `524794/16890`; the lazy-extension delta is the same
  7,680 entries. C destroys a still-published global root and restores
  `mi_page_map_empty`; Rust's `PageMapRoot` must be unpublished before
  `PageMap::destroy`. A failed initial or trailing-submap commit whose cleanup
  release also fails matches C (`mi_os_prim_free` warns, leaks the mapping and
  fails initialization).
  Rust additionally retains state on failures where C's release is void:
  a failed lazy submap mapping leaves the top-level mapping intact, a failed
  submap reclaim leaves its exact raw slot, and a failed final release leaves
  the top-level owner for retry. The source CAS-loser branch is not injectable
  because every current publisher holds the same private lock and reloads; a
  competing writer must retain a losing candidate before that branch is
  reachable.
- **Check:** `./scripts/dev.sh allocator-m2` compares the pinned-C fixture
  (4-KiB/48-bit trace) with `page_map::tests::emit_m2_page_map_init_c_rust_trace`,
  requiring every other transition field to match, and compares the lazy-commit
  failure (`_mi_os_commit` wrapped in a source process, failure before
  `committed_count` Release publication and before `_mi_os_zalloc`, then a
  retry that publishes one submap) with
  `emit_m2_page_map_lazy_commit_failure_c_rust_trace`;
  `m2_page_map_init_cleanup_x86_64.c` against `emit_m2_page_map_init_cleanup_c_rust_trace`;
  Rust-only `lazy_extension_commit_failure_preserves_the_top_level_mapping_for_retry`,
  `lazy_submap_mapping_failure_preserves_the_page_map_for_retry`,
  `destroy_lazy_submap_release_failure_retains_the_exact_slot_for_retry`,
  `destroy_top_mapping_release_failure_retains_the_exact_mapping_for_retry`.
  Not compared: header sizes, root representation, error form, cold
  initialization, range rollback, lazy submap-map failure, CAS losers, races.
- **Removal:** change the representation only with source-order, ownership,
  differential and performance review.

### `CRABC-MI-NORMAL-OFFSET-OS-ALLOCATION-OWNER` — accepted private VM-substrate safety boundary

- **Port map:** `src/os.c:normal-offset-os-allocation-full-provenance-owner`
- **Upstream/Rust:** `src/os.c:240-294,344-430,438-467,502-527` and the regular
  one-arena caller `src/arena.c:1885-1912`; `os::NormalOsAllocation`,
  `NormalOsBaseAllocation`, `NormalOsAllocationFailure`,
  `NormalOsAllocationReleaseFailure`, `Mapping`.
- **Scope:** private normal non-huge OS-allocation ownership; no C ABI effect.
- **Difference:** the Rust owner fixes the route to non-huge, non-hinted
  `allow_large = false`, retains the full mapping base and extent in
  `MemoryId::os`, and exposes a separate, potentially interior client pointer
  for offset alignment. Zero offset delegates to ordinary aligned-map
  normalization; a committed nonzero route best-effort decommits the prefix,
  the reserved route does not. C reports failure as `NULL` and frees through a
  void best-effort primitive; Rust returns diagnostics and the exact
  unmap-failure owner for retry. The regular one-arena caller may consume only
  `NormalOsBaseAllocation` (from the zero-offset path), moving the original
  `Mapping` and `MemoryId` together into arena management; an offset
  allocation has no such conversion.
- **Check:** `os::tests::{normal_offset_os_allocation_retains_full_provenance_and_retries_release,normal_os_allocation_uses_good_size_and_base_provenance,normal_offset_os_allocation_delegates_zero_and_rejects_invalid_geometry,normal_os_base_handoff_preserves_full_mapping_and_memid}`,
  `process_arena::tests::normal_os_base_handoff_preserves_full_provenance_until_one_arena_publication`,
  and the `explicit_os_reservation_*` regressions.
- **Removal:** none planned; applies to one fixed private route, not hints,
  huge pages, NUMA, options, statistics or other source callers.

### `CRABC-MI-LINUX-REUSE-NOOP` — accepted private VM-substrate safety boundary

- **Port map:** `src/os.c:linux-os-reuse-contained-range-noop`
- **Upstream/Rust:** `src/os.c:643-653` and `src/prim/unix/prim.c:536-542`;
  `os::Mapping::reuse`, `os::reuse_arena_range`, `ReuseOutcome::NoOp`; the
  caller is `src/arena.c:266-307` `mi_arena_try_alloc_at`.
- **Scope:** private reuse primitive plus one non-owning external-arena caller;
  no C ABI effect.
- **Difference:** after the source's conservative page normalization, Linux
  `_mi_prim_reuse` succeeds without a VM operation. Rust represents that
  contained-range outcome as `NoOp`; an empty conservative range returns
  `None`, and invalid or closed `Mapping` input returns typed `EINVAL` before
  a VM edge (C's void wrapper assumes a valid raw mapping, so the checked
  errors are a Rust strengthening). After the arena binned free claim succeeds
  and the committed bitmap reports its exact span fully set,
  `ArenaView::try_claim_suitable_slices` calls `reuse_arena_range` before
  `MemoryId::initially_committed`; that helper takes a prevalidated span, not a
  `Mapping` or release capability, so the backing owner is unchanged.
- **Check:** `os::tests::reuse_is_a_contained_range_noop_on_linux`,
  `arena::tests::fully_committed_arena_claim_invokes_linux_reuse_for_its_exact_span`.
- **Removal:** none planned; not partial or fresh commit behavior, another
  caller, reuse policy, Apple `MADV_FREE_REUSE`, hints or late failure.

### `CRABC-MI-FIXED-NUMA-CACHE-WRAPPER` — accepted private VM-substrate boundary

- **Port map:** `src/os.c:fixed-no-option-numa-cache-and-current-node-normalization`
- **Upstream/Rust:** `src/os.c:860-898` (`_mi_os_numa_node_count`,
  `mi_os_numa_node_get`, `_mi_os_numa_node`); `os::os_numa_node_count` and
  `os::os_numa_node` over the private `OS_NUMA_NODE_COUNT` cache.
- **Scope:** private NUMA observation and cache; one ticket-zero static-TLD
  caller (`src/init.c:236-250,260-272`); no arena placement; no C ABI effect.
- **Difference:** the fixed profile selects only the raw-primitive branch:
  `mi_option_use_numa_nodes` and verbose diagnostics are absent. Rust retains
  the source Acquire cache read, zero-or-above-`INT_MAX` count normalization to
  one, Release cache write, Relaxed single-node fast path, strict current-node
  `INT_MAX` rejection and modulo normalization. A local-atomic test seam avoids
  polluting the process cache and keeps the source's simple load/fill/store
  shape rather than adding a CAS or once protocol.
- **Check:** `os::tests::os_numa_wrapper_caches_and_normalizes_the_raw_primitives`,
  `os::tests::emit_m1_raw_c_rust_trace` (raw primitives), and
  `main_theap::tests::ticket_zero_static_tld_uses_fixed_numa_wrapper_after_static_memid`.
- **Removal:** none planned; not option override, diagnostics, topology change,
  first-fill races or arena placement.

### `CRABC-MI-ORDINARY-BITMAP-HIGHEST-SET-STALE-CHUNKMAP` — accepted checked observer boundary

- **Port map:** `src/bitmap.c:ordinary-bitmap-highest-set-relaxed-stale-chunkmap-scan`
- **Upstream/Rust:** `src/bitmap.c:1383-1403` `mi_bitmap_bsr` and its
  `src/bitmap.h:205-208` contract; `bitmap::BitmapView::highest_set_relaxed`.
- **Scope:** private read-only observer; no C ABI effect.
- **Difference:** Rust keeps the descending Relaxed chunk-map/data scan and
  scans every lower chunk below a high map bit, so a stale in-layout high entry
  cannot hide a lower live bit. C asserts every selected map bit is within its
  trailing layout; Rust caps the final field scan at the initialized chunk count
  instead of deriving the assertion-invalid pointer. Neither image is mutated.
- **Check:** `bitmap::tests::bitmap_highest_set_scan_skips_a_stale_high_chunk_and_preserves_the_map`,
  `bitmap::tests::bitmap_highest_set_caps_an_out_of_layout_chunkmap_bit`.
- **Removal:** none planned for this read-only slice.

### `CRABC-MI-ORDINARY-BITMAP-POPCOUNT-CONSERVATIVE-CHUNKMAP` — accepted checked observer boundary

- **Port map:** `src/bitmap.c:ordinary-bitmap-popcount-relaxed-conservative-chunkmap`
- **Upstream/Rust:** `src/bitmap.c:1406-1420` `mi_bitmap_popcount`;
  `bitmap::BitmapView::popcount_relaxed`.
- **Scope:** private read-only observer; no C ABI effect.
- **Difference:** Rust keeps the low-to-high Relaxed chunk-map and data scan. A
  stale in-layout map bit selects an empty chunk, contributes zero and stays
  set. C requires its valid trailing-storage layout; Rust skips the invalid
  data access of an out-of-layout stale map bit and retains the bit. Neither
  image is mutated.
- **Check:** `bitmap::tests::bitmap_popcount_relaxed_scans_conservative_map_fields_without_repair`.
- **Removal:** none planned for this read-only slice.

### `CRABC-MI-PROCESS-SHARED-ONE-ARENA-SIDECAR` — accepted incomplete arena boundary

- **Port map:** `src/arena.c:mi-manage-os-memory-ex2-process-shared-one-arena`, `src/arena.c:process-ready-published-shared-arena-pair`
- **Upstream/Rust:** `src/arena.c:341-406,525-569,1573-1611,1676-1791,1794-1912`
  (`mi_arena_reserve` and its retry point, `mi_arenas_add`,
  `mi_arena_initialize`, `mi_manage_os_memory_ex2`, the regular-map part of
  `mi_reserve_os_memory_ex2`); `process_arena::ProcessSharedArenaStorage`,
  `main_static_page::MainStaticRuntimeFirstArenaPageAllocator`,
  `process_owned_mapping_commit` and `ProcessPageArenaLease` over
  `ArenaRegistry`, `ManagedExternalRegion`, `Mapping` and `ProcessPageMapRoot`.
- **Scope:** private incomplete process-arena ownership; no C ABI effect.
- **Difference:** C may manage arbitrary external spans (including split
  sub-arenas) and chooses reservations through live option policy. Rust admits
  exactly one caller-selected complete aligned external mapping, or one
  explicit regular OS reservation whose slice-rounded request is one complete
  arena, and preserves only the first lazy automatic reservation decision:
  source max-page headroom, the 64-bit 1-GiB default, the Linux overcommit
  eager-map condition and the 128-MiB retry after an unpublished first attempt
  returns COLD. The ticket-zero first-arena owner invokes it only after a valid
  empty-Theap fresh-page miss (deriving the source small/medium/large/singleton
  span and preflighting the zero-page static image); it neither searches an
  existing arena nor reserves a later one.
  - The regular path consumes only a `NormalOsBaseAllocation`, carries its
    `MemoryId` with the exact `Mapping`, records `MemoryKind::Os`, and unmaps
    an unpublished metadata failure before returning COLD; a failed unmap
    retains the mapping terminally. The external path returns a
    pre-publication rejected `Mapping` to its caller. Once published, the map
    and its in-place arena are process-lived.
  - A reserved mapping enters its final sidecar slot before in-place
    initialization, so its callback commits metadata and later ranges through
    the exact `Mapping`; it conservatively reports nonzero, and the frozen
    Linux decommit path reports no recommit requirement. This is not source
    page-on-demand policy: the typed pair makes one range-checked direct
    page-area commit for an already-selected extension but does not select
    on-demand commitment, maintain `slice_pcommitted`, or reabandon after a
    failed commit.
  - The typed pair may be consumed by ticket-zero or one sequential
    later-thread page owner (installing the arena's embedded `pages_main`,
    registering and releasing ordinary pages, retaining a joined scoped
    producer). Absent: general arena selection, multiple or sub-arena support,
    concurrent later-thread ownership, root clear and destruction.
- **Check:** `process_arena::tests::` `shared_owned_arena_binds_to_the_release_published_map_and_selected_subprocess`,
  `reserved_owned_arena_commits_metadata_and_claims_slices_through_its_stable_mapping`,
  `reserved_owned_arena_commit_failure_returns_the_unpublished_mapping_for_retry`,
  `paired_page_lease_commits_one_page_area_without_marking_a_full_arena_slice`,
  `foreign_map_or_subprocess_rejects_before_mapping_or_registry_mutation`,
  `explicit_os_reservation_*`, `default_os_reservation_is_lazy_and_uses_the_pinned_first_arena_policy`,
  `default_os_reservation_retries_the_pinned_smaller_arena_after_its_first_map_failure`,
  `default_os_reservation_releases_both_failed_attempts_before_retrying_from_cold`,
  `default_os_reservation_plan_preserves_headroom_commit_and_retry_boundaries`;
  `main_static_page::tests::` `first_fresh_page_requirement_preserves_the_empty_theap_source_size_branches`,
  `first_ticket_zero_fresh_page_reserves_the_default_arena_only_after_a_valid_miss`,
  `reserved_os_arena_reservation_drives_one_static_page_lifecycle`,
  `main_static_page_allocator_binds_the_in_place_main_arena_bitmap_before_page_map_publication`.
- **Removal:** when existing-arena search, later reservation and scaling, and
  the fresh-allocation and owner-exit protocol connect the first policy to
  multiple owners and shutdown quiescence. It does not authorize eager startup
  reservation, option mutation, large-page or NUMA policy, generic arena
  management, raw page-map access or process teardown.

### `CRABC-MI-ABANDONED-BIT-ORDINARY-PAGE-GUARD` — accepted checked invariant

- **Port map:** `src/bitmap.c:abandoned-page-claim-and-clear-once-set-quiescence`
- **Upstream/Rust:** `src/arena.c:655-671` `mi_arena_try_claim_abandoned`,
  `:684-696` `mi_page_arena_pages`, `:725-778` `mi_arenas_page_try_find_abandoned`,
  `:1304-1337` `_mi_arenas_page_abandon`, `:1383-1409` `_mi_arenas_page_unabandon`;
  `src/bitmap.c:1306-1328` `mi_bitmap_find`, `:1340-1380`
  `mi_bitmap_try_find_and_claim`, `:1425-1432` `mi_bitmap_clear_once_set`;
  `BitmapView::try_find_and_claim_abandoned`/`clear_once_set`,
  `ArenaAbandonedPages::main_page_is_set` and the static-main and dynamic
  `MappedAbandonedPages` capabilities.
- **Scope:** private checked invariant; not general abandoned-page reclaim.
- **Difference:** C treats a missing heap-local ordinary `pages` bit in
  `mi_page_arena_pages` as an internal assertion failure. The checked Rust
  capabilities reject the stale `pages_abandoned[bin]` candidate instead: the
  rejection returns `KeepSet`, restoring the abandoned bit and its conservative
  chunk-map entry, without calling the ownership closure or decrementing
  `Heap::abandoned_count[bin]` (only a successful claim consumes the count).
  If an `unabandon` observes the reader's temporary clear, `clear_once_set`
  waits until the rejection restores the bit before clearing permanently. The
  source snapshot visits a rejected candidate once while an independent reader
  can claim a later set atomic word; the guard preserves both.
- **Caller obligation:** the ordinary-bit check is neither a PageMap lookup nor
  a page-identity proof. The caller must prove the arena/slice names a live
  PageMap entry and matching page metadata for the whole claim, preserve
  failed-claim restoration before an `unabandon` clear, then follow bitmap
  clear, mapped-identity clear, count decrement; final release is PageMap
  removal, ordinary-page-bit clear, metadata retirement, slice release.
- **Check:** `arena::tests::abandoned_reclaim_main_map_rejects_an_orphan_bit_without_consuming_it`,
  `abandoned_reclaim_main_map_retains_rejected_boundary_candidate_count`,
  `bitmap::tests::abandoned_reclaim_bitmap_rejected_reader_quiesces_before_later_word_retry`.
- **Removal:** when a complete PageMap/lifecycle owner supplies the identity
  and release proofs. It does not authorize a fallback lookup or a global owner
  registry.

### `CRABC-MI-STATIC-MAIN-PROCESS-PAGE-LIFECYCLE` — accepted bounded page-owner slice

- **Port map:** `src/arena.c:main-static-process-page-map-arena-lifecycle`
- **Upstream/Rust:** `src/init.c:181-224,305-360`, `src/arena.c:674-723`
  (`pages_main` selection), `:781-821,951-1114` (fresh page publication),
  `:1240-1282` (all-free release); the cfg(test) sidecar
  `main_static_page::MainStaticProcessPageAllocator`, `main_theap::MainStaticPageSession`,
  `process_arena::ProcessPageArenaLease`, `process_page_map::ProcessPageMapMutationLease`.
- **Scope:** cfg(test) isolated x86-64 sidecar page-owner model; no C ABI surface.
- **Difference:** the coordinator establishes static Heap, detached metadata,
  global PageMap, then ticket-zero roots in source order. This historical test
  slice receives an explicit matching one-arena map/root/configuration/subprocess
  pair rather than choosing or reserving an arena; the production x86-64 path
  uses `MainStaticRuntimeFirstArenaPageAllocator` with its process backing and
  owned PageMap ranges. The session rejects a
  foreign subprocess before static-image, map or arena mutation, rejects any
  linked later shared-main Theap, and installs only that arena's in-place
  `pages_main`, never a dynamic `mi_arena_pages_t`. It holds the sole map
  plain-entry lifecycle through fresh allocation, local free/collection and a
  joined scoped remote producer. Release follows PageMap removal, main bitmap
  clear, metadata retirement, slice release. A dropped unfinished engine
  poisons both static and map owners; unlike C there is no recovery or
  owner-exit traversal.
- **Check:** `main_static_page::tests::` `main_static_page_allocator_binds_the_in_place_main_arena_bitmap_before_page_map_publication`,
  `foreign_process_page_pair_rejects_before_static_heap_map_or_arena_mutation`,
  `preexisting_main_arena_bit_rolls_back_the_static_fresh_claim_without_map_publication`,
  `joined_remote_producer_is_collected_by_the_static_main_page_owner`, and the
  unfinished-engine regression.
- **Removal:** when options/OS and TLS-key startup, later-thread owners,
  multi-arena routing, abandonment, owner-exit traversal, process destruction
  and public allocation routing are proved. It is a test-only private owner and
  not a default allocator backend.

### `CRABC-MI-LATER-MAIN-PROCESS-PAGE-LIFECYCLE` — accepted test/audit page-owner adapter

- **Port map:** `src/arena.c:later-main-process-page-map-arena-lifecycle`
- **Upstream/Rust:** later-thread `_mi_thread_init_with_heap(mi_heap_main())`
  and `_mi_thread_done` ordering (`src/init.c:236-282,305-360,377-421,448-481`);
  `_mi_theap_collect_abandon` visit order (`src/theap.c:89-152`); force
  `_mi_page_free_collect` (`src/page.c:214-243`); sole-singleton
  `_mi_page_abandon` (`src/page.c:245-302`); failed-reclaim final free
  (`src/free.c:372-514`); main-heap `pages_main` selection and abandoned claim
  (`src/arena.c:631-778`); fresh arena-page publication
  (`src/arena.c:781-821,951-1153`); queue-tail insertion
  (`src/page-queue.c:204-330`); all-free release (`src/arena.c:1240-1282`).
  Represented by `main_heap_page::{MainHeapThreadProcessPageAllocator,
  MainHeapThreadProcessPageExitDrain, MainHeapThreadProcessPageExitSingletonHandoff,
  MainHeapThreadProcessPageExitMappedOneBlockHandoff,
  MainHeapThreadProcessPageExitMappedRegularRoute,
  MainHeapThreadProcessPageExitMappedRegularAdoption}`,
  `main_heap_thread::{MainHeapThreadPageSession, MainHeapThreadPageDrainSession}`,
  the `single_thread::ThreadExit*` handoff and post-exit types,
  `process_arena::ProcessPageArenaLease` and
  `process_page_map::{ProcessPageMapMutationLease, ProcessPageMapPostExitAccess}`.
- **Scope:** crate-private test, native-audit, and non-x86 process-PageMap
  adapter; no C ABI or selected x86 production lifecycle.
- **Difference:** the detailed `MainHeapThreadProcessPageAllocator` and
  `MainHeapThreadProcessPageExit*` shapes below are compiled only for tests,
  the native audit feature, or non-x86 targets. They preserve source-shaped
  process-PageMap lifecycle and exit cases for focused evidence; they are not
  the fixed x86-64 runtime route. The selected production x86 owner is
  `MainHeapThreadOwnerLocalPageEngine` inside `NativePersistentThreadOwner`.
  It keeps its page state in the owner and does not use this adapter's long
  PageMap mutation lease, suspension tokens, or post-exit route families.
  Within the adapter, the source fixture requires one current later metadata
  TLD/Theap and an independently published matching map/arena pair; it
  validates the exact subprocess and frozen configuration before taking the
  map lifecycle, takes short serialized projections of the shared static Heap
  only where it needs a mutable Heap address, and installs the arena's embedded
  `pages_main` (never a dynamic `mi_arena_pages_t`). One map lifecycle covers
  fresh allocation, local free/collection and one joined scoped producer.
  Normal finish returns only an empty owner. The consuming exit drain clears
  the fixed fast slot, visits every queue (including full), detaches joined
  remote frees and force-appends `local_free` before deciding all-free; an
  all-free page is released PageMap removal, main bitmap clear, metadata
  retirement, slice release. The pass continues past a live page and then
  retains that page rather than queue-detaching or abandoning it.
  Supported owner-exit shapes are exactly these routes; every other shape,
  including allocation-time adoption beyond those named, scanning and
  concurrent routing, is absent:
  - Sole-page post-fast-slot handoffs (`page_count == 1`, target the only queue
    member, every other queue and direct slot empty): a full one-block arena
    singleton in `BIN_FULL` (false-collect, queue/count detach, unmapped
    abandon; only the raw failed-reclaim empty result releases it); a sole
    OS-aligned singleton in `BIN_FULL` (linked into `Heap::os_abandoned_pages`
    before unown, removed before terminal PageMap, alias, metadata and mapping
    release; a failed `munmap` retains its owner terminally); a medium page with
    `reserved > 1` and `used == 1` (force then false collect, publish the
    `pages_abandoned[bin]` bit and static `Heap::abandoned_count[bin]`; a
    nonempty result at the final free is retained, not reclaimed); full medium
    and full large `BIN_FULL` pages, full non-direct-small pages
    (`SMALL_SIZE_MAX < block_size`) and full direct-small pages
    (`block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, complete rounded
    direct-cache range, partial collector with the pinned one-head free-count
    lag), each stays unmapped while `free <= reserved / 8` and is reabandoned
    into its mapped bit/count on the first below-mostly-used free; and one
    sole nonfull medium or small page, which returns a linear
    `ProcessPageMapPostExitAccess` route (a direct small member derives its
    cache class from the rounded size and requires `reserved >= 16`).
  - Each full sole shape with one joined remote free: force collection leaves
    `used == reserved - 1` with the page still queued, false collection removes
    it and publishes the ordinary mapped bit/count into the mapped regular
    route, which accepts only client frees afterward.
  - Aggregate routes of two or more members, each proving its own class,
    rounded bin and exact span before any collection, then force, false
    collect, detach and unmapped-abandon every member before old-Theap/TLD
    teardown: full arena singletons, full OS singletons (private list starts
    empty, raw links retained until the exact free), full medium, full large,
    mixed medium/large, mixed singleton/regular, full non-direct-small, and
    homogeneous full direct-small. No raw member list is kept; every free
    re-resolves PageMap membership and claims the low owner bit before
    selecting the member's bitmap/count capability.
  - `abandon_mapped_regular_pages_to_process_route`, a general aggregate
    registry: every direct slot must equal the source queue-head image, and
    every queued page must be a nonfull small/medium/large arena page, a full
    medium/large `BIN_FULL` page, a full ordinary-bin small page, a live full
    arena singleton, or a live full OS singleton with an initially empty
    private list. It proves the doubly linked queue image, ports
    `_mi_theap_collect_retired(theap, true)`'s regular-bin release, then
    force-collects, releases all-free pages, false-collects, detaches and
    publishes each survivor as mapped, unmapped, or raw singleton. The count
    drops only after full PageMap, bitmap, metadata, slice release; a retired
    or force-empty traversal returns the ordinary drain, and a traversal that
    leaves one immediate-head nonfull medium returns the one-page handoff.
    The adapter continuations enter `_mi_deferred_free` before their first
    retirement or queue work. One synchronous same-page remote exception exists
    (`mi_free_block_mt` to `mi_free_try_collect_mt`): after B claims the low
    owner bit, a joined C appends exactly one distinct client to the remote
    head and gets no other authority.
  - `MainHeapThreadProcessPageExitMappedRegularRoute::adopt_into_later_main`
    (sole route only): a source-initially-nonfull mapped medium page, or a
    direct-small page with an immediate local free block, an exhausted fully
    committed scalar-extension shape, an exhausted prefix-covered extension, or
    an exhausted on-demand page-area-commit shape (the direct `_mi_os_commit` of
    the source byte range precedes the OS-page-count, free-list and capacity
    publication; an injected commit failure reabandons and permits a retry of
    only the same candidate). Full-origin pages stay client-free-only. Before
    consuming the route the target proves subprocess, configuration, PageMap
    root, static main Heap, arena, span and page identity; it then claims the
    bitmap/count member, collects abandoned and live state, reassociates the
    page, re-proves the span and appends it at the queue tail. Any other
    post-transfer failure is terminal.
  - Persistent native later and reactivated initial owners have one ordinary
    allocation-time exception (`static-main-selected-mapped-regular-abandoned-reclaim`
    in `port-map.toml`): after `collect_retired(false)`, a same-bin direct-small,
    medium or ordinary large request may use the matching static-main Heap's
    Relaxed abandoned count as an early skip (never a claim proof), then takes
    one paired PageMap access, claims the low-owner bitmap member, collects
    abandoned and live state, proves the span with `used < reserved`, and only
    then queue-tail inserts. A direct mapping/commit miss reabandons the page
    and gets the source's one false-mode retry; any other post-claim failure
    retains the root, range and page and closes that owner to later
    allocations. Explicit 16-byte C-facing requests use the aligned selector.
  A dropped unfinished engine, drain or route poisons its owner rather than
  fabricating cleanup. Absent: a live OS singleton with a pre-existing private
  list, foreign or malformed direct-cache state, process-global deferred
  callback registration and allocator re-entry, arena collection, statistics
  merge.
- **Check:** the `main_heap_page::tests::later_thread_*` regressions, one or
  more per route above (each with its sole-input rejection before mutation,
  stale direct-cache rejection and injected collector-failure retention), for
  example `later_thread_page_engine_uses_the_static_main_heap_and_in_place_arena_bitmap`,
  `later_thread_exit_force_collects_joined_remote_full_page_before_teardown`,
  `later_thread_exit_full_medium_route_reabandons_after_mostly_used_frees`,
  `later_thread_exit_mapped_regular_route_adopts_from_a_distinct_later_thread`,
  `later_thread_exit_mapped_medium_on_demand_reabandons_after_commit_failure_then_retries`,
  `later_thread_exit_mapped_regular_pages_route_releases_live_os_singleton_with_mapped_medium`;
  `process_page_map::tests::post_exit_access_can_transfer_to_one_new_long_page_lifecycle`;
  `runtime_lifecycle::tests::dormant_ticket_zero_page_owner_repeats_mixed_owner_exit_without_state_growth`
  and `..._repeats_mapped_regular_reclamation_without_state_growth` (eight
  cycles; state returns to baseline, metadata high-water plateaus);
  the `runtime_lifecycle::tests` regressions; the prefixed C
  `allocator --churn` lane (128 cycles) and opt-in `allocator --soak` lane
  (1,024 cycles); `unfinished_later_page_engine_poison_retains_the_attachment_and_process_map`.
- **Removal:** when evidence no longer needs the process-PageMap adapter's
  test/audit/non-x86 cases. Its absence from the selected x86 runtime does not
  authorize concurrent later-thread allocation routing, a public thread
  attachment API, process shutdown or default backend use.

### `CRABC-MI-HUGE-FREE-TRACKING-OWNERSHIP` — accepted retained cleanup bookkeeping

- **Port map:** `src/os.c`, `src/arena.c`
- **Source:** `src/arena.c:2167-2222` reserves and manages a huge prefix and
  frees it after an unpublished manage rejection; `src/os.c:845-853` attempts
  every huge primitive free without retaining errors; `src/init.c:566-579`
  invokes huge options before regular reservation and ignores either
  reservation error.
- **Rust contract:** `arena_huge::PendingHugeCleanup` retains every exact
  failed owner. Only a failed manage requires `HugeReleaseMetadata`, one bit
  per primitive page, allocated through the bound detached metadata owner
  outside the regular arena lock, with no page-count cap. Successful
  reservations and an unavailable first primitive allocate no tracking
  metadata. `HugeOsRawReleaseRetry` owns its tracker by value; a raw retry
  cannot repeat a successful unmap or source statistics.
- **Difference:** source C discards free errors. Rust can delay the first free
  pass if it cannot obtain tracking metadata (retaining the whole huge
  allocation), retains failed pages after that pass, and rejects further huge
  reservations until explicit cleanup consumes the pending owners. Regular
  reservations stay independent. After the last huge page is gone,
  `MetaRelease` retains an entry-rejected tracker for exact-owner retry and
  keeps post-claim failures terminal. No tracker reference gets a forged
  static lifetime.
- **Check:** `allocator-huge-reservation` compares 69 pinned policy values and
  runs ten native tests (missing metadata, a failed middle page, repeated raw
  failure, metadata-entry recursion after raw cleanup, huge-before-regular
  startup with the source overmap retry). Simulated primitive recorders do not
  prove hardware huge-page allocation.
- **Removal:** remove the bookkeeping only with another proved owner that
  preserves every live primitive page. Private native ownership and startup
  only; not C fault-recovery or diagnostic-callback parity.

### `CRABC-MI-OS-ON-DEMAND-ARENA-REFUSAL` — accepted pinned-upstream safety correction

- **Port map:** `src/arena.c:os-fallback-commit-on-demand-initially-committed-correction`
- **Upstream/Rust:** `src/arena.c:819-855` takes the OS fallback when
  `mi_option_disallow_arena_alloc=1` and `mi_option_page_commit_on_demand=1`:
  it reserves the block span uncommitted, commits only the aligned metadata
  prefix, then unconditionally sets `memid.initially_committed = true`
  (line 855). Rust: `os_page::OsAlignedPageClaim::allocate_on_demand_for_process`,
  `OsAlignedPageClaim::commit_initial_page_prefix`,
  `single_thread::PageAllocatorEngine::allocate_fresh_os_page`,
  `extend_on_demand_page_before_allocation`.
- **Scope:** native x86-64 process-bound metadata safety correction to a
  pinned upstream defect; no public API.
- **Difference:** C treats the uncommitted OS span as fully committed and
  `_mi_page_init` writes the first free-list link into `PROT_NONE`, faulting
  before the allocation returns. Rust leaves `MemoryId::initially_committed`
  false, commits the initial regular-page prefix while the private `Mapping`
  is retained, and only then publishes `Page::slice_pcommitted`, free-list
  links and capacity. After PageMap publication a later extension uses only
  `VmProcess::commit_direct_page_area` for its exclusive old-to-new prefix.
  Terminal OS release debits `slice_pcommitted * page_size` from committed
  accounting plus any successful secure tail reset (recorded once by the
  original claim token); fully committed suffix accounting already includes the
  tail. A failed initial or later commit publishes no capacity and follows the
  ordinary source fresh retry. The pinned-C OS-only setter and pre-constructor
  environment invocations fault (exit 139).
- **Ownership differences checked against C:** on a failed first metadata
  commit followed by a successful or failed terminal unmap of a fresh OS area,
  both sides produce the same statistics, warning order and mapped state; C's
  void `_mi_os_free` loses the retry capability, so Rust retains one
  unpublished (or published) claim and retries the exact range raw, with no
  second warning or statistics event. On the successful fresh OS singleton
  path both sides agree on mmap/commit counts and reserved/committed deltas.
  Rust keeps the ID uncommitted where C marks the area committed without a
  prefix protection call.
- **Check:** `meta::tests::process_metadata_incrementally_commits_and_releases_its_arena_page_prefix`
  (C arena geometry: 400 live 64-byte allocations give block 64, capacity 512,
  prefix 49,152, one arena), `process_metadata_os_only_on_demand_commits_before_publishing_capacity`,
  `process_metadata_failed_extension_keeps_the_old_page_and_selects_fresh`,
  `process_metadata_failed_initial_prefix_takes_source_retry_before_forced_collection`,
  `process_metadata_os_only_failed_initial_prefix_rolls_back_before_source_retry`,
  `process_metadata_os_only_failed_extension_selects_fresh_without_forging_commitment`;
  `allocator-fault-seam-inventory --os-publication-receiver` against the
  pinned-C receivers.
- **Removal:** when upstream fixes it, with a fresh setter/environment
  differential. Do not generalize it into another allocation policy.

### `CRABC-MI-LEGACY-OS-PAGE-PROCESSLESS-TRIM` — bounded unpaired caller difference

- **Port map:** `src/arena.c:os-aligned-singleton-metadata-page-map-and-release`, `src/os.c:retryable-os-singleton-release-and-rollback-ownership`
- **Upstream/Rust:** `src/arena.c:781-869` (fresh OS page area) and
  `src/os.c:240-294,303-430` (aligned mapping and free);
  `os_page::OsAlignedPageClaim::allocate` and `release`.
- **Difference:** the pinned-C fresh-area caller has a subprocess. When its
  192 KiB aligned middle retains an escaped 4 KiB suffix after a failed trim, C
  records a 192 KiB reserved increase, 64 KiB metadata commitment and two mmap
  calls, emits the fallback and failed-suffix warnings before final release,
  then warns on the failed terminal unmap before decreasing the statistics. The
  legacy Rust claim has no `VmProcess`: the same physical middle and suffix
  carry no subprocess statistics or warning callback. Its failed terminal unmap
  retains one claim for raw-only retry, and the escaped suffix is raw released.
  The paired `allocate_for_process` caller has the source accounting and
  warnings.
- **Check:** `compat/allocator/m2_legacy_os_page_trim_x86_64.py` builds the
  pinned-C fixture and compares eight mapping, MemoryId and cleanup relations;
  the strict comparison must fail on exactly `reserved_claim` (196608 vs 0),
  `committed_claim` (65536 vs 0) and `mmap_claim` (2 vs 0), with three C
  warning bodies in order, no Rust warning, zero final deltas and successful
  raw cleanup of both live ranges.

### `CRABC-MI-ARENA-RESERVATION-NO-THP` — accepted musl-defaults residency divergence

- **Port map:** `src/prim/unix/prim.c:arena-reservation-thp-advice`
- **Upstream/Rust:** `src/prim/unix/prim.c:461-484` (`unix_mmap`) advises a
  regular mapping `MADV_HUGEPAGE` when the caller allows large pages,
  `allow_thp` is enabled and size and alignment are large-page multiples. An
  arena reservation (`src/arena.c:1886-1896`, `mi_reserve_os_memory_ex2` through
  `_mi_os_alloc_aligned`) meets these whenever it is committed.
  `os::Mapping::map_unix_policy` keeps that branch for every caller except
  `ThpAdvice::Arena`, passed by `NormalOsAllocation::allocate_arena_base_for_process`
  for `arena_owned::ProcessArenaBacking::reserve_one_locked` and
  `process_arena::ProcessSharedArenaStorage::reserve_cold_regular_os_arena_for_process`.
- **Scope:** native x86-64 memory-residency policy; no allocation, ABI,
  diagnostics or invalid-use difference.
- **Difference:** at default `allow_thp=1` without `allow_large_os_pages`, a
  regular arena reservation, committed or not, is advised `MADV_NOHUGEPAGE`
  instead of `MADV_HUGEPAGE` (or, uncommitted, instead of no advice).
  `allow_thp=0` still disables THP as upstream does; `allow_thp=2` and large OS
  pages request huge pages and keep the source advice, as do non-arena mappings
  (page map, OS page claims, huge pages). The advice is best-effort like the
  source's: errors are ignored and the mapping is never marked large.
- **Why:** the musl-defaults contract keeps the process THP policy as musl
  leaves it and has the allocator's own arenas opt out, so first-allocation
  residency is musl-like. Under THP `always` a 1 GiB arena faults in 2 MiB pages
  on first touch even without `MADV_HUGEPAGE`, so only an explicit opt-out gives
  small-page residency; process-wide `PR_SET_THP_DISABLE` would also change the
  application's own mappings.
- **Check:** `arena::owned::tests::emit_native_arena_lifecycle_trace` scenario
  23 with the pinned-C fixture `compat/allocator/m2_arena_lifecycle_x86_64.c`
  records each reservation's advice for `allow_thp` 1/2/0 under eager and
  on-demand commit; `m2_arena_lifecycle_x86_64.py` maps only the `allow_thp=1`
  cells to `MADV_NOHUGEPAGE` and requires every other field to equal C.
  `os::tests::arena_reservation_declines_thp_only_at_the_default_options` and
  `process_arena::tests::process_bound_regular_first_arena_declines_thp_at_the_default_options`
  cover the option matrix. The qualified integrated report's startup and churn
  rows are the performance gate (`divergence-evidence-v3.5.0.json`).
- **Removal:** if the musl-defaults contract changes or a qualified report
  shows the opt-out costs a CPU row its gate.

### `CRABC-MI-SHARED-MAIN-NO-PAGE-LIFECYCLE` — accepted incomplete lifecycle boundary

- **Port map:** `src/init.c:later-thread-process-static-main-heap-no-page-attachment`
- **Upstream/Rust:** the later-thread `_mi_thread_init_with_heap(mi_heap_main())`
  and `_mi_thread_done` branch (`src/init.c:236-282,305-360,377-421,448-481`,
  `src/theap.c:228-306,414-449`); `main_heap_thread::MainHeapThreadAttachment`
  and the borrow-tied `main_theap::MainStaticHeapLease`.
- **Scope:** private incomplete lifecycle; no C ABI surface.
- **Difference:** the path starts only after the ticket-zero
  `MainStaticTheapAttachment` is live. A later owner receives a metadata TLD and
  Theap, links its Theap through a short lock-serialized projection of the
  static main Heap, and publishes default before the main Heap's fixed fast
  slot. Unlike the one-owner static branch, shared heap-list contention waits
  on the private futex lock. The direct finish is no-page: it retains a nonempty
  page count, nonempty dynamic backing or a root/list mismatch rather than
  inventing a collect/abandon/release path (the page-bearing variants are the
  later-main entry). A successful finish clears fast, resets default/cached,
  detaches the shared heap list before its TLD list, frees metadata and
  releases the main-attachment gate. A fallible lock or metadata error after
  source mutation retains the concrete owner instead of claiming teardown.
  The private libc bridge uses only this no-page entry/finish path.
- **Check:** `main_heap_thread::tests::later_thread_uses_main_fast_slot_and_retires_before_main_storage`,
  `later_thread_rejects_a_foreign_root_before_consuming_a_ticket`,
  `overlapping_later_threads_link_distinct_metadata_theaps_to_one_main_heap`.
  Exact C comparison is inapplicable without a page-bearing general lifecycle.
- **Removal:** when a shared PageMap/arena and remote-producer lifetime support
  the remaining `_mi_theap_collect_abandon` paths and the crabc pthread/TLS
  integration invokes that lifecycle. It does not authorize a raw shared-Heap
  pointer, a user-visible attachment API or page-bearing routing.

### `CRABC-MI-RUNTIME-NO-PAGE-PTHREAD-BRIDGE` — accepted private runtime bridge

- **Port map:** `src/init.c:private-no-page-process-pthread-runtime-lifecycle`
- **Upstream/Rust:** the same no-page initialization and finish boundary
  (`src/init.c:236-282,305-360,377-421,448-481`, `src/theap.c:228-306,414-449`,
  `src/threadlocal.c:205-214`) with musl 1.2.6 `src/process/fork.c` as the libc
  fork-order oracle; `runtime_lifecycle.rs`, its hidden `__crabc_runtime`
  boundary and callers in `libc/src/c_abi.rs`.
- **Scope:** private lifecycle control, not allocator routing; no installed C
  symbol, public API or pthread key. The C backend's private key stays outside
  the 128-key application capacity.
- **Difference:** `__libc_start_main` retains the ticket-zero
  `ProcessMainThread` and the main-thread-minted `MainStaticHeapLease` after
  initial TLS/guard setup and before constructors. A pthread child attaches
  before user code and its parent waits for a success/failure handshake; a
  failed attach reaches no user code and `pthread_create` returns `EAGAIN`.
  Normal return, `pthread_exit` and cancellation finish after libc cleanup and
  TSD destructors. Main-thread teardown is absent. Fork order is public
  prepare, bridge prepare, raw fork, bridge child/parent, public child/parent.
  The bridge gate preserves copied state only when the original ticket-zero
  thread-pointer image has no live or retained later bridge owner and its page
  owner is cold or dormant (`AwaitingFreshPage` or `DormantExistingArena`) with
  no live native client or PageMap operation; that child resets the gate and may
  reactivate the dormant owner or attach a fresh pthread. An unprepared
  raw-fork child, a foreign caller, or a child copied from a live, parked,
  retained or nonquiescent owner disables the bridge. No inherited lock, root,
  pointer, list or page state is repaired.
- **Check:** the `runtime_lifecycle::tests` regressions (attach/finish churn,
  process-isolated quiescent fork children, conservative disablement with a
  live bridge owner, the dormant-page predicate);
  `crabc-mimalloc/tests/native_post_exit_terminal_proof_fork_gate.rs` (fork
  while B holds A's terminal post-exit proof: the child disables, the parent
  keeps both admission claims until B finishes);
  `tests/fixtures/pthread_atfork_test.c`;
  `tests/fixtures/pthread_create_join_tls_regression_test.c` and
  `tests/fixtures/static_pthread_tls_test.c`; `scripts/build_owned_sysroot.py`
  and `scripts/crabc_sysroot.py` audit the post-LTO `THREAD_LIFECYCLE` TLSIE
  root and final shared TPREL form.
- **Removal:** only while the libc-facing bridge stays no-page and private;
  child recovery for a live or retained owner needs its own lock/root/page
  proof. It does not authorize allocation interposition, a generic callback
  registry, public lifecycle attachment or general fork recovery.

### `CRABC-MI-RUNTIME-PAGE-OWNER-NORMAL-FINISH-WITNESS` — accepted bounded evidence path

- **Port map:** `src/init.c:private-lazy-ticket-zero-runtime-first-arena-page-owner`
- **Upstream/Rust:** later-main `_mi_thread_done` / `_mi_thread_theaps_done`
  ordering (`src/init.c:377-421,448-481`), the dynamic regular-slot clear and
  `MI_ABANDON` traversal (`src/threadlocal.c:205-214`, `src/theap.c:89-152`)
  and the post-exit free/reclaim tails (`src/free.c:372-418,479-515`,
  `src/arena.c:1304-1424`); `runtime_lifecycle::{ThreadLifecycleSlot,
  ThreadLifecyclePageOwner, ThreadLifecyclePreparedPageOwner,
  CurrentThreadPageOwnerSession, PreparedOwnerExitClients,
  begin_current_thread_page_owner_session, install_current_thread_page_owner,
  finish_current_thread_all_free_page_owner_after_user_destructors,
  finish_current_thread_after_user_destructors}`,
  `RuntimePersistentPageEngine::begin_thread_exit_drain` and the hidden
  aggregate, sole-medium and direct-small `*_through_normal_finish` witnesses.
- **Scope:** pointer-private route evidence and stability evidence only; not
  the libc pthread bridge, allocator routing or a public post-exit capability.
- **Difference:** a prepared mixed-aggregate, sole-medium or direct-small
  reclaim workload suspends its exact A-side engine into compiler TLS before
  ordinary post-destructor finish. The dispatcher resumes only that matching
  owner, clears the source fast slot, and runs the aggregate traversal (or the
  cache-validating `abandon_mapped_small_or_medium_to_process_route` drain for
  direct small); it adds no class- or block-count-specific owner-exit entry.
  - A fixed preparation ledger mints every A-side allocation as one capability
    that must be freed locally, joined-published before exit, or moved exactly
    once into the typed route; omitted, duplicate or over-capacity sets reject
    before the engine suspends. `CurrentThreadPageOwnerSession` pairs an inline
    ledger with one generation-checked parked engine and grows a private
    metadata-backed extension; `prepare_sequential_exit` moves every live entry
    (and the extension) with the opaque route, leaving source-published entries
    for source collection.
  - A session with no locally live entry takes the all-free drain and teardown
    before its admission releases; a live session stays outside the no-page
    finalizer. The ledger records an immediate local-head fact only while A
    holds the engine exclusively, so B attempts aggregate final-member adoption
    only with that fact and otherwise frees sequentially with no speculative
    claim.
  - The resulting route owns A's client identities and admission until fresh B
    terminally frees, or adopts and drains, the exact route; ticket zero
    settles only after B returns its typed proof. Rejected, retained, poisoned
    or mismatched outcomes are terminal and never invoke A's no-page finalizer.
    The exact-client façade is `#[cfg(test)]` only; the C ABI stays nine
    prefixed test symbols with no client address, finalizer or reclamation
    exposure.
- **Check:** the `runtime_lifecycle::tests` regressions (mixed route paused
  after transfer; sole-medium and direct-small routes through the same
  dispatcher with reactivation; eight normal-finish/reclaim cycles; a shuffled
  eight-epoch schedule of the pointer-private routes),
  the `main_heap_page` regressions for
  retired-page release and release failure after PageMap unregister,
  `later_thread_exit_post_detach_aggregate_failure_cannot_finish_as_all_free`,
  `native_post_exit_claimed_remote_producers.rs`,
  `native_post_exit_claim_page_map_lifetime.rs`,
  `native_source_selected_medium_owner_exit.rs`,
  `native_post_exit_split_releaser_lifecycle.rs`,
  `native_post_exit_terminal_proof_fork_gate`, `native_post_exit_with_local_session`,
  and the C witnesses `native_mimalloc_owner_exit_realloc` and
  `native_terminal_completion_live_remote_free`. Exact frees stay serialized;
  this is not a concurrent route or general pointer-routing claim.
- **Removal:** when a general page-bearing pthread lifecycle, concurrent
  routing, broad abandonment/reclamation and libc allocation routing are
  proved. It does not make this witness C lifecycle wiring, backend selection,
  fork recovery or an allocator API; the nondefault native shadow has its own
  route evidence under
  `nondefault-crabc-libc-native-mimalloc-shadow-ordinary-boundary`.

### `CRABC-MI-AUTOMATIC-PTHREAD-DESTRUCTOR-C-ORACLE-ONLY` — accepted evidence boundary

- **Port map:** `src/init.c:private-no-page-process-pthread-runtime-lifecycle`
- **Upstream/Rust:** `src/init.c:504-511,426-477`, `src/prim/unix/prim.c:1011-1040`,
  `src/threadlocal.c:205-214`, `src/theap.c:97-152` and the page/arena/free/map
  tails, contrasted with `dynamic_theap::DynamicTheapAttachment` and its typed
  owner-exit routes.
- **Scope:** native x86-64 private C-oracle evidence only; no C ABI surface and
  no Rust/C differential.
- **Difference:** the pinned C worker returns naturally with no explicit
  `mi_thread_done()` or `pthread_exit()`; mimalloc's private pthread key is
  associated with its initialized default Theap, and the key destructor invokes
  `_mi_thread_done`, leaving the nonfull medium page mapped-abandoned,
  detached and available only to the consumer-free tail. Rust has only
  explicit typed owner-exit models and no crabc pthread/TLS callback or
  detached post-exit owner that can carry live worker pages across that
  boundary, so this establishes neither Rust callback parity nor destructor
  ordering. A second C oracle keeps cancellation disabled while allocating,
  enables deferred cancellation before a non-cancellation-point gate, and takes
  one `pthread_cancel()` at one `pthread_testcancel()`; its `PTHREAD_CANCELED`
  join result and post-join page state show this C path only.
- **Check:** `x86_64_automatic_pthread_destructor_evidence.py` (gate
  `native-pinned-c-automatic-pthread-destructor`) and
  `x86_64_cancellation_pthread_destructor_evidence.py` (gate
  `native-pinned-c-cancel-testcancel-automatic-destructor`).
- **Removal:** when a private crabc lifecycle bridge invokes the Rust allocator
  in source order at thread exit and a Rust/C boundary proof covers it. It does
  not authorize a fake pthread callback, a `Send` detached attachment or
  general destructor-ordering claims.

### `CRABC-MI-PROCESS-DONE-PTHREAD-KEY-C-ORACLE-ONLY` — accepted late-worker evidence boundary

- **Port map:** `src/init.c:process-done-subprocess-destroy-order`
- **Upstream/Rust:** `include/mimalloc/atomic.h:18-20`,
  `src/prim/unix/prim.c:1011-1040`, `src/init.c:305-360,595-648`,
  `src/prim/prim-tls.c:211-250`, `src/free.c:223-255`, contrasted with the x86
  bridge in `libc/src/c_abi/x86_64/native_mimalloc_lifecycle.rs` and its
  compiler-TLS persistent owner.
- **Scope:** native x86-64 private C-oracle evidence using the declared
  `mi_process_done()` in one controlled fixture; no public API.
- **Difference:** Linux enables source `MI_USE_PTHREADS` independently of
  `MI_TLS_MODEL_LOCAL`. `mi_process_done()` resets the cached Theap and deletes
  the private auto-done key. A worker created afterwards still runs
  `_mi_thread_init`, creates its default Theap and allocates two medium
  clients, but `_mi_prim_thread_associate_default_theap` sees the invalid key,
  so natural return does not invoke `_mi_thread_done`: after join the page
  stays owned by the worker Theap and its TLD identity stays live, and two
  main-thread `mi_free` calls publish remote frees with `used` unchanged. The
  Rust bridge therefore cannot skip its explicit finish after a logical
  process-done flag: libc reclaims the worker's compiler TLS while the Rust
  owner and admission still require explicit teardown.
- **Check:** `x86_64_process_done_pthread_key_evidence.py` (gate
  `native-pinned-c-process-done-pthread-key`; 31 address-independent values).
- **Removal:** when a native process-shutdown owner has a typed, lifetime-safe
  mapping for late workers, without dropping a pinned compiler-TLS owner or
  inventing a post-shutdown worker rejection policy.

### `CRABC-MI-DYNAMIC-THEAP-INVALID-OWNER` — accepted private lifecycle boundary

- **Port map:** `src/theap.c:private-current-thread-regular-key-dynamic-theap-attachment`
- **Upstream/Rust:** `src/threadlocal.c:23-214`, `src/init.c:236-360,377-421,448-481`,
  `src/theap.c:228-306,357-369,414-449`, `src/heap.c:60-100`;
  `dynamic_theap::DynamicTheapAttachment`, `DynamicTheapPageSession` and
  `single_thread::PageAllocatorEngine`.
- **Scope:** cfg(test) isolated dynamic-owner model for private invalid-owner
  and incomplete dynamic-thread lifecycle handling; fixed x86-64 has no
  production caller for these paths. No C ABI surface or valid allocation-trace
  differential.
- **Difference (ownership and errors):** the bounded owner uses fallible Rust
  private locks and typed metadata capabilities where valid C initialization
  has uncontended locks and no capability errors.
  - Before Theap/list publication, a backing, key or Theap allocation failure
    tears down the empty backing/TLD state and rejects without a live-count
    leak. Begin admits only the canonical empty cached predecessor, then
    follows the source regular-slot store, cached-root store and dynamic-Theap
    reference `1 -> 2`; a foreign cached root is a pre-ticket rejection. After
    list publication, any lock/list, backing, metadata or cached-root/reference
    failure retains the concrete poisoned owner with every still-known TLD
    registration, allocation, backing, binding and lease, with no invented
    rollback.
  - Teardown validates the cached pointer and refcount before mutation, clears
    the regular heap-key entry, then the compiler-TLS backing root, stores the
    canonical empty cached root, and transitions `2 -> 1` before list detach.
    The dynamic TLD releases its live count before identity invalidation and
    private-lock quiescence. A metadata free ambiguity retains only the
    capabilities still known valid. Mismatch and nonzero-page checks are
    pre-mutation.
  - Two retryable outer states exist. `AwaitingBackingRelease` (only after the
    heap-key entry and binding marker clear, and only for a
    same-current-thread `MetaRelease::Malloc` pre-claim rejection) retains the
    compiler-TLS backing root, key lease, TLD, Theap, Heap binding, cached
    reference and any sealed engine image while ordinary allocation, free,
    collection and remote-producer entry stay suspended; its sole re-entry
    resumes backing release. `AwaitingKeyRelease` retains only the linear lease
    until its pre-mutation final regular-key release succeeds. Every other
    Malloc terminal, impossible-owner mismatch or later teardown/page/list error
    is terminal; a wrong-thread call is rejected.
  - Released capabilities cannot project typed images. The test-only ordinary
    constructor stores the source abandoning `true`/`2` profile and rejects
    page-session construction; the test-only non-abandoning constructor stores
    the `false`/`-1` profile before Release heap publication and instantiates
    the shared page engine (a separate ordinary fixture validates the `true`/`2`
    image to build `MI_ABANDON` aggregate shapes). None of these dynamic
    attachment paths has a production caller in the fixed x86-64 profile. An
    unfinished engine drop, retained collection poison or pending OS unmap
    failure latches the attachment terminally and keeps the page/map/resource
    state.
  - The first dynamic arena page proves the arena's subprocess equals the
    attachment's, then lazily owns one BCHUNK-aligned `mi_arena_pages_t` image
    bound to the Heap and arena slot, with an ordinary page bitmap disjoint from
    `Arena::pages_main`. Image allocation failure before slot publication is
    retryable; later lock/unlock/free ambiguity retains the known terminal
    owner. A nonempty image is rejected before root/list/key mutation.
    `DynamicMappedPageHandoff` moves a mapped regular arena page through
    heap-local `pages_abandoned[bin]` and `Heap::abandoned_count`, then
    reclaims it or consumes one live client through the source mapped
    same-origin remote-free branch; the all-free branch unregisters the span,
    clears the ordinary bit, retires metadata and releases slices.
- **Difference (supported owner-exit shapes):** after the regular backing is
  cleared, `DrainingPages` first force-collects an already-retired all-free
  regular page; its live-page transitions are exactly these (anything else,
  including reclaim, adoption, requeue, scanning, allocation-time use, producers
  and concurrent routing, is absent, and a collection failure retains the
  drain):
  - A full one-block arena or OS-aligned singleton (`reserved == used == 1`) is
    false-collected, detached from `BIN_FULL`, unmapped-abandoned and retained
    until its exact client free takes the failed-reclaim all-free release. The
    OS form is `MemoryKind::Os`, links into this Heap's `os_abandoned_pages`
    before unown and is removed before clipped PageMap, alias, metadata and
    mapping release; a failed `munmap` retains the owner terminally.
  - `DynamicThreadExitDrain::abandon_*` aggregates of two or more members that
    each prove their own class, rounded bin, `reserved`/`used` geometry, zero
    retirement countdown, empty local free list, exact span and matching
    dynamic bitmap/count capability before any collection, then force, false
    collect, detach and unmapped-abandon every member: `full_singleton_pages`
    (arena), `full_os_singleton_pages` (initially empty private list),
    `full_medium_pages`, `full_large_pages`, `full_medium_or_large_pages`,
    `full_singleton_or_regular_pages`, `full_non_direct_small_pages` and
    `full_direct_small_pages` (rounded direct-cache range names the ordinary
    queue head; a member stays unmapped through `reserved / 8 + 1` frees).
    The route keeps only the drain and a count; each canonical free
    re-resolves PageMap, claims the low owner bit, selects the member's own
    capability and tail, releases only that member in PageMap, ordinary bit,
    metadata, slice order, and the last free returns the empty drain.
  - Sole full handoffs (`abandon_full_medium`, `abandon_full_large`,
    `abandon_full_non_direct_small`, `abandon_full_direct_small`) stay unmapped
    through the source mostly-used prefix and publish the dynamic pair only
    after the first free beyond `reserved / 8` (direct small: the retained
    partial head delays this by one free). The `*_after_force_collect_to_mapped`
    variants take one already-joined remote free so the page begins mapped.
  - Nonfull handoffs: `DynamicThreadExitMappedOneBlockHandoff`
    (`abandon_mapped_one_block`, `_large`, `_non_direct_small`, `_direct_small`;
    `reserved > 1`, `used == 1`), `abandon_mapped_two_block_medium` (`used == 2`;
    the first free yields `UnownedMapped`, the last `Empty`),
    `abandon_mapped_medium_pair` (two distinct-bin pages), and
    `abandon_nonfull_medium_pages_distinct_bins`. Stale direct-small ranges
    reject before collection; source queue removal clears a valid range before
    page-count detach.
  Raw `free_unmapped_after_failed_reclaim` ports expected-head unown, conflict
  collection and the terminal-empty/reabandon/unown choice; production ordinary
  dynamic allocation stays sealed.
- **Check:** the `dynamic_theap::tests` regressions, for example
  `post_list_publication_backing_failure_returns_a_retained_poisoned_owner`,
  `regular_slot_then_cached_publication_increments_the_dynamic_theap_reference`,
  `foreign_cached_root_rejects_before_later_ticket_or_backing_allocation`,
  `cached_root_is_empty_and_reference_is_one_before_a_terminal_heap_detach_failure`,
  `dynamic_theap_backing_release_recursive_entry_retains_outer_lifecycle_for_retry`,
  `key_release_lock_failure_keeps_only_the_linear_lease_for_retry`,
  `non_abandoning_dynamic_page_session_allocates_on_its_exact_theap_and_pinned_heap`,
  `dynamic_mapped_regular_remote_free_reclaims_to_its_same_origin`,
  `dynamic_arena_pages_*`; the `dynamic_thread_exit_*` family, one group per
  route above, each with the happy path, sole-input or wrong-class rejection
  before mutation, and injected collection-failure retention (for example
  `dynamic_thread_exit_full_medium_pages_route_reabandons_each_distinct_bin_page_then_releases`,
  `dynamic_thread_exit_os_aligned_singleton_handoff_retains_failed_unmap_terminally`,
  `dynamic_thread_exit_mapped_two_block_large_handoff_retains_post_force_shape_mismatch`);
  `abandoned::tests::unmapped_*` and
  `failed_expected_head_unown_collects_new_publication_without_a_second_reclaim`;
  `remote_free::tests::abandoned_partly_collection_*`;
  `meta::tests::released_capability_cannot_project_any_safe_typed_image`,
  `tls_projection_cannot_be_reinterpreted_as_dynamic_arena_or_bitmap_image`;
  `tld::tests::dynamic_teardown_releases_registration_before_busy_lock_poison`.
  A native x86-64 C/Rust differential compares 51 address-independent values
  for two same-size full `BIN_FULL` arena singletons (request 524289, 589824-byte
  blocks, nine slices per member) with real `mi_thread_done()` in the C worker
  and sequential consumer frees; Rust is the typed current-thread model only.
- **Removal:** when a complete dynamic heap/Theap, cached-root switching,
  private-lock retry, public routing, abandonment, pthread/process lifecycle
  and allocator integration design can distinguish all failures and reach full
  source shutdown. It does not authorize pointer reconstruction, lock stealing,
  arbitrary predecessor restoration, implicit lease drop, post-publication
  rollback or a false registration/key decrement.

### `CRABC-MI-RANDOM-WEAK-EXPANSION` — accepted degraded-entropy substitution

- **Port map:** `src/random.c`, `src/random.c:original-chacha-context-state-and-output-contract`
- **Upstream/Rust:** `src/random.c:_mi_os_random_weak` and `mi_random_init_ex`;
  `random::WeakObservations::expand_into`.
- **Scope:** allocator random-state behavior only after `getrandom` errors or
  short reads; no C ABI surface, not part of the deterministic traces.
- **Difference:** pinned C repeatedly applies its local `_mi_random_shuffle`
  core to ASLR/time material. The project crypto policy forbids maintaining
  that PRNG core. Rust serializes the same degraded context-address, time and
  identity observations plus the initializer's fixed-zero extra seed, then asks
  RustCrypto `ChaCha20LegacyCore` for one domain-separated block to form the
  weak key. It preserves the source continuation, weak flag, reinitialization
  and original-ChaCha context lifecycle, and adds no entropy.
- **Check:** `random::tests::weak_observations_have_a_dependency_owned_deterministic_expansion`
  fixes the replacement vector; the entropy-fault regression covers error
  continuation and weak reinitialization;
  `normal_entropy_initialization_treats_a_short_fill_as_weak` fixes the
  short-read (`Ok(false)`) classification. The C/Rust M1 state trace compares
  every non-weak-key state fact (split, zero-result retry, forced weak
  initialization, strong reinit no-op). Exact weak-key/output comparison is
  inapplicable: both paths consume ASLR/time and use different cores.
  Native x86 `ProcessMainRuntimeStartupTail` owns warning dispatch and weak
  default/metadata Theap reinitialization. The existing
  `runtime_lifecycle::tests::entropy_failure_at_runtime_startup_is_reseeded_before_activation`
  regression checks that both states become strong after transient initial
  entropy failures. This runtime check is separate from the primitive state
  trace.
- **Removal:** when pinned upstream changes its weak path or the project crypto
  boundary changes; it does not authorize a local replacement core.

### `CRABC-MI-INVALID-PROGRAM-ERROR-SITES` — accepted invalid-use handling

- **Port map:** `src/page.c:invalid-program-error-sites`

Three release-live pinned `_mi_error_message` sites are reached only by an
invalid program, and the Rust port responds more strictly than C instead of
reproducing its continuation:

- `src/page.c:164-172` (`_mi_page_thread_free_collect`): a cross-thread free
  list longer than the page capacity, or longer than its `used` count, reports
  `EFAULT` and returns, leaking the detached list and continuing to allocate
  from the page. The Rust `remote_free` collectors return
  `RemoteFreeError::TooManyRemoteBlocks` or `UsedCountUnderflow`, and the page
  engine poisons that collection and retains the page, so no block of a list
  known to be corrupt is handed out.
- `src/arena.c:1455-1478` (`_mi_arenas_free`): freeing from an invalid arena,
  an invalid arena block, or an already-free arena block. Unreachable in Rust:
  every free first resolves its page through the PageMap and releases only an
  exact claim the engine retains, and crabc libc terminates on a pointer the
  PageMap does not own.

Only a valid program's behavior is a parity requirement, so no valid-program
differential applies; the M7 gate's `m7.callbacks` blocker records these sites
as not applicable. Remove only if the project decides to reproduce C's
invalid-use continuation.

### `CRABC-MI-STARTUP-PAGE-MAP-FAILURE` — accepted diagnostics difference

- **Port map:** `src/page-map.c:startup-page-map-failure`

Pinned `mi_page_map_init_once` (`src/page-map.c:302-305`) reports "unable to
reserve virtual memory for the page map" when its reservation cannot be
mapped, and `mi_process_init_once` ignores the result (`src/init.c:549`): the
process starts and every later allocation fails with ENOMEM. The Rust runtime
ports that outcome (`runtime_lifecycle::PROCESS_PAGE_MAP_UNAVAILABLE`): the
report is emitted at the same mapping failure in `PageMap::initialize`, the
loader tail flushes it, startup succeeds, the initial thread reports `unable to
allocate memory` for each request's generic size, and each worker's deferred
attachment reports C's thread-local-data failure on every allocation.

The retained state has no page map, arena or page engine, so Rust does not
repeat C's attempts to allocate a fresh page that cannot be registered and
emits none of C's per-allocation warnings. At startup both sides warn three
times (two failed OS allocations and the fallback to over-allocation of
`_mi_os_alloc_aligned`). Per allocation C then warns once per failed page-map
commit (`unable to commit the allocation page-map on-demand`) in each
fresh-page attempt; a small request makes three attempts (the counted queue
search, `mi_find_page` in `mi_malloc_generic_fallback`, and the forced retry).
The compared trace (error reports, results, errno) is identical. Warnings are
advisory: they carry no errno, reach no error handler and are capped by
`max_warnings`.

Check: `python3 compat/allocator/x86_64_m7_gate.py --offline --page-map-differential`.
Remove only by keeping an empty page map in which allocation can be attempted
and fail, which would make an arena and page engine run without a page map.

### `CRABC-MI-FORCED-COLLECTION-OS-RELEASE-OWNER` — accepted private failure-retention boundary

Pinned `src/theap.c:mi_theap_collect_ex(MI_FORCE)` visits all owned queues
before arena collection; `src/page.c:mi_malloc_generic_fallback` then retries
allocation. `PageAllocatorEngine::collect_all_pages_for_allocation_retry` ports
that post-prepass page/backing transition. The retained Rust prepass also has an
existing non-abandoning full-page scan, so an exact whole-source collection
sequence is not claimed; generic callback administration and statistics merging
are separate.

Unlike C's void, best-effort OS free, Rust retains a failed mapping release in
`pending_os_release`. The full-queue prepass and forced traversal both stop
when this slot becomes occupied: the OOM allocation returns no block and the
next page keeps its queue, PageMap, metadata and remote head. `release_page`
rejects a second OS release before queue mutation while that owner exists. A
later explicit collection retries the parked mapping before visiting another
page; a repeated failure preserves both owners. Ordinary arena operations are
unchanged. This is ownership-safety strengthening, not C unmap-error parity.

Check: `single_thread::tests::generic_forced_collection_stops_at_one_pending_os_release`
(two remotely emptied OS singletons in both huge and full queues, paired
release failures, preservation of the next registered page, explicit retry).

### `CRABC-MI-OS-PUBLICATION-ROLLBACK-OWNER` — accepted private provenance-failure retention

- **Port map:** `src/arena.c:os-aligned-singleton-metadata-page-map-and-release`

Pinned `src/arena.c:951-1120` initializes primary metadata, Release-publishes
its aligned aliases and registers the clipped PageMap span; a failed
registration calls `mi_arenas_page_free_prim`. The Rust
`PageAllocatorEngine::rollback_fresh_os_aligned` reverses these publications
before releasing the still-private `OsAlignedPageClaim`. An ordinary failed
unmap retains that exact claim for explicit retry.

An alias ownership mismatch, rejected primary retirement or rejected map
unregistration is outside the source's valid private-page precondition. Rust
retains the exact claim terminally; its release state rejects further release
attempts without a syscall, so a retry cannot unmap unresolved metadata, and
ownership is never silently dropped or treated as an ordinary detached mapping.
This is not C failure parity or general metadata recovery.

Check: `single_thread::tests::os_claim_*` (legal PageMap-allocation and
rollback-unmap failures versus terminal alias provenance refusal), and the
direct fresh OS page receiver for a failed PageMap registration after both
page commits: pinned C and Rust return no Page, unmap the same 256 KiB OS area,
leave one 64 KiB rollback submap and record the same reserved, committed,
commit-call and mmap-call deltas, with the same four warning fragments. The
process-owned Rust map releases its private lock before invoking the registered
callback so callback reentry cannot deadlock.

## Entry requirements

Each entry must state:

- a stable difference identifier and status (`observed`, `pending`, `accepted`,
  or `rejected`);
- the upstream source path/function or type and the Rust module/function;
- whether the difference affects engine semantics, C ABI integration,
  configuration, performance, diagnostics, or invalid-use handling;
- a minimal reproducer and exact-C differential result for valid programs;
- its written design note, when it is algorithmic or behavioral;
- performance and memory evidence for the selected native target;
- the decision and conditions that would remove the difference; and
- the port-map row or rows that carry it, as one line
  ``- **Port map:** `upstream:name`, ...`` (a unit row is its bare
  `upstream` path), unless a carrying row's `intentional_difference` names
  the identifier.

`crabc-libc` ownership of C ABI and `errno`, and direct crabc lifecycle wiring
for threads and fork, are integration boundaries rather than implicit
differences; they still require tests. Invalid use must not be copied merely to
reproduce C memory unsafety; document a deliberate safe difference here if one
is necessary.

An entry cannot replace the exact pinned C implementation as a differential
oracle or justify a runtime fallback. Accepted differences require the design,
differential and performance evidence specified in
[`docs/design/allocator.md`](../../docs/design/allocator.md).
