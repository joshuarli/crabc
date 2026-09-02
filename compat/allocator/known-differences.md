# Pinned mimalloc Rust/C known differences

This is the durable register of observable or algorithmic differences between
the incomplete `crabc-mimalloc` Rust port and exact pinned mimalloc v3.5.0 C.
The source pin is defined in
[`crabc-mimalloc/UPSTREAM.md`](../../crabc-mimalloc/UPSTREAM.md).

## Current status

No successful ordinary pinned-mimalloc engine allocation-trace difference is
recorded. One public-C ABI backend known red and one test-only native x86-64
on-demand failed-direct-commit divergence are recorded below. The former are
not pinned-engine parity claims; they are deliberately visible in the paired
ordinary/native libc artifact report. The latter is deliberately excluded from
the C/Rust trace equivalence. The current Rust crate contains source-mapped
foundations plus a private, explicit single-thread ordinary-allocation
lifecycle across small, medium, large, and singleton pages. Its small path has
exact address-independent trace parity with pinned C v3.5.0, and the AArch64
production record has a separate 51-key exact differential slice covering
page-kind, calloc, realloc, aligned/offset-aligned, usable-size, preservation,
and failure. Native x86-64 evidence separately extends that private trace to
75 keys with fixed no-padding in-place expansion and checked `mi_recalloc`; it is not AArch64 production
evidence, whose expansion revalidation remains pending. This includes live
arena-backed alignment through 64 KiB and separately
owned OS-aligned singleton mappings below 256 MiB. The lifecycle is not
exported and does not imply parity for the absent process/TLS, general remote-free routing,
teardown, purge, or public-API regions. The bounded ticket-zero and later-main
page owners now delegate ordinary reallocations to that same live engine; only
the ticket-zero null case may activate its completed first-arena policy. This
does not create a public allocator route. The private regular-TLS and generic
subprocess-attached/no-theap TLD owners record one internal recovery limitation
in the source map:
`MetaAllocator::free` may report an error after consuming a capability. The
regular owner clears its dynamic root, while the TLD owner has already
invalidated `thread_id`; each terminally poisons rather than retaining a
capability that could name freed storage. The selected `MetaRelease` boundary
makes that distinction explicit: its exact Malloc owner is terminal diagnostic
state rather than a false retry token, while its normal anonymous `Mapping`
owner remains live and is returned after a failed `munmap`. It intentionally
does not represent no-free, arena, huge, or remap source branches. This state
is not a valid C-program observable difference and has no C differential
entry; an arena-release result may be added only when it can prove retained
registry/subprocess ownership.

### `CRABC-LIBC-SHADOW-ABI-REALLOC-NULL-ZERO-ALIGNMENT` — observed public-C ABI known red

- **Backends:** `libc/src/allocator_mimalloc.rs:realloc` through the ordinary
  `libmimalloc-sys` 0.1.49 C-backed artifact, compared with
  `libc/src/allocator_native_mimalloc.rs:realloc` under the nondefault
  `native-mimalloc-shadow` feature. This is not a Rust-port versus pinned
  mimalloc v3.5.0 engine differential.
- **Category:** Linux/AArch64 local public-C allocation ABI comparison only.
  It does not select a runtime backend, grant lifecycle/routing authority, or
  change the production allocator.
- **Difference:** in the captured ordinary `libc.so`, `realloc(NULL, 0)`
  returns a freeable zero-size result that is not 16-byte aligned; the selected
  native-shadow artifact returns a freeable 16-byte-aligned zero-size result.
  Both preserve the fixture's incoming errno. The ordinary wrapper's existing
  source comment asserts a malloc-like zero-size result, so this alignment
  divergence is a known red, not an accepted musl-equivalence outcome.
- **Evidence:**
  `compat/allocator/shadow-abi-matrix-v1.json`,
  `compat/allocator/shadow-abi-matrix/run.py`, and
  `tests/fixtures/native_mimalloc_shadow_backend_matrix_test.c` snapshot and
  attest both artifacts, then publish the exact normalized row in
  `compat/reports/allocator/shadow-abi-matrix/latest.json`. The harness accepts
  only the recorded `ordinary-c-mimalloc =
  freeable-misaligned-preserves-errno` and
  `native-rust-mimalloc-shadow = freeable-aligned-preserves-errno` outcomes;
  any other result is a harness failure rather than a silently normalized pass.
- **Decision/removal:** pending. A successful matrix run proves that this
  known red was observed exactly; it does not mark the two artifacts equivalent
  or promote either backend. Remove or change the row only with an explicit
  C-ABI decision and a focused default-backend implementation change plus musl
  evidence. This harness work does not alter runtime lifecycle production code.

### `CRABC-MI-SCOPED-REGULAR-AND-FULL-REMOTE-PRODUCER` — accepted bounded routing boundary

- **Upstream/Rust:** `src/free.c:mi_free_block_mt` and
  `src/page.c:mi_page_thread_free_collect`,
  `mi_page_queue_find_free_ex`, `mi_page_to_full`, and
  `mi_theap_collect_full_pages`, represented by
  `single_thread::RemoteFreeProducer` and
  `SingleThreadAllocator::begin_remote_free`.
- **Category:** private routing/lifetime boundary only. It has no C ABI
  surface or valid allocation-trace differential entry.
- **Difference:** mimalloc admits normal remote frees from general allocation
  routes and collects them under its full lifecycle. This bounded port admits
  one caller-proved current allocation from a live same-Theap/same-thread page
  only when it is an active `BIN_FULL` member or an active matching regular
  non-huge-bin member. The regular source candidate scan (including a small
  direct-cache miss) consumes publication before extension/full
  classification; the full scan consumes it before unfull/release. The linear
  `Send`/`!Sync` token holds the exclusive allocator borrow while a scoped
  worker may only publish the canonical block or cancel to the original client
  pointer. Separately, the nondefault native libc shadow has one bounded
  A-live route: static state retains only A's compiler-TLS slot/generation, B
  proves one exact C address against A's private ledger, and B completes
  `PARKED -> BUSY -> PARKED` with the process PageMap lease before the same
  atomic push. A's next ordinary operation or all-free drain collects the
  head, and A claims or removes the static handoff before every TLS access.
  Detached sessions, a producer registry, concurrent queue
  collection, abandonment integration beyond one consuming dynamic mapped
  regular handoff and the separately recorded later-main all-free scan plus
  its eight sole-page handoffs and bounded aggregate regular-pages traversal,
  general owner exit, general pthread lifecycle, multiple independently
  published A routes, and
  general asynchronous/public free routing remain absent. The caller still
  proves join/quiescence before queue collection because existing queue helpers
  borrow page metadata. Unlike the infallible C collection calls, a Rust
  owner-side collection error permanently poisons this private allocator and
  retains the exact page, error, and optional locally popped block; production
  allocation, inspection, free, producer preparation, and collection then all
  reject rather than guessing whether a detached remote list remains owned. The
  raw local-list substrate separately implements the source force-only append
  and rejects a malformed local cycle before relinking. Ordinary bounded
  regular/full callers still select false force; the separately recorded
  later-main all-free exit scan invokes true force, while its sole singleton
  handoff uses false force and both of its mapped-medium handoffs use true then
  false before detach; the sole and aggregate process routes then support only
  linear client frees after old Theap/TLD teardown. Neither adds a general
  owner-exit traversal or routing path.
- **Evidence:**
  `single_thread::tests::full_page_false_collection_reclaims_a_joined_remote_block_for_ordinary_reuse`
  and
  `full_page_false_collection_releases_a_joined_remotely_empty_page` prove
  source-order joined publication followed by unfull/reuse and all-free
  release. `regular_generic_remote_publication_is_collected_before_full_classification`
  and `small_direct_remote_publication_retries_the_direct_page_before_full_transition`
  prove regular generic and direct-to-generic collection, exact reuse, used
  decrement, and no incorrect full transition.
  `page_to_full_collects_a_remote_publication_after_the_enqueue` proves the
  second non-abandoning `mi_page_to_full` collection: a local head can trigger
  the move while a distinct remote publication is detached and installed only
  after enqueue.
  `page_to_full_collection_failure_permanently_retains_the_popped_block`
  injects that post-enqueue false-force failure and proves retained page/block
  identity plus non-mutating rejection at later allocation, inspection, free,
  producer-preparation, and collection boundaries.
  `remote_producer_rejects_an_unlinked_regular_page_without_mutation` proves
  active regular-queue membership is required and preserves the rejected
  allocation for ordinary local cleanup.
  `full_page_remote_producer_cancellation_restores_the_original_interior_client`
  proves canonicalization does not lose the client pointer; the detached and
  type-level Send regressions prove their respective admission/type boundaries.
  `crabc-mimalloc/tests/native_live_remote_free.rs` and
  `tests/fixtures/native_mimalloc_live_remote_free_test.c` prove the bounded
  A-live B/C handoff: two exact producer clients race, the one static A route
  serializes their source publications, and A later collects both through the
  direct runtime and selected libc artifact.
  `crabc-mimalloc/tests/native_parallel_local_workers.rs` and
  `tests/fixtures/native_mimalloc_parallel_local_workers_test.c` separately
  prove that the same one static route does not reject a second independently
  parked worker's local-only C allocation/free lifecycle. The distinct
  `crabc-mimalloc/tests/native_live_remote_free.rs` regression and
  `tests/fixtures/native_mimalloc_live_remote_from_parked_worker_test.c`
  prove the narrower transfer case: B may already have a parked local session
  when it presents one exact A client, briefly resumes and re-parks only B's
  session, and source-publishes that exact block to A's remote head. Neither
  witness gives B an A client identity absent an explicit C handoff, a route
  iterator, concurrent PageMap mutation, or general remote-free authority.
- **Decision/removal:** accepted until producer lifetime registration,
  queue-safe concurrent collection, general allocation/free routing, and the
  broader allocator/thread lifecycle are ported. It does not authorize an
  unbounded `Send` page handle, raw-pointer ownership reconstruction, or a
  general remote-free API.

### `CRABC-MI-OWNED-TLS-KEY-REGISTRY-INVALID-OWNER` — accepted private terminal boundary

- **Upstream/Rust:** `src/threadlocal.c:221-315`, especially
  `mi_thread_local_create_expand` / `_mi_thread_locals_done`, and
  `owned_tls_key_registry::OwnedThreadLocalKeyRegistry` with its typed bitmap
  boundary in `meta.rs`.
- **Category:** private invalid-owner and incomplete-process-shutdown handling
  only. It has no C ABI surface or valid allocation-trace differential entry.
- **Difference:** the bounded process-global registry uses fallible private
  locks, typed-image validation, and linear `MetaAllocation` release where C
  exposes no equivalent error. A failed allocation before replacement commit
  is retryable and preserves the old image/generation exactly. By contrast, an
  impossible published-image/provenance projection, absent appended-range
  result, or error after new-image commit while freeing the old capability is
  terminal: the registry becomes poisoned and retains its process-static typed
  state rather than reinterpreting uncertain ownership. Its explicit shutdown
  also rejects live leases and late release/claim; it does not claim the
  source's complete `_mi_thread_locals_done`, fast-key deletion, lock
  destruction, or process shutdown wiring.
- **Evidence:**
  `owned_tls_key_registry::tests::failed_first_or_expansion_allocation_preserves_bitmap_and_generation`
  proves pre-commit preservation;
  `shutdown_requires_quiescence_then_rejects_late_claim_and_release_without_bitmap_access`
  proves the bounded shutdown gate; and
  `meta::tests::selected_aligned_main_metadata_projects_only_an_exact_transient_bitmap_image`
  proves exact typed projection/foreign-owner rejection. The focused registry
  suite also proves the selected-main 1,024-bit image, 63-block ceiling,
  concurrency, and explicit lease behavior. Exact C comparison is inapplicable
  to impossible private-lock/provenance failures.
- **Decision/removal:** accepted until a full process initialization/shutdown
  and key-to-thread attachment lifecycle can distinguish every release outcome
  without retrying ambiguous ownership. It does not authorize raw capability
  reconstruction, persistent bitmap views, lock stealing, silent `Drop`
  release, or a false live-lease decrement.

### `CRABC-MI-MAIN-STATIC-LOCK-POISON` — accepted invalid-owner teardown boundary

- **Upstream/Rust:** `src/theap.c:_mi_tld_detach_theaps` and
  `src/init.c:mi_thread_theaps_done` / `main_theap::MainStaticTheapAttachment::teardown`.
- **Category:** private invalid-owner lifecycle handling only. It has no C ABI
  surface, allocation trace, or valid-program differential entry.
- **Difference:** after owned roots have been reset in source order, any
  fallible private-lock or intrusive-list boundary is terminal invalid-owner
  handling. C locks do not return an error here, and this bounded port does not
  implement the source heap-busy retry. The Rust private futex lock must not
  wait, steal a lock, or continue after an unexpected alias/guard, so heap-busy
  before list mutation, later list failures, and the post-detach TLD quiescence
  boundary poison the static attachment before registration release. The
  process-static storage and live registration remain, rather than claiming a
  completed teardown. This is distinct from root mismatch and nonzero-page
  rejection before root mutation, which preserve every live/foreign root and
  list before terminal poison.
- **Evidence:**
  `main_theap::tests::busy_heap_lock_after_root_reset_poison_retains_lists_and_live_registration`
  proves the heap-busy pre-mutation case resets roots but retains both lists
  and the live count; `main_theap::tests::post_detach_busy_tld_lock_poison_retains_the_live_registration`
  covers the later quiescence boundary. The normal static-attachment test
  proves successful quiescence then release/retirement. Exact C comparison is
  inapplicable: a valid C lifecycle reaches teardown with no held private lock.
- **Decision/removal:** accepted until a later complete private-lock and
  process/thread shutdown design can prove a source-faithful destruction path
  without aliasing risk. It does not authorize retries, lock stealing, or
  counter decrements after a failed quiescence check.

### `CRABC-MI-MAIN-STATIC-INIT-POISON` — accepted invalid-owner initialization boundary

- **Upstream/Rust:** `src/theap.c:_mi_theap_init` / `src/init.c:_mi_thread_init_with_heap`
  and `main_theap::MainStaticTheapAttachment::begin_after_heap_foundation` /
  `types::Theap::initialize_main_static`.
- **Category:** private invalid-owner lifecycle handling only. It has no C ABI
  surface, allocation trace, or valid-program differential entry.
- **Difference:** the process-static attachment is entitled to freshly
  initialized, uncontended TLD and heap lists. Rust consequently uses a
  non-blocking private-lock boundary for those one-owner attachments. A busy
  fresh list proves an invalid alias; a private unlock error after list
  mutation, or a subsequent heap-list error, likewise requires invalid
  concurrency or a kernel/private-lock failure outside the valid owner
  contract. C mutex operations do not return these failures. Once the static
  TLD has been completed and registered, this slice does not invent rollback:
  it terminally poisons process-static storage, retains the static TLD and its
  live registration, and returns no teardown owner. The injected TLD-list
  case fails before root publication, so dynamic/default/cached/fast roots
  remain pristine and the heap list remains empty.
- **Evidence:**
  `main_theap::tests::busy_tld_list_during_initial_attachment_poison_retains_static_tld_registration`
  injects a busy TLD-list lock after static-TLD registration and proves total
  and live counts remain one, roots are pristine, the heap list is empty, the
  Theap is not initialized, storage is poisoned, and retry rejects. Exact C
  comparison is inapplicable because a valid C lifecycle does not begin from
  an aliased or failed private lock.
- **Decision/removal:** accepted until complete private-lock and teardown
  ownership can prove source-faithful cleanup without aliasing. The bounded
  process-order coordinator now supplies its predecessor stages, but not a
  recovery protocol for a post-publication invalid owner.
  It does not authorize retry, lock stealing, registration decrement, or
  fabricated teardown capability after a partial initialization.

### `CRABC-MI-BOUNDED-PROCESS-MAIN-INITIALIZATION` — accepted incomplete process lifecycle

- **Upstream/Rust:** `src/init.c:151-214,305-360,536-592` (`mi_heap_main_init_once`,
  `_mi_thread_init_with_heap`, and `mi_process_init_once`),
  `src/libc.c:115-140` (`_mi_atomic_once_enter` and
  `_mi_atomic_once_release`), and `src/subproc.c:29-46,95-101`; represented by
  `process_init::ProcessMainInitializationStorage`, `once::AllocatorOnce`,
  `main_theap::MainStaticHeapFoundation`,
  `meta::MetaAllocator::prepare_for_main_subprocess`,
  `process_page_map::ProcessPageMapStorage`, and the
  `subproc::MainStaticBootstrapSelection` selector.
- **Category:** crate-private source-order startup boundary. It has no C ABI
  surface or valid allocation-trace differential entry.
- **Difference:** the Rust coordinator proves the central source order—static
  Heap, static detached metadata-image binding without backing, global PageMap,
  then ticket-zero TLD/Theap/default/fast roots—but accepts a frozen
  `MemoryConfig` instead of running source option/OS initialization. C forms
  `mi_process_theap_meta` during main-heap initialization and takes metadata
  backing only on demand. Rust likewise binds its pinned detached image before
  the global PageMap, but a first valid Rust metadata request forms a private
  direct-OS PageMap/external-arena backing rather than claiming C's normal
  `_mi_meta_zalloc` backing route. It exposes only immutable ready witnesses,
  does not reserve the process-shared arena, initialize pthread or TLS keys,
  route allocations/frees, coordinate general concurrent startup, or
  destroy/restart the process. Identity-capable bounded `initialize` callers
  do hold the source-shaped once gate through terminal publication and private
  lock release; recursive owner entry returns the typed `Initializing` refusal
  without executing a source body, while a foreign caller waits. The Rust-only
  allocation-free preflight may cancel before source selection, retaining the
  owner identity through unlock before reopening the gate. A preflight
  rejection remains cold; any failure after static selection is terminally
  retained rather than replaying a partial static image. C's static empty
  PageMap root remains absent.
- **Evidence:**
  `process_init::tests::process_main_initialization_orders_heap_metadata_map_then_ticket_zero_roots`
  proves the successful source order, bound-but-unbacked metadata, default-
  then-fast roots, and no automatic process-shared arena reservation.
  `process_init::tests::process_main_binds_metadata_before_global_page_map_failure`
  proves Map #1 belongs to the global PageMap after metadata is bound, with no
  private metadata map or ticket-zero roots; `process_main_defers_private_metadata_backing_until_first_demand`
  and `meta::tests::bound_metadata_rejects_a_foreign_subprocess_before_first_backing`
  prove first-demand private backing, frozen identity rejection before Map #1,
  and clean same-identity retry.
  `process_main_once_blocks_a_distinct_racer_until_release_and_refuses_reentry`,
  `process_main_once_blocks_a_terminal_ready_observer_until_once_release`, and
  `process_main_once_wakes_a_distinct_racer_with_retained_after_failure` prove
  the bounded source-shaped once envelope; the preflight and
  `cancelled_pre_body_claim_handoffs_a_waiter_to_the_reopened_once` regressions
  prove its retryable Rust-only cancellation boundary. The global-map failure,
  rejected-map, and ready-lease regressions prove terminal retention and
  immutable root reuse.
  `main_theap::tests::static_heap_foundation_precedes_ticket_zero_tld_theap_and_tls_roots`
  and `subproc::tests::selected_static_bootstrap_cannot_issue_ticket_zero_before_heap_foundation`
  prove the two prerequisite boundaries.
- **Decision/removal:** accepted until source options/OS and TLS-key/local
  stages, the C empty-root policy, concurrent/general thread and map startup,
  automatic arena policy, routing, shutdown, and fork repair have their own
  proved owners. It does not authorize treating this coordinator as a complete
  process initializer or public allocator startup API.

### `CRABC-MI-PROCESS-PAGE-MAP-COLD-ROOT` — accepted bounded cold-root safety divergence

- **Upstream/Rust:** `src/page-map.c:228-365`, especially static
  `mi_page_map_empty`, `__mi_page_map`, `mi_page_map_init_once`, and
  `_mi_page_map_init`, plus `src/subproc.c:253-255`; represented by
  `process_page_map::ProcessPageMapStorage`, `ProcessPageMapLease`, and
  `ProcessPageMapMutationLease` over `page_map::PageMap`.
- **Category:** private incomplete process-initialization and page-owner
  boundary. It has no C ABI surface or valid allocation-trace differential;
  its separate M2 source-private cold-init record names the failure boundary
  without selecting general allocation routing.
- **Difference:** C begins with a non-null static empty page map so early
  `free(NULL)` lookup remains valid, then its once body swaps in the mapped
  root. After a failed once body, the C sentinel remains and a later call
  reports success, but that sentinel only gives the null lookup its safe-null
  result; it is not a valid dynamic map or a safe registration/mutation
  continuation. The Rust owner begins cold with no root and has no free/lookup
  route while cold. It freezes one `MemoryConfig` and selected
  `MainSubprocess`, constructs the map in its final slot, and Release-publishes
  its root exactly once. Its current entry consumers are typed ticket-zero and
  later-thread page engines: `ProcessPageMapMutationLease` holds a
  nonrecursive private lock for one complete engine and joined scoped-producer
  lifetime, so no second Rust route may overlap plain map entries. That is a
  deliberate bounded substitute for neither C's empty root nor its general
  concurrent consumers. C's once helper consumes an allocation failure yet
  later calls cannot report that failed body through a typed result; Rust
  instead terminally poisons the unpublished owner and rejects later
  initialization. A later PageMap-only retry could not safely restart the
  Rust process coordinator after its Heap and detached-metadata predecessors
  have run. Dropping an unfinished mutation lease likewise poisons the root
  rather than allowing a later owner to treat retained entries as a fresh map.
- **Evidence:**
  `process_page_map::tests::process_map_publishes_one_stable_root_for_its_selected_main_subprocess`
  proves frozen identity/configuration and stable root reuse;
  `concurrent_process_map_initializers_share_the_one_release_published_root`
  makes the second map reservation fail and proves all workers observe the one
  publication; `page_lifecycle_is_exclusive_and_an_unfinished_owner_poisoned_the_root`
  proves the nonrecursive lifecycle and terminal drop boundary; and the three
  mapping/commit-failure regressions prove the no-root terminal failure edge.
  `process_page_map::tests::emit_m2_page_map_cold_init_failure_rust_trace`
  and the paired `./scripts/dev.sh allocator-m2` pinned-C producer inject one
  first PageMap allocation failure. They agree that the body fails once, no
  dynamic map publishes, and the body is not replayed; they intentionally
  record C's static empty root/null lookup/later-success result separately
  from Rust's absent root/no-cold-lookup-route/typed poison.
  `process_init::tests::rejected_page_map_after_heap_and_metadata_retains_ticket_zero_without_tls_publication`
  proves the coordinator observes that terminal PageMap boundary only after
  its Heap and detached-metadata predecessors, retains startup, leaves
  ticket-zero roots unpublished, and rejects later generic-thread admission.
  This is a safety-divergence witness, not a C ABI or full-process-lifecycle
  comparison.
  `process_init::tests::process_main_initialization_orders_heap_metadata_map_then_ticket_zero_roots`
  proves the coordinator publishes this distinct root before ticket-zero TLS
  roots. `main_static_page::tests::unfinished_static_page_engine_poison_retains_the_page_and_process_map_owner`
  and `main_heap_page::tests::unfinished_later_page_engine_poison_retains_the_attachment_and_process_map`
  additionally prove that a poisoned root retains a live registration rather
  than erasing it. General process-lifecycle and allocator-ABI comparison
  remain inapplicable until their owners exist.
- **Decision/removal:** this is an intentionally accepted bounded M2 PageMap
  safety divergence, not source-equivalent cold-root parity. It closes only
  the M2 component's documented cold-root condition: Rust must not fabricate a
  live `PageMap` or successful process continuation from C's lookup-only
  sentinel. A future public C allocator ABI or complete process lifecycle that
  needs cold `free(NULL)` semantics must reopen this boundary with a distinct
  cold-sentinel owner, a lookup-only API, and lifecycle tests. It does not
  authorize a null-root lookup, a retryable global mapping owner, a private
  alternate map for shared threads, or page-bearing runtime integration beyond
  the recorded bounded ticket-zero and sequential later-thread slices.

### `CRABC-MI-PAGE-MAP-HEADER-AND-ROOT-OWNER` — recorded M2 success-differential boundary

- **Upstream/Rust:** pinned `src/page-map.c:228-457,367-394`, including
  `mi_page_map_t`, `mi_page_map_init_once`, `mi_page_map_set_range`, and
  `_mi_page_map_unsafe_destroy`; represented by `page_map::PageMapHeader`,
  `PageMap`, and `PageMapRoot`.
- **Category:** Linux/AArch64, source-private M2 success-path evidence only.
  It has no public C ABI effect and does not establish process lifecycle,
  allocation routing, or fault parity.
- **Difference:** under the pinned Linux/musl fixture, C embeds its
  40-byte `pthread_mutex_t` `mi_lock_t` in an 88-byte PageMap header. The
  `#![no_std]` Rust port embeds its 4-byte `PrivateLock` in a 56-byte header.
  Because the source sizing formula includes that header, C records
  `reserved/initial-committed = 524790/16886` and Rust records
  `524794/16890`; their selected lazy-extension delta is the same 7,680
  entries. C destroys a still-published global root and restores
  `mi_page_map_empty`; Rust's separately owned `PageMapRoot` must be
  unpublished before `PageMap::destroy`. These are explicit representation and
  ownership-boundary records, not silently accepted exact-equality fields.
- **Evidence:** `./scripts/dev.sh allocator-m2` builds the direct pinned-C
  source fixture and compares the fixed 4-KiB/48-bit selected trace with
  `page_map::tests::emit_m2_page_map_init_c_rust_trace`. It requires every
  other controlled transition field to match and records both header/root
  values in `m2-memory-substrate-latest.json`.
- **Decision/removal:** accepted for this selected no_std PageMap witness.
  A future change may alter the representation only with a source-order,
  ownership, differential, and performance review. This entry does not waive
  the remaining M2 concurrent-lifetime or allocator-integration conditions.
  The M2 PageMap component's cold-root difference is separately and explicitly
  closed only as the bounded safety divergence above. The previously open paired initial
  commit/cleanup-release owner is now explicit: `PageMapInitializationError`
  carries the live `Mapping`, `ProcessPageMapStorage` retains it before
  terminal poison for both initial commit branches, and `MetaAllocator` uses
  a distinct terminal slot for its caller path. The paired regressions release
  that exact owner only after the injected cleanup fault is disabled.
  `page_map::tests::{lazy_extension_commit_failure_preserves_the_top_level_mapping_for_retry,lazy_submap_mapping_failure_preserves_the_page_map_for_retry,destroy_lazy_submap_release_failure_retains_the_exact_slot_for_retry,destroy_top_mapping_release_failure_retains_the_exact_mapping_for_retry}`
  separately inject the real `Commit`, `Map`, and `Unmap` seams: they prove
  the original top-level mapping survives lazy failure, a failed submap
  reclaim leaves its exact raw slot, and a failed final release leaves its
  exact top-level owner for retry. The source-shaped CAS loser is not an
  independently injectable path: fields and atomic-slot access are private
  to `page_map.rs`, and every current publisher owns the same private lock
  and reloads before publication. A future competing writer must retain a
  losing candidate before it may make that branch reachable. These are Rust
  safety strengthenings over C's void/best-effort release boundary, not
  source-equivalent retry claims.

### `CRABC-MI-ALIGNED-OVERMAP-CLEANUP-OWNER` — accepted private VM-substrate safety boundary

- **Upstream/Rust:** pinned `src/prim/unix/prim.c` aligned anonymous-map
  path and `src/os.c` callers, represented by
  `os::Mapping::map_aligned_for_allocator`, `AlignedMappingFailure`, and the
  typed owners in `os_page`, `meta`, `process_arena`, and the test adapter's
  unpublished `TestContextInitFailure` boundary.
- **Category:** Linux/AArch64 private M2 VM-substrate failure evidence. It
  has no public C ABI effect and is not a C/Rust allocation differential.
- **Difference:** the pinned C path treats its direct-candidate release and
  prefix/suffix partial frees as void, best-effort cleanup. Rust's non-RAII
  `Mapping` cannot be allowed to disappear on a failed cleanup edge:
  `AlignedMappingFailure` transfers the exact live direct mapping, untrimmed
  overmap, or prefix-trimmed aligned suffix. Every receiving path either
  explicitly retries release or makes its final owner terminal; `Mapping` has
  no implicit `Drop` unmap. This is a deliberate Rust ownership-safety
  strengthening, not a claim that C supplies retry semantics.
- **Evidence:**
  `os::tests::{aligned_mapping_retains_the_direct_candidate_when_its_cleanup_fails,aligned_mapping_retains_the_untrimmed_overmap_when_prefix_release_fails,aligned_mapping_retains_only_the_live_suffix_when_suffix_release_fails,forced_aligned_mapping_exercises_all_three_release_edges_before_returning_the_exact_range}`
  cover every native cleanup edge and a successful complete trim. The M2
  manifest additionally selects
  `os_page::tests::aligned_map_prefix_cleanup_failure_transfers_the_live_claim_owner`,
  `meta::tests::aligned_map_prefix_cleanup_failure_retains_metadata_before_publication`,
  and
  `process_arena::tests::explicit_os_reservation_retains_an_aligned_map_cleanup_failure_before_setup`.
  `test_context::tests::initialization_failure_retains_then_retries_the_aligned_map_and_page_map_owners`
  is supplemental test-adapter evidence for the paired private-owner retry.
- **Decision/removal:** accepted for the selected cleanup-owner slice. It
  does not close VM primitives, aligned allocation policy, the complete OS
  allocation lifecycle, or the M2 fault matrix. Revisit only with a source
  mapping, a typed owner for every new cleanup branch, and native failure
  evidence.

### `CRABC-MI-PROCESS-SHARED-ONE-ARENA-SIDECAR` — accepted incomplete arena boundary

- **Upstream/Rust:** `src/arena.c:341-406,525-569,1573-1611,1676-1791,1794-1912`,
  especially `mi_arena_reserve`, its one-at-a-time fresh-arena retry point,
  `mi_arenas_add`, `mi_arena_initialize`, `mi_manage_os_memory_ex2`, and the
  bounded regular-map part of `mi_reserve_os_memory_ex2`;
  represented by `process_arena::ProcessSharedArenaStorage`,
  `main_static_page::MainStaticFirstArenaPageAllocator`, and
  `process_owned_mapping_commit` / `ProcessPageArenaLease` over the existing
  `ArenaRegistry`, `ManagedExternalRegion`, `Mapping`, and
  `ProcessPageMapLease` boundaries.
- **Category:** private incomplete process-arena ownership only. It has no C
  ABI surface or valid allocation-trace differential entry.
- **Difference:** C may manage arbitrary external spans (including split
  sub-arenas) and chooses reservations through live option policy. Rust admits
  exactly one caller-selected, complete aligned external mapping and one
  explicit caller-selected regular OS reservation whose slice-rounded request
  is exactly one complete arena. It also preserves the first lazy automatic
  reservation decision only: source max-page headroom, the 64-bit 1-GiB
  default, the Linux overcommit eager-map condition, and the 128-MiB retry
  after an unpublished first attempt returns COLD. The private ticket-zero
  first-arena owner now invokes it only after a valid empty-Theap ordinary
  fresh-page miss: it derives the source small/medium/large/singleton span,
  preflights the zero-page static image, and retains the matching PageMap
  lifecycle through activation. `ProcessMainThread` is the only
  production-shaped factory and transfers its retained attachment plus ready
  immutable map witness without a startup reservation. It does not search an
  existing arena or reserve a later one. The regular path accepts
  only reserved or committed normal mappings, records `MemoryKind::Os`, and
  unmaps an unpublished metadata failure before returning COLD; a failed unmap
  instead retains the exact mapping terminally. The external path still returns
  a pre-publication rejected `Mapping` to its caller because it remains the
  lower `mi_manage_os_memory_ex2` boundary. Once published, either map and its
  in-place arena are process-lived. A reserved mapping enters its final sidecar
  slot before in-place initialization, so its retained callback can commit
  metadata and later selected/page-metadata ranges through the exact `Mapping`;
  it conservatively reports nonzero and the frozen Linux decommit path reports
  no recommit requirement. This is not source page-on-demand allocation policy:
  its typed pair can make one range-checked direct page-area commit for an
  already-selected extension, but does not select on-demand commitment,
  maintain `slice_pcommitted`, or perform failed-commit `_mi_page_abandon`
  reabandonment. The typed pair may now be consumed by
  separately recorded ticket-zero or one sequential later-thread page owners:
  each installs this arena's embedded `pages_main`, registers/releases ordinary
  pages, and retains a joined scoped producer. That does not create general
  arena selection, multiple/sub-arena support, concurrent/general later-thread
  ownership, root clear, or destruction. After one separate bounded
  reservation is already READY, the process owner may reconstruct only that
  exact immutable matching pair for one subsequent bounded owner; it does not
  iterate the registry, probe free slices, reserve, or map.
- **Evidence:**
  `process_arena::tests::shared_owned_arena_binds_to_the_release_published_map_and_selected_subprocess`
  proves exact root/configuration/subprocess pairing, registry publication,
  retained mapping geometry, and an empty page map.
  `reserved_owned_arena_commits_metadata_and_claims_slices_through_its_stable_mapping`
  proves reserved metadata, selected-slice, page-metadata, and later purge
  requests stay on the final mapping callback.
  `reserved_owned_arena_commit_failure_returns_the_unpublished_mapping_for_retry`
  proves an injected metadata commit failure returns the exact live backing,
  leaves the registry empty/cold, and permits only a matching retry; its foreign
  retry cannot consume the selected pair.
  `paired_page_lease_commits_one_page_area_without_marking_a_full_arena_slice`
  proves the paired capability reaches the retained mapping directly, propagates
  a direct-commit failure, remains retryable, and never manufactures a
  complete-slice commitment bit.
  `foreign_map_or_subprocess_rejects_before_mapping_or_registry_mutation`
  proves a ready owner cannot accept a foreign process map.
  `explicit_os_reservation_publishes_one_os_arena_for_reserved_and_committed_requests`,
  `explicit_os_reservation_rejects_invalid_or_second_requests_before_mapping`,
  `explicit_os_reservation_unmaps_a_failed_metadata_setup_and_allows_the_selected_retry`,
  and `explicit_os_reservation_retains_the_mapping_when_failed_setup_cannot_unmap`
  prove the bounded regular-map provenance, pre-map refusals, source-shaped
  release/retry, and terminal failed-release ownership.
  `default_os_reservation_is_lazy_and_uses_the_pinned_first_arena_policy`,
  `default_os_reservation_retries_the_pinned_smaller_arena_after_its_first_map_failure`,
  `default_os_reservation_releases_both_failed_attempts_before_retrying_from_cold`,
  and `default_os_reservation_plan_preserves_headroom_commit_and_retry_boundaries`
  prove the lazy 1-GiB first-arena policy, source smaller-map retry, COLD
  failure ownership, max-page headroom, and overcommit access decision.
  `main_static_page::tests::first_fresh_page_requirement_preserves_the_empty_theap_source_size_branches`
  and
  `main_static_page::tests::first_ticket_zero_fresh_page_reserves_the_default_arena_only_after_a_valid_miss`
  prove the exact empty-Theap span decision and that invalid requests remain
  side-effect free until the first valid ticket-zero fresh-page miss.
  `main_static_page::tests::reserved_os_arena_reservation_drives_one_static_page_lifecycle`
  proves that reserved regular mapping reaches one normal static page lifecycle.
  `main_static_page::tests::main_static_page_allocator_binds_the_in_place_main_arena_bitmap_before_page_map_publication`
  proves the paired static owner uses the arena's actual embedded bitmap and
  returns its slice after map removal; the later-thread page-engine regression
  proves the same bitmap is selected by the shared main Heap.
- **Decision/removal:** accepted until general existing-arena search, later
  source reservation/scaling, and the page-bearing fresh-allocation/owner-exit
  protocol connect the first policy to multiple owners and shutdown quiescence.
  It does not authorize eager startup reservation, option mutation, large-page
  or NUMA policy, generic arena management, raw page-map access, or process
  teardown.

### `CRABC-MI-ABANDONED-BIT-ORDINARY-PAGE-GUARD` — accepted checked invariant

- **Upstream/Rust:** pinned `src/arena.c:655-671`
  `mi_arena_try_claim_abandoned`, `src/arena.c:684-696`
  `mi_page_arena_pages`, `src/arena.c:725-778`
  `mi_arenas_page_try_find_abandoned`, `src/arena.c:1304-1337`
  `_mi_arenas_page_abandon`, and `src/arena.c:1383-1409`
  `_mi_arenas_page_unabandon`; plus `src/bitmap.c:1306-1328`
  `mi_bitmap_find`, `src/bitmap.c:1340-1380`
  `mi_bitmap_try_find_and_claim_visit`/
  `mi_bitmap_try_find_and_claim`, and `src/bitmap.c:1425-1432`
  `mi_bitmap_clear_once_set`. Rust represents this in
  `BitmapView::try_find_and_claim_abandoned`/`clear_once_set`,
  `ArenaAbandonedPages::main_page_is_set`, and the exact static-main and
  dynamic `MappedAbandonedPages` capabilities.
- **Category:** source-backed private invariant. It has no C ABI surface and
  does not constitute general abandoned-page reclaim or allocation support.
- **Difference:** C treats a missing heap-local ordinary `pages` bit at
  `mi_page_arena_pages` as an internal assertion failure. The checked Rust
  capabilities instead reject that stale `pages_abandoned[bin]` candidate.
  The rejection returns `KeepSet`: it restores the abandoned bit and its
  conservative chunk-map entry, does not call the ownership closure, and does
  not decrement the paired `Heap::abandoned_count[bin]`. A successful claim
  alone consumes that count. If an `unabandon` observes the reader's temporary
  clear, `clear_once_set` waits until the rejection restores the bit before it
  permanently clears it; only then may the owning lifecycle clear the mapped
  identity and decrement the count. The source snapshot visits a rejected
  candidate once, while an independent reader can claim a later set atomic
  word; the guard preserves both facts.
- **Evidence:**
  `arena::tests::abandoned_reclaim_main_map_rejects_an_orphan_bit_without_consuming_it`
  proves an ordinary-bit-missing candidate neither reaches ownership nor loses
  its abandoned bit/count.
  `arena::tests::abandoned_reclaim_main_map_retains_rejected_boundary_candidate_count`
  proves rejection retains the first boundary candidate and count until the
  source-order unabandon transition, after which a fresh search may claim the
  later-word candidate.
  `bitmap::tests::abandoned_reclaim_bitmap_rejected_reader_quiesces_before_later_word_retry`
  proves the temporary clear/restore quiescence at adjacent bitmap-word
  boundaries while another reader claims the later candidate.
- **Remaining dependency:** this ordinary-bit check is not a PageMap lookup or
  a page-identity proof. The caller still has to prove that the exact
  arena/slice names a live PageMap entry and matching page metadata for the
  entire claim/reclaim operation. The lifecycle owner must preserve failed
  claim restoration before an `unabandon` clear, then the source
  `unabandon` order of bitmap clear -> mapped-identity clear -> count
  decrement; its final release remains the owner-specific PageMap removal ->
  ordinary-page-bit clear -> metadata retirement -> arena slice release.
  General arena scanning, reclaim/adoption routing, concurrent
  PageMap consumers, and terminal lifecycle wiring remain unimplemented.
- **Decision/removal:** retain this checked guard until a complete source
  PageMap/lifecycle owner can supply those identity and release proofs. It does
  not authorize a fallback lookup, a global owner registry, or a claim of
  allocator parity.

### `CRABC-MI-STATIC-MAIN-PROCESS-PAGE-LIFECYCLE` — accepted bounded page-owner slice

- **Upstream/Rust:** static main-heap setup and thread attachment in
  `src/init.c:181-224,305-360`; main-heap `pages_main` selection in
  `src/arena.c:674-723`; fresh arena page publication in
  `src/arena.c:781-821,951-1114`; and all-free release in
  `src/arena.c:1240-1282`; represented by
  `main_static_page::MainStaticProcessPageAllocator`,
  `main_theap::MainStaticPageSession`,
  `process_arena::ProcessPageArenaLease`, and
  `process_page_map::ProcessPageMapMutationLease`.
- **Category:** crate-private, single-ticket-zero page owner only. It has no C
  ABI surface or valid allocation-trace differential entry.
- **Difference:** the bounded Rust coordinator now establishes static Heap,
  detached metadata, global PageMap, then ticket-zero roots in that source
  order, but this page slice still receives an explicit matching one-arena
  map/root/configuration/subprocess pair rather than choosing or reserving an
  arena. The session rejects a foreign subprocess before static-image, map, or arena
  mutation; it rejects any linked later shared-main Theap; and it installs only
  that arena's in-place `pages_main`, never a dynamic `mi_arena_pages_t` image.
  It holds the sole map plain-entry lifecycle through fresh allocation, local
  free/collection, and a joined scoped remote producer. Successful release
  follows PageMap removal -> main bitmap clear -> metadata retirement -> slice
  release. A dropped unfinished engine poisons both static and map owners;
  unlike C it has no recovery or owner-exit traversal.
- **Evidence:**
  `main_static_page::tests::main_static_page_allocator_binds_the_in_place_main_arena_bitmap_before_page_map_publication`
  proves exact static Heap/Theap identity, in-place bitmap publication, map
  visibility, map lifecycle exclusion, and all-free release;
  `foreign_process_page_pair_rejects_before_static_heap_map_or_arena_mutation`
  proves pre-mutation identity rejection;
  `preexisting_main_arena_bit_rolls_back_the_static_fresh_claim_without_map_publication`
  proves bitmap conflict rollback; and
  `joined_remote_producer_is_collected_by_the_static_main_page_owner` proves
  the joined scoped producer uses the same owner. The unfinished-engine
  regression proves terminal retention rather than cleanup fabrication.
- **Decision/removal:** accepted until the remaining options/OS and TLS-key
  startup stages, general later-thread page owners, automatic reservation/
  multi-arena routing, abandonment and owner-exit traversal, process
  destruction, pthread/TLS hooks, and public allocation routing are proved.
  It does not authorize treating this
  test-only private owner as a default allocator backend.

### `CRABC-MI-LATER-MAIN-PROCESS-PAGE-LIFECYCLE` — accepted bounded page-owner slice

- **Upstream/Rust:** later-thread `_mi_thread_init_with_heap(mi_heap_main())`
  setup and `_mi_thread_done` ordering in `src/init.c:236-282,305-360,377-421,
  448-481`; `_mi_theap_collect_abandon`'s visit order in
  `src/theap.c:89-152`; force `_mi_page_free_collect` in
  `src/page.c:214-243`; sole-singleton `_mi_page_abandon` in
  `src/page.c:245-302`; failed-reclaim final free in `src/free.c:372-514`;
  main-heap `pages_main` selection and abandoned-page claim in
  `src/arena.c:631-778`; fresh arena-page publication in
  `src/arena.c:781-821,951-1153`; queue-tail insertion in
  `src/page-queue.c:204-330`; and all-free release in
  `src/arena.c:1240-1282`; represented by
  `main_heap_page::MainHeapThreadProcessPageAllocator`,
  `main_heap_page::MainHeapThreadProcessPageExitDrain`,
  `main_heap_page::MainHeapThreadProcessPageExitSingletonHandoff`,
  `main_heap_page::MainHeapThreadProcessPageExitMappedOneBlockHandoff`,
  `main_heap_page::MainHeapThreadProcessPageExitMappedRegularRoute`,
  `MainHeapThreadProcessPageExitMappedRegularAdoption`, and its typed
  adoption failure,
  `main_heap_thread::{MainHeapThreadPageSession, MainHeapThreadPageDrainSession}`,
  `single_thread::{ThreadExitSingletonHandoff, ThreadExitMappedOneBlockHandoff,
  ThreadExitMappedRegularPostExitParts, ThreadExitMappedRegularPostExitAdoptOutcome,
  ThreadExitMappedRegularPostExitAdoptError,
  ThreadExitMappedRegularPagesPostExitParts,
  ThreadExitMappedRegularPagesPostExitRemoteFreeProducer}`,
  `process_arena::ProcessPageArenaLease`, and
  `process_page_map::{ProcessPageMapMutationLease, ProcessPageMapPostExitAccess,
  ProcessPageMapPostExitAccess::into_mutation_lease}`.
- **Category:** crate-private, one sequential later-thread page owner only. It
  has no C ABI surface or valid allocation-trace differential entry.
- **Difference:** C permits normal concurrent page-map consumers and later
  threads enter through its complete process initializer. Rust's bounded
  coordinator can now create the ticket-zero predecessor in source order, but
  a later page owner still requires one current later metadata TLD/Theap and
  an independently published matching map/arena pair. It
  validates the exact subprocess and frozen configuration before acquiring the
  map lifecycle. The session takes short serialized projections of the shared
  static Heap only where it needs a mutable Heap address, and installs that
  arena's embedded `pages_main`; it never constructs a dynamic heap-local
  `mi_arena_pages_t`. One map lifecycle covers fresh allocation, local
  free/collection, and one joined scoped producer. Its normal finish returns
  only an empty owner to no-page teardown. Its separate consuming exit drain
  clears the fixed fast slot before it visits every queue (including full),
  detaches joined remote frees, and force-appends `local_free` before deciding
  whether the page is all-free. For an all-free page it preserves PageMap
  removal -> main bitmap clear -> metadata retirement -> slice release. The
  pass continues through later queues even when an earlier page remains live,
  then retains that general live page rather than queue-detaching or abandoning
  it. Eight explicit sole-page post-fast-slot handoffs require `page_count ==
  1`, the target as its sole queue member, and every other queue/direct slot
  empty. A full one-block arena singleton in `BIN_FULL` false-collects,
  detaches its queue/count, unmapped-abandons, and retains the process PageMap
  lifecycle plus registration through its exact final free; only the raw
  failed-reclaim empty result may perform PageMap removal -> main bitmap clear
  -> metadata retirement -> slice release. A sole OS-aligned singleton in
  `BIN_FULL` may have a small ordinary block size but retains `MemoryKind::Os`,
  one reserved/used block, and the complete clipped PageMap/alias witness. It
  links into `Heap::os_abandoned_pages` before common unown, removes that exact
  member before terminal PageMap -> alias -> primary-metadata -> mapping
  release, and retains a failed `munmap` owner terminally in the later
  attachment. It supplies no OS-list scan, reclaim, requeue, or reuse. A
  medium regular arena page with
  `reserved > 1` and `used == 1` force- then false-collects, detaches its
  regular queue/count, and publishes its exact main `pages_abandoned[bin]` bit
  plus paired static `Heap::abandoned_count[bin]`. Its exact final free follows
  source mapped abandoned-free collection and accepts only its empty decision
  before reclamation: it clears the bit/identity, consumes that count, and
  performs the same terminal release. A nonempty result remains terminally
  retained rather than reclaimed or requeued. Full medium and full large
  `BIN_FULL` pages take distinct typed process routes over the same source
  full-regular state machine: after force then false collection and queue/count
  detach, source abandonment deliberately leaves them unmapped. Sequential
  failed-reclaim frees remain unmapped while `free <= reserved / 8`; the first
  below-mostly-used free reabandons the page into its exact static-main
  `pages_abandoned[bin]` bit/count pair, and later frees use the mapped tail
  until the same terminal PageMap -> main bitmap -> metadata -> slice release.
  The full-large route additionally proves its complete 64-slice span before
  that release. A separate full-singleton aggregate route accepts two or more
  full arena `PageKind::Singleton` members in `BIN_FULL` only when every direct
  slot and other queue is empty and every member has its own rounded block
  size, `reserved == used == 1`, a zero retirement countdown, an empty local
  free list, and an exact paired-arena span. It force- then false-collects,
  detaches, and ordinary-unmapped-abandons every member before old-Theap/TLD
  teardown. Its route keeps no raw list or static-main bitmap/count pair: each
  canonical one-block free re-resolves and validates PageMap membership, must
  take the raw empty failed-reclaim outcome, then releases that member in
  PageMap -> main bitmap first-bit -> metadata -> arena-slice order. Sole
  members, non-singletons, OS members, allocation-time adoption/reclaim/
  requeue, scanning, and concurrent routing remain absent. A separate
  full-OS-singleton aggregate route accepts two or more `MemoryKind::Os`
  singleton members in `BIN_FULL`, each with its own rounded block size, only when
  `reserved == used == 1`, zero
  retirement countdowns, empty local free lists, valid clipped PageMap/alias
  release images, every direct slot and other queue is empty, and the
  static-main `Heap::os_abandoned_pages` list starts empty. It force- then
  false-collects, full-queue/page-count-detaches, inserts every member into
  that private list, then unmapped-abandons it before old-Theap/TLD teardown.
  Full-queue removal clears `PAGE_IN_FULL_QUEUE`, but the private list retains
  the page's raw intrusive links until its exact canonical free removes that
  member. That free re-resolves PageMap membership, takes only the raw empty
  failed-reclaim outcome, then releases one member in private-list removal ->
  clipped PageMap -> aliases -> metadata -> mapping order. Sole or non-OS
  members, nonempty initial lists, list traversal, retry
  after failed `munmap`, adoption, reclaim/requeue, scanning, allocation-time,
  and concurrent routing remain absent; failed mapping release retains the
  exact `OsAlignedPageOwner` terminally. A separate full-medium aggregate route
  accepts two or more arena `PageKind::Medium` members in `BIN_FULL` only when
  every direct slot and other queue is empty and every member has its own
  rounded block size/static-main bin, `reserved > 1`, `used == reserved`, a
  zero retirement countdown, and one paired-arena span. It force- then
  false-collects, detaches, and ordinary-unmapped-abandons every member before
  old-Theap/TLD teardown. Its route retains no raw member list: each sequential
  client free re-resolves PageMap membership, claims the member low owner bit,
  then selects that member's exact bitmap/count capability and source unmapped
  or mapped tail. Each terminal release removes only that member through PageMap
  -> main bitmap -> metadata -> slice; a sole full page rejects before mutation.
  The separate full-large aggregate accepts only the corresponding
  `PageKind::Large` members, each with its own rounded bin, with the same
  complete preflight plus every member's exact 64-slice arena/PageMap span;
  terminal release proves and removes that complete span. A fifth bounded mixed
  medium/large aggregate accepts two or more full arena `BIN_FULL` members only
  when at least one member has each regular kind. Every member independently
  proves its rounded static-main bin, full state, empty local free list, and
  exact one-slice medium or 64-slice large span. It preserves source force ->
  false collection -> full-queue/page-count detachment -> unmapped abandonment
  before old-Theap/TLD teardown; every sequential free re-resolves its PageMap
  member, claims the low owner bit before selecting its exact static-main
  bitmap/count capability, and terminally releases only that member. A sixth
  bounded mixed singleton/regular aggregate accepts only two or more full arena
  `BIN_FULL` members with at least one `PageKind::Singleton` and at least one
  regular `PageKind::Medium` or `PageKind::Large`. A singleton proves `BIN_HUGE`,
  `reserved == used == 1`, zero retirement, an empty local free list, and an
  exact rounded span; a regular member proves an ordinary static-main bin,
  `reserved > 1`, `used == reserved`, zero retirement, an empty local free
  list, and its exact medium or large span. The route preserves source force ->
  false collection -> full-queue/page-count detach -> unmapped abandonment
  before old-Theap/TLD teardown. Every free classifies a fresh PageMap member:
  a singleton takes only the raw empty terminal tail, while a regular member
  claims its low owner bit before selecting its exact static-main bitmap/count
  pair and normal collector tail. Terminal release removes only that member;
  the map route closes only after both source-tail counts reach zero. A seventh
  per-member full non-direct-small aggregate accepts only two or more ordinary `PageKind::Small`
  arena members, each with its own `SMALL_SIZE_MAX < block_size <=
  SMALL_MAX_OBJ_SIZE` bin, every direct slot and `BIN_FULL` empty, zero
  retirement countdown, empty local free list, and one paired-arena slice per
  member. It preserves
  source force -> false collection -> ordinary-bin removal with the proven
  no-op direct-cache update -> page-count detach -> ordinary unmapped
  abandonment, then uses free.c's normal collector to re-resolve, reabandon,
  and release each one-slice member independently. An eighth homogeneous full
  direct-small aggregate accepts two or more same-bin ordinary `PageKind::Small`
  arena members with `block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, full
  state, zero retirement countdowns, empty local free lists, and one
  paired-arena slice per member. Its complete rounded direct-cache range names
  the source ordinary-queue head while every other direct slot and queue is
  empty. Source force -> false collection -> ordinary-bin removal ->
  direct-cache-head advance -> page-count detach -> ordinary unmapped
  abandonment runs for every member. Each later free re-resolves PageMap
  membership, uses the partial collector, and preserves its just-pushed head
  through the source accounting lag before mapped reabandonment or terminal
  release. All eight aggregate routes enforce their own complete class/geometry
  preflight before collection; the full-medium route admits distinct rounded
  medium bins, while the bounded medium/large and singleton/regular routes
  admit only their separately sealed heterogeneous `BIN_FULL` pairs. Stale/mixed direct-cache
  images, remote-force nonfull state, allocation-time adoption/reclaim/requeue,
  and concurrent routing remain absent. Distinct source-specific predecessors accept one sole full
  medium, non-direct-small, or direct-small page with one joined remote free:
  force collection changes `used` to exactly `reserved - 1` while each page
  remains linked in its source queue. The medium page remains marked full in
  `BIN_FULL`; false collection then removes that same member and immediately
  publishes the ordinary medium mapped bit/count pair into the existing mapped
  regular route. The non-direct-small counterpart starts from the sole full
  ordinary-bin `PageKind::Small` page with `SMALL_SIZE_MAX < block_size <=
  SMALL_MAX_OBJ_SIZE` and every direct slot empty. Its source direct-cache
  update is a no-op; false collection removes the regular member and immediately
  publishes the ordinary small mapped bit/count pair. The direct-small
  counterpart requires `block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, and
  the complete rounded direct-cache range; removal clears that exact range
  before page-count detach and immediately publishes the same client-free-only
  route. No predecessor is a general full-page traversal: malformed/nonfull
  input rejects before mutation and a collector fault retains the drain
  terminally. The sixth handoff accepts one full non-direct small page only
  when its rounded `block_size > SMALL_SIZE_MAX`: unlike the `BIN_FULL` medium
  and large shapes, it remains in its ordinary small bin, has no direct-cache
  range, and takes the ordinary collector. It follows the same
  unmapped-through-mostly-used and later mapped-tail state machine. The seventh
  handoff accepts the complementary full direct small page: its rounded
  `block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, and `used == reserved`
  retain it in the ordinary small bin with its complete rounded direct-cache
  range naming the sole page and every other direct slot empty. Source removal
  clears that range before page-count detach, then preserves ordinary unmapped
  abandonment; its partial collector retains the just-published atomic head,
  producing the pinned one-head free-count lag before the later
  below-mostly-used mapped publication. The eighth handoff accepts one
  sole nonfull medium page or small page with one or more live blocks, tears
  down the old Theap/TLD, and returns a linear
  `ProcessPageMapPostExitAccess` route. A direct small member derives its
  cache class from rounded `block_size`, requires the complete source direct
  range to name that sole page with every other direct slot empty, and clears
  the range during queue removal before page-count detach. It requires the
  source partial-collection `reserved >= 16` invariant. This nonfull route
  excludes full small pages before source collection through the explicit
  `used < reserved` guard; the distinct sixth and seventh handoffs above own the
  source non-direct and direct full-small shapes.

  One explicit consuming allocation-time edge is complete for the sole route
  only: `MainHeapThreadProcessPageExitMappedRegularRoute::adopt_into_later_main`
  accepts its source-initially-nonfull mapped medium page, or its direct-small
  page when source force/false collection leaves an immediate local free block,
  the exhausted fully committed scalar-extension shape, the exact exhausted
  prefix-covered extension shape, or the exact exhausted on-demand
  page-area-commit shape. A full `BIN_FULL`
  medium or full ordinary-bin direct-small page that force collection makes
  nonfull preserves that origin and remains client-free-only.
  Before it consumes the short route, the target
  proves the source subprocess, frozen configuration,
  PageMap-root identity, static main Heap, selected arena, complete span, and
  PageMap page identity. It turns `ProcessPageMapPostExitAccess` into the one
  long `ProcessPageMapMutationLease`, claims the exact bitmap/count member,
collects abandoned state, reassociates the page with the fresh Theap/thread,
collects live state, re-proves the complete span and exact source class, and
appends the detached page at the target queue tail. For the direct-small class,
it restores the complete rounded direct-cache range before target page-count
increment and immediately reuses that same page; an exhausted fully committed
direct-small page enters the scalar extension after tail restoration, the exact
prefix-covered shape retains its prefix count and extends without direct
commit, while the exact exhausted on-demand page-area-commit shape performs
the direct commit before prefix-count/free-list/capacity publication. Those
three no-immediate outcomes are exhaustive for valid frozen-profile metadata;
the defensive unsupported classifier rejects malformed or out-of-profile state. The
medium branch also handles an exhausted nonfull medium page (`capacity < reserved`).
A fully committed medium page (`slice_pcommitted == 0`) applies scalar
`mi_page_extend_free` list/capacity mutation after tail insertion. Its bounded
test-only `commit == false` seam
constructs one actual reserved medium or direct-small page with the source
initial callback-committed prefix. A commit-requiring nonzero-prefix branch
derives the source direct `_mi_os_commit` byte range, commits it through the
paired retained mapping, then publishes the monotonic OS-page count before
free-list/capacity mutation. The exact prefix-covered direct-small fixture arms
that commit fault and proves the zero-delta plan never invokes it. An injected
commit failure repeats false collection, queue detachment,
direct-cache/page-count repair, and mapped identity/bit/count/unown
publication; the returned consuming owner retries only the same candidate with
its retained long lifecycle. This is not a production option, scan, or fresh
fallback. A bitmap miss, malformed state, scalar extension error, or any other
post-transfer failure remains terminally retained. Non-direct-small, other
no-immediate direct-small cases, full, singleton,
unmapped, huge, foreign, automatic-scanning, concurrent, and multi-member
aggregate-registry adoption remain absent. The separately mapped final-member
edge may consume only one mapped regular member after every sibling and
singleton tail terminally releases; it has no scan, fallback, or source-full
transfer capability.

  Separately, the persistent native later-main owner has one ordinary
  allocation-time exception, recorded by
  `owner-local-selected-static-main-medium-mapped-abandoned-reclaim` in
  `compat/allocator/port-map.toml`. After the existing
  `collect_retired(false)` boundary, a same-bin normal medium request may
  inspect only its matching selected static-main Heap's Relaxed abandoned
  count. That count is an early skip, never a bitmap claim proof. The sealed
  owner-local callback then takes one paired PageMap access, claims the
  matching low-owner bitmap member, performs abandoned and live false
  collection, proves the complete arena span under that same access with
  `used < reserved`, and only then transfers the range for target queue-tail
  insertion. An inherited immediate head is consumed directly; an exhausted
  page follows the scalar extension. A direct mapping/commit miss alone
  reabandons the exact page and gets the source's one false-mode retry; every
  other post-claim failure retains the root/range/page and closes that owner to
  all later allocations. The two native audit witnesses use ordinary A and B
  threads without giving B A's pointer or route: one proves extension and one
  proves inherited-head reuse. This remains selected static-main medium
  evidence, not scanning, a fresh fallback after claim, another size class,
  public allocator parity, default selection, or an M5/promotion claim.

  `abandon_mapped_regular_pages_to_process_route` is a distinct aggregate
  transition, not a local repetition of that sole-page handoff. Its complete
  structural preflight rejects before mutation unless every direct slot is the
  source-derived queue-head image and every queued page is either a nonfull
  regular small, medium, or large arena page; a full `BIN_FULL` medium or
  large page; a full ordinary-bin direct/non-direct small page; a live full
  arena singleton in `BIN_FULL`/`BIN_HUGE`; or a live full OS-aligned singleton
  in `BIN_FULL` whose static-main private list is initially empty. A joined remote free makes a full
  regular page nonfull during force collection, so queue removal publishes its
  ordinary bitmap/count pair. An unchanged full regular page instead
  queue-detaches into source-unmapped abandonment. A live arena singleton
  retains its PageMap-only raw terminal tail; a live OS singleton links through
  the source private list before unmapped unown and retains its clipped-mapping
  terminal tail. A direct small member also
  requires `reserved >= 16` for the source partial collector. It proves the
  complete bounded doubly linked queue image before the unsafe removal kernel:
  zero-count queues have null endpoints, nonempty heads have null predecessors,
  every successor points back to its predecessor, and the counted forward walk
  ends at the registered null-terminated tail. It accepts an empty page only
  with a nonzero source retirement countdown. It then ports
  `_mi_theap_collect_retired(theap, true)`'s regular-bin release before source
  force collection, ordinary all-free release, false collection, queue detach,
  direct-cache refresh, page-count detach, and either mapped
  identity/bit/count/unown, source-unmapped abandonment, or raw singleton
  abandonment for each live survivor. Its typed registry retains no old-Theap
  pointer or raw page list: PageMap registration is membership, while an
  initially nonfull or force-normalized regular member additionally owns its
  exact static-main bitmap/count pair. The count decreases only after a full
  PageMap -> main bitmap -> metadata -> slice release. A regular free chooses
  its bin only after acquiring the source low owner bit; its shared
  failed-reclaim tail preserves the direct small partial head, maps an
  initially-unmapped member only after the source mostly-used predicate
  permits it, and otherwise unowns it unmapped. An arena singleton takes its
  sealed raw terminal tail; an OS singleton removes its exact private-list
  member before clipped mapping release. A terminal free re-derives its complete regular or
  singleton span before release (one slice for small, 8 for medium, 64 for
  large, and the source singleton span).
  A retired/force-empty traversal returns the ordinary drain. If that completed
  source traversal releases every other member and leaves exactly one
  initially-nonfull medium with an immediate local head, it captures that
  exact page/span/bin witness before registry construction and returns the
  established one-page mapped handoff instead. Reclaim revalidates the head,
  so this edge cannot extend, commit, scan, or take a fresh-page fallback.
  Fresh engines may serialize independent map operations between frees. The
  separately recorded aggregate-last-member edge may consume exactly one
  mapped regular member after every sibling and singleton tail terminally
  releases; it uses the current opaque client to constrain one bitmap claim,
  with no raw member cache, alternative scan, or general requeue capability.
  The aggregate, direct small-or-medium, and all-free runtime continuations
  enter pinned `_mi_deferred_free` before their first retirement, queue, or
  page-inspection work: production advances the Theap heartbeat and a private
  attachment-local test observer proves force/recursion ordering.
  The sole post-exit remote exception is one synchronous same-page
  `mi_free_block_mt` -> `mi_free_try_collect_mt`-shaped handoff: after B has
  claimed the regular page's low owner bit for a direct private client,
  `ThreadExitMappedRegularPagesPostExitRemoteFreeProducer` lets joined C append
  exactly one distinct private client to that page's atomic remote head. C
  returns before B's existing collector resumes; C receives no client address,
  PageMap, route, collector, terminal-release, adoption, or generic-finalizer
  authority. Every other concurrent client-free route remains absent. A live
  OS singleton with a pre-existing private-list owner, foreign, malformed
  direct-cache, public/process-global deferred-callback registration or
  allocator re-entry, arena collection, statistics merge, and retry/reuse as a
  normal allocator remain absent. A
  dropped unfinished engine, drain, or route
  poisons its owner rather than fabricating cleanup.
- **Evidence:**
  `main_heap_page::tests::later_thread_page_engine_uses_the_static_main_heap_and_in_place_arena_bitmap`
  proves exact shared Heap/later Theap identity, `pages_main` publication, map
  lifecycle exclusion, all-free release, and subsequent source teardown;
  `later_thread_rejects_a_foreign_process_pair_before_static_heap_or_map_mutation`
  proves pre-mutation process rejection;
  `later_thread_scoped_remote_producer_is_collected_before_source_teardown`
  proves the joined producer stays inside the same lifecycle; and
  `later_thread_exit_force_collects_joined_remote_full_page_before_teardown`
  proves fast-slot clear precedes force collection of a full page's joined
  remote/local frees, PageMap removal, main-bitmap clear, and final attachment
  teardown; `later_thread_exit_collects_later_full_pages_before_retaining_an_earlier_live_page`
  proves the force pass continues past a retained small live page and releases
  a later remotely freed full page; `later_thread_exit_retains_a_nonempty_page_after_the_fast_slot_is_clear`
  proves this bounded drain does not pretend a live page has completed owner
  exit; `later_thread_exit_full_singleton_handoff_releases_after_its_final_free`
  proves fast-slot clear, retained PageMap registration through the handoff,
  raw failed-reclaim release, `pages_main` clear, and subsequent root/list/TLD
  teardown; `later_thread_exit_singleton_handoff_rejects_before_detach_when_another_page_is_live`
  proves a second live page leaves both registrations intact;
  The former caller-selected mapped-one-block handoff regressions are
  superseded by source selection. The
  `later_thread_exit_generic_source_selected_medium_releases_after_its_final_free`
  regression proves main-bitmap/count publication, retained PageMap
  registration, mapped-bit quiescence/count consumption, empty-before-reclaim
  release, and subsequent root/list/TLD teardown. The
  `later_thread_exit_generic_route_releases_mixed_live_medium_and_singleton`
  regression proves the source traversal selects both live pages without
  skipping either one;
  `later_thread_exit_full_singleton_pages_route_releases_each_same_size_page`
  proves two full same-size arena singleton members detach before old-Theap/TLD
  teardown, remain PageMap-routable without a static-main abandoned bitmap,
  and release independently in complete PageMap -> first ordinary bitmap bit ->
  metadata -> arena-slice order; its distinct-size sibling
  `later_thread_exit_full_singleton_pages_route_releases_each_mixed_size_page`
  proves that every member's later free derives and releases its own arena
  span; its remaining siblings
  `later_thread_exit_full_singleton_pages_route_rejects_a_sole_singleton_before_mutation`,
  and `later_thread_exit_full_singleton_pages_route_retains_a_collection_failure`
  prove sole input rejects before mutation and an injected force-collector
  failure retains the complete source drain;
  and
  `later_thread_exit_full_medium_route_reabandons_after_mostly_used_frees`
  proves old-Theap/TLD teardown precedes client frees, the full medium page
  stays PageMap-routable but unmapped through its exact mostly-used threshold,
  then publishes the paired static-main bitmap/count before its mapped tail
  clears all terminal ownership; and
  `later_thread_exit_full_medium_pages_route_reabandons_each_distinct_bin_page_then_releases`
  proves two distinct-bin full medium members detach before old-Theap/TLD
  teardown, independently cross their source unmapped-to-mapped threshold,
  preserve each paired static-main count, and release one PageMap span at a
  time; its sibling
  `later_thread_exit_full_medium_pages_route_rejects_a_sole_full_medium_before_mutation`
  proves the aggregate boundary never overlaps the established sole-page
  route. The corresponding
  `later_thread_exit_full_large_pages_route_reabandons_each_distinct_bin_page_then_releases`
  proves independent large-member threshold transitions, one-member-at-a-time
  64-slice release, and last-member map closure; its siblings
  `later_thread_exit_full_large_pages_route_rejects_a_sole_full_large_before_mutation`,
  `later_thread_exit_full_large_pages_route_rejects_a_mixed_full_queue_before_mutation`,
  and `later_thread_exit_full_large_pages_route_retains_a_collection_failure`
  prove pre-mutation sole/mixed refusal and terminal retention after force
  collection fails; and
  `later_thread_exit_full_non_direct_small_pages_route_reabandons_each_same_bin_page_then_releases`
  proves two ordinary-bin full non-direct-small members detach before
  old-Theap/TLD teardown, independently cross the normal-collector
  unmapped-to-mapped threshold, and release one one-slice PageMap member at a
  time. Its siblings
  `later_thread_exit_full_non_direct_small_pages_route_rejects_a_sole_full_page_before_mutation`
  and
  `later_thread_exit_full_non_direct_small_pages_route_retains_a_collection_failure`
  prove the aggregate boundary never overlaps the established sole-page route
  and retains its drain terminally after force collection fails; and
  `later_thread_exit_full_direct_small_pages_route_reabandons_each_distinct_bin_page_then_releases`
  proves two distinct-bin full direct-small members retain the complete rounded
  source cache image, detach before old-Theap/TLD teardown, independently hold
  the partial-collector head through their source accounting lag, and release
  one one-slice PageMap member at a time. Its siblings
  `later_thread_exit_full_direct_small_pages_route_rejects_a_sole_full_page_before_mutation`,
  `later_thread_exit_full_direct_small_pages_route_refuses_stale_rounded_direct_cache_before_detach`,
  and `later_thread_exit_full_direct_small_pages_route_retains_a_collection_failure`
  prove the aggregate boundary never overlaps the sole route, stale direct
  state rejects before mutation, and a force-collector failure is retained
  terminally; and
  `later_thread_exit_full_medium_force_collects_to_a_client_free_only_mapped_process_route`
  proves one joined remote free is collected while the page remains linked in
  `BIN_FULL`, then source removes that full member, immediately publishes the
  mapped medium bit/count, tears down the old Theap/TLD, rejects allocation-time
  adoption before a fresh target can claim/requeue its bitmap member, retains
  all eight PageMap slices through sequential client frees, and releases them
  in source order; `later_thread_exit_full_medium_force_collect_route_rejects_a_regular_medium_before_mutation`
  proves the distinct entry shape leaves a regular medium queue/map/count
  untouched, while
  `later_thread_exit_full_medium_force_collect_route_retains_a_collection_failure`
  proves a force-collector failure records terminal drain poison rather than
  fabricating a retry; and
  `later_thread_exit_full_large_force_collects_to_client_free_only_mapped_process_route`
  proves one joined remote free is collected while the large page remains
  linked in `BIN_FULL`, then source removes that full member, immediately
  publishes the mapped large bit/count, tears down the old Theap/TLD, rejects
  allocation-time adoption before a fresh target can claim/requeue its bitmap
  member, retains all 64 PageMap slices through sequential client frees, and
  releases them in source order;
  `later_thread_exit_full_large_force_collect_route_rejects_a_regular_large_before_mutation`
  proves the distinct nonfull large entry shape leaves its regular queue/map
  and full flag untouched, while
  `later_thread_exit_full_large_force_collect_route_retains_a_collection_failure`
  proves a force-collector failure records terminal drain poison rather than
  fabricating a retry; and
  `later_thread_exit_full_non_direct_small_force_collects_to_client_free_only_mapped_process_route`
  proves one joined remote free makes the sole full ordinary-bin non-direct
  small page nonfull during force collection, then source retains its empty
  direct-cache image, removes the regular member, immediately publishes the
  mapped bit/count pair, tears down the old Theap/TLD, rejects allocation-time
  adoption, and releases its one-slice span through sequential client frees.
  `later_thread_exit_full_non_direct_small_force_collect_route_rejects_direct_small_before_mutation`
  proves the sibling direct-small class cannot cross this source boundary, and
  `later_thread_exit_full_non_direct_small_force_collect_route_retains_a_collection_failure`
  proves a force-collector fault retains terminal drain poison; and
  `later_thread_exit_full_large_route_reabandons_after_mostly_used_frees`
  proves the same full-regular owner-exit state machine for a large page,
  including old-Theap/TLD teardown before client frees, the threshold-adjacent
  unmapped-to-mapped transition, and terminal release of every one of its
  64 PageMap slices; and
  `later_thread_exit_full_non_direct_small_route_reabandons_after_mostly_used_frees`
  proves the source regular-bin full-small detach, no direct-cache image,
  ordinary-collector branch, threshold-adjacent unmapped-to-mapped transition,
  and one-slice terminal release after
  old-Theap/TLD teardown; and
  `later_thread_exit_full_direct_small_route_reabandons_after_mostly_used_frees`
  proves the complementary full direct-small regular-bin detach, exact rounded
  direct-cache image, source partial-head accounting lag, threshold-adjacent
  unmapped-to-mapped transition, and one-slice terminal release after
  old-Theap/TLD teardown; while
  `later_thread_exit_full_direct_small_force_collects_to_client_free_only_mapped_process_route`
  proves one joined remote free makes that same full ordinary-bin page nonfull
  during force collection, then source clears its rounded direct range before
  page-count detach, immediately publishes the mapped bit/count pair, tears
  down the old Theap/TLD, rejects allocation-time adoption, and releases its
  one-slice span through sequential client frees.
  `later_thread_exit_full_direct_small_force_collect_route_refuses_stale_rounded_direct_cache_before_detach`
  proves a stale range rejects before collection or detachment, and
  `later_thread_exit_full_direct_small_force_collect_route_retains_a_collection_failure`
  proves a force-collector fault retains terminal drain poison; while
  `later_thread_exit_full_direct_small_route_refuses_stale_rounded_direct_cache_before_detach`
  proves a stale slot rejects before collection, direct-cache clearing, queue
  detachment, or PageMap mutation; and
  `later_thread_exit_mapped_regular_route_tears_down_before_two_client_frees`
  proves the mapped identity/bit/count survives actual old attachment teardown,
  stays paired after the first client free, and clears before the final span
  release; `later_thread_exit_mapped_regular_route_tears_down_before_two_non_direct_small_client_frees`
  proves the same complete lifecycle for a non-direct small page, while
  `later_thread_exit_mapped_regular_route_accepts_non_direct_small_upper_boundary`,
  `later_thread_exit_mapped_regular_route_tears_down_before_two_direct_small_client_frees`,
  and `later_thread_exit_mapped_regular_route_accepts_direct_small_upper_boundary`
  prove both rounded small boundaries use that same route. The direct success
  path proves old-Theap/TLD teardown precedes its two partial-tail client frees;
  `later_thread_exit_mapped_regular_route_refuses_malformed_direct_image_before_detach`
  proves a stale direct slot rejects before collection, queue detachment, or
  PageMap mutation; and
  `later_thread_exit_mapped_regular_route_refuses_full_non_direct_small_before_detach`
  proves the nonfull route's full-small exclusion occurs before collection,
  queue detachment, or PageMap mutation; `later_thread_exit_mapped_regular_route_refuses_another_live_page_before_detach`
  proves the route remains one-page only; and
  `later_thread_exit_mapped_regular_route_can_move_to_the_client_free_thread`
  proves the linear route can cross to its later client-free thread without
  retaining the departed Theap/TLD; and
  `later_thread_exit_mapped_medium_route_adopts_into_a_fresh_later_owner`
  proves one sole mapped nonfull medium page keeps its exact PageMap identity
  and static-main bitmap/count pairing through short-to-long lifecycle
  transfer, abandoned/live collection, reassociation, queue-tail reentry, and
  final normal target release; and
  `later_thread_exit_mapped_regular_route_adopts_from_a_distinct_later_thread`
  proves that same typed source-valid route moves from A to a distinct B OS
  thread before B reclaims/reuses the page and releases every inherited client;
  `later_thread_exit_mapped_medium_on_demand_commits_before_reuse` proves a
  real reserved medium prefix uses the source direct page-area commitment
  before it extends/reuses the exact queue-tail candidate; and
  `later_thread_exit_mapped_medium_on_demand_reabandons_after_commit_failure_then_retries`
  proves an injected commit failure preserves PageMap/ordinary arena membership,
  restores the static-main mapped bitmap/count and target Theap association,
  then permits only a same-candidate retry.
  `later_thread_exit_mapped_regular_route_rejects_direct_small_allocation_adoption`
  proves a small/direct route is rejected before the map/session transfer and
  remains available for its normal client-free tail.
  `process_page_map::tests::post_exit_access_can_transfer_to_one_new_long_page_lifecycle`
  proves the short post-exit capability cannot coexist with a second long
  lifecycle and leaves the root reusable only after that long lease finishes.
  `later_thread_exit_mapped_regular_pages_route_tears_down_and_releases_mixed_pages`
  proves one aggregate registry keeps mixed direct-small, medium, and large
  PageMap/bitmap/count memberships paired across still-live frees, one-page
  releases, and the last-page release;
  `later_thread_exit_mapped_regular_pages_route_releases_retired_direct_small_before_live_medium`
  proves a normally retired all-free direct-small page retains its complete
  rounded cache image until the source prepass clears it and releases its
  one-slice span before the remaining no-immediate-head medium remains a
  sequential aggregate registry member; and
  `later_thread_exit_mapped_regular_pages_route_adopts_sole_immediate_medium_after_retired_large`
  proves a normally retired all-free large span releases before the remaining
  immediate-head medium becomes that exact one-page handoff, reclaims/reuses
  the same PageMap identity, and does not observe an armed direct-commit
  fault; and
  `later_thread_exit_mapped_regular_pages_route_releases_live_arena_singleton_with_mapped_medium`
  proves the general source traversal retains an unchanged live arena singleton
  as a PageMap-only raw-terminal member beside an initially mapped medium,
  tears down the old owner, then releases the singleton without a regular
  bitmap before the medium finishes the aggregate; and
  `later_thread_exit_mapped_regular_pages_route_releases_live_os_singleton_with_mapped_medium`
  proves the same general traversal inserts an unchanged live OS singleton in
  the static-main private list before unmapped unown, tears down the old owner,
  then removes that exact member before its clipped PageMap/mapping release
  while the initially mapped medium remains routable; and
  `later_thread_exit_mapped_regular_pages_route_rejects_malformed_direct_image_before_mutation`
  proves a stale direct-small cache slot rejects before retirement, collection,
  queue removal, or PageMap mutation; and
  `later_thread_exit_mapped_regular_pages_route_rejects_malformed_prev_before_mutation`
  proves a malformed predecessor rejects before retirement, collection, queue
  removal, or PageMap mutation; and
  `later_thread_exit_mapped_regular_pages_route_keeps_an_unchanged_full_medium_in_its_unmapped_tail`,
  `later_thread_exit_mapped_regular_pages_route_keeps_an_unchanged_full_large_in_its_unmapped_tail`,
  `later_thread_exit_mapped_regular_pages_route_keeps_an_unchanged_full_non_direct_small_in_its_unmapped_tail`,
  and
  `later_thread_exit_mapped_regular_pages_route_keeps_an_unchanged_full_direct_small_in_its_unmapped_tail`
  prove one general post-exit registry accepts each unchanged full regular
  source class, preserves its PageMap span while source-unmapped, publishes
  the exact static-main bitmap/count only after the source mostly-used
  predicate, preserves the direct small partial-head lag, and terminally
  releases its complete arena span; and
  `later_thread_exit_mapped_regular_pages_route_selects_each_large_page_bin_after_claim`
  proves two distinct large bins select their paired static-main capability
  only after the source low owner-bit claim; and
  `later_thread_exit_mapped_regular_pages_route_releases_large_page_span`
  proves the 64-slice large span remains PageMap-registered until its final
  client free, then unregisters and returns every slice; and
  `later_thread_exit_mapped_regular_pages_route_returns_drained_after_large_force_collection`
  proves a force-empty large traversal returns the ordinary drain and releases
  its full span before route construction; and
  `runtime_lifecycle::tests::dormant_ticket_zero_page_owner_repeats_mixed_owner_exit_without_state_growth`
  proves the private runtime witness moves only one opaque general route to B,
  keeps two full-medium pages plus live arena- and OS-aligned-singleton client
  identities private, and has joined C publish one second same-page full-medium
  client only after B claims the source low owner bit for its direct post-exit
  free. B's existing collector consumes both before it continues the normal
  route tail, and A's admission returns only after all members, including the
  arena PageMap-only and OS private-list/clipped-mapping tails, terminally
  release. Its eight-cycle audit proves the retained process/page-owner state, PageMap, arena,
  static-main abandoned counts, and private OS-list head return to baseline
  while metadata high-water plateaus.
  `crabc-mimalloc/tests/runtime_lifecycle.rs` additionally pauses after the
  opaque route transfer, runs the same scoped B/C publication, and proves
  ticket zero remains unavailable until B returns that terminal proof; and
  `runtime_lifecycle::tests::dormant_ticket_zero_page_owner_repeats_mapped_regular_reclamation_without_state_growth`
  alternates the opaque A-to-B sole-medium and direct-small routes. Both keep
  A's private client identities and admission inside the route until B adopts
  and uses the exact page, drains its engine, and completes B's attachment.
  Its independent eight-cycle audit permits the one retained PageMap submap
  warmup, then proves exact state and metadata-high-water plateaus. The
  prefixed C `allocator --churn` lane executes its two remaining
  pointer-private worker routes once per deterministic seed-shuffled cycle for
  128 cycles
  from recorded seed `0xd1b54a32d192ed03` under its 30-second watchdog. The
  opt-in `allocator --soak` lane executes the same two-worker schedule for
  1,024 cycles from seed `0x94d049bb133111eb` under a separate 180-second
  watchdog; and
  `unfinished_later_page_engine_poison_retains_the_attachment_and_process_map`
  proves terminal retention rather than forged thread cleanup.
- **Decision/removal:** accepted until the PageMap supports its source
  concurrent consumers, automatic reservation/multi-arena routing exists, and
  the remaining broader owner-exit traversal plus page-bearing pthread/TLS
  integration is proved.
  It does not
  authorize concurrent later-thread allocation routing, a public thread
  attachment API, process shutdown, or default backend use.

### `CRABC-MI-TEST-ONLY-ON-DEMAND-FAILED-COMMIT` — accepted test-only fault-path divergence

- **Upstream/Rust:** the direct-extension failure branch at
  `src/page.c:845-863`, represented only by
  `single_thread::PageAllocatorEngine::extend_on_demand_page_before_allocation`
  and
  `main_heap_page::tests::ordinary_reserved_medium_on_demand_commit_before_reuse`.
- **Category:** private native x86-64 test seam only. It has no C ABI surface,
  public Rust API, or production page-on-demand option/policy claim.
- **Difference:** after a failed direct extension, pinned C may retire the
  selected page and fall through to a fresh allocation path. The Rust test seam
  instead returns `None` without changing the selected page's committed prefix,
  capacity, free-list, queue membership, PageMap registration, or arena bit;
  its next test allocation explicitly retries that same page. This intentional
  divergence isolates failure-state preservation and avoids claiming a fresh
  fallback. The pinned C probe sets `mi_option_page_commit_on_demand` only to
  select its successful ordinary branch; the 23-field C/Rust differential does
  not inject a C commit fault and therefore does not establish fault-path
  parity.
- **Evidence:**
  `main_heap_page::tests::ordinary_reserved_medium_on_demand_commit_before_reuse`
  injects the Rust direct-commit failure, proves the unchanged selected-page
  witnesses, then proves same-page retry. The checked-in
  `x86_64-on-demand-evidence-v3.5.0.json` contract and
  `x86_64_on_demand_evidence.py` compare only the successful ordinary C/Rust
  trace with native x86-64 provenance.
- **Decision/removal:** accepted solely for the private test fixture until a
  separately reviewed source-shaped failed-extension lane proves the C retire
  and any fresh-selection behavior, or the fixture is removed. It does not
  authorize production option processing, a public allocator control, a
  general retry rule, or backend promotion.

### `CRABC-MI-SHARED-MAIN-NO-PAGE-LIFECYCLE` — accepted incomplete lifecycle boundary

- **Upstream/Rust:** the ordinary later-thread
  `_mi_thread_init_with_heap(mi_heap_main())` and `_mi_thread_done` branch in
  `src/init.c:236-282,305-360,377-421,448-481`, with
  `src/theap.c:228-306,414-449`, represented by
  `main_heap_thread::MainHeapThreadAttachment` and the borrow-tied
  `main_theap::MainStaticHeapLease`.
- **Category:** private incomplete lifecycle boundary only. It has no C ABI
  surface or valid allocation-trace differential entry.
- **Difference:** the Rust path begins only after its separately selected
  ticket-zero `MainStaticTheapAttachment` is live. A later owner receives a
  metadata TLD and metadata Theap, uses a short lock-serialized projection of
  that static main Heap to link its Theap, then publishes default before the
  main Heap's fixed fast slot. Unlike the one-owner static branch, normal
  shared heap-list contention waits through the private futex lock. The direct
  finish is deliberately no-page: it retains a nonempty page count, a nonempty
  dynamic backing, or a root/list mismatch rather than inventing a partial
  collect/abandon/release path. A separately recorded
  `MainHeapThreadProcessPageAllocator` may borrow one current owner before that
  finish, return only after its bounded normal engine is empty, or consume it
  into the separately recorded all-free exit drain. The successful direct or
  post-drain finish clears fast, resets default/cached, detaches the shared heap
  list before its TLD list, then frees metadata and releases the main-attachment
  gate. It has no general shared PageMap/arena routing, producer-lifetime
  registry, nonempty-page traversal, page-bearing `pthread`/TLS callback,
  process shutdown, or public routing. The separately recorded private libc
  bridge invokes only this direct no-page entry/finish path. Fallible private lock or metadata errors after source
  mutation retain the concrete owner instead of claiming a completed teardown.
- **Evidence:**
  `main_heap_thread::tests::later_thread_uses_main_fast_slot_and_retires_before_main_storage`
  proves fixed-fast publication and source-order no-page retirement;
  `later_thread_rejects_a_foreign_root_before_consuming_a_ticket` proves the
  pre-ticket root boundary; and
  `overlapping_later_threads_link_distinct_metadata_theaps_to_one_main_heap`
  uses two scoped native workers and proves both distinct Theaps are linked
  concurrently, static teardown is gated, and the shared count returns to
  zero after both finishes. Exact C differential comparison is inapplicable
  until a page-bearing general lifecycle can be driven through the runtime.
- **Decision/removal:** accepted until a shared PageMap/arena and remote
  producer lifetime can support the remaining `_mi_theap_collect_abandon`
  nonempty-page paths, after which the real crabc pthread/TLS integration can
  invoke that completed lifecycle. It does not authorize a raw shared-Heap
  pointer, a user-visible attachment API, page-bearing routing, or treating a
  retained owner as safely torn down.

### `CRABC-MI-RUNTIME-NO-PAGE-PTHREAD-BRIDGE` — accepted private runtime bridge

- **Upstream/Rust:** the same source-order no-page initialization and finish
  boundary in `src/init.c:236-282,305-360,377-421,448-481`,
  `src/theap.c:228-306,414-449`, and `src/threadlocal.c:205-214`, plus pinned
  musl 1.2.6 `src/process/fork.c` as the direct libc fork-order oracle,
  represented by `runtime_lifecycle.rs`, its hidden `__crabc_runtime`
  Rust-only boundary, and the callers in `libc/src/c_abi.rs`.
- **Category:** private production lifecycle control, not allocator routing.
  The bridge itself has no installed C symbol, public Rust API, pthread key,
  or allocation trace differential entry. The active C backend's pre-existing
  private key remains outside the 128-key application capacity.
- **Difference:** `__libc_start_main` retains the ticket-zero
  `ProcessMainThread` and the main-thread-minted `MainStaticHeapLease` after
  initial TLS/guard setup and before constructors. A pthread child attaches
  before user code, and its parent waits for an explicit success/failure
  handshake; a failed attach reaches no user code and makes `pthread_create`
  return `EAGAIN`. Normal return, `pthread_exit`, and cancellation finish only
  after libc cleanup and TSD destructors. The C mimalloc allocation backend is
  unchanged. Main-thread teardown is deliberately absent. The direct public
  fork order is public prepare -> private bridge prepare -> raw fork -> private
  bridge child/parent -> public child/parent. The allocation-free bridge gate
  first excludes later bridge owners. It preserves copied state only when the
  original ticket-zero `TPIDR_EL0` image has zero live or retained later bridge
  owners and its page owner is either cold or permanently dormant in
  `AwaitingFreshPage` or `DormantExistingArena`, with no live native client or
  PageMap operation. That child resets the copied gate and may reactivate that
  dormant owner or attach a fresh pthread. An unprepared raw-fork child, a
  foreign caller, or a child copied from a live, parked, retained, or otherwise
  nonquiescent owner disables the bridge. No inherited lock, root, pointer,
  list, or page state is repaired.
- **Evidence:** `crabc-mimalloc/tests/runtime_lifecycle.rs` proves overlapping
  attach/finish and churn against the retained process owner, two
  process-isolated quiescent fork children that each attach and finish a fresh
  worker, conservative child disablement with a live bridge owner, and the
  admission-gated dormant-page predicate.
  `crabc-mimalloc/tests/native_post_exit_terminal_proof_fork_gate.rs` then
  crosses raw fork while B holds A's already-terminal post-exit proof: the
  copied child disables without route repair, while the parent keeps both
  admission claims until B's normal finish. The selected
  `tests/fixtures/pthread_atfork_test.c` then returns ticket zero to dormant
  before a normal fork and proves child and parent `malloc`/`realloc`/`free`
  after public callbacks; callbacks themselves allocate nothing. Its raw
  `wait4` deadline bounds a broken child path;
  `tests/fixtures/pthread_create_join_tls_regression_test.c` and
  `tests/fixtures/static_pthread_tls_test.c` exercise return, direct
  `pthread_exit`, and TSD-dtor allocation through the dynamic and static
  runtime paths; `scripts/build_owned_sysroot.py` and
  `scripts/crabc_sysroot.py` audit the post-LTO named
  `THREAD_LIFECYCLE` TLSIE root and final shared TPREL form.
- **Decision/removal:** accepted only while the libc-facing bridge stays
  no-page and private. The separate bounded page-bearing witness below has
  its own source-shaped owner, retention, and direct stress evidence, but does
  not authorize this bridge to route pages. Full child recovery for a
  live/retained owner also needs its own lock/root/page proof. This does not
  authorize allocation interposition, a generic callback registry, public
  lifecycle attachment, or general fork recovery.

### `CRABC-MI-RUNTIME-PAGE-OWNER-NORMAL-FINISH-WITNESS` — accepted bounded evidence path

- **Upstream/Rust:** later-main `_mi_thread_done` / `_mi_thread_theaps_done`
  ordering from `src/init.c:377-421,448-481`, the dynamic regular-slot clear
  and `MI_ABANDON` traversal from `src/threadlocal.c:205-214` and
  `src/theap.c:89-152`, plus source post-exit free/reclaim tails in
  `src/free.c:372-418,479-515` and `src/arena.c:1304-1424`, represented by
  `runtime_lifecycle::{ThreadLifecycleSlot,ThreadLifecyclePageOwner,
  ThreadLifecyclePreparedPageOwner,CurrentThreadPageOwnerSession,
  CurrentThreadPageOwnerSessionHandle,PreparedOwnerExitClients,
  CurrentThreadPageOwnerPreparation,begin_current_thread_page_owner_session,
  install_current_thread_page_owner,
  RuntimePersistentPageEngine::begin_thread_exit_drain,
  finish_current_thread_all_free_page_owner_after_user_destructors,
  finish_current_thread_after_user_destructors}` and the two hidden
  aggregate/sole-medium witnesses plus the hidden direct-small
  `*_through_normal_finish` witness.
- **Category:** pointer-private Gate 5C route evidence and bounded Gate 5D
  stability evidence only; not the libc pthread bridge, allocator routing, or
  a public post-exit capability.
- **Difference:** a prepared mixed aggregate, sole-medium reclaim, or
  source-valid direct-small reclaim workload suspends its exact A-side engine
  into compiler TLS before ordinary post-destructor finish. The dispatcher
  resumes only that matching owner, clears the source fast slot, and runs the
  aggregate traversal for the aggregate/medium cases or the existing
  `abandon_mapped_small_or_medium_to_process_route` cache-validating source
  drain for direct small. The aggregate keeps direct-small, non-direct-small,
  a pre-exit-normalized medium, a source-unmapped full medium, an A-locally
  unfull mapped medium, force-empty large, two-client live-large,
  arena-singleton, and OS-singleton members in that one existing traversal; it
  does not create a
  class- or block-count-specific owner-exit entry. A fixed preparation ledger
  mints every A-side allocation as one capability and requires it to be
  locally freed, joined-published before exit, or moved exactly once into the
  typed route. Omitted, duplicate, or caller-selected over-capacity sets reject
  before the engine can suspend. `CurrentThreadPageOwnerSession` starts with
  that inline ledger beside one generation-checked parked engine, then grows a
  private metadata-backed extension before another native C allocation can
  escape across ordinary allocation, local-free, and joined source-publication
  calls. Its consuming `prepare_sequential_exit` transfers every still-live
  entry without a workload-shaped client list, moving that extension only with
  the opaque route; source-published entries remain outside the route for
  source collection. For a source-valid B/C/D interleaving,
  it may move exactly two generation-checked opaque keys into the existing
  scoped post-exit pair only after validating them before transfer. The TLS
  state distinguishes that active session from a prepared parked engine and
  typed route facts, so the fixed workloads are regression builders rather
  than lifecycle-state constructors.
  A session with no locally live ledger entry instead takes the dedicated
  all-free page drain and attachment teardown before its admission releases;
  joined source-published entries remain for that drain's source collection,
while a live session remains outside the no-page finalizer. The isolated
source-published-session tests warm ticket zero, join either one or two
private publications, and prove that force collection tears down A and
reopens ticket zero. A separate active-session regression locally retires a
direct-small page while one medium client stays live in another source bin;
the normal prepared finish must release that retired page before it publishes
the medium route to B. The private ledger records an immediate local-head fact
only while A has exclusive engine ownership, so B attempts aggregate
final-member adoption only with that fact and otherwise uses sequential free
without an irreversible speculative claim. A resulting aggregate-free or sole-adoption route
  owns A's client identities and admission until fresh B terminally frees, or
  adopts/uses and drains, the exact route; the common completion boundary
  settles ticket zero only after B returns its typed proof. Rejected, retained,
  poisoned, or mismatched route outcomes remain terminal and never invoke A's
  no-page finalizer. This exact-client façade is now `#[cfg(test)]` only. The
  C ABI remains nine prefixed test symbols with no client address, generic
  finalizer, owner-exit, or reclamation exposure.
- **Evidence:** `crabc-mimalloc/tests/runtime_lifecycle.rs` pauses the mixed
  route after transfer, proves ticket zero remains unavailable until B's
  terminal proof, then drives the sole-medium and direct-small routes through
  the same normal dispatcher and verifies reactivation after each; the
  direct-small integration repeats eight normal-finish/reclaim cycles.
  `crabc-mimalloc/tests/runtime_lifecycle_retired_session.rs` proves an active
  parked session's direct-small retired-page prepass completes before B
  sequentially releases its one remaining medium client. The
  `main_heap_page` unit regression separately arms the generic collector after
  a sole direct-small page becomes retired and proves the all-free continuation
  releases that page in the shared prepass instead. A second unit regression
  injects a retired-page release failure after its PageMap unregister beside a
  live medium member and proves the retained aggregate is lifecycle-poisoned,
  not retryable or eligible for no-page teardown. The
  `later_thread_exit_post_detach_aggregate_failure_cannot_finish_as_all_free`
  regression separately injects a failure after aggregate queue/count
  detachment while the medium's PageMap entry remains live; it proves the
  `MainHeapThreadProcessPageExitDrain` retained-route boundary latches every
  source-mutated `RetainedEngine`, keeps its process-map lease, and rejects
  the ordinary all-free/no-page finisher. The
  deterministic state audit alternates sole-medium and direct-small
  reclamation across eight cycles. The runtime integration additionally
  shuffles eight core pointer-private routes, including the all-free
  parked-session finish, ordinary parked-session owner exit, and the
  parked-session scoped B/C publication route, for eight epochs from seed
  `0x9e3779b97f4a7c15`, proving ticket-zero reactivation after each.
  The former session-publisher integration targets were removed with that
  façade. The current direct pointer-first witnesses instead prove post-exit
  same-page producer collection in
  `crabc-mimalloc/tests/native_post_exit_claimed_remote_producers.rs`, retain
  a live PageMap entry through the winning claim tail in
  `crabc-mimalloc/tests/native_post_exit_claim_page_map_lifetime.rs`, and
  select the live medium only after the retired-large prepass in
  `crabc-mimalloc/tests/native_source_selected_medium_owner_exit.rs`. They do
  not revive a session route or client-ledger capability. The
  `crabc-mimalloc/tests/native_post_exit_split_releaser_lifecycle.rs`
  then proves one detached aggregate can outlive a nonterminal B no-page
  lifecycle and reach terminal source release through fresh C: A's parked
  scheduler token and admission remain private until C's normal finish. The
  separate `native_post_exit_terminal_proof_fork_gate` regression proves the
  same terminal proof remains fork-nonquiescent while its matched B lifecycle
  is still live; the child disables rather than repairing the copied route.
  The audited `native_post_exit_with_local_session` route additionally proves
  that B's parked local session holds both admissions through A's terminal
  release, then leaves only B's successor-route admission until C completes
  its own typed terminal finish. Once A's terminal proof is resident in B
  TLS, B may resume only its independently parked local session for ordinary
  allocation, local `realloc`, and exact local free; that does not expose or
  settle A's completion. The selected `native_mimalloc_owner_exit_realloc` C
  witness proves the continued B-local replacement preserves the source-copied
  contents, including from B's `pthread_exit` cleanup handler for a new local
  allocation and then B's TSD destructor for the existing client's valid
  `realloc`, before its native all-free finish settles A's proof. The same
  selected fixture repeats the TSD-only normal-return phase and the
  cleanup/TSD ordering through deferred cancellation at a real cancellation
  point. The companion `native_terminal_completion_live_remote_free` direct
  witness proves that generic post-exit PageMap frees do not prevent B from
  publishing an exact live C client through persistent page state; B and C
  finish through their ordinary lifecycles. The removed installation-order
  unit tests covered only the retired registry scaffolding. Exact frees remain
  serialized; this is not a concurrent route or general pointer-routing
  claim. The
  pinned AArch64 `allocator --churn` fixture executes its four existing routes
  once per deterministic seed-shuffled cycle for 128 cycles from seed
  `0xd1b54a32d192ed03` under its 30-second watchdog without changing the
  symbol inventory.
- **Decision/removal:** retain this bounded witness until a general
  page-bearing pthread lifecycle, source-concurrent routing, broad
  abandonment/reclamation, and general libc allocation routing are proved.
  The separate nondefault `native-mimalloc-shadow` boundary now has its own
  pointer-private post-exit route evidence in
  `nondefault-crabc-libc-native-mimalloc-shadow-ordinary-boundary`; it does
  not turn this test-only witness into C lifecycle wiring, backend selection,
  fork recovery, or a general allocator API.

### `CRABC-MI-AUTOMATIC-PTHREAD-DESTRUCTOR-C-ORACLE-ONLY` — accepted evidence boundary

- **Upstream/Rust:** pinned C `src/init.c:504-511`,
  `src/prim/unix/prim.c:1011-1040`, `src/init.c:426-477`,
  `src/threadlocal.c:205-214`, `src/theap.c:97-152`, and the selected
  page/arena/free/map tails, contrasted with
  `dynamic_theap::DynamicTheapAttachment` and its bounded typed owner-exit
  routes.
- **Category:** native Linux/x86-64 private C-oracle evidence only. It has no
  C ABI surface and no Rust/C differential entry.
- **Difference:** the pinned C worker proves the actual automatic path: it
  observes mimalloc's private pthread key associated with its initialized
  default Theap, returns naturally without explicit `mi_thread_done()` or
  `pthread_exit()`, and `pthread_join()` precedes the consumer's observations.
  The source key destructor invokes `_mi_thread_done`, leaving the selected
  nonfull medium page mapped-abandoned, detached, and available only to the
  recorded consumer-free tail. Rust currently has bounded explicit typed
  owner-exit models only; it has no crabc pthread/TLS lifecycle callback or
  detached post-exit owner capable of carrying live worker pages across that
  boundary. This C result therefore does not establish Rust callback parity or
  general destructor ordering.
  The separate cancellation-triggered C oracle preserves that same boundary:
  it keeps cancellation disabled while allocating, enables only deferred
  cancellation before a non-cancellation-point atomic gate, and permits one
  parent `pthread_cancel()` to be delivered at one explicit
  `pthread_testcancel()`. Its `PTHREAD_CANCELED` join result plus the same
  post-join page state proves this bounded C path only, not crabc cancellation
  behavior, Rust parity, or general cancellation ordering.
- **Evidence:**
  `x86_64_automatic_pthread_destructor_evidence.py`,
  `x86_64-automatic-pthread-destructor-evidence-v3.5.0.json`, its focused
  static contracts, and the
  `native-pinned-c-automatic-pthread-destructor` parity gate record the
  natural-return source/key boundary, 37 address-independent values, and the
  mapped-abandoned/terminal-release postcondition.
  `x86_64_cancellation_pthread_destructor_evidence.py`,
  `x86_64-cancellation-pthread-destructor-evidence-v3.5.0.json`, and the
  `native-pinned-c-cancel-testcancel-automatic-destructor` gate separately
  record 46 address-independent values for that deferred-cancellation path.
- **Decision/removal:** accepted until a real private crabc lifecycle bridge
  invokes the Rust allocator in source order at thread exit and a direct
  Rust/C boundary proof covers that behavior. It does not authorize a fake
  pthread callback, a `Send` detached attachment, general lifecycle or
  destructor-ordering claims, public x86 support, or backend promotion.

### `CRABC-MI-DYNAMIC-THEAP-INVALID-OWNER` — accepted private lifecycle boundary

- **Upstream/Rust:** `src/threadlocal.c:23-214`, `src/init.c:236-360,377-421,448-481`,
  `src/theap.c:228-306,357-369,414-449`, and `src/heap.c:60-100` /
  `dynamic_theap::DynamicTheapAttachment`, `DynamicTheapPageSession`, and
  `single_thread::PageAllocatorEngine`.
- **Category:** private invalid-owner and incomplete dynamic-thread lifecycle
  handling only. It has no C ABI surface or valid allocation-trace
  differential entry.
- **Difference:** the bounded owner uses fallible Rust private locks and typed
  metadata capabilities where valid C initialization has uncontended locks and
  no equivalent capability errors. Before Theap/list publication, a backing,
  key, or Theap allocation failure tears down its empty backing/TLD state and
  rejects without a live-count leak. Begin admits only the canonical empty
  cached predecessor, then follows source regular-slot store, cached-root
  store, and exact dynamic-Theap `1 -> 2` reference transition. A foreign
  cached root is a pre-ticket rejection. After list publication, a lock/list,
  backing, metadata, or cached-root/reference failure during begin retains the
  concrete poisoned owner with every still-known TLD registration, allocation,
  backing, binding, and lease capability; it does not attempt a source-invented
  rollback. Teardown validates its cached pointer/refcount before mutation,
  clears slot/backing, stores the canonical empty cached root, then transitions
  `2 -> 1` before list detach. Thus an invalid busy heap-list outcome after
  root reset retains the list/image/registration/key capabilities but has the
  empty cached root and refcount one. During teardown, the dynamic TLD follows
  source order by releasing its live count before identity invalidation and
  private-lock quiescence. A metadata free ambiguity retains only the
  capabilities still known valid and never fabricates ownership of the
  consumed image. Teardown mismatch and nonzero-page checks are pre-mutation.
  The one retryable outcome is a
  final regular-key release lock error after all other valid teardown work:
  `AwaitingKeyRelease` retains only the linear lease until that pre-mutation
  release succeeds. Safe typed metadata projections also reject released
  capabilities before forming a reference. Ordinary dynamic begin stores the
  source abandoning `true`/`2` profile and rejects page-session construction.
  The crate-private unsafe non-abandoning begin stores the source-reachable
  `false`/`-1` profile before Release heap publication; its sealed borrowed
  session is the only dynamic instantiation of the private shared page engine.
  A `cfg(test)`-only fixture validates the frozen ordinary `true`/`2` source
  image solely to construct one `MI_ABANDON` aggregate queue shape; production
  ordinary attachments still reject the general page session.
  The engine must be consumed by a fully quiescent finish; an unfinished drop,
  retained collection poison, or pending OS unmap failure latches the
  attachment terminally, transfers any pending OS release owner into it, and
  retains the live page/map/resource state rather than claiming teardown. This
  remains bounded private routing, not a general dynamic allocation,
  abandonment, pthread, fork, or process lifecycle. After the regular backing
  is cleared, its `DrainingPages` owner first force-collects an already-retired
  all-free regular page. Its singleton live-page transition is a full
  one-block dynamic arena or OS-aligned singleton, false-collected, detached
  from `BIN_FULL`, unmapped-abandoned, and retained until its exact client free
  takes the failed-reclaim all-free release. The OS form is exactly
  `MemoryKind::Os` with `reserved == used == 1`; it may have a small ordinary
  block size, links the still-owned page into this dynamic Heap's
  `os_abandoned_pages` list before common unown, and removes that exact member
  before clipped PageMap -> alias -> primary-metadata -> mapping release. A
  failed `munmap` retains the unique published owner terminally in the dynamic
  attachment. It supplies no OS-list traversal, reclaim, requeue, or reuse.
  The source force-only local-list append is unreachable under the
  `reserved == used == 1`, no-producer proof; the raw free-list primitive
  separately ports and tests it without broadening this drain. The successful
  drain then permits the existing cached-root/list/key teardown.
  `DynamicThreadExitDrain::abandon_full_singleton_pages` is a separate
  sequential dynamic aggregate, not a general `BIN_FULL` traversal: it
  requires two or more full `MemoryKind::Arena` `PageKind::Singleton` members
  with their own rounded block sizes, `reserved == used == 1`, zero retirement
  countdown, empty local free lists, exact arena spans, and every other
  queue/direct entry empty. It force- then false-collects and detaches each
  member before unmapped abandonment. The returned
  `DynamicThreadExitFullSingletonPagesRoute` retains the original drain rather
  than a raw member list or dynamic bitmap/count pair; every sequential
  canonical free re-resolves and validates PageMap, accepts only the raw empty
  failed-reclaim result, and releases its exact PageMap -> dynamic ordinary-bit
  -> metadata -> arena-slice span. The final free returns an empty drain for
  existing teardown. A sole, non-singleton, OS-backed, existing queue/direct,
  allocation-time, reclaim/adoption/requeue, scan, or concurrent case remains
  absent, while a collection failure retains the drain.
  `DynamicThreadExitDrain::abandon_full_os_singleton_pages` is a separate
  sequential dynamic aggregate, not a general `BIN_FULL` or OS-list traversal:
  it requires two or more full `MemoryKind::Os` singleton members, each with
  its own rounded block size, `reserved == used == 1`, zero retirement countdown, empty
  local free list, a valid clipped PageMap/alias release image, an initially
  empty dynamic `Heap::os_abandoned_pages` list, and every other queue/direct
  entry empty. It preserves source force -> false collection -> full-queue/
  page-count detach -> private OS-list insertion -> unmapped unown for every
  member. The returned `DynamicThreadExitFullOsSingletonPagesRoute` retains
  only the original drain and member count, not a raw member list
  or dynamic bitmap/count pair. Each sequential canonical free re-resolves
  PageMap, accepts only the raw empty failed-reclaim result, removes that exact
  private-list member, then releases its clipped PageMap -> alias -> primary
  metadata -> mapping image. The final free returns the empty drain for
existing teardown. A sole, arena-backed, non-singleton,
  preexisting-list, allocation-time, reclaim/adoption/requeue, scan, producer,
  concurrent, huge, or general owner-exit case remains absent, while a
  collection, list, or mapping-release failure retains the sole owner
  terminally.
  `DynamicThreadExitDrain::abandon_full_medium_pages` is a third separate
  sequential dynamic aggregate, not a general `BIN_FULL` traversal: it
  requires two or more full `MemoryKind::Arena` `PageKind::Medium` members,
  each with its own rounded block size and regular bin, `reserved > 1`,
  `used == reserved`, zero retirement countdown, empty local free list, exact
  arena span, and matching dynamic bitmap/count capability. Every other
  queue/direct entry is empty. It force- then false-collects and detaches each
  member before unmapped abandonment. The returned
  `DynamicThreadExitFullMediumPagesRoute` retains the original drain rather
  than raw member pointers or per-member mapped state; every sequential
  canonical free re-resolves PageMap, claims the member low owner bit, then
  selects that member's exact dynamic bitmap/count capability and unmapped or
  mapped full-medium failed-reclaim tail. It releases only that member through
  PageMap -> dynamic ordinary bit -> metadata -> arena slices. The final free
  returns an empty drain for existing teardown. A sole, mixed-class, non-medium,
  OS-backed, existing queue/direct,
  allocation-time, reclaim/adoption/requeue, scan, producer, or concurrent case
  remains absent, while a collection failure retains the drain.
  `DynamicThreadExitDrain::abandon_full_large_pages` is a fourth separate
  sequential dynamic aggregate, not a general `BIN_FULL` traversal: it
  requires two or more full `MemoryKind::Arena` `PageKind::Large` members,
  each with its own rounded block size and regular bin, `reserved > 1`,
  `used == reserved`, zero retirement countdown, empty local free list, the
  matching dynamic bitmap/count capability for every member, every other
  queue/direct entry empty, and every member's exact 64-slice arena/PageMap
  span. It force- then false-collects and detaches each member before unmapped
  abandonment. The returned `DynamicThreadExitFullLargePagesRoute` retains the
  original drain rather than raw member pointers or per-member mapped state;
  every sequential canonical free re-resolves PageMap, claims the low owner
  bit, then selects the member's exact dynamic bitmap/count capability and
  unmapped or mapped full-large failed-reclaim tail. It releases only that
  member through PageMap -> dynamic ordinary bit -> metadata -> its complete
  64-slice arena span. The final free returns an empty drain for existing
  teardown. A sole, mixed-class, non-large, OS-backed,
  malformed-span, existing queue/direct, allocation-time,
  reclaim/adoption/requeue, scan, producer, or concurrent case remains absent,
  while a collection failure retains the drain.
  `DynamicThreadExitDrain::abandon_full_medium_or_large_pages` is a fifth
  separate sequential dynamic aggregate, not a general heterogeneous `BIN_FULL`
  traversal. It admits two or more full arena regular members only when at
  least one is medium and one is large; every other queue/direct entry is
  empty. Each member independently proves its rounded bin, full state, zero
  retirement countdown, empty local free list, matching dynamic bitmap/count
  capability, and exact one-slice medium or 64-slice large PageMap span. Source
  force -> false collection -> full-queue/page-count detach -> unmapped
  abandonment runs for every member. The route retains only the dynamic drain
  and count; each canonical free re-resolves its PageMap member, claims the low
  owner bit, derives only that member's exact dynamic map, follows the normal
  failed-reclaim tail, and releases only that member's exact span. Homogeneous
  queues, small/direct-small, singleton, OS, malformed spans, allocation-time,
  reclaim/adoption/requeue, scans, producers, and concurrent routing remain
  absent.
  `DynamicThreadExitDrain::abandon_full_singleton_or_regular_pages` is a sixth
  separate sequential dynamic aggregate, not a general heterogeneous
  `BIN_FULL` traversal. It admits two or more full arena members only when at
  least one is `PageKind::Singleton` and at least one is a regular
  `PageKind::Medium` or `PageKind::Large`; every other queue/direct entry is
  empty. Every singleton independently proves `BIN_HUGE`, `reserved == used ==
  1`, and its rounded arena span; every regular member proves its rounded bin,
  full state, matching dynamic bitmap/count capability, and exact one-slice or
  64-slice span. Source force -> false collection -> full-queue/page-count
  detach -> unmapped abandonment runs for every member. The route retains only
  the dynamic drain and count: singleton frees take the raw empty
  failed-reclaim tail, while regular frees claim their low owner bit before the
  normal failed-reclaim tail. Each member releases only its exact span.
  Homogeneous queues, regular-only mixed medium/large queues, small/direct-
  small, OS, malformed spans, allocation-time, reclaim/adoption/requeue,
  scans, producers, and concurrent routing remain absent.
  `DynamicThreadExitDrain::abandon_full_non_direct_small_pages` is a seventh
  separate sequential dynamic aggregate, not a general ordinary-bin traversal:
  it is proven through that exact ordinary source fixture and requires two or
  more full `MemoryKind::Arena` `PageKind::Small` members in one ordinary bin,
  with one rounded `SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE`,
  `reserved > 1`, `used == reserved`, zero retirement countdowns, empty local
  free lists, every direct entry and every other queue empty, the matching
  dynamic bitmap/count capability, and one exact arena slice/PageMap span per
  member. It force- then false-collects and removes every member from the
  ordinary bin before unmapped abandonment; the non-direct direct-cache update
  is a proven no-op. The returned
  `DynamicThreadExitFullNonDirectSmallPagesRoute` retains the original drain,
  not a raw member list or per-member mapped state. Every sequential canonical
  free re-resolves PageMap, uses the member's abandoned identity to select the
  normal unmapped or mapped failed-reclaim tail, and releases only that member
  through PageMap -> dynamic ordinary bit -> metadata -> one arena slice. The
  final free returns an empty drain for existing teardown. Sole, mixed-bin/class,
  direct-small, `BIN_FULL`, OS-backed, malformed-span, allocation-time,
  reclaim/adoption/requeue, scan, producer, and concurrent cases remain absent,
  while a collection failure retains the drain; production ordinary dynamic
  allocation remains sealed.
  `DynamicThreadExitDrain::abandon_full_direct_small_pages` is an eighth
  separate sequential dynamic aggregate, not a general ordinary-bin traversal:
  it is proven through that exact ordinary source fixture and requires two or
  more full `MemoryKind::Arena` `PageKind::Small` members in one ordinary bin,
  with one rounded `block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, `used ==
  reserved`, zero retirement countdowns, empty local free lists, the matching
  dynamic bitmap/count capability and one exact arena slice/PageMap span per
  member, and the complete rounded direct-cache range naming the ordinary queue
  head while every other direct entry and queue is empty. It force- then
  false-collects, removes every member from the ordinary bin, refreshes that
  range before page-count detach, and unmapped-abandons every member. The
  returned `DynamicThreadExitFullDirectSmallPagesRoute` retains the original
  drain, not a raw member list, cached direct image, or per-member mapped
  state. Every sequential canonical free re-resolves PageMap, uses the
  member's abandoned identity to select the partial-collector unmapped or
  mapped failed-reclaim tail, and preserves its just-pushed head through the
  source accounting lag before reabandonment or terminal release. A member
  stays unmapped through `reserved / 8 + 1` frees; only the next may publish
  its dynamic bitmap/count pair. Sole, stale/mixed direct-cache, mixed-bin/
  class, non-direct-small, `BIN_FULL`, OS-backed, malformed-span,
  allocation-time, reclaim/adoption/requeue, scan, producer, concurrent, and
  joined-remote nonfull cases remain absent, while a collection failure retains
  the drain; production ordinary dynamic allocation remains sealed.
  `DynamicThreadExitDrain::abandon_nonfull_medium_pages_distinct_bins` is a
  separate exact dynamic owner-exit aggregate, not a general regular-page
  registry: it requires exactly two active `MemoryKind::Arena`
  `PageKind::Medium` members in distinct ordinary non-`BIN_FULL` regular bins,
  the ordinary `allow_page_abandon == true` and `page_full_retain == 2` source
  image, one live client per member, zero retirement countdowns, canonical
  eight-slice spans, empty direct/other queue state, the exact owner-only empty
  remote-list word, and clear matching dynamic bitmap/count capability. Source
  force -> false collection -> queue/count detach -> dynamic publication ->
  unown drives the transition. Its route retains sealed bin/size witnesses,
  permits only two sequential terminal canonical frees, and then returns the
  drain. Full, direct-small, same-bin, retired, nonterminal, adoption, reclaim,
  requeue, allocation-scan, producer, and concurrent cases remain absent.
  `DynamicThreadExitDrain::abandon_full_medium` is a separate sequential
  dynamic owner-exit endpoint for the drain's sole full `MemoryKind::Arena`
  medium page in `BIN_FULL`, with `reserved > 1`, `used == reserved`, and no
  direct-cache entry. It force- then false-collects, detaches the full queue
  and page count, and ordinary-unmapped abandons. Its linear
  `DynamicThreadExitFullMediumHandoff` remains unmapped through the source
  mostly-used prefix, publishes the exact dynamic bitmap/count pair only after
  the first free beyond `reserved / 8`, then clears that pair before PageMap ->
  dynamic ordinary-bit -> metadata -> slice release. It does not cover full
  small/large, multiple pages, reclaim, adoption, requeue, scanning, or a
  general dynamic owner-exit traversal.
  `DynamicThreadExitDrain::abandon_full_large` is a separate sequential
  dynamic owner-exit endpoint for the drain's sole full `MemoryKind::Arena`
  large page in `BIN_FULL`. It requires `reserved > 1`, `used == reserved`,
  and no direct-cache entry. It force- then false-collects, detaches the full
  queue and page count, and ordinary-unmapped abandons. Its linear
  `DynamicThreadExitFullLargeHandoff` uses the normal failed-reclaim collector,
  remains unmapped through the source mostly-used prefix, publishes the exact
  dynamic bitmap/count pair only after the first free beyond `reserved / 8`,
  and clears that pair before PageMap -> dynamic ordinary-bit -> metadata ->
  complete 64-slice arena release. It rejects non-large before collection and
  adds no full medium/small, multiple-page, reclaim, adoption, requeue,
  scanning, or general dynamic owner-exit traversal capability.
  `DynamicThreadExitDrain::abandon_full_medium_after_force_collect_to_mapped`
  separately ports the exact source full-medium branch with one already joined
  remote free: force collection keeps the sole `BIN_FULL` member linked and
  marked full while changing it to `used == reserved - 1`; false collection
  preserves that geometry; full-queue/page-count detach clears its full flag;
  and mapped abandonment immediately publishes the exact dynamic bitmap/count
  pair. Its `DynamicThreadExitFullMediumHandoff` begins mapped and permits only
  sequential failed-reclaim client frees, which clear that pair before the
  ordinary arena release. Multiple frees, normal full-page unmapped
  abandonment, other classes, reclaim, adoption, requeue, scanning, and
  general dynamic owner-exit traversal remain absent.
  `DynamicThreadExitDrain::abandon_full_large_after_force_collect_to_mapped`
  ports the corresponding full-large branch with the same one-remote
  force/false/detach/mapped sequence; its
  `DynamicThreadExitFullLargeHandoff` retains the complete 64-slice terminal
  release. It introduces no broader full-page or owner-exit routing.
  `DynamicThreadExitDrain::abandon_full_non_direct_small` is a sixth, separate
  sequential dynamic owner-exit endpoint for the drain's sole full
  `MemoryKind::Arena` small page in its ordinary bin. It requires
  `SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE`, `reserved > 1`,
  `used == reserved`, `!page_is_in_full`, and an empty direct-cache image.
  It force- then false-collects, detaches that regular queue and page count,
  and ordinary-unmapped abandons. Its linear
  `DynamicThreadExitFullNonDirectSmallHandoff` uses the normal failed-reclaim
  collector, remains unmapped through the same mostly-used prefix, publishes
  the exact dynamic bitmap/count pair only after the first free beyond
  `reserved / 8`, and clears that pair before PageMap -> dynamic ordinary-bit
  -> metadata -> slice release. It rejects direct-small before collection and
  does not cover full medium/direct-small/large, multiple pages, reclaim,
  adoption, requeue, scanning, or a general dynamic owner-exit traversal.
  `DynamicThreadExitDrain::abandon_full_non_direct_small_after_force_collect_to_mapped`
  separately ports the exact source full non-direct-small branch with one
  already joined remote free: force collection keeps the sole ordinary-bin
  member linked while changing it to `used == reserved - 1`; false collection
  preserves that geometry; regular-bin/page-count detach leaves it nonfull;
  and mapped abandonment immediately publishes the exact dynamic bitmap/count
  pair. Its `DynamicThreadExitFullNonDirectSmallHandoff` begins mapped and
  permits only sequential failed-reclaim client frees, which clear that pair
  before the ordinary arena release. The direct-cache image remains empty, so
  source's update is a no-op. Multiple frees, normal full-page unmapped
  abandonment, direct-small or other classes, reclaim, adoption, requeue,
  scanning, and general dynamic owner-exit traversal remain absent.
  `DynamicThreadExitDrain::abandon_full_direct_small` is a seventh, separate
  sequential dynamic owner-exit endpoint for the drain's sole full
  `MemoryKind::Arena` small page in its ordinary bin. It requires
  `block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, `used == reserved`,
  `!page_is_in_full`, and its complete rounded direct-cache range naming that
  sole page while every other slot is empty. It force- then false-collects,
  removes the regular queue member, clears the complete range before page-count
  detach, and ordinary-unmapped abandons. Its linear
  `DynamicThreadExitFullDirectSmallHandoff` takes the partial failed-reclaim
  collector: the retained just-published head delays the reabandon-to-mapped
  threshold by one client free relative to the normal full-page paths. The
  mapped tail clears the exact dynamic bitmap/count pair before PageMap ->
  dynamic ordinary-bit -> metadata -> slice release. A stale direct image,
  non-direct small, additional page, or collection fault cannot evade its
  separate source boundary; it adds no reclaim, adoption, requeue, scanning,
  multi-page, or general dynamic owner-exit traversal.
  Separately, `DynamicThreadExitMappedOneBlockHandoff` admits only one sole
  nonfull `MemoryKind::Arena` medium, large, non-direct-small, or direct-small
  page with `reserved > 1`, `used == 1`, and one regular queue member.
  `DynamicThreadExitDrain::abandon_mapped_one_block` remains medium-only;
  `abandon_mapped_one_block_large` admits only `PageKind::Large` and retains
  the complete 64-slice terminal span;
  `abandon_mapped_one_block_non_direct_small` requires
  `SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE` and an empty direct-cache
  image; `abandon_mapped_one_block_direct_small` requires
  `block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, and its complete rounded
  direct-cache range. A stale direct-small range rejects before collection or
  detach, while source queue removal clears a valid range before page-count
  detach. Its source-class witness preserves force -> false collection ->
  queue/page-count detach -> dynamic bitmap/count/unown order. Its exact final
  free reaches empty before any reclaim branch—through the normal collector for
  medium/large/non-direct small or the partial collector for direct small—
  clears that dynamic `pages_abandoned[bin]` bit plus paired
  `Heap::abandoned_count[bin]`, then releases PageMap -> dynamic ordinary-bit
  -> metadata -> slice release. It cannot reclaim the departed Theap, adopt,
  requeue, scan, or represent a second page or free.
  `DynamicThreadExitDrain::abandon_mapped_two_block_medium` is a separate
  post-TLS dynamic source class: exactly one sole nonfull `MemoryKind::Arena`
  `PageKind::Medium` page with `block_size > SMALL_SIZE_MAX`, `reserved > 2`,
  `used == 2`, zero retirement countdown, one regular queue member, an empty
  direct-cache image, and no other queue/direct entry. It preserves force ->
  false collection -> regular-queue removal -> page-count decrement ->
  non-direct no-op cache update -> dynamic mapped identity/bit/count/unown.
  Its private handoff retains no client pointer/list; the first exact canonical
  client free must produce `UnownedMapped` and keep the matching dynamic pair
  with one live block, while the final free alone may produce `Empty`, clear
  the pair, and release PageMap -> dynamic ordinary-bit -> metadata -> slice.
  One/three live blocks, another page, every other source class, reclaim,
  adoption, requeue, scans, producer/concurrent routing, and a general
  multi-free owner-exit traversal remain absent.
  `DynamicThreadExitDrain::abandon_mapped_medium_pair` is a separate bounded
  post-TLS aggregate, not a generic multi-page registry: it accepts exactly
  two nonfull `MemoryKind::Arena` `PageKind::Medium` pages in distinct regular
  bins, one sole member with `reserved > 2`, `used == 2` and one with
  `reserved > 1`, `used == 1`, while every direct entry and every other queue
  is empty. Complete preflight proves both arena spans, dynamic bitmap/count
  capabilities, and the total three live blocks before source bin-order force
  -> false collection -> queue removal -> page-count decrement -> no-op
  direct update -> mapped identity/bit/count/unown. Its route stores only the
  drain and sealed page/free counts: every exact canonical free re-resolves a
  PageMap member and claims its low owner bit before choosing the matching
  dynamic map. `UnownedMapped` retains that member; `Empty` clears only its
  pair and releases only its PageMap -> ordinary-bit -> metadata -> slice
  span, returning the drain only after the final member. It adds no raw page,
  bin, map, or client registry; no scan, reclaim/adoption/requeue,
  allocation-time, producer, concurrent, or general owner-exit authority.
  Its first dynamic arena page first proves the registry-published arena's
  non-null subprocess identity equals the attachment's selected main
  subprocess, then lazily owns one exact BCHUNK-aligned `mi_arena_pages_t`
  metadata image bound to the exact Heap and one arena slot. The ordinary page
  bitmap is disjoint from
  `Arena::pages_main` for fresh/rollback/release. One consuming same-owner
  `DynamicMappedPageHandoff` additionally moves only a mapped regular arena
  page through heap-local `pages_abandoned[bin]` and its paired
  `Heap::abandoned_count`, then either reclaims it through the same pinned
  engine or consumes one still-live client block through the source mapped
  `allow_collect=true` same-origin remote-free branch. The small-page branch
  keeps its published head atomic until reassociation. Its all-free
  dynamic-arena branch then unregisters the full PageMap span, clears the
  exact heap-local ordinary bit, retires metadata, releases slices, and only
  then returns the drained engine; an existing owner or a post-unregister
  release failure retains the handoff terminally. A separate raw
  `free_unmapped_after_failed_reclaim` substrate ports expected-head unown,
  conflict collection without another reclaim attempt, and terminal-empty /
  reabandon / unown selection. Its lifecycle-integrated raw terminal-release
  owners are the post-TLS arena/OS singleton, full-singleton,
  homogeneous-full-OS-singleton, full-medium, full-large, full-non-direct-small, and
  full-direct-small aggregates, sole full-medium, full-large, full-non-direct-small, and
  full-direct-small handoffs above and the later-main full-OS-singleton
  aggregate, full-medium, full-large, and full-non-direct-small routes;
  none routes
  general policy through the dynamic handoff. Other regular/nonempty unmapped,
  other non-arena, foreign, and full/singleton/huge pages
  still lack lifecycle integration or terminal reuse.
  Image allocation failure before
  slot publication remains retryable; any post-slot private lock/unlock/free
  ambiguity retains the known terminal owner. A nonempty image is rejected
  before dynamic root/list/key mutation; multiple arenas and general heap
  destruction remain deferred.
- **Evidence:**
  `dynamic_theap::tests::post_list_publication_backing_failure_returns_a_retained_poisoned_owner`
  proves retained post-publication authority;
  `regular_slot_then_cached_publication_increments_the_dynamic_theap_reference`,
  `foreign_cached_root_rejects_before_later_ticket_or_backing_allocation`, and
  `cached_root_is_empty_and_reference_is_one_before_a_terminal_heap_detach_failure`
  prove the canonical-predecessor, refcount, pre-ticket rejection, and
  post-root-reset terminal ordering;
  `key_release_lock_failure_keeps_only_the_linear_lease_for_retry` proves the
  lone retryable release state; and
  `dynamic_theap::tests::non_abandoning_dynamic_page_session_allocates_on_its_exact_theap_and_pinned_heap`,
  `dynamic_non_abandoning_small_page_uses_the_stored_minus_one_full_profile`,
  `dynamic_non_abandoning_full_page_collects_joined_remote_block_and_unfulls`,
  and `dynamic_pending_os_release_makes_finish_retain_then_drop_latch_attachment`
  prove bounded dynamic page-session identity, source `-1` full routing,
  joined remote collection, and terminal unfinished shutdown;
  `dynamic_mapped_regular_remote_free_reclaims_to_its_same_origin` and
  `dynamic_mapped_regular_remote_free_empty_releases_the_queue_detached_arena_page`,
  with `remote_free::tests::abandoned_partly_collection_*`, prove the source
  small-page partial-head transfer, mapped bit/count removal before
  same-origin reassociation, and all-free PageMap/ordinary-bit/metadata/slice
  release. `abandoned::tests::unmapped_*` plus
  `failed_expected_head_unown_collects_new_publication_without_a_second_reclaim`
  prove the separate failed-reclaim tail's reabandon, terminal-empty, expected
  head, and conflict-collection decisions. The dynamic
  `dynamic_thread_exit_singleton_remote_free_clears_tls_then_releases_its_arena_page`
  regression proves regular-slot clearing precedes arena abandonment, failed
  reclaim is real rather than injected, raw all-free release clears the full
  PageMap span and dynamic ordinary bit, and attachment teardown can then
  finish. The dynamic
  `dynamic_thread_exit_full_singleton_pages_route_releases_each_same_size_page`,
  `dynamic_thread_exit_full_singleton_pages_route_releases_each_mixed_size_page`,
  `dynamic_thread_exit_full_singleton_pages_route_rejects_a_sole_singleton_before_mutation`,
  and
  `dynamic_thread_exit_full_singleton_pages_route_retains_a_collection_failure`
  regressions prove complete same- and mixed-size arena-only aggregate
  preflight, one-member-at-a-time PageMap/ordinary-bit/metadata/slice release,
  wholly pre-mutation sole refusal, and retained dynamic-drain collection
  failure.
  The corresponding native x86-64 C/Rust differential compares 51
  address-independent values for exactly two same-size full `BIN_FULL` arena
  singleton pages: request 524289, 589824-byte blocks, capacity/reserved 1,
  and nine arena slices per member. The C worker runs real `mi_thread_done()`
  and the consumer joins before sequential frees. Both members begin
  unmapped-abandoned, unowned, PageMap-registered across all nine slices,
  ordinary-arena-bitmap-set, and full-queue-detached; no dynamic abandoned
  bitmap/count is claimed. The first terminal free releases only page 0 while
  page 1 remains registered, unmapped-abandoned, unowned, and used 1; the
  second releases page 1. Rust is only the typed current-thread owner-exit
  model and makes no Rust worker/join claim. This remains private native
  x86-64 engine evidence only, not a general dynamic owner-exit, public x86
  libc/ldso/crabc, or AArch64 claim.
  `dynamic_thread_exit_full_medium_pages_route_reabandons_each_distinct_bin_page_then_releases`,
  `dynamic_thread_exit_full_medium_pages_route_rejects_a_sole_full_medium_before_mutation`,
  `dynamic_thread_exit_full_medium_pages_route_rejects_mixed_full_classes_before_mutation`,
  and
  `dynamic_thread_exit_full_medium_pages_route_retains_a_collection_failure`
  prove complete per-member-bin medium aggregate preflight, independent
  unmapped-to-mapped reabandonment and PageMap/ordinary-bit/metadata/slice
  release for each member, wholly pre-mutation sole/mixed-class refusal, and
  retained dynamic-drain collection failure.
  `dynamic_thread_exit_full_large_pages_route_reabandons_each_distinct_bin_page_then_releases`,
  `dynamic_thread_exit_full_large_pages_route_rejects_a_sole_full_large_before_mutation`,
  `dynamic_thread_exit_full_large_pages_route_rejects_mixed_full_classes_before_mutation`,
  and
  `dynamic_thread_exit_full_large_pages_route_retains_a_collection_failure`
  prove complete distinct-bin large aggregate preflight, independent
  unmapped-to-mapped reabandonment and complete 64-slice
  PageMap/ordinary-bit/metadata release for each member, wholly pre-mutation
  sole/mixed-class refusal, and retained dynamic-drain collection failure.
  `dynamic_thread_exit_full_non_direct_small_pages_route_reabandons_each_distinct_bin_page_then_releases`,
  `dynamic_thread_exit_full_non_direct_small_pages_route_rejects_a_sole_full_page_before_mutation`,
  `dynamic_thread_exit_full_non_direct_small_pages_route_rejects_mixed_full_classes_before_mutation`,
  and
  `dynamic_thread_exit_full_non_direct_small_pages_route_retains_a_collection_failure`
  prove the exact ordinary `true`/`2` fixture, complete per-member ordinary-bin
  non-direct-small aggregate preflight, independent normal-collector
  unmapped-to-mapped reabandonment and PageMap/ordinary-bit/metadata/one-slice
  release for each member, wholly pre-mutation sole/mixed-class refusal, and
  retained dynamic-drain collection failure.
  `dynamic_thread_exit_full_direct_small_pages_route_preserves_partial_head_then_releases_each_member`,
  `dynamic_thread_exit_full_direct_small_pages_route_rejects_a_sole_full_page_before_mutation`,
  `dynamic_thread_exit_full_direct_small_pages_route_refuses_stale_rounded_direct_cache_before_detach`,
  `dynamic_thread_exit_full_direct_small_pages_route_rejects_mixed_full_classes_before_mutation`,
  and
  `dynamic_thread_exit_full_direct_small_pages_route_retains_a_collection_failure`
  prove the exact ordinary `true`/`2` fixture, complete same-bin direct-small
  aggregate and rounded-cache queue-head preflight, each member's independent
  partial-head-lag unmapped-to-mapped transition, one-slice
  PageMap/ordinary-bit/metadata release, wholly pre-mutation sole/stale/mixed
  refusal, and retained dynamic-drain collection failure.
  The dynamic
  `dynamic_thread_exit_os_aligned_singleton_handoff_releases_after_its_final_free`,
  `dynamic_thread_exit_os_aligned_singleton_handoff_rejects_unmapped_pointer_before_detach`,
  and
  `dynamic_thread_exit_os_aligned_singleton_handoff_retains_failed_unmap_terminally`
  regressions prove the dynamic Heap list insertion/removal order, pre-detach
  refusal, clipped PageMap removal, and terminal failed-`munmap` owner
  retention.
  `dynamic_thread_exit_full_medium_handoff_reabandons_after_mostly_used_frees_then_releases`,
  `dynamic_thread_exit_full_medium_handoff_rejects_before_detach_when_another_page_is_live`,
  and `dynamic_thread_exit_full_medium_handoff_retains_collection_failure`
  prove the full `BIN_FULL` preflight, exact unmapped-to-mapped mostly-used
  threshold, dynamic bitmap/count cleanup before terminal arena release,
  wholly pre-detach sole-page refusal, and retained collection failure.
  `dynamic_thread_exit_full_large_handoff_reabandons_after_mostly_used_frees_then_releases`,
  `dynamic_thread_exit_full_large_handoff_rejects_a_full_medium_before_detach`,
  and `dynamic_thread_exit_full_large_handoff_retains_collection_failure`
  prove the full-large `BIN_FULL` preflight, normal unmapped-to-mapped
  mostly-used threshold, complete 64-slice terminal release, wholly pre-detach
  class refusal, and retained collection failure.
  `dynamic_thread_exit_full_medium_one_remote_force_collects_to_mapped_handoff_then_releases`,
  `dynamic_thread_exit_full_medium_one_remote_force_collect_route_rejects_regular_medium_before_detach`,
  `dynamic_thread_exit_full_medium_one_remote_force_collect_route_rejects_full_large_before_detach`,
  and `dynamic_thread_exit_full_medium_one_remote_force_collect_route_retains_collection_failure`
  prove the distinct exact-one-joined-remote branch: force collection changes
  the still-linked full-medium member to `used == reserved - 1`, mapped
  abandonment retains every medium PageMap slice, regular-medium and full-large
  inputs reject before mutation, and injected collection failure retains the
  post-TLS drain.
  `dynamic_thread_exit_full_large_one_remote_force_collects_to_mapped_handoff_then_releases`,
  `dynamic_thread_exit_full_large_one_remote_force_collect_route_rejects_full_medium_before_detach`,
  and `dynamic_thread_exit_full_large_one_remote_force_collect_route_retains_collection_failure`
  prove the distinct exact-one-joined-remote branch: force collection changes
  the still-linked full-large member to `used == reserved - 1`, mapped
  abandonment retains all 64 PageMap slices, full-medium rejects before
  mutation, and injected collection failure retains the post-TLS drain.
  `dynamic_thread_exit_full_non_direct_small_handoff_reabandons_after_mostly_used_frees_then_releases`,
  `dynamic_thread_exit_full_non_direct_small_handoff_rejects_before_detach_when_another_page_is_live`,
  `dynamic_thread_exit_full_non_direct_small_handoff_rejects_direct_small_before_detach`,
  `dynamic_thread_exit_full_non_direct_small_handoff_refuses_stale_direct_cache_before_detach`,
  and `dynamic_thread_exit_full_non_direct_small_handoff_retains_collection_failure`
  prove ordinary-bin and empty-direct-image preflight, direct-small exclusion
  and stale-cache refusal before collection, the exact unmapped-to-mapped
  mostly-used threshold, dynamic bitmap/count cleanup before terminal arena
  release, wholly pre-detach sole-page refusal, and retained collection failure.
  `dynamic_thread_exit_full_non_direct_small_one_remote_force_collects_to_mapped_handoff_then_releases`,
  `dynamic_thread_exit_full_non_direct_small_one_remote_force_collect_route_rejects_regular_non_direct_small_before_detach`,
  `dynamic_thread_exit_full_non_direct_small_one_remote_force_collect_route_rejects_full_direct_small_before_detach`,
  `dynamic_thread_exit_full_non_direct_small_one_remote_force_collect_route_refuses_stale_direct_cache_before_detach`,
  and `dynamic_thread_exit_full_non_direct_small_one_remote_force_collect_route_retains_collection_failure`
  prove the distinct exact-one-joined-remote ordinary-bin branch: force
  collection changes the still-linked full non-direct-small member to
  `used == reserved - 1`, mapped abandonment retains its complete one-slice
  PageMap span, regular/non-direct-small and full direct-small inputs reject
  before mutation, a stale direct image rejects before detachment, and injected
  collection failure retains the post-TLS drain.
  `dynamic_thread_exit_full_direct_small_one_remote_force_collects_to_mapped_handoff_then_releases`,
  `dynamic_thread_exit_full_direct_small_one_remote_force_collect_route_rejects_regular_direct_small_before_detach`,
  `dynamic_thread_exit_full_direct_small_one_remote_force_collect_route_rejects_full_non_direct_small_before_detach`,
  `dynamic_thread_exit_full_direct_small_one_remote_force_collect_route_refuses_stale_direct_cache_before_detach`,
  and `dynamic_thread_exit_full_direct_small_one_remote_force_collect_route_retains_collection_failure`
  prove the distinct exact-one-joined-remote ordinary-bin branch: force
  collection changes the still-linked full direct-small member to
  `used == reserved - 1`, direct-range clearing precedes page-count detach,
  mapped abandonment retains its complete one-slice PageMap span, regular
  direct-small and full non-direct-small inputs reject before mutation, a stale
  direct image rejects before detachment, and injected collection failure
  retains the post-TLS drain.
  `dynamic_thread_exit_full_direct_small_handoff_reabandons_after_partial_head_lag_then_releases`,
  `dynamic_thread_exit_full_direct_small_handoff_refuses_stale_rounded_direct_cache_before_detach`,
  `dynamic_thread_exit_full_direct_small_handoff_rejects_non_direct_small_before_detach`,
  `dynamic_thread_exit_full_direct_small_handoff_rejects_before_detach_when_another_page_is_live`,
  and `dynamic_thread_exit_full_direct_small_handoff_retains_collection_failure`
  prove the complete rounded-cache preflight and clear-before-count ordering,
  partial-head one-free mapping lag, class and sole-page refusals before
  mutation, dynamic bitmap/count cleanup before terminal release, and retained
  collection poison.
  `dynamic_thread_exit_mapped_one_block_handoff_releases_after_its_final_free`,
  `dynamic_thread_exit_mapped_one_block_handoff_rejects_before_detach_when_another_page_is_live`,
  and `dynamic_thread_exit_mapped_one_block_handoff_retains_collection_failure`
  prove the medium class's dynamic bitmap/count publication and terminal
  release, wholly pre-detach sole-page refusal, and retained post-TLS
  collection failure. The large-specific
  `dynamic_thread_exit_mapped_one_block_large_handoff_releases_its_complete_span_after_final_free`,
  `dynamic_thread_exit_mapped_one_block_large_handoff_rejects_medium_before_detach`,
  and `dynamic_thread_exit_mapped_one_block_large_handoff_retains_collection_failure`
  prove the large-only preflight, normal-collector bitmap/count cleanup, full
  64-slice PageMap release, and retained collection failure. The corresponding
  `dynamic_thread_exit_mapped_one_block_non_direct_small_handoff_releases_after_its_final_free`,
  `dynamic_thread_exit_mapped_one_block_non_direct_small_handoff_rejects_direct_small_before_detach`,
  and `dynamic_thread_exit_mapped_one_block_non_direct_small_handoff_retains_collection_failure`
  prove normal-collector terminal release, direct-small refusal with its
  complete cache image unchanged, and retained collection failure for the
  separate non-direct-small class.
  `dynamic_thread_exit_mapped_one_block_direct_small_handoff_releases_after_its_final_free`,
  `dynamic_thread_exit_mapped_one_block_direct_small_handoff_refuses_stale_direct_cache_before_detach`,
  and `dynamic_thread_exit_mapped_one_block_direct_small_handoff_retains_collection_failure`
  prove the partial-collector terminal release, wholly pre-detach stale-cache
  refusal, direct-range clearing before page-count detach, and retained
  collection failure for the separate direct-small class. The two-block-medium
  `dynamic_thread_exit_mapped_two_block_medium_handoff_keeps_first_free_mapped_then_releases`,
  `dynamic_thread_exit_mapped_two_block_medium_handoff_rejects_one_live_block_before_detach`,
  `dynamic_thread_exit_mapped_two_block_medium_handoff_rejects_three_live_blocks_before_detach`,
  `dynamic_thread_exit_mapped_two_block_medium_handoff_rejects_another_page_before_detach`,
  and `dynamic_thread_exit_mapped_two_block_medium_handoff_retains_collection_failure`
  prove the two-free `UnownedMapped` then `Empty` state transition, dynamic
  bitmap/count preservation then cleanup, wholly pre-detach live-count and
  sole-page refusals, and retained post-TLS collection poison. The distinct
  mapped-medium-pair
  `dynamic_thread_exit_mapped_medium_pair_route_releases_distinct_bin_pages_in_source_order`,
  `dynamic_thread_exit_mapped_medium_pair_route_rejects_a_non_pair_before_detach`,
  and `dynamic_thread_exit_mapped_medium_pair_route_retains_force_collection_failure`
  prove the exact distinct-bin `{2, 1}` source image, bin-order mapped
  publication, PageMap-selected `StillLive -> ReleasedPage -> Released`
  lifecycle, PageMap/bitmap/count cleanup one member at a time, wholly
  pre-detach non-pair refusal, and retained force-collection poison. The
  distinct two-block large
  `dynamic_thread_exit_mapped_two_block_large_handoff_keeps_first_free_mapped_then_releases_complete_span`,
  `dynamic_thread_exit_mapped_two_block_large_handoff_rejects_one_live_block_before_detach`,
  `dynamic_thread_exit_mapped_two_block_large_handoff_rejects_three_live_blocks_before_detach`,
  `dynamic_thread_exit_mapped_two_block_large_handoff_rejects_another_page_before_detach`,
  `dynamic_thread_exit_mapped_two_block_large_handoff_rejects_medium_before_detach`,
  `dynamic_thread_exit_mapped_two_block_large_handoff_rejects_singleton_before_detach`,
  `dynamic_thread_exit_mapped_two_block_large_handoff_refuses_stale_direct_cache_before_detach`,
  `dynamic_thread_exit_mapped_two_block_large_handoff_retains_collection_failure`,
  `dynamic_thread_exit_mapped_two_block_large_handoff_retains_false_collection_failure`,
  and `dynamic_thread_exit_mapped_two_block_large_handoff_retains_post_force_shape_mismatch`
  prove the normal large collector's `2 -> 1 -> 0` state transition, dynamic
  bitmap/count and complete 64-slice PageMap preservation after the first
  free, terminal full-span release, wholly pre-detach cardinality/class/
  direct-cache/sole-page refusals, and retained post-TLS collection or
  post-collection-shape poison.
  The distinct
  two-block non-direct-small
  `dynamic_thread_exit_mapped_two_block_non_direct_small_handoff_keeps_first_free_mapped_then_releases`,
  `dynamic_thread_exit_mapped_two_block_non_direct_small_handoff_rejects_one_live_block_before_detach`,
  `dynamic_thread_exit_mapped_two_block_non_direct_small_handoff_rejects_three_live_blocks_before_detach`,
  `dynamic_thread_exit_mapped_two_block_non_direct_small_handoff_rejects_another_page_before_detach`,
  `dynamic_thread_exit_mapped_two_block_non_direct_small_handoff_rejects_direct_small_before_detach`,
  and `dynamic_thread_exit_mapped_two_block_non_direct_small_handoff_retains_collection_failure`
  prove the normal small collector's two-free `UnownedMapped` then `Empty`
  transition, one-slice dynamic bitmap/count preservation then cleanup,
  pre-detach live-count, sole-page, and direct-small class refusals, and
  retained post-TLS collection poison. The distinct two-block direct-small
  `dynamic_thread_exit_mapped_two_block_direct_small_handoff_keeps_partial_head_mapped_then_releases`,
  `dynamic_thread_exit_mapped_two_block_direct_small_handoff_refuses_stale_direct_cache_before_detach`,
  `dynamic_thread_exit_mapped_two_block_direct_small_handoff_rejects_one_live_block_before_detach`,
  `dynamic_thread_exit_mapped_two_block_direct_small_handoff_rejects_three_live_blocks_before_detach`,
  `dynamic_thread_exit_mapped_two_block_direct_small_handoff_rejects_non_direct_small_before_detach`,
  `dynamic_thread_exit_mapped_two_block_direct_small_handoff_rejects_another_page_before_detach`,
  and `dynamic_thread_exit_mapped_two_block_direct_small_handoff_retains_collection_failure`
  prove the direct partial collector's `used == 2` head lag across the first
  `UnownedMapped` free, final `Empty` release, direct-range clearing before
  page-count detach, wholly pre-detach stale-cache/live-count/class/sole-page
  refusals, and retained post-TLS collection poison. The raw
  `mapped_direct_one_block_owner_exit_free_collects_its_final_head_then_releases`
  and
  `mapped_direct_one_block_owner_exit_free_rejects_small_geometry_without_source_reserve`
  regressions prove final-head consumption and the pinned `reserved >= 16`
  boundary below the dynamic owner-exit API.
  `dynamic_thread_exit_force_collects_a_retired_regular_page_after_tls_clear`
  proves the post-TLS force-retirement release happens before that same
  teardown. The image-boundary regressions
  `dynamic_arena_pages_aligned_metadata_failure_leaves_slot_null_and_retries`,
  `dynamic_arena_pages_nonempty_teardown_rejects_without_root_or_slot_mutation`,
  `dynamic_arena_pages_rejects_cross_heap_removal_and_retains_exact_slot`, and
  `dynamic_arena_pages_slot_publish_failure_retains_typed_owner_terminally`,
  and `dynamic_arena_pages_reject_unbound_or_foreign_arena_subprocess_before_allocation`
  prove the private image's retry, pre-mutation, exact-Heap, source-identity,
  and terminal ownership boundaries.
  `meta::tests::released_capability_cannot_project_any_safe_typed_image` and
  `tls_projection_cannot_be_reinterpreted_as_dynamic_arena_or_bitmap_image`
  prove released capabilities cannot form safe byte references and an exact
  size-coincident dynamic TLS backing cannot become an arena-pages or bitmap
  image;
  `tld::tests::dynamic_teardown_releases_registration_before_busy_lock_poison`
  proves the source live-count order across an invalid quiescence boundary.
  The remaining dynamic attachment tests prove regular-slot
  publication, unrelated-root preservation, pre-mutation no-page rejection,
  exact list membership, ticket-zero refusal, and valid release order.
- **Decision/removal:** accepted until a complete dynamic heap/Theap, general
  cached-root switching/reference, private-lock retry, public routing,
  general abandonment, pthread/process lifecycle, and allocator integration design can
  distinguish all failures and reach full source shutdown. It does not
  authorize pointer reconstruction,
  lock stealing, arbitrary predecessor restoration, implicit lease drop,
  post-publication rollback, or a false registration/key decrement.

### `CRABC-MI-RANDOM-WEAK-EXPANSION` — accepted degraded-entropy substitution

- **Upstream/Rust:** `src/random.c:_mi_os_random_weak` and
  `mi_random_init_ex` / `random::WeakObservations::expand_into`.
- **Category:** allocator random-state behavior only after `getrandom` errors
  or short reads; it has no C ABI surface and is not part of the deterministic
  allocation traces.
- **Difference:** pinned C repeatedly applies its local
  `_mi_random_shuffle` core to ASLR/time material. The project crypto policy
  forbids maintaining that PRNG/DRBG core. Rust serializes the same degraded
  context-address/time/identity observations plus the selected initializer's
  fixed-zero source extra seed, then asks approved RustCrypto
  `ChaCha20LegacyCore` for one domain-separated block to form the weak key.
  It preserves the source continuation, weak flag, reinitialization, and
  original-ChaCha context lifecycle; it does not claim to add entropy.
- **Evidence:** `random::tests::weak_observations_have_a_dependency_owned_deterministic_expansion`
  fixes the replacement vector. The entropy fault regression proves error
  continuation and weak reinitialization, while
  `normal_entropy_initialization_treats_a_short_fill_as_weak` fixes the short
  read (`Ok(false)`) classification. The C/Rust M1 state trace exactly compares
  every non-weak-key state fact for split, zero-result retry, forced weak
  initialization, and a strong reinit no-op. Exact C weak-key/output comparison
  is intentionally inapplicable because both source paths consume ASLR/time
  and use different approved cores; no random cookie is a deterministic
  valid-program oracle. The automatic-process reinit caller and entropy-failure
  diagnostic remain explicit lifecycle/diagnostics exclusions. The static
  ticket-zero Theap exercises this path; performance remains unqualified.
- **Decision/removal:** accepted because the source-local cryptographic core
  cannot enter this repository. It remains until the pinned upstream changes
  its weak path or the project crypto boundary is explicitly changed; it does
  not authorize a local replacement implementation.

## Entry requirements

Each entry must state:

- a stable difference identifier and status (`observed`, `pending`, `accepted`,
  or `rejected`);
- the upstream source path/function or type and the Rust module/function;
- whether the difference affects engine semantics, C ABI integration,
  configuration, performance, diagnostics, or invalid-use handling;
- a minimal reproducer and exact-C differential result for valid programs;
- its written design note, when it is algorithmic or behavioral;
- Linux/AArch64 performance and memory evidence; and
- the decision and conditions that would remove the difference.

`crabc-libc` ownership of C ABI and `errno`, and direct crabc lifecycle wiring
for threads and fork, are integration boundaries rather than implicit
differences. They still require tests. Invalid use must not be copied merely to
reproduce C memory unsafety; document a deliberate safe difference here if one
is necessary.

An entry cannot replace the exact pinned C implementation as a differential
oracle or justify a runtime fallback. Accepted differences require the design,
differential, and performance evidence specified in
[`docs/design/allocator.md`](../../docs/design/allocator.md).
