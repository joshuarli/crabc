# Pinned mimalloc Rust/C known differences

This is the durable register of observable or algorithmic differences between
the incomplete `crabc-mimalloc` Rust port and exact pinned mimalloc v3.5.0 C.
The source pin is defined in
[`crabc-mimalloc/UPSTREAM.md`](../../crabc-mimalloc/UPSTREAM.md).

## Current status

No ordinary allocation-trace difference is recorded. The current Rust crate contains source-mapped
foundations plus a private, explicit single-thread ordinary-allocation
lifecycle across small, medium, large, and singleton pages. Its small path has
exact address-independent trace parity with pinned C v3.5.0, and a separate
51-key exact differential record covers the bounded fundamental page-kind,
calloc, realloc, aligned/offset-aligned, usable-size, preservation, and failure
slice. This includes live arena-backed alignment through 64 KiB and separately
owned OS-aligned singleton mappings below 256 MiB. The lifecycle is not
exported and does not imply parity for the absent process/TLS, general remote-free routing,
teardown, purge, or public-API regions. The private regular-TLS and generic
subprocess-attached/no-theap TLD owners record one internal recovery limitation
in the source map:
`MetaAllocator::free` may report an error after consuming a capability. The
regular owner clears its dynamic root, while the TLD owner has already
invalidated `thread_id`; each terminally poisons rather than retaining a
capability that could name freed storage. This state is not a valid C-program
observable difference and has no C differential entry; a richer metadata-free
result may refine it only when it can prove retained ownership.

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
  pointer. Detached sessions, a producer registry, concurrent queue
  collection, abandonment integration, owner exit, pthread lifecycle, and
  general asynchronous/public free routing remain absent. The caller still
  proves join/quiescence before queue collection because existing queue helpers
  borrow page metadata. Unlike the infallible C collection calls, a Rust
  false-force collection error permanently poisons this private allocator and
  retains the exact page, error, and optional locally popped block; production
  allocation, inspection, free, producer preparation, and collection then all
  reject rather than guessing whether a detached remote list remains owned.
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
  and `main_theap::MainStaticTheapAttachment::begin` /
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
- **Decision/removal:** accepted until complete private-lock, process-init,
  and teardown ownership can prove source-faithful cleanup without aliasing.
  It does not authorize retry, lock stealing, registration decrement, or
  fabricated teardown capability after a partial initialization.

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
  The engine must be consumed by a fully quiescent finish; an unfinished drop,
  retained collection poison, or pending OS unmap failure latches the
  attachment terminally, transfers any pending OS release owner into it, and
  retains the live page/map/resource state rather than claiming teardown. This
  remains bounded private routing, not a general
  dynamic allocation, abandonment, pthread, fork, or process lifecycle.
  Its first dynamic arena page first proves the registry-published arena's
  non-null subprocess identity equals the attachment's selected main
  subprocess, then lazily owns one exact BCHUNK-aligned `mi_arena_pages_t`
  metadata image bound to the exact Heap and one arena slot. The ordinary page
  bitmap is disjoint from
  `Arena::pages_main` for fresh/rollback/release; a test-only abandoned-bin
  witness is not abandonment publication. Image allocation failure before
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
  abandonment, pthread/process lifecycle, and allocator integration design can
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
  context-address/time/identity observations plus the source extra seed, then
  asks approved RustCrypto `ChaCha20LegacyCore` for one domain-separated block
  to form the weak key. It preserves the source continuation, weak flag,
  reinitialization, and original-ChaCha context lifecycle; it does not claim
  to add entropy.
- **Evidence:** `random::tests::weak_observations_have_a_dependency_owned_deterministic_expansion`
  fixes the replacement vector. The entropy fault regression proves error
  continuation and weak reinitialization; the direct primitive contract treats
  a short read as `Ok(false)` on that same branch. Exact C output comparison is
  intentionally inapplicable because both source paths consume ASLR/time and
  no random cookie is a deterministic valid-program oracle. The static
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
