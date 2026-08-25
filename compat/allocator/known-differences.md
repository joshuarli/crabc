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
  collection, abandonment integration beyond one consuming dynamic mapped
  regular handoff and the separately recorded later-main all-free drain,
  general owner exit, pthread lifecycle, and
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
  later-main all-free exit drain invokes true force without adding a general
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

### `CRABC-MI-PROCESS-PAGE-MAP-COLD-ROOT` — accepted incomplete process-owner boundary

- **Upstream/Rust:** `src/page-map.c:228-365`, especially static
  `mi_page_map_empty`, `__mi_page_map`, `mi_page_map_init_once`, and
  `_mi_page_map_init`, plus `src/subproc.c:253-255`; represented by
  `process_page_map::ProcessPageMapStorage`, `ProcessPageMapLease`, and
  `ProcessPageMapMutationLease` over `page_map::PageMap`.
- **Category:** private incomplete process-initialization and page-owner
  boundary. It has no C ABI surface or valid allocation-trace differential
  entry.
- **Difference:** C begins with a non-null static empty page map so early
  `free(NULL)` lookup remains valid, then its once body swaps in the mapped
  root. The Rust owner begins cold with no root and has no free/lookup route
  while cold. It freezes one `MemoryConfig` and selected `MainSubprocess`,
  constructs the map in its final slot, and Release-publishes its root exactly
  once. Its current entry consumers are typed ticket-zero and later-thread
  page engines: `ProcessPageMapMutationLease` holds a nonrecursive private lock
  for one complete engine and joined scoped-producer lifetime, so no second
  Rust route may overlap plain map entries. That is a deliberate bounded
  substitute for neither C's empty root nor its general concurrent consumers. C's once
  helper consumes an allocation failure yet later calls cannot report that
  failed body through a typed result; Rust instead terminally poisons the
  unpublished owner and rejects later initialization. Dropping an unfinished
  mutation lease likewise poisons the root rather than allowing a later owner
  to treat retained entries as a fresh map.
- **Evidence:**
  `process_page_map::tests::process_map_publishes_one_stable_root_for_its_selected_main_subprocess`
  proves frozen identity/configuration and stable root reuse;
  `concurrent_process_map_initializers_share_the_one_release_published_root`
  makes the second map reservation fail and proves all workers observe the one
  publication; `page_lifecycle_is_exclusive_and_an_unfinished_owner_poisoned_the_root`
  proves the nonrecursive lifecycle and terminal drop boundary; and the three
  mapping/commit-failure regressions prove the no-root terminal failure edge.
  `main_static_page::tests::unfinished_static_page_engine_poison_retains_the_page_and_process_map_owner`
  and `main_heap_page::tests::unfinished_later_page_engine_poison_retains_the_attachment_and_process_map`
  additionally prove that a poisoned root retains a live registration rather
  than erasing it. Exact C differential comparison is inapplicable until a
  real process lifecycle and allocator ABI exist.
- **Decision/removal:** accepted until complete process initialization supplies
  the C empty-root behavior where required, owns startup selection and general
  map concurrency, supports the remaining page/producer owners, and proves
  process-main quiescence/root clear/destruction. It does not authorize a
  null-root lookup, a retryable global mapping owner, a private alternate map
  for shared threads, or page-bearing runtime integration beyond the recorded
  bounded ticket-zero and sequential later-thread slices.

### `CRABC-MI-PROCESS-SHARED-ONE-ARENA-SIDECAR` — accepted incomplete arena boundary

- **Upstream/Rust:** `src/arena.c:1573-1611,1676-1791,1794-1871`, especially
  `mi_arenas_add`, `mi_arena_initialize`, and `mi_manage_os_memory_ex2`;
  represented by `process_arena::ProcessSharedArenaStorage` and
  `ProcessPageArenaLease` over the existing `ArenaRegistry`,
  `ManagedExternalRegion`, `Mapping`, and `ProcessPageMapLease` boundaries.
- **Category:** private incomplete process-arena ownership only. It has no C
  ABI surface or valid allocation-trace differential entry.
- **Difference:** C may manage arbitrary external spans (including split
  sub-arenas) and its later reserve path chooses mappings through live option
  policy. Rust currently admits exactly one caller-selected, complete aligned
  mapping whose page size/configuration/main-subprocess identity match the
  already Release-published process page map. A pre-publication rejection
  returns that `Mapping` to the caller instead of silently unmapping it,
  because this is the lower `mi_manage_os_memory_ex2` boundary and no Rust
  `mi_reserve_os_memory_ex2` policy owner exists yet. Once published, the map
  and in-place arena are process-lived. The typed pair may now be consumed by
  separately recorded ticket-zero or one sequential later-thread page owners:
  each installs this arena's embedded `pages_main`, registers/releases ordinary
  pages, and retains a joined scoped producer. That does not create general
  arena selection, multiple/sub-arena support, concurrent/general later-thread
  ownership, root clear, or destruction.
- **Evidence:**
  `process_arena::tests::shared_owned_arena_binds_to_the_release_published_map_and_selected_subprocess`
  proves exact root/configuration/subprocess pairing, registry publication,
  retained mapping geometry, and an empty page map. The setup-failure test
  proves an inaccessible backing returns unchanged while the global root stays
  ready, including a foreign retry that cannot consume the selected cold pair;
  `foreign_map_or_subprocess_rejects_before_mapping_or_registry_mutation`
  proves a ready owner cannot accept a foreign process map.
  `main_static_page::tests::main_static_page_allocator_binds_the_in_place_main_arena_bitmap_before_page_map_publication`
  proves the paired static owner uses the arena's actual embedded bitmap and
  returns its slice after map removal; the later-thread page-engine regression
  proves the same bitmap is selected by the shared main Heap.
- **Decision/removal:** accepted until a source-shaped reserve policy and
  general page-bearing fresh-allocation/owner-exit protocol can connect this
  exact arena to multiple source owners and shutdown quiescence. It does not
  authorize eager startup reservation, a fixed reserve size, generic arena
  management, raw page-map access, or process teardown.

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
- **Difference:** source `mi_process_init_once` first establishes options/OS,
  initializes the main heap before the page map, then initializes the thread;
  the Rust slice deliberately does not claim that coordinator. Its caller must
  already have selected a live ticket-zero attachment and independently
  published a matching one-arena map/root/configuration/subprocess pair. The
  session rejects a foreign subprocess before static-image, map, or arena
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
- **Decision/removal:** accepted until a source-shaped process-initialization
  coordinator owns options/OS/main-heap/page-map/thread ordering, general
  later-thread page owners, automatic reservation/multi-arena routing,
  abandonment and owner-exit traversal, process destruction, pthread/TLS
  hooks, and public allocation routing. It does not authorize treating this
  test-only private owner as a default allocator backend.

### `CRABC-MI-LATER-MAIN-PROCESS-PAGE-LIFECYCLE` — accepted bounded page-owner slice

- **Upstream/Rust:** later-thread `_mi_thread_init_with_heap(mi_heap_main())`
  setup and `_mi_thread_done` ordering in `src/init.c:236-282,305-360,377-421,
  448-481`; `_mi_theap_collect_abandon`'s visit order in
  `src/theap.c:89-152`; force `_mi_page_free_collect` in
  `src/page.c:214-243`; main-heap `pages_main` selection in
  `src/arena.c:674-723`; fresh arena-page publication in
  `src/arena.c:781-821,951-1114`; and all-free release in
  `src/arena.c:1240-1282`; represented by
  `main_heap_page::MainHeapThreadProcessPageAllocator`,
  `main_heap_page::MainHeapThreadProcessPageExitDrain`,
  `main_heap_thread::{MainHeapThreadPageSession, MainHeapThreadPageDrainSession}`,
  `process_arena::ProcessPageArenaLease`, and
  `process_page_map::ProcessPageMapMutationLease`.
- **Category:** crate-private, one sequential later-thread page owner only. It
  has no C ABI surface or valid allocation-trace differential entry.
- **Difference:** C permits normal concurrent page-map consumers and later
  threads enter through its complete process initializer. Rust requires an
  already selected ticket-zero static attachment plus one current later
  metadata TLD/Theap and independently published matching map/arena pair. It
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
  then retains that page rather than queue-detaching or abandoning it; only an
  all-free pass lets `finish_after_page_drain` reset default/cached and detach
  the lists/TLD. Any force/release failure remains terminally retained. Source deferred callbacks, arena
  collection, statistics merge, general regular/unmapped/huge abandonment,
  later free/reclaim, and retry/reuse of a post-drain normal allocator remain
  absent. A dropped unfinished engine or drain poisons the later attachment and
  map root rather than fabricating cleanup.
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
  exit; and
  `unfinished_later_page_engine_poison_retains_the_attachment_and_process_map`
  proves terminal retention rather than forged thread cleanup.
- **Decision/removal:** accepted until a source-shaped process-init coordinator
  owns startup selection/order, the PageMap supports its source concurrent
  consumers, automatic reservation/multi-arena routing exists, and the
  remaining `_mi_theap_collect_abandon` nonempty-page traversal plus
  pthread/TLS integration is proved. It does not authorize concurrent
  later-thread allocation routing, a public thread attachment API, process
  shutdown, or default backend use.

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
  registry, nonempty-page traversal, `pthread`/TLS callback, process shutdown,
  or public routing. Fallible private lock or metadata errors after source
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
  nonempty-page paths, after which the real crabc pthread/TLS integration can invoke that completed
  lifecycle. It does not authorize a raw shared-Heap pointer, a user-visible
  attachment API, a fake pthread hook, or treating a retained owner as safely
  torn down.

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
  remains bounded private routing, not a general dynamic allocation,
  abandonment, pthread, fork, or process lifecycle. After the regular backing
  is cleared, its `DrainingPages` owner first force-collects an already-retired
  all-free regular page. Its one additional live-page transition is a full
  one-block dynamic arena singleton, false-collected, detached from `BIN_FULL`,
  unmapped-abandoned, and retained until its exact client free takes the
  failed-reclaim all-free release. The source force-only local-list append is
  unreachable under the `reserved == used == 1`, no-producer proof; the raw
  free-list primitive separately ports and tests it without broadening this
  drain. The successful drain then permits the existing cached-root/list/key
  teardown.
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
  reabandon / unown selection. Its only raw terminal-release owner is the
  post-TLS singleton above; it does not route general policy through either
  dynamic handoff. Regular/nonempty unmapped, non-arena, foreign, and general
  full/singleton/huge pages still lack lifecycle integration or terminal reuse.
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
  regression proves regular-slot clearing precedes abandonment, failed reclaim
  is real rather than injected, raw all-free release clears the full PageMap
  span and dynamic ordinary bit, and attachment teardown can then finish.
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
