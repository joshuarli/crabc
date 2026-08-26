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
  regular handoff and the separately recorded later-main all-free scan plus
  its eight sole-page handoffs and bounded aggregate regular-pages traversal,
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

- **Upstream/Rust:** `src/init.c:184-214,305-360,536-592` (`mi_heap_main_init_once`,
  `_mi_thread_init_with_heap`, and `mi_process_init_once`) and
  `src/subproc.c:29-46,95-101`; represented by
  `process_init::ProcessMainInitializationStorage`,
  `main_theap::MainStaticHeapFoundation`,
  `meta::MetaAllocator::prepare_for_main_subprocess`,
  `process_page_map::ProcessPageMapStorage`, and the
  `subproc::MainStaticBootstrapSelection` selector.
- **Category:** crate-private source-order startup boundary. It has no C ABI
  surface or valid allocation-trace differential entry.
- **Difference:** the Rust coordinator proves the central source order—static
  Heap, detached metadata readiness, global PageMap, then ticket-zero
  TLD/Theap/default/fast roots—but accepts a frozen `MemoryConfig` instead of
  running source option/OS initialization. It exposes only immutable ready
  witnesses, does not reserve the process-shared arena, initialize pthread or
  TLS keys, route allocations/frees, coordinate full concurrent startup, or
  destroy/restart the process. Metadata's private map/arena stays private.
  A preflight rejection remains cold; any failure after static selection is
  terminally retained rather than replaying a partial static image. C's static
  empty PageMap root remains absent.
- **Evidence:**
  `process_init::tests::process_main_initialization_orders_heap_metadata_map_then_ticket_zero_roots`
  proves the source order, distinct metadata/global map identities, default-
  then-fast roots, and no automatic process-shared arena reservation.
  The preflight, metadata-failure, rejected-map, and ready-lease regressions
  prove cold rejection, terminal retention, and immutable root reuse.
  `main_theap::tests::static_heap_foundation_precedes_ticket_zero_tld_theap_and_tls_roots`
  and `subproc::tests::selected_static_bootstrap_cannot_issue_ticket_zero_before_heap_foundation`
  prove the two prerequisite boundaries.
- **Decision/removal:** accepted until source options/OS and TLS-key/local
  stages, the C empty-root policy, concurrent/general thread and map startup,
  automatic arena policy, routing, shutdown, and fork repair have their own
  proved owners. It does not authorize treating this coordinator as a complete
  process initializer or public allocator startup API.

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
  `process_init::tests::process_main_initialization_orders_heap_metadata_map_then_ticket_zero_roots`
  proves the coordinator publishes this distinct root before ticket-zero TLS
  roots. `main_static_page::tests::unfinished_static_page_engine_poison_retains_the_page_and_process_map_owner`
  and `main_heap_page::tests::unfinished_later_page_engine_poison_retains_the_attachment_and_process_map`
  additionally prove that a poisoned root retains a live registration rather
  than erasing it. Exact C differential comparison is inapplicable until a
  real process lifecycle and allocator ABI exist.
- **Decision/removal:** accepted until the remaining full process lifecycle
  supplies the C empty-root behavior where required, general map concurrency,
  the remaining page/producer owners, and process-main quiescence/root
  clear/destruction. It does not authorize a
  null-root lookup, a retryable global mapping owner, a private alternate map
  for shared threads, or page-bearing runtime integration beyond the recorded
  bounded ticket-zero and sequential later-thread slices.

### `CRABC-MI-PROCESS-SHARED-ONE-ARENA-SIDECAR` — accepted incomplete arena boundary

- **Upstream/Rust:** `src/arena.c:1573-1611,1676-1791,1794-1871`, especially
  `mi_arenas_add`, `mi_arena_initialize`, and `mi_manage_os_memory_ex2`;
  represented by `process_arena::ProcessSharedArenaStorage` and
  `process_owned_mapping_commit` / `ProcessPageArenaLease` over the existing
  `ArenaRegistry`, `ManagedExternalRegion`, `Mapping`, and
  `ProcessPageMapLease` boundaries.
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
  and in-place arena are process-lived. A reserved mapping enters its final
  sidecar slot before in-place initialization, so its retained callback can
  commit metadata and later selected/page-metadata ranges through the exact
  `Mapping`; it conservatively reports nonzero and the frozen Linux decommit
  path reports no recommit requirement. An injected metadata-commit failure
  returns that exact mapping with an empty registry and COLD sidecar, while the
  selected map/subprocess pair remains available for a matching retry. This is
  not source page-on-demand allocation policy: its typed pair can make one
  range-checked direct page-area commit for an already-selected extension, but
  does not select on-demand commitment, maintain `slice_pcommitted`, or perform
  failed-commit `_mi_page_abandon` reabandonment. The typed pair may now be
  consumed by
  separately recorded ticket-zero or one sequential later-thread page owners:
  each installs this arena's embedded `pages_main`, registers/releases ordinary
  pages, and retains a joined scoped producer. That does not create general
  arena selection, multiple/sub-arena support, concurrent/general later-thread
  ownership, root clear, or destruction.
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
  ThreadExitMappedRegularPostExitAdoptError}`,
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
  that release. A separate homogeneous full-singleton aggregate route accepts
  two or more full arena `PageKind::Singleton` members in `BIN_FULL` only when
  every direct slot and other queue is empty and every member has one rounded
  block size, `reserved == used == 1`, a zero retirement countdown, an empty
  local free list, and an exact paired-arena span. It force- then
  false-collects, detaches, and ordinary-unmapped-abandons every member before
  old-Theap/TLD teardown. Its route keeps no raw list or static-main
  bitmap/count pair: each canonical one-block free re-resolves PageMap
  membership, must take the raw empty failed-reclaim outcome, then releases
  that member in PageMap -> main bitmap first-bit -> metadata -> arena-slice
  order. Sole members, heterogeneous rounded singleton sizes, non-singletons,
  OS members, allocation-time adoption/reclaim/requeue, scanning, and
  concurrent routing remain absent. A separate homogeneous full-medium aggregate route accepts two
  or more arena `PageKind::Medium` members in `BIN_FULL` only when every direct
  slot and other queue is empty and every member has one rounded block
  size/static-main bin, `reserved > 1`, `used == reserved`, a zero retirement
  countdown, and one paired-arena span. It force- then false-collects,
  detaches, and ordinary-unmapped-abandons every member before old-Theap/TLD
  teardown. Its route retains no raw member list: each sequential client free
  re-resolves PageMap membership, holds the one preselected bitmap/count pair,
  and uses the claimed abandoned identity to select the source unmapped or
  mapped tail. Each terminal release removes only that member through PageMap
  -> main bitmap -> metadata -> slice; a sole full page rejects before
  mutation. The separate homogeneous full-large aggregate accepts only the
  corresponding `PageKind::Large` members, with the same complete preflight
  plus every member's exact 64-slice arena/PageMap span; terminal release
  proves and removes that complete span. A fourth homogeneous full
  non-direct-small aggregate accepts only two or more same-bin ordinary
  `PageKind::Small` arena members with `SMALL_SIZE_MAX < block_size <=
  SMALL_MAX_OBJ_SIZE`, every direct slot empty, zero retirement countdowns,
  empty local free lists, and one paired-arena slice per member. It preserves
  source force -> false collection -> ordinary-bin removal with the proven
  no-op direct-cache update -> page-count detach -> ordinary unmapped
  abandonment, then uses free.c's normal collector to re-resolve, reabandon,
  and release each one-slice member independently. A fifth homogeneous full
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
  release. All five aggregate routes reject heterogeneous full queues before
  collection. Stale/mixed direct-cache images, remote-force nonfull state,
  allocation-time adoption/reclaim/requeue, and concurrent routing remain
  absent. Distinct source-specific predecessors accept one sole full
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
aggregate-registry adoption remain absent.

  `abandon_mapped_regular_pages_to_process_route` is a distinct aggregate
  transition, not a local repetition of that sole-page handoff. Its complete
  structural preflight rejects before mutation unless every direct slot is
  the source-derived queue-head image and every queued page is a nonfull
  regular small, medium, or large arena page. A direct small member also
  requires `reserved >= 16` for the source partial collector. It proves the
  complete bounded doubly linked queue image before the unsafe removal kernel:
  zero-count queues have null endpoints, nonempty heads have null predecessors,
  every successor points back to its predecessor, and the counted forward walk
  ends at the registered null-terminated tail. It accepts an empty page only
  with a nonzero source retirement countdown. It then ports
  `_mi_theap_collect_retired(theap, true)`'s regular-bin release before source
  force collection, ordinary all-free release, false collection, queue detach,
  direct-cache refresh, page-count detach, and mapped identity/bit/count/unown
  for each live survivor. Its typed
  registry retains no old-Theap pointer or raw page list: PageMap registration
  plus the exact static-main bitmap/count pair are membership, and the count
  decreases only after a full PageMap -> main bitmap -> metadata -> slice
  release. A free chooses its bin only after acquiring the source low owner
  bit; a nonempty result keeps the pairing, and a terminal free re-derives its
  complete regular span before release (one slice for small, 8 for medium, 64
  for large).
  A retired/force-empty traversal returns the ordinary drain. If that completed
  source traversal releases every other member and leaves exactly one
  initially-nonfull medium with an immediate local head, it captures that
  exact page/span/bin witness before registry construction and returns the
  established one-page mapped handoff instead. Reclaim revalidates the head,
  so this edge cannot extend, commit, scan, or take a fresh-page fallback.
  Fresh engines may serialize independent map operations between frees, but no
  current engine receives an adoption, reclaim, or requeue capability for an
  aggregate registry member, including one reduced to a single member by a
  later client free. Other
  full/singleton/unmapped/huge/foreign pages, malformed direct-cache images, concurrent
  client-free routes, source deferred
  callbacks, arena collection, statistics merge, and retry/reuse as a normal
  allocator remain absent. A dropped unfinished engine, drain, or route
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
  `later_thread_exit_mapped_one_block_handoff_releases_after_its_final_free`
  proves main-bitmap/count publication, retained PageMap registration,
  mapped-bit quiescence/count consumption, empty-before-reclaim release, and
  subsequent root/list/TLD
  teardown; `later_thread_exit_mapped_one_block_handoff_rejects_before_detach_when_another_page_is_live`
  proves the medium handoff does not skip another live page;
  `later_thread_exit_full_singleton_pages_route_releases_each_same_size_page`
  proves two full same-size arena singleton members detach before old-Theap/TLD
  teardown, remain PageMap-routable without a static-main abandoned bitmap,
  and release independently in complete PageMap -> first ordinary bitmap bit ->
  metadata -> arena-slice order; its siblings
  `later_thread_exit_full_singleton_pages_route_rejects_a_sole_singleton_before_mutation`,
  `later_thread_exit_full_singleton_pages_route_rejects_mixed_sizes_before_mutation`,
  and `later_thread_exit_full_singleton_pages_route_retains_a_collection_failure`
  prove sole and heterogeneous rounded singleton input reject before mutation
  and an injected force-collector failure retains the complete source drain;
  and
  `later_thread_exit_full_medium_route_reabandons_after_mostly_used_frees`
  proves old-Theap/TLD teardown precedes client frees, the full medium page
  stays PageMap-routable but unmapped through its exact mostly-used threshold,
  then publishes the paired static-main bitmap/count before its mapped tail
  clears all terminal ownership; and
  `later_thread_exit_full_medium_pages_route_reabandons_each_same_bin_page_then_releases`
  proves two same-bin full medium members detach before old-Theap/TLD teardown,
  independently cross their source unmapped-to-mapped threshold, preserve the
  paired static-main count, and release one PageMap span at a time; its sibling
  `later_thread_exit_full_medium_pages_route_rejects_a_sole_full_medium_before_mutation`
  proves the aggregate boundary never overlaps the established sole-page
  route. The corresponding
  `later_thread_exit_full_large_pages_route_reabandons_each_same_bin_page_then_releases`
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
  `later_thread_exit_full_direct_small_pages_route_preserves_partial_head_then_releases_each_member`
  proves two ordinary-bin full direct-small members retain the exact rounded
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
  final normal target release.
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
  `later_thread_exit_mapped_regular_pages_route_rejects_malformed_direct_image_before_mutation`
  proves a stale direct-small cache slot rejects before retirement, collection,
  queue removal, or PageMap mutation; and
  `later_thread_exit_mapped_regular_pages_route_rejects_malformed_prev_before_mutation`
  proves a malformed predecessor rejects before retirement, collection, queue
  removal, or PageMap mutation; and
  `later_thread_exit_mapped_regular_pages_route_refuses_full_non_direct_small_before_detach`
  proves the nonfull aggregate rejects a full small page before source
  collection or detachment; and
  `later_thread_exit_mapped_regular_pages_route_selects_each_large_page_bin_after_claim`
  proves two distinct large bins select their paired static-main capability
  only after the source low owner-bit claim; and
  `later_thread_exit_mapped_regular_pages_route_releases_large_page_span`
  proves the 64-slice large span remains PageMap-registered until its final
  client free, then unregisters and returns every slice; and
  `later_thread_exit_mapped_regular_pages_route_returns_drained_after_large_force_collection`
  proves a force-empty large traversal returns the ordinary drain and releases
  its full span before route construction; and
  `unfinished_later_page_engine_poison_retains_the_attachment_and_process_map`
  proves terminal retention rather than forged thread cleanup.
- **Decision/removal:** accepted until the PageMap supports its source
  concurrent consumers, automatic reservation/multi-arena routing exists, and
  the remaining heterogeneous-full/singleton/unmapped/huge owner-exit
  traversal plus pthread/TLS integration is proved.
  It does not
  authorize concurrent later-thread allocation routing, a public thread
  attachment API, process shutdown, or default backend use.

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
  with one rounded block size, `reserved == used == 1`, zero retirement
  countdown, empty local free lists, exact arena spans, and every other
  queue/direct entry empty. It force- then false-collects and detaches each
  member before unmapped abandonment. The returned
  `DynamicThreadExitFullSingletonPagesRoute` retains the original drain rather
  than a raw member list or dynamic bitmap/count pair; every sequential
  canonical free re-resolves PageMap, accepts only the raw empty
  failed-reclaim result, and releases its exact PageMap -> dynamic ordinary-bit
  -> metadata -> arena-slice span. The final free returns an empty drain for
  existing teardown. A sole, mixed-size, non-singleton, OS-backed, existing
  queue/direct, allocation-time, reclaim/adoption/requeue, scan, or concurrent
  case remains absent, while a collection failure retains the drain.
  `DynamicThreadExitDrain::abandon_full_medium_pages` is a second separate
  sequential dynamic aggregate, not a general `BIN_FULL` traversal: it
  requires two or more full `MemoryKind::Arena` `PageKind::Medium` members with
  one rounded block size and regular bin, `reserved > 1`, `used == reserved`,
  zero retirement countdown, empty local free lists, exact arena spans, the
  matching dynamic bitmap/count capability for every member, and every other
  queue/direct entry empty. It force- then false-collects and detaches each
  member before unmapped abandonment. The returned
  `DynamicThreadExitFullMediumPagesRoute` retains the original drain rather
  than raw member pointers or per-member mapped state; every sequential
  canonical free re-resolves PageMap, uses the member's abandoned identity to
  select its unmapped or mapped full-medium failed-reclaim tail, and releases
  only that member through PageMap -> dynamic ordinary bit -> metadata -> arena
  slices. The final free returns an empty drain for existing teardown. A sole,
  mixed-size/class, non-medium, OS-backed, existing queue/direct,
  allocation-time, reclaim/adoption/requeue, scan, producer, or concurrent case
  remains absent, while a collection failure retains the drain.
  `DynamicThreadExitDrain::abandon_full_large_pages` is a third separate
  sequential dynamic aggregate, not a general `BIN_FULL` traversal: it
  requires two or more full `MemoryKind::Arena` `PageKind::Large` members with
  one rounded block size and regular bin, `reserved > 1`, `used == reserved`,
  zero retirement countdown, empty local free lists, the matching dynamic
  bitmap/count capability for every member, every other queue/direct entry
  empty, and every member's exact 64-slice arena/PageMap span. It force- then
  false-collects and detaches each member before unmapped abandonment. The
  returned `DynamicThreadExitFullLargePagesRoute` retains the original drain
  rather than raw member pointers or per-member mapped state; every sequential
  canonical free re-resolves PageMap, uses the member's abandoned identity to
  select its unmapped or mapped full-large failed-reclaim tail, and releases
  only that member through PageMap -> dynamic ordinary bit -> metadata -> its
  complete 64-slice arena span. The final free returns an empty drain for
  existing teardown. A sole, mixed-size/class, non-large, OS-backed,
  malformed-span, existing queue/direct, allocation-time,
  reclaim/adoption/requeue, scan, producer, or concurrent case remains absent,
  while a collection failure retains the drain.
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
  owners are the post-TLS arena/OS singleton, homogeneous full-singleton,
  full-medium, and full-large aggregates, sole full-medium, full-large,
  full-non-direct-small, and
  full-direct-small handoffs above and the later-main full-medium,
  full-large, and full-non-direct-small routes;
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
  `dynamic_thread_exit_full_singleton_pages_route_rejects_a_sole_singleton_before_mutation`,
  `dynamic_thread_exit_full_singleton_pages_route_rejects_mixed_sizes_before_mutation`,
  and
  `dynamic_thread_exit_full_singleton_pages_route_retains_a_collection_failure`
  regressions prove complete same-size arena-only aggregate preflight,
  one-member-at-a-time PageMap/ordinary-bit/metadata/slice release, wholly
  pre-mutation sole/mixed refusal, and retained dynamic-drain collection
  failure.
  `dynamic_thread_exit_full_medium_pages_route_reabandons_each_same_bin_page_then_releases`,
  `dynamic_thread_exit_full_medium_pages_route_rejects_a_sole_full_medium_before_mutation`,
  `dynamic_thread_exit_full_medium_pages_route_rejects_mixed_full_classes_before_mutation`,
  and
  `dynamic_thread_exit_full_medium_pages_route_retains_a_collection_failure`
  prove complete same-bin medium aggregate preflight, independent
  unmapped-to-mapped reabandonment and PageMap/ordinary-bit/metadata/slice
  release for each member, wholly pre-mutation sole/mixed-class refusal, and
  retained dynamic-drain collection failure.
  `dynamic_thread_exit_full_large_pages_route_reabandons_each_same_bin_page_then_releases`,
  `dynamic_thread_exit_full_large_pages_route_rejects_a_sole_full_large_before_mutation`,
  `dynamic_thread_exit_full_large_pages_route_rejects_mixed_full_classes_before_mutation`,
  and
  `dynamic_thread_exit_full_large_pages_route_retains_a_collection_failure`
  prove complete same-bin large aggregate preflight, independent
  unmapped-to-mapped reabandonment and complete 64-slice
  PageMap/ordinary-bit/metadata release for each member, wholly pre-mutation
  sole/mixed-class refusal, and retained dynamic-drain collection failure.
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
  collection failure for the separate direct-small class. The raw
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
