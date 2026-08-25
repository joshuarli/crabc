The crucial framing is: **do not design a new allocator**. Produce a provenance-preserving, semantically faithful Rust port of a fixed upstream mimalloc v3 release, then optimize only where measurement shows the Rust translation diverges. The objective is to remove the C allocator from the production dependency graph while retaining mimalloc’s design, behavior, and performance—not to create “mimalloc-inspired” machinery.

## Handoff — 2026-08-25

The current checkpoint completes the dependency/crypto boundary, dynamic
Theap-to-page-engine binding, private dynamic arena-pages ownership, and two
bounded abandoned-free slices. The consuming mapped regular-page handoff keeps
exact heap-local bitmap/count accounting and can either adopt one exact page
or consume one still-live same-origin client block through
`free.c:mi_free_try_collect_mt`'s `allow_collect=true` branch. The small-page
route preserves the source partial head, requires the source `reserved >= 16`
invariant, clears the map/count before live reassociation, collects again, and
requeues. Its all-free dynamic-arena result now follows the source terminal
order—full PageMap-span unregister, exact heap-local ordinary-bit clear,
metadata retirement, then arena-slice release—and returns a finishable engine.
An existing owner remains a retained terminal handoff.

Separately, `abandoned::free_unmapped_after_failed_reclaim` ports the failed
reclaim tail for a stable initially-unmapped abandoned page: source partial or
full collection, the exact expected-head unown CAS, conflict collection
without a second reclaim attempt, the integer mostly-used reabandon predicate,
and terminal-empty/reabandon/unown selection. Its first lifecycle owner is now
also complete, but deliberately only for one source-reachable case:
`DynamicThreadExitDrain` clears a private dynamic Theap's regular TLS backing,
retains its cached root/lists/page map/arena image, and first force-collects an
already-retired all-free regular page. Its singleton live-page transition accepts one
full one-block arena or OS-aligned singleton. The arena form keeps the existing
heap-local ordinary-bit, metadata, and arena-slice release tail.
`DynamicThreadExitSingletonHandoff` handles the OS form as one
`MemoryKind::Os`, `reserved == used == 1`, `BIN_FULL` singleton whose ordinary
block size may be small: after full-queue/page-count detach it links the exact
page into the dynamic Heap's `os_abandoned_pages` list, then unmapped-abandons
it. Its exact final client free removes that list member before clipped PageMap
unregister, secondary-alias clear, primary-metadata retirement, and mapping
reclaim; a failed `munmap` retains the unique mapping owner terminally. The
source force-only local-list append is unreachable for either
`reserved == used == 1`, no-producer singleton, and a successful drain still
completes the separate cached-root/list/key teardown. This neither scans,
reclaims, requeues, nor generalizes the OS list, and is not general production
free routing or a general thread-exit traversal.

The same post-TLS drain now has three separate mapped regular endpoints.
`DynamicThreadExitDrain::abandon_mapped_one_block` accepts exactly one sole,
nonfull `MemoryKind::Arena` medium page; its sibling
`DynamicThreadExitDrain::abandon_mapped_one_block_non_direct_small` accepts
only a small page with `SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE`;
and `DynamicThreadExitDrain::abandon_mapped_one_block_direct_small` accepts a
small page with `block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, and its
complete rounded source direct-cache range. All require `reserved > 1`,
`used == 1`, and one regular queue member. The non-direct-small class has an
empty source direct-cache image; the direct-small class validates its complete
image before collection and clears that range after queue removal but before
page-count detach. They retain the dynamic arena-pages image after TLS clear
solely to form that exact heap-local `pages_abandoned[bin]` bit plus paired
`Heap::abandoned_count[bin]` capability. Source force then false collection
precedes queue/page-count detach, mapped identity/bit/count publication, and
unown. `DynamicThreadExitMappedOneBlockHandoff` retains the private
source-class witness and admits only its exact final client free: medium and
non-direct small use the normal collector, while direct small consumes its
partial collector head; each must become empty before any reclaim branch,
clear that dynamic bit/count pair, then release PageMap -> dynamic ordinary bit
-> metadata -> arena slices. It cannot reclaim the departed Theap, requeue,
adopt, scan, accept a second free, or generalize dynamic owner exit.

`DynamicThreadExitDrain::abandon_full_medium` is a fourth, disjoint dynamic
owner-exit endpoint. It accepts only a sole full `MemoryKind::Arena` medium
page in `BIN_FULL`, with `reserved > 1`, `used == reserved`, and no direct
cache entry. Source force then false collection precedes full-queue/page-count
detach and ordinary unmapped abandonment. Its
`DynamicThreadExitFullMediumHandoff` carries sequential client frees through
the failed-reclaim tail: they remain unmapped while the source mostly-used
predicate holds, then the first free beyond `reserved / 8` publishes the exact
dynamic `pages_abandoned[bin]` bit plus paired `Heap::abandoned_count[bin]`.
The mapped tail clears that pair before PageMap -> dynamic ordinary bit ->
metadata -> arena-slice release. It cannot reclaim, adopt, requeue, scan, or
cover full non-direct-small/direct-small, large, multi-page, or general dynamic
thread-exit state.

`DynamicThreadExitDrain::abandon_full_non_direct_small` is a fifth, disjoint
dynamic owner-exit endpoint. It accepts only a sole full `MemoryKind::Arena`
small page in its ordinary regular bin, with
`SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE`, `reserved > 1`,
`used == reserved`, `!page_is_in_full`, and an empty direct-cache image.
Source force then false collection precedes regular-bin/page-count detach and
ordinary unmapped abandonment. Its `DynamicThreadExitFullNonDirectSmallHandoff`
carries sequential normal failed-reclaim frees through the same tail: they
remain unmapped while the source mostly-used predicate holds, then the first
free beyond `reserved / 8` publishes the exact dynamic
`pages_abandoned[bin]` bit plus paired `Heap::abandoned_count[bin]`. The mapped
tail clears that pair before PageMap -> dynamic ordinary bit -> metadata ->
arena-slice release. It rejects direct small before collection and cannot
reclaim, adopt, requeue, scan, or cover full medium/direct-small/large,
multi-page, or general dynamic thread-exit state.

The raw owner-local free-list substrate now also ports that source force-only
append: it validates the deferred local chain, appends the old immediate head,
and rejects a malformed cycle before relinking. Ordinary regular/full callers
still select false force; the bounded later-main all-free exit drain now uses
true force after joined remote detachment. That remains a deliberately narrow
release decision, not a general owner-exit traversal or broadened handoff.

The next lifecycle foundation is now also present, with a deliberately no-page
direct finish: `main_heap_thread.rs` ports the ordinary later-thread
`_mi_thread_init_with_heap(mi_heap_main())` branch against the ticket-zero
process-static main Heap. `MainStaticHeapLease` is borrow-tied to the live main
attachment and serializes short shared-Heap projections; each later owner gets
a nonzero metadata TLD and Theap, links it to that main Heap, publishes default
then fast, and after user destructors clears fast, resets default/cached,
detaches heap then TLD lists, and retires metadata. The static owner refuses
teardown while any such Theap remains linked. This proves source root/list/TLD
order and overlapping no-page later threads only. It is not a PageMap/arena
owner, producer lifetime, general abandonment traversal, pthread/TLS callback,
or public backend integration. Its separate `MainHeapThreadPageDrainSession`
is reachable only through the paired page owner below after it clears the fixed
fast slot; it retains the metadata/list/TLD state until all-free release has
completed or a terminal owner is retained.

The first process-global page-map owner is now also present and has one
separate, deliberately lower-level shared-arena sidecar.
`process_page_map.rs` source-maps `mi_page_map_init_once` /
`_mi_page_map_init`, freezes one `MemoryConfig` and `MainSubprocess`, constructs
a `PageMap` in its final process-static slot, and Release-publishes a stable
root exactly once. `process_arena.rs` source-maps the caller-selected
`mi_manage_os_memory_ex2` edge for one complete mapping: it binds an
`ArenaRegistry` to that exact root/configuration/main identity before
in-place publication. A reserved mapping first moves into the sidecar's final
slot, whose stable callback commits source metadata and later selected arena
ranges through that same `Mapping`; its frozen Linux decommit reports that
reuse needs no recommit. An injected metadata-commit failure recovers the
exact unpublished mapping, leaves the registry empty and the sidecar cold, and
keeps the selected map/subprocess pair available for a matching retry. This is
still only the lower external-map boundary: it does not select page-on-demand
policy or maintain `slice_pcommitted`. Its paired lease now has one narrow,
range-checked direct page-area commit operation for the already-selected
`mi_page_extend_free` transition; the page lifecycle, not the sidecar, owns
the resulting count publication and failed-commit `_mi_page_abandon` tail.
`ProcessPageArenaLease` proves that exact tuple for `main_static_page.rs`'s one
bounded page-bearing owner.
`MainStaticProcessPageAllocator` borrows only the live ticket-zero attachment,
holds a nonrecursive process-map lifecycle lease through its complete engine
and joined scoped producer, installs the selected arena's embedded `pages_main`
in the source main Heap, and preserves bitmap -> map fresh publication plus
map -> bitmap -> metadata -> slice all-free release. The matching
`MainHeapThreadProcessPageAllocator` borrows one current later-thread metadata
TLD/Theap after it proves the same subprocess and frozen configuration; it uses
that same static Heap and embedded bitmap, holds the same one-at-a-time map
lifecycle through its engine and joined producer, then returns to the existing
no-page post-user-destructor teardown only when empty. It can also consume the
later engine into `MainHeapThreadProcessPageExitDrain`: source fast-slot clear
precedes force collection of every queue (including regular and full); a page
that becomes all-free follows the same PageMap -> bitmap -> metadata -> slice
release order. The pass continues after an earlier live page, then retains that
live page rather than queue-detaching or abandoning it. Eight explicit
live-page handoffs require the drain's sole page after fast-slot clear: one
target queue member and every other queue/direct slot empty. The full one-block
arena singleton false-collects, queue-detaches, and unmapped-abandons while its
exact final client free takes the existing failed-reclaim empty tail and
performs PageMap -> `pages_main` -> metadata -> slice release. The second
handoff accepts one sole OS-aligned singleton in `BIN_FULL`, even when its
single object's ordinary size class is small. It validates the exact clipped
PageMap/alias provenance, queue-detaches, links the still-owned page into the
source `Heap::os_abandoned_pages` list, then unmapped-abandons it. Its final
free removes that exact list member before PageMap unregistration, secondary
alias clearing, primary metadata retirement, and mapping reclaim; an injected
`munmap` failure retains the unique published mapping owner terminally in the
later attachment. It neither scans, reclaims, requeues, nor generalizes the
OS list. The third handoff accepts only a medium regular arena page with
`reserved > 1` and
`used == 1`; it force- then false-collects, queue-detaches, and publishes its
exact main `pages_abandoned[bin]` bit plus paired `Heap::abandoned_count[bin]`.
Its final client free takes only the source mapped empty-before-reclaim
decision, clears the bit/identity, consumes the paired count, and performs the
same release; a still-live result is terminally retained rather than reclaimed
or requeued.

The fourth and fifth handoffs,
`MainHeapThreadProcessPageExitDrain::abandon_full_medium_to_process_route` and
`MainHeapThreadProcessPageExitDrain::abandon_full_large_to_process_route`,
accept one sole full medium or large arena page in `BIN_FULL`. They preserve
source force -> false collection, queue/page-count detach, and ordinary
unmapped abandonment before
`MainHeapThreadAttachment::finish_after_detached_process_page_route` tears down
the old Theap/TLD. Their linear process routes retain exact arena/span/static-main
Heap/bin facts. Client frees remain unmapped while `free <= reserved / 8`; the
first below-mostly-used free reabandons the page into its exact
`pages_abandoned[bin]` bit plus paired `Heap::abandoned_count[bin]`, and the
mapped tail then owns the same terminal PageMap -> `pages_main` -> metadata ->
slice release. The full-large route proves the complete 64-slice PageMap span
before that terminal release. They provide no reclaim, requeue, allocation-time
adoption, concurrent client-free routing, or another full-regular owner-exit
shape.

The sixth handoff,
`MainHeapThreadProcessPageExitDrain::abandon_full_non_direct_small_to_process_route`,
accepts one sole full small arena page only when its rounded `block_size`
exceeds `SMALL_SIZE_MAX`. That is source's non-direct full-small shape: it
remains in its ordinary regular size bin rather than `BIN_FULL`, has no
direct-cache range, and takes free.c's ordinary collector rather than the
direct-sized partial branch. It force- then false-collects, detaches that exact
regular queue member and page count, and keeps ordinary unmapped abandonment through
`free <= reserved / 8`. The first below-mostly-used client free publishes the
exact static-main bitmap/count pair and its mapped tail performs the same
PageMap -> `pages_main` -> metadata -> slice release after old-Theap/TLD
teardown. It does not admit direct full small pages, mixed traversal,
allocation-time adoption, reclaim, requeue, or concurrent frees.

The seventh handoff,
`MainHeapThreadProcessPageExitDrain::abandon_full_direct_small_to_process_route`,
accepts one sole full small arena page only when its rounded `block_size` is at
most `SMALL_SIZE_MAX`. This is the complementary source direct full-small
shape: pinned direct allocation leaves it in its ordinary regular bin rather
than `BIN_FULL`, and its complete rounded `pages_free_direct` range must name
the sole page with every other direct slot empty. It requires `reserved >= 16`
and `used == reserved`; source queue removal clears that direct range before
the Theap page-count decrement. It then force- then false-collects and retains
ordinary unmapped abandonment through the mostly-used boundary. Its
direct-sized partial collector leaves the just-published atomic head in place,
so the observed free count has the pinned one-free head lag before the later
below-mostly-used decision publishes the exact static-main bitmap/count pair.
The mapped tail retains the same one-slice PageMap -> `pages_main` -> metadata
-> slice release after old-Theap/TLD teardown. It does not admit non-direct
full small pages, mixed traversal, allocation-time adoption, reclaim, requeue,
or concurrent frees.

The eighth handoff,
`MainHeapThreadProcessPageExitDrain::abandon_mapped_small_or_medium_to_process_route`,
accepts one sole nonfull arena page with one or more live blocks when it is a
medium page or any small page. A direct small member is classified by rounded
source `block_size`, not request size: before collection, its exact source
`pages_free_direct` range must name the sole page and every other direct slot
must be empty. Queue removal then clears that exact range before the Theap
page-count decrement. A direct small page retains the source `reserved >= 16`
partial-collection invariant; this nonfull route excludes full small pages
through `used < reserved`, since they can remain in a regular queue. The
separate sixth and seventh handoffs above own the non-direct and direct
full-small classes. This
handoff preserves
source force -> false collection, queue/direct/page-count detach, and mapped
identity/bit/count/unown publication, then retains exact arena/span/static-main
Heap facts while `MainHeapThreadAttachment::finish_after_detached_process_page_route`
actually tears down the former Theap/TLD. The resulting
`MainHeapThreadProcessPageExitMappedRegularRoute` holds only those facts and a
linear `ProcessPageMapPostExitAccess`. Each client free re-acquires the same
map lock briefly: a nonempty result keeps PageMap registration and the paired
bitmap/count, while the final free clears them before PageMap -> `pages_main`
-> metadata -> slice release. The route is movable to one client-free thread.
One explicit consuming allocation-time edge is now complete for its sole
mapped nonfull medium form:
`MainHeapThreadProcessPageExitMappedRegularRoute::adopt_into_later_main`
requires an exact matching fresh later-main attachment/process pair (same
subprocess, frozen configuration, stable PageMap root, static main Heap, and
arena) and re-proves the source span and page identity. It transfers the short
`ProcessPageMapPostExitAccess` into one long mutation lease, claims the exact
bitmap/count member, collects abandoned state, reassociates the page with the
fresh Theap/thread, collects live state, and restores source queue-tail order.
The completed branch accepts either an immediate head or an exhausted nonfull
medium page (`capacity < reserved`). A fully committed page
(`slice_pcommitted == 0`) performs the scalar source
`mi_page_extend_free` list/capacity transition after tail insertion. The
bounded test-only `commit == false` seam instead constructs one actual
reserved medium page with the source initial callback-committed prefix. Its
nonzero-prefix path derives the source OS-page count and byte-range plan, then
uses the paired retained mapping for direct `_mi_os_commit`-shape commitment
before it writes `slice_pcommitted` or its free list. An injected direct-commit
failure repeats false collection, queue detach, direct-cache/page-count repair,
and mapped identity/bit/count/unown publication; the retained owner can retry
only that same candidate through its existing long lifecycle. This does not
add a production page-on-demand option, a generic fresh fallback, or a bitmap
scan. A bitmap miss, malformed state, scalar extension error, or any other
post-transfer error remains terminally retained.
Small/direct, full, singleton, unmapped, huge, foreign, aggregate-registry,
automatic-scanning, and concurrent adoption remain deliberately absent.

The bounded aggregate extension,
`MainHeapThreadProcessPageExitDrain::abandon_mapped_regular_pages_to_process_route`,
now performs one source-shaped traversal over more than one live page. Its
complete structural preflight leaves queue, direct-cache, and page ownership
untouched unless every direct slot matches the source-derived
`pages_free_direct` queue-head image and every queued member is a nonfull
regular small, medium, or large page in the paired arena: live members require
`reserved > 1` and `0 < used < reserved`; direct small members additionally
require `reserved >= 16` for `free.c`'s partial collector; and an empty member
is admitted only with a nonzero source retirement countdown. It proves each
intrusive queue's complete bounded doubly linked image before the unsafe
queue-removal kernel: zero-count queues have null endpoints; nonempty queues
have a null head predecessor, correct predecessor links, and a counted forward
walk ending at the registered null-terminated tail. Full, singleton/huge,
unmapped, foreign, malformed, and unsupported mixed queues reject before any
queue/page mutation.
After that refusal boundary it ports
`_mi_theap_collect_retired(theap, true)`: tracked empty retired pages release
through the ordinary PageMap -> `pages_main` -> metadata -> slice path before
the remaining traversal follows `mi_theap_collect_abandon`'s force collect,
all-free release, false collect, and otherwise queue detach, direct-cache
queue-head refresh, page-count detach, plus mapped identity/bit/count/unown
publication. It does not add the absent
deferred-callback, arena-collection, or stats-merge work. It keeps no raw page
list: every survivor is represented by its PageMap registration plus the exact
static-main `pages_abandoned[bin]` bit and paired
`Heap::abandoned_count[bin]`. A fully retired/force-collected result returns
the normal drained owner. Otherwise the former Theap/TLD tears down and the linear
`MainHeapThreadProcessPageExitMappedRegularPagesRoute` re-resolves each client
free under a short PageMap lock. Only after the free tail has claimed the low
owner bit does it select that page's bin-specific bitmap/count capability;
this permits distinct small, medium, and large bins without retaining stale
page metadata. A nonempty free retains its pairing, while a final free
re-derives the supported page's complete regular span (one slice for small,
eight for medium, and 64 for large) before clearing identity/bit/count and
performing PageMap -> `pages_main` -> metadata -> slice release. A fresh engine
may serialize an independent map operation between frees, but no current
allocator path receives a capability to adopt, reclaim, or requeue a registry
member.

An empty drain still returns for the ordinary post-drain root/list/TLD teardown;
the process routes use their separate typed attachment finish. Every route
rejects a foreign process pair before page mutation and terminally poisons its
attachment plus the map if unfinished. They do not reserve a mapping, route
concurrent/general later-thread or multiple-arena pages, permit process
destruction, or turn the aggregate registry into general allocation-time
abandonment policy. They remain distinct from the metadata allocator's private
map/arena and every caller-managed map. The C static `mi_page_map_empty`
pre-root remains absent; an unpublished map reservation failure or unfinished
lifecycle is terminal rather than a null or fresh root.

The bounded source-order process-init prerequisite is now also present.
`process_init.rs` reserves the static ticket-zero branch only after pure
root/current-thread preflight, publishes the static Heap foundation, readies
the detached metadata allocator without exposing its private map/arena,
publishes the distinct global PageMap, and only then attaches the static
TLD/Theap and default-then-fast roots. `MainStaticBootstrapSelection` prevents
generic ticket zero from racing that branch and requires Heap foundation before
ticket issue. `ProcessMainReadyLease` is immutable; the coordinator does not
choose options or OS facts, reserve the process-shared arena, create
pthread/TLS keys, route allocation/free, or perform shutdown/fork repair.
Preflight rejection remains cold, while every later error retains the partial
process image rather than replaying static startup. The direct static
attachment remains a test-only seam; production static startup must use this
coordinator.

General producer routing, concurrent/general shared/later-thread page-bearing
ownership, remaining full/singleton/unmapped/huge owner-exit pages and behavior beyond
the bounded sole full-medium/full-large/full-non-direct-small/full-direct-small routes, sole
small-or-medium route (apart from its exact mapped-medium consuming handoff),
and aggregate regular-pages registry, terminal reuse, automatic and multiple
dynamic arenas, complete process options/TLS/shutdown, pthread/TLS teardown
hooks, fork repair, public libc backend integration, performance qualification,
and default promotion remain unfinished. The next safe lifecycle frontier is
another source-shaped owner-exit page class or a separately proven
aggregate-registry policy—not a superficial broad abandonment loop or generic
allocation-time scan. The bounded mapped-medium page-area
commit/failure-reabandon path is complete only for its real test fixture and
same-candidate retry; it does not establish source option policy or general
on-demand allocation.

A fresh pinned-source audit makes that prerequisite concrete: after its absent
deferred-callback edge, `mi_theap_collect_ex(MI_ABANDON)` first calls
`_mi_theap_collect_retired(theap, true)`, then force-collects each queue member
and calls `_mi_page_abandon` for every still-live page
(`src/theap.c:97-152`, `src/page.c:414-518,291-302`). The latter
false-collects, detaches the page, and delegates mapped publication/count
pairing or unmapped abandonment to `src/arena.c:1304-1424`. The current
`PageAllocatorEngine::finish_after_all_free_thread_exit` can release the
process-map mutation lease only after its page count, queues, and direct roots
are empty; an unfinished lease poisons that map owner. The post-exit
client-free transfer has six narrow forms: the full-medium route, full-large
route, full non-direct-small route, full direct-small route, sole
small-or-medium route, and aggregate regular-pages registry. Each converts the
long mutation lease into a short locked free owner, retains stable
span/arena/Heap facts rather than the old Theap/TLD, and proves bitmap/count
pairing through actual teardown and sequential later frees. The sole mapped
regular route additionally has three source-specific full-page predecessors:
exactly one joined remote free makes either the sole medium `BIN_FULL` page,
the sole non-direct-small ordinary-bin page, or the sole direct-small
ordinary-bin page nonfull during force collection. False collection removes
that same source member; the non-direct-small branch retains the empty
direct-cache image, while the direct-small branch clears its rounded range
before page-count detach. All three immediately publish the ordinary mapped
bit/count pair before old-Theap/TLD teardown. They are not general full-page
traversals. All full-origin predecessors remain client-free-only even though their final geometry is
nonfull. Only the separately completed source-initially-nonfull sole
mapped-medium route has the explicit inverse bridge into one fresh
later-main mutation lease. Its bounded reserved-prefix fixture
now covers source direct page-area commitment and failed-commit reabandonment
before a same-candidate retry; it is not a generic allocation policy. The
aggregate registry intentionally stops
at nonfull regular small, medium, and large pages and has no adoption
capability. Do not extend either boundary to another page shape without its
source-specific publication, terminal-release, allocation-time claim/reclaim,
and concurrency evidence.

Checkpoint evidence is green: the focused
`dynamic_theap::tests::dynamic_thread_exit_singleton_remote_free_clears_tls_then_releases_its_arena_page`,
`dynamic_thread_exit_full_medium_handoff_reabandons_after_mostly_used_frees_then_releases`,
`dynamic_thread_exit_full_medium_handoff_rejects_before_detach_when_another_page_is_live`,
and `dynamic_thread_exit_full_medium_handoff_retains_collection_failure`,
`dynamic_thread_exit_full_non_direct_small_handoff_reabandons_after_mostly_used_frees_then_releases`,
`dynamic_thread_exit_full_non_direct_small_handoff_rejects_before_detach_when_another_page_is_live`,
`dynamic_thread_exit_full_non_direct_small_handoff_rejects_direct_small_before_detach`,
`dynamic_thread_exit_full_non_direct_small_handoff_refuses_stale_direct_cache_before_detach`,
and `dynamic_thread_exit_full_non_direct_small_handoff_retains_collection_failure`,
`dynamic_thread_exit_full_direct_small_handoff_reabandons_after_partial_head_lag_then_releases`,
`dynamic_thread_exit_full_direct_small_handoff_refuses_stale_rounded_direct_cache_before_detach`,
`dynamic_thread_exit_full_direct_small_handoff_rejects_non_direct_small_before_detach`,
`dynamic_thread_exit_full_direct_small_handoff_rejects_before_detach_when_another_page_is_live`,
and `dynamic_thread_exit_full_direct_small_handoff_retains_collection_failure`,
`dynamic_thread_exit_force_collects_a_retired_regular_page_after_tls_clear`,
and the raw false/force-local-list order/cycle regressions in `free_list::tests`,
the no-page shared-main regressions in `main_heap_thread::tests`, the
process-map commit/once/lifecycle regressions in `process_page_map::tests`
(including `post_exit_access_can_transfer_to_one_new_long_page_lifecycle`), the
root-pairing regressions in `process_arena::tests`, the five bounded
static-main page-owner regressions in `main_static_page::tests`, the bounded
later-main page-owner regressions in `main_heap_page::tests` (including
the joined remote-full all-free exit drain, its later-queue collection behind a
retained live page, the retained-live-page boundary, the sole-full-singleton
final-free/reject-before-detach regressions, the sole-medium
mapped-bit/count/final-free/reject-before-detach regressions, the post-exit
full-medium and full-large routes' unmapped mostly-used thresholds and later
mapped tails (including the full-large route's 64-slice terminal release), the
full-medium one-joined-remote force-collection predecessor's immediate mapped
publication, client-free-only allocation-adoption refusal, eight-slice
client-free release, pre-mutation regular-medium refusal, and terminal
collection-failure retention; the full-non-direct-small one-joined-remote
force-collection predecessor's immediate mapped publication, client-free-only
allocation-adoption refusal, one-slice client-free release, pre-mutation
direct-small refusal, and terminal collection-failure retention; the
full-direct-small one-joined-remote
force-collection predecessor's immediate mapped publication, direct-range
clear-before-count-detach, client-free-only adoption refusal, one-slice
terminal release, stale-cache preflight refusal, and terminal
collection-failure retention; the
full non-direct-small route's ordinary-bin detach, threshold-adjacent
unmapped-to-mapped transition, and terminal release, the full direct-small
route's exact rounded cache preflight/clear boundary, partial-head-lag
threshold transition, terminal release, and stale-cache refusal, the
post-exit regular route's medium, threshold-adjacent non-direct small, upper direct and
non-direct small boundaries, direct-image preflight refusal, full-small
pre-detach refusal, one-page-refusal, and cross-thread movement regressions;
the sole mapped-medium route's immediate and exhausted-fully-committed
fresh-owner adoption, scalar capacity-extension, real reserved-prefix direct
page-area commitment, failed-commit mapped reabandonment/same-candidate retry,
and direct-small pre-transfer refusal regressions; and the aggregate
regular-pages registry's mixed small/medium/large
release, retired-large prepass, malformed direct-image and malformed-predecessor
preflight refusal, full-small preflight refusal, post-claim distinct-large-bin
selection, large-span terminal release,
and large force-collection-to-drained regressions), and
`abandoned::tests::mapped_one_block_owner_exit_free_retains_a_nonempty_medium_page`,
which proves the mapped endpoint cannot reclaim or requeue a still-live page,
the source-order process-main coordinator regressions in `process_init::tests`,
and the static-Heap/ticket-zero selector regressions in `main_theap::tests` and
`subproc::tests` all pass. The current `./scripts/dev.sh test -p
crabc-mimalloc` package run passes all 445 tests. `./scripts/dev.sh test -p crabc-mimalloc
--lib --features loom
remote_free::loom_tests -- --test-threads=1` passes the five Loom remote-head
schedules; `./scripts/dev.sh structure`, the 39 allocator-runner unit tests,
and `./scripts/dev.sh allocator --quick` also pass (report:
`compat/reports/allocator/latest.json`). The current explicit
`compat/allocator/run.py --check` passes after a reviewed
`compat/allocator/ratchet-v3.5.0.json` snapshot with 93 items and 97
implemented/unit-verified statuses. Resume with a fresh source/lifecycle review
before broadening the newly proven post-TLS arena/OS-singleton or
full-medium/full-non-direct-small/full-direct-small or mapped-one-block-medium/non-direct-small/direct-small cases, the later-main
all-free scan/eight sole-page handoffs/aggregate regular-pages registry, or
either bounded process page owner.
The next frontier is another page-bearing owner-exit class or a separately
proven aggregate-registry policy, then complete process and real
pthread/TLS lifecycle integration—not a generic allocation-time scan routed
through a bounded singleton, mapped-one-block handoff, no-page finish, or these
sequential ticket-zero/later page-owner slices.

The current upstream baseline should be **mimalloc v3.5.0**, released August 19, 2026, at tag commit `18b08671c9302247bfb682286e6bf3cc1773f801`. Upstream marks v3 as its recommended current design. Pin that exact commit and archive hash; never track `main`. ([GitHub][1])

This is significantly more substantial than porting mimalloc v2. In v3, first-class heaps are backed by per-thread “theaps,” and the allocator has substantial page-map, arena, subprocess, thread-local, remote-free, and lifecycle machinery. That architecture is precisely what should be preserved rather than simplified prematurely. ([Microsoft GitHub][2])

crabc already has an excellent integration boundary: the public allocator ABI is a thin wrapper over `libmimalloc-sys`, while raw VM operations live in `crabc-core`. The main work is therefore allocator metadata, page management, atomics, TLS, thread teardown, cross-thread frees, initialization, fork behavior, and validation—not the six basic C ABI wrappers.

It is also a deliberate scope reversal. The current durable project guidance explicitly says not to turn allocation into a research project and excludes a pure-Rust allocator. The first change should replace that doctrine with a narrow exception: **a pinned compatibility port is in scope; allocator invention and cross-platform generalization remain out of scope**.

I would lock in these decisions:

1. Name the crate **`crabc-mimalloc`**, not `crabc-alloc`. The provenance and compatibility target should be obvious.
2. Make it `#![no_std]`, with no `alloc`, no libc dependency or native build
   script, and exactly the approved focused direct production dependencies
   `crabc-core`, `chacha20`, and `zeroize` unless a later reviewable dependency
   decision changes that graph. Never hand-roll a crypto or PRNG core to avoid
   one of those focused dependencies.
3. Keep the current C implementation as a mandatory differential oracle and selectable shadow backend until the promotion gates pass.
4. Keep the POSIX/musl C contract in `crabc-libc`; keep the allocator engine errno-free.
5. Separate “ready to back crabc’s `malloc` family” from “all platform-applicable `mi_*` extended APIs are complete.” Track both, but do not confuse them.
6. Integrate directly with crabc’s pthread startup/teardown and fork path. Do not build an allocator-internal dependency on public pthread APIs.
7. Promote the Rust implementation to default only in a final, isolated commit after correctness, RSS, latency, throughput, ABI, TLS, fork, and real-program gates pass.

There is useful prior art: `rimalloc` applies deterministic differential testing, Miri shims, and Loom to a pure-Rust mimalloc v2.3.2 port, while the Verus verified-memory-allocator project demonstrates how to decompose free-list-sharding invariants. Those are valuable verification patterns, but neither should replace a direct v3.5.0 source audit and translation. ([GitHub][3])

A local AArch64 performance and memory harness is essential. There is an open upstream report concerning RSS behavior on musl/Alpine AArch64 across v3 releases, and upstream users have also asked for refreshed v3 performance charts. Treat upstream claims as hypotheses; crabc’s own evidence must decide promotion. ([GitHub][4])

## Obective

Implement a pure-Rust, no_std port of mimalloc v3.5.0 as a new workspace
crate named `crabc-mimalloc`, integrate it as a selectable allocator backend
for crabc-libc, build a rigorous differential correctness and performance
harness against the exact upstream C implementation, and promote the Rust
backend to crabc's default allocator only after the objective promotion gates
defined below pass.

This is a large, safety-critical subsystem. Work incrementally in complete
vertical slices. Do not produce one enormous mechanical translation and only
then begin testing.

======================================================================
1. FIXED BASELINE
======================================================================

Upstream allocator baseline:

- Project: microsoft/mimalloc
- Release: v3.5.0
- Full tag commit:
  18b08671c9302247bfb682286e6bf3cc1773f801
- Source repository:
  https://github.com/microsoft/mimalloc
- Release:
  https://github.com/microsoft/mimalloc/releases/tag/v3.5.0

Pin the exact source archive and its SHA-256 in `compat/upstreams.toml`.
Verify that the fetched tag resolves to the commit above.

Do not silently upgrade to a later mimalloc tag, even if one exists when this
task executes. A newer release requires a separate, reviewable upstream-update
change with a generated source/API/configuration diff, complete correctness
rerun, and complete performance rerun.

This prompt was prepared against crabc around commit:

    ec8eafe108348448729685cfe9d45a38fae08d7e

That is orientation only. Begin from the actual current HEAD. Do not reset,
discard, or overwrite intervening work. Record the actual starting commit and
whether the tree was dirty in the final evidence report.

Supported production platform:

- Linux only.
- AArch64 little-endian only.
- Linux kernel floor defined by current crabc policy, presently Linux >= 5.10.
- Preserve support for valid Linux/AArch64 page sizes; do not assume 4 KiB.
- Preserve the repository's pinned Rust nightly, Alpine image, musl oracle,
  and Docker-hermetic workflow.

Explicitly out of scope:

- x86-64, RISC-V, macOS, Windows, or generic portability scaffolding.
- mimalloc v1 or v2 compatibility.
- A novel allocator design.
- Replacing mimalloc algorithms with more idiomatic but materially different
  algorithms.
- A generic allocator-strategy framework.
- A generic operating-system abstraction intended for future platforms.
- C or C++ code in the production allocator.
- glibc as a behavioral oracle.
- Runtime selection between allocators in production.
- Unsupported stubs that return success or silently degrade semantics.

======================================================================
2. MISSION AND DEFINITIONS OF DONE
======================================================================

The project has five separate outcomes. Track them independently.

A. Pure-Rust engine

`crabc-mimalloc` implements the Linux/AArch64-applicable mimalloc v3.5.0
allocator engine in Rust:

- `#![no_std]`
- no dependency on `alloc`
- no dependency on libc
- no C or C++ compilation
- no bindgen-generated production implementation
- no native build script
- no allocator use during allocator bootstrap, diagnostics, TLS setup,
  teardown, or fault injection
- no normal dependency on `libmimalloc-sys`

B. crabc libc integration

The existing crabc allocator symbols are backed by `crabc-mimalloc` while
preserving the current musl-compatible public contract, including:

- weak/preemptible allocator symbols
- allocator/free interposition behavior
- `errno` behavior
- zero-size allocation behavior
- allocation alignment
- calloc overflow behavior
- realloc failure preservation
- crabc's current `realloc(p, 0)` policy
- musl-compatible aligned allocation behavior
- `posix_memalign` output preservation on error

The C ABI policy remains in `crabc-libc`. The allocator engine must not own
`errno`.

C. mimalloc feature parity

All public v3.5.0 interfaces and compile-time modes applicable to
Linux/AArch64 are mechanically inventoried and assigned an explicit status.

Do not manually guess the public API from memory. Derive the inventory from
the pinned `include/mimalloc.h`, related public headers, option declarations,
exported symbols, and upstream tests.

D. correctness evidence

The implementation is supported by:

- focused unit and invariant tests
- layout and configuration probes against the C implementation
- unchanged or minimally adapted upstream mimalloc tests
- deterministic differential traces against pinned C mimalloc
- concurrency model tests
- Miri-compatible host-model tests
- deterministic fault injection
- process-isolated corruption and wrong-use tests
- crabc pthread/TLS/fork tests
- ABI and interposition tests
- real-program and compatibility-corpus tests

E. performance and memory parity

The Rust port is non-inferior to the exact C v3.5.0 baseline within the
specified confidence bounds for the default production profile.

Do not claim completion merely because basic malloc/free tests pass.
Do not switch the default backend merely because the Rust implementation
appears fast in an informal benchmark.

======================================================================
3. FIRST CHANGE: DURABLE SCOPE RESET
======================================================================

Before implementing allocator internals, update durable project documentation.

Current crabc guidance deliberately excludes a pure-Rust allocator. Replace
that with a narrowly defined exception:

- crabc may maintain a pure-Rust semantic port of a fixed mature allocator.
- mimalloc v3.5.0 is the initial fixed target.
- the work is compatibility engineering, not allocator research.
- upstream algorithms, data structures, memory orderings, and observable
  behavior are preserved until parity is established.
- Linux/AArch64 is the only implementation target.
- no speculative architecture abstraction is accepted.
- algorithmic divergence requires a written design note, differential
  evidence, and performance evidence.
- the mature C implementation remains a test oracle even after it leaves the
  production dependency graph.

Update at least:

- `SCOPE.md`
- `AGENTS.md`
- `docs/design/performance.md`
- `compat/perf/README.md`

Add:

- `docs/design/allocator.md`
- `crabc-mimalloc/UPSTREAM.md`
- `compat/allocator/README.md`
- `compat/allocator/known-differences.md`

`UPSTREAM.md` must record:

- repository
- tag
- full commit
- archive SHA-256
- upstream license
- source-to-Rust module mapping
- intentional deviations
- configuration profile
- update procedure

Preserve the exact upstream license notices required for translated code.
Do not blindly apply the workspace's dual-license header to translated files
without resolving the derivative-code provenance correctly.

======================================================================
4. CRATE AND DEPENDENCY ARCHITECTURE
======================================================================

Add `crabc-mimalloc` to the workspace.

Required production dependency direction:

    crabc-mimalloc -> crabc-core + chacha20 + zeroize
    crabc-libc     -> crabc-core + crabc-mimalloc

Forbidden:

    crabc-mimalloc -> crabc-libc

`crabc-mimalloc` may request narrowly scoped additions to `crabc-core` for raw
Linux primitives that are genuinely missing. Add those primitives to
`crabc-core`; do not duplicate raw syscall assembly inside the allocator.

The intended production manifest is approximately:

    [package]
    name = "crabc-mimalloc"
    ...

    [dependencies]
    chacha20 = { version = "=0.10.1", default-features = false, features = ["legacy", "zeroize"] }
    crabc-core = { path = "../crabc-core" }
    zeroize = { version = "=1.9.0", default-features = false }

The focused RustCrypto dependencies above are the mandatory boundary around
the pinned original-ChaCha permutation and key erasure: cryptographic
algorithms and PRNG/DRBG cores must never be translated or maintained locally.
Small, mature, focused production dependencies satisfying the governing
`SCOPE.md` policy have standing approval, while every addition still requires
a written capability and dependency-graph justification. The expected direct
normal dependency count for this crate is three.

Development-only verification dependencies are permitted when narrowly
justified. In particular, Loom may be used for modeled atomic protocols.
Miri requires no production dependency. Do not introduce a broad async
runtime, libc wrapper, serialization framework, logging framework, or
benchmark framework into the production graph.

The allocator crate must reject unsupported production targets:

- non-Linux
- non-AArch64
- big-endian

A host-model configuration used by Miri or Loom is a test instrument, not a
supported production platform. Keep it clearly separated with test-only cfgs.

The engine should expose unsafe Rust operations and lifecycle hooks, roughly:

- process/bootstrap initialization
- thread initialization
- thread teardown
- allocation
- zeroed allocation
- reallocation
- aligned allocation
- deallocation
- usable size
- collect/purge
- first-class heap operations
- theap operations
- arena operations
- subprocess operations
- option/statistics/callback operations
- fork prepare/parent/child hooks if required by the crabc guarantee

Do not export `mi_*` ELF symbols from crabc's libc accidentally.

For running the upstream C API tests, provide a small test-only C ABI adapter
that exports the exact required `mi_*` symbols and delegates to the Rust
engine. This adapter may be a feature or a package under
`compat/allocator/capi`, but it must not become a normal crabc-libc dependency.

A `core::alloc::GlobalAlloc` adapter may be added after the fundamental
allocator operations are stable. It is useful, but it is not the primary
crabc integration boundary and must not distort the initial implementation.

======================================================================
5. LIBC BACKEND TRANSITION
======================================================================

Refactor the existing allocator wrapper into:

1. A backend-independent C ABI contract layer.
2. A temporary C mimalloc backend.
3. The new Rust mimalloc backend.

Use clear feature names such as:

- `allocator-mimalloc-c`
- `allocator-mimalloc-rust`

Initially:

- C remains the default.
- Rust is a required CI/test lane.
- exactly one backend must be enabled.
- enabling both or neither must fail clearly at compile time.

Do not implement a runtime backend selector. Runtime allocator selection
complicates bootstrap, TLS, interposition, and benchmarking and is unnecessary.

After all promotion gates pass:

- flip the default feature to `allocator-mimalloc-rust` in a dedicated commit;
- remove `libmimalloc-sys` from the default production dependency graph;
- retain the C backend only as an explicitly selected transitional lane if it
  remains useful;
- retain the exact upstream C implementation in the compatibility harness as
  the long-term oracle.

Eventually, the C oracle should be built from the pinned upstream source by
the compatibility harness rather than relying on an opaque crates.io sys crate.

Do not assume the currently used `libmimalloc-sys` package contains exactly
v3.5.0. Establish its bundled version before using it for any comparison.
The authoritative oracle is the independently pinned v3.5.0 source.

Preserve the existing weak-symbol and interposition design. In particular,
audit and retain the special free-routing behavior that ensures an allocation
created through an interposed malloc is released through the matching free
implementation.

Run ELF symbol inspections with `readelf`, `nm`, and the existing crabc symbol
harness. Verify:

- intended weak versus strong binding
- symbol visibility
- no accidental `mi_*` exports
- no unresolved libc allocator recursion
- no native mimalloc objects in the Rust-default artifact
- expected static and dynamic link behavior

======================================================================
6. PORTING DISCIPLINE
======================================================================

This must be a source-mapped semantic port.

Create a machine-readable mapping such as:

    compat/allocator/port-map.toml

Each meaningful upstream source unit or function must record:

- upstream file
- upstream symbol or source region
- Rust module/item
- implementation status
- verification status
- associated tests
- intentional differences
- performance qualification where relevant

Use distinct monotonic fields rather than one vague "done" flag:

- exported
- implemented
- unit_verified
- differential_verified
- stress_verified
- performance_qualified

A true status may not silently regress to false. Add a ratchet check.

Preserve upstream terminology where it conveys allocator invariants:

- page
- segment or arena terminology used by v3.5.0
- heap
- theap
- TLD
- page queues
- owner-local and cross-thread deferred-free lists
- remote free
- abandoned state
- subprocess
- memory ID/provenance
- page map
- bitmap claims

Do not perform a broad early "Rustification" of the design.

Recommended Rust module decomposition, adjusted only when the source audit
demonstrates a better dependency boundary:

    src/lib.rs
    src/config.rs
    src/types.rs
    src/atomic.rs
    src/bits.rs
    src/provenance.rs
    src/invariants.rs
    src/init.rs
    src/os.rs
    src/random.rs
    src/bitmap.rs
    src/arena.rs
    src/page_map.rs
    src/page.rs
    src/page_queue.rs
    src/heap.rs
    src/theap.rs
    src/thread_local.rs
    src/subproc.rs
    src/alloc.rs
    src/aligned.rs
    src/free.rs
    src/options.rs
    src/stats.rs
    src/api.rs

Map these explicitly to the v3.5.0 source files, including at least:

- `alloc.c`
- `alloc-aligned.c`
- `free.c`
- `arena.c`
- `bitmap.c`
- `heap.c`
- `theap.c`
- `threadlocal.c`
- `init.c`
- `os.c`
- `page-map.c`
- `page.c`
- `page-queue.c`
- `random.c`
- `stats.c`
- `options.c`
- `subproc.c`
- Linux/Unix primitive code
- relevant internal headers

Automated tools may generate:

- API inventories
- configuration snapshots
- constants
- layout reports
- source maps
- test vectors

Do not use C2Rust output, bindgen output, or a generated transliteration as the
unchecked production implementation. Production Rust must be reviewed in
allocator-sized semantic slices.

Every translated module must identify its pinned upstream source and document
material adaptations.

Do not change an upstream atomic ordering merely because another ordering
looks simpler. Port the ordering and protocol first. Any later change requires:

- an invariant explanation;
- a Loom or equivalent protocol test where applicable;
- full differential and stress reruns;
- performance evidence.

Do not replace every atomic with SeqCst. That can conceal an incomplete memory
model while destroying hot-path performance.

======================================================================
7. RUST UNSAFETY AND MEMORY MODEL RULES
======================================================================

Use:

    #![deny(unsafe_op_in_unsafe_fn)]

Every unsafe function must state its caller obligations.

Every nontrivial unsafe block must explain the local invariant that makes it
sound. Avoid comments that merely restate the operation.

Allocator metadata is concurrently mutable and may be mapped, committed,
decommitted, abandoned, or reclaimed. Therefore:

- do not construct long-lived shared or mutable references over memory whose
  aliasing cannot satisfy Rust reference rules;
- use raw pointers, `UnsafeCell`, and atomics deliberately;
- do not manufacture `&mut T` merely because the current code path believes
  it owns a block;
- do not read padding or uninitialized fields through typed references;
- do not use `MaybeUninit::assume_init` without a local initialization proof;
- preserve explicit ownership and memory provenance in types where practical.

Use strict-provenance-compatible pointer operations where possible:

- separate address extraction from pointer reconstruction;
- do not perform arbitrary pointer-to-integer-to-pointer round trips without
  retaining a valid provenance basis;
- isolate unavoidable address-map operations and document them;
- exercise those operations under Miri's strict-provenance model through the
  host backend.

Add compile-time assertions for critical:

- size
- alignment
- offsets
- bit widths
- bin counts
- page constants
- bitmap widths
- maximum allocation limits
- tagged-pointer assumptions

The allocator may not unwind.

The production workspace already uses aborting panic profiles. Nevertheless,
hot paths must not accidentally call formatting, bounds-panic, overflow-panic,
UTF-8, or allocation machinery. Inspect optimized assembly and undefined
symbols.

Diagnostics and corruption reports must use fixed stack buffers and direct
nonallocating output primitives. Logging must never recursively allocate.

======================================================================
8. EXACT UPSTREAM CONFIGURATION
======================================================================

Do not infer the active v3.5.0 configuration from comments alone.

Build a configuration probe against the pinned C source for the exact
Linux/AArch64 baseline. Capture relevant resolved `MI_*` preprocessor values
using the compiler preprocessor and store a deterministic report.

Create a C/Rust layout probe that compares:

- public opaque handle assumptions
- internal struct size where layout parity matters
- internal alignment
- important field offsets
- bin constants
- page and arena constants
- bitmap sizes
- maximum object sizes
- compile-time feature values
- secure/debug/statistics configuration

The Rust implementation need not have C-identical internal layout where no ABI
or algorithmic assumption depends on it. Any deliberate layout difference
must be documented and tested against the underlying invariant.

Default production code must target the repository's baseline AArch64 feature
set. Do not require Armv8.3 by default.

Upstream v3.5.0 has an architecture-optimized Armv8.3 path. Represent that as
an explicit optional profile only after the baseline implementation works:

- disabled by default
- compiled and tested separately
- benchmarked separately
- never selected based on host detection during a reproducible build

Do not assume a 4 KiB kernel page. Obtain the actual page size from crabc's
startup/auxiliary-vector context and verify behavior on supported 4 KiB,
16 KiB, and 64 KiB AArch64 configurations where execution environments are
available.

Do not assume one fixed userspace virtual-address width. Preserve the upstream
page-map range logic and validate its arithmetic at boundary addresses.

======================================================================
9. LINUX/AARCH64 PRIMITIVE LAYER
======================================================================

Map the upstream Unix primitive layer onto `crabc-core`.

Inventory all required primitives before adding code, including:

- reserve/map
- unmap
- commit
- decommit
- reset/purge
- protect/unprotect
- remap where used
- huge-page flags and fallback
- page size
- monotonic clock
- thread ID
- process ID
- scheduling yield
- random entropy
- NUMA information where supported
- memory advice
- process information needed by statistics

Use existing `crabc-core` wrappers whenever they have the required semantics.
Add a narrowly scoped raw primitive to `crabc-core` when missing.

Do not make `crabc-mimalloc` call the public crabc libc ABI. That would create
an allocator/libc cycle and can recurse.

Represent upstream memory provenance explicitly. Preserve distinctions such
as:

- static/bootstrap memory
- externally managed memory
- direct OS memory
- huge memory
- remapped memory
- arena-managed memory
- metadata memory

Fault injection must operate at this primitive boundary without adding runtime
virtual dispatch to production hot paths.

Use compile-time backend selection:

- production Linux/AArch64 backend
- host model for Miri
- Loom atomic model for selected protocols
- deterministic fault-injection wrapper for tests

Do not create a generic public OS trait.

======================================================================
10. BOOTSTRAP, PROCESS INITIALIZATION, AND REENTRANCY
======================================================================

Port the upstream allocation-free bootstrap model faithfully.

The allocator must have statically initialized minimal state sufficient to
survive the earliest valid allocation call without recursively allocating.
This includes the equivalent of upstream empty/static pages, main heap/theap,
metadata state, and initialization guards as required by v3.5.0.

Initialization must be:

- idempotent
- race-safe
- reentrancy-safe
- allocation-free until the primitive layer is ready
- valid when entered lazily through malloc
- valid when entered explicitly through crabc startup
- safe when an error or entropy fallback path is taken

Define an explicit startup context supplied by crabc-libc or the loader. It
should provide only raw, nonowning information, such as:

- page size
- auxiliary-vector information
- `AT_RANDOM` material when available
- raw environment pointer
- process startup state needed by the allocator

The allocator crate must not depend on libc environment functions.

Parse mimalloc environment options without allocation. Account for the fact
that an exceptionally early allocation may occur before the full environment
has been installed. Early allocations must use deterministic safe defaults;
the explicit startup hook may finalize options before user constructors and
user code.

Do not read `/proc/self/environ` as a substitute for correct startup plumbing.

Entropy acquisition must be allocation-free:

- use a direct crabc-core `getrandom`-style primitive when available;
- use appropriate upstream-compatible startup entropy fallback;
- preserve secure-mode requirements;
- do not silently use a predictable fixed key in production.

Add deterministic entropy injection for tests.

Exercise:

- first allocation before explicit process initialization
- concurrent first allocation
- initialization failure
- entropy syscall failure
- page-map bootstrap failure
- option parsing during already-partial initialization
- diagnostics during initialization failure

======================================================================
11. THREAD LOCAL STORAGE AND THREAD LIFECYCLE
======================================================================

mimalloc v3's theap and TLS design is core allocator machinery, not optional
integration polish.

Port the v3.5.0 thread-local design faithfully, including:

- the fast current/default theap slot
- dynamically allocated versioned TLS slots used by first-class heaps
- key allocation and reuse
- stale-key/version rejection
- per-thread TLD state
- lazy thread initialization
- attachment and detachment of theaps
- abandoned-page handling
- thread teardown

Use direct Rust compiler TLS for the hot slot where consistent with the pinned
crabc nightly and existing runtime TLS model.

Do not call public `pthread_key_create` from the allocator. Instead, integrate
with the crabc pthread runtime through private lifecycle calls:

- initialize allocator thread state before invoking a user thread start
  routine;
- run allocator thread teardown after user cleanup handlers and TSD
  destructors have finished, because those destructors may allocate;
- guarantee exactly-once teardown;
- initialize and tear down the main thread correctly;
- make explicit `mi_thread_init` / `mi_thread_done` behavior consistent with
  the automatic lifecycle.

Audit cancellation and abnormal thread-exit paths. No thread exit path may
silently skip allocator teardown when crabc otherwise guarantees cleanup.

Document behavior for threads created outside crabc's supported pthread
runtime through raw clone. Do not claim automatic teardown that is not
actually implemented.

Required stress cases include:

- repeated thread creation and destruction
- thread exits with locally owned live pages
- remote frees arriving before, during, and after owner teardown
- abandoned pages reclaimed by another thread
- first-class heap used from multiple threads
- TLS slot key reuse and version wrap boundaries
- thread teardown with deferred frees
- thread-local state exhaustion/failure injection

======================================================================
12. CROSS-THREAD FREE AND ATOMIC PROTOCOLS
======================================================================

Translate the v3.5.0 owner-local `local_free`, cross-thread `xthread_free`, and
page ownership protocols exactly before optimizing. The pinned release has no
separate delayed-free state; its unrelated `_mi_deferred_free` user callback is
part of the later callback surface.

For every atomic field, document:

- what state it represents
- which threads may read/write it
- the ownership transition
- why each memory ordering is sufficient
- which operation establishes publication
- which operation consumes publication
- ABA or versioning defense
- destruction/reuse conditions

Create a narrow atomics compatibility module that re-exports production
`core::sync::atomic` operations and can substitute Loom atomics in modeled
tests.

Do not make the complete allocator generic over an atomics trait. Keep the
abstraction limited to protocol-bearing modules.

Required Loom/model scenarios include, as applicable:

- local free racing remote free
- multiple remote frees
- local/remote deferred-list state transitions
- owner collecting while another thread publishes
- page retirement racing remote publication
- heap/theap detachment
- abandoned-page adoption
- first-class heap deletion with outstanding theaps
- TLS key reuse
- arena bitmap claim/release
- metadata reclamation

The model may use smaller capacities and finite state, but it must execute the
same transition functions or closely shared pure protocol code used by
production. Do not maintain a completely separate "verified" algorithm that
can drift from live code.

======================================================================
13. FORK CORRECTNESS
======================================================================

Audit the exact upstream v3.5.0 fork behavior and guarantees. Do not assume
that absence or presence of a public atfork hook settles correctness.

crabc supports fork and has its own internal fork sequence. Define and test a
clear allocator guarantee:

- after a multithreaded parent forks, the parent remains valid;
- the single-threaded child can allocate, reallocate, free, collect, and exit;
- allocator locks or ownership records held by vanished threads cannot
  permanently deadlock the child;
- remote-free and abandoned-page state is repaired or conservatively handled;
- current-thread TLS and IDs are valid in the child;
- callbacks and statistics remain internally consistent.

Add internal allocator lifecycle hooks to crabc's fork path when required:

- prepare
- parent
- child

Do not consume one of the bounded public `pthread_atfork` registration slots
for internal allocator correctness. Invoke internal hooks directly from the
runtime's fork implementation in a documented order relative to user handlers
and the thread registry.

Fork hooks must not allocate.

Use process-isolated tests with timeouts for:

- fork before any allocation
- fork after single-thread allocation
- fork while several worker threads have private and remotely freed blocks
- fork after thread churn
- child allocation/free/realloc
- child freeing memory inherited from the parent where permitted
- parent continuing after child exits
- repeated fork cycles
- fork failure
- fork under debug and secure configurations

If crabc intentionally provides stronger fork behavior than upstream C
mimalloc, document it as a crabc hardening extension rather than falsely
claiming byte-for-byte upstream parity.

======================================================================
14. PUBLIC API AND FEATURE PARITY INVENTORY
======================================================================

Generate an inventory from pinned v3.5.0 public headers and tests.

Include:

- standard allocation APIs
- extended allocation APIs
- aligned and offset-aligned APIs
- usable-size APIs
- first-class heap APIs
- theap APIs
- arena APIs
- subprocess APIs
- collection and purge APIs
- statistics and process-information APIs
- options
- output/error/deferred callbacks
- process and thread lifecycle APIs
- memory visitation/walking APIs
- externally managed memory APIs
- experimental APIs present in the pinned public header
- compile-time secure/debug/statistics/guarded modes
- macro-only source conveniences, distinguished from ABI functions

For every item classify:

- required and platform-applicable
- platform-applicable but optional mode
- source-only macro
- unsupported on Linux/AArch64, with exact rationale
- deliberately omitted from crabc-libc's exported ELF surface while still
  implemented by the allocator engine or test C API adapter

Store the inventory in a deterministic machine-readable format, for example:

    compat/allocator/api-v3.5.0.json
    compat/allocator/parity.toml

Generate a human-readable allocator section in the compatibility dashboard.

An API counts as:

- exported only when the intended adapter exposes it;
- implemented only when it has real behavior;
- verified only when an applicable test exercises it;
- performance-qualified only when its relevant workload has passed.

No TODO, panic, unconditional error, or inert stub counts as implementation.

Separate two milestones:

1. libc allocator readiness:
   crabc's public malloc-family contract can safely use the Rust engine.

2. complete mimalloc parity:
   every platform-applicable v3.5.0 public feature is implemented and verified.

The first may be reached earlier. The final project goal includes both.

======================================================================
15. SECURE, DEBUG, GUARDED, AND STATISTICS MODES
======================================================================

Mechanically inventory the actual v3.5.0 compile-time configurations. Do not
invent an approximate `secure = true` mode that loses upstream distinctions.

Represent supported configurations explicitly through Cargo features or
compile-time cfg profiles. Enforce invalid combinations at compile time.

Default production configuration must match upstream's normal release profile
as closely as applicable.

Test relevant profiles separately:

- default release
- debug/checking levels
- secure levels
- full guard configuration where supported
- statistics enabled
- guarded sampling/options
- optional AArch64 architecture optimization

Secure-mode tests must cover applicable protections such as:

- encoded free-list corruption
- double-free detection
- metadata protection
- guard pages
- randomized state
- invalid pointer diagnostics
- buffer padding/overrun checks where configured

Use subprocesses for tests expected to abort or fault. Compare the semantic
outcome and diagnostic category, not randomized addresses or exact
address-containing text.

Do not claim malloc is async-signal-safe. Diagnostics and callbacks must still
avoid accidental allocator recursion.

Statistics and callback code must be reentrancy-aware. Test callbacks that:

- inspect statistics
- trigger deferred collection
- write output
- attempt reentry
- are installed and replaced concurrently where the upstream API allows it

======================================================================
16. CORRECTNESS ORACLES
======================================================================

Use the correct oracle for each layer:

- pinned C mimalloc v3.5.0:
  mimalloc engine and `mi_*` semantics
- pinned musl 1.2.6:
  crabc's standard libc allocation contract
- Linux kernel:
  raw VM primitive behavior
- deterministic shadow model:
  allocation-lifetime and content properties
- crabc's existing ABI:
  symbol binding, interposition, errno, startup, pthread, and fork behavior

Do not use glibc as the normative oracle.

When upstream mimalloc and musl-facing behavior differ, keep the adaptation in
the crabc-libc facade. Do not contaminate the allocator engine with errno or
unrelated libc policy.

When apparent upstream behavior is undefined, erroneous, or security-sensitive:

1. reduce it to a minimal C oracle reproducer;
2. identify whether the public contract defines the behavior;
3. do not deliberately reproduce memory unsafety merely to make an invalid-use
   test look identical;
4. document a deliberate safe difference when necessary;
5. preserve valid-program semantic parity.

======================================================================
17. C ORACLE BUILD
======================================================================

Add a hermetic oracle builder under `compat/allocator`.

It must:

- fetch or use the pinned v3.5.0 archive;
- verify its SHA-256;
- build inside the pinned Linux/AArch64 development image;
- use a recorded compiler and flags;
- build default, debug, secure, and other required profiles;
- operate offline once the development image/cache is prepared;
- record source, compiler, flags, configuration macros, artifact hashes, and
  symbols.

Build the C baseline with optimization appropriate to an upstream release,
such as `-O3`/release configuration, but record the exact command.

Provide two fair performance comparison forms:

A. Opaque allocator boundary

Both C and Rust allocators are called through comparable non-inlined ABI
boundaries. This isolates allocator implementation behavior.

B. Integrated production build

Measure the actual crabc configurations:

- current C mimalloc integration
- Rust mimalloc integration with the workspace's production fat-LTO profile

Do not present only the integrated comparison, because Rust whole-program LTO
and C library boundaries can otherwise conceal whether the algorithmic port
itself regressed.

Do not present only the opaque comparison, because the integrated result is
the actual product.

======================================================================
18. LAYOUT, CONSTANT, AND BIN TESTS
======================================================================

Before general allocation works, build exhaustive tests for pure allocator
arithmetic:

- size rounding
- overflow rejection
- alignment validation
- bin selection
- every bin boundary
- object size and usable size
- page capacity
- page-map indexing
- bitmap bit/run selection
- arena slice arithmetic
- pointer encoding/decoding
- tagged state
- maximum allocation boundaries
- `PTRDIFF_MAX` and `SIZE_MAX` edges
- OS page-size interactions
- virtual-address upper boundaries

Generate boundary vectors around every transition, not merely random inputs:

- N - 1
- N
- N + 1
- alignment - 1
- exact alignment
- one object beyond page capacity
- one slice beyond arena capacity
- highest valid and first invalid values

Compare generated Rust outputs with a small C probe compiled against pinned
v3.5.0.

These tests should run quickly and become the first regression gate for every
later change.

======================================================================
19. DETERMINISTIC DIFFERENTIAL TRACE HARNESS
======================================================================

Build a deterministic operation-trace harness.

Run the C and Rust implementations in separate fresh processes. Do not load
both process-global allocators into one address space.

The same seed and operation stream must execute against both implementations.

Use logical allocation IDs. Never compare pointer addresses directly.

Operations must eventually cover:

- allocate
- zeroed allocate
- free
- realloc grow
- realloc shrink
- realloc failure
- zero-size forms
- aligned allocation
- offset-aligned allocation
- usable size
- fill/check byte patterns
- collect
- purge
- first-class heap create/delete/destroy
- cross-thread allocation and free
- theap acquisition/release
- arena reserve/manage/allocate
- subprocess create/delete
- thread creation and exit
- option changes allowed by the API
- callback installation
- deterministic OS failures

Compare observable properties such as:

- success or failure
- required alignment
- usable size constraints
- preservation of old bytes
- zero initialization
- old-allocation validity after failed realloc
- object identity relationships where specified
- callback event categories
- normalized statistics
- leak/liveness counts
- exit or diagnostic category for invalid-use subprocess tests
- errno at the crabc-libc facade

Do not compare:

- raw pointer values
- ASLR-dependent placement
- random cookies
- exact randomized allocation order unless a deterministic injected seed makes
  it contractual
- timing inside a correctness trace

The child trace runners must minimize interference from their own machinery.
Prefer:

- deterministic in-process PRNG from a seed
- fixed-capacity operation tables
- binary output
- direct writes
- no JSON allocation inside the allocator-under-test process

The parent harness may translate the fixed binary record into JSON reports.

On failure:

- store the seed;
- store the exact operation trace;
- automatically shrink the trace when practical;
- emit a standalone reproducer;
- keep the minimized trace as a permanent regression.

Run a bounded deterministic seed set in normal CI and a much larger seed set
in the full/soak lane.

======================================================================
20. UPSTREAM TEST SUITE
======================================================================

Compile and run all relevant pinned upstream tests against:

1. pinned C v3.5.0;
2. the Rust test C API adapter.

Begin with the upstream test inventory, including relevant API, fill, stress,
heap, subprocess, wrong-use, and override tests.

Track each upstream test as:

- runs unchanged
- minimally adapted for the crabc harness
- not applicable, with exact reason
- blocked by a missing feature
- passing
- failing with known difference

Avoid rewriting upstream tests into unrelated Rust tests when the original C
test can directly prove source and ABI compatibility.

Any adaptation must be a small recorded patch applied by the harness. Store
the patch and its hash. Do not maintain an untraceable copied test fork.

Run wrong-use/corruption tests in isolated processes with timeouts.

======================================================================
21. FAULT INJECTION AND OOM
======================================================================

Create deterministic, allocation-free fault injection at the primitive layer.

Support failure of the Nth applicable operation, including:

- reserve/map
- commit
- metadata map
- page-map expansion
- protect
- purge/decommit
- remap
- huge-page request
- entropy acquisition
- arena metadata allocation

Also support:

- address-space/commit ceilings
- bounded metadata capacity in model tests
- deterministic thread/TLS initialization failure where meaningful

Verify:

- null/error result is correct
- allocator global state remains usable
- no double unmap
- no leaked ownership claim
- no stale bitmap claim
- no partially published page
- failed realloc preserves the original allocation
- callbacks and errno behavior are correct at the appropriate layer
- later successful allocation can proceed where the contract permits

Combine synthetic fault injection with process-level resource limits or
cgroups for a smaller set of realistic OOM tests.

Fault-injection counters, logs, and reports must not allocate through the
allocator under test.

======================================================================
22. MIRI, LOOM, AND OPTIONAL FORMAL SIDECARS
======================================================================

Miri:

Create a host-model primitive backend for allocator logic that cannot execute
direct Linux/AArch64 syscalls under Miri.

Use it to exercise:

- pointer arithmetic
- initialization and teardown
- page/object state transitions
- local allocation/free
- realloc content preservation
- alignment
- metadata initialization
- strict provenance
- deterministic trace fragments

The host backend is test-only. Do not broaden production target support.

Loom:

Use Loom for finite models of the actual atomic protocols identified earlier.
Keep the atomics substitution narrow and auditable.

Formal verification:

After the relevant live code stabilizes, consider a small Verus or equivalent
sidecar for pure, high-value kernels such as:

- bin mapping
- overflow-safe rounding
- bitmap run claims
- page-map bounds
- selected free-list state transitions

A proof sidecar must remain tied to live code through shared pure functions,
generated exhaustive vectors, or an explicit equivalence check. Do not prove
a separate toy allocator and count that as production verification.

Formal proof is not a substitute for the C oracle, real concurrency tests, or
performance evidence.

======================================================================
23. STRESS MATRIX
======================================================================

Create deterministic and soak variants of allocator stress.

Size distributions:

- every small-bin boundary
- tiny allocations
- medium allocations
- large allocations
- very large allocations
- mixed powers of two and near-powers of two
- random bounded sizes
- high alignments
- page-size and arena-boundary sizes

Lifetime patterns:

- immediate allocate/free
- FIFO
- LIFO
- random lifetime
- mostly live
- mostly dead
- periodic full collection
- long-lived sparse pages
- burst, idle, purge, burst
- fragmentation and partial reuse

Concurrency patterns:

- thread-private allocation/free
- producer allocates, consumer frees
- many producers, one consumer
- one producer, many consumers
- random cross-thread transfer
- owner exits before remote free
- thread churn
- first-class heap shared by many threads
- concurrent heap/theap lifecycle
- arena contention
- subprocess isolation

Modes:

- default
- debug
- each supported secure profile
- guarded mode where applicable
- stats enabled
- baseline AArch64
- optional Armv8.3 profile

Every stress run must have:

- deterministic seed
- bounded duration or operation count
- watchdog timeout
- direct crash/deadlock identification
- final liveness/leak accounting
- report artifact

======================================================================
24. CRABC-SPECIFIC INTEGRATION TESTS
======================================================================

Expand the existing allocator fixture rather than replacing it.

Preserve and extend tests for:

- non-null/freeable zero-size allocation
- required alignment
- distinct live allocations
- calloc zeroing and multiplication overflow
- realloc grow/shrink
- realloc failure preserving the original allocation
- crabc's zero-size realloc behavior
- `free` preserving errno
- musl-compatible aligned allocation behavior
- `posix_memalign` output untouched on failure
- usable-size behavior
- all allocator-related symbols currently expected from musl

Add:

- allocations before main
- global constructors allocating
- allocations during thread-local initialization
- pthread-specific destructors allocating
- cleanup handlers allocating
- thread cancellation where supported
- fork after concurrent allocation
- allocator use in the fork child
- weak-symbol interposition
- replacement malloc/free pair
- mixed static and dynamic linking
- shared-library constructor/destructor use
- loader interactions
- no accidental recursion through libc
- exit-time teardown
- process termination without explicit allocator shutdown

Run the existing crabc evidence commands, including the relevant portions of:

    ./scripts/dev.sh structure
    ./scripts/dev.sh build
    ./scripts/dev.sh test
    ./scripts/dev.sh compat
    ./scripts/dev.sh pthread-stress
    ./scripts/dev.sh static-pthread-tls
    ./scripts/dev.sh corpus
    ./scripts/dev.sh rust-std
    ./scripts/dev.sh rust-std-dependent
    ./scripts/dev.sh lua
    ./scripts/dev.sh perf

Add focused canonical commands:

    ./scripts/dev.sh allocator --quick
    ./scripts/dev.sh allocator --full
    ./scripts/dev.sh allocator-perf --smoke
    ./scripts/dev.sh allocator-perf --full

`allocator --quick` must be suitable for ordinary development.

`allocator --full` must include the upstream suite, differential seeds,
stress, backend matrix, modes, fork/TLS tests, and corpus integration.

The normal workspace test lane must exercise the Rust allocator backend even
while the C backend remains the default.

======================================================================
25. PERFORMANCE HARNESS
======================================================================

Extend the repository's existing controlled AArch64 performance machinery.
Do not replace its statistical methodology with a casual benchmark library.

Allocator workloads must include at least:

Single-thread fast path:

- fixed-size malloc/free across representative bins
- mixed small sizes
- calloc
- realloc grow/shrink
- aligned allocation
- usable-size query
- hot page reuse

Concurrency:

- thread-private allocation
- remote free
- producer/consumer
- many-to-many transfer
- thread churn
- shared first-class heap/theap
- arena contention

Memory behavior:

- fragmentation
- long-lived sparse pages
- burst then idle
- purge/collection
- partial page liveness
- repeated peak allocation
- large and huge allocations
- metadata-heavy workloads
- arena reservation and release

Real workloads:

- existing Lua lane
- existing Rust std lane
- dependency-bearing Rust fixture
- selected Alpine package corpus programs
- representative C programs compiled against crabc
- at least one long-running mixed allocation workload

Measure:

- operations per second
- CPU time
- batch latency distribution
- p50, p95, p99, and p99.9 where statistically meaningful
- cycles
- instructions
- branches and branch misses
- cache misses where counters are stable
- syscall counts
- minor and major page faults
- reserved memory
- committed memory
- RSS
- PSS/USS where available
- cgroup `memory.peak`
- allocator-reported statistics
- startup time
- text/rodata/data size
- final binary size

For extremely fast operations, do not put a clock read around every single
operation and report the timer overhead as allocator latency. Measure
controlled batches and derive statistically valid distributions.

Use:

- fresh processes
- pinned CPU or vCPU
- deterministic workload seeds
- randomized/interleaved backend run order
- identical workload binaries where technically possible
- at least 31 valid samples for gating comparisons
- one-sided bootstrap confidence intervals
- explicit environment metadata
- unchanged source-tree and artifact hashes

Separate baseline AArch64 from any Armv8.3-optimized profile.

Do not use QEMU TCG or a shared public CI runner for the final performance
qualification. A dedicated native AArch64 Linux machine or sufficiently
isolated hardware-virtualized AArch64 Linux executor is acceptable when the
harness records stable variance and environment data.

Docker Desktop on Apple Silicon is useful for development measurements but
must not automatically be labeled a qualified performance environment. Detect
and report virtualization, counter availability, and observed variance.

Run benchmark smoke tests in ordinary CI to detect crashes and gross
regressions. Run statistical promotion gates only on a qualified executor.

======================================================================
26. INITIAL PERFORMANCE PROMOTION BANDS
======================================================================

Compare Rust against exact C mimalloc v3.5.0 under equivalent configurations.

Use ratios where 1.0 is C parity.

Default-profile initial non-inferiority gates:

Throughput:

- lower one-sided 95% confidence bound for the suite geometric mean >= 0.95
- no critical workload lower bound < 0.90 without an explicitly accepted,
  narrowly explained exception

Tail latency:

- upper one-sided 95% confidence bound for critical p99 batch-latency ratio
  <= 1.10

Memory:

- upper one-sided 95% confidence bound for peak RSS/PSS suite geometric mean
  <= 1.05
- no critical workload upper bound > 1.10
- no unexplained unbounded growth or failure to purge

System behavior:

- no material unexplained syscall amplification
- no material unexplained page-fault amplification
- no allocator metadata leak under thread churn
- no regression hidden by process exit

Binary/code size:

- report allocator text/rodata and final artifact size
- investigate any >10% increase attributable to the Rust allocator
- do not accept accidental monomorphization or duplicated cold paths merely
  because throughput passes

These are initial explicit bands. Tighten them when evidence supports it.

Do not weaken them solely to make the implementation pass. A threshold change
requires a documented rationale, before/after reports, and review as its own
change.

Run at least three independent full comparison runs on a qualified environment
before default promotion. Store each immutable report.

Benchmark secure and debug profiles as informational and regression evidence,
but default-profile parity is the primary default-promotion gate.

======================================================================
27. AARCH64 CODE-GENERATION AUDIT
======================================================================

Compare optimized C and Rust hot paths using the pinned LLVM tools and system
object tools.

Inspect at least:

- default small allocation
- local free
- remote free publication
- page lookup
- bin lookup
- aligned allocation fast path
- thread-local theap lookup

Check for accidental Rust costs:

- panic branches
- bounds checks
- integer division
- calls to formatting or unwinding
- TLS helper calls in the expected fast path
- missed inlining
- unnecessary zeroing
- redundant atomic fences
- unnecessary SeqCst operations
- address-provenance helper calls not optimized away
- code duplication

Do not add `#[inline(always)]`, unchecked indexing, custom assembly, or weaker
atomics merely on intuition.

Optimization procedure:

1. demonstrate a statistically credible regression;
2. profile it;
3. compare generated C and Rust code;
4. identify a concrete semantic/code-generation cause;
5. add or retain a focused correctness regression;
6. make the smallest change;
7. rerun differential, modeled concurrency, stress, and performance tests;
8. record the result.

Preserve baseline Armv8 compatibility. Keep optional Armv8.3 optimizations in a
separate profile.

======================================================================
28. IMPLEMENTATION MILESTONES
======================================================================

Implement in these reviewable vertical milestones.

Milestone 0: scope, pin, inventory, skeleton

- update durable scope/docs
- pin v3.5.0 source and archive hash
- add `crabc-mimalloc` no_std crate
- establish dependency checks
- add API inventory generator
- add source port map and ratchet
- build exact C oracle
- generate configuration/layout baseline
- add canonical dev commands
- leave current allocator behavior unchanged

Acceptance:

- hermetic oracle build works
- crate builds as an empty/skeletal Linux/AArch64 library
- production dependency policy is enforced
- inventories and reports are deterministic

Milestone 1: pure foundations

- configuration
- bits/arithmetic
- types
- atomics facade
- provenance helpers
- invariants
- random primitives
- minimal OS primitive boundary
- static/bootstrap state definitions

Acceptance:

- exhaustive arithmetic/bin/layout tests
- C differential constants pass
- host-model Miri tests pass
- no allocator operation is advertised yet

Milestone 2: OS memory, metadata, arena, page map

- reserve/commit/decommit/purge/protect
- memory provenance IDs
- bitmap machinery
- metadata allocation
- page map
- arena substrate
- initialization state machine
- fault injection

Acceptance:

- map/unmap lifecycle tests
- page-map boundary tests
- deterministic failure tests
- concurrent initialization tests
- no recursive allocation

Milestone 3: single-thread small allocation

- default heap/theap bootstrap
- pages and page queues
- small-bin allocation
- local free
- page retirement/reuse

Acceptance:

- every bin boundary
- deterministic C traces
- Miri host traces
- repeated allocate/fill/free
- no concurrency claims yet beyond initialization

Milestone 4: complete fundamental allocation API

- calloc
- realloc
- aligned and offset-aligned allocation
- usable size
- medium/large/huge paths
- collection and purge
- overflow and OOM semantics

Acceptance:

- existing crabc allocator fixture passes through Rust backend
- relevant upstream API tests pass
- deterministic fault injection passes
- all fundamental operations have C differential coverage

Milestone 5: concurrency and thread lifecycle

- remote free
- owner-local and cross-thread deferred-free list integration
- page abandonment/adoption
- thread initialization and teardown
- dynamic versioned TLS slots
- first-class heap/theap attachment

Acceptance:

- Loom protocol suite
- pthread stress
- thread churn
- owner-exit/remote-free tests
- no deadlock or metadata growth
- applicable upstream stress tests pass

Milestone 6: heaps, theaps, arenas, subprocesses

- complete first-class heap API
- complete theap API
- arena API
- externally managed memory where applicable
- subprocess API
- deletion/destruction semantics

Acceptance:

- upstream heap/subprocess tests
- deterministic cross-thread traces
- lifecycle/failure tests
- API inventory for these groups fully verified

Milestone 7: options, callbacks, stats, secure/debug modes

- options and environment parsing
- output/error/deferred callbacks
- process statistics
- walking/visitation
- debug modes
- secure modes
- guard modes
- optional architecture profile

Acceptance:

- complete platform-applicable API inventory
- all supported compile profiles build and test
- wrong-use tests run in isolated processes
- no unclassified public API holes

Milestone 8: full crabc-libc shadow integration

- selectable Rust backend
- startup context
- pthread hooks
- fork behavior
- errno/POSIX facade
- weak-symbol/interposition preservation
- static and dynamic link tests

Acceptance:

- all existing crabc allocator tests
- full workspace tests
- pthread/TLS/fork tests
- symbol and ABI gates
- Rust std, Lua, and selected corpus programs
- Rust backend remains nondefault during this milestone

Milestone 9: performance convergence

- full C/Rust benchmark matrix
- hot-path code-generation audit
- targeted optimization
- RSS/purge investigation
- repeated qualified reports

Acceptance:

- performance, latency, memory, syscall, and code-size gates pass
- no correctness or verification ratchet regression
- at least three independent qualified full reports

Milestone 10: default promotion

Make default promotion a small isolated commit.

- change default allocator feature to Rust
- ensure `libmimalloc-sys` is absent from the default production graph
- preserve explicit C oracle lane
- regenerate all compatibility and performance reports
- update durable docs to state the evidence-backed default
- retain a compile-time rollback backend during a bounded stabilization period
  if useful; no runtime selector

Acceptance:

- clean checkout
- offline-capable pinned build
- all quick/full allocator gates
- all workspace gates
- all real-program gates
- all ABI/interposition gates
- all qualified performance gates
- `cargo tree`, symbols, and artifact inspection prove no production C mimalloc

If any promotion condition is unavailable or fails, leave the Rust backend
required and fully tested but nondefault. Report the precise unmet gate.
Do not redefine "complete" and do not flip the default speculatively.

Milestone 11: stabilization and cleanup

After the Rust default has accumulated complete evidence:

- remove obsolete production C-backend plumbing where safe
- retain pinned C oracle construction in `compat/allocator`
- preserve differential and performance lanes
- simplify transitional features
- document the upstream update procedure
- freeze a v3.5.0 parity baseline report

Do not delete the oracle merely because the Rust implementation is now
default.

======================================================================
29. COMPLETENESS AND REGRESSION RATCHETS
======================================================================

Add machine-enforced ratchets for:

- upstream public API inventory
- API implementation count
- API verification count
- translated source map coverage
- upstream test coverage
- configuration-profile coverage
- differential seed corpus
- ABI symbol contract
- performance-qualified workloads

Generated dashboards must distinguish:

- absent
- exported
- implemented
- unit verified
- differentially verified
- stress verified
- performance qualified
- deliberately unsupported

Never count an implementation merely because a symbol links.

Every fixed bug must add at least one durable regression artifact:

- focused test
- minimized operation trace
- Loom schedule/model
- fault-injection case
- upstream test adaptation
- real-program fixture
- benchmark workload

The compatibility dashboard should show both:

- crabc libc allocator readiness
- full mimalloc v3.5.0 feature parity

======================================================================
30. REPOSITORY AND COMMIT DISCIPLINE
======================================================================

Read the current repository's durable docs and follow its established harness
and report conventions.

Do not perform unrelated cleanup.

Do not rename existing public APIs without necessity.

Do not introduce future-platform abstractions.

Before each production slice:

1. identify the upstream source region and invariants;
2. add or extend the focused test;
3. implement the smallest complete behavior;
4. run the focused test;
5. run relevant differential and model tests;
6. update the port map and parity ledger;
7. commit the coherent slice.

Keep commits small enough to review semantically.

Suggested commit progression:

- scope/pin/harness
- crate foundations
- OS and metadata substrate
- small allocation
- fundamental API
- remote free/TLS
- heaps/theaps
- arenas/subprocess
- options/stats/secure
- libc integration
- fork hardening
- performance convergence
- default promotion

Do not combine default promotion with a large allocator rewrite.

Do not weaken tests, skip failures, or widen tolerances in the same commit that
introduces the regression unless the commit contains a separately justified
contract correction with oracle evidence.

======================================================================
31. FINAL EVIDENCE REPORT
======================================================================

At the end, produce a concise but complete report containing:

- actual starting and ending crabc commits
- exact upstream tag, commit, archive hash, and license
- production dependency graph
- source-map coverage
- public API counts by status
- upstream test counts and adaptations
- deterministic differential results and seed counts
- Miri result
- Loom/model result
- stress operation counts and seeds
- fault-injection coverage
- pthread/TLS/fork results
- ABI/interposition/symbol results
- real-program and corpus results
- performance environment qualification
- C-versus-Rust throughput table
- tail-latency table
- RSS/PSS/peak-memory table
- syscall/page-fault table
- code-size table
- known deliberate differences
- any unqualified features
- whether the Rust backend was promoted to default
- evidence for the promotion decision

Every success claim must name the command and resulting report artifact.

A clean implementation that remains nondefault because one objective gate did
not pass is preferable to an unjustified default switch.

The final state should make it possible for a future maintainer to answer,
mechanically and without relying on prose optimism:

- Which v3.5.0 APIs are present?
- Which are actually implemented?
- Which have C differential evidence?
- Which have concurrency or stress evidence?
- Which compile-time profiles work?
- Which workloads are performance-qualified?
- What differs intentionally from upstream?
- Can the exact C oracle and all reports be reproduced offline?
- Does the default crabc artifact contain any C mimalloc code?

The most important element is the **two-stage notion of completion**. The Rust backend can become suitable for crabc’s ordinary `malloc` ABI before every optional arena, subprocess, visitation, and secure-mode API is finished. But the project should continue until the machine-readable v3.5.0 ledger reaches full Linux/AArch64-applicable parity. Conversely, even 100% API coverage is insufficient to justify making it default until the thread, fork, memory-use, and non-inferiority gates pass.

[1]: https://github.com/microsoft/mimalloc/releases/tag/v3.5.0 "https://github.com/microsoft/mimalloc/releases/tag/v3.5.0"
[2]: https://microsoft.github.io/mimalloc/group__heap.html "https://microsoft.github.io/mimalloc/group__heap.html"
[3]: https://github.com/verus-lang/verified-memory-allocator "https://github.com/verus-lang/verified-memory-allocator"
[4]: https://github.com/microsoft/mimalloc/issues/1282 "https://github.com/microsoft/mimalloc/issues/1282"
