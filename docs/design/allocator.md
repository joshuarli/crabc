# Fixed mimalloc semantic-port contract

## Purpose and status

`crabc` may replace the C allocator implementation in its production graph
with a provenance-preserving, pure-Rust semantic port of a fixed mature
allocator. This is a narrow compatibility exception to the project rule
against allocator research. It does not authorize a new allocator design.

The initial target is mimalloc v3.5.0, pinned at
`18b08671c9302247bfb682286e6bf3cc1773f801`. Its archive, license, source
mapping register, and update procedure are in
[`crabc-mimalloc/UPSTREAM.md`](../../crabc-mimalloc/UPSTREAM.md).

The current production `libmimalloc-sys` 0.1.49 backend bundles mimalloc
v3.3.2. It remains the default during this work, but it is not the exact
v3.5.0 C oracle: the pinned v3.5.0 archive must be built separately for the
Rust-port differential and performance baseline.

The workspace now contains the `crabc-mimalloc` crate with source-mapped
configuration, arithmetic, types, provenance, atomic operations, size classes,
ordinary and binned caller-owned bitmap views, a live two-level page map,
immutable Linux memory policy, regular/aligned mapping ownership, an in-place
external-arena substrate, a private futex lock boundary, and bounded
nonallocating support kernels. Its allocator-owned random state is the exact
`mi_random_ctx_t` image stored directly in `Theap::random`; it preserves the
pinned original-ChaCha state and output contract through the audited RustCrypto
primitive, direct entropy lifecycle, and a documented degraded entropy path.
A bounded current-thread TLD checkpoint attaches each private TLD to one
process-main identity. Its generic metadata branch remains no-theap, while
`main_theap.rs` consumes only ticket zero into one private process-static main
heap/default-Theap attachment and publishes its compiler-TLS default then fast
roots. `process_init.rs` now owns one deliberately bounded source-order
transition: it reserves the static ticket-zero branch, initializes the static
Heap, readies detached metadata, publishes the distinct global PageMap, and
only then attaches the static TLD/Theap roots. Its selector prevents a generic
TLD constructor from consuming ticket zero while that transition is active or
retained. `ProcessMainReadyLease` is an immutable process-root witness; it
does not expose map mutation, a shared arena, metadata's private map/arena, or
thread teardown. This is not a general process initialization state machine:
options/OS setup, stats, pthread/TLS keys, automatic shared-arena reservation,
free routing, shutdown, and fork handling remain separate.

`process_page_map.rs` owns the separate process-static source-page-map
publication boundary. It freezes one `MemoryConfig` and selected
`MainSubprocess`, initializes a `PageMap` in its final slot, then
Release-publishes the header root. `process_arena.rs` is its deliberately
separate `mi_manage_os_memory_ex2` sidecar: it accepts one caller-selected,
single-arena `Mapping`, binds an `ArenaRegistry` to that exact map/root/main
identity before publication, and retains the mapping and in-place arena image
for process lifetime. For a reserved map, it first places the `Mapping` in its
final sidecar slot, then gives the in-place arena a stable callback to commit
metadata and later selected/page-metadata ranges through that exact owner; the
frozen Linux decommit callback reports no recommit requirement. A metadata
commit failure takes the exact map back before publication, with an empty
registry and COLD sidecar but the selected pair still bound for retry.
`ProcessPageArenaLease` validates that immutable tuple
before either `main_static_page.rs` or `main_heap_page.rs` may borrow its
selected source Theap. Each private owner holds the map's nonrecursive
lifecycle lease for its complete engine and scoped-producer lifetime, installs
the chosen arena's in-place `pages_main` bitmap in the shared static main Heap,
and preserves the source bitmap -> PageMap publication and PageMap -> bitmap ->
metadata -> slice-release order. It is distinct from `MetaAllocator`'s private
map/arena and every caller-managed test map. The bounded process coordinator
now invokes the global map stage in source order, but this map/arena subsystem
still has no automatic reserve policy, C `mi_page_map_empty` pre-root, general
concurrent page consumer, owner-exit traversal, or process shutdown. A rejected
unpublished mapping returns to its caller; a failed map reservation or dropped
unfinished lifecycle is terminal rather than exposing a null or fresh root.
This callback is not a fresh-page policy. The paired lease has only one
range-checked direct page-area commitment operation for an already-selected
`mi_page_extend_free` transition; page-on-demand selection,
`slice_pcommitted` advancement, and failed-commit `_mi_page_abandon`
reabandonment remain separate page-lifecycle transitions.

The bounded metadata prerequisite from `src/subproc.c:19-88` is now also
present. `MetaAllocator` is one process-static, `!Unpin` owner: its internal
operations require `Pin<&'static MetaAllocator>`, validate the current live
AArch64 thread-pointer identity before taking a nonrecursive `PrivateLock`,
then lazily build a direct-OS page map and aligned external arena in their
final static slots before Release-publishing a detached `ExclusiveTheap`.
Before that arena is published, the metadata owner selects the same bounded
main-subprocess identity for its arena registry, so its registry and published
arena agree with the detached heap/TLD/theap image.
The ordinary page lifecycle supplies the first and later metadata blocks; no
`alloc`, libc, public pthread API, compiler-TLS root, separate metadata slab,
or mmap-per-block path participates. Its must-use, non-Copy
`MetaAllocation<'owner>` capability records the static owner address, requested
size, and `MemoryId::Malloc` provenance. The bounded regular-TLS and
subprocess-attached/no-theap TLD owners retain and move that capability as a field, never
reconstruct it from the raw pointer. Every safe typed backing, TLD, and dynamic-Theap
projection first requires that capability's atomic lifecycle to remain live, so a
released capability cannot form a reference into freed bytes. The checkpoint retains the source allocation-under-lock,
unlock-before-copy/free `rezalloc` ordering and serializes cross-thread free,
but it intentionally covers only successful Malloc capabilities: null,
needs-no-free, and non-Malloc arena-release paths, subprocess destruction,
full heap/theap lifecycle, and public ABI routing remain open. A separate,
narrow regular-TLS owner now retains its `MetaAllocation` capability while its
dynamic compiler-TLS root is live; it does not attach a TLD or theap.

One private vertical slice now binds a caller-pinned default theap to a
caller-managed external arena and page map. It claims and publishes exact
small, medium, large, and singleton spans, maintains direct and generic
candidate/regular/full queues, extends and collects scalar local free lists,
retires fully free pages, unregisters complete spans before arena release, and
rolls back injected commitment, bitmap, and page-map failures. The quick oracle
gate compares 378 address-independent allocation facts with exact pinned C
v3.5.0 across all 62 small-bin transition requests. A second 51-key exact
differential record covers page-kind selection, checked calloc, ordinary
reallocation, aligned and offset-aligned allocation, usable size, preservation,
and invalid-size failure. Those operations are live in the private lifecycle,
including OS-aligned singleton ownership for power-of-two alignments above
64 KiB and below the 256 MiB metadata limit. Failed terminal unmaps retain one
exact allocation-free owner for later collection or allocation-boundary retry.
For unpinned external arenas, slice release now schedules the pinned default
four-second purge delay before reuse. Forced collection owns the free-bitmap
range while applying the source `purge_decommits=1` non-owning decommit; pinned
backing skips the path, decommit failure restores availability plus immediate
retry state, and only the external owner may unmap the complete mapping.
This is bounded engine evidence, not an exported production allocator: the
crate still has no production public operation, libc integration, integrated
process/TLS lifecycle, general thread teardown, integrated remote-free routing,
fork protocol, or backend selection. The present Milestone 5 foundations are intentionally
narrower: exact AArch64 versioned TLS keys, caller-owned per-thread slots, the
older lock-serialized caller-storage registry substrate, and one distinct
allocator-owned process-global regular-key registry, five private compiler-TLS
roots with direct `TPIDR_EL0` identity, low-bit atomic remote publication and
owner collection, and one private linear `RemoteFreeProducer` over an exact
active matching regular non-huge-bin or `BIN_FULL` allocation. Its exclusive
allocator borrow prevents safe owner mutation while one scoped worker holds the
`Send`/`!Sync` token; `publish` touches only the source remote head and
`cancel` restores the original client pointer. The caller must still prove the
worker joined/quiesced before queue collection. The regular generic scan,
including a small direct-cache miss, consumes publication before it extends or
classifies a page full; the non-abandoning full-page pass consumes it before
release-or-unfull. Every non-abandoning move to `BIN_FULL` also performs the
source's second false-force collection after enqueue. The explicit detached
metadata session has no producer path and performs only the local false-force
portion. The raw owner-local projection also ports the force-only list append:
when both lists are nonempty it validates the local chain, appends the old
immediate head, and clears `local_free`; a malformed cycle is rejected before
that link. The bounded later-main all-free exit drain invokes that true-force
operation only after its fixed fast-slot clear; ordinary regular/full and
detached paths still use false force. Its separate sole full-singleton handoff
uses false force after its preflight and before queue detach, while both
mapped-one-block sole-page handoffs preserve the source force-then-false sequence
before bitmap publication. The full-origin medium branch retains that origin
after force collection, so it remains client-free-only rather than borrowing
the separate initially-nonfull medium adoption/requeue authority. The one-block
handoff accepts only its empty final free. Separate full-medium and full-large
routes first preserve the source full-queue detach and ordinary unmapped
abandonment. A separate full
non-direct-small route preserves that same unmapped tail while detaching from
its ordinary small bin instead of `BIN_FULL`; it requires
`block_size > SMALL_SIZE_MAX`, has no direct-cache image, and takes the
ordinary failed-reclaim collector. The complementary full direct-small route
also remains in its ordinary bin, but requires `block_size <= SMALL_SIZE_MAX`,
`reserved >= 16`, `used == reserved`, and its complete rounded
`pages_free_direct` range. Queue removal clears that range before page-count
detach, and its failed-reclaim partial collector retains the just-published
atomic head before the source free count reaches the mostly-used boundary.
Sequential client frees remain unmapped while `free <= reserved / 8`, then the
first below-mostly-used free publishes the exact static-main bitmap/count pair
and subsequent frees use the mapped tail. Their terminal empty results still
release in PageMap -> `pages_main` -> metadata -> slice order after old-Theap
teardown; the large route validates its complete 64-slice span. The process
route can keep one sole
nonfull small-or-medium page mapped while its linear
client frees finish after the old Theap/TLD is gone. A direct small member is
recognized by rounded source block size, preflights its exact
`pages_free_direct` range, and clears that range with queue removal before the
former Theap page count drops; the small partial-free tail retains its source
`reserved >= 16` invariant. Full small pages remain outside that nonfull route;
the dedicated routes above admit the direct and non-direct full-small shapes. The
aggregate regular-pages route applies that same source sequence to every
qualifying small, medium, or large page, releases force-empty pages, and stores
PageMap/bitmap registry. Its direct-small preflight accepts only the complete
source-derived queue-head cache image and refreshes that cache during queue
removal before the Theap count changes. None of these process routes broadens
the drain into general live-page abandonment or routing. An owner-side collection error permanently poisons this private
allocator with the exact page, error, and any already-popped block; all later
allocation, inspection, free, producer preparation, and collection entry
points reject without another queue or page-map transition. A bounded one-page
abandonment/adoption protocol, a current-thread-only regular TLS backing owner,
one ticket-zero process-static main heap/default-Theap attachment with one
bounded paired-process page engine, a no-page later-thread attachment with one
sequential paired-process page engine over that same main Heap, and one
later-ticket dynamic Theap attachment over a caller-pinned Heap image. That
backing owner has an explicitly unsafe lifecycle boundary: its caller must
exclusively own the current `TPIDR_EL0` TLS lifecycle. It obtains a zeroed
`mi_thread_locals_t`-shaped flexible image from `MetaAllocator`, starts at 16
slots, doubles below 1024, adds 1024 at and above 1024, honors the least-index
override, rejects a derived count above 65535, and publishes `memid` then
`count` before the regular dynamic root. Its live projection checks the header
count and exact Malloc provenance against the retained capability; null
out-of-range writes do not allocate, and generation matching remains the
caller-owned slot contract. Regular teardown frees before setting only that
dynamic root null, leaving the default/cached/fast roots untouched. If an
internal metadata free or replacement reports an ownership-consumption
ambiguous error, the owner clears that root and becomes terminal rather than
inventing a retryable capability. No valid-program C semantic difference is
claimed from that internal error limitation. `DynamicTheapAttachment` is the
only key-to-current-thread integration: it retains the backing owner with one
linear regular-key lease, metadata TLD registration/allocation, typed dynamic
Theap metadata, and a pinned caller Heap. Process/pthread hooks and production
ELF integration remain absent.

`owned_tls_key_registry.rs` ports the separate process-global regular-key
bitmap from `src/threadlocal.c:221-315`. It is allocator metadata, not
compiler TLS, and never writes `DYNAMIC_BACKING_ROOT`. Its private lock
serializes the 16-bit-index/48-bit-generation stream and retains each bitmap
as one typed `MetaAllocation`; a `BitmapView` exists only within a locked
operation. The first image is 1,024 bits (256 bytes), every growth appends
exactly 1,024 bits, and 63 growth-block allocations reach the 64,512-bit source ceiling before a
64th allocation is rejected. Every image uses the selected main subprocess's
aligned Malloc metadata route. Claim follows ordinary `tseq = 0` low-to-high
chunk-map traversal and advances generation only after the one-bit claim. Copy
growth preserves the old image, Release-publishes the larger count without
clearing that prefix, then marks only the append free. The linear lease requires
explicit release; drop deliberately does not return a key. Bounded shutdown
rejects live leases and late claim/release, but is not `_mi_thread_locals_done`,
fast-key deletion, or process shutdown. It never installs compiler TLS itself;
the private dynamic attachment is its sole current-thread consumer. The
fixed lock order is registry then `MetaAllocator`. Typed-image invariant or
ownership-ambiguous post-commit-free failures poison and retain process-static
ownership; allocation failures before commit preserve the old image and
generation.

`subproc.rs` now represents the deliberately small process-static identity of
`mi_process_subproc_main`: it owns only the relaxed source
`thread_total_count` sequence, relaxed live `thread_count`, and the real
static `mi_process_tld_main` slot. It is explicitly not a Rust layout claim
for full `mi_subproc_t`; subprocess lists, heaps, arenas, statistics, and M6
subprocess APIs remain absent. A linear non-Send ticket records the old value
from `thread_total_count.fetch_add(Relaxed)` before any static/metadata storage
choice. Ticket zero initializes the actual `MemoryKind::Static` TLD slot with
its own source base and `size_of::<ThreadLocalData>()` image size, without
touching `MetaAllocator`; later tickets use the existing fresh
direct-zeroed metadata route. An allocation failure therefore consumes its
source sequence but never increments the live count. Only a fully initialized
TLD can consume its ticket into a non-dropping registration lease, whose
explicit consuming release performs exactly one live-count decrement.

`ThreadLocalDataOwner` receives that ticket internally rather than taking a
caller-supplied sequence. Its full source-ordered TLD image names the same
process-main identity as the detached metadata heap/TLD/theap bootstrap and
its pre-publication-bound arena registry, records direct `TPIDR_EL0`, Linux
NUMA, the pinned Unix `is_in_threadpool = false` result, an initialized private
lock, and initially a null theap-list pointer. This generic owner is precisely
**subprocess-attached, no-theap**. Generic construction can own ticket zero
only while `MainSubprocess` remains open. Production static startup uses
`ProcessMainInitializationStorage`, whose selector blocks generic ticket
issuance after static selection and whose Heap-foundation capability must exist
before ticket zero can issue. `MainStaticTheapAttachment` is the sole static
exception: its static Heap foundation precedes the coordinator's PageMap stage,
then dynamic-empty/fast-null/default-empty/cached-empty root preflight precedes
the static TLD/Theap attachment. Its one process-static owner has cache-aligned,
address-stable `Heap` and `Theap` field slots, not separate Rust statics. The
main `Heap` follows `mi_heap_main_init_once` with kind-only
`_mi_memid_create(MI_MEM_STATIC)` provenance (zero union/flags); concrete
pinned/committed static image memids remain for the TLD and Theap. It then
preserves `_mi_theap_init` order: empty-image copy, TLD/refcount/subprocess,
normal live options, locked TLD-list attachment and random/cookie setup,
Release heap publication, and locked heap-list attachment. It publishes the
default root followed by fast; cached and dynamic remain their immutable empty
roots. The represented `Heap` stops after its source `memid`, retaining only
valid zero/deferred abandoned and arena regions; it is neither a full C size
assertion nor a public heap API.

A busy freshly owned TLD/heap list, a subsequent list-attachment error, or a
post-mutation private unlock error is terminal initialization-invalid-owner
handling: the static TLD/live registration and process-static storage remain,
no teardown owner is returned, and a TLD-list failure before root publication
leaves every root pristine. These failures require invalid concurrency or a
kernel/private-lock failure outside the valid one-owner contract; C locks do
not return them.

After exact root ownership validation, static teardown requires
`page_count == 0` as a Rust pre-mutation invariant; a nonzero count poisons but
preserves every live root, list, image, and registration. Once that check
passes, `_mi_thread_done` (`src/init.c:448-481`) calls
`_mi_thread_locals_thread_done` before `mi_thread_theaps_done`, so the valid
count-zero/no-pages path is fast-root clear, then default/cached reset, then
the heap/TLD detach. It leaves the untouched count-zero dynamic image
installed, detaches the heap list under the outer TLD lock before
Release-clearing `theap.heap`, then detaches the TLD list and clears
links/TLD/random/cookie/subprocess. It invalidates the TLD, proves its lock
quiescent, releases the live registration, and terminally retires the static
TLD slot. Root mismatch and pre-root page failure preserve their foreign/live
roots. Conversely, fallible private lock/list boundaries after root reset are
terminal invalid-owner states; a post-mutation unlock error likewise requires
invalid concurrency or a kernel/private-lock failure, and process-static
storage/live registration remain rather than claiming teardown. This slice
does not implement source heap-busy retry.

`main_heap_thread.rs` separately ports the ordinary later-thread branch of
`_mi_thread_init_with_heap(mi_heap_main())`. A
`MainStaticTheapAttachment::shared_main_heap_lease` is borrow-tied to the live
ticket-zero owner and grants only short, lock-serialized mutable projections of
its address-stable main `Heap`; it cannot publish or retire ticket-zero roots.
Each `MainHeapThreadAttachment` obtains a nonzero metadata TLD and metadata
Theap, links that Theap into the shared main heap, then publishes default before
the fixed fast slot while retaining the immutable count-zero dynamic backing and
the canonical empty cached root. After user destructors, its direct no-page
finish clears fast, resets default/cached, detaches the shared heap list before
the TLD list, clears/frees the Theap metadata, tears down the TLD, and releases
the shared-main lifetime count. The main attachment rejects teardown while that
count is nonzero. `main_heap_page.rs` now binds one current
`MainHeapThreadAttachment` to the same matching `ProcessPageArenaLease` before
it borrows the attachment as a page session. It verifies subprocess and frozen
configuration before map acquisition, serializes the complete engine and one
joined scoped producer through the process-map lease, and uses the shared
main Heap's `Arena::pages_main` image rather than a dynamic bitmap. Its normal
finish returns to the no-page path only after map registrations, bitmap bits,
queues, direct entries, and page count are empty. Its separate consuming exit
drain instead clears the fixed fast slot first, force-collects every queue
(including full), and releases pages that become all-free through PageMap
unregistration -> `pages_main` clear -> metadata retirement -> slice release.
That scan still retains any general live page rather than queue-detaching or
abandoning it. Eight explicit, disjoint owner-exit handoffs are available only
after fast-slot clear and only when the drain has `page_count == 1`, the target
is its sole queue member, and every other queue/direct slot is empty.
`MainHeapThreadProcessPageExitDrain::abandon_full_singleton` accepts the full
one-block arena singleton (`BIN_FULL`), false-collects, queue-detaches, and
unmapped-abandons it while retaining its PageMap lifecycle lease and
registration. Its exact final client free takes the raw failed-reclaim empty
result, then performs PageMap -> `pages_main` -> metadata -> slice release.
The same handoff also accepts one sole OS-aligned singleton in `BIN_FULL`,
regardless of the ordinary size class of its one object. It validates the
complete clipped PageMap/alias release witness, links the still-owned page in
the source `Heap::os_abandoned_pages` list before unowning it, then removes
that exact member before PageMap unregister -> alias clear -> primary retire
-> mapping reclaim. A failed `munmap` retains the unique published mapping
owner terminally in the later attachment; this does not add OS-list scanning,
reclaim, requeue, or reuse.
`MainHeapThreadProcessPageExitDrain::abandon_mapped_one_block` accepts only a
medium regular arena page with `reserved > 1`, `used == 1`, no direct-cache
entry, and a main-arena abandoned bitmap for its exact regular bin. It first
performs the source force then false collection sequence, queue-detaches the
page, and publishes that exact `pages_abandoned[bin]` bit plus the paired
static-main `Heap::abandoned_count[bin]` before unowning it.
`MainHeapThreadProcessPageExitMappedOneBlockHandoff::remote_free_to_empty`
then takes the source mapped abandoned-free prefix: it collects the final block
and admits only the empty decision, which precedes any reclaim branch. It
clears the mapped identity/bit, consumes that paired count, and performs the
same PageMap -> `pages_main` -> metadata -> slice release; a still-live page
is terminally retained rather than reclaimed or requeued.

`MainHeapThreadProcessPageExitDrain::abandon_full_medium_to_process_route` and
`MainHeapThreadProcessPageExitDrain::abandon_full_large_to_process_route` are
the fourth and fifth handoffs. They accept only the sole full medium or large
arena page in `BIN_FULL`, preserve force then false collection and
queue/page-count detach, and follow source's ordinary unmapped abandonment
before actually tearing down the old Theap/TLD. Their linear
`MainHeapThreadProcessPageExitFullMediumRoute` and
`MainHeapThreadProcessPageExitFullLargeRoute` keep stable arena/Heap/span/bin
witnesses under short PageMap access. Client frees remain unmapped through
`free <= reserved / 8`; the first below-mostly-used free reabandons the page
into its exact static-main `pages_abandoned[bin]` bit plus paired
`Heap::abandoned_count[bin]`, after which the mapped failed-reclaim tail owns
the final PageMap -> `pages_main` -> metadata -> slice release. The large
route validates the complete 64-slice PageMap span before terminal release.
They expose no allocation-time claim, reclaim, requeue, or concurrent route.

`MainHeapThreadProcessPageExitDrain::abandon_full_medium_after_force_collect_to_mapped_process_route`
is a separate, source-specific predecessor of the eighth mapped route rather
than a new full-page state machine. It accepts the same sole full medium
`BIN_FULL` page only when one different allocation has already been published
through a joined remote producer. The `MI_ABANDON` force collector changes
`used` from `reserved` to exactly `reserved - 1` while source still leaves the
page linked and marked full; its following false collector must preserve that
state. `_mi_page_abandon` then removes the exact `BIN_FULL` member, clearing
the full flag and page count, and immediately publishes the ordinary medium
mapped-abandoned identity plus the exact static-main bitmap/count pair. The
old Theap/TLD tears down before the remaining linear client frees enter
`MainHeapThreadProcessPageExitMappedRegularRoute`. Regular/nonfull input
rejects before mutation, and a collector fault retains the drain terminally.
It deliberately excludes multiple joined frees, local-free variants,
small/large pages, all-free release, normal full-page unmapped abandonment,
allocation-time adoption/requeue, mixed traversal, and concurrent frees.

`MainHeapThreadProcessPageExitDrain::abandon_full_non_direct_small_to_process_route`
is the sixth handoff. It accepts only a sole full `PageKind::Small` arena page
with rounded `block_size > SMALL_SIZE_MAX`. Unlike the
medium/large `BIN_FULL` shapes, pinned `page.c:766-832` retains this full small
page in its ordinary regular bin, so the transition verifies that exact queue,
requires every direct slot empty, and never treats it as a direct cache member.
It takes free.c's ordinary collector, then preserves force then false
collection, regular-queue/page-count detach, ordinary unmapped abandonment,
the mostly-used boundary, static-main
bitmap/count reabandonment, and the existing one-slice terminal release. It
does not accept direct full small pages, mixed pages, adoption, reclaim,
requeue, or concurrent frees.

`MainHeapThreadProcessPageExitDrain::abandon_full_direct_small_to_process_route`
is the seventh handoff. It accepts only a sole full `PageKind::Small` arena page
with rounded `block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, and
`used == reserved`. Pinned direct allocation leaves this full page in its
ordinary regular bin rather than `BIN_FULL`, so preflight requires its complete
rounded `pages_free_direct` range to name the sole page and every other direct
slot to be empty. It preserves force then false collection, regular-queue
removal, direct-cache clear before page-count detach, and ordinary unmapped
abandonment before old-Theap/TLD teardown. Its free.c partial collector retains
the just-published atomic head, so the exact source mostly-used decision occurs
after that one-head accounting lag. The resulting mapped tail keeps the exact
static-main bitmap/count pair until the same one-slice PageMap -> `pages_main`
-> metadata -> slice release. It exposes no allocation-time claim, reclaim,
requeue, adoption, mixed traversal, or concurrent free routing.

`MainHeapThreadProcessPageExitDrain::abandon_mapped_small_or_medium_to_process_route`
is the eighth handoff. It accepts one sole nonfull arena page with one or more
live blocks when it is a medium page or any small page. The small decision uses
the rounded source block size, not the request size. A direct small page must
have its complete source direct-cache range point at that sole page with every
other direct slot empty; queue removal clears that range before page-count
detach. It also retains the source partial-collector `reserved >= 16`
invariant. It preserves the same force -> false -> queue/direct/page-count
detach -> mapped identity/bit/count -> unown order, and retains the exact
complete PageMap span plus static-main arena/Heap witnesses. It then calls
`MainHeapThreadAttachment::finish_after_detached_process_page_route`, so the
old Theap/TLD is genuinely detached and freed before a later client free.
`MainHeapThreadProcessPageExitMappedRegularRoute` holds only those stable
witnesses plus `ProcessPageMapPostExitAccess`: every consuming client free
briefly re-acquires the same process PageMap serialization, looks up the
mapped-abandoned page, and runs the source no-current-Theap free tail. A
nonempty result keeps the paired mapped identity/bit/count and returns the
linear route; the final free clears that pairing before the PageMap ->
`pages_main` -> metadata -> slice release. The route is movable to a client
free thread but is not shareable as concurrent routes. Every full small page
remains outside this nonfull sole route, checked by `used < reserved` because
it can remain in a regular queue; the sixth and seventh handoffs own the
non-direct and direct full-small counterparts.

One deliberately consuming allocation-time edge is now complete for this
sole route only. `MainHeapThreadProcessPageExitMappedRegularRoute::adopt_into_later_main`
accepts an exact `PageKind::Medium` route and a fresh
`MainHeapThreadAttachment` only after the subprocess, frozen configuration,
stable PageMap root, static main Heap, and selected arena all match. It turns
the route's `ProcessPageMapPostExitAccess` back into a
`ProcessPageMapMutationLease`, so the new engine owns one continuous
source-plain map lifecycle. `ThreadExitMappedRegularPostExitParts` keeps a
non-dereferencing page identity solely to reject a foreign PageMap entry before
the source low-owner claim. The handoff then follows
`src/arena.c:631-778,951-1153` and `src/page.c:245-302`: it claims the exact
static-main bitmap member and paired count, collects while abandoned,
reassociates the page with the new Theap/thread identity, collects live state,
re-proves the complete PageMap span and medium geometry, and appends the
queue-detached page with `page_queue_push_at_end_metadata` at the target queue
tail before restoring its page count/direct-cache image. It accepts either an
immediate head or an exhausted nonfull medium page (`capacity < reserved`). A
fully committed page (`slice_pcommitted == 0`) performs scalar
`mi_page_extend_free` free-list/capacity mutation after that tail restoration.
The bounded test-only `commit == false` seam creates one actual reserved medium
page with the source initial callback-committed prefix. For that nonzero-prefix
case, `page_area_commit_plan` separates OS-page counts from byte ranges, then
the paired retained mapping performs the direct `_mi_os_commit`-shape extension
before `Page::set_slice_pcommitted_after_commit` or
`LocalFreeList::extend_count` may publish state. If that commit fails,
`reabandon_after_page_commit_failure` follows source false collection, queue
detach, direct-cache/page-count repair, and mapped identity/bit/count/unown
publication. The resulting consuming owner can retry only the same candidate
through its long lifecycle; it cannot reopen short map access, scan, or take a
fresh fallback. This proves no production page-on-demand option. A bitmap miss,
malformed state, scalar extension error, or any other post-transfer failure
likewise retains the target owner. Small/direct,
full, aggregate-registry, singleton, unmapped, huge, foreign,
automatic-scanning, and concurrent adoption remain deliberately unsupported.

`MainHeapThreadProcessPageExitDrain::abandon_mapped_regular_pages_to_process_route`
is a separate aggregate boundary, not a loop over the older sole-page token.
Its complete non-mutating structural preflight requires every direct slot to
match the source queue-head image and every queued page to be a nonfull regular
small, medium, or large arena page. A direct small member must retain
`reserved >= 16` for the source partial collector. It also
proves every intrusive queue's complete bounded doubly linked image: an empty
queue has null endpoints; a nonempty queue has a null head predecessor, each
successor names its actual predecessor, and its counted forward walk ends at
the registered null-terminated tail. A zero-used page is accepted only when
normal local free left its source retirement countdown nonzero;
unsupported/mixed images still reject before mutation. It then ports
`_mi_theap_collect_retired(theap, true)`'s regular-bin portion, releasing those
already-empty retired spans before the normal source visit order for each
remaining page: force-collect, immediately release an all-free page,
false-collect a still-live page, then queue detach, direct-cache refresh,
page-count detach, and mapped identity/bit/count publication. This narrow `MI_ABANDON` edge deliberately
does not turn on the absent deferred-callback, arena-collection, or stats-merge
work. `ThreadExitMappedRegularPagesPostExitParts` is the resulting fixed-capacity
registry: membership remains in each page's PageMap registration and exact
`pages_abandoned[bin]`/`abandoned_count[bin]` pair, while its `remaining_pages`
count tracks only spans that have not yet completed terminal release. It
contains neither raw page pointers nor a former-Theap borrow. After actual
old-Theap/TLD teardown, each consuming free briefly locks the map, acquires the
source low owner bit before deriving that page's bin/capability, and either
returns the still-live route, releases one page, or releases the last page and
completes the map route. A terminal free re-derives that page's regular span
before unregistration, so the one-slice small, 8-slice medium, and 64-slice
large spans remain distinct source shapes. A retired/force-empty traversal returns the
ordinary drain instead of creating an empty registry. Fresh engines may serialize
independent PageMap operations between frees, but the current engine surface
exposes no allocation-time adoption, reclaim, or requeue capability for a
registered aggregate member. Apart from the explicit sole-medium handoff
above, it exposes no allocation-time claim, reclaim, or requeue for a
post-exit route.

Other live-page states are rejected before aggregate detach: full, singleton,
huge, unmapped, foreign, malformed, or non-source-derived direct-cache state
remain separate work.
An empty drain may call `MainHeapThreadAttachment::finish_after_page_drain`;
the detached routes instead use their narrowly typed finish once the old Theap
image is empty. Any force/release failure is retained terminally; the drain
cannot allocate, run source deferred callbacks/arena collection, or resume as
a normal engine. This remains deliberately bounded: apart from the explicit
sole-medium handoff above, it is not allocation-time claiming, reclaim/requeue,
concurrent later-thread routing, general page traversal/abandonment or owner
exit, a `pthread` hook, or public allocator routing.

`main_static_page.rs` is the corresponding ticket-zero owner of that separately
initialized process pair. Its `MainStaticProcessPageAllocator` accepts only a
matched `ProcessPageArenaLease` and the live ticket-zero
`MainStaticTheapAttachment`; it rejects a foreign subprocess before borrowing
the static image or acquiring the map lifecycle lock. The session requires no
linked later Theap, installs only `Arena::pages_main` into the static main
Heap, and gives every fresh page the exact static Heap/Theap identity. It
supports ordinary local allocation/free plus one joined scoped producer, then
finishes only after map registrations, bitmap bits, queues, direct entries,
and page count are empty. An unfinished engine poisons both the static owner
and the process map root rather than fabricating a release route. The bounded
process coordinator may supply the map predecessor, but neither page owner
reserves an arena or implements multi-arena routing, general abandonment/owner
exit, pthread/TLS hooks, process shutdown, or public allocator routing.

`DynamicTheapAttachment` uses `MainSubprocess::issue_later_thread_ticket` so
it atomically refuses ticket zero while the selected static bootstrap is
active or retained. It is `!Send`/`!Sync`, holds the caller-pinned Heap plus exact
metadata TLD/live-registration/Theap/backing/key capabilities, and preserves
dynamic `_mi_theap_init` through the TLD and heap lists before publishing the
regular-key slot, then replaces only the canonical empty cached root and
performs its owner-only `1 -> 2` Theap reference transition. Default and fast
remain unchanged; a foreign or merely separately empty cached root rejects
before ticket issuance. Its no-page preflight validates TPIDR identity,
default/fast preservation, its exact cached pointer/refcount, single-member
lists, regular slot, and `page_count == 0` before mutation. Valid teardown
clears the slot and dynamic backing, restores that exact empty cached root and
performs `2 -> 1`, then detaches, Release-clears the Theap heap, releases the
live TLD registration, and invalidates/quiesces/frees metadata before retiring
the caller binding and key. Pre-publication OOM cleans up and rejects;
post-list-publication list/backing/free failures retain a poisoned owner and
all still-valid capabilities. A pre-mutation key-release lock error is the
sole retry state: `AwaitingKeyRelease` retries only that lease.

The ordinary dynamic constructor stores the source abandoning option image
`allow_page_abandon = true` / `page_full_retain = 2`, so
`DynamicTheapAttachment::page_session` rejects it without touching an arena or
page map. The crate-private unsafe non-abandoning constructor instead stores
the source-reachable `false` / `-1` image before Release heap publication.
Only that mode can create a sealed unsafe `DynamicTheapPageSession`, which
borrows the attachment for the whole `PageAllocatorEngine` lifetime and
revalidates its current thread, regular slot, cached root/refcount, lists,
heap/TLD binding, zero page count, and exact option profile. It reuses the
existing private page engine and its scoped joined/quiescent remote producer;
it is not a general dynamic allocation route. `finish(self)` consumes a
dynamic engine only after force collection, empty queues/direct entries, zero
page count, and no retained collection poison or pending OS release. An
unfinished engine Drop latches the attachment terminally, leaving its live
page/map/resource state in place and transferring any pending OS release owner
into that retained attachment rather than allowing teardown to claim
quiescence. This does not implement heap new/delete/destroy, general
cached-root switching/references, general dynamic routing or remote-free
concurrency, abandonment, pthread hooks, or process shutdown.

After that same attachment clears its regular backing, a distinct
`DynamicTheapPageDrainSession` retains the cached root, both list memberships,
the dynamic arena image, and the PageMap until its pages are resolved. The
current drain is intentionally one source-reachable owner-exit case rather than
a traversal: its finishing boundary force-collects an already-retired all-free
regular page, and its singleton live-page transition accepts a full one-block arena
or OS-aligned singleton. Both forms retain `reserved == used == 1` and the
no-producer proof that makes the outer source force collector's local-list
append unreachable; `_mi_page_abandon` false collection still precedes queue
detach. The arena form follows the existing PageMap-span unregister,
heap-local ordinary-bit clear, metadata retirement, and arena-slice release.
The OS form is exactly one `MemoryKind::Os` page in `BIN_FULL`; its ordinary
block size may be small. After queue/page-count detach it links the still-owned
page into the dynamic Heap's `os_abandoned_pages` list before common unown.
Its exact client free removes that member before clipped PageMap unregister,
secondary alias clear, primary metadata retirement, and mapping reclaim. A
failed `munmap` parks the unique published mapping owner terminally in the
attachment. The returned handoff cannot scan, reclaim, requeue, or otherwise
generalize that OS list. Because the regular backing is already clear, source
reclaim cannot find the Theap. A drained attachment alone can then resume
cached-root/list/key teardown.

The same drain has three separately bounded mapped endpoints,
`DynamicThreadExitDrain::abandon_mapped_one_block` for a medium page,
`DynamicThreadExitDrain::abandon_mapped_one_block_non_direct_small` for a
small page with `SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE`, and
`DynamicThreadExitDrain::abandon_mapped_one_block_direct_small` for a small
page with `block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, and its complete
rounded source direct-cache range. Each accepts only one sole, nonfull
`MemoryKind::Arena` page with `reserved > 1`, `used == 1`, and a single regular
queue member. The non-direct-small class has an empty direct-cache image; the
direct-small class rejects any stale range before source collection and clears
its exact range after queue removal but before page-count detach. Its retained
dynamic arena image can form only that page's matching heap-local
`pages_abandoned[bin]` bit and paired `Heap::abandoned_count[bin]`; it is not a
post-TLS allocation or reclaim capability. Source force then false collection
precedes queue/page-count detach and mapped identity/bit/count/unown
publication. `DynamicThreadExitMappedOneBlockHandoff` retains that source-class
witness and receives only the exact final client free: medium/non-direct small
use the normal collector, while direct small consumes the partial collector
head; each becomes empty before any reclaim branch, clears the dynamic
bit/count pair, then releases the queue-detached PageMap span -> dynamic
ordinary bit -> metadata -> arena slices. It cannot adopt, requeue, scan,
reclaim the departed Theap, or handle multiple pages or frees.

On the first fresh dynamic arena page, that same session lazily creates one
private `DynamicArenaPagesOwner`. Before allocating it proves that the
registry-published arena has a non-null `Arena::subprocess` equal to the
attachment's selected main subprocess. It then retains one exact zeroed,
`BCHUNK_SIZE`-aligned `MetaAllocation`, initializes the `mi_arena_pages_t`
header plus ordinary bitmap tail, and Release-publishes only the bound dynamic
Heap's `arena_pages[arena_index]` slot under its private lock. The shared
engine then follows the source order:
fresh page metadata, heap-local ordinary bitmap bit, page-map registration;
rollback and terminal release use the inverse map-clear then exact
heap-local-bit-clear order. `ArenaView::pages_main` remains untouched by a
dynamic page. Empty teardown removes that exact slot before freeing the typed
image; a nonempty image is a wholly pre-mutation rejection. Allocation failure
before publication leaves the slot null and retryable. Lock/unlock/free
ambiguity after mutation terminally retains the known owner state. A consuming
`DynamicMappedPageHandoff` now ports one mapped regular arena-page handoff:
after false-force collection it removes the exact regular queue member and
page count, installs abandoned identity, Release-publishes its one heap-local
abandoned bit, increments `Heap::abandoned_count[bin]`, and unowns it. The
same token can either claim that exact bit for adoption or consume one still
live client block through `free.c:mi_free_try_collect_mt`'s
`allow_collect=true` same-origin branch. The latter preserves the small-page
partial collector's head, clears the bit/count before live reassociation,
collects again, and appends the page back to the same Theap queue. Its all-free
dynamic-arena result retains the distinct queue-detached release capability and
follows the source order: full PageMap-span unregister, exact heap-local
ordinary-bit clear, metadata retirement, then arena-slice release. Only after
all four succeed does it expose the drained engine. An existing abandoned owner
or a later release failure remains terminal; forgetting or post-claim failure
also retains the engine rather than exposing normal free/allocation. Full,
non-singleton huge, non-arena, foreign, and ordinary abandoning-session pages
remain rejected. The sole singleton exceptions are the post-TLS arena and
OS-aligned owner-exit handoffs above; neither is normal abandoned routing or a
general thread-exit page traversal. The separate post-TLS mapped
medium/non-direct-small/direct-small one-block handoffs above likewise have no
adoption/reclaim/requeue or general
dynamic traversal. General producer routing, multiple arena images, OS-list
traversal/reclaim/requeue, and general heap destruction remain deferred.

`PrivateLock` preserves the TLD field's private-lock meaning but is not a
byte-identical pthread mutex, so no C `sizeof(mi_tld_t)` claim is made.
General cached-root switching/reference ownership, general remote-free/page
routing or abandonment integration beyond these bounded handoffs, full
heap/Theap/arena/subprocess APIs,
pthread/process hooks, fork repair, process shutdown, and general lock
destruction remain outside this slice.

The abandonment/adoption protocol preserves mapped versus unmapped source
classification, publishes the abandoned bitmap/count before releasing
ownership, restores a failed reader's bit, waits for reader quiescence before
unabandoning, drains after source bitmap claim while still abandoned, then
reassociates a claimed page and performs the live-owner collection before
queue insertion. Its separate
`abandoned::free_unmapped_after_failed_reclaim` tail starts only after the
source reclaim decision has failed: it preserves a small partial head through
the expected-head CAS, collects a conflict without retrying reclaim, and then
selects terminal-empty, mapped reabandonment, or unmapped unownership using
the source integer mostly-used boundary. It deliberately does not itself
release or reuse a page. Its raw-release owners are the post-TLS arena and
OS-aligned singleton handoffs above; all other initially-unmapped pages retain
the raw terminal decision for a later lifecycle. A test-only Loom model executes the
live-owner remote-head publication/detach loops and the abandoned
owner-claim/unown races under bounded schedules; deterministic native
regressions cover the bitmap-field quiescence and full one-page abandonment
interleavings. A dedicated pinned-target probe proves that the TLS
roots are hidden `STT_TLS` objects accessed through initial-exec relocations
without `__tls_get_addr`; its negative control proves the pinned compiler
default emits TLSDESC. Rust has no per-static model annotation, so this is a
bounded crate-codegen proof: production integration must apply the same
per-crate setting and audit the final linked static and shared images. These
slices do not provide integrated allocator thread lifecycle, general terminal
page release, or metadata reuse while a remote producer can exist.
A default-off `test-adapter` feature is the sole exception to that public-
operation statement: it provides an allocation-backed, creating-thread-only
context for the standalone prefixed C evidence adapter. Its stable boxed control
owners, root-last publication, exact outstanding-block count, and staged
page-map/arena teardown are test harness machinery, not a production process
singleton or libc integration path. The separate
`compat/allocator/test-adapter` package exports exactly 16 `crabc_test_*`
symbols and no standard allocation or `mi_*` symbols. The full evidence lane
uses it for the existing crabc allocator fixture and 33 reviewed checks from
the hash-pinned upstream `test/test-api.c`; the applied patch and every omission
are checked-in contracts rather than a copied upstream source fork.
A fixed-capacity `cfg(miri)` mapping model exercises current
VM ownership and page-map transitions without broadening production support;
the pinned toolchain does not currently install Miri itself. No allocator
readiness or promotion claim follows from this slice.

## Scope boundary

The port is Linux/AArch64 little-endian only, with Linux 5.10 as the kernel
floor and support for valid Linux/AArch64 page sizes. It must be `#![no_std]`,
must not depend on `alloc` or libc, and must not compile C or C++ in the
production allocator. No x86-64, RISC-V, macOS, Windows, big-endian,
32-bit, or portability scaffold is in scope.

The port preserves mimalloc v3.5.0's algorithms, data structures, memory
orderings, lifecycle behavior, and valid-program observable behavior until
parity is established. It is not permitted to replace those mechanisms with
more idiomatic but materially different Rust algorithms. Any such divergence
requires all of the following before acceptance:

- a written design note explaining the upstream behavior and the divergence;
- deterministic differential evidence against the exact pinned C source; and
- Linux/AArch64 performance and memory evidence showing that the divergence is
  justified.

The pinned C implementation remains the mandatory source, differential, and
performance oracle after it is removed from the production dependency graph.
Glibc is never an allocator or C-runtime oracle.

### Random-state dependency boundary

Pinned mimalloc `src/random.c` implements a ChaCha20-based PRNG/DRBG for
allocator cookies and secure mode; it is not merely a `getrandom` syscall
adapter. The project-wide cryptography contract therefore forbids translating
that algorithm locally into `crabc-mimalloc`. `crabc-core::rand` may provide
raw Linux entropy, but substituting repeated syscalls or another algorithm
would be an unproved semantic and performance divergence.

The approved dependency is
`chacha20 = "=0.10.1"` with default features disabled and only `legacy` plus
`zeroize` enabled. `zeroize = "=1.9.0"`, also with defaults disabled, is a
direct dependency so the source's temporary key and output-block cleanup use
its compiler-resistant primitive. The selected Linux/AArch64 external graph
is nine packages total:
`chacha20`, `cfg-if`, `cipher`, `block-buffer`, `hybrid-array`, `typenum`,
`crypto-common`, `inout`, and `zeroize`. None has a build script or native
code in that graph; the selected features use neither `std` nor `alloc`, keep
no global state, and allocate no memory. All are MIT-or-Apache-2.0 licensed.
The resolved lockfile also records `cpufeatures` 0.3.0 and `libc` 0.2.189 for
the crate's target-conditional non-AArch64 backend; Cargo does not select
either package in the fixed Linux/AArch64 graph. The structure check fixes the
direct versions and features, while `allocator --quick` traverses Cargo
metadata for `aarch64-unknown-linux-musl` and rejects any selected package,
version, edge, source, build script, or proc macro outside the audited graph.
It therefore still rejects a compiled libc dependency instead of mistaking
lockfile presence for an active allocator edge.

`random::TheapRandomImage` is the authoritative `#[repr(C)]`
`mi_random_ctx_t` layout: source sigma/key words occupy `input[0..12]`, its
64-bit counter occupies `input[12..14]`, its 64-bit nonce occupies
`input[14..16]`, and its C-ordered output/availability/weak fields follow.
`ChaCha20LegacyCore` is instantiated one block at a time from those words.
This preserves the pinned source's counter carry into only the low nonce word,
output word ordering, immediate clearing of consumed words, and eager child
block after `split_into`. Initialization and split derive nonces from the
actual stable random-field address; they do not return a movable child context.

`TheapRandomImage::initialize` calls direct Linux `getrandom` once. A complete
fill makes a strong context. An error or short fill (`Ok(false)`) follows the
source's continuation path, clears any temporary bytes, and marks the image
weak. The source's `_mi_random_shuffle` core cannot be translated under the
crypto policy, so `WeakObservations` serializes direct address, monotonic-clock,
thread-pointer, process/thread-ID, and extra-seed observations into a
domain-separated `ChaCha20LegacyCore` expansion. This is intentionally a
dependency-owned substitute for the source weak-key expansion; it adds no
entropy and does not create a second PRNG. `reinitialize_if_weak` retries direct
entropy only for a weak image; strong images make no second syscall.

Both `TheapRandomImage` and temporary key/output block copies are zeroized.
Normal Rust-owned bootstrap/test values run `Drop`; metadata release bypasses
Rust drop glue, so the future owner must call `TheapRandomImage::clear` before
returning a live theap image to the metadata allocator. The pure-Rust generic
implementation introduces no native call boundary and remains eligible for fat
LTO; its AArch64 code size, selected NEON path, and throughput are explicitly
unqualified until measured.

### Concurrency-test dependency boundary

`loom = "=0.7.2"`, with defaults disabled, is the sole allocator
`dev-dependency`. It is enabled only by the empty `loom` test feature and
models the exact `mi_thread_free_t` publication, owner-detach, abandoned
ownership-claim, and abandoned-unown transitions shared with production. The
model substitutes only the atomic head, address-free block links, and a boolean
for bitmap restoration responsibility; the bitmap field algorithm has its own
native quiescence regression. Raw-pointer lifetime, owner-local page mutation,
page identity, TLS, and page release remain outside that proof.

Loom's normal test graph includes its `generator`, `scoped-tls`, `tracing`, and
`tracing-subscriber` support stack. That graph uses `std`, allocation, global
scheduler state, and TLS. `generator` has a build script and a `cc` dependency,
but its external assembly path is PowerPC64-only and does not compile native
code for Linux/AArch64. Cargo metadata traversal continues to admit only normal
production edges from `crabc-mimalloc`, so Loom and its complete graph are absent
from allocator production builds and have no production `no_std`, native-code,
or fat-LTO consequence. `scripts/check_structure.py` pins this test boundary and
rejects any additional allocator dev-dependency.

## Ownership and integration boundary

The future production direction is:

```text
crabc-mimalloc -> crabc-core + chacha20 + zeroize
crabc-libc     -> crabc-core + crabc-mimalloc
```

`crabc-mimalloc -> crabc-libc` is forbidden. Raw Linux primitives belong in
`crabc-core` when genuinely needed; the allocator must not duplicate syscall
assembly or depend on public pthread APIs. Its lifecycle integration is direct
with crabc pthread startup, thread teardown, and fork paths.

`crabc-libc` retains the musl/POSIX C allocation ABI: weak and preemptible
symbols, interposition, `errno`, zero-size behavior, alignment, overflow,
reallocation preservation, and aligned-allocation output rules. The engine is
errno-free. `crabc-rs` continues to use ordinary Rust allocation and exposes
no C `malloc`/`free` allocation API.

There is no runtime allocator-selection framework. During validation, the C
implementation may be a build- or test-selected shadow backend; the Rust
implementation becomes the default only in a final isolated promotion change.

## Evidence and promotion

Track two outcomes separately:

1. readiness to back crabc's `malloc` family without changing its C ABI; and
2. parity for every Linux/AArch64-applicable public mimalloc v3.5.0 `mi_*`
   interface and compile-time mode.

Neither outcome follows from basic allocation tests. Promotion requires focused
invariants, layout/configuration probes, upstream-test evidence, deterministic
C differential traces, concurrency-model evidence, fault injection,
process-isolated misuse tests, pthread/TLS/fork and ABI/interposition tests,
and real-program/corpus evidence. It also requires C-vs-Rust throughput,
latency, RSS, virtual-mapping, startup, and allocation-path evidence on the
same Linux/AArch64 measurement contract. See
[`compat/allocator/README.md`](../../compat/allocator/README.md) and
[`docs/design/performance.md`](performance.md).

The current C backend remains the default until every stated correctness,
memory, latency, throughput, ABI, TLS, fork, and real-program gate passes.
