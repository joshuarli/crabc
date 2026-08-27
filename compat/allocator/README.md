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
map, one bounded source-order process-main coordinator, one separately owned
process-static page-map publication root plus one caller-selected
process-shared arena sidecar, its first lazy default-reservation policy, its
one ticket-zero first ordinary fresh-page connection, and bounded ticket-zero
and later-thread page
engines over their matched pair, including one all-free later-main exit drain
and its eight sole-page handoffs (a full arena singleton, an OS-aligned
singleton linked through `Heap::os_abandoned_pages` until its final release, a mapped medium
one-block page, full medium and full large `BIN_FULL` pages plus full
non-direct-small and direct-small regular-bin pages that begin unmapped and
reabandon after the source mostly-used boundary, and a nonfull mapped small-or-medium post-exit
route with exact full-medium, full-large, full-non-direct-small, and full-direct-small
one-joined-remote-free force-collection predecessors), six bounded later-main
full-page aggregate routes (arena singleton, homogeneous OS singleton, medium,
and large `BIN_FULL` members, plus non-direct-small and direct-small ordinary-bin
members), and one aggregate regular
small/medium/large post-exit registry, ordinary
and binned caller-owned bitmap views, an in-place external-arena substrate,
the private futex-lock boundary, bounded nonallocating support
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
not claim general subprocess destruction or public allocation routing.

`process_init.rs` owns a bounded source-order transition: static Heap
foundation, detached metadata readiness, global PageMap publication, then the
ticket-zero TLD/Theap roots. Its selector prevents generic TLD construction
from consuming ticket zero while startup is active or retained, and its ready
lease exposes only immutable map/configuration/subprocess witnesses.
`process_page_map.rs` owns that distinct process-static map
initialization/publication boundary. It freezes one `MemoryConfig` and selected
`MainSubprocess`, initializes the map in its final slot, and Release-publishes
the root; it is distinct from metadata's private map and all caller-managed
maps. `process_arena.rs` retains the lower `mi_manage_os_memory_ex2` ownership
edge for a caller-selected external mapping and adds one explicit regular
`mi_reserve_os_memory_ex2` entry. The latter accepts only a nonzero request
that rounds to exactly one complete arena, maps ordinary reserved or committed
memory, and records `MemoryKind::Os`. `reserve_default_os_arena` separately
ports the first lazy `mi_arena_reserve` policy: source max-page headroom, the
frozen 1-GiB Linux/AArch64 default, its overcommit-only eager mapping choice,
and the 128-MiB retry after an unpublished first attempt returns COLD. It is
not invoked at process startup; `MainStaticFirstArenaPageAllocator` owns the
one current private ticket-zero route, deriving an empty-Theap ordinary page
span and revalidating its zero-page image before the mapping side effect.
`ProcessMainThread` is its only production-shaped factory and transfers the
retained attachment plus immutable ready-map witness without mapping at
startup.
An unpublished metadata failure unmaps that exact regular mapping before
returning a cold retry state; a failed unmap retains it terminally. The
external entry still returns its unpublished rejected mapping to the caller. A
reserved map first enters the final sidecar slot so a stable arena callback
commits metadata and later selected/page-metadata ranges through that exact
owner; default Linux decommit reports no recommit requirement. Later arena
scaling, option mutation, large-page/exclusive/NUMA policy, and page-on-demand
routing remain absent. `ProcessPageArenaLease` has one range-checked direct
page-area commitment operation for an already-selected source extension, but it
does not maintain `slice_pcommitted` or own the failed-commit page-reabandon
branch. It then proves the exact map/root/configuration/main tuple for private
`MainStaticProcessPageAllocator`, `MainStaticFirstArenaPageAllocator`, and
`MainHeapThreadProcessPageAllocator`
owners. Each holds the process map's exclusive plain-entry lifecycle through
its complete engine and joined scoped producer, installs only the arena's
in-place `pages_main` bitmap into the shared static main Heap, and completes
normal fresh/release ordering through map, bitmap, metadata, and slices. It
can reconstruct one already-READY immutable map/arena pair for a subsequent
bounded owner, but does not search the registry, inspect free slices, or map.
Their normal `realloc` delegates retain source replacement-failure/copy
semantics; the ticket-zero null case alone may activate the completed
first-arena policy. It has only that bounded first ticket-zero connection from the completed
default-reserve policy to a fresh-page miss; it does not model the C
`mi_page_map_empty` pre-root or an existing-arena search,
and has no concurrent/general later-thread page routing, general owner exit
beyond the recorded all-free later-main scan, its eight sole-page handoffs, and
the bounded aggregate regular-pages traversal, teardown, or public routing.
Only the explicit consuming medium and direct-small handoffs (immediate-head,
exhausted fully committed scalar extension, exact prefix-covered extension, or
exact on-demand page-area commit) can turn a detached route's short PageMap
access back into one long later-main lifecycle. A completed aggregate
traversal may use the existing immediate-medium handoff only when it itself
leaves exactly one initial nonfull medium survivor with an immediate head,
before a registry is built; ordinary routes, other no-immediate direct-small
cases, multi-member registries, and registries later reduced by client frees
remain sequential client-free access.
The coordinator deliberately does not reserve this shared arena or supply a
full process lifecycle. An unpublished
reservation failure or dropped unfinished lifecycle terminally poisons rather
than exposing a null or fresh root.

A narrow unsafe
current-thread-only owner now uses that metadata prerequisite for regular
dynamic TLS backing: it retains the typed Malloc capability, follows the
source 16/double/+1024/least-index/65535 growth rule, publishes a fully
initialized flexible header before the dynamic root, validates live header
provenance, and frees before clearing only that root. It deliberately has no
TLD/theap attachment, key-to-current-thread registry integration, or actual
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
metadata path remains **subprocess-attached, no-theap**. Generic construction
can own ticket zero only while `MainSubprocess` is open. Production static
startup instead uses `process_init.rs`; its selector blocks generic ticket
issue while source static startup is active or retained. A distinct
process-global `OwnedThreadLocalKeyRegistry` now owns the
regular-key source bitmap from `src/threadlocal.c:221-315`. It fixes the main
subprocess identity on first claim, retains exactly one current typed aligned
`MetaAllocation`, replaced per 1,024-bit growth step, and projects
`BitmapView` only while its registry lock is held. Its ordinary `tseq = 0`
claim repairs conservative chunk-map state, expansion preserves a nonzero
prefix, and only the appended range is then marked free. The
63-block/64,512-bit ceiling prevents a 64th allocation. A non-Copy
lease requires explicit release; bounded shutdown rejects live leases and late
operations. It never installs compiler TLS itself; the private dynamic
attachment is its sole current-thread consumer. Typed-image invariant and ownership-ambiguous
post-commit failures poison with retained process-static ownership; allocation
failure before commit preserves the old image/generation. Every safe typed
backing/TLD/dynamic-Theap projection also checks that its retained capability
is still live before forming a byte reference. The static branch
attaches that exact TLD to cache-aligned,
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
absent. `main_heap_thread.rs` now separately ports the ordinary later-thread
`_mi_thread_init_with_heap(mi_heap_main())` branch. A live static attachment
lends only a borrow-tied, lock-serialized shared-main-Heap lease; each later
owner gets a nonzero metadata TLD and metadata Theap, links it to that Heap,
then publishes default followed by its fixed fast slot while dynamic remains
the immutable count-zero image and cached remains empty. After user destructors
its direct no-page finish clears fast, resets default/cached, detaches the
shared heap list then its TLD list, releases metadata, and decrements the main
attachment's teardown gate. A private `libc` bridge now drives exactly this
no-page path for real pthread workers: process startup retains the ticket-zero
owner and its main-thread-minted Heap lease before constructors, child attach
precedes user code and has a parent/child failure handshake, and normal return,
`pthread_exit`, and cancellation finish after cleanup and TSD destructors. The
bridge itself has no C ABI, pthread key, allocation routing, or main-thread
teardown. Its direct public-fork gate preserves only a quiescent ticket-zero
no-page child and otherwise disables the bridge; general fork repair remains
absent. The active C mimalloc backend retains its existing private key outside
the 128-key application capacity. `main_heap_page.rs`
can borrow one current later owner with a matched
process pair, use the same `pages_main` bitmap, and retain the map lifecycle
through normal free/release plus one scoped producer before returning to that
no-page teardown. It can also consume a live engine into a post-fast-slot drain
that force-collects every queue (including full), releases only all-free pages
in PageMap -> `pages_main` -> metadata -> slice order, and finishes that pass
even if an earlier page remains live. It then retains the post-fast-slot owner
rather than abandoning a general live page. Eight explicit, disjoint handoffs
require the drain's sole page with every other queue/direct slot empty: a full
one-block arena singleton, an OS-aligned singleton, a mapped one-block medium
page, full medium and full large `BIN_FULL` pages, full non-direct-small and
direct-small regular-bin pages, and a nonfull small-or-medium page. The full
arena singleton false-collects, queue-detaches, and unmapped-abandons while
preserving the PageMap registration/lifecycle lease; its final client free
takes the raw failed-reclaim empty result and releases PageMap ->
`pages_main` -> metadata -> slice. The OS form instead links/removes its exact
`Heap::os_abandoned_pages` member around clipped PageMap -> alias -> primary
metadata -> mapping release and retains a failed `munmap` owner terminally.
The mapped one-block medium handoff requires `reserved > 1` and `used == 1`,
runs source force then false collection, queue-detaches, and publishes the
exact main `pages_abandoned[bin]` bit plus paired
`Heap::abandoned_count[bin]`; its final free accepts only the source
empty-before-reclaim result. The other full and nonfull routes preserve their
separately recorded source shape/predicate, map/count, and terminal-release
boundaries; none adds general abandoned-page routing, reclaim, or requeue.
Every other live-page state rejects before detach. Only an empty drain permits the attachment's separate
root/list/TLD teardown. A force/release failure remains terminally retained.
This admits overlapping no-page owners but only one sequential page owner;
concurrent routing, general page abandonment/owner exit, later free/reclaim
beyond those handoffs, source deferred callbacks/arena collection, page-bearing
libc/pthread hooks, and public allocation routing remain absent. Any page/root/list mismatch
is retained rather than treated as complete teardown.
`dynamic_theap.rs` now takes a nonzero ticket through an atomic
later-ticket gate, then retains one `!Send` caller-pinned Heap, metadata TLD
and registration, typed Malloc Theap, regular backing, and regular-key lease.
It preserves dynamic `_mi_theap_init` through both lists before publishing the
regular slot, then sets the cached root only from the canonical empty image and
acquires the paired `1 -> 2` dynamic Theap reference; default/fast stay
unchanged. Its no-page teardown clears slot/backing, resets that cached root
with `2 -> 1`, then detaches lists and releases metadata. Pre-publication OOM
cleans up and rejects, whereas post-list-publication or post-root-reset failure
returns a retained poisoned owner. A pre-mutation key-release lock failure
retains only the linear lease in `AwaitingKeyRelease` for retry. Ordinary
dynamic begin uses the source abandoning `true`/`2` option image and rejects a
page session. The crate-private unsafe non-abandoning begin stores `false`/`-1`
before heap publication and alone creates the sealed borrowed
`DynamicTheapPageSession` for the shared private `PageAllocatorEngine`; its
consuming finish requires no pages, queues/direct entries, collection poison,
or pending OS release, while unfinished Drop latches the attachment terminally
and transfers any pending OS release owner into that retained attachment.
A `cfg(test)`-only fixture validates the frozen ordinary `true`/`2` source
image solely to construct one `MI_ABANDON` aggregate queue shape. It leaves the
production ordinary `page_session` rejection intact and does not add a general
dynamic allocation API.
This is bounded private routing, not general dynamic allocation or remote-free
concurrency. After clearing its regular backing, it has one distinct
`DrainingPages` owner-exit state: it first force-collects an already-retired
all-free regular page, while a full one-block arena or OS-aligned singleton may
be queue-detached and unmapped-abandoned so its exact final client free takes
the raw failed-reclaim all-free release before cached-root/list/key teardown.
The OS form is exactly `MemoryKind::Os`, `reserved == used == 1`, and
`BIN_FULL`; it links the still-owned page through the dynamic Heap's
`os_abandoned_pages` list before common unown, then removes that exact member
before clipped PageMap -> alias -> primary-metadata -> mapping release. A
failed `munmap` retains the unique mapping owner terminally. The arena form
continues to use the dynamic ordinary-bit/slice release tail. Neither form
adds OS-list traversal, reclaim, or requeue. Their `reserved == used == 1` and
no-producer proof excludes invoking the source force-only local-list append;
`free_list::collect_local` separately ports and tests that raw operation, which
the separately recorded later-main all-free exit drain uses without broadening
this dynamic traversal.

`DynamicThreadExitDrain::abandon_full_singleton_pages` is a separate bounded
dynamic aggregate, not a general full-queue traversal. It admits only two or
more full `MemoryKind::Arena` `PageKind::Singleton` members in `BIN_FULL`; each
has its own rounded block size, `reserved == used == 1`, zero retirement
countdown, empty local free list, exact arena span, and every direct slot and
other queue empty. Source force -> false collection -> full-queue/page-count
detach -> unmapped abandonment runs for every member. The route retains the
dynamic drain rather than a raw member list or a dynamic bitmap/count pair;
each sequential canonical client free re-resolves and validates its PageMap
member, must take the raw empty failed-reclaim result, and releases only
PageMap -> dynamic ordinary bit -> metadata -> arena slices. The last release
returns the empty drain for its existing teardown. Sole, non-singleton,
OS-backed, allocation-time, reclaim/adoption/requeue, scan, and concurrent
cases remain outside this route; a collection failure retains the drain.

`DynamicThreadExitDrain::abandon_full_os_singleton_pages` is a separate bounded
dynamic aggregate, not a general full-queue or OS-list traversal. It admits
two or more full `MemoryKind::Os` singleton members in `BIN_FULL`, each with
its own rounded block size, `reserved == used == 1`, zero retirement countdown, empty
local free list, a valid clipped PageMap/alias release image, an initially
empty dynamic `Heap::os_abandoned_pages` list, and every direct slot and other
queue empty. Source force -> false collection -> full-queue/page-count detach
-> private OS-list insertion -> unmapped unown runs for every member. The route
retains the dynamic drain and member count rather than a raw
member list or dynamic bitmap/count pair; each sequential canonical free
re-resolves PageMap, must take the raw empty failed-reclaim result, removes its
exact private-list member, and releases only its clipped PageMap -> alias ->
primary metadata -> mapping image. The last release returns the empty drain for
existing teardown. Sole, arena-backed, non-singleton,
preexisting-list, allocation-time, reclaim/adoption/requeue, scan, producer,
concurrent, huge, and general owner-exit cases remain outside this route; a
collection, list, or mapping-release failure retains the sole owner terminally.

`DynamicThreadExitDrain::abandon_full_medium_pages` is a third bounded dynamic
aggregate, not a general full-queue traversal. It admits only two or more full
`MemoryKind::Arena` `PageKind::Medium` members in `BIN_FULL`, each with its
own rounded block size and regular bin, `reserved > 1`, `used == reserved`,
zero retirement countdown, empty local free list, exact arena span, and a
matching dynamic bitmap/count capability. Every other queue/direct entry is
empty. Source force -> false collection -> full-queue/page-count detach ->
unmapped abandonment runs for every member. The route retains the dynamic drain
rather than raw member pointers or per-member mapped state; each sequential
canonical free re-resolves PageMap, claims the member low owner bit, then
selects that member's exact dynamic bitmap/count capability and unmapped or
mapped full-medium failed-reclaim tail. It releases only that member through
PageMap -> dynamic ordinary bit -> metadata -> arena slices. The final release
returns the empty drain for existing teardown. Sole, mixed-class, non-medium,
OS-backed, allocation-time,
reclaim/adoption/requeue, scan, producer, and concurrent cases remain outside
this route; a collection failure retains the drain.

`DynamicThreadExitDrain::abandon_full_large_pages` is a fourth bounded dynamic
aggregate, not a general full-queue traversal. It admits only two or more full
`MemoryKind::Arena` `PageKind::Large` members in `BIN_FULL`, each with its own
rounded block size and regular bin, `reserved > 1`, `used == reserved`, zero
retirement countdowns, empty local free lists, the matching dynamic bitmap/count
capability for every member, every other queue/direct entry empty, and every member's exact
64-slice arena/PageMap span. Source force -> false collection ->
full-queue/page-count detach -> unmapped abandonment runs for every member. The
route retains the dynamic drain rather than raw member pointers or per-member
mapped state; each sequential canonical free re-resolves PageMap, claims the
member low owner bit, then selects its exact dynamic bitmap/count capability
and unmapped or mapped full-large failed-reclaim tail, and releases only that
member through PageMap -> dynamic
ordinary bit -> metadata -> its complete 64-slice arena span. The final release
returns the empty drain for existing teardown. Sole, mixed-class,
non-large, OS-backed, malformed-span, allocation-time, reclaim/adoption/requeue,
scan, producer, and concurrent cases remain outside this route; a collection
failure retains the drain.

`DynamicThreadExitDrain::abandon_full_non_direct_small_pages` is a fifth
bounded dynamic aggregate, not a general ordinary-bin traversal. It is proven
only through the exact ordinary `true`/`2` fixture and admits two or more full
`MemoryKind::Arena` `PageKind::Small` members across ordinary bins, each with
its own rounded `SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE`,
`reserved > 1`, `used == reserved`, zero retirement countdown, empty local
free list, exact one-slice arena span, and matching dynamic bitmap/count
capability. Every direct entry and `BIN_FULL` are empty, and no other page
class may occupy a populated ordinary bin. Source force -> false collection ->
ordinary-bin/page-count detach -> unmapped abandonment runs for every member;
the non-direct direct-cache update is a proven no-op. The returned
`DynamicThreadExitFullNonDirectSmallPagesRoute` retains the dynamic drain rather
than a raw member list or per-member mapped state. Each canonical free
re-resolves PageMap, claims its member's abandoned identity, then selects that
member's normal unmapped or mapped failed-reclaim tail and dynamic bitmap/count
capability. It releases only that member through PageMap -> dynamic ordinary
bit -> metadata -> one arena slice. The final free returns the empty drain for
existing teardown. Sole, mixed-class, direct-small, `BIN_FULL`, OS-backed,
allocation-time, reclaim/adoption/requeue, scan, producer, and concurrent cases
remain outside this route; a collection failure retains the drain. Production
ordinary dynamic allocation remains sealed.

`DynamicThreadExitDrain::abandon_full_direct_small_pages` is a sixth bounded
dynamic aggregate, not a general ordinary-bin traversal. It is proven only
through the exact ordinary `true`/`2` fixture and admits two or more full
`MemoryKind::Arena` `PageKind::Small` members in one ordinary bin, with one
rounded `block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, `used == reserved`,
zero retirement countdowns, empty local free lists, exact one-slice arena
spans, matching dynamic bitmap/count capabilities, and the complete rounded
direct-cache range naming the ordinary queue head while every other direct
entry and queue is empty. Source force -> false collection -> ordinary-bin
removal -> direct-cache refresh before page-count detach -> unmapped
abandonment runs for every member. The returned
`DynamicThreadExitFullDirectSmallPagesRoute` retains the dynamic drain rather
than a raw member list, cached direct image, or per-member mapped state. Each
canonical free re-resolves PageMap, selects the partial-collector unmapped or
mapped failed-reclaim tail from its claimed abandoned identity, preserves the
just-pushed head through the source accounting lag, and releases only that
member through PageMap -> dynamic ordinary bit -> metadata -> one arena slice.
A member remains unmapped through `reserved / 8 + 1` frees; the next may
publish its exact dynamic bitmap/count pair. The final free returns the empty
drain for existing teardown. Sole, stale/mixed direct-cache, mixed-bin/class,
non-direct-small, `BIN_FULL`, OS-backed, allocation-time,
reclaim/adoption/requeue, scan, producer, concurrent, and joined-remote
nonfull cases remain outside this route; a collection failure retains the
drain. Production ordinary dynamic allocation remains sealed.

`DynamicThreadExitDrain::abandon_full_medium` is a separate, source-unmapped
dynamic endpoint. It admits only the sole full `MemoryKind::Arena` medium page
in `BIN_FULL`, with `reserved > 1`, `used == reserved`, and no direct-cache
entry. Source force -> false collection -> full-queue/page-count detach leaves
ordinary unmapped abandonment. Its linear handoff consumes sequential failed-
reclaim frees, stays unmapped through the source mostly-used prefix, then
publishes the exact dynamic `pages_abandoned[bin]` bit plus paired
`Heap::abandoned_count[bin]` on the first free beyond `reserved / 8`. The
mapped tail clears that pair before PageMap -> dynamic ordinary bit -> metadata
-> arena-slice release. It is not a full-small/full-large, multi-page,
reclaim/adoption/requeue, or general owner-exit traversal capability.

`DynamicThreadExitDrain::abandon_full_large` is a fifth, source-unmapped
dynamic endpoint. It admits only the sole full `MemoryKind::Arena` large page
in `BIN_FULL`, with `reserved > 1`, `used == reserved`, and no direct-cache
entry. Source force -> false collection -> full-queue/page-count detach leaves
ordinary unmapped abandonment. Its `DynamicThreadExitFullLargeHandoff` uses
the normal failed-reclaim collector: the page stays unmapped through the
mostly-used prefix, maps exactly on the first free beyond `reserved / 8`, and
the mapped tail clears the exact dynamic bitmap/count pair before PageMap ->
dynamic ordinary bit -> metadata -> complete 64-slice arena release. It
rejects non-large before collection and does not cover full
medium/non-direct-small/direct-small, multi-page, reclaim/adoption/requeue, or
general owner-exit traversal.

`DynamicThreadExitDrain::abandon_full_medium_after_force_collect_to_mapped` is
the distinct dynamic full-medium branch where exactly one remote client has
already joined before owner exit. Force collection changes the still-linked,
still-full `BIN_FULL` member to `used == reserved - 1`; false collection keeps
that geometry; removal clears the full flag; and mapped abandonment publishes
the exact heap-local bitmap/count pair immediately. Its
`DynamicThreadExitFullMediumHandoff` starts mapped and accepts only sequential
failed-reclaim client frees, clearing that pair before the ordinary arena
release. It does not generalize normal full-medium abandonment to multiple
frees, another class, reclaim, adoption, requeue, scans, or general owner-exit
traversal.

`DynamicThreadExitDrain::abandon_full_large_after_force_collect_to_mapped` is
the corresponding dynamic full-large branch. Its one joined remote free takes
the same still-linked full member to `used == reserved - 1`, then false
collection, full-queue removal, and mapped abandonment publish the exact
heap-local bitmap/count pair immediately. Its
`DynamicThreadExitFullLargeHandoff` starts mapped and accepts only sequential
failed-reclaim client frees, clearing that pair before the complete 64-slice
release. Neither branch generalizes normal full-page abandonment to multiple
frees, another class, reclaim, adoption, requeue, scans, or general owner-exit
traversal.

`DynamicThreadExitDrain::abandon_full_non_direct_small` is a sixth,
source-unmapped dynamic endpoint. It admits only the sole full
`MemoryKind::Arena` small page in its ordinary regular bin, with
`SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE`, `reserved > 1`,
`used == reserved`, `!page_is_in_full`, and every direct-cache slot empty.
Source force -> false collection -> regular-bin/page-count detach leaves
ordinary unmapped abandonment. Its `DynamicThreadExitFullNonDirectSmallHandoff`
uses the normal failed-reclaim collector: the page stays unmapped through the
mostly-used prefix, maps exactly on the first free beyond `reserved / 8`, and
the mapped tail clears the exact dynamic bitmap/count pair before PageMap ->
dynamic ordinary bit -> metadata -> arena-slice release. It rejects direct
small before collection and does not cover full medium/direct-small/large,
multi-page, reclaim/adoption/requeue, or general owner-exit traversal.

`DynamicThreadExitDrain::abandon_full_non_direct_small_after_force_collect_to_mapped`
is the distinct dynamic full non-direct-small branch where exactly one remote
client has already joined before owner exit. Force collection changes the
still-linked ordinary-bin member to `used == reserved - 1`; false collection
keeps that geometry; regular-bin/page-count removal leaves it nonfull; and
mapped abandonment publishes the exact heap-local bitmap/count pair
immediately. Its `DynamicThreadExitFullNonDirectSmallHandoff` starts mapped
and accepts only sequential failed-reclaim client frees, clearing that pair
before the ordinary arena release. The source direct-cache update is a no-op
because the class has an empty direct image and a rounded size above
`SMALL_SIZE_MAX`. It does not generalize normal full non-direct-small
abandonment to multiple frees, direct-small or other classes, reclaim,
adoption, requeue, scans, or general owner-exit traversal.

`DynamicThreadExitDrain::abandon_full_direct_small_after_force_collect_to_mapped`
is the distinct dynamic full direct-small branch where exactly one remote
client has already joined before owner exit. Force collection changes the
still-linked ordinary-bin member to `used == reserved - 1`; false collection
keeps that geometry; regular-bin removal clears its complete rounded
direct-cache range before page-count detach; and mapped abandonment publishes
the exact heap-local bitmap/count pair immediately. Its
`DynamicThreadExitFullDirectSmallHandoff` starts mapped and accepts only
sequential failed-reclaim client frees through the source partial collector,
clearing that pair before the ordinary arena release. It does not generalize
normal full direct-small abandonment to multiple frees, non-direct-small or
other classes, reclaim, adoption, requeue, scans, or general owner-exit
traversal.

`DynamicThreadExitDrain::abandon_full_direct_small` is a seventh,
source-unmapped dynamic endpoint. It admits only the sole full
`MemoryKind::Arena` small page in its ordinary regular bin, with
`block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, `used == reserved`,
`!page_is_in_full`, and its complete rounded source direct-cache range naming
the page while every other direct slot is empty. Source force -> false
collection -> regular-bin removal clears that entire range before page-count
detach, then ordinary unmapped abandonment. Its
`DynamicThreadExitFullDirectSmallHandoff` uses the partial failed-reclaim
collector. The retained just-published head holds the page unmapped for one
additional client free before it reabandons to the matching dynamic
bitmap/count pair; the mapped tail clears that pair before PageMap -> dynamic
ordinary bit -> metadata -> arena-slice release. It rejects stale cache state,
non-direct small, another page, and a collection failure before or at their
respective source boundaries, and it does not cover full medium/non-direct
small/large, multi-page, reclaim/adoption/requeue, or general traversal.

Four separate mapped endpoints accept only a sole nonfull `MemoryKind::Arena`
page with `reserved > 1`, `used == 1`, and one regular queue member.
`DynamicThreadExitDrain::abandon_mapped_one_block` admits the medium class;
`abandon_mapped_one_block_large` admits only a large page and retains its
complete 64-slice span; `abandon_mapped_one_block_non_direct_small` admits
only `SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE`, whose direct-cache
image is empty; and `abandon_mapped_one_block_direct_small` admits only
`block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, and its complete rounded
source direct-cache range. The direct-small preflight rejects a stale range
before collection or detach, and source queue removal clears the exact range
before page-count detach. Each endpoint force- then false-collects and
publishes that exact dynamic `pages_abandoned[bin]` bit plus paired
`Heap::abandoned_count[bin]`. Its class-carrying handoff admits only the exact
final free, which reaches empty before any reclaim branch—through the normal
collector for medium/large/non-direct small or the partial collector for direct
small—clears that bit/count, and releases PageMap -> dynamic ordinary bit ->
metadata -> arena slices. The large endpoint validates all 64 PageMap entries
before that terminal release. It does not reclaim the departed Theap, adopt,
requeue, scan, or accept multiple pages or frees.
General cached-root
switching/reference ownership, abandonment beyond the mapped-regular,
post-TLS singleton, full-singleton/homogeneous-full-OS-singleton/full-medium/full-large/full-non-direct-small/full-direct-small aggregate, sole
full-medium/full-large/full-non-direct-small/full-direct-small, and
mapped-one-block handoffs, pthread/process hooks, complete
subprocess layout/lifecycle, and C pthread-mutex layout claims remain absent. A
first dynamic arena page additionally creates a private
`DynamicArenaPagesOwner`: after proving the registry-published arena's
non-null subprocess identity equals the attachment's selected main subprocess,
one exact zeroed BCHUNK-aligned typed metadata image is Release-published into
its bound Heap's exact arena slot. The shared engine uses this image, rather
than `pages_main`, for fresh-page registration, rollback, and terminal release.
A nonempty image rejects
teardown before roots mutate; pre-publication allocation failure leaves no
slot, while post-mutation lock/free ambiguity remains terminally retained.
One consuming `DynamicMappedPageHandoff` now supplies the bounded mapped
regular dynamic handoff: it removes one exact live regular queue page after
false-force collection, publishes only the bound heap-local abandoned bit and
count, and only same-token adoption or one same-origin `allow_collect` remote
free may clear/reassociate/requeue it. The small-page path preserves the
source partial-head collection. Its all-free dynamic-arena result now follows
the queue-detached source release order—full PageMap-span unregister, exact
heap-local ordinary-bit clear, metadata retirement, then arena-slice
release—and returns the drained engine; an existing owner remains terminal.
Separately, the source-shaped initially-unmapped failed-reclaim substrate
selects terminal-empty, reabandonment, or unownership after its expected-head
CAS/conflict collection. It has raw page-span release authority only through
the post-TLS arena/OS-singleton, full-singleton/homogeneous-full-OS-singleton/full-medium/full-large/
full-non-direct-small/full-direct-small aggregate, sole full-medium, full-large, full-non-direct-small, and
full-direct-small handoffs above, not as general
free routing. General
producer routing, regular/nonempty unmapped lifecycle integration, terminal
reuse, and general abandonment routing remain absent. The private explicit single-thread slice now binds a pinned default theap to a
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
the AArch64 versioned TLS key, caller-owned slot, caller-storage registry
substrate, and allocator-owned process-global regular-key registry; the
private compiler-TLS roots; the source low-bit live/abandoned-page remote-free
head transitions; one private linear scoped `RemoteFreeProducer` for an exact
active matching regular non-huge-bin or `BIN_FULL` allocation; and one
caller-proved joined/quiescent false-force collection path. The token holds an
exclusive-owner borrow, is `Send` but explicitly `!Sync`, and permits a scoped
worker only to publish the canonical block or cancel back to the original
client pointer. The live regular candidate scan, including a direct-cache miss
that falls through to generic search, detaches remote publication before it
extends or classifies a page full; the full scan detaches before release or
unfull, and each non-abandoning move to `BIN_FULL` performs the source's second
false-force collection after enqueue. The detached metadata branch has no
remote producer path and performs only local false-force collection. Any
false-force collection error permanently retains its page/error and any
already-popped block as private allocator poison, so later allocator entry
points reject without further state mutation. This slice also includes one
queue-detached, stable page's mapped/unmapped abandonment/adoption
protocol, including failed-reader restoration and clear-once-set quiescence.
A default-off Loom model exercises five exact shared head protocols: two
live-owner publishers, owner collection racing publication, bitmap adoption
racing an abandoned producer, and abandoned unown racing publication.
Deterministic native regressions separately cover the bitmap-field
quiescence, abandonment publication, adoption versus a remote producer,
ownership-release races, scoped producer cancellation/admission, regular
generic/direct collection, and the joined full-page release/unfull branches.
Except for these bounded owner-side collection routes, post-TLS arena/OS-
singleton, full-singleton/homogeneous-full-OS-singleton/full-medium/full-large/full-non-direct-small/full-direct-small aggregate, sole full-medium,
full-large, full-non-direct-small, and full-direct-small terminal releases,
bounded ticket-zero and sequential later
process-page engines, the shared-main no-page lifecycle, and the later-main
all-free exit drain plus its full-singleton and full-OS-singleton aggregates,
mapped-medium-one-block, full medium/full-large/full-non-direct-small/full-direct-small,
and sole mapped small-or-medium post-exit client-free handoffs and
aggregate regular-pages
post-exit registry, these pieces are
not yet wired into general
allocation/free routing, integrated allocator TLS/process/thread teardown,
terminal page release, or metadata reuse. The later page owner proves normal
map/bitmap/fresh/release/producer ordering plus the all-free scan, one
preflight-bounded full-singleton failed-reclaim handoff, one sole-medium
mapped empty-before-reclaim handoff, four full source-unmapped routes (medium,
large, non-direct small, and direct small), and one sole nonfull small-or-medium process
route whose linear client frees begin after actual old Theap/TLD teardown. Its
separate full-medium, full-large, full-non-direct-small, and
full-direct-small predecessors each accept one joined remote free only: force
collection makes the full source page `reserved - 1` used, then false
collection removes the retained source member and immediately publishes the
mapped regular state before old-Theap/TLD teardown. The medium and large pages
stay linked in `BIN_FULL`; the non-direct-small page stays in its ordinary bin
with an empty direct-cache image; and the direct-small page clears its exact
rounded direct-cache range before page-count detach. The large mapped route
retains its complete 64-slice terminal-release proof.
A separate later-main full-singleton aggregate route accepts two or more full
arena `PageKind::Singleton` members in `BIN_FULL` only when every direct slot
and other queue is empty; every member has its own rounded singleton block
size, `reserved == used == 1`, zero retirement countdown, an empty local free
list, and an exact paired-arena span. It force- then false-collects, detaches,
and ordinary-unmapped-abandons every member before old-Theap/TLD teardown. Its
linear client-free route keeps no raw list or static-main abandoned bitmap:
each final canonical singleton free re-resolves and validates its PageMap
member, takes the raw empty failed-reclaim result, then releases that member in
PageMap -> `pages_main` first-bit -> metadata -> arena-slice order. Sole
members, non-singletons, OS members, adoption, reclaim/requeue, scanning, and
concurrent routing remain absent.
A separate later-main full-OS-singleton aggregate route accepts two or more
`MemoryKind::Os` singleton members in `BIN_FULL`, each with its own rounded
block size, only when `reserved == used == 1`, zero retirement countdowns, empty local free lists,
valid clipped PageMap/alias release images, every direct slot and other queue
is empty, and the static-main `Heap::os_abandoned_pages` list is initially
empty. It force- then false-collects, full-queue/page-count-detaches, links
each still-associated member into that private list, then unmapped-abandons it
before old-Theap/TLD teardown. Full-queue removal clears
`PAGE_IN_FULL_QUEUE`, but the private list deliberately retains the page's raw
intrusive links until an exact canonical client free removes that member. Each
such free re-resolves PageMap membership, takes only the raw empty
failed-reclaim outcome, then releases one member in private-list removal ->
clipped PageMap -> aliases -> metadata -> mapping order. A sole or non-OS
member, nonempty initial list, list traversal, retry after
failed `munmap`, adoption, reclaim/requeue, scanning, allocation-time, and
concurrent routing remain absent; a failed mapping release retains its exact
`OsAlignedPageOwner` terminally.
A separate later-main full-medium aggregate route accepts two or more full
arena members in `BIN_FULL`, each with its own rounded block size/static-main
bin, only when every direct slot and other queue is empty. It force- then
false-collects, detaches, and ordinary-unmapped-abandons every member before
old-Theap/TLD teardown. Its linear client-free route retains no raw page list:
each free re-resolves PageMap membership, claims the member low owner bit, then
selects that member's exact static-main bitmap/count capability and unmapped or
mapped tail. It releases one member at a time. It does not admit a sole page, a
mixed class, allocation-time adoption, reclaim/requeue, or concurrent routing.
A parallel but separate full-large aggregate route accepts only two or more
full `PageKind::Large` arena members, each with its own rounded bin, under the
same complete direct/queue and zero-retirement preflight. Each member proves
its exact 64-slice arena/PageMap span before the route force- then
false-collects, detaches, and ordinary-unmapped-abandons it. Its sequential
client frees re-resolve PageMap membership, claim the low owner bit, then
select that member's exact static-main bitmap/count capability, independently
cross the source unmapped-to-mapped threshold, and release one complete large
span at a time. Sole pages and mixed medium/large full queues reject before
mutation; the route has no adoption, reclaim, requeue, scanning, or concurrent
routing.
A fourth, separately typed full non-direct-small aggregate route accepts two or
more arena `PageKind::Small` members across ordinary source bins, each with its
own rounded `SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE` and static-main
bin, full state, zero-retirement countdown, empty local free list, and exact
one-slice paired-arena span. Every direct slot and `BIN_FULL` must be empty,
and no other page class may occupy a populated ordinary bin. It force- then
false-collects, removes each regular-bin member with the proven no-op
direct-cache update, decrements the page count, and ordinary-unmapped-abandons
every member before old-Theap/TLD teardown. Its sequential normal-collector
client frees re-resolve PageMap membership rather than retaining a raw list,
claim the member low owner bit before selecting that member's static-main
bitmap/count pair, independently cross each member's mostly-used boundary, and
release one one-slice member at a time. Sole pages, direct-small geometry/cache
images, mixed classes, allocation-time adoption, reclaim, requeue, scanning,
and concurrent routing remain absent.
A fifth, separately typed full direct-small aggregate route accepts two or
more arena `PageKind::Small` members across ordinary source bins. Each member
has its own rounded `block_size <= SMALL_SIZE_MAX`, static-main bin, full
state, `reserved >= 16`, zero-retirement countdown, empty local free list, and
exact one-slice paired-arena span. Its preflight requires the complete rounded
direct-cache image to name every populated ordinary queue head. It force- then
false-collects, removes members in source bin order, advances each member's
direct-cache range before decrementing the page count, and ordinary-unmapped-
abandons every member before old-Theap/TLD teardown. Its sequential partial-
collector client frees re-resolve PageMap membership, claim the member low
owner bit before selecting its bitmap/count capability, preserve each just-
pushed expected head through the source accounting lag, and release one one-
slice member at a time. Sole pages, stale/mixed cache images, non-direct
geometry, mixed classes, allocation-time adoption, reclaim, requeue, scanning,
and concurrent routing remain absent.
A fresh later-main owner may explicitly consume a sole mapped medium page that
entered source owner exit already nonfull, or a sole direct-small page whose
source collection left an immediate local free block, the exhausted fully
committed scalar-extension shape, the exact exhausted prefix-covered extension
shape, or the exact exhausted on-demand page-area-commit shape. All
force-collected full-origin predecessors
stay client-free-only even though their final geometry is nonfull. The eligible
route
proves the same subprocess/configuration/PageMap root, static main Heap,
arena, span, and page identity; transfers short PageMap access into one long
lifecycle; claims the bitmap/count member; collects and reassociates it; then
restores source queue-tail order. A direct-small target restores its exact
rounded cache range before target page-count increment and allocates from that
same page; an exhausted fully committed direct-small page extends after that
tail restoration, the exact prefix-covered direct-small shape retains its
recorded prefix and extends without a direct mapping operation, while the exact
on-demand direct-small shape commits its page area before
prefix-count/free-list/capacity publication. Those three no-immediate
direct-small outcomes are exhaustive for valid frozen-profile metadata; the
remaining defensive classifier rejects malformed or out-of-profile state. The medium slice requires an
immediate head or an exhausted nonfull medium page
(`capacity < reserved`). A fully committed medium page
(`slice_pcommitted == 0`) performs the scalar source capacity extension after
tail insertion. Its bounded test-only
`commit == false` seam constructs one actual reserved medium or direct-small
prefix. A commit-requiring plan commits the direct page area before
free-list/capacity mutation and records its OS-page prefix count only on
success; the prefix-covered direct-small regression instead arms that commit
fault and proves adoption skips it. An injected direct-commit failure follows
the source false-collect -> queue-detach -> mapped identity/bit/count/unown
tail, preserving the PageMap and ordinary arena membership for a consuming
same-candidate retry. This is not a production page-on-demand option or a
fresh allocation fallback. A bitmap miss, malformed state, scalar extension
error, or other post-transfer failure is retained terminally. Non-direct-small,
malformed or out-of-profile no-immediate direct-small metadata, full, and
aggregate registry members remain client-free-only. The completed aggregate
traversal's separate sole initial-medium/immediate-head outcome becomes the
existing one-page route before that registry exists. The
full non-direct-small route detaches from its regular size bin, requires
`block_size > SMALL_SIZE_MAX`, takes the ordinary collector, and reabandons
only after the source mostly-used boundary. The sole full direct-small route also
detaches from its regular bin, but requires `block_size <= SMALL_SIZE_MAX`,
`reserved >= 16`, `used == reserved`, and its complete rounded direct-cache
range; queue removal clears that range before page-count detach, and its
partial collector keeps the just-published head through the source accounting
lag. The nonfull route's direct-small member
validates and clears the exact rounded source direct-cache range before that
teardown; its `used < reserved` guard excludes full small pages. The
separate regular-pages source-order aggregate traversal validates the complete
source direct-cache image, refreshes its queue head before page-count detach,
and returns an ordinary drain when retirement/force collection empties every
page. When it instead leaves exactly one initial nonfull medium with an
immediate head, it returns that exact existing one-page handoff rather than an
aggregate registry; multi-member and post-free-reduced registries never gain
that edge. It still does not claim a general thread lifecycle, abandonment
traversal, or page-bearing `pthread` integration. The private no-page bridge
is separately bounded to the direct process/pthread entry and finish order.
The compiler-TLS codegen probe proves hidden initial-exec AArch64 root access
and direct thread-pointer identity without a TLS resolver. The actual bridge
sets that model target-wide in normal and sealed-sysroot builds; the sysroot
audit requires the post-LTO named `THREAD_LIFECYCLE` static TLSIE root and a
TPREL-only final `libc.so`, rejecting TLSDESC and `__tls_get_addr`. A
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
./scripts/dev.sh sysroot
./scripts/dev.sh static-pthread-tls
./scripts/dev.sh test -p crabc-libc --test pthread_create_join_tls_regression
./scripts/dev.sh pthread-stress --iterations 1 --timeout 15
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
runs the five test-only Loom schedules over the shared production remote-head
publication/detach and abandoned owner-claim/unown loops and records their
exact pass count separately from the
ordinary unit suite.

The quick gate also invokes the dedicated allocator compiler-TLS judge. It
builds one default-off probe codegen unit with
`-Ztls-model=initial-exec`, requires all five roots to be hidden `STT_TLS`
objects in the appropriate initialized/uninitialized TLS sections, and rejects
resolver-based or dynamic TLS relocation forms. Its negative-control build
explicitly clears the production target rustflags and must show that the
pinned compiler default emits TLSDESC, keeping the production model requirement
explicit. `allocator-tls` runs this judge alone and writes
`compat/reports/allocator/tls-codegen.json`.

`allocator --full` extends that gate by building and auditing the standalone
static and shared test adapter, including its exact 16-symbol export boundary,
native link tail, and dynamic dependencies. It applies the reviewed patch to
the hash-pinned upstream `test/test-api.c` without checking in a source fork,
then runs both the existing crabc allocator fixture and 33 selected upstream
API checks. After that passing Milestone 4 adapter lane it deliberately returns
exit status 3 with an `UNMET MILESTONE` explanation until Milestone 5 supplies
general integrated remote-free routing, abandonment/adoption, thread/TLS lifecycle, the
remaining applicable Loom protocols, and pthread stress. The bounded page
protocols, caller-owned TLS registry, and private no-page bridge do not satisfy
that lifecycle gate.
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
to deviate. The register currently records private invalid-owner/lifecycle
boundaries and the degraded-entropy substitution, but no ordinary allocation-
trace difference. The bounded small-allocation slice has exact logical-trace
parity; its deliberately absent lifecycle and API regions are incomplete scope
rather than claimed differences.
