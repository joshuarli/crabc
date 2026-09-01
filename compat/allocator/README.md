# Allocator-port evidence contract

> **Status: paused.** This document preserves fixed-mimalloc source,
> contracts, and native evidence as a handoff. Its commands reproduce existing
> private evidence; they are not an active allocator backlog. Resume
> implementation, ledger expansion, differential work, performance work, or
> backend integration only after an explicit reprioritization.

This directory owns the reproducible source, inventory, C-oracle, and later
Rust/C evidence for the Linux/AArch64 production-oriented semantic port of
pinned mimalloc v3.5.0 and its preserved native Linux/x86-64 little-endian
historical evidence profile. The x86-64 profile is evidence-only: it does not
authorize public x86 `crabc` support, public allocator integration,
default-backend promotion, AArch64 emulation, allocator invention, a
cross-platform abstraction, or a runtime allocator-selection system. The
immutable source and licensing record are in
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
and its nine sole-page handoffs (a full arena singleton, an OS-aligned
singleton linked through `Heap::os_abandoned_pages` until its final release, a mapped medium
one-block page, full medium and full large `BIN_FULL` pages plus full
non-direct-small and direct-small regular-bin pages that begin unmapped and
reabandon after the source mostly-used boundary, a nonfull mapped small-or-medium post-exit
route, and an exact two-block large post-exit route with its complete 64-slice span, with exact full-medium, full-large, full-non-direct-small, and full-direct-small
one-joined-remote-free force-collection predecessors), eight bounded later-main
full-page aggregate routes (arena singleton, homogeneous OS singleton, medium,
large, bounded mixed medium/large, and bounded mixed singleton/regular
`BIN_FULL` members, plus non-direct-small and direct-small ordinary-bin
members), and one aggregate regular
small/medium/large plus live-arena-singleton post-exit registry, ordinary
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
page-area commitment operation for an already-selected source extension; the
lease itself does not maintain `slice_pcommitted` or own the failed-commit
page-reabandon branch. Under `cfg(test)` only, a matched page engine may bind
that lease to reproduce one source direct extension; that does not add Rust
option processing, a public control, or production policy. It then proves the
exact map/root/configuration/main tuple for private
`MainStaticProcessPageAllocator`, `MainStaticFirstArenaPageAllocator`, and
`MainHeapThreadProcessPageAllocator`
owners. Each holds the process map's exclusive plain-entry lifecycle while its
engine or joined scoped producer can access source page state, installs only
the arena's in-place `pages_main` bitmap into the shared static main Heap, and
completes normal fresh/release ordering through map, bitmap, metadata, and
slices. A later-main engine may move its complete state plus attachment marker
into `MainHeapThreadPausedProcessPageAllocator`, which holds only
`ProcessPageMapSuspendedEngineAccess`: it exposes no PageMap reference or
client pointer while another complete normal engine operation serializes the
plain entries. Its only nonterminal transition reclaims the matching long lease
before reassembling that exact engine; a failed handoff or unfinished drop
retains state and poisons the root. The owner can reconstruct one already-READY
immutable map/arena pair for a subsequent bounded owner, but does not search
the registry, inspect free slices, or map.
Their normal `realloc` delegates retain source replacement-failure/copy
semantics; the ticket-zero null case alone may activate the completed
first-arena policy. It has only that bounded first ticket-zero connection from the completed
default-reserve policy to a fresh-page miss; it does not model the C
`mi_page_map_empty` pre-root or an existing-arena search,
and has no concurrent/general later-thread page routing, general owner exit
beyond the recorded all-free later-main scan, its nine sole-page handoffs, and
the bounded aggregate regular-pages traversal, teardown, or public routing.
The explicit consuming medium and direct-small handoffs (immediate-head,
exhausted fully committed scalar extension, exact prefix-covered extension, or
exact on-demand page-area commit) can turn a detached route's short PageMap
access back into one long later-main lifecycle. A completed aggregate
traversal may use the existing immediate-medium handoff only when it itself
leaves exactly one initial nonfull medium survivor with an immediate head,
before a registry is built. Separately, sequential client frees may reduce an
existing aggregate to exactly one mapped regular member with no singleton tail;
only then can its opaque selected client constrain one source bitmap claim and
move that member into one fresh later-main engine. The bounded runtime ledger
keeps that client's normal request and immutable process pair private, and
uses the same edge only after the publisher pair, every sibling, and each
singleton tail terminally release; B uses, drains, and finishes its target
before it completes its own attachment and returns A's admission proof. Other
no-immediate direct-small cases, aggregates with multiple or
source-unmapped/singleton members, scans, fallbacks, and concurrent reclamation
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
teardown. Its direct public-fork gate preserves only the original ticket-zero
child after it has excluded later admissions and observed either no page owner
or an all-free `AwaitingFreshPage`/`DormantExistingArena` permanent owner;
otherwise it disables the bridge. The selected `pthread_atfork` smoke first
returns that owner to dormant, then proves child and parent `malloc`/`realloc`/
`free` after the public callbacks; the callbacks themselves do not allocate.
This is not inherited-pointer, lock, or general fork repair. The active C
mimalloc backend retains its existing private key outside the 128-key
application capacity. `main_heap_page.rs`
can borrow one current later owner with a matched
process pair, use the same `pages_main` bitmap, and retain the map lifecycle
through normal free/release plus one scoped producer before returning to that
no-page teardown. It can also consume a live engine into a post-fast-slot drain
that force-collects every queue (including full), releases only all-free pages
in PageMap -> `pages_main` -> metadata -> slice order, and finishes that pass
even if an earlier page remains live. It then retains the post-fast-slot owner
rather than abandoning a general live page. Nine explicit, disjoint handoffs
require the drain's sole page with every other queue/direct slot empty: a full
one-block arena singleton, an OS-aligned singleton, a mapped one-block medium
page, full medium and full large `BIN_FULL` pages, full non-direct-small and
direct-small regular-bin pages, a nonfull small-or-medium page, and a distinct
exactly-two-block large page. The full
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
beyond those handoffs, public source deferred-callback registration/re-entry,
arena collection, page-bearing libc/pthread hooks, and public allocation
routing remain absent. The aggregate, direct small-or-medium, and all-free
runtime owner-exit continuations take the source deferred-free heartbeat phase
under their live Theap/TLD pairing, with an attachment-local test observer
proving callback ordering. Any page/root/list mismatch is retained rather than
treated as complete teardown.
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

`DynamicThreadExitDrain::abandon_full_medium_or_large_pages` is a fifth bounded
dynamic aggregate. It accepts the complete full arena `BIN_FULL` image only
when it contains two or more regular members with at least one medium and one
large page. Every direct entry and other queue is empty; every member proves
its rounded bin, full state, zero retirement countdown, empty local free list,
matching dynamic bitmap/count capability, and its exact one-slice medium or
64-slice large span. It preserves force -> false collection -> full-queue/
page-count detach -> unmapped abandonment. The returned
`DynamicThreadExitFullMediumOrLargePagesRoute` retains only the dynamic drain
and count: each sequential free re-resolves PageMap, claims the low owner bit
before selecting its exact dynamic map and normal collector tail, and releases
only that member's exact span. Homogeneous queues, small/direct-small,
singleton, OS, malformed, allocation-time, reclaim/requeue, scan, producer,
and concurrent cases remain absent.

`DynamicThreadExitDrain::abandon_full_singleton_or_regular_pages` is a sixth
bounded dynamic aggregate. It admits the complete full arena `BIN_FULL` image
only when it contains two or more members with at least one singleton and at
least one medium or large regular page; every direct entry and other queue is
empty. A singleton independently proves `BIN_HUGE`, `reserved == used == 1`,
and its rounded arena span. A regular member independently proves its rounded
bin, `reserved > 1`, `used == reserved`, matching dynamic bitmap/count
capability, and exact one-slice medium or 64-slice large span. Force -> false
collection -> full-queue/page-count detach -> unmapped abandonment runs for
every member. The returned `DynamicThreadExitFullSingletonOrRegularPagesRoute`
stores only the drain and count: singleton frees take the raw terminal tail,
while regular frees claim their low owner bit before selecting the normal
collector tail. Each release is limited to its exact PageMap -> dynamic
ordinary bit -> metadata -> arena span. Homogeneous queues, regular-only mixed
medium/large queues, small/direct-small, OS, malformed, allocation-time,
reclaim/requeue, scan, producer, and concurrent cases remain absent.

`DynamicThreadExitDrain::abandon_full_non_direct_small_pages` is a seventh
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

`DynamicThreadExitDrain::abandon_full_direct_small_pages` is an eighth bounded
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
metadata -> arena slices. The large endpoint validates its 63 PageMap-registered
source page-area slices; the final PageMap-null arena slice is slack but remains
part of the terminal 64-slice release. It does not reclaim the departed Theap, adopt,
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
large, non-direct small, and direct small), one sole nonfull small-or-medium process
route, and one exact two-block large process route whose linear client frees begin after actual old Theap/TLD teardown. The large route retains its complete 64-slice span through the second free. Its
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
mutation from this homogeneous route; it has no adoption, reclaim, requeue,
scanning, or concurrent routing.
A separately typed full medium-or-large aggregate route accepts two or more
full arena members in `BIN_FULL` only when the queue contains at least one
medium and one large member, every direct slot and other queue is empty, and
each member proves its rounded static-main bin, full state, empty local free
list, and exact span (one slice for medium and 64 slices for large). It
preserves force -> false collection -> full-queue/page-count detach -> unmapped
abandonment before old-Theap/TLD teardown. Each sequential free re-resolves its
PageMap member, claims the low owner bit before selecting its exact static-main
bitmap/count capability and normal collector tail, and terminally releases only
that member. Homogeneous queues, small/direct-small, singleton, OS, malformed,
allocation-time, reclaim/requeue, scan, producer, and concurrent cases remain
absent.
A sixth, separately typed full non-direct-small aggregate route accepts two or
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
A seventh, separately typed full direct-small aggregate route accepts two or
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
malformed or out-of-profile no-immediate direct-small metadata, and full
members remain client-free-only for this sole-route handoff. The completed
aggregate traversal's separate sole initial-medium/immediate-head outcome
becomes the existing one-page route before that registry exists; its separately
recorded final mapped regular-member edge remains the only post-free aggregate
exception. The independent native
x86-64 `allocator-on-demand` lane instead exercises one ordinary fresh
reserved medium page: its first allocation exhausts the fixed four-OS-page
prefix, then its second allocation commits the selected page area before
free-list extension and reuses that same page. It compares 23
address-independent success-path values with pinned C. Only the C probe sets
`mi_option_page_commit_on_demand`; Rust uses a private `cfg(test)` seam. Its
Rust-only failed-direct-commit assertion returns no allocation and explicitly
retries the unchanged selected page, whereas C may retire/fall through to a
fresh allocation at `src/page.c:845-863`. That deliberate test-only divergence
is recorded in [`known-differences.md`](known-differences.md); this lane makes
no C fault-injection parity, production option/API/policy, fresh-fallback,
public x86-runtime, libc-integration, backend, or AArch64 claim. The
separate native x86-64 `allocator-direct-on-demand` lane exercises the matching
small direct-cache success path without widening that seam: a fresh 1024-byte
page starts at capacity 8 with a four-OS-page prefix, allocation nine falls
through its exhausted direct head to the generic queue and reaches capacity 16
without a new mapping, and allocation seventeen reaches capacity 24 after the
prefix grows from four to eight OS pages. Its 44 address-independent C/Rust
values also retain the complete direct-cache image, queue, PageMap, arena bit,
payload, and forced normal release. The trace is a source-anchored poststate
witness of the direct-commit-before-extension order, not temporal
instrumentation. Only the C oracle sets the option and Rust remains
`cfg(test)`-only; this success-path lane makes no C fault-injection, production
option/API/policy, fresh-fallback, public-runtime, backend, or AArch64 claim.
The full non-direct-small route detaches from its regular size bin, requires
`block_size > SMALL_SIZE_MAX`, takes the ordinary collector, and reabandons
only after the source mostly-used boundary. The sole full direct-small route also
detaches from its regular bin, but requires `block_size <= SMALL_SIZE_MAX`,
`reserved >= 16`, `used == reserved`, and its complete rounded direct-cache
range; queue removal clears that range before page-count detach, and its
partial collector keeps the just-published head through the source accounting
lag. The nonfull route's direct-small member
validates and clears the exact rounded source direct-cache range before that
teardown; its `used < reserved` guard excludes full small pages. The separate
regular-pages source-order aggregate traversal validates the complete source
direct-cache image, refreshes its queue head before page-count detach, and
returns an ordinary drain when retirement/force collection empties every page.
It retains nonfull regular pages as mapped abandonment. It also retains full
`BIN_FULL` medium/large and full ordinary-bin direct/non-direct small pages: a
joined remote free normalizes that page to mapped abandonment, while an
unchanged full page remains source-unmapped until a later client free crosses
the source mostly-used predicate. A live arena singleton remains PageMap-only
for its raw terminal release; a live OS singleton first links into the static
main Heap's private list and retains its clipped-mapping terminal tail. It keeps no
raw client/page list; the linear post-exit route re-resolves the PageMap entry
and retains only terminal release authority. When the traversal instead leaves exactly one initial nonfull
medium with an immediate head, it returns that exact existing one-page handoff
rather than an aggregate registry. A post-free-reduced registry may instead
make one separate final-mapped-member handoff only after every other member
terminally releases; it keeps no raw member list, scans no alternative page,
and retains the target owner on a bitmap miss or post-claim failure. It still
does not claim a general thread
lifecycle, abandonment traversal, or page-bearing `pthread` integration. The
private no-page bridge is separately bounded to the direct process/pthread
entry and finish order.
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

## Recorded reproduction commands (paused)

Run the harness through the pinned Linux/AArch64 development image:

```sh
./scripts/dev.sh allocator --quick
./scripts/dev.sh allocator --full
./scripts/dev.sh allocator --churn
./scripts/dev.sh allocator-tls
./scripts/dev.sh sysroot
./scripts/dev.sh static-pthread-tls
./scripts/dev.sh test -p crabc-libc --test pthread_create_join_tls_regression
./scripts/dev.sh pthread-stress --iterations 1 --timeout 15
./scripts/dev.sh allocator-perf --smoke
./scripts/dev.sh allocator-perf --full
./scripts/dev.sh test -p crabc-mimalloc --lib --features loom remote_free::loom_tests -- --test-threads=1
```

Runner-owned mutable state stays below `CRABC_WORK_DIR`, or the checkout's
`.work/` directory when that variable is unset. The pinned archive and tag
attestation use `.work/allocator-cache/`; compiled C-oracle, adapter, fixture,
and isolated Cargo outputs use `.work/target/compat/allocator/`; reports use
`.work/reports/allocator/`; and disposable extracted sources and probe files
use `.work/tmp/allocator/`. The selected native-shadow runtime remains the
logical `target/debug` location: the canonical dispatcher maps that repository
path to the repository-local target volume rather than changing the runtime
selection contract.

`allocator --quick` is the former ordinary development gate, retained to
reproduce evidence. It verifies the
annotated tag and archive identities, regenerates the checked-in contracts in
memory, checks them and the source-map ratchet, and builds all five exact C
oracle profiles. Its ignored report is
`.work/reports/allocator/latest.json`; profile artifacts and layout probes
are under `.work/target/compat/allocator/oracle/`. The gate runs the complete
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
requires exact equality with that pinned C baseline. The native x86-64 lane
below extends its own trace to 75 fields with no-padding `mi_expand` and
checked `mi_recalloc`; native AArch64 revalidation of that extension remains
pending. This proves the bounded
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
ordinary unit suite. That test command explicitly clears
`CARGO_ENCODED_RUSTFLAGS`: the model does not access a compiler-TLS root, and
the pinned nightly cannot link its `std`/Loom test binary with the production
initial-exec TLS setting. The dedicated TLS-codegen judge below remains the
sole evidence for that production setting.

The quick gate also invokes the dedicated allocator compiler-TLS judge. It
builds one default-off probe codegen unit with
`-Ztls-model=initial-exec`, requires all five roots to be hidden `STT_TLS`
objects in the appropriate initialized/uninitialized TLS sections, and rejects
resolver-based or dynamic TLS relocation forms. Its negative-control build
explicitly clears the production target rustflags and must show that the
pinned compiler default emits TLSDESC, keeping the production model requirement
explicit. `allocator-tls` runs this judge alone and writes
`.work/reports/allocator/tls-codegen.json`.

`allocator --full` extends that gate by building and auditing the standalone
static and shared test adapter, including its exact 16-symbol export boundary,
native link tail, and dynamic dependencies. It applies the reviewed patch to
the hash-pinned upstream `test/test-api.c` without checking in a source fork,
then runs both the existing crabc allocator fixture and 33 selected upstream
API checks. In that full-only lane it also applies the separately reviewed
creating-thread `test/test-stress.c` patch, compiles it with `NTHREADS=1`, and invokes
the exact source program as `1 1 2`. That preserves the source allocation
distribution, zero/cookie checks, reallocating data table, retained objects,
atomic transfer buffer, and final cleanup across two iterations. The patched
scheduler instead runs its sole worker on the creating thread, so it creates
no pthread; heaps, subprocesses, large-object mode, and the libc allocator
path hard-fail at compile time. It is therefore recorded as preliminary
source-derived stress evidence, not a cross-thread, remote-free, or
thread-recreation acceptance claim. `allocator --churn` and `--soak` do not
silently run that distinct full-lane witness. `allocator --full` also executes
the reviewed
[`native-owner-exit-lifecycle-v3.5.0.json`](native-owner-exit-lifecycle-v3.5.0.json)
suite: fifteen focused direct `crabc-mimalloc` checks spanning the mixed runtime
route, pointer-first publication before and after exit, source-selected live
medium abandonment, same-page PageMap-claim lifetime, aggregate final-member
reclamation, failed OS terminal release, terminal finish ordering, and source
traversal filters. It records
Gate 5C as passed only when that complete checked
record is present; the suite is direct-engine lifecycle evidence, not a
shadow-ABI or general concurrent-routing claim. It then runs the same 128-cycle,
30-second, seed
`0xd1b54a32d192ed03` ticket-zero lifecycle schedule as `allocator --churn`
and writes a versioned [`m5-gate-v3.5.0.json`](m5-gate-v3.5.0.json) result to
`.work/reports/allocator/latest.json`. The report records the bounded base,
persistent-worker, live-owner remote-free, and owner-exit evidence as passed
only when their executed checks pass. It records Gate 5D (soak, stability, and
upstream stress) and Gate 5E (selected native-shadow acceptance) as explicit
blockers until their documented acceptance criteria are met. Consequently
`allocator --full` still exits 3 today, but its failure is
the named reviewed gate state rather than a synthetic post-run placeholder.

Before rendering that M5 record, `allocator --full` reads only the fixed
`.work/reports/allocator/upstream-stress/latest.json` canonical report; it does
not invoke `upstream-stress/run.py` itself. The consumer accepts a report only
when its format, pin, ordered eight-case source matrix, failure-closed
capability, selected native-shadow backend/build record, live named artifacts,
and current-head companion all still bind to the current clean Git source. The
sole execution-scoped artifact is the producer-container's staged
`/lib/ld-crabc-aarch64.so.1` record: its fixed path and bytes bind to the live
selected loader, but the later consumer does not require that transient file.
Its Git reads set `GIT_OPTIONAL_LOCKS=0`. The durable
`canonical_upstream_stress` field is `verified`, `unavailable`, or `rejected`.
Only a `verified` record is surfaced as observed Gate 5D evidence; it remains
a nondefault `shadow_subset` with `large_object_mode: not-claimed`, so it does
not promote Gate 5D or Gate 5E. The separate opt-in 1024-cycle soak and
metadata high-water acceptance remain required.

`allocator --churn` uses that same prefixed evidence adapter but succeeds only
when one fresh process completes 128 bounded C cycles within its 30-second
watchdog. Each cycle runs the existing mixed-local, live-owner remote-free,
mixed post-exit owner-exit, and alternating mapped-regular reclamation worker
exactly once, in a deterministic Fisher-Yates order from recorded unsigned
64-bit seed `0xd1b54a32d192ed03`. The fixture accepts no arguments for its
three-cycle default, or at most one each of `--worker-cycles N` for decimal
`N` in 1..1024 and `--stress-seed SEED` for a base-0 unsigned-64-bit seed, in
either order; it exports no additional symbol. Its
mixed route and alternating mapped-regular reclamation route first suspend A's
exact page engine into the private runtime TLS slot and invoke ordinary
post-destructor finish. That dispatcher resumes the matching engine, runs the
existing aggregate source traversal for the mixed and sole-medium cases or the
direct-cache-validating small-or-medium drain for direct small, and retains
A's admission until the resulting typed B-side route terminally releases; A
cannot fall through the no-page finalizer after its Theap/TLD has detached. Its
mixed opaque owner-exit route carries two full medium pages (one mapped by a
joined pre-exit remote free and one source-unmapped), a distinct one-client
large page whose joined remote free releases it during source collection, one
live arena singleton, and one live OS-aligned singleton; B receives no client
address and must terminally release the arena singleton's PageMap-only tail
and the OS singleton's private-list/clipped-mapping tail before A becomes
fork-quiescent. On B's first direct free of either an existing direct-small
client or one of three remaining clients on the pre-exit-normalized mapped,
non-full medium page, joined C and D each receive the matching nominal scoped
same-page producer after B claims the source low owner bit; C and D atomically
append distinct private clients in separate joined turns and B's ordinary
collector consumes the resulting two-node remote chain before the route
continues. The direct runtime regressions pause after this opaque route
transfers and prove ticket zero remains unavailable until B returns the final
PageMap-release proof; a missing or mismatched publisher retains the route
instead of invoking B's ordinary no-page finalizer. The alternating sole-medium
and direct-small reclamation sides give B no client identity or PageMap handle;
B attaches, adopts/uses the exact page, drains it, and finishes its attachment
before returning the only proof that releases A's admission. The direct-small
side first validates and clears its rounded direct-cache image and immediate
head; it does not make direct small an aggregate traversal result. This is Gate 5D
preliminary stability evidence alongside deterministic eight-cycle Rust state
audits, which also check static-main abandoned counts and the private
OS-abandoned-list baseline. The runtime integration additionally shuffles
eight core pointer-private routes, including the all-free parked TLS session
finish, ordinary parked TLS session owner exit, and the parked session's
scoped B/C/D post-exit publication group, for eight epochs from seed
`0x9e3779b97f4a7c15` and proves ticket-zero reactivation after every route.
It does not close general abandonment/reclamation or promote a libc backend.
`allocator --soak` runs the same two-worker C fixture schedule for 1,024
cycles from seed `0x94d049bb133111eb` under a separate 180-second watchdog;
its JSON report records the run command, seed, two routes per cycle, and exact
route-invocation count. After its first complete two-worker cycle, the
original fixture thread also records a scalar-only quiescent baseline: process
and ticket-zero readiness, PageMap registration/submap counts, arena registry,
live TLDs, metadata live/high-water capabilities, shared Theaps, regular
abandoned pages, and whether the private OS-abandoned list is empty. Every
later cycle and the final ticket-zero allocation/free must match it; the report
records the baseline and audit-snapshot count. This direct adapter does not
install a post-exit registry; its C worker paths start from their supplied
pointer or their own live engine. It
is opt-in larger stability evidence, while `allocator --churn` remains the
128-cycle, 30-second development gate.

The prefixed mixed-local and live-owner remote-free workers now enter through
the typed runtime A-side operation and prove their ordinary
`PAGE_OWNER_READY -> BUSY -> READY` finish without widening the C ABI. A
separate lower persistent-engine regression represents a counted `PARKED(n)`
set of independently suspended normal engines. Each normal suspend increments
that count, each exact token finish decrements it, and ticket zero remains
unavailable until the count reaches zero; one active mutation still owns the
serial `BUSY` transition and PageMap lease. A non-parkable interleaving
operation preserves the observed count. Neither token exposes a client address,
PageMap handle, or post-exit finalizer; abandoning either retains the process
owner. This is not a public worker API, a general concurrent allocator, or
libc allocation routing.

Loom 0.7.2 is an exact, defaults-disabled optional test-model dependency. The
`loom = ["dep:loom"]` feature selects its allocation-backed `std` scheduler,
`generator` build script, and tracing support stack only for the
`cfg(all(test, feature = "loom"))` library model; ordinary selected native
integration tests do not resolve that graph. The generator's external assembly
path is not selected on AArch64, and Cargo's production-graph judge excludes
the entire Loom graph. Both performance modes likewise remain explicitly
unavailable; these status-3 results are not skips and must not become
successful placeholders.

The native x86-64 quick lane is separate from the AArch64 allocator gate.
Run it only through the architecture-aware native dispatcher:

```sh
./compat/allocator/run-x86_64.sh allocator --quick
```

The runner rejects emulation by requiring both the native x86-64 guest and
the dispatcher's native-host provenance. Its report is
`.work/reports/allocator/x86_64/latest.json` and its profile is
`x86_64-native-c-oracle`: the lane checks the target-local declaration
inventory and source-only API/mode/test/symbol coverage ledger; the exact
unfeatured x86 normal dependency graph (including
`cpufeatures` and no selected `libc` package); and a fresh, lockfile-verified
`#![no_std]` release `rlib`. The workspace release profile uses fat LTO, so
that normal-library artifact's codegen member is recorded as LLVM bitcode,
not falsely presented as a linked ELF/staticlib ABI. The lane then builds the
pinned native C oracle, compares direct Rust-engine configuration/layout and
small/fundamental traces, proves x86-64 TLS codegen, and builds/audits the
private prefixed adapter. That adapter has exactly 16 `crabc_test_*` exports,
no `mi_*` exports, and native executions of both the existing allocator
fixture and 33 selected patched upstream API checks. The x86 musl Rust target
does not support a `cdylib`; this lane audits its staticlib instead. Rustc's
recorded C-consumer tail is `-lunwind -lc`, and the private image makes the
target toolchain's static `libunwind.a` available through its derived
`rustc --print sysroot` target self-contained search directory. Both fixture
executables are audited for their x86-64 ELF identity, empty `DT_NEEDED` set,
and a PT_INTERP loader whose basename is `ld-musl-x86_64.so.1`. Its first
native run may populate the architecture-local Cargo cache from the checked-in
lockfile; it never updates that lockfile.

The direct native C/Rust fundamental trace currently contains 75 exact logical
fields, including the fixed no-padding `mi_expand` nonzero null-pointer, zero-size,
below-half, exact-fit, oversize, and state-preservation cases plus checked
`mi_recalloc` growth/tail-zeroing, zero-product, and overflow-preservation
outcomes. It remains private engine evidence rather than a public x86 allocator
API.

The target-local native C release boundary has a dedicated evidence-only
command:

```sh
./compat/allocator/run-x86_64.sh allocator-release-evidence
```

It compiles the pinned mimalloc v3.5.0 release source set with the recorded
release flags, proves the selected x86-64 preprocessor mode, inventories
globally defined `mi_*` symbols across the individual release objects, and
separately inventories default-visible defined `mi_*` dynamic symbols in the
linked shared object. Its report is
`compat/reports/allocator/x86_64/release-evidence.json`. This is native x86-64
evidence only: it does not add public x86 `crabc`, libc, or ldso support and
does not reuse AArch64 status.

The selected-release source API assessment is a separate native x86-only
accounting gate:

```sh
./compat/allocator/run-x86_64.sh allocator-api-coverage
```

It first creates the attested release-mode/object-symbol report, then records
object and dynamic-symbol presence for 194 distinct source-declared C
functions and marks 183 C/C++/macro/type/option forms as
`not-an-object-symbol`. Its report is
`compat/reports/allocator/x86_64/api-native-coverage.json`. This resolves
only selected-release mode and symbol presence; it does not establish behavior,
Rust implementation coverage, a public `mi_*` API, libc/loader integration,
or public x86 runtime support.

Selected staged public-header C/C++ compile/linkability has a distinct native
gate:

```sh
./compat/allocator/run-x86_64.sh allocator-header-modes
```

It builds the pinned C normal-release shared object, stages the exact four
public header byte streams, then compile-links six selected C/C++ consumer
forms, including one C11 compile/link-only probe that instantiates the five
base-header `*_csize` static-inline dispatch helpers, and records x86-64 ELF
identity for every artifact. The report is
`compat/reports/allocator/x86_64/header-mode-evidence.json`. This is not a
CMake configure/install proof and it does not execute consumers or claim their
behavior, Rust implementation, public x86 runtime support, or AArch64 status.

One fixed CMake normal-release shared-library profile has its own native
configure/build/install gate:

```sh
./compat/allocator/run-x86_64.sh allocator-cmake-modes
```

It configures the pinned source with Unix Makefiles and the selected musl
release cache values, records the resolved cache and `src/alloc.c` compiler
mode, builds and installs the shared object, and verifies the installed public
header bytes, lexical install manifest, ELF identity, SONAME, and dynamic
dependencies. Its report is
`compat/reports/allocator/x86_64/cmake-mode-evidence.json`. This establishes
only that one native CMake configure/build/install profile: it does not
compile/link or execute a consumer, establish allocator behavior or Rust
implementation parity, cover static/object or unselected CMake modes, create
public x86 runtime support, or reuse AArch64 status.

Selected static artifact modes have a separate native gate:

```sh
./compat/allocator/run-x86_64.sh allocator-static-modes
```

It compiles the pinned normal-release source set into one static archive,
observes its exact members with `ar t`, then separately compiles the upstream
`src/static.c` amalgamation as the musl static override object and observes its
`malloc`, `free`, `mi_malloc`, and `mi_free` definitions with `nm`. It
compile-links one `mi_malloc` static-library consumer and one `malloc`/`free`
override-object consumer, recording each ELF identity in
`compat/reports/allocator/x86_64/static-mode-evidence.json`. It does not run
either consumer, prove behavior or Rust implementation, perform a CMake
configure/install, or create public x86/AArch64 runtime support.

The dedicated live-owner remote-free differential is likewise native x86-only:

```sh
./compat/allocator/run-x86_64.sh allocator-remote-free
```

It compiles a private `mimalloc/internal.h` C probe against the pinned release
source set, uses exactly two `mi_free` calls from one quiescent `pthread` to
select the live-owner cross-thread route, joins that worker, and invokes the
exact private owner false collector. It compares its 25 address-independent
protocol values with one isolated Rust test and writes
`compat/reports/allocator/x86_64/live-owner-remote-free.json`. The probe proves
only owner-bit preservation, LIFO publication, exact used-count transition,
and post-join detach/local-free merge. It does not prove general remote-free
routing or concurrent collection, abandonment, thread teardown, public
`mi_*` API, libc integration, a backend, or AArch64 behavior. Like the native
release gate, it runs offline against the verified archive cache populated by
the x86 `allocator --quick` lane.

The live-owner full-medium remote-release differential is another native
x86-only private lane:

```sh
./compat/allocator/run-x86_64.sh allocator-live-owner-full-medium-remote-release
```

It fills one non-abandoning full-medium arena page (10248-byte request,
12288-byte blocks, capacity/reserved 42, and eight slices) alongside one
regular successor. A real pinned-C `pthread` worker frees all 42 first-page
blocks and `pthread_join()` completes before the still-live owner inspects the
non-atomic remote list or calls `mi_heap_collect(heap, false)`. That normal
false collector empties the full queue and releases only the empty first page's
PageMap span, ordinary arena bitmap, and complete slice span; the successor
remains a regular member with its PageMap publication intact. Rust uses only 42
joined, staged scoped test workers to compare shared typed private facts. The
35 address-independent values are written to
`compat/reports/allocator/x86_64/live-owner-full-medium-remote-release.json`.
This does not claim pthread/TLS ABI parity, thread teardown, broad remote-free
routing or collection, public `mi_*` behavior or runtime, public x86 support,
libc integration, backend promotion, or AArch64 evidence.

The live-owner full-medium one-remote unfull/reuse differential is a separate
native x86-only private lane:

```sh
./compat/allocator/run-x86_64.sh allocator-live-owner-full-medium-one-remote-unfull-reuse
```

It fills one non-abandoning full-medium arena page (10248-byte request,
12288-byte blocks, capacity/reserved 42, eight slices) beside one regular
successor. A real pinned-C `pthread` publishes exactly one remote `mi_free`
and joins before the owner observes its non-atomic remote list. The owner
false-collects the full page into the regular queue behind the successor,
exhausts the successor's remaining capacity, and reuses the exact remotely
freed block through ordinary allocation. Rust uses only a joined scoped
producer for common typed private facts. The 43 address-independent values are
written to
`compat/reports/allocator/x86_64/live-owner-full-medium-one-remote-unfull-reuse.json`.
This does not claim pthread/TLS ABI parity, generic remote routing/collection,
teardown, abandonment, public `mi_*` behavior or runtime, libc integration,
backend promotion, public x86 support, or AArch64 evidence.

The real small direct-cache route has its own native private differential:

```sh
./compat/allocator/run-x86_64.sh allocator-direct-remote
```

It fills one real small direct-cache page to its current capacity, sends one
exact live block through `mi_free` from a joined/quiescent `pthread`, and
requires the owner direct-cache miss to fall through the regular queue search,
detach that remote block, and reuse it exactly once. The C and Rust probes
compare 28 address-independent values in
`compat/reports/allocator/x86_64/small-direct-remote.json`. It is limited to
this private direct-page route, not general allocation/free routing or
concurrent collection, abandonment, thread teardown, public `mi_*` behavior,
libc integration, a backend, or AArch64 evidence.

One mapped-arena same-origin reclaim transition has its own native private
differential:

```sh
./compat/allocator/run-x86_64.sh allocator-mapped-reclaim
```

Its pinned-C fixture queue-detaches one arena-backed mapped page with two
same-page live blocks, then frees one through `mi_free`; the survivor keeps the
page nonempty while the same-origin reclaim clears mapped abandonment and
requeues the page. It compares eight address-independent values with one Rust
test and writes `compat/reports/allocator/x86_64/mapped-reclaim.json`. It does
not prove general abandonment/adoption, cross-thread reclaim, public `mi_*`
behavior, libc integration, a backend, or AArch64 evidence.

One allocation-time mapped-arena adoption transition has a separate native
private differential:

```sh
./compat/allocator/run-x86_64.sh allocator-mapped-adoption
```

Its pinned-C fixture abandons one nonfull arena-backed medium page with two
live blocks, then requires the next same-heap allocation to claim, reassociate,
and requeue that exact page. Rust explicitly invokes its test-only linear
mapped-page handoff's `adopt()` transition immediately before allocating the
third block; generic Rust allocation does not scan abandoned pages. The 18
address-independent values record PageMap and ordinary-arena-bitmap
preservation, the abandoned bitmap/count clear, original-Theap restoration,
queue-tail/page-count restoration, empty remote state, and same-page third
allocation in `compat/reports/allocator/x86_64/mapped-adoption.json`. This
proves only one same-origin, one-thread allocation-time adoption transition;
it does not prove general or cross-thread abandonment/adoption, public `mi_*`
behavior, libc integration, a backend, public x86 support, or AArch64
evidence.

One direct-small allocation-time mapped-arena adoption transition has a
separate native private differential:

```sh
./compat/allocator/run-x86_64.sh allocator-direct-small-allocation-adoption
```

Its pinned-C fixture uses one same-origin, same-thread/same-Theap,
arena-backed 1024-byte direct-small page with two live blocks. Abandonment
detaches the regular queue and clears the complete rounded direct-cache range
while retaining PageMap and ordinary-arena-bitmap registration. The next C
`mi_heap_malloc_small` claims the exact mapped page, clears its bitmap/count,
restores its original Theap, requeues it at the regular tail, restores the
complete direct-cache range, and consumes its third block. Rust explicitly
consumes its private test-only `adopt()` handoff immediately before the
matching third allocation; generic Rust allocation does not scan abandoned
pages. The 32 address-independent values are recorded in
`compat/reports/allocator/x86_64/direct-small-allocation-adoption.json`. This
proves only the direct-small allocation-time same-origin adapter mapping; it
does not prove general or cross-thread abandonment/adoption, remote routing,
lifecycle, public `mi_*` behavior, libc integration, a backend, public x86
support, or AArch64 evidence.

One initially-unmapped full-medium reabandon tail has a distinct native
private differential:

```sh
./compat/allocator/run-x86_64.sh allocator-unmapped-reabandon
```

The pinned-C side creates an arena Theap with reclaim-on-free and full-page
abandon disabled, fills one real medium page into the source full queue, then
source-abandons it while unmapped. Public `mi_free` calls cross the exact
eighth threshold and republish its arena bitmap. The 13 logical C values match
one Rust test's bounded real full-medium post-Theap-teardown route in
`compat/reports/allocator/x86_64/unmapped-reabandon.json`. The Rust result is
one linear full-medium routing and owner-exit fixture, and this lane does not claim
general free routing, abandonment/adoption, public `mi_*` behavior, libc
integration, a backend, public x86 support, or AArch64 evidence.
The isolated C probe frees its blocks and heap; its exclusive reserved arena
remains process-lifetime fixture state and is reclaimed when that short-lived
probe exits, not a reusable long-lived harness.

One selected mapped post-Theap-teardown route has a separate native private
differential:

```sh
./compat/allocator/run-x86_64.sh allocator-mapped-post-exit
```

Its pinned-C producer uses one worker `pthread` to allocate two same-page
regular medium arena blocks, calls real `mi_thread_done()` before joining, and
has the consumer perform two public `mi_free` calls after the real
`mi_thread_done()` and `pthread_join()` boundary. The 18-field trace records
the mapped failed-reclaim/unown transition plus terminal checks for
`page_map_unregistered_after_final_free`,
`arena_page_bitmap_clear_after_final_free`, and
`arena_slice_released_after_final_free`. Rust compares only one bounded
process-owned mapped regular handoff after Theap/TLD teardown and directly
observes its PageMap, ordinary arena-page bitmap, and free-slice bitmap
release. This lane does not establish general thread exit, general free
routing or concurrency, adoption or reclaim, public `mi_*` behavior, libc
integration, backend promotion, public x86 support, or AArch64 evidence; its
report is `compat/reports/allocator/x86_64/mapped-post-exit.json`.

A separate retired-page prepass is also available on native x86-64:

```sh
./compat/allocator/run-x86_64.sh allocator-retired-prepass
```

This 21-field private C/Rust differential uses a real worker-local `mi_free`
to retire one medium page, then real `mi_thread_done()` and `pthread_join()`
force-release that retired page before a distinct live medium page is mapped-
abandoned; one consumer `mi_free` then terminally releases the live page. The
trace records retired/local-retirement state, retired teardown PageMap,
ordinary arena-page bitmap, and exact slice-span release, followed by live
mapped-abandoned state and terminal PageMap, ordinary bitmap, exact slice-span,
and empty-route checks. Rust directly observes the equivalent bounded private
transitions. This lane does not establish general retirement, teardown,
routing or concurrency, public `mi_*` behavior, libc integration, backend
promotion, public x86 support, or AArch64 evidence; its report is
`compat/reports/allocator/x86_64/retired-prepass.json`.

A separate two-live-page aggregate post-exit route is available on native
x86-64:

```sh
./compat/allocator/run-x86_64.sh allocator-aggregate-post-exit
```

This private 25-field C/Rust differential has a real worker `pthread` create
exactly two distinct live nonfull medium arena pages in distinct bins, then run
real `mi_thread_done()` and return. The consumer calls `pthread_join()` on that worker
before freeing; both selected pages are mapped-abandoned after teardown. The
consumer frees the second page first,
which records only that page's PageMap unregister, ordinary arena-page bitmap
clear, and exact slice-span release while the first remains PageMap-registered,
arena-bitmap-set, mapped-abandoned, and `used == 1`; the consumer then frees
the first page and records an empty route. Rust compares only the equivalent
bounded private aggregate post-exit traversal. This lane does not establish
general teardown, routing or concurrency, public `mi_*` behavior or runtime,
libc integration, backend promotion, public x86 support, or AArch64 evidence;
its report is `compat/reports/allocator/x86_64/aggregate-post-exit.json`.

A separate aggregate still-live route is available on native x86-64:

```sh
./compat/allocator/run-x86_64.sh allocator-aggregate-still-live
```

This private 46-field C/Rust differential has a real worker `pthread` create
two distinct clients on one nonfull medium arena page A and a one-client medium
arena page B in a distinct bin, then run real `mi_thread_done()` and return.
The consumer calls `pthread_join()` before any free. Both pages are mapped-abandoned after
teardown. The consumer's first A free returns `StillLive`, preserving A, B, and
the route; its B free returns `ReleasedPage`, terminally releasing only B; its
second A free returns `ReleasedAll` and completes the route. Rust compares only
this equivalent bounded private aggregate still-live traversal. This lane does
not establish general teardown, routing or concurrency, public `mi_*` behavior
or runtime, libc integration, backend promotion, public x86 support, or
AArch64 evidence; its report is
`compat/reports/allocator/x86_64/aggregate-still-live.json`.

A separate same-bin aggregate still-live route is available on native x86-64:

```sh
./compat/allocator/run-x86_64.sh allocator-aggregate-same-bin-still-live
```

This private 53-field C/Rust differential has a real worker `pthread` fill
medium arena page A, create distinct medium arena page B in the same bin, and
locally restore A to two distinct live clients before real `mi_thread_done()`
and return. The consumer calls `pthread_join()` before every free. It proves
the selected same-bin queue count/link/saved-successor traversal before exit
and same-bin mapped-abandoned count/bitmap transitions `2 -> 2 -> 1 -> 0`.
The first A free returns `StillLive`, preserving both pages and the route; B
returns `ReleasedPage`, terminally releasing only B; and the second A free
returns `ReleasedAll`, completing the route. Rust compares only this equivalent
bounded private aggregate same-bin traversal. This lane does not establish
general teardown, routing or concurrency, public `mi_*` behavior or runtime,
libc integration, backend promotion, public x86 support, or AArch64 evidence;
its report is
`compat/reports/allocator/x86_64/aggregate-same-bin-still-live.json`.

A separate dynamic full-medium one-remote force-collect-to-mapped route is
available on native x86-64:

```sh
./compat/allocator/run-x86_64.sh allocator-dynamic-full-medium-one-remote-force-collect-to-mapped
```

This private 29-field C/Rust differential fills one sole full `BIN_FULL`
medium arena page with the 10248-byte request (12288-byte blocks, capacity
and reserved 42, eight slices), publishes exactly one joined remote `mi_free`
before real `mi_thread_done()` in the C oracle, and force-collects it to mapped
abandonment. Rust exercises only the corresponding private typed drain.
The trace records dynamic abandoned bitmap/count state, `used == 41`, mapped
retention through sequential consumer frees, and terminal PageMap, ordinary
arena bitmap, dynamic bitmap/count, and exact slice release. It is private
native x86-64 engine evidence only; it does not establish general lifecycle,
routing, concurrent collection, abandonment/adoption, public `mi_*` behavior
or runtime, public x86 support, libc integration, backend promotion, or
AArch64 evidence. Its report is
`compat/reports/allocator/x86_64/dynamic-full-medium-one-remote-force-collect-to-mapped.json`.

A separate dynamic full-medium unmapped-reabandon route is available on native
x86-64:

```sh
./compat/allocator/run-x86_64.sh allocator-dynamic-full-medium-unmapped-reabandon
```

This private 34-field C/Rust differential fills one sole full `BIN_FULL`
medium arena page (request 10248, 12288-byte blocks, capacity/reserved 42,
eight slices). No remote `mi_free` is published: the worker runs real
`mi_thread_done()`, and the consumer joins before sequential frees. Force then
false collection detaches the full queue but keeps the PageMap and ordinary
arena bitmap; it is unmapped-abandoned with dynamic bitmap/count clear and
`used == 42`. Five normal-collector frees retain that state at `used == 37`.
The sixth free crosses `reserved / 8 == 5`, maps the page at `used == 36`, and
sets dynamic bitmap/count to one. The mapped tail clears the PageMap, ordinary
arena bitmap, dynamic bitmap/count, and complete eight-slice arena span. It is
private native x86-64 engine evidence only; it does not establish general
lifecycle/routing/concurrent collection, abandonment/adoption, public
API/runtime, backend promotion, public x86 support, or AArch64 evidence. Its
report is
`compat/reports/allocator/x86_64/dynamic-full-medium-unmapped-reabandon.json`.

A separate dynamic full-large one-remote force-collect-to-mapped route is
available on native x86-64:

```sh
./compat/allocator/run-x86_64.sh allocator-dynamic-full-large-one-remote-force-collect-to-mapped
```

This private 31-field C/Rust differential fills one sole full `BIN_FULL`
large arena page (request 86706, 98304-byte blocks, capacity/reserved 42,
64 arena slices, 63 PageMap-registered source page-area slices), publishes exactly one joined remote `mi_free` before real
`mi_thread_done()` in the C oracle, and force-collects it to mapped
abandonment. Rust exercises only the corresponding private typed drain.
Sequential consumer frees retain the mapped route until terminal PageMap,
ordinary arena bitmap, dynamic bitmap/count, and complete 64-slice release;
the final PageMap-null arena slice is slack but is still terminally released.
It is private native x86-64 engine evidence only; it does not establish
general lifecycle/routing/concurrent collection, abandonment/adoption, public
API/runtime, backend promotion, public x86 support, or AArch64 evidence. Its
report is
`compat/reports/allocator/x86_64/dynamic-full-large-one-remote-force-collect-to-mapped.json`.

A separate dynamic full-large unmapped-reabandon route is also covered:

```sh
./compat/allocator/run-x86_64.sh allocator-dynamic-full-large-unmapped-reabandon
```

The private 34-field pinned-C/Rust differential uses request 86706, which
produces 98304-byte blocks with capacity/reserved 42. The full arena span has
64 slices, while only 63 source page-area slices are PageMap-registered; the
final PageMap-null slice is slack but remains part of terminal release. No
remote `mi_free` is published in the C oracle: its real `mi_thread_done()` and
`pthread_join()` precede five normal-collector frees that retain unmapped abandonment at
`used == 37` with dynamic bitmap/count zero, then a sixth free maps the page at
`used == 36` with dynamic bitmap/count one. The mapped tail clears PageMap,
the ordinary arena bitmap, and dynamic bitmap/count before releasing the
complete 64-slice span. Rust independently exercises the bounded typed
owner-exit route on its owning test thread and does not claim a literal
worker-thread/join counterpart. It remains private native x86-64 engine evidence only;
it does not claim general lifecycle/routing/concurrent collection,
abandonment/adoption, public API/runtime, public x86 support, libc integration,
backend promotion, or AArch64 evidence. Its report is
`compat/reports/allocator/x86_64/dynamic-full-large-unmapped-reabandon.json`.

A separate dynamic full direct-small one-remote force-collect-to-mapped route
is available on native x86-64:

```sh
./compat/allocator/run-x86_64.sh allocator-dynamic-full-direct-small-one-remote-force-collect-to-mapped
```

This private 32-field C/Rust differential fills one sole full direct-small
ordinary regular-bin arena page (request/block size 1024, capacity/reserved 64,
one slice), whose pre-remote check requires the exact rounded direct-cache range
`[113, 128]`. The consumer/main thread publishes exactly one joined remote
`mi_free`; the worker later runs real `mi_thread_done()`, and the consumer joins
before sequential frees. Force collection records `used == 63`, mapped
abandonment, and dynamic bitmap/count
state; pinned source anchors plus Rust's typed handoff establish direct-cache
clear-before-page-count-detach. Only the bounded partial collector serves the
mapped consumer tail, ending with PageMap, ordinary arena bitmap, dynamic
bitmap/count, and one-slice release. It is private native x86-64 engine
evidence only; it does not establish general lifecycle/routing/concurrent
collection, abandonment/adoption, public API/runtime, backend promotion,
public x86 support, or AArch64 evidence. Its report is
`compat/reports/allocator/x86_64/dynamic-full-direct-small-one-remote-force-collect-to-mapped.json`.

A separate dynamic full direct-small unmapped-reabandon route is available on
native x86-64:

```sh
./compat/allocator/run-x86_64.sh allocator-dynamic-full-direct-small-unmapped-reabandon
```

This private 38-field C/Rust differential fills one sole full direct-small
ordinary regular-bin arena page (request/block size 1024, capacity/reserved 64,
one slice) with the exact rounded direct-cache range `[113, 128]`. No remote
`mi_free` is published: the worker runs real `mi_thread_done()`, and the
consumer joins before sequential frees. Force then false collection clears that
range before page-count detach, leaving the page unmapped-abandoned with
PageMap and ordinary arena bitmap retained, ordinary queue detached, dynamic
bitmap/count clear, and `used == 64`. The first partial-collector consumer free
retains `used == 64`; nine partial-collector frees preserve that unmapped route
at `used == 56`; the tenth partial collector takes `used` to 55, then generic
unown consumes the retained current head and maps it at `used == 54` with the
dynamic bitmap/count set to one. The mapped tail clears PageMap, ordinary arena
bitmap, dynamic bitmap/count, and the one slice. It is private native x86-64
engine evidence only; it does not establish general lifecycle/routing/concurrent
collection, abandonment/adoption, public API/runtime, backend promotion,
public x86 support, or AArch64 evidence. Its report is
`compat/reports/allocator/x86_64/dynamic-full-direct-small-unmapped-reabandon.json`.

A separate dynamic full non-direct-small unmapped-reabandon route is available
on native x86-64:

```sh
./compat/allocator/run-x86_64.sh allocator-dynamic-full-non-direct-small-unmapped-reabandon
```

This private 35-field C/Rust differential fills one sole full non-direct-small
ordinary regular-bin arena page (request 1032, 1280-byte blocks,
capacity/reserved 51, one slice, and an empty direct-cache image). No remote
`mi_free` is published: the worker runs real `mi_thread_done()`, and the
consumer joins before sequential frees. The full page is initially
unmapped-abandoned with its PageMap and ordinary arena bitmap retained, dynamic
bitmap/count clear, and `used == 51`. Six normal-collector frees preserve that
unmapped route at `used == 45`; the seventh maps it at `used == 44` with the
dynamic bitmap/count set to one. The mapped tail ends by clearing PageMap,
ordinary arena bitmap, dynamic bitmap/count, and the one slice. It is private
native x86-64 engine evidence only; it does not establish general
lifecycle/routing/concurrent collection, abandonment/adoption, public
API/runtime, backend promotion, public x86 support, or AArch64 evidence. Its
report is
`compat/reports/allocator/x86_64/dynamic-full-non-direct-small-unmapped-reabandon.json`.

A separate dynamic full non-direct-small one-remote force-collect-to-mapped
route is available on native x86-64:

```sh
./compat/allocator/run-x86_64.sh allocator-dynamic-full-non-direct-small-one-remote-force-collect-to-mapped
```

This private 30-field C/Rust differential fills one sole full non-direct-small
ordinary regular-bin arena page (request 1032, 1280-byte blocks,
capacity/reserved 51, one slice, and an empty direct-cache image). The
consumer/main thread publishes exactly one joined remote `mi_free`; the worker
later runs real `mi_thread_done()`, and the consumer joins before sequential
frees. Force collection records `used == 50`, mapped abandonment, and dynamic
bitmap/count state. The first sequential failed-reclaim free follows the normal
`used + 2 == reserved` geometry while keeping the mapped route; only the final
free clears PageMap, ordinary arena bitmap, dynamic bitmap/count, and the one
slice. It is private native x86-64 engine evidence only; it does not establish
general lifecycle/routing/concurrent collection, abandonment/adoption, public
API/runtime, backend promotion, public x86 support, or AArch64 evidence. Its
report is
`compat/reports/allocator/x86_64/dynamic-full-non-direct-small-one-remote-force-collect-to-mapped.json`.

A separate pinned-C automatic pthread-destructor lane is available on native
x86-64:

```sh
./compat/allocator/run-x86_64.sh allocator-automatic-pthread-destructor
```

This private 37-value C-oracle-only probe gives one worker two live 10241-byte
clients on a private arena medium page, verifies mimalloc's real pthread key
points at its initialized default Theap, and returns naturally without an
explicit `mi_thread_done()` or `pthread_exit()` call. After `pthread_join()`,
the consumer records mapped abandonment, PageMap/arena-bitmap retention,
detached ownership, and the two-free terminal release. It does not compare
Rust or establish a crabc pthread/TLS callback, Rust/private-runtime lifecycle
integration, general destructor ordering, public `mi_*` behavior, public x86
support, libc integration, backend promotion, or AArch64 evidence. Its report
is `compat/reports/allocator/x86_64/automatic-pthread-destructor.json`.

A separate cancellation-triggered automatic pthread-destructor lane is also
available on native x86-64:

```sh
./compat/allocator/run-x86_64.sh allocator-cancellation-pthread-destructor
```

This private 46-value C-oracle-only probe disables cancellation during worker
setup, verifies the same real mimalloc pthread-key association, then enables
only deferred cancellation before an atomic-ready gate. The consumer issues
exactly one `pthread_cancel()` and opens that gate; the worker reaches exactly
one explicit `pthread_testcancel()`, and `pthread_join()` returns
`PTHREAD_CANCELED` before the same mapped-abandoned, detached, and two-free
terminal observations. It does not compare Rust or establish crabc pthread
cancellation/TLS callback parity, Rust/private-runtime lifecycle integration,
general cancellation or destructor ordering, public `mi_*` behavior, public
x86 support, libc integration, backend promotion, or AArch64 evidence. Its
report is
`compat/reports/allocator/x86_64/cancellation-pthread-destructor.json`.

A separate dynamic OS-aligned singleton owner-exit route is available on native
x86-64:

```sh
./compat/allocator/run-x86_64.sh allocator-dynamic-os-aligned-singleton
```

This private 21-value C/Rust differential allocates 7 bytes at 128 KiB
alignment in a real pinned-C worker, runs real `mi_thread_done()`, joins the
worker, then performs the consumer's sole free. The selected 4096-byte OS
singleton is semantically full (`reserved == used == 1`) but remains in
`MI_BIN_HUGE`, not `MI_BIN_FULL`; the trace records its empty full queue,
OS-abandoned-list handoff, PageMap preservation, and terminal mapping cleanup.
Rust observes only the matching typed private owner-exit transition, not a
pthread/TLS callback. This does not establish general lifecycle, routing,
concurrent collection, abandonment/adoption, public API/runtime, backend
promotion, public x86 support, or AArch64 evidence. Its report is
`compat/reports/allocator/x86_64/dynamic-os-aligned-singleton.json`.

A separate dynamic arena-singleton post-exit differential is available on
native x86-64:

```sh
./compat/allocator/run-x86_64.sh allocator-dynamic-arena-singleton-post-exit
```

This private 21-value pinned-C/Rust differential's C oracle uses one real
worker to allocate a full arena singleton from request 524289 (589824-byte
block size, capacity/reserved 1, nine arena slices), run real
`mi_thread_done()`, and join before the sole terminal consumer `mi_free`. It
records source teardown/join,
unmapped/unowned/detached state, all-nine-slice PageMap registration and
ordinary arena-page bitmap state, then PageMap/bitmap clear, slice release,
and terminal cleanup. Rust observes a scoped test worker and join while
comparing only the matching common typed private owner-exit facts; this is
distinct from the Rust-only route and does not establish crabc pthread/TLS
callback parity. It does not establish general lifecycle/routing/concurrency, public x86/crabc API/runtime, backend
promotion, or AArch64 evidence. Its report is
`compat/reports/allocator/x86_64/dynamic-arena-singleton-post-exit.json`.

A separate native private-adapter measurement lane is available through the
same dispatcher:

```sh
./compat/allocator/run-x86_64.sh allocator-perf --smoke --label x86-private-adapter-smoke
./compat/allocator/run-x86_64.sh allocator-perf --full --label x86-private-adapter-baseline
```

It compiles one shared, release-optimized C fixture against pinned C mimalloc
and the private Rust adapter, pins one allowed CPU, interleaves fresh-process
samples, and records batch timing plus post-initialization touched-live-set
memory observations under `compat/reports/allocator/x86_64/perf/`. These are
bounded single-thread measurements with no promotion threshold—not whole-engine
performance qualification, public `mi_*` behavior, libc integration, or an
x86 backend decision. The x86 lane does not claim public `mi_*` API, libc
integration, general lifecycle or stress coverage, full x86 mimalloc parity,
or public x86 `crabc` support.

The separate bounded lifecycle/concurrency judge is also native x86-only:

```sh
./compat/allocator/run-x86_64.sh allocator-lifecycle
```

It records nine named private Rust lanes (13 selected tests, including five
finite Loom head-protocol models) in
`compat/reports/allocator/x86_64/lifecycle-concurrency.json`. It is evidence
for only those listed compiler-TLS, private-key, and remote-head transitions;
it is not general process/thread lifecycle, client routing,
abandonment/adoption, pthread callback, general fault-injection or misuse
parity, or whole-allocator stress evidence.

One lane is a Rust-only bounded dynamic post-exit route: a source worker
tears down dynamic TLS, cached-root, Theap/TLD, and key state before returning
`DynamicThreadExitArenaSingletonPostExitRoute`; after join, its receiver
consumes one exact arena-singleton free only after proving whole-PageMap
quiescence, then verifies the PageMap, dynamic image bit, and full arena span
release. It does not compare a C pthread callback or claim pthread/TLS
lifecycle parity, general cross-thread routing, public x86 runtime support,
allocator integration, or AArch64 evidence.

The separate bounded fault-injection judge is also native x86-only:

```sh
./compat/allocator/run-x86_64.sh allocator-fault
```

It records five named crate-private state-preservation regressions at selected
Map, Commit, Unmap, and Decommit points in
`compat/reports/allocator/x86_64/fault-injection.json`. It does not establish
general fault-injection or misuse parity, syscall interposition, C-oracle
differentials, lifecycle/stress coverage, public `mi_*` behavior, libc
integration, or an x86 backend. Each named Rust test runs serially with
`--locked` against an isolated disposable x86-64 target directory.

The separate ordinary reserved-medium on-demand differential is also native
x86-64 only:

```sh
./compat/allocator/run-x86_64.sh allocator-on-demand
```

It writes `compat/reports/allocator/x86_64/on-demand.json` after comparing 23
address-independent success-path values. The C oracle alone sets
`mi_option_page_commit_on_demand`; the Rust side uses only a private
`cfg(test)` seam. Its Rust fault assertion deliberately preserves the selected
page and asks the next test allocation to retry it, while pinned C may retire
and fall through to fresh allocation. That limitation is recorded in
[`known-differences.md`](known-differences.md), so this command does not claim
C fault-injection parity, a production option/API/policy, fresh fallback,
public x86 runtime support, libc integration, backend promotion, or AArch64
evidence.

The separate reserved-small direct-cache on-demand differential is also native
x86-64 only:

```sh
./compat/allocator/run-x86_64.sh allocator-direct-on-demand
```

It writes `compat/reports/allocator/x86_64/direct-on-demand.json` after
comparing 44 address-independent success-path values. The C oracle alone sets
`mi_option_page_commit_on_demand`; Rust uses the same private `cfg(test)` seam
without a production option/API/policy. The selected page crosses the fixed
`8/8/4 -> 16/9/4 -> 24/17/8` capacity/used/OS-page-prefix states while the
complete direct-cache image, queue, PageMap, arena bit, payload, and normal
release remain coherent. Its source anchors establish the source commit order;
the trace itself is poststate evidence only. It does not claim C
fault-injection parity, fresh fallback, public x86 runtime support, libc
integration, backend promotion, or AArch64 evidence.

The separate aligned over-allocation/reallocation differential is also native
x86-64 only:

```sh
./compat/allocator/run-x86_64.sh allocator-aligned-overalloc-realloc
```

It writes `compat/reports/allocator/x86_64/aligned-overalloc-realloc.json`
after comparing 29 address-independent values from pinned C and one private
Rust test. The fixture is limited to one ordinary arena-backed 33-byte
offset-aligned request (64-byte alignment, offset 7). It observes
interior-base recovery, adjusted usable size, the aligned ceil-half reuse
boundary, replacement preservation, zeroed growth, and terminal PageMap,
arena-page, and slice release. This is private native x86 engine evidence
only; it does not claim a public `mi_*` API, public x86 libc/ldso/runtime
support, general aligned allocation/reallocation coverage, or AArch64
evidence.

The separate ordinary regular-small retirement differential is also native
x86-64 only:

```sh
./compat/allocator/run-x86_64.sh allocator-regular-small
```

It writes `compat/reports/allocator/x86_64/regular-small.json` after comparing
40 address-independent values across pinned C and one private Rust test. It
fills one 1025-byte ordinary regular-small arena page (1280-byte class, 51
blocks, one slice), locally retires it with `retire_expire == 16`, lets the
next generic same-Theap allocation quick-collect and reuse a just-freed block
on the same page, then force-collects the second retired state through queue,
PageMap, ordinary arena-page bitmap, and exact slice release. It is only
same-thread/same-Theap private engine evidence for that route; it does not
establish general retirement or lifecycle, remote/concurrent collection,
abandonment, thread teardown, public `mi_*` behavior, libc integration,
backend promotion, public x86 support, or AArch64 evidence.

The separate full direct-small regular-bin retirement differential is also
native x86-64 only:

```sh
./compat/allocator/run-x86_64.sh allocator-direct-small-full-retire
```

It writes `compat/reports/allocator/x86_64/direct-small-full-retire.json`
after comparing 38 fixed address-independent pinned-C/Rust values. One
same-thread/same-Theap, arena-backed 1024-byte direct-small page has 1024-byte
blocks, capacity 64, and one slice. When full (`used == reserved`), it remains
the sole ordinary regular-bin member with its complete rounded direct-cache
range; it does not enter `BIN_FULL` or take an unfull transition. Owner-local
frees retire it at `retire_expire == 16` without queue or cache detachment, and
forced retired collection restores the source empty-page cache image before
queue, PageMap, ordinary arena-page bitmap, and slice release. This is only
that bounded private engine route, not general retirement/lifecycle, remote or
concurrent collection, thread exit, abandonment/adoption, public API/runtime,
backend, public x86 support, or AArch64 evidence.

The separate ordinary medium-page full-to-retire differential is also native
x86-64 only:

```sh
./compat/allocator/run-x86_64.sh allocator-medium-full-retire
```

It writes `compat/reports/allocator/x86_64/medium-full-retire.json` after
comparing the fixed address-independent trace from pinned C and one private
Rust test. The one same-thread/same-Theap arena-backed 10241-byte request has
a 12288-byte block size, 42-block capacity, and eight slices. With C
`mi_option_page_full_retain == -1`, it fills `BIN_FULL`, one local free returns
the page to regular, the remaining local frees retire it with
`retire_expire == 4`, and forced release checks queue, PageMap, arena-page bit,
and slice-span teardown. It does not establish general retirement/lifecycle,
remote or concurrent collection, abandonment, thread teardown, public API or
runtime support, backend promotion, public x86 support, or AArch64 evidence.

The separate full non-direct-small force-collect post-exit differential is
also native x86-64 only:

```sh
./compat/allocator/run-x86_64.sh allocator-full-non-direct-small-force-collect-post-exit
```

It writes
`compat/reports/allocator/x86_64/full-non-direct-small-force-collect-post-exit.json`
after comparing 25 address-independent values from pinned C and one private
Rust test. One worker-owned arena page receives a 1032-byte request in the
1280-byte, 51-block, one-slice non-direct-small regular bin. The consumer
publishes exactly one remote `mi_free` before the worker runs real
`mi_thread_done()`, then `pthread_join()` completes before the consumer's
sequential frees. Force collection makes the page nonfull, mapped-abandoned,
PageMap-registered, arena-bitmap-set, and detached from its ordinary queue with
50 remaining clients. A nonfinal consumer free preserves the mapped route;
only the final free unregisters its PageMap entry, clears its ordinary
arena-page bitmap, and releases its exact slice. This is private native x86-64
engine evidence only: it does not establish general remote-free routing, thread
exit/teardown/lifecycle, abandonment/adoption, concurrent collection, public
`mi_*` behavior or runtime, libc integration, backend promotion, public x86
support, or AArch64 evidence.

The separate full direct-small force-collect post-exit differential is also
native x86-64 only:

```sh
./compat/allocator/run-x86_64.sh allocator-full-direct-small-force-collect-post-exit
```

It writes
`compat/reports/allocator/x86_64/full-direct-small-force-collect-post-exit.json`
after comparing 28 address-independent values from pinned C and one private
Rust test. One worker-owned arena page receives a 1024-byte request in the
1024-byte, 64-block, one-slice full direct-small regular bin. Its pre-remote
preflight requires the complete rounded direct-cache range, and the pinned
source anchors establish that range update before queue detachment. The
consumer publishes exactly one remote `mi_free` before real `mi_thread_done()`;
`pthread_join()` completes before sequential consumer frees. Force collection
immediately publishes mapped abandonment while detaching the ordinary queue;
the mapped route remains PageMap- and arena-bitmap-registered until the final
free releases the PageMap, ordinary arena bitmap, exact slice, and the
terminal static-main abandoned-bin bitmap (`arena_abandoned_bin_bitmap_clear_after_final_free`). This is
private native x86-64 engine evidence only: it does not establish general
remote-free routing, thread exit/teardown/lifecycle, abandonment/adoption,
concurrent collection, public `mi_*` behavior or runtime, libc integration,
backend promotion, public x86 support, or AArch64 evidence.

`owner-exit-publication-v3.5.0.json` is a pinned-source order gate, not
runtime parity evidence. `validate_owner_exit_publication_contract` in
`compat/allocator/run.py` checks the source sequence from queue detach through
the abandoned identity, then either mapped bitmap/count or non-arena private
OS-list publication, before common unown. It separately records the empty
terminal-release branches and prohibits reconstructing a stale W07 owner-exit
claim from a raw page, block, remote-head, or departed-Theap hint; only the
typed drain, a current PageMap resolution, and the matching publication
capability can authorize a later route.

Maintainer-only contract operations run directly on the host and require a
review of their diffs:

```sh
python3 compat/allocator/run.py --check --offline
python3 compat/allocator/run.py --check --architecture x86_64 --offline
python3 compat/allocator/run.py --generate-contracts --offline
python3 compat/allocator/run.py --snapshot-ratchet
python3 -m unittest compat/allocator/tests/test_runner.py
```

The verified archive and tag attestation live in the ignored
`.work/allocator-cache/`. Once they are present, `--offline` performs no
network access. Contract or source-map changes require an explicit ratchet
snapshot after review; the normal gate never updates its own baseline.

## Checked-in contracts

| Path | Contract |
| --- | --- |
| `api-v3.5.0.json` | Deterministic, source-audited AArch64 public-header and root-CMake mode inventory. It separates external C declarations, static inlines, types, enum options, macros, override macros, C++ conveniences, and all 52 initial `MI_*` compile-time declarations. Every item and mode records target applicability, source-backed exclusions or platform-limited observable behavior, implementation/evidence status, and an explicit blocker where parity is required but incomplete. Exported EINVAL operations, accepted option values with platform-specific effects, and unconditionally declared modes remain applicable parity obligations; only public declarations absent from the normal Linux release definition are currently inapplicable. Malloc-engine readiness remains owned by the architecture/M5 gates and cannot be inferred from the separate full Linux/AArch64 v3.5.0 parity track. Native x86-64 parity requires a separate architecture-qualified inventory. |
| `x86_64-api-v3.5.0.json` | Target-local, source-only inventory of the pinned base `mimalloc.h` `mi_decl_export` declarations. It does not claim object exports, adapter coverage, implementation, or public integration. |
| `x86_64-api-coverage-v3.5.0.json` and `x86_64_api_coverage.py` | Target-local source-only ledger for the pinned installed headers, source-form modes, test inputs, and symbol dispositions. Its separate native assessment records selected-release object/dynamic presence without changing the unassessed behavior, Rust, or public-runtime boundary. |
| `x86_64-source-map-v3.5.0.json` and `x86_64_source_map.py` | Target-local pinned-source mapping and ratchet foundation for 34 x86-relevant source units. Its statuses remain explicitly incomplete and never reuse the AArch64 port-map/ratchet. |
| `upstream-tests-v3.5.0.json` | Exact pinned upstream test/support-file inventory and current execution status. Its v3 status records the reviewed M4 `test-api.c`/`testhelper.h` inputs, one constrained M5 `test-stress.c` source-derived route, and the remaining M5+-blocked sources separately. |
| `upstream-stress-v3.5.0.json` and `upstream-stress/run.py` | Canonical source-unmodified `test/test-stress.c` native-shadow contract and runner. The dispatch captures the exact matching Cargo compiler-artifact from its selected `crabc-libc` dev build, and the runner binds its package, target, profile, features, ordered `libc.so`/`libc.a` filenames, and file hashes without assuming fingerprint-cache uniqueness. They inventory the sole Linux/AArch64 little-endian target and selected nondefault backend, attest the fixture's ELF identity, exact selected-loader `PT_INTERP`, `DT_NEEDED`, and hashes, run fresh-process 1/2/4/8-pthread cases at two fixed source argument configurations, record the upstream seed/watchdog/artifact schemas, normalize the deleted extraction root out of durable evidence, and fail closed unless every case passes natively. `allocator --full` consumes only the fixed report through a separate strict, lock-free-Git reader; it verifies live artifact and current-head-companion binding but treats the result only as blocked Gate 5D observed evidence. Contract-only validation remains `not-run`, not runtime evidence. |
| `adapted-tests-v3.5.0.json` | Reviewed selected-API omissions, source hashes, patch identity, prefixed symbol inventory, and native link contract for pinned upstream `test-api.c`. |
| `adapted-tests-x86_64-v3.5.0.json` | Target-local private x86-64 adapter contract. It hashes only the extracted target-neutral patch/selection facts from the M4 record and separately records the staticlib-only `-lunwind -lc` C-link tail, its derived rustc target self-contained search path, executable ELF, PT_INTERP, and empty `DT_NEEDED` expectations. |
| `adapted/test-api-selected.patch` | Minimal source adaptation applied to the exact extracted upstream file; no copied upstream source fork is stored. |
| `adapted-stress-test-v3.5.0.json` | Reviewed creating-thread stress source/provenance map, exact patch/hash, fixed `NTHREADS=1`/`1 1 2` invocation, unsupported-mode rejections, and native link contract for the constrained upstream `test/test-stress.c` route. |
| `adapted/test-stress-creating-thread.patch` | Minimal source adaptation of the exact upstream stress fixture; it keeps the source workload but intentionally excludes every unsupported scheduler or allocator mode rather than copying a C fork. |
| `native-shadow-stress-v3.5.0.json` | Reviewed selected-libc source-stress provenance map, behavior-named patch/hash, fixed four-pthread `4 1 2` execution, fresh-process count, source-transfer cleanup boundary, and unsupported-mode rejections. |
| `adapted/test-stress-native-shadow-pthreads.patch` | Minimal selected-shadow adaptation of the exact upstream stress fixture; standard C allocation names bind to the native shadow `libc.so`, while unsupported upstream modes fail at compile time. |
| `shadow-abi-matrix-v1.json` and `shadow-abi-matrix/` | Closed paired-artifact local C ABI contract and runner. It snapshots and attests the ordinary C-backed `libc.so` before native feature selection, then independently attests and compares one normalized `malloc`/`free`/`realloc` trace through both artifacts. It records the two current zero-size `realloc` ordinary/native alignment known reds exactly and keeps lifecycle, cross-owner, DSO/static-linkage, and allocator-layout cases explicitly blocked rather than smuggling them into a local comparison. |
| `test-adapter/` | Standalone default-off Rust staticlib/cdylib, private C header, and checked-in wrapper for the existing allocator fixture. |
| `runtime-ticket-zero-test-v3.5.0.json` | Reviewed source map, nine-symbol inventory, one-shot caller contract, and native link contract for the process-lifetime ticket-zero C witness, including scalar-only lifecycle stability auditing plus the retained narrow, persistent mixed-local, and live-owner remote-free worker round trips. |
| `native-owner-exit-lifecycle-v3.5.0.json` | Reviewed direct-engine Gate 5C suite: exact Cargo feature set, fifteen focused runtime/source traversal checks, and the required owner-exit scenario coverage. |
| `owner-exit-publication-v3.5.0.json` | Pinned-source order gate for collection, queue detach, abandoned identity, mapped bitmap/count or non-arena OS-list publication, and common unown. It keeps empty terminal release distinct and prohibits treating a raw page/block snapshot or Loom-only W07 model as a reconstructed owner-exit claim. |
| `m5-gate-v3.5.0.json` | Versioned full-lane contract for the 128-cycle lifecycle schedule and its current Gate 5A--5E acceptance/blocker classification. |
| `runtime-ticket-zero-adapter/` | Separate `no_std` staticlib/cdylib and direct C fixture for the hidden ticket-zero runtime owner; it has no libc allocator or `mi_*` export. |
| `port-map.toml` | AArch64 source-unit and meaningful-item translation/verification ledger with separate monotonic status fields. Native x86-64 parity must not reuse its AArch64 statuses. |
| `ratchet-v3.5.0.json` | Reviewed AArch64 inventory hashes, counts, and non-regression baseline. An x86-64 ratchet must remain architecture-qualified. |
| `x86_64-parity-v3.5.0.json` | Target-local x86-64 parity/evidence ledger. It records available native evidence without promoting the adapter or engine to a public allocator backend. |
| `x86_64_release_evidence.py` and `x86_64-release-evidence-v3.5.0.json` | Native x86-64-only C release-mode, ELF identity, object-symbol, and dynamic-symbol evidence. It is dispatched by `allocator-release-evidence`; it does not claim public x86 support or reuse AArch64 status. |
| `x86_64_api_native_coverage.py` and `x86_64-api-native-coverage-v3.5.0.json` | Native x86-64-only selected-release per-source-form object/dynamic-symbol assessment. It is dispatched by `allocator-api-coverage`; it does not claim behavior, Rust implementation, public API, or runtime compatibility. |
| `x86_64_header_mode_evidence.py` and `x86_64-header-mode-evidence-v3.5.0.json` | Native x86-64-only staged public-header C/C++ compile/link evidence for six selected forms, including one C11 probe that instantiates five base-header `*_csize` static-inline dispatch helpers, plus the linked pinned C shared object. It is dispatched by `allocator-header-modes`; it does not validate CMake installation, execute consumers, or claim behavior/public runtime support. |
| `x86_64_cmake_mode_evidence.py` and `x86_64-cmake-mode-evidence-v3.5.0.json` | Native x86-64-only CMake normal-release shared configure/build/install evidence. It is dispatched by `allocator-cmake-modes`; it records source-bound cache/compiler selections, installed headers/manifest, and shared-object ELF/SONAME/dependencies, but does not compile/link or execute consumers, claim behavior or Rust implementation parity, cover static/object or unselected CMake modes, or create public x86/AArch64 runtime support. |
| `x86_64_static_mode_evidence.py` and `x86_64-static-mode-evidence-v3.5.0.json` | Native x86-64-only selected static archive and `src/static.c` override-object artifact evidence. It is dispatched by `allocator-static-modes`; it observes archive members and override symbols, compile-links two consumers, but does not execute them, configure/install CMake, or claim behavior/public runtime support. |
| `x86_64_remote_free_evidence.py` and `x86_64-remote-free-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one quiescent live-owner remote-free publication/owner-collection protocol. It is dispatched by `allocator-remote-free` and does not claim general routing, lifecycle, public API, or AArch64 evidence. |
| `x86_64_live_owner_full_medium_remote_release_evidence.py` and `x86_64-live-owner-full-medium-remote-release-evidence-v3.5.0.json` | Native x86-64-only private 35-field pinned-C/Rust differential for one live owner with a non-abandoning full-medium arena page (10248-byte request, 12288-byte blocks, capacity/reserved 42, eight slices) and a regular successor. A real C `pthread` worker frees all 42 first-page blocks and joins before the owner observes its non-atomic remote list or false-collects; only the empty first page's PageMap/ordinary-arena-bitmap/eight-slice span releases while the successor remains regular and PageMap-published. Rust uses only 42 joined, staged scoped test workers for shared typed private facts, not pthread/TLS ABI parity or broad routing/collection. It is dispatched by `allocator-live-owner-full-medium-remote-release`; it does not claim thread teardown, public API/runtime, backend, public x86 support, libc integration, or AArch64 evidence. |
| `x86_64_live_owner_full_medium_one_remote_unfull_reuse_evidence.py` and `x86_64-live-owner-full-medium-one-remote-unfull-reuse-evidence-v3.5.0.json` | Native x86-64-only private 43-field pinned-C/Rust differential for one non-abandoning full-medium live owner and one regular successor. A real C `pthread` publishes exactly one remote `mi_free` and joins before owner observation; false collection requeues the full page behind the successor, and ordinary allocation exhausts the successor before reusing the exact remote block. Rust uses only a joined scoped producer for common typed private facts. It is dispatched by `allocator-live-owner-full-medium-one-remote-unfull-reuse`; it does not claim pthread/TLS ABI parity, generic routing/collection, teardown, abandonment, public API/runtime, backend promotion, public x86 support, libc integration, or AArch64 evidence. |
| `x86_64_direct_remote_evidence.py` and `x86_64-direct-remote-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one small direct-cache remote-free/reuse route. It is dispatched by `allocator-direct-remote` and does not claim general routing, lifecycle, public API, or AArch64 evidence. |
| `x86_64_mapped_reclaim_evidence.py` and `x86_64-mapped-reclaim-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one mapped arena page’s nonempty same-origin reclaim and requeue. It is dispatched by `allocator-mapped-reclaim` and does not claim general abandonment/adoption, public API, or AArch64 evidence. |
| `x86_64_mapped_adoption_evidence.py` and `x86_64-mapped-adoption-evidence-v3.5.0.json` | Native x86-64-only private 18-value pinned-C/Rust differential for one arena-backed, same-origin, one-thread nonfull medium page: the C next same-heap allocation claims, reassociates, and queue-tail requeues that exact PageMap/ordinary-arena-bitmap-preserved page, while Rust explicitly consumes its test-only `adopt()` adapter before its matching third allocation. It is dispatched by `allocator-mapped-adoption`; it does not claim general or cross-thread abandonment/adoption, public API/runtime, backend, public x86 support, or AArch64 evidence. |
| `x86_64_direct_small_allocation_adoption_evidence.py` and `x86_64-direct-small-allocation-adoption-evidence-v3.5.0.json` | Native x86-64-only private 32-value pinned-C/Rust differential for one same-origin, same-thread/same-Theap, arena-backed 1024-byte direct-small page with two live blocks: abandonment clears its complete rounded direct-cache range while retaining PageMap/ordinary-arena-bitmap state, and the next C `mi_heap_malloc_small` claims, reassociates, queue-tail requeues, restores that range, and allocates the third block while Rust explicitly consumes its test-only `adopt()` handoff before its matching third allocation. It is dispatched by `allocator-direct-small-allocation-adoption`; it does not claim general/cross-thread adoption, generic Rust abandoned-page scanning, remote routing, lifecycle, public API/runtime, backend, public x86 support, or AArch64 evidence. |
| `x86_64_unmapped_reabandon_evidence.py` and `x86_64-unmapped-reabandon-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one full medium arena page's unmapped-abandonment to threshold-triggered mapped reabandon. It is dispatched by `allocator-unmapped-reabandon`; Rust exercises one bounded real post-Theap-teardown full-medium route and it does not claim general routing, lifecycle, public API, or AArch64 evidence. |
| `x86_64_on_demand_evidence.py` and `x86_64-on-demand-evidence-v3.5.0.json` | Native x86-64-only private 23-field pinned-C/Rust differential for one ordinary reserved medium page whose first allocation exhausts the fixed four-OS-page prefix and whose second allocation directly commits before free-list extension and same-page reuse. It is dispatched by `allocator-on-demand`; only C sets `mi_option_page_commit_on_demand`, Rust uses a `cfg(test)` seam, and its deliberate Rust failed-commit same-page retry is not C fault-injection parity or a production option/API/policy, fresh-fallback, public-runtime, backend, or AArch64 claim. |
| `x86_64_direct_on_demand_evidence.py` and `x86_64-direct-on-demand-evidence-v3.5.0.json` | Native x86-64-only private 44-field pinned-C/Rust differential for one reserved 1024-byte small direct-cache page: direct exhaustion at eight objects, generic zero-commit extension at allocation nine, and direct prefix growth before the allocation-seventeen extension. It is dispatched by `allocator-direct-on-demand`; C alone sets `mi_option_page_commit_on_demand`, Rust uses a `cfg(test)` seam, and its source-anchored poststate trace does not claim C fault-injection parity, a production option/API/policy, fresh fallback, public runtime, backend, or AArch64 evidence. |
| `x86_64_regular_small_evidence.py` and `x86_64-regular-small-evidence-v3.5.0.json` | Native x86-64-only private 40-field pinned-C/Rust differential for one 1025-byte ordinary regular-small arena page: a 1280-byte 51-block one-slice class locally retires at 16, the next same-Theap generic allocation quick-collects/reuses a just-freed same-page block, and forced collection verifies queue/PageMap/ordinary arena bitmap/exact slice release. It is dispatched by `allocator-regular-small`; it does not claim general retirement/lifecycle, remote or concurrent collection, public API/runtime, backend, public x86 support, or AArch64 evidence. |
| `x86_64_direct_small_full_retire_evidence.py` and `x86_64-direct-small-full-retire-evidence-v3.5.0.json` | Native x86-64-only private 38-field pinned-C/Rust differential for one same-thread/same-Theap 1024-byte direct-small arena page (1024-byte blocks, capacity 64, one slice): when full it remains in its ordinary regular bin with its complete rounded direct-cache range, never enters `BIN_FULL` or takes an unfull transition, then owner-local frees retire it at 16 while that range remains populated. Forced retired collection restores the source empty-page cache image and releases queue/PageMap/ordinary arena bitmap/slice. It is dispatched by `allocator-direct-small-full-retire`; it does not claim general retirement/lifecycle, remote or concurrent collection, thread exit, abandonment/adoption, public API/runtime, backend, public x86 support, or AArch64 evidence. |
| `x86_64_medium_full_retire_evidence.py` and `x86_64-medium-full-retire-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one same-thread/same-Theap, arena-backed ordinary 10241-byte medium page (12288-byte block size, 42 capacity, eight slices) under C full-retain `-1`: `BIN_FULL`, one local-free return to regular, retire expiry `4`, and forced queue/PageMap/arena-bit/slice-span release. It is dispatched by `allocator-medium-full-retire`; it does not claim general retirement/lifecycle, remote or concurrent collection, public API/runtime, backend, public x86 support, or AArch64 evidence. |
| `x86_64_full_non_direct_small_force_collect_post_exit_evidence.py` and `x86_64-full-non-direct-small-force-collect-post-exit-evidence-v3.5.0.json` | Native x86-64-only private 25-field pinned-C/Rust differential for one worker-owned arena full non-direct-small regular-bin page: a 1032-byte request uses the 1280-byte, 51-block, one-slice class; one remote `mi_free` is published before real `mi_thread_done()`, `pthread_join()` precedes sequential consumer frees, force collection makes the page nonfull/mapped-abandoned and detaches its ordinary queue, and only the final free releases the PageMap/arena bitmap/slice. It is dispatched by `allocator-full-non-direct-small-force-collect-post-exit`; it does not claim general remote-free routing, thread exit/teardown/lifecycle, abandonment/adoption, concurrent collection, public API/runtime/backend, public x86 support, or AArch64 evidence. |
| `x86_64_full_direct_small_force_collect_post_exit_evidence.py` and `x86_64-full-direct-small-force-collect-post-exit-evidence-v3.5.0.json` | Native x86-64-only private 28-field pinned-C/Rust differential for one worker-owned arena full direct-small regular-bin page: a 1024-byte request uses the 1024-byte, 64-block, one-slice class; a pre-remote preflight requires the complete rounded direct-cache range, one remote `mi_free` precedes real `mi_thread_done()`, `pthread_join()` precedes sequential consumer frees, force collection immediately publishes the mapped route while detaching the ordinary queue, and only the final free releases the PageMap/arena bitmap/slice and clears the terminal static-main abandoned-bin bitmap (`arena_abandoned_bin_bitmap_clear_after_final_free`). It is dispatched by `allocator-full-direct-small-force-collect-post-exit`; it does not claim general remote-free routing, thread exit/teardown/lifecycle, abandonment/adoption, concurrent collection, public API/runtime/backend, public x86 support, or AArch64 evidence. |
| `x86_64_automatic_pthread_destructor_evidence.py` and `x86_64-automatic-pthread-destructor-evidence-v3.5.0.json` | Native x86-64-only private 37-value pinned-C automatic pthread-destructor oracle. Its worker verifies mimalloc's real pthread key is associated with the initialized default Theap, returns naturally without an explicit `mi_thread_done()` or `pthread_exit()`, and is joined before the consumer observes its mapped-abandoned detached medium page and performs two terminal frees. It is dispatched by `allocator-automatic-pthread-destructor`; it does not compare Rust or claim a crabc pthread/TLS callback, Rust/private-runtime lifecycle integration, general destructor ordering, public API/runtime/backend, public x86 support, or AArch64 evidence. |
| `x86_64_cancellation_pthread_destructor_evidence.py` and `x86_64-cancellation-pthread-destructor-evidence-v3.5.0.json` | Native x86-64-only private 46-value pinned-C cancellation-triggered automatic pthread-destructor oracle. Its worker disables cancellation during setup, enables only deferred cancellation before its atomic-ready gate, and reaches exactly one `pthread_testcancel()` after the consumer's one `pthread_cancel()`; `pthread_join()` returns `PTHREAD_CANCELED` before the consumer observes its mapped-abandoned detached medium page and performs two terminal frees. It is dispatched by `allocator-cancellation-pthread-destructor`; it does not compare Rust or claim crabc pthread cancellation/TLS callback parity, Rust/private-runtime lifecycle integration, general cancellation/destructor ordering, public API/runtime/backend, public x86 support, or AArch64 evidence. |
| `x86_64_dynamic_full_medium_one_remote_force_collect_to_mapped_evidence.py` and `x86_64-dynamic-full-medium-one-remote-force-collect-to-mapped-evidence-v3.5.0.json` | Native x86-64-only private 29-field pinned-C/Rust differential for one sole full `BIN_FULL` medium arena page: request 10248 yields 12288-byte blocks, capacity/reserved 42, and eight slices; the C oracle's exactly one joined remote `mi_free` precedes real `mi_thread_done()`, while Rust uses only the corresponding private typed drain; force collection publishes mapped abandonment with dynamic bitmap/count and `used == 41`, and sequential consumer frees retain the mapped route until PageMap, ordinary arena bitmap, dynamic bitmap/count, and exact slice release. It is dispatched by `allocator-dynamic-full-medium-one-remote-force-collect-to-mapped`; it does not claim general lifecycle/routing/concurrent collection, abandonment/adoption, public API/runtime, backend, public x86 support, or AArch64 evidence. |
| `x86_64_dynamic_full_medium_unmapped_reabandon_evidence.py` and `x86_64-dynamic-full-medium-unmapped-reabandon-evidence-v3.5.0.json` | Native x86-64-only private 34-field pinned-C/Rust differential for one sole full `BIN_FULL` medium arena page: request 10248 yields 12288-byte blocks, capacity/reserved 42, and eight slices. No remote `mi_free` precedes real `mi_thread_done()`; the consumer joins before sequential frees. Force then false collection leaves it unmapped-abandoned with its full queue detached, PageMap and ordinary arena bitmap retained, dynamic bitmap/count clear, and `used == 42`. Five normal-collector frees retain that state at `used == 37`; the sixth crosses `reserved / 8 == 5`, maps it at `used == 36`, and sets dynamic bitmap/count one. The mapped tail clears PageMap, ordinary arena bitmap, dynamic bitmap/count, and the complete eight-slice span. It is dispatched by `allocator-dynamic-full-medium-unmapped-reabandon`; it does not claim general lifecycle/routing/concurrent collection, abandonment/adoption, public API/runtime, backend, public x86 support, or AArch64 evidence. |
| `x86_64_dynamic_full_large_one_remote_force_collect_to_mapped_evidence.py` and `x86_64-dynamic-full-large-one-remote-force-collect-to-mapped-evidence-v3.5.0.json` | Native x86-64-only private 31-field pinned-C/Rust differential for one sole full `BIN_FULL` large arena page: request 86706 yields 98304-byte blocks, capacity/reserved 42, and a 64-slice arena span with 63 PageMap-registered source page-area slices; the C oracle's exactly one joined remote `mi_free` precedes real `mi_thread_done()`, while Rust uses only the corresponding private typed drain; force collection publishes mapped abandonment with dynamic bitmap/count and `used == 41`, and sequential consumer frees retain the mapped route until PageMap, ordinary arena bitmap, dynamic bitmap/count, and complete 64-slice release. The final PageMap-null arena slice is slack but remains terminally released. It is dispatched by `allocator-dynamic-full-large-one-remote-force-collect-to-mapped`; it does not claim general lifecycle/routing/concurrent collection, abandonment/adoption, public API/runtime, backend promotion, public x86 support, or AArch64 evidence. |
| `x86_64_dynamic_full_large_unmapped_reabandon_evidence.py` and `x86_64-dynamic-full-large-unmapped-reabandon-evidence-v3.5.0.json` | Native x86-64-only private 34-field pinned-C/Rust differential for one sole full `BIN_FULL` large arena page: request 86706 yields 98304-byte blocks, capacity/reserved 42, and a 64-slice arena span with only 63 PageMap-registered source page-area slices; the final PageMap-null slice is slack but remains terminally released. In the C oracle, no remote `mi_free` precedes real `mi_thread_done()` and `pthread_join()`; Rust independently exercises its bounded typed owner-exit route on the owning test thread and does not claim a literal worker-thread/join counterpart. Five normal-collector frees retain unmapped abandonment at `used == 37` with dynamic bitmap/count zero; the sixth maps it at `used == 36` with dynamic bitmap/count one, and the mapped tail releases the complete 64-slice span. It is dispatched by `allocator-dynamic-full-large-unmapped-reabandon`; it does not claim general lifecycle/routing/concurrent collection, abandonment/adoption, public API/runtime, backend promotion, public x86 support, libc integration, or AArch64 evidence. |
| `x86_64_dynamic_full_singleton_homogeneous_aggregate_evidence.py` and `x86_64-dynamic-full-singleton-homogeneous-aggregate-evidence-v3.5.0.json` | Native x86-64-only private 51-field pinned-C/Rust differential for exactly two same-size full `BIN_FULL` arena singleton pages: request 524289 yields 589824-byte blocks, capacity/reserved 1, and nine arena slices per member. The C worker performs real `mi_thread_done()` and the joined consumer frees sequentially; both members begin unmapped-abandoned, unowned, PageMap-registered across all nine slices, ordinary-arena-bitmap-set, and full-queue-detached, with no dynamic abandoned bitmap/count. The first terminal free releases only page 0 while page 1 remains registered, unmapped-abandoned, unowned, and used 1; the second releases page 1. Rust uses only the typed current-thread owner-exit model and makes no Rust worker/join claim. It is dispatched by `allocator-dynamic-full-singleton-homogeneous-aggregate`; it does not claim general lifecycle/routing/concurrency, abandonment/adoption, public x86 libc/ldso/crabc support, backend promotion, or AArch64 evidence. |
| `x86_64_dynamic_full_direct_small_one_remote_force_collect_to_mapped_evidence.py` and `x86_64-dynamic-full-direct-small-one-remote-force-collect-to-mapped-evidence-v3.5.0.json` | Native x86-64-only private 32-field pinned-C/Rust differential for one sole full direct-small ordinary regular-bin arena page: request/block size 1024, capacity/reserved 64, one slice, and exact rounded direct-cache range `[113, 128]`; the consumer/main thread's exactly one joined remote `mi_free` precedes the worker's real `mi_thread_done()`, while Rust uses only the corresponding private typed drain. Force collection publishes mapped abandonment with dynamic bitmap/count and `used == 63`; pinned source anchors and the typed handoff establish direct-cache clear-before-page-count-detach; sequential consumer frees use only the source partial collector until PageMap, ordinary arena bitmap, dynamic bitmap/count, and one-slice release. It is dispatched by `allocator-dynamic-full-direct-small-one-remote-force-collect-to-mapped`; it does not claim general lifecycle/routing/concurrent collection, abandonment/adoption, public API/runtime, backend promotion, public x86 support, or AArch64 evidence. |
| `x86_64_dynamic_full_direct_small_unmapped_reabandon_evidence.py` and `x86_64-dynamic-full-direct-small-unmapped-reabandon-evidence-v3.5.0.json` | Native x86-64-only private 38-field pinned-C/Rust differential for one sole full direct-small ordinary regular-bin arena page: request/block size 1024, capacity/reserved 64, one slice, and exact rounded direct-cache range `[113, 128]`. No remote `mi_free` precedes the worker's real `mi_thread_done()`; the consumer joins before sequential frees. Exact direct-cache clear-before-page-count-detach leaves the page unmapped-abandoned with PageMap/ordinary-arena-bitmap preserved, ordinary queue detached, dynamic bitmap/count clear, and `used == 64`; the first partial-collector consumer free retains `used == 64`. Nine partial-collector frees retain unmapped state at `used == 56`; the tenth partial collector takes `used` to 55, then generic unown consumes the retained current head and maps it at `used == 54` with dynamic bitmap/count one. The mapped tail clears PageMap, ordinary arena bitmap, dynamic bitmap/count, and the one slice. It is dispatched by `allocator-dynamic-full-direct-small-unmapped-reabandon`; it does not claim general lifecycle/routing/concurrent collection, abandonment/adoption, public API/runtime, backend promotion, public x86 support, or AArch64 evidence. |
| `x86_64_later_thread_exit_full_direct_small_pages_evidence.py` and `x86_64-later-thread-exit-full-direct-small-pages-evidence-v3.5.0.json` | Native x86-64-only private 67-field pinned-C/Rust differential for exactly two same-bin full ordinary regular-bin direct-small arena pages: request/block size 1024, capacity/reserved 64, one slice per member, and complete direct-cache range `[113, 128]`. The real C pthread worker has no remote free, runs `mi_thread_done()`, and the consumer `pthread_join()`s before every sequential free. Both members begin unmapped-abandoned with PageMap and ordinary arena bitmap retained and ordinary queues detached. The C source dynamic and Rust typed later-main static-main abandoned bitmap/count are both clear through the nine-free partial-collector prefix at `used == 56`, then both publish the normalized common `abandoned_*` state at the mapped `used == 54` boundary. Page 0 releases independently before page 1 closes the route. Rust observes a scoped test worker and join only for common typed private facts; it does not claim crabc pthread/TLS callback parity. It is dispatched by `allocator-later-thread-exit-full-direct-small-pages`; it does not claim general lifecycle/routing/concurrency, abandonment/adoption, allocation-time claim/reclaim/requeue, public API/runtime, backend, public x86 support, or AArch64 evidence. |
| `x86_64_dynamic_full_non_direct_small_unmapped_reabandon_evidence.py` and `x86_64-dynamic-full-non-direct-small-unmapped-reabandon-evidence-v3.5.0.json` | Native x86-64-only private 35-field pinned-C/Rust differential for one sole full non-direct-small ordinary regular-bin arena page: request 1032 yields 1280-byte blocks, capacity/reserved 51, one slice, and an empty direct-cache image. No remote `mi_free` precedes the worker's real `mi_thread_done()`; the consumer joins before sequential frees, so the full page begins unmapped-abandoned with PageMap/ordinary-arena-bitmap preserved, dynamic bitmap/count clear, and `used == 51`. Six normal-collector frees retain unmapped state at `used == 45`; the seventh maps at `used == 44` and publishes dynamic bitmap/count one. The mapped tail clears PageMap, ordinary arena bitmap, dynamic bitmap/count, and the one slice. It is dispatched by `allocator-dynamic-full-non-direct-small-unmapped-reabandon`; it does not claim general lifecycle/routing/concurrent collection, abandonment/adoption, public API/runtime, backend promotion, public x86 support, or AArch64 evidence. |
| `x86_64_dynamic_full_non_direct_small_one_remote_force_collect_to_mapped_evidence.py` and `x86_64-dynamic-full-non-direct-small-one-remote-force-collect-to-mapped-evidence-v3.5.0.json` | Native x86-64-only private 30-field pinned-C/Rust differential for one sole full non-direct-small ordinary regular-bin arena page: request 1032 yields 1280-byte blocks, capacity/reserved 51, one slice, and an empty direct-cache image; the consumer/main thread's exactly one joined remote `mi_free` precedes the worker's real `mi_thread_done()`, while Rust uses only the corresponding private typed drain. Force collection publishes mapped abandonment with dynamic bitmap/count and `used == 50`; the first sequential failed-reclaim free follows normal `used + 2 == reserved` geometry while preserving the mapped route, and the final free clears PageMap, ordinary arena bitmap, dynamic bitmap/count, and the one slice. It is dispatched by `allocator-dynamic-full-non-direct-small-one-remote-force-collect-to-mapped`; it does not claim general lifecycle/routing/concurrent collection, abandonment/adoption, public API/runtime, backend promotion, public x86 support, or AArch64 evidence. |
| `x86_64_mapped_post_exit_evidence.py` and `x86_64-mapped-post-exit-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one worker `mi_thread_done()` followed by `pthread_join()` before consumer frees, selected mapped failed-reclaim/unown, and three observed terminal cleanup checks. It is dispatched by `allocator-mapped-post-exit`; Rust covers only one bounded process-owned mapped regular handoff and directly observes PageMap, ordinary arena-page bitmap, and free-slice bitmap release. The lane does not claim general thread exit/routing, public API, backend, public x86 support, or AArch64 evidence. |
| `x86_64_retired_prepass_evidence.py` and `x86_64-retired-prepass-evidence-v3.5.0.json` | Native x86-64-only private 21-field pinned-C/Rust differential for one worker-local retirement, real `mi_thread_done()`/`pthread_join()` retired-page force-release, one distinct live mapped-abandoned page, and one consumer terminal free. It is dispatched by `allocator-retired-prepass`; it directly records PageMap, ordinary arena bitmap, exact slice-span, and empty-route checks, and does not claim general retirement/teardown/routing/concurrency, public API/runtime/backend, public x86 support, or AArch64 evidence. |
| `x86_64_aggregate_post_exit_evidence.py` and `x86_64-aggregate-post-exit-evidence-v3.5.0.json` | Native x86-64-only private 25-field pinned-C/Rust differential for exactly two distinct live nonfull medium arena pages in distinct bins: the real worker runs `mi_thread_done()` and returns, the consumer calls `pthread_join()` before freeing, both pages are mapped-abandoned after teardown, then a second-first selective terminal release is followed by a first-page terminal release and empty route. It is dispatched by `allocator-aggregate-post-exit`; it directly records PageMap, ordinary arena bitmap, exact slice span, and the first page's registered/bit-set/mapped-abandoned/`used == 1` state after the second-page free. It does not claim general teardown/routing/concurrency, public API/runtime/backend, public x86 support, or AArch64 evidence. |
| `x86_64_aggregate_still_live_evidence.py` and `x86_64-aggregate-still-live-evidence-v3.5.0.json` | Native x86-64-only private 46-field pinned-C/Rust differential for two distinct clients on one nonfull medium page A and a one-client distinct-bin medium page B: the worker runs `mi_thread_done()` and returns, the consumer calls `pthread_join()` before every free, A's first free is `StillLive` and preserves A/B/the route, B's free is `ReleasedPage` and terminally releases only B, and A's second free is `ReleasedAll` and completes the route. It is dispatched by `allocator-aggregate-still-live`; it does not claim general teardown/routing/concurrency, public API/runtime/backend, public x86 support, or AArch64 evidence. |
| `x86_64_aggregate_same_bin_still_live_evidence.py` and `x86_64-aggregate-same-bin-still-live-evidence-v3.5.0.json` | Native x86-64-only private 53-field pinned-C/Rust differential for two distinct clients on one nonfull medium page A plus a one-client medium page B in the same bin: the worker fills A, creates B, locally restores A to two clients, runs `mi_thread_done()`, and returns; the consumer calls `pthread_join()` before every free. It records selected same-bin queue count/link/saved-successor traversal and mapped-abandoned count/bitmap transitions `2 -> 2 -> 1 -> 0`; A's first free is `StillLive`, B's is `ReleasedPage`, and A's second free is `ReleasedAll`. It is dispatched by `allocator-aggregate-same-bin-still-live`; it does not claim general teardown/routing/concurrency, public API/runtime/backend, public x86 support, or AArch64 evidence. |
| `x86_64_dynamic_os_aligned_singleton_evidence.py` and `x86_64-dynamic-os-aligned-singleton-evidence-v3.5.0.json` | Native x86-64-only private 21-field pinned-C/Rust differential for a 7-byte, 128 KiB-aligned OS singleton: real C `mi_thread_done()` and `pthread_join()` precede the sole consumer free; the selected 4096-byte page is semantically full but is an unflagged `MI_BIN_HUGE` member with an empty `MI_BIN_FULL` queue. It records the bounded OS-list/PageMap/mapping terminal tail while Rust uses only a typed private owner-exit handoff. It is dispatched by `allocator-dynamic-os-aligned-singleton`; it does not claim general lifecycle/routing/concurrency, abandonment/adoption, public API/runtime/backend, public x86 support, or AArch64 evidence. |
| `x86_64_dynamic_arena_singleton_post_exit_evidence.py` and `x86_64-dynamic-arena-singleton-post-exit-evidence-v3.5.0.json` | Native x86-64-only private 21-value pinned-C/Rust differential for one full arena singleton (request 524289, 589824-byte block size, capacity/reserved 1, nine arena slices): a real C worker runs `mi_thread_done()` and joins before the sole terminal consumer `mi_free`; the trace records teardown/join, unmapped/unowned/detached state, all-nine-slice PageMap/arena-bitmap preconditions, and terminal PageMap/bitmap/slice cleanup. Rust observes a scoped test worker and join while comparing only common typed private owner-exit facts, distinct from its Rust-only route. It is dispatched by `allocator-dynamic-arena-singleton-post-exit`; it does not claim pthread/TLS callback parity, general lifecycle/routing/concurrency, public x86/crabc API/runtime, backend promotion, or AArch64 evidence. |
| `x86_64_lifecycle_evidence.py` | Native x86-only fixed private lifecycle/concurrency selections. Its nine lanes are deliberately narrower than general allocator lifecycle or stress qualification. |
| `x86_64_fault_evidence.py` | Native x86-only fixed crate-private fault-injection state-preservation selections. Its five lanes are deliberately narrower than general fault/misuse, lifecycle, or stress qualification. |
| `perf_x86_64.py` and `perf-x86_64/` | Native x86-only private-adapter C/Rust timing and post-init live-memory measurement harness. Its reports are not the public-runtime `compat/perf/` matrix. |
| `known-differences.md` | Sole register for observed, pending, accepted, or rejected Rust/C differences; every entry must identify its architecture profile. |

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

`./scripts/dev.sh allocator-shadow` is the explicit early Rust-shadow lane.
It first builds the default owned sysroot and then rebuilds only
`crabc-libc` with `native-mimalloc-shadow`, so the C ABI fixtures execute the
selected `libc.so` rather than a default artifact left by sysroot assembly.
Immediately before that feature rebuild, its paired shadow-ABI matrix snapshots
and attests the ordinary C-backed `libc.so`; immediately afterward, it links
and runs one normalized local public C allocation trace once against each
explicit artifact. The matrix is the sole deliberate ordinary-artifact run in
this command, uses an isolated `LD_LIBRARY_PATH` for each process, and records
its two zero-size `realloc` alignment known-red backend differences plus
intentionally blocked cross-owner/lifecycle/DSO/layout rows rather than
treating either as a default-backend fallback. The remaining C ABI fixtures
stay selected-native only.
It covers the allocator fixture's local malloc/calloc/realloc/free/alignment/
usable-size contract, the pthread TSD-destructor fixture's worker-local
allocation/free plus all-free finish, bounded one- and two-owner owner-exit
fixtures, and one bounded live-owner remote-free fixture. The selected
`native_mimalloc_initial_remote_free` fixture additionally proves that an
attached worker can return exact still-live initial-thread normal and aligned
clients through the source atomic remote head. The client itself pins its page;
the worker takes no page engine, scheduler claim, or stored pointer capability,
and ticket zero collects the head during its next ordinary operation. In the
separate `native_mimalloc_initial_live_local_worker` fixture, the initial
thread keeps its ordinary client in its persistent compiler-TLS owner while
the child attaches an independent local owner. No initial engine, session, or
address crosses `clone`, and the parent does not suspend or park its live
owner. After the child returns all-free, the initial thread continues to query,
reallocate, validate, free, and reuse its client. This is a serialized
initial-live/local-worker witness, not a concurrent allocator or general
pointer handoff. Its companion
`native_mimalloc_initial_live_parallel_workers` fixture synchronizes two
distinct later local workers, releases and joins them one at a time, and then
verifies the initial live client through its direct owner. It likewise admits
no concurrent PageMap mutation or pointer handoff. The
`native_mimalloc_initial_live_owner_exit` companion keeps that same initial
client with its direct owner while a later A leaves the existing mixed
owner-exit aggregate; fresh B terminally frees its exact C inputs and finishes
normally before the initial thread queries, reallocates, validates, and frees
its own client. It does not hand A or B the initial client or admit concurrent
PageMap mutation. In the
owner-exit fixture A leaves a
direct-small block, a non-direct-small block, a medium block, a regular-large
block, an unaligned arena singleton, and an OS-aligned singleton live; a fresh
no-page B first reads their PageMap-derived usable extents, then frees their
exact C addresses through generic pointer-first free. A detached client never
enters B's `realloc` engine or a route replacement transition; its source
bytes remain live until that generic free consumes it. This exposes neither
A's page nor allocator.
The
same aggregate exercises A's normal return, `pthread_exit`, and deferred
cancellation. Its cancellation path runs one cleanup handler and then one
A-side TSD destructor, each allocating and freeing locally, before A's source
teardown collect-abandons the surviving pages. The
`native_mimalloc_many_owner_exit_allocations` fixture drives the same ordinary
session past its inline ledger with 80 1 KiB direct-small clients, then adds
non-direct-small, medium, large, and arena-singleton clients. It therefore
requires the one aggregate traversal to account for a full direct-small page,
a later nonfull page in that same source bin, and the other regular source
classes across eight owner-exit epochs. It remains an exact-address,
pointer-private PageMap witness rather than a general cross-thread allocator.
The `native_mimalloc_concurrent_post_exit_release` fixture adds the OS-aligned
singleton tail and releases that same mixed aggregate from four fresh B workers
that begin together. Each worker receives only a disjoint exact subset of A's
C inputs; each free starts from its PageMap source and W03 performs only the
page or abandoned-state serialization required by that source operation. There
is no `ACTIVE -> BUSY` route entry, completion token, or old-owner admission
carried into B's normal finish. A's source exit releases A's admission; each B
finish releases only B's own admission. The terminal free releases the source
page and OS mapping in source order, and ticket zero may continue whenever that
source state permits. The same pointer-first rule applies to usable-size and
nonlocal `realloc`: B allocates and copies its replacement, then consumes the
old source through generic free before returning the replacement. Exact live
remote publication is also pointer-first: A's persistent PageMap/page state
names each exact live client, and B/C can query its immutable usable extent or
push its canonical block to the source remote head without claiming A's TLS,
a parked session, or a client ledger. A's next ordinary operation or finish
collects that source head.

`native_mimalloc_source_published_exit` covers the no-local-client finish:
after B publishes A's sole exact client, A performs no further allocator
operation and its ordinary pthread destructor collects the source head before
ticket zero reactivates. `native_source_published_live_owner_exit` and its
selected-C companion cover the mixed boundary, where one joined source
publication is collected by A while a distinct client follows the existing
post-exit PageMap route.

The direct and selected-C `native_two_live_remote_owners` fixtures keep two
independent live source pointers while B1/B2 each query or free only the
pointer handed to them. The historical
`native_live_remote_owner_registry_reuse` target is now an ungated repeated
persistent-PageMap epoch witness; it no longer observes or compiles a registry
audit. These fixtures do not establish general worker-pointer dispatch,
concurrent PageMap mutation, or a worker allocator.
The separate two-owner and three-owner fixtures make A workers detach before
any fresh B starts. Their surviving clients are represented only by PageMap and
abandoned-page state. A releases its admission when its source owner exits;
each B derives an exact client from the pointer and completes only its own
attachment lifecycle. The Rust witnesses interleave B frees and finishes in a
different order, while the selected C fixture releases the same sources in
non-FIFO order. This establishes concurrent callers with source-local PageMap
serialization, not a registry traversal, route completion, or B-held A
admission. A terminal source failure retains that source state rather than
publishing a fallback, but it does not make an unrelated B teardown terminal.
After W07 has claimed one exact final source page, only W03's regular or
singleton terminal callback may wait on the existing private PageMap lock for
that short release; ordinary lifecycle admission remains nonblocking and
reports contention instead.
The separately feature-gated `native_post_exit_failed_os_release` witness
constructs the same mixed aggregate but gives B only the OS-aligned address.
It injects failure into the next source `munmap`, verifies that B's exact free
returns `Retained`, then lets B finish its own no-page attachment. The failed
PageMap source is not retried by either a second free or B's teardown; B's
admission still releases normally. Clearing the direct-test injection does not
create a retry or fallback, and the hook exposes neither a generic fault plan
nor an allocator capability.
`native_post_exit_with_local_session` separately proves that B may already
hold a local session while it reads A's PageMap extent, establishes a
replacement, copies A's bounded prefix, and consumes A's source through the
generic pointer-first free continuation. B then reallocates only its own local
client; the W03 source operation remains wholly PageMap-owned and B's later
teardown remains its own lifecycle.
The feature-gated `native_multiple_post_exit_completions` regression then
has one B consume two independent abandoned A sources, resume B-local
allocation and `realloc`, and then discharge B's local client before B's own
teardown. Its scalar audit requires the two A exits to release their admissions
before B attaches and B's own finish to release the remaining admission. It
proves pointer-first source consumption, not a cross-thread client registry or
a normal no-page finalizer for an abandoned owner.
`native_terminal_completion_live_remote_free` is now the adjacent
post-exit/PageMap witness: B frees A's post-exit clients, then source-publishes
one exact C-owned live client through persistent PageMap/page state. B and C
finish through their own ordinary boundaries; the test does not use a live
owner handoff or a worker-pointer dispatcher.
`tests/native_mimalloc_parallel_local_workers.rs` pauses A with a persistent
live allocation and B with a distinct local allocation; B can query and free
only B's own client, complete its all-free thread finish, and leave A's source
state valid for A's later local free. The
fixture then proves ticket-zero reactivation after A finishes across 128 fresh
process epochs. An already parked session retries a lost scheduler CAS only
while the scheduler still records `BUSY` or a nonzero parked count; `READY`
and terminal states mean its own token is no longer represented. A first
session has no token yet, so it may retry from `READY` when a peer completed
between its sampled CAS and retry. This does not create a pointer handoff or
concurrent PageMap mutation.
`tests/native_mimalloc_live_remote_owner_exit.rs` composes that exact live
publication with A-side source collection and a later deferred A exit: a
separate fresh worker frees the remaining small/medium aggregate only through
generic pointer-first PageMap/W03 dispatch. This serial witness does not
broaden that path into general concurrent pointer dispatch.
`crabc-mimalloc/tests/native_post_exit_lifecycle.rs`,
`crabc-mimalloc/tests/native_aggregate_post_exit_reclaim.rs`, and
`crabc-mimalloc/tests/native_sole_post_exit_lifecycle.rs` are historical
source-scoped witnesses; production post-exit behavior is instead specified by
the pointer-first PageMap/W03 regressions and has no B-held scheduler token.
The selected boundary has no C fallback: wrong-owner native pointers fail-stop.
`tests/native_mimalloc_owner_exit_realloc.rs` proves the selected C boundary:
an overflowing foreign `realloc` returns `ENOMEM` while preserving A's exact
client and source bytes. A valid post-exit foreign `realloc` establishes B's
persistent replacement owner, allocates and copies the requested prefix, then
consumes A's source once through generic pointer-first free before returning
the replacement. B separately preserves its prefix across local shrink and
growth, receives its zero-size local replacement, and retains that client in a
TSD value. The destructor makes a further local `realloc` and frees it before
B's own native finish. B exits through `pthread_exit`: its cleanup handler
makes and frees a local allocation, then the TSD destructor continues the
existing local client before freeing it. The same fixture also proves normal
return's TSD-only phase and repeats the cleanup/TSD ordering through deferred
cancellation at a real cancellation point. It does not yet cover general
concurrent owner-exit traversal or arbitrary worker allocation beyond the
bounded live-entry witnesses, and is not a Gate 5E or promotion pass.
`tests/native_mimalloc_shadow_abi.rs` runs
`tests/fixtures/native_mimalloc_shadow_foreign_realloc_test.c`, which keeps A
live under an explicit pthread handshake while the initial thread presents A's
client to `realloc`. The native-shadow-only witness requires `NULL`/`ENOMEM`
and a preserved prefix for its overflowing request; its valid request returns
B's copied replacement after generic pointer-first free consumes the old
source. Pinned musl permits this live cross-thread reallocation, so the
witness remains a differential rather than a native-contract divergence.
The same command ends with the separately reviewed
`native-shadow-stress-v3.5.0.json` witness. It applies a behavior-named patch
to pinned upstream `test/test-stress.c`, routes standard C allocation calls
through the selected shadow `libc.so`, and runs exactly four source pthread
workers with fixed `4 1 2` inputs for 128 fresh process epochs. Each selected
source transfer cleanup runs in one fresh pthread after its producing workers
join. The contract rejects unsupported heap, walk, subprocess, leak, and
large-object modes; this is bounded source-derived lifecycle evidence, not a
general pointer-routing, concurrent-PageMap, or promotion claim.

## Separate completion tracks

Record these outcomes independently:

| Track | Required question |
| --- | --- |
| libc allocator readiness | Can the Rust engine back crabc's `malloc` family while preserving the existing C ABI, interposition, `errno`, failure, alignment, zero-size, and output-preservation rules? |
| mimalloc v3.5.0 AArch64 parity | Is every public Linux/AArch64-applicable `mi_*` API and compile-time mode derived from the pinned headers, symbols, declarations, and upstream tests accounted for? |
| mimalloc v3.5.0 x86-64 parity | Is every selected native Linux/x86-64-applicable `mi_*` API and compile-time mode separately accounted for and verified against native C, without implying public x86 `crabc` support? |

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
