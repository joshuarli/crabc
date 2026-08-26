The crucial framing is: **do not design a new allocator**. Produce a provenance-preserving, semantically faithful Rust port of a fixed upstream mimalloc v3 release, then optimize only where measurement shows the Rust translation diverges. The objective is to remove the C allocator from the production dependency graph while retaining mimalloc’s design, behavior, and performance—not to create “mimalloc-inspired” machinery.

## Handoff — 2026-08-27

### Current slice — later-main mapped two-block large post-exit route

`MainHeapThreadProcessPageExitDrain::abandon_mapped_two_block_large_to_process_route`
now ports one deliberately disjoint `MI_ABANDON` shape: the departing
later-main owner has exactly one initially nonfull `PageKind::Large` arena page
with `MEDIUM_MAX_OBJ_SIZE < block_size <= LARGE_MAX_OBJ_SIZE`, `reserved > 2`,
`used == 2`, no direct-cache image, no other queue member, zero retirement,
and its complete fixed 64-slice span. It preserves source force collection,
false collection, queue/page-count detach, static-main bitmap/count
publication, and unown before the old Theap/TLD tears down. The generic
small-or-medium entry remains disjoint.

The returned linear process route is client-free-only. Its first free retains
every PageMap registration and `pages_main` bit across the entire large span;
its second free clears the bitmap/count pairing, unregisters all 64 PageMap
entries, clears the source ordinary static-arena bit, retires metadata, and returns the
complete span. `ThreadExitMappedRegularPostExitOrigin::InitiallyNonfullLargeTwoBlock`
therefore cannot enter the existing allocation-time adoption/requeue edge. The
focused regressions prove the two-free lifecycle and full-span release, and
that a one-block large page rejects before collection or detach. One or three
blocks, another page, direct-cache state, aggregates, producers, concurrency,
and general large-page routing remain outside this slice.

The two focused regressions, the complete 586-test `crabc-mimalloc` library
suite, and the offline allocator ratchet check pass in the pinned
Linux/AArch64 container (134 source items; 138 implemented and unit-verified).
The offline `allocator --full` adapter lane also passes, then exits with its
documented later-milestone status because integrated lifecycle/remote-free/
pthread evidence remains incomplete.

### Current slice — dormant ticket-zero/later-worker page handoff

`MainStaticRuntimeFirstArenaPageAllocator` now carries the permanent
ticket-zero `MainStaticProcessPageSession` inside `RuntimeProcessStorage`. It
starts with no mapping and only reserves the frozen source default arena when
its first valid ordinary request needs a fresh page. While pages are live, the
stored engine and its `ProcessPageMapMutationLease` remain process-owned. Once
that engine proves every page, queue, direct entry, retired record, and pending
OS release empty, it returns only the Rust aliasing lease: the permanent
session and its already-published first arena stay process-owned, static
teardown remains closed, and the next ticket-zero request may reactivate
against that same arena without a second reservation. The runtime's short
`READY -> BUSY` transition keeps the native owner on its exact ticket-zero
TPIDR_EL0 image and prevents recursive mutable entry.

The preceding permanent session is now deliberately constructed from a shared
`ProcessMainThread` view, rather than by making an aliased mutable process
owner beside the already-published `MainStaticHeapLease`. It still validates
the zero-page roots and images, permanently closes main teardown, and permits
later *no-page* main-Heap attachments through the existing projection lock.
Once the page owner starts—even before it maps—the existing no-page fork
preservation predicate rejects it conservatively; child repair remains out of
scope.

The isolated runtime-storage regression proves the owner is mapping-free at
startup, allocates and frees one real ticket-zero block through the first
source arena, lets one later main-heap attachment borrow that same published
pair only while ticket zero is dormant, restores its normal empty worker
teardown, then reactivates ticket zero. It also disables no-page fork
preservation. A distinct `no_std`
`crabc-mimalloc-runtime-ticket-zero-adapter` now exposes exactly six
*test-only prefixed* C symbols in a fresh process: init with the caller's
`AT_PAGESZ`, malloc, zalloc, realloc, free, and one pointer-free worker round
trip. Its direct fixture proves first-allocation activation, realloc prefix
preservation, zeroing, exact free, the all-free dormant handoff, one fresh
pthread's scoped page-engine allocation/free and normal attachment teardown,
same-arena ticket-zero reactivation, and successful-path `errno` preservation.
The evidence adapter has no unprefixed `malloc`/`free` or `mi_*` export, no
dynamic dependency, no process-exit shutdown or external reuse path, and no
relation to `crabc-libc`'s production ABI.
`crabc-libc` still does not call this seam, `libmimalloc-sys` remains the C
allocator backend, and there is no concurrent or general later-worker page
engine, fork repair, or backend switch. The focused regression, complete
584-test `crabc-mimalloc` library suite, and direct C fixture pass in the
pinned Linux/AArch64 image. `allocator --full` records this adapter evidence
and exits with its documented later-milestone status until the broader
routing/lifecycle gates are complete.

### Current slice — later-main mixed full singleton/regular aggregate route

`MainHeapThreadProcessPageExitDrain::abandon_full_singleton_or_regular_pages_to_process_route`
now ports one bounded heterogeneous `src/theap.c` `BIN_FULL` owner-exit image:
two or more full arena members with at least one `PageKind::Singleton` and at
least one regular `PageKind::Medium` or `PageKind::Large`. Every direct slot and
every other queue is empty. Singleton members prove `BIN_HUGE`, `reserved ==
used == 1`, zero retirement, an empty local free list, and an exact rounded
span; regular members prove an ordinary static-main bin, `reserved > 1`, `used
== reserved`, zero retirement, an empty local free list, and their exact
medium or large span. Source order remains force -> false collection ->
full-queue/page-count detach -> unmapped abandonment before old-Theap/TLD
teardown.

`ThreadExitFullSingletonOrRegularPagesPostExitParts` composes only the two
source-specific post-exit facts plus an aggregate terminal count; it stores no
raw former-Theap page list. Each free classifies a fresh PageMap registration.
The singleton takes only the raw empty failed-reclaim tail; the regular member
claims its low owner bit before selecting the exact static-main bitmap/count
pair and normal unmapped-or-mapped tail. A terminal release removes only that
member's PageMap -> `pages_main` -> metadata -> exact arena span, and the map
route closes only after both tails have released. The focused later-main
regression fills one singleton and one medium page, proves the singleton
release, observes the regular static-main bitmap/count publication, then
proves the final regular release. Homogeneous queues, regular-only mixed
medium/large queues, small/direct-small, OS, huge, malformed spans,
allocation-time claim/adoption/reclaim/requeue, scans, producers, concurrent
frees, and general owner-exit traversal remain absent.

The focused regression and the complete 580-test `crabc-mimalloc` library
suite pass in the pinned Linux/AArch64 container. The allocator ratchet checks
at 130 items and 134 implemented/unit-verified entries; the quick C
differential gate also passes, including its five test-only Loom schedules and
the separate production initial-exec TLS code-generation proof.

### Current slice — dynamic mixed full singleton/regular aggregate route

`DynamicThreadExitDrain::abandon_full_singleton_or_regular_pages` now ports
the bounded heterogeneous `src/theap.c` `BIN_FULL` owner-exit image containing
two or more full arena pages, at least one `PageKind::Singleton` and at least
one regular `PageKind::Medium` or `PageKind::Large`. Every member independently
proves full state, zero retirement, an empty local free list, and its exact
arena/PageMap span; singleton members additionally prove `BIN_HUGE` and
`reserved == used == 1`, while regular members prove their ordinary bin,
`reserved > 1`, and matching dynamic bitmap/count capability. Every direct
slot and other queue is empty. The route preserves force -> false collection ->
full-queue/page-count detach -> unmapped abandonment while retaining the
dynamic drain rather than taking later-main teardown.

`DynamicThreadExitFullSingletonOrRegularPagesRoute` carries only that drain
and a member count. Each client free re-resolves its PageMap member. A
singleton follows the raw terminal failed-reclaim tail and releases its own
rounded span; a regular member claims its low owner bit before selecting its
dynamic map and follows the normal unmapped-or-mapped collector tail. The
focused native regression fills one singleton and one medium page, proves the
singleton release, observes the medium unmapped-to-mapped transition, and
then proves the medium release. It is not a general heterogeneous registry:
homogeneous queues, regular-only mixed medium/large queues, small/direct-small,
OS, malformed spans, allocation-time, reclaim/adoption/requeue, scan,
producer, concurrent, and general owner-exit paths remain absent.

The focused regression and the complete 579-test `crabc-mimalloc` library
suite pass in the pinned Linux/AArch64 container. The complete allocator quick
gate also passes with the 129-item/133-implemented ratchet. Its five test-only
Loom schedules clear the production `CARGO_ENCODED_RUSTFLAGS` because they
model atomic ordering without touching compiler TLS; the separate codegen gate
continues to prove the production initial-exec TLS requirement.

### Current slice — later-main mixed full medium/large aggregate route

`MainHeapThreadProcessPageExitDrain::abandon_full_medium_or_large_pages_to_process_route`
now ports one deliberately bounded heterogeneous `src/theap.c` `BIN_FULL`
owner-exit class: the complete later-main source queue must contain two or more
full arena regular pages, including at least one `PageKind::Medium` and one
`PageKind::Large`; every direct slot and every other queue is empty. Each member
independently proves its rounded static-main bin, `reserved > 1`, `used ==
reserved`, zero retirement countdown, empty local free list, and exact paired
arena/PageMap span (one slice for medium, 64 slices for large). The route keeps
the source order—force collection, false collection, full-queue removal,
page-count decrement, then unmapped abandonment—before old Theap/TLD teardown.

The new `ThreadExitFullMediumOrLargePagesPostExitParts` registry keeps no raw
former-Theap member list. Each sequential canonical client free re-resolves a
PageMap entry under short access, claims its low owner bit, derives that
member's bitmap/count capability only after that claim, follows the shared
normal-collector unmapped-or-mapped failed-reclaim tail, and then releases only
the selected PageMap -> `pages_main` -> metadata -> exact arena span. The
aggregate closes its map only after the final member. The companion low-level
test covers the source tail for both page kinds; the end-to-end later-main test
fills one medium and one large page, crosses both routes, and proves both spans
release. This is not a general heterogeneous registry: homogeneous queues,
small/direct-small, singleton, OS, huge, malformed spans, remote-force
nonfull, allocation-time adoption/reclaim/requeue, producers, concurrency, and
full queue scans outside the one consuming transition remain absent.

The two focused regressions and the complete 579-test `crabc-mimalloc`
library suite pass in the pinned Linux/AArch64 container.

### Current slice — dynamic mixed full medium/large aggregate route

`DynamicThreadExitDrain::abandon_full_medium_or_large_pages` now ports the
matching bounded dynamic-drain `src/theap.c` `BIN_FULL` class. Its complete
source queue has two or more full arena regular pages, at least one
`PageKind::Medium` and one `PageKind::Large`, an empty direct-cache/other-queue
image, and independently proven rounded dynamic bins, zero retirement, empty
local free lists, and exact one-slice medium or 64-slice large arena/PageMap
spans. It preserves force -> false collection -> full-queue/page-count detach
-> unmapped abandonment while retaining the dynamic drain rather than taking
the later-main Theap/TLD teardown path.

`DynamicThreadExitFullMediumOrLargePagesRoute` carries only that drain and a
member count. Each sequential client free re-resolves its PageMap member,
claims the low owner bit, derives only that member's dynamic bitmap/count map,
uses the shared normal-collector failed-reclaim tail, and releases just that
member's PageMap -> dynamic ordinary bit -> metadata -> exact arena span. The
final release returns the empty dynamic drain. The end-to-end native regression
fills one medium and one large page and proves both spans release; the complete
579-test library suite passes. Homogeneous queues, small/direct-small,
singleton, OS, malformed span, allocation-time, reclaim/adoption/requeue,
scan, producer, concurrent, and general owner-exit paths remain absent.

### Current slice — ticket-zero first fresh-page default arena

`ProcessSharedArenaStorage::reserve_default_os_arena` now ports the first
automatic `src/arena.c:341-406` `mi_arena_reserve` decision for the frozen
Linux/AArch64 normal-release profile. Given a source fresh-page byte
requirement, it adds `MI_ARENA_MAX_CHUNK_OBJ_SIZE` headroom, selects the
64-bit default 1-GiB arena, chooses a committed map only when the source
`arena_eager_commit == 2` condition sees Linux overcommit, and retries the
source 128-MiB arena only after the first map or unpublished in-place setup
has fully returned the one-arena sidecar to COLD. The regular reservation still
owns the exact final mapping/registry/metadata transition; a retained map or
failed release never opens a second attempt.

`MainStaticFirstArenaPageAllocator` now consumes that policy for exactly one
private ticket-zero page engine. It begins with no mapping, derives the
small/medium/large/singleton span for an empty Theap's first ordinary request,
revalidates the zero-page ticket-zero image before mapping, holds the matching
PageMap lifecycle through activation, and then delegates to the established
static page engine. `ProcessMainThread::begin_first_arena_page_allocator` is
its only production-shaped factory: it passes the retained ticket-zero
attachment and immutable ready PageMap witness without reserving or mapping
during process initialization. Invalid requests leave the sidecar cold; a
retryable map rejection returns the owner to that state. This is deliberately not process
initialization, a fixed eager startup reservation, or general allocation:
there is no existing-arena scan, later arena-count scaling, option mutation,
large-page/NUMA/exclusive policy, multiple arenas, aligned route, concurrent
consumer, shutdown, or public C ABI integration. The focused native
regressions cover the default shape, Linux commit condition, smaller-reservation
retry, two failed attempts returning to COLD, the empty-Theap span branches,
the ticket-zero lazy fresh-page connection, and one immutable post-publication
pair: after the first engine is empty, a scoped later main-heap owner can reuse
the exact selected map/arena. Both bounded process page owners now expose the
source normal `realloc` delegate: `realloc(NULL, size)` alone reaches the
ticket-zero first-arena policy, while live-block failure preservation and
replacement copying stay inside the owner that already holds the map lifecycle.
That pair is not a free-arena scan, a later reservation, a pthread runtime
route, or a public allocator call.

### Previous checkpoint — explicit regular OS one-arena reservation

This checkpoint is complete. `ProcessSharedArenaStorage::reserve_one_os_arena`
ports the bounded regular-map portion of `src/arena.c:1885-1912`
(`mi_reserve_os_memory_ex2`) over the existing process PageMap/arena pair. A
caller selects only a nonzero request that rounds to exactly one complete
arena and whether that regular mapping starts reserved or committed. The
boundary rejects a trailing unmanaged tail, a second reservation, or a foreign
process pair before mapping; it does not choose automatic reservation policy,
large pages, exclusive/NUMA policy, multiple sub-arenas, allocation routing,
or shutdown.

`arena::manage_os_in_place` records the resulting parent arena as
`MemoryKind::Os`, distinct from the existing caller-supplied external-map
entry. A pre-publication metadata failure unmaps the exact new mapping before
the sidecar returns to COLD and permits the same pair to retry. If that unmap
fails, the sidecar retains the exact mapping and becomes terminal rather than
allowing a second reservation to obscure its ownership. The static
`MainStaticProcessPageAllocator` regression proves that a reserved OS arena
can commit metadata, publish one page, and complete its normal page-map,
bitmap, metadata, and slice-release lifecycle.

Native Linux/AArch64 focused reservation tests and the complete
`crabc-mimalloc` library suite passed (578 tests). The allocator ledger and
ratchet must remain synchronized with this checkpoint. The next slice should
remain a separately source-shaped owner or lifecycle boundary; do not broaden
this explicit reservation entry into automatic routing or a registry scan.

### Previous checkpoint — heterogeneous full arena-large aggregate route

This checkpoint is complete. The dynamic
`DynamicThreadExitDrain::abandon_full_large_pages` and later-main
`MainHeapThreadProcessPageExitDrain::abandon_full_large_pages_to_process_route`
now accept two or more full `MemoryKind::Arena` `PageKind::Large` members in
`BIN_FULL` with independently validated rounded block sizes and regular bins.
Every member still proves `reserved > 1`, `used == reserved`, zero retirement,
an empty local free list, its matching arena bitmap/count capability, and its
exact 64-slice arena/PageMap span; every other queue and direct slot remains
empty. Mixed page classes, OS pages, sole pages, malformed spans, allocation
routing, adoption, reclaim/requeue, scans, producers, and concurrent frees
remain outside the route.

Both routes retain no raw page list. A sequential client free re-resolves the
exact PageMap member, claims its source low owner bit, then selects that
member's bitmap/count capability and unmapped or mapped full-large tail. The
terminal path releases only that complete member span through PageMap -> arena
bit -> metadata -> arena slices. The paired dynamic and later-main regressions
use distinct large bins and independently cross each member's mostly-used
threshold before one-at-a-time 64-slice release.

### Previous checkpoint — heterogeneous full OS-singleton aggregate route

This checkpoint removes the artificial cross-member rounded-size seal from
the dynamic `DynamicThreadExitDrain::abandon_full_os_singleton_pages` and
later-main
`MainHeapThreadProcessPageExitDrain::abandon_full_os_singleton_pages_to_process_route`
routes. Each complete `BIN_FULL` source image still contains two or more full
`MemoryKind::Os` singletons, zero retirement countdown, empty local free
lists, no direct or other queue members, valid clipped PageMap/alias release
images, and an initially empty private OS list. Each member now independently
proves `reserved == used == 1` and carries its own rounded block size and
clipped mapping geometry.

The source order remains force -> false collection -> full-queue/page-count
detach -> private OS-list insertion -> unmapped unown. The routes retain only
their drain/process facts and a member count, not a raw registry or common
size. Every sequential canonical free re-resolves its PageMap member, takes
only the raw empty failed-reclaim tail, removes that exact list member, and
releases that member's clipped PageMap -> aliases -> metadata -> mapping
image. The paired dynamic and later-main regressions use distinct 4 KiB and
larger rounded members, releasing each mapping independently. Sole,
arena-backed, non-singleton, preexisting-list, allocation-time,
reclaim/adoption/requeue, scanning, producer, concurrent-free, huge, and
general owner-exit cases remain outside this boundary.

### Previous checkpoint — heterogeneous full non-direct-small aggregate route

This checkpoint removes the artificial cross-member ordinary-bin and rounded
size seal from the full non-direct-small aggregate routes. The dynamic
`DynamicThreadExitDrain::abandon_full_non_direct_small_pages` and later-main
`MainHeapThreadProcessPageExitDrain::abandon_full_non_direct_small_pages_to_process_route`
now accept two or more full `MemoryKind::Arena` `PageKind::Small` members
across ordinary bins. Each member still proves
`SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE`, `reserved > 1`,
`used == reserved`, `!page_is_in_full`, zero retirement, an empty local free
list, its exact bitmap/count capability, and one exact arena/PageMap slice.
Every direct entry and `BIN_FULL` remain empty; no other page class may occupy
a populated ordinary bin.

The source order remains force -> false collection -> ordinary-bin removal
with the no-op non-direct cache update -> page-count detach -> unmapped
abandonment. Routes retain only their dynamic drain or process facts plus a
member count. A sequential canonical free re-resolves its PageMap member,
claims the low owner bit, then derives only that member's rounded bin and
bitmap/count capability for the normal unmapped or mapped failed-reclaim tail.
Terminal release removes one exact PageMap -> arena bit -> metadata ->
one-slice member at a time. The paired dynamic and later-main regressions use
two distinct ordinary bins, independently cross each mostly-used threshold,
and release each member independently. Direct-small partial collection, sole
pages, `BIN_FULL`, mixed classes, remote-force nonfull state, allocation-time
reclaim/adoption/requeue, scanning, producers, concurrent frees, and general
owner exit remain outside the boundary.

### Previous checkpoint — heterogeneous full direct-small aggregate route

This checkpoint removes the artificial cross-member ordinary-bin and rounded
size seal from the full direct-small aggregate routes. The dynamic
`DynamicThreadExitDrain::abandon_full_direct_small_pages` and later-main
`MainHeapThreadProcessPageExitDrain::abandon_full_direct_small_pages_to_process_route`
now accept two or more full `MemoryKind::Arena` `PageKind::Small` members
across ordinary bins. Each member still proves `block_size <= SMALL_SIZE_MAX`,
`reserved >= 16`, `used == reserved`, `!page_is_in_full`, zero retirement, an
empty local free list, its exact bitmap/count capability, one exact
arena/PageMap slice, and its rounded direct-cache range; complete preflight
also proves the source-derived cache image names every populated queue head.

The source order remains force -> false collection -> bin-order ordinary-bin
removal with each rounded cache refresh before page-count detach -> unmapped
abandonment. Routes retain only their dynamic drain or process facts plus a
member count. A sequential canonical free re-resolves its PageMap member,
claims the low owner bit, then derives only that member's rounded bin and
bitmap/count capability for the partial-collector unmapped or mapped failed-
reclaim tail. The partial collector keeps the just-pushed head for its one-free
accounting lag. Terminal release removes one exact PageMap -> arena bit ->
metadata -> one-slice member at a time. The paired dynamic and later-main
regressions use two distinct ordinary bins, independently cross each
partial-head/mostly-used threshold, and release each member independently.
Sole pages, stale or mixed cache images, `BIN_FULL`, mixed classes,
remote-force nonfull state, allocation-time reclaim/adoption/requeue, scanning,
producers, concurrent frees, and general owner exit remain outside the
boundary.

The paired distinct-bin regressions pass in the native Linux/AArch64
container, together with the complete `crabc-mimalloc` library suite (578
tests), all five `remote_free` Loom schedules, and the allocator quick runner.
The completed mapping remains ratcheted at 128 items and 132
implemented/unit-verified statuses.

### Previous checkpoint — private no-page process/pthread runtime lifecycle

This checkpoint is complete on top of the bounded owners below. The hidden
Rust-only `crabc_mimalloc::__crabc_runtime` boundary retains the ticket-zero
`ProcessMainThread` and its main-thread-minted `MainStaticHeapLease` after
initial TLS/guard setup and before constructors. `libc/src/c_abi.rs` attaches a
real pthread child before its start routine, waits in the parent for an
attachment result, and returns `EAGAIN` without user-code execution if the
no-page owner cannot attach. Normal return, `pthread_exit`, and cancellation
finish only after libc cleanup/TSD destructors. The main owner is retained at
normal exit. On libc's direct `fork` path, after public prepare handlers and
before the raw syscall, an allocation-free gate freezes later bridge
attachment. A child preserves the copied no-page process owner only when the
original ticket-zero `TPIDR_EL0` image forked with zero live or retained later
bridge owners; it resets that copied gate and may attach a fresh pthread. Any
other child—including an unprepared raw-fork child—disables the bridge. No
lock, root, page, or general fork repair is attempted. This is not allocation routing: the C
`libmimalloc-sys` backend remains active, no C symbol or public pthread key is
added, its existing private key stays outside the 128-key application capacity,
and no page-bearing session enters through this bridge.

The production TLS contract is target-wide initial-exec in both
`.cargo/config.toml` and the sealed sysroot builder. The static archive audit
binds the post-LTO named `THREAD_LIFECYCLE` root to its exact TLSIE relocation
pair; the installed final shared `libc.so` must use TPREL and rejects TLSDESC
and `__tls_get_addr`. `crabc-mimalloc/tests/runtime_lifecycle.rs` supplies the
direct overlapping/churn lifecycle regression plus two process-isolated
quiescent-child cycles that each create and finish a fresh pthread; it also
proves that a child copied from a live bridge owner is conservatively inactive.
The dynamic and static C pthread/TSD fixtures provide the installed-runtime
boundary evidence. The next lifecycle frontier is page-bearing ownership or
general fork repair for live/retained owners, never a broad callback or
premature backend routing.

### Previous checkpoint — later-main full OS-singleton aggregate post-exit route

This checkpoint adds one separately typed, later-main aggregate over exactly
two or more `MemoryKind::Os` singleton pages in `BIN_FULL`, each with its own
rounded block size. It requires `reserved == used == 1`, zero retirement, empty local free lists,
an otherwise empty direct/queue image, valid clipped PageMap/alias release
images, and an initially empty static-main `Heap::os_abandoned_pages` list.
For every member it preserves source force -> false collection -> full-queue
and page-count detach -> private OS-list insertion -> unmapped unown before
old-Theap/TLD teardown. Full-queue removal clears the full-queue flag, but the
private list deliberately reuses the page's intrusive links; raw link
detachment therefore happens only when the later client free removes that
exact list member. Each sequential free re-resolves current PageMap membership
and takes only the raw empty failed-reclaim tail, then removes the list member
before clipped PageMap -> aliases -> metadata -> mapping release. A failed
`munmap` retains one terminal `OsAlignedPageOwner`; this slice supplies no
list traversal, retry, reclamation, requeue, allocation-time, or concurrent
routing policy.

### Previous checkpoint — heterogeneous full arena-singleton aggregate route

This checkpoint removes the artificial cross-member rounded-size seal from
the existing full arena-singleton owner-exit routes. The dynamic
`DynamicThreadExitDrain::abandon_full_singleton_pages` and later-main
`MainHeapThreadProcessPageExitDrain::abandon_full_singleton_pages_to_process_route`
now accept two or more full `MemoryKind::Arena` `PageKind::Singleton` members
in `BIN_FULL` with independently validated rounded sizes. Every member still
must have `reserved == used == 1`, zero retirement, an empty local free list,
its exact arena span, and the complete otherwise-empty direct/queue image.
They preserve the pinned source force -> false collection -> queue/count detach
-> unmapped abandonment order for every member, then retain no raw member list
or general aggregate registry.

Each later client free re-resolves and validates only its selected PageMap
member, deriving its singleton slice count and usable offset from that page's
current block size before the raw empty failed-reclaim tail releases the exact
PageMap -> arena bit -> metadata -> arena span. Mixed arena/OS classes,
non-singletons, sole pages, scanning, adoption, reclamation/requeue,
allocation-time, producer, and concurrent routing remain absent. The dynamic
and later-main mixed-size regressions prove independent sequential terminal
release alongside the existing same-size, sole-page, and collection-failure
boundaries.
## Scope amendment — 2026-08-25

The user has explicitly reopened a native Linux/x86-64 little-endian
`crabc-mimalloc` parity lane. This amendment changes only the fixed
allocator's validation target. The public `crabc` runtime and production
allocator integration remain Linux/AArch64; x86 work is private evidence only,
must run on native x86-64 Linux, must not use AArch64 emulation, and must not
introduce a generic portability layer or claim public x86 support/default
promotion. The AArch64-only production statements below remain authoritative
for that production profile; new x86 work must use architecture-qualified
contracts, reports, and status.

### Remaining native x86-64 allocator-parity work

- [ ] Resolve the target-local source API/mode/test/symbol coverage ledger's
  remaining mode-dependent forms, unselected C/C++ inline/override forms,
  upstream-test coverage, behavior, and Rust implementation statuses into
  reviewed outcomes. The fixed native CMake normal-release shared
  configure/build/install profile is covered, but it must not be generalized
  into behavior, public-runtime, consumer-execution, or unselected-mode
  evidence, and AArch64 statuses must not be reused.
- [ ] Close the source-applicable engine behavior holes identified by the x86
  source map and ledger, record every intentional difference, and add native
  pinned-C differential evidence for each completed behavior.
- [ ] Extend native lifecycle and concurrency coverage into process
  initialization/done, general remote-free or concurrent collection,
  abandonment/adoption, pthread/TLS/fork, fault and misuse isolation, remaining
  upstream tests, and stress evidence. Do not generalize any bounded lane into
  a broader lifecycle, routing, runtime, backend, or architecture claim without
  new native evidence.
- [ ] Broaden the bounded private-adapter C/Rust timing and post-init memory
  measurements into qualified whole-engine performance evidence.

Public x86 `crabc` support, x86 libc/ldso/`crabc-rs` integration, public
allocator exports, and default-backend promotion remain explicitly excluded;
they are not x86 parity backlog items.

## Handoff — 2026-08-25

The paired mixed-size regressions pass in the native Linux/AArch64 container,
together with the complete `crabc-mimalloc` library suite, the remote-free
Loom schedules, and the allocator quick runner.

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
`MemoryKind::Os`, `reserved == used == 1`, semantically-full `BIN_HUGE` singleton whose ordinary
block size may be small: after huge-queue/page-count detach it links the exact
page into the dynamic Heap's `os_abandoned_pages` list, then unmapped-abandons
it. Its exact final client free removes that list member before clipped PageMap
unregister, secondary-alias clear, primary-metadata retirement, and mapping
reclaim; a failed `munmap` retains the unique mapping owner terminally. The
source force-only local-list append is unreachable for either
`reserved == used == 1`, no-producer singleton, and a successful drain still
completes the separate cached-root/list/key teardown. This neither scans,
reclaims, requeues, nor generalizes the OS list, and is not general production
free routing or a general thread-exit traversal.

`DynamicThreadExitDrain::abandon_full_singleton_pages` now captures one
separate post-TLS `MI_ABANDON` aggregate: two or more full
`MemoryKind::Arena` `PageKind::Singleton` members in `BIN_FULL`, each with
its own rounded block size, `reserved == used == 1`, zero retirement countdown,
an empty local free list, exact arena span, and no other queue/direct state. It
force- then false-collects, full-queue/page-count detaches, and
unmapped-abandons every member before any client free. The returned
`DynamicThreadExitFullSingletonPagesRoute` retains the existing dynamic drain,
not a raw member list or a bitmap/count pair. Each sequential canonical free
re-resolves and validates its PageMap member, takes only the raw empty
failed-reclaim result, and releases exactly one PageMap -> dynamic ordinary-bit
-> metadata -> arena-slice span; the final member returns the empty drain for
its existing teardown. Sole, non-singleton, OS-backed, preexisting queue/direct,
allocation-time, reclaim/adoption/requeue, scan, and concurrent cases reject
before detach, while a collection failure retains the drain.

`DynamicThreadExitDrain::abandon_full_os_singleton_pages` now captures a
separate bounded post-TLS `MI_ABANDON` aggregate: two or more full
`MemoryKind::Os` singleton members in `BIN_FULL`, each with its own rounded
block size,
`reserved == used == 1`, zero retirement countdown, empty local free lists,
valid clipped PageMap/alias release images, an initially empty dynamic
`Heap::os_abandoned_pages` list, and no other queue/direct state. It preserves
source force -> false collection -> full-queue/page-count detach -> private
OS-list insertion -> unmapped unown for every member. The returned
`DynamicThreadExitFullOsSingletonPagesRoute` retains only the dynamic drain
and member count—not a raw member list or a dynamic
bitmap/count pair. Each sequential canonical free re-resolves PageMap, takes
only the raw empty failed-reclaim result, removes its exact private-list member,
then releases one clipped PageMap -> alias -> primary-metadata -> mapping
image; the final member returns the empty drain for existing teardown. Sole,
arena-backed, non-singleton, preexisting-list, allocation-time,
reclaim/adoption/requeue, scan, producer, concurrent, huge, and general
owner-exit cases reject before detach; collection, list, or mapping-release
failure retains the only owner terminally.

`DynamicThreadExitDrain::abandon_full_medium_pages` now captures a third
separate post-TLS `MI_ABANDON` aggregate: two or more full
`MemoryKind::Arena` `PageKind::Medium` members in `BIN_FULL`, each with its
own rounded block size and regular bin, `reserved > 1`, `used == reserved`,
zero retirement countdown, empty local free list, exact arena span, and a
matching dynamic bitmap/count capability. No other queue/direct state is
admitted. It force- then false-collects, full-queue/page-count detaches, and
unmapped-abandons every member before any client free. The returned
`DynamicThreadExitFullMediumPagesRoute` retains the existing dynamic drain, not
raw member pointers or per-member mapped state. Each sequential canonical free
re-resolves PageMap, claims its member's low owner bit, then selects that
member's exact dynamic bitmap/count capability and its unmapped or mapped
full-medium failed-reclaim tail. It releases exactly one PageMap -> dynamic
ordinary-bit -> metadata -> arena-slice span; the final member returns the
empty drain for existing teardown. Sole, mixed-class, non-medium, OS-backed,
preexisting queue/direct, allocation-time,
reclaim/adoption/requeue, scan, producer, and concurrent cases reject before
detach, while a collection failure retains the drain.

`DynamicThreadExitDrain::abandon_full_large_pages` now captures a fourth
separate post-TLS `MI_ABANDON` aggregate: two or more full
`MemoryKind::Arena` `PageKind::Large` members in `BIN_FULL`, each with its own
rounded block size and regular bin, `reserved > 1`, `used == reserved`, zero
retirement countdowns, empty local free lists, the matching dynamic bitmap/count
capability for every member, no other queue/direct state, and every member's exact
64-slice arena/PageMap span. It force- then false-collects,
full-queue/page-count detaches, and unmapped-abandons every member before any
client free. The returned `DynamicThreadExitFullLargePagesRoute` retains the
existing dynamic drain, not raw member pointers or per-member mapped state.
Each sequential canonical free re-resolves PageMap, claims its member's low
owner bit, then selects its exact dynamic bitmap/count capability and unmapped
or mapped full-large failed-reclaim tail, and releases exactly one PageMap -> dynamic ordinary-bit -> metadata ->
complete 64-slice arena span; the final member returns the empty drain for
existing teardown. Sole, mixed-class, non-large, OS-backed,
malformed-span, preexisting queue/direct, allocation-time,
reclaim/adoption/requeue, scan, producer, and concurrent cases reject before
detach, while a collection failure retains the drain.

`DynamicThreadExitDrain::abandon_full_non_direct_small_pages` now captures a
fifth separate post-TLS `MI_ABANDON` aggregate: two or more full
`MemoryKind::Arena` `PageKind::Small` members across ordinary source bins, each
with its own rounded `SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE`, `reserved > 1`,
`used == reserved`, zero retirement countdowns, empty local free lists, exact
one-slice arena/PageMap spans, the matching dynamic bitmap/count capability for
every member, every direct entry empty, and no other queue state. This exact
ordinary source shape requires `allow_page_abandon=true` and
`page_full_retain=2`, so its test-only fixture validates that normal dynamic
image while production ordinary attachments continue to reject a general page
session. It force- then false-collects, ordinary-bin/page-count detaches, and
unmapped-abandons every member. The returned
`DynamicThreadExitFullNonDirectSmallPagesRoute` retains the dynamic drain, not
raw member pointers or per-member mapped state. Each sequential canonical free
re-resolves PageMap, uses its member's abandoned identity to select the normal
unmapped or mapped failed-reclaim tail, and releases exactly one PageMap ->
dynamic ordinary-bit -> metadata -> arena-slice span; the final member returns
the empty drain for existing teardown. Sole, mixed-bin/class, direct-small,
`BIN_FULL`, OS-backed, allocation-time, reclaim/adoption/requeue, scan,
producer, and concurrent cases reject before detach, while a collection failure
retains the drain. This proves the source aggregate without exposing ordinary
dynamic allocation or a general thread-exit traversal.

`DynamicThreadExitDrain::abandon_full_direct_small_pages` now captures a sixth
separate post-TLS `MI_ABANDON` aggregate, also proved only through that exact
ordinary source fixture: two or more full `MemoryKind::Arena` `PageKind::Small`
members across ordinary source bins, each with its own rounded
`block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, `used == reserved`, zero
retirement countdown, empty local free list, exact one-slice arena/PageMap
span, matching dynamic bitmap/count capability, and rounded direct-cache
range. Complete preflight requires the source-derived cache image to name every
populated ordinary queue head. It force- then false-collects, removes members
in bin order, refreshes each direct range before its page-count detach, and
unmapped-abandons every member. The
returned `DynamicThreadExitFullDirectSmallPagesRoute` retains the dynamic
drain, not raw member pointers, a raw direct-cache image, or per-member mapped
state. Each sequential canonical free re-resolves PageMap, claims its member's
low owner bit, derives its exact dynamic bitmap/count capability, selects the
partial-collector unmapped or mapped failed-reclaim tail, preserves the just-
pushed expected head through the source accounting lag, and releases exactly
one PageMap -> dynamic ordinary bit -> metadata -> arena-slice span; the final
member returns the empty drain for existing teardown. A member stays unmapped
through `reserved / 8 + 1` frees; only the next may publish its matching
dynamic bitmap/count pair. Sole, stale/mixed direct-cache, mixed class,
non-direct-small, `BIN_FULL`,
OS-backed, allocation-time, reclaim/adoption/requeue, scan, producer,
concurrent, and joined-remote nonfull cases reject before detach, while a
collection failure retains the drain. This proves the source partial-head
aggregate without exposing ordinary dynamic allocation or a general
thread-exit traversal.

The same post-TLS drain now has four separate mapped regular endpoints.
`DynamicThreadExitDrain::abandon_mapped_one_block` accepts exactly one sole,
nonfull `MemoryKind::Arena` medium page; its large sibling
`DynamicThreadExitDrain::abandon_mapped_one_block_large` accepts only a
`PageKind::Large` page and retains its complete 64-slice span; its
`abandon_mapped_one_block_non_direct_small` sibling accepts only a small page
with `SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE`; and
`DynamicThreadExitDrain::abandon_mapped_one_block_direct_small` accepts a
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
source-class witness and admits only its exact final client free: medium,
large, and non-direct small use the normal collector, while direct small
consumes its partial collector head; each must become empty before any reclaim
branch, clear that dynamic bit/count pair, then release PageMap -> dynamic
ordinary bit -> metadata -> arena slices. The large route validates the full
64-slice PageMap span before that terminal release. It cannot reclaim the
departed Theap, requeue, adopt, scan, accept a second free, or generalize
dynamic owner exit.

`DynamicThreadExitDrain::abandon_mapped_two_block_medium` is a separate,
source-shaped post-TLS dynamic handoff. It admits only one sole nonfull
`MemoryKind::Arena` `PageKind::Medium` page with `block_size >
SMALL_SIZE_MAX`, `reserved > 2`, `used == 2`, zero retirement countdown, one
regular queue member, an empty direct-cache image, and no other queue/direct
entry. It preserves force -> false collection -> regular-queue removal ->
page-count decrement -> non-direct no-op cache update -> mapped
identity/bit/count/unown. Its private token stores no client pointer or list:
the first exact canonical client free must return `UnownedMapped` and keep the
dynamic bit/count with one block live; the final free alone may return `Empty`,
clear that pair, and release PageMap -> dynamic ordinary bit -> metadata ->
arena slices. One or three live blocks, another page, any other source class,
reclaim/adoption/requeue/scanning, producers, concurrency, and general owner
exit remain excluded.

`DynamicThreadExitDrain::abandon_mapped_medium_pair` is a separate bounded
post-TLS aggregate, not a generalized multi-page route. It admits exactly two
nonfull `MemoryKind::Arena` `PageKind::Medium` pages in distinct regular bins:
one sole member with `reserved > 2`, `used == 2`, and one sole member with
`reserved > 1`, `used == 1`; every direct entry and every other queue must be
empty. Complete preflight proves both arena spans, dynamic bitmap/count
capabilities, and the total three live blocks before source bin-order force ->
false collection -> queue removal -> page-count decrement -> non-direct no-op
cache update -> mapped identity/bit/count/unown. Its
`DynamicThreadExitMappedMediumPairRoute` stores only the drain and sealed
remaining page/free counts. Every exact client free re-resolves its PageMap
member and claims its low owner bit before selecting that member's dynamic map:
`UnownedMapped` retains the route, while `Empty` clears and releases only that
member, returning the empty drain only after the final release. It retains no
raw member pointer, bin/map cache, or client list and adds no scan,
reclaim/adoption/requeue, allocation-time, producer, concurrent, or general
owner-exit authority.

`DynamicThreadExitDrain::abandon_full_medium` is a separate disjoint dynamic
owner-exit endpoint. It accepts only a sole full `MemoryKind::Arena` medium
page in `BIN_FULL`, with `reserved > 1`, `used == reserved`, and no direct
cache entry. Its typed Rust model uses source-mapped force then false collection
before full-queue/page-count detach and ordinary unmapped abandonment. Its
`DynamicThreadExitFullMediumHandoff` carries sequential client frees through
the failed-reclaim tail: they remain unmapped while the source mostly-used
predicate holds, then the first free beyond `reserved / 8` publishes the exact
dynamic `pages_abandoned[bin]` bit plus paired `Heap::abandoned_count[bin]`.
The mapped tail clears that pair before PageMap -> dynamic ordinary bit ->
metadata -> arena-slice release. It cannot reclaim, adopt, requeue, scan, or
cover full large/non-direct-small/direct-small, multi-page, or general dynamic
thread-exit state.

The private native x86-64 differential for this endpoint records one exact
no-remote medium route: request 10248, 12288-byte blocks, capacity/reserved
42, and eight slices. Real `mi_thread_done()` plus join leaves the full page
unmapped at `used == 42` with dynamic bitmap/count clear; five normal-collector
frees leave `used == 37`, and the sixth crosses `reserved / 8 == 5` to map at
`used == 36` with bitmap/count one. The mapped tail proves the selected
PageMap, ordinary-arena-bit, dynamic bitmap/count, and complete eight-slice
release only. It remains private x86 evidence, not general lifecycle/routing,
public runtime, public x86 support, backend promotion, or AArch64 evidence.

The matching private native x86-64 differential now fixes the selected
no-remote dynamic full-large route at 34 address-independent values. Request
86706 yields 98304-byte blocks with capacity/reserved 42 and a 64-slice arena
span; only 63 source page-area slices are PageMap-registered, while the final
PageMap-null slice is slack but remains part of terminal release. In the pinned
C oracle, real `mi_thread_done()` and join precede five normal-collector frees
that leave the page unmapped at `used == 37` with dynamic bitmap/count zero, then a sixth free
maps it at `used == 36` with dynamic bitmap/count one. The mapped tail clears
PageMap, the ordinary arena bit, and dynamic bitmap/count before complete
64-slice release. Rust independently exercises the typed owner-exit route on
its owning test thread and does not claim a literal worker-thread/join
counterpart. This remains private x86 evidence only, not general
lifecycle/routing/concurrency, public runtime, public x86 support, backend
promotion, or AArch64 evidence.

`DynamicThreadExitDrain::abandon_full_large` is a separate disjoint dynamic
owner-exit endpoint. It accepts only a sole full `MemoryKind::Arena` large
page in `BIN_FULL`, with `reserved > 1`, `used == reserved`, and no direct
cache entry. Source force then false collection precedes full-queue/page-count
detach and ordinary unmapped abandonment. Its
`DynamicThreadExitFullLargeHandoff` carries sequential normal failed-reclaim
frees through the same tail: they remain unmapped while the source mostly-used
predicate holds, then the first free beyond `reserved / 8` publishes the exact
dynamic `pages_abandoned[bin]` bit plus paired `Heap::abandoned_count[bin]`.
The mapped tail clears that pair before PageMap -> dynamic ordinary bit ->
metadata -> complete 64-slice arena release. It cannot reclaim, adopt,
requeue, scan, or cover full medium/non-direct-small/direct-small, multi-page,
or general dynamic thread-exit state.

`DynamicThreadExitDrain::abandon_full_medium_after_force_collect_to_mapped`
now captures the separate dynamic full-medium source branch with exactly one
joined remote free. Force collection changes the still-linked, still-full sole
`BIN_FULL` member to `used == reserved - 1`; false collection preserves it;
full-queue/page-count detachment clears the full flag; then mapped abandonment
immediately publishes the exact heap-local bitmap/count pair. The returned
`DynamicThreadExitFullMediumHandoff` starts mapped and accepts only sequential
failed-reclaim client frees, clearing the pair before the ordinary arena
release. This does not broaden the normal unmapped full-medium endpoint to
multiple frees, other page classes, reclaim, adoption, requeue, scanning, or a
general dynamic owner-exit traversal.

`DynamicThreadExitDrain::abandon_full_large_after_force_collect_to_mapped`
captures the corresponding dynamic full-large branch with the same one-remote
force/false/detach/mapped sequence. Its returned
`DynamicThreadExitFullLargeHandoff` retains the complete 64-slice terminal
release. Neither branch broadens normal full-page abandonment or general
dynamic owner-exit traversal.

`DynamicThreadExitDrain::abandon_full_non_direct_small` is a sixth, disjoint
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

The matching private native x86-64 differential fixes this no-remote,
source-unmapped route at 35 address-independent values: one sole full
ordinary-bin page with a 1032-byte request, 1280-byte blocks,
capacity/reserved 51, one slice, and an empty direct-cache image. The worker
runs real `mi_thread_done()` without a remote free, and the consumer joins
before its frees. It records the initial unmapped abandoned PageMap/ordinary
bit state at `used == 51`, six unmapped frees at `used == 45`, then the seventh
free's mapped bitmap/count publication at `used == 44`, before terminal
one-slice release. It is private x86 evidence only, not a broader lifecycle,
routing, concurrent collection, public runtime, or AArch64 claim.

`DynamicThreadExitDrain::abandon_full_non_direct_small_after_force_collect_to_mapped`
captures the separate dynamic full non-direct-small branch with exactly one
joined remote free. Force collection changes the still-linked sole ordinary-bin
member to `used == reserved - 1`; false collection preserves it;
regular-bin/page-count detachment leaves the page nonfull; then mapped
abandonment immediately publishes the exact heap-local bitmap/count pair. The
returned `DynamicThreadExitFullNonDirectSmallHandoff` starts mapped and accepts
only sequential failed-reclaim client frees, clearing the pair before the
ordinary arena release. The source direct-cache update is a no-op because the
class requires an empty direct image above `SMALL_SIZE_MAX`. This does not
broaden normal unmapped full non-direct-small abandonment to multiple frees,
direct-small or other page classes, reclaim, adoption, requeue, scanning, or a
general dynamic owner-exit traversal.

The matching private native x86-64 differential fixes this source-shaped
non-direct-small predecessor at 30 address-independent values: one sole full
ordinary-bin page with a 1032-byte request, 1280-byte blocks,
capacity/reserved 51, one slice, and an empty direct-cache image. The
consumer/main thread publishes the one joined remote free before the worker's
real `mi_thread_done()`; the consumer then joins before its frees. Force
collection records `used == 50`, mapped bitmap/count state, and the normal
first sequential failed-reclaim free's
`used + 2 == reserved` geometry before the one-slice terminal release. It is
private x86 evidence only, not a broader lifecycle, routing, concurrent, public
runtime, or AArch64 claim.

`DynamicThreadExitDrain::abandon_full_direct_small_after_force_collect_to_mapped`
captures the separate dynamic full direct-small branch with exactly one joined
remote free. Force collection changes the still-linked sole ordinary-bin member
to `used == reserved - 1`; false collection preserves it; regular-bin removal
clears the complete rounded direct-cache range before page-count detach; then
mapped abandonment immediately publishes the exact heap-local bitmap/count
pair. The returned `DynamicThreadExitFullDirectSmallHandoff` starts mapped and
accepts only sequential failed-reclaim client frees through the source partial
collector, clearing the pair before the ordinary one-slice arena release. This
does not broaden normal unmapped full direct-small abandonment to multiple
frees, non-direct-small or other page classes, reclaim, adoption, requeue,
scanning, or a general dynamic owner-exit traversal.

The matching private native x86-64 differential fixes this no-remote,
source-unmapped direct-small route at 38 address-independent values: one sole
full ordinary-bin page with a 1024-byte request/block size, capacity/reserved
64, one slice, and exact rounded direct-cache range `[113, 128]`. The worker
runs real `mi_thread_done()` without a remote free, and the consumer joins
before its frees. Force then false collection clears that range before
page-count detach and records unmapped abandonment with PageMap/ordinary bit
retained, dynamic bitmap/count clear, and `used == 64`. The first
partial-collector consumer free also retains `used == 64`; nine such frees
leave `used == 56`, then the tenth partial collector takes `used` to 55 before
generic unown consumes the retained current head and maps it at `used == 54`
with bitmap/count publication before terminal one-slice release. It is private x86 evidence
only, not a broader lifecycle, routing, concurrent collection, public runtime,
or AArch64 claim.

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
owner, producer lifetime, general abandonment traversal, page-bearing
pthread/TLS callback, or public backend integration. The completed private
libc bridge invokes only this exact no-page entry/finish boundary. Its separate
`MainHeapThreadPageDrainSession`
is reachable only through the paired page owner below after it clears the fixed
fast slot; it retains the metadata/list/TLD state until all-free release has
completed or a terminal owner is retained.

The first process-global page-map owner is now also present and has one
separate, deliberately lower-level shared-arena sidecar.
`process_page_map.rs` source-maps `mi_page_map_init_once` /
`_mi_page_map_init`, freezes one `MemoryConfig` and `MainSubprocess`, constructs
a `PageMap` in its final process-static slot, and Release-publishes a stable
root exactly once. `process_arena.rs` retains the caller-selected
`mi_manage_os_memory_ex2` edge for one complete external mapping and adds one
explicit regular `mi_reserve_os_memory_ex2` entry. Its separate
`reserve_default_os_arena` policy ports the first lazy `mi_arena_reserve`
choice—source max-page headroom, a 1-GiB default, Linux overcommit eager-map
selection, and a 128-MiB retry. `MainStaticFirstArenaPageAllocator` now calls
it only after its ticket-zero empty Theap has a valid first ordinary fresh-page
miss; it then activates the existing bounded static page engine over that
one arena. It does not run at process startup or choose a later arena.
It binds an `ArenaRegistry`
to that exact root/configuration/main identity before in-place publication.
The regular entry accepts only one complete slice-rounded arena and normal
reserved or committed mapping access, records `MemoryKind::Os`, and unmaps an
unpublished metadata failure before making the sidecar cold for a matching
retry; a failed unmap retains the map terminally. A reserved mapping first
moves into the sidecar's final slot, whose stable callback commits source
metadata and later selected arena ranges through that same `Mapping`; its
frozen Linux decommit reports that reuse needs no recommit. Later automatic
arena scaling, option mutation, large-page/exclusive/NUMA policy,
page-on-demand policy, and `slice_pcommitted` remain absent. Its paired lease now has one
narrow, range-checked direct page-area commit operation for the already-
selected `mi_page_extend_free` transition; the page lifecycle, not the
sidecar, owns the resulting count publication and failed-commit
`_mi_page_abandon` tail.
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
handoff accepts one sole semantically-full OS-aligned singleton in `BIN_HUGE`, not `BIN_FULL`, even when its
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

`MainHeapThreadProcessPageExitDrain::abandon_full_singleton_pages_to_process_route`
is a separately typed bounded aggregate route for two or more full arena
`PageKind::Singleton` members in `BIN_FULL`. Complete preflight requires every
direct entry and every other queue empty; every member has its own rounded
singleton block size, `reserved == used == 1`, zero retirement countdown, an
empty local free list, and an exact selected-arena span. It preserves source
force -> false collection -> full-queue/page-count detach -> unmappable
abandonment for every member before old-Theap/TLD teardown. The linear route
retains only sealed arena/count facts: every canonical client free re-resolves
and validates its PageMap membership before it takes the raw empty
failed-reclaim tail. Its terminal order is complete PageMap span -> ordinary
`pages_main` first-slice bit -> metadata -> arena slices, and the final member
closes the map route. Sole pages, non-singletons, OS-backed members,
allocation-time adoption/reclaim/requeue, scanning, and concurrent routing
remain absent; injected collection failure retains the complete drain after
preflight rather than partially detaching a member.

Separately,
`MainHeapThreadProcessPageExitDrain::abandon_full_os_singleton_pages_to_process_route`
is a bounded aggregate for two or more `MemoryKind::Os` singleton members in
`BIN_FULL`, each with its own rounded block size. Complete preflight requires
`reserved == used == 1`, zero retirement countdowns, empty local free lists, valid clipped
PageMap/alias release images, every direct slot and other queue empty, and an
initially empty static-main `Heap::os_abandoned_pages` list. It preserves source
force -> false collection -> full-queue/page-count detach -> private OS-list
insertion -> unmapped unown for every member before old-Theap/TLD teardown.
Full-queue removal clears `PAGE_IN_FULL_QUEUE`, but the private list
intentionally reuses the page's raw intrusive links; an exact later free
removes its list member before clipped PageMap -> aliases -> metadata ->
mapping release. The route retains no separate raw member list: each canonical
singleton free re-resolves PageMap membership and must take the raw empty
failed-reclaim result. A sole page, non-OS member, nonempty initial private
list, list traversal, retry after failed `munmap`,
reclaim, requeue, allocation-time, and concurrent routing remain absent; an
injected collection failure retains the complete drain, and a mapping-release
failure retains the exact `OsAlignedPageOwner` terminally.

Separately,
`MainHeapThreadProcessPageExitDrain::abandon_full_medium_pages_to_process_route`
is one bounded aggregate full-page route. It accepts two or more full arena
medium members in `BIN_FULL` only when every direct slot and every other queue
is empty, each member has its own rounded block size/static-main bin, `reserved
> 1`, `used == reserved`, a zero retirement countdown, and one exact paired
arena span. It preserves source force -> false collection, full-queue/page-count
detach, and ordinary unmapped abandonment for every member before the old
Theap/TLD tears down. Its `MainHeapThreadProcessPageExitFullMediumPagesRoute`
retains no raw page list: a later sequential client free re-resolves its member
through short PageMap access, claims the low owner bit, then uses the resulting
abandoned identity to select that member's exact static-main bitmap/count
capability and source unmapped or mapped tail. The first below-mostly-used free
may independently publish that member's pair; terminal PageMap -> `pages_main`
-> metadata -> slice release removes only that member, and the last one closes
the map route. A sole full page rejects before mutation. Mixed-class queues,
small or large full pages, remote-force nonfull state, allocation-time
adoption/reclaim/requeue, scanning, and concurrent free routing remain absent.

`MainHeapThreadProcessPageExitDrain::abandon_full_large_pages_to_process_route`
is a parallel, separately typed bounded aggregate full-page route. It accepts
two or more full arena large members in `BIN_FULL` only when every direct slot
and every other queue is empty, each member has its own rounded block
size/static-main bin, `reserved > 1`, `used == reserved`, a zero retirement
countdown, and one exact 64-slice paired arena/PageMap span. It preserves
source force -> false collection, full-queue/page-count detach, and ordinary
unmapped abandonment for every member before the old Theap/TLD tears down. Its
`MainHeapThreadProcessPageExitFullLargePagesRoute` keeps no raw page list: a
later sequential client free re-resolves its member through short PageMap
access, claims the low owner bit, then selects that member's exact static-main
bitmap/count capability and source unmapped or mapped tail. The first
below-mostly-used free may independently publish that member's pair; terminal
PageMap -> `pages_main` -> metadata -> slice release proves and
removes only that member's complete 64-slice span, and the last one closes the
map route. A sole page or a mixed medium/large full queue rejects before
mutation. Allocation-time adoption/reclaim/requeue, scanning, remote-force
nonfull state, and concurrent free routing remain absent.

`MainHeapThreadProcessPageExitDrain::abandon_full_non_direct_small_pages_to_process_route`
is a fourth, separately typed bounded aggregate full-page route. It accepts two
or more full arena `PageKind::Small` members across ordinary source bins, each
with its own rounded `SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE` and
static-main bin, every direct slot and `BIN_FULL` empty, `reserved > 1`,
`used == reserved`, `!page_is_in_full`, a zero retirement countdown, an empty
local free list, and one exact paired-arena slice per member. It preserves
source force -> false collection, ordinary-bin removal with the proven no-op
direct-cache update, page-count detach, and ordinary unmapped abandonment for
every member before old-Theap/TLD teardown. Its
`MainHeapThreadProcessPageExitFullNonDirectSmallPagesRoute` stores no raw page
list: each later sequential client free re-resolves one PageMap member, claims
the low owner bit, then uses the sealed non-direct-small class and that
member's derived bin to choose free.c's normal unmapped or mapped tail and
exact static-main bitmap/count pair. The first below-mostly-used free may
independently publish that member's pair; terminal PageMap -> `pages_main` ->
metadata -> slice release removes only that one-slice member, and the last
member closes the map route. A sole page, direct-small geometry/cache image,
mixed class, or collection failure rejects or retains before a route can form.
Allocation-time adoption/reclaim/requeue, scanning, direct-small partial-head
semantics outside its own route, remote-force nonfull state, and concurrent
free routing remain absent.

`MainHeapThreadProcessPageExitDrain::abandon_full_direct_small_pages_to_process_route`
is a fifth, separately typed bounded aggregate full-page route. It accepts two
or more full arena `PageKind::Small` members across ordinary source bins, each
with its own rounded `block_size <= SMALL_SIZE_MAX` and static-main bin,
`reserved >= 16`, `used == reserved`, `!page_is_in_full`, a zero retirement
countdown, an empty local free list, and one exact paired-arena slice. Its
complete rounded `pages_free_direct` image must name every populated
ordinary-queue head. It preserves source force -> false collection, bin-order
ordinary-bin removal, direct-cache head advance before each page-count detach,
and ordinary unmapped abandonment for every member before old-Theap/TLD
teardown. Its
`MainHeapThreadProcessPageExitFullDirectSmallPagesRoute` stores no raw page
list: each later sequential client free re-resolves one PageMap member, claims
the low owner bit, and derives that member's static-main bitmap/count capability
to choose free.c's partial unmapped or mapped tail. The just-pushed head remains
the expected unown value through `reserved / 8 + 1` frees; the next free may
independently publish that member's exact bitmap/count pair. Terminal PageMap -> `pages_main` -> metadata ->
slice release removes only that one-slice member, and the last member closes
the map route. A sole page, stale/mixed cache image, non-direct geometry, mixed
bin/class, or collection failure rejects or retains before a route can form.
Allocation-time adoption/reclaim/requeue, scanning, remote-force nonfull state,
and concurrent free routing remain absent.

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
Five explicit consuming allocation-time edges are now complete for the sole
mapped nonfull medium form and its direct-small immediate-head,
exhausted-fully-committed scalar-extension, exhausted prefix-covered extension,
and exact on-demand page-area-commit counterparts:
`MainHeapThreadProcessPageExitMappedRegularRoute::adopt_into_later_main`
requires an exact matching fresh later-main attachment/process pair (same
subprocess, frozen configuration, stable PageMap root, static main Heap, and
arena) and re-proves the source span and page identity. It transfers the short
`ProcessPageMapPostExitAccess` into one long mutation lease, claims the exact
bitmap/count member, collects abandoned state, reassociates the page with the
fresh Theap/thread, collects live state, and restores source queue-tail order.
A direct-small target restores its complete rounded direct-cache range before
target page-count increment and immediately allocates from that exact page.
Its exhausted fully committed scalar-extension shape then extends after that
tail restoration; its exact prefix-covered shape retains the recorded prefix
and extends without a direct mapping operation; its exact on-demand shape
performs the direct page-area commit before prefix-count/free-list/capacity
publication.
The medium branch accepts either an immediate head or an exhausted nonfull
medium page (`capacity < reserved`). A fully committed medium page
(`slice_pcommitted == 0`) performs the scalar source
`mi_page_extend_free` list/capacity transition after tail insertion. The
bounded test-only `commit == false` seam instead constructs actual reserved
medium and direct-small pages with source initial callback-committed prefixes.
Their nonzero-prefix paths derive the source OS-page count and byte-range plan:
the exact prefix-covered direct-small plan retains its prefix and directly
extends the free list, while a positive mapping delta uses the paired retained
mapping for direct `_mi_os_commit`-shape commitment before it writes
`slice_pcommitted` or its free list. An injected direct-commit failure repeats
false collection, queue detach, direct-cache/page-count repair, and mapped
identity/bit/count/unown publication; the retained owner can retry only that
same candidate through its existing long lifecycle. The prefix-covered fixture
arms that fault before adoption, proving its zero-delta plan cannot enter the
mapping path. This does not add a production page-on-demand option, a generic
fresh fallback, or a bitmap scan. A bitmap miss, malformed state, scalar
extension error, or any other post-transfer error remains terminally retained.
Non-direct-small, malformed or out-of-profile no-immediate direct-small metadata, full, singleton,
unmapped, huge, foreign, multi-member aggregate-registry, automatic-
scanning, and concurrent adoption remain deliberately absent. The one aggregate
exception is described below: a completed source traversal may turn exactly
one initial nonfull medium survivor with an immediate local head into the
existing one-page handoff before a registry exists.

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
performing PageMap -> `pages_main` -> metadata -> slice release. If that complete
source traversal releases every other page and leaves exactly one
initially-nonfull medium page with an immediate local head, the traversal
captures its exact page/span/bin witness while it still owns every queue and
returns the established one-page mapped route instead of creating a registry.
That route reuses only its exact bitmap member through the established
fresh-later-main claim/requeue path; its immediate-head revalidation forbids
extension, direct commitment, a fresh-page fallback, and a bitmap/PageMap
search. A multi-member registry, a non-medium/no-immediate survivor, and a
registry later reduced to one member by client frees remain sequential
client-free-only. A fresh engine may serialize an independent map operation
between frees, but no current allocator path receives a capability to adopt,
reclaim, or requeue a registry member.

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
attachment remains a test-only seam; the production no-page bridge now uses
this coordinator after initial TLS/guard setup and before constructors.

General producer routing, concurrent/general shared/later-thread page-bearing
ownership, remaining heterogeneous full classes beyond the bounded dynamic and
later-main medium/large aggregate routes plus singleton/unmapped/huge owner-exit pages and
behavior beyond the bounded sole
full-medium/full-large/full-non-direct-small/full-direct-small routes, the
full-singleton/homogeneous-full-OS-singleton/full-medium/full-large/mixed-medium-large/full-non-direct-small/full-direct-small aggregate routes, sole small-or-medium route (apart
from its exact mapped-medium consuming handoff), and aggregate regular-pages
registry, terminal reuse, automatic and multiple
dynamic arenas, complete process options/TLS/shutdown, pthread/TLS teardown
hooks beyond the completed no-page bridge, general fork repair for live or
retained owners, public libc backend
integration, performance qualification,
and default promotion remain unfinished. The next safe lifecycle frontier is
another source-shaped owner-exit page class, a full repair contract for a
nonquiescent fork child, or a separately proven aggregate-registry policy—not
a superficial broad abandonment loop or generic allocation-time scan. The
bounded mapped-medium page-area
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
client-free transfer has thirteen narrow forms: the sole full-medium route,
full-large route, full non-direct-small route, full direct-small route,
full-singleton, homogeneous full-OS-singleton, full-medium, full-large,
mixed-medium-large, full-non-direct-small, and full-direct-small aggregate routes, sole
small-or-medium route, and
aggregate regular-pages registry. Each converts the
long mutation lease into a short locked free owner, retains stable
span/arena/Heap facts rather than the old Theap/TLD, and proves bitmap/count
pairing through actual teardown and sequential later frees. The sole mapped
regular route additionally has four source-specific full-page predecessors:
exactly one joined remote free makes either the sole medium or large `BIN_FULL`
page, the sole non-direct-small ordinary-bin page, or the sole direct-small
ordinary-bin page nonfull during force collection. False collection removes
that same source member; the large branch retains its complete 64-slice span,
the non-direct-small branch retains the empty direct-cache image, while the
direct-small branch clears its rounded range before page-count detach. All four
immediately publish the ordinary mapped bit/count pair before old-Theap/TLD
teardown. They are not general full-page traversals. All full-origin
predecessors remain client-free-only even though their final geometry is
nonfull. The separately completed source-initially-nonfull sole mapped-medium
route and immediate-head or exhausted-fully-committed-scalar-extension
direct-small routes have the explicit inverse bridge into one fresh later-main
mutation lease. The mapped-medium route's bounded reserved-prefix fixture now
covers source direct page-area commitment and failed-commit reabandonment
before a same-candidate retry; it is not a generic allocation policy. The
nonfull aggregate registry intentionally stops at nonfull regular small,
medium, and large pages and has no adoption capability; the separate full
aggregates intentionally stop at their per-member medium and large `BIN_FULL`
classes plus the full non-direct-small and direct-small ordinary-bin
classes.
The direct-small aggregate additionally seals its exact rounded direct-cache
queue-head image and uses free.c's partial collector. Only the
completed nonfull traversal's separately typed sole
initial-medium/immediate-head outcome becomes the existing one-page route
before registry construction. Do not extend either boundary to another page
shape without its source-specific publication, terminal-release,
allocation-time claim/reclaim, and concurrency evidence.

Checkpoint evidence is green: the focused
`dynamic_theap::tests::dynamic_thread_exit_singleton_remote_free_clears_tls_then_releases_its_arena_page`,
`dynamic_thread_exit_full_singleton_pages_route_releases_each_same_size_page`,
`dynamic_thread_exit_full_singleton_pages_route_releases_each_mixed_size_page`,
`dynamic_thread_exit_full_singleton_pages_route_rejects_a_sole_singleton_before_mutation`,
and `dynamic_thread_exit_full_singleton_pages_route_retains_a_collection_failure`,
`dynamic_thread_exit_full_os_singleton_pages_route_releases_each_clipped_map`,
`dynamic_thread_exit_full_os_singleton_pages_route_rejects_a_sole_page_before_mutation`,
`dynamic_thread_exit_full_os_singleton_pages_route_retains_a_collection_failure`,
and `dynamic_thread_exit_full_os_singleton_pages_route_retains_failed_unmap_terminally`,
`dynamic_thread_exit_full_medium_pages_route_reabandons_each_distinct_bin_page_then_releases`,
`dynamic_thread_exit_full_medium_pages_route_rejects_a_sole_full_medium_before_mutation`,
`dynamic_thread_exit_full_medium_pages_route_rejects_mixed_full_classes_before_mutation`,
and `dynamic_thread_exit_full_medium_pages_route_retains_a_collection_failure`,
`dynamic_thread_exit_full_large_pages_route_reabandons_each_distinct_bin_page_then_releases`,
`dynamic_thread_exit_full_large_pages_route_rejects_a_sole_full_large_before_mutation`,
`dynamic_thread_exit_full_large_pages_route_rejects_mixed_full_classes_before_mutation`,
and `dynamic_thread_exit_full_large_pages_route_retains_a_collection_failure`,
`dynamic_thread_exit_full_non_direct_small_pages_route_reabandons_each_distinct_bin_page_then_releases`,
`dynamic_thread_exit_full_non_direct_small_pages_route_rejects_a_sole_full_page_before_mutation`,
`dynamic_thread_exit_full_non_direct_small_pages_route_rejects_mixed_full_classes_before_mutation`,
and `dynamic_thread_exit_full_non_direct_small_pages_route_retains_a_collection_failure`,
`dynamic_thread_exit_full_direct_small_pages_route_preserves_partial_head_then_releases_each_member`,
`dynamic_thread_exit_full_direct_small_pages_route_rejects_a_sole_full_page_before_mutation`,
`dynamic_thread_exit_full_direct_small_pages_route_refuses_stale_rounded_direct_cache_before_detach`,
`dynamic_thread_exit_full_direct_small_pages_route_rejects_mixed_full_classes_before_mutation`,
and `dynamic_thread_exit_full_direct_small_pages_route_retains_a_collection_failure`,
`dynamic_thread_exit_full_medium_handoff_reabandons_after_mostly_used_frees_then_releases`,
`dynamic_thread_exit_full_medium_handoff_rejects_before_detach_when_another_page_is_live`,
and `dynamic_thread_exit_full_medium_handoff_retains_collection_failure`,
`dynamic_thread_exit_full_large_handoff_reabandons_after_mostly_used_frees_then_releases`,
`dynamic_thread_exit_full_large_handoff_rejects_a_full_medium_before_detach`,
and `dynamic_thread_exit_full_large_handoff_retains_collection_failure`,
`dynamic_thread_exit_full_large_one_remote_force_collects_to_mapped_handoff_then_releases`,
`dynamic_thread_exit_full_large_one_remote_force_collect_route_rejects_full_medium_before_detach`,
and `dynamic_thread_exit_full_large_one_remote_force_collect_route_retains_collection_failure`,
`dynamic_thread_exit_full_non_direct_small_handoff_reabandons_after_mostly_used_frees_then_releases`,
`dynamic_thread_exit_full_non_direct_small_handoff_rejects_before_detach_when_another_page_is_live`,
`dynamic_thread_exit_full_non_direct_small_handoff_rejects_direct_small_before_detach`,
`dynamic_thread_exit_full_non_direct_small_handoff_refuses_stale_direct_cache_before_detach`,
and `dynamic_thread_exit_full_non_direct_small_handoff_retains_collection_failure`,
`dynamic_thread_exit_full_non_direct_small_one_remote_force_collects_to_mapped_handoff_then_releases`,
`dynamic_thread_exit_full_non_direct_small_one_remote_force_collect_route_rejects_regular_non_direct_small_before_detach`,
`dynamic_thread_exit_full_non_direct_small_one_remote_force_collect_route_rejects_full_direct_small_before_detach`,
`dynamic_thread_exit_full_non_direct_small_one_remote_force_collect_route_refuses_stale_direct_cache_before_detach`,
and `dynamic_thread_exit_full_non_direct_small_one_remote_force_collect_route_retains_collection_failure`,
`dynamic_thread_exit_full_direct_small_handoff_reabandons_after_partial_head_lag_then_releases`,
`dynamic_thread_exit_full_direct_small_handoff_refuses_stale_rounded_direct_cache_before_detach`,
`dynamic_thread_exit_full_direct_small_handoff_rejects_non_direct_small_before_detach`,
`dynamic_thread_exit_full_direct_small_handoff_rejects_before_detach_when_another_page_is_live`,
and `dynamic_thread_exit_full_direct_small_handoff_retains_collection_failure`,
`dynamic_thread_exit_mapped_one_block_large_handoff_releases_its_complete_span_after_final_free`,
`dynamic_thread_exit_mapped_one_block_large_handoff_rejects_medium_before_detach`,
and `dynamic_thread_exit_mapped_one_block_large_handoff_retains_collection_failure`,
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
full-singleton aggregate's same- and mixed-rounded-size arena-only inputs,
one-member-at-a-time terminal release, sole-page refusal, and collection-failure
retention; the full-medium aggregate's distinct-rounded-bin independent
per-member unmapped-to-mapped thresholds, one-member-at-a-time terminal
release, and sole-full-page preflight refusal; the full-large aggregate's
distinct-rounded-bin independent per-member unmapped-to-mapped thresholds,
one-member-at-a-time complete
64-slice terminal release, sole/mixed-full preflight refusal, and terminal
collection-failure retention; the per-member full-non-direct-small aggregate's
distinct-bin normal-collector unmapped-to-mapped thresholds,
one-member-at-a-time one-slice terminal release, sole-full-page preflight
refusal, direct-small helper rejection after owner claim, and terminal
collection-failure retention; the per-member full-direct-small aggregate's
complete rounded direct-cache image preflight, independent partial-head-lag
unmapped-to-mapped thresholds across distinct bins, one-member-at-a-time
one-slice terminal release, sole-full-page and stale-cache preflight refusal,
non-direct helper rejection after owner claim, and terminal collection-failure
retention; the
full-medium one-joined-remote force-collection predecessor's immediate mapped
publication, client-free-only allocation-adoption refusal, eight-slice
client-free release, pre-mutation regular-medium refusal, and terminal
collection-failure retention; the full-large one-joined-remote force-collection
predecessor's immediate mapped publication, client-free-only
allocation-adoption refusal, complete 64-slice client-free release,
pre-mutation regular-large refusal, and terminal collection-failure retention;
the full-non-direct-small one-joined-remote
force-collection predecessor's immediate mapped publication, client-free-only
allocation-adoption refusal, one-slice client-free release, pre-mutation
direct-small refusal, and terminal collection-failure retention; the
full-direct-small one-joined-remote
force-collection predecessor's immediate mapped publication, direct-range
clear-before-count-detach, one-slice terminal release, regular/non-direct
class and stale-cache preflight refusals, and terminal
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
page-area commitment, failed-commit mapped reabandonment/same-candidate retry;
the direct-small immediate-head, exhausted-fully-committed scalar-extension,
reserved-prefix-covered no-commit extension, and reserved-prefix page-area-
commit fresh-owner reclaim/reuse regressions (including failed-commit
direct-cache repair and same-candidate retry); and the aggregate
regular-pages registry's mixed small/medium/large
release, retired-direct-small prepass, and retired-large prepass followed by
sole immediate-medium exact reclaim/reuse with an armed no-commit fault,
malformed direct-image and malformed-predecessor
preflight refusal, full-small preflight refusal, post-claim distinct-large-bin
selection, large-span terminal release,
and large force-collection-to-drained regressions), and
`abandoned::tests::mapped_one_block_owner_exit_free_retains_a_nonempty_medium_page`,
which proves the mapped endpoint cannot reclaim or requeue a still-live page,
the source-order process-main coordinator regressions in `process_init::tests`,
and the static-Heap/ticket-zero selector regressions in `main_theap::tests` and
`subproc::tests` all pass. The current pinned Linux/AArch64 container
`cargo test -p crabc-mimalloc --lib` run passes all 578 tests, including
`dynamic_thread_exit_mapped_medium_pair_route_releases_distinct_bin_pages_in_source_order`,
`dynamic_thread_exit_mapped_medium_pair_route_rejects_a_non_pair_before_detach`,
and `dynamic_thread_exit_mapped_medium_pair_route_retains_force_collection_failure`.
`./scripts/dev.sh test -p crabc-mimalloc
--lib --features loom
remote_free::loom_tests -- --test-threads=1` passes the five Loom remote-head
schedules; `./scripts/dev.sh structure`, the 39 allocator-runner unit tests,
and `./scripts/dev.sh allocator --quick` also pass (report:
`compat/reports/allocator/latest.json`). The current explicit
`compat/allocator/run.py --check` passes after a reviewed
`compat/allocator/ratchet-v3.5.0.json` snapshot with 125 items and 129
implemented/unit-verified statuses. Resume with a fresh source/lifecycle review
before broadening the newly proven post-TLS arena/OS-singleton or
dynamic-full-singleton-aggregate/dynamic-full-os-singleton-homogeneous-aggregate/dynamic-full-medium-aggregate/dynamic-full-large-aggregate/dynamic-full-non-direct-small-homogeneous-aggregate/dynamic-full-direct-small-homogeneous-aggregate/full-singleton/full-singleton-aggregate/full-medium/full-medium-aggregate/full-large/full-large-aggregate/full-large-one-remote-mapped/full-non-direct-small/full-non-direct-small-homogeneous-aggregate/full-direct-small/full-direct-small-homogeneous-aggregate/full-medium-one-remote-mapped/full-large/full-large-one-remote-mapped/full-non-direct-small/full-non-direct-small-one-remote-mapped/full-direct-small-one-remote-mapped or mapped-one-block-medium/large/non-direct-small/direct-small, mapped-medium-pair, or mapped-two-block-medium/large/non-direct-small/direct-small cases, the later-main
all-free scan/eight sole-page handoffs/two aggregate registries, or
either bounded process page owner.
The two-block dynamic normal classes are deliberately separate: medium, large,
and one-slice non-direct-small pages each prove force -> false collection ->
ordinary detach -> mapped identity/bit/count/unown, then exactly one
`UnownedMapped` first free and one `Empty` final free. The large class also
proves that all 64 source PageMap slots remain mapped after its first normal
free and release only after the final free. None admits direct-small's
cache-range collector, a third client free, a second source member, or general
post-TLS traversal.
`DynamicThreadExitDrain::abandon_mapped_two_block_large` now records that
separate large source boundary: one sole nonfull `MemoryKind::Arena`
`PageKind::Large` page with `MEDIUM_MAX_OBJ_SIZE < block_size <=
LARGE_MAX_OBJ_SIZE`, `reserved > 2`, `used == 2`, one matching regular queue
member, an empty direct-cache image, and its exact 64-slice arena span. It
keeps source force -> false collection -> ordinary removal -> page-count
decrement -> large no-op direct-cache update -> dynamic
identity/bit/count/unown. The first exact canonical normal free returns
`UnownedMapped`, preserves the bit/count plus every span mapping with
`used == 1`, and only the final `Empty` free clears the pair and releases
PageMap/ordinary-bit/metadata/all 64 slices. This is not a generic multi-free,
cache-repair, reclaim/adoption/requeue, scan, producer, concurrent routing, or
owner-exit traversal path.
`DynamicThreadExitDrain::abandon_mapped_two_block_direct_small` now records
that remaining direct-small source boundary as its own post-TLS handoff: one
sole nonfull one-slice `MemoryKind::Arena` `PageKind::Small` page with
`block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, `used == 2`, one matching
ordinary queue member, and its complete rounded direct-cache range. It keeps
source force -> false collection -> ordinary removal -> direct-range clear ->
page-count decrement -> dynamic identity/bit/count/unown. The first exact
canonical free returns `UnownedMapped`, but direct partial collection leaves
its just-published head atomic, so observed `used` deliberately remains two;
the final free supplies the next head, consumes both heads, returns `Empty`,
and releases the one-slice PageMap/bitmap/metadata/span. The direct route is
still not a generic multi-free or cache-repair mechanism: stale/mixed cache
images, one or three live blocks, another page, non-direct geometry, producer
or concurrent routing, reclaim/adoption/requeue/scans, and general owner-exit
traversal remain outside it.
The frozen-profile direct-small no-immediate source family is now exhaustive:
after force/false collection, every valid nonfull page has either a fully
committed scalar extension, a prefix-covered extension, or a positive
page-area-commit extension. The defensive unsupported classifier is only for
malformed or out-of-profile metadata. The later-main and dynamic per-member
full direct-small aggregates now each seal the complete rounded direct-cache
image, advance every affected queue head before its count detach, and use
free.c's partial collector through the source accounting lag.
`DynamicThreadExitDrain::abandon_mapped_medium_pair` now proves the separate
distinct-bin `{2, 1}` medium aggregate boundary: after complete preflight, it
walks source bin order and retains only the drain plus page/free counts; each
later client free re-selects its map through PageMap after claiming that
member's low owner bit, yielding `StillLive`, `ReleasedPage`, then `Released`
without retaining a raw member registry. The full-medium aggregates now have
the same bounded per-member shape: pinned `src/theap.c:97-115,123-152` visits
each full member independently and `src/arena.c:1316-1337` derives its bin
from that page. Dynamic and later-main homogeneous preflight admit distinct
rounded medium bins. Later-main additionally has the separately typed complete
`BIN_FULL` medium/large mix described above; it still rejects every other mixed
class. Its later frees choose the exact static map only after the source
low-owner claim. The completed no-page
process/pthread bridge now also preserves a quiescent ticket-zero child through
libc's direct fork boundary. The next frontier is a source-shaped page-bearing
owner or full fork repair for a child copied from live/retained owners—not a
generic allocation-time scan, broad callback, raw no-page pointer, or premature
allocator-backend routing.

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

- x86-64 public/runtime support, RISC-V, macOS, Windows, or generic
  portability scaffolding. The allocator-only native x86-64 parity exception
  is defined by the scope amendment above.
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
allocator engine in Rust. The reopened native x86-64 profile validates the
same fixed engine against x86-64 source applicability, but does not add public
allocator integration:

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
Linux/AArch64 are mechanically inventoried and assigned an explicit status;
the reopened x86-64 parity profile requires a separate architecture-qualified
inventory and status.

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
- Linux/AArch64 is the only production integration target; the allocator-only
  native x86-64 parity profile is evidence-only.
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

The most important element is the **two-stage notion of completion**. The Rust backend can become suitable for crabc’s ordinary `malloc` ABI before every optional arena, subprocess, visitation, and secure-mode API is finished. But the project should continue until the machine-readable v3.5.0 ledger reaches full Linux/AArch64-applicable parity and the separately reopened native x86-64 parity track has its own complete architecture-qualified evidence. Conversely, even 100% API coverage is insufficient to justify making it default until the thread, fork, memory-use, and non-inferiority gates pass; x86 parity alone never makes an x86 backend public or default.

[1]: https://github.com/microsoft/mimalloc/releases/tag/v3.5.0 "https://github.com/microsoft/mimalloc/releases/tag/v3.5.0"
[2]: https://microsoft.github.io/mimalloc/group__heap.html "https://microsoft.github.io/mimalloc/group__heap.html"
[3]: https://github.com/verus-lang/verified-memory-allocator "https://github.com/verus-lang/verified-memory-allocator"
[4]: https://github.com/microsoft/mimalloc/issues/1282 "https://github.com/microsoft/mimalloc/issues/1282"
