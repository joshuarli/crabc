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

One private `crabc-libc` bridge now consumes only the already-complete no-page
owners. After initial TLS and the stack guard exist but before constructors,
`libc/src/c_abi.rs::__libc_start_main` initializes and process-lifetime retains
the ticket-zero `ProcessMainThread` plus its main-thread-minted
`MainStaticHeapLease`. Each real `pthread` child attaches before its start
routine can run; the parent waits for that result and returns `EAGAIN` rather
than reporting a runnable thread whose no-page owner could not attach. Normal
return, `pthread_exit`, and cancellation finish the Rust owner only after libc
has run cleanup handlers and POSIX TSD destructors. This boundary has no C
symbol, does not consume a pthread key, does not route `malloc`/`free`, and
leaves the C mimalloc backend active with its existing private key outside the
128-key application capacity. The process owner is retained at normal exit. On
libc's direct `fork` path, after public prepare handlers and before the raw
syscall, a private allocation-free gate preserves the copied no-page owner only
when the original ticket-zero `TPIDR_EL0` image has zero live or retained later
bridge owners. That child resets the copied gate and may attach a fresh pthread;
any other child disables the bridge. This is not inherited-lock, root, or
page-state repair, and it does not claim general fork recovery.

`process_page_map.rs` owns the separate process-static source-page-map
publication boundary. It freezes one `MemoryConfig` and selected
`MainSubprocess`, initializes a `PageMap` in its final slot, then
Release-publishes the header root. `process_arena.rs` retains the lower
`mi_manage_os_memory_ex2` sidecar for one caller-supplied external mapping and
adds one explicit regular `mi_reserve_os_memory_ex2` entry. The latter accepts
only a caller-selected nonzero request that rounds to exactly one complete
arena, maps ordinary reserved or committed memory, records `MemoryKind::Os`,
and binds the same map/root/main identity before publication.
`reserve_default_os_arena` separately ports the first lazy
`mi_arena_reserve` decision: source max-page headroom, the frozen 1-GiB
Linux/AArch64 default, its overcommit-only eager mapping mode, and its 128-MiB
retry after an unpublished first attempt returns COLD. It has no process-start
caller. `MainStaticFirstArenaPageAllocator` is the one private ticket-zero
fresh-page route: it derives the empty-Theap small/medium/large/singleton span,
validates the zero-page static image before mapping, retains the PageMap
lifecycle through activation, and calls the policy only for that first valid
ordinary miss. `ProcessMainThread` is its sole production-shaped factory,
transferring only the retained attachment and immutable ready-map witness;
creating that private owner has no reservation or mapping side effect. An
unpublished metadata failure unmaps that exact regular map
before returning a COLD retry state; a failed unmap retains the mapping
terminally. The external entry still returns an unpublished rejected mapping to
its caller. For either reserved map, the final sidecar slot gives the in-place
arena a stable callback to commit metadata and later selected/page-metadata
ranges through that exact owner; frozen Linux decommit reports no recommit
requirement. Later arena scaling, option mutation, large-page/exclusive/NUMA
policy, existing-arena search, aligned routing, and general fresh-page routing
remain absent.
`ProcessPageArenaLease` validates that immutable tuple
before either `main_static_page.rs` or `main_heap_page.rs` may borrow its
selected source Theap. Each private owner holds the map's nonrecursive
lifecycle lease for its complete engine and scoped-producer lifetime, installs
the chosen arena's in-place `pages_main` bitmap in the shared static main Heap,
and preserves the source bitmap -> PageMap publication and PageMap -> bitmap ->
metadata -> slice-release order. It is distinct from `MetaAllocator`'s private
map/arena and every caller-managed test map. The bounded process coordinator
now invokes the global map stage in source order. Once a separately bounded
reservation is READY, it can reconstruct only that immutable matching pair
for one subsequent owner; this does not search the arena registry, select free
slices, or perform a mapping operation. Its one automatic connection
is the bounded ticket-zero first ordinary miss. Its normal `realloc` delegates
preserve source replacement failure and copy behavior; `realloc(NULL, size)`
alone may activate that ticket-zero policy. It still lacks C
`mi_page_map_empty` pre-root, existing-arena search, later automatic arena
reservation, general concurrent page consumers, owner-exit traversal, and
process shutdown. A rejected
unpublished external mapping returns to its caller; a failed regular-map release
or dropped unfinished lifecycle is terminal rather than exposing a null or fresh root.
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
and invalid-size failure. The native x86-64 evidence lane separately extends
its private trace to 75 fields with fixed no-padding `mi_expand` and checked
`mi_recalloc` growth, zero-product, and overflow-preservation cases; native
AArch64 revalidation of that extension remains pending. A separate native
x86-64-only 25-field C/Rust differential records two live-owner publications
from one quiescent `pthread`, then the pinned private owner false collector.
It proves only owner-bit preservation, LIFO publication, exact used-count, and
the post-join detach/local-free merge; it is not general remote-free routing or
concurrent collection, abandonment, thread teardown, public API, libc
integration, backend, or AArch64 evidence.
The same x86-only track separately compares 28 address-independent C/Rust
values for one real small direct-cache page filled to its current capacity,
one joined `pthread` remote free, and the owner direct-cache miss falling
through the regular queue search to detach and reuse that exact block. This is
one private small direct-page route only, not general allocation/free routing,
concurrent collection, abandonment, thread teardown, public API, libc
integration, backend, or AArch64 evidence. A third native x86-only
eight-field C/Rust differential creates one arena-backed mapped page with two
same-page live blocks, applies the source queue-detach abandonment transition,
and frees one block through the same-origin reclaim path while the survivor
keeps the page nonempty. It proves only mapped abandonment clearing,
re-association, and requeue for that one route—not general abandonment/adoption
or cross-thread reclaim. A further native x86-only 18-field C/Rust differential
uses a worker `pthread` that runs real `mi_thread_done()` and returns; the
consumer calls `pthread_join()` before it performs two public `mi_free` calls. It records the
selected mapped failed-reclaim/unown transition and terminal checks for
`page_map_unregistered_after_final_free`,
`arena_page_bitmap_clear_after_final_free`, and
`arena_slice_released_after_final_free`. Rust covers only one bounded
process-owned mapped regular handoff after teardown and directly observes its
PageMap, ordinary arena-page bitmap, and free-slice bitmap release. This does
not establish general thread exit, routing or concurrency, adoption or reclaim,
public `mi_*` behavior, libc integration, backend promotion, public x86 support,
or AArch64 evidence. The same native x86-only track also has a 21-field
retired-page prepass differential. Its real worker-local `mi_free` retires one
medium page; real `mi_thread_done()` and `pthread_join()` force-release that
retired page before one distinct live medium page is mapped-abandoned, and one
consumer `mi_free` then terminally releases the live page. C and Rust compare
retired/local-retirement state, teardown PageMap/ordinary arena bitmap/exact
slice-span release, live mapped-abandoned state, terminal PageMap/ordinary
bitmap/exact slice-span release, and an empty route. This remains private
native x86 engine evidence only: it does not establish general retirement,
teardown, routing or concurrency, public `mi_*` behavior, libc integration,
backend promotion, public x86 support, or AArch64 evidence. A native x86-only
track additionally has a 25-field aggregate post-exit
differential for exactly two distinct live nonfull medium arena pages in
distinct bins. Its real worker runs `mi_thread_done()` and returns; the
consumer calls `pthread_join()` before freeing. Both selected pages are
mapped-abandoned after teardown. The consumer frees
the second page first, directly observing only that page's PageMap unregister,
ordinary arena-page bitmap clear, and exact slice-span release while the first
remains PageMap-registered, arena-bitmap-set, mapped-abandoned, and
`used == 1`. The final consumer free releases the first page and records an
empty route.
Rust compares only this bounded private aggregate post-exit traversal. It does
not establish general teardown, routing or concurrency, public `mi_*` behavior
or runtime, libc integration, backend promotion, public x86 support, or
AArch64 evidence. The selected
normal-release source surface is also
accounted per item for native object/dynamic symbol presence, while a separate
five-mode staged public-header gate proves selected C/C++ compile/linkability
and ELF identity. Neither accounting nor the header gate establishes behavior,
Rust implementation, CMake installation, consumer execution, or public runtime
compatibility.

Those operations are
live in the private lifecycle,
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
general fork protocol, or backend selection. The present Milestone 5 foundations are intentionally
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
before bitmap publication. The full-origin medium and direct-small branches
retain that origin after force collection, so they remain client-free-only
rather than borrowing the separate initially-nonfull medium adoption/requeue
authority. The one-block
handoff accepts only its empty final free. Separate full-medium and full-large
routes first preserve the source full-queue detach and ordinary unmapped
abandonment. A separate full
non-direct-small route preserves that same unmapped tail while detaching from
its ordinary small bin instead of `BIN_FULL`; it requires
`block_size > SMALL_SIZE_MAX`, has no direct-cache image, and takes the
ordinary failed-reclaim collector. The complementary sole full direct-small route
also remains in its ordinary bin, but requires `block_size <= SMALL_SIZE_MAX`,
`reserved >= 16`, `used == reserved`, and its complete rounded
`pages_free_direct` range. Queue removal clears that range before page-count
detach, and its failed-reclaim partial collector retains the just-published
atomic head before the source free count reaches the mostly-used boundary.
A separate per-member full direct-small aggregate advances each ordinary-bin
range to that bin's remaining queue head before its respective page-count
detach, then leaves the complete image empty only after the final member is
removed.
Sequential client frees remain unmapped while `free <= reserved / 8`, then the
first below-mostly-used free publishes the exact static-main bitmap/count pair
and subsequent frees use the mapped tail. Their terminal empty results still
release in PageMap -> `pages_main` -> metadata -> slice order after old-Theap
teardown; the large route validates its complete 64-slice span. The process
route can keep one sole
nonfull small-or-medium page mapped while its linear
client frees finish after the old Theap/TLD is gone. A distinct client-free-only
route accepts one nonfull large page with exactly two client blocks, proves its
complete fixed 64-slice PageMap span and source leading `pages_main` bit before
and after source collection, and releases that entire span on the second free. A direct small member is
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
count is nonzero. The private libc bridge invokes this direct no-page
attach/finish path for real pthread workers, but never enters the page session.
It is therefore not a page-bearing production pthread/TLS lifecycle or
allocation-routing claim. Separately, `MainStaticProcessPageSession` is the one internal bridge
for the Rust lifetime gap between a ticket-zero page session and a copied
shared-main lease. It validates the ordinary zero-page static image, then
permanently closes main-image teardown before issuing that lease. The static
Theap stays current-thread-only; its Heap installation and fresh-page pointer
association take only short `shared_heap_projection_lock` views, so a later
*no-page* TLD/Theap may attach and detach without an aliased `&mut Heap`.
Its focused regression completes that later lifecycle and then one ticket-zero
ordinary page allocation/free under the paired PageMap lease. This permanent
session now has one private lazy `MainStaticRuntimeFirstArenaPageAllocator` in
`runtime_lifecycle.rs`: it is created only from the original ticket-zero
thread, retains no mapping until a valid first request, and keeps its
`ProcessPageMapMutationLease` while its bounded engine has live page state.
After the engine proves its full local image empty, it returns only that
Rust-side aliasing lease while retaining the permanent session and
already-published first arena; a later ticket-zero request may reactivate
sequentially through that same arena without a new reservation. The internal
state still disables the prior no-page-only fork-preservation predicate as soon
as the permanent page authority exists. While dormant, it may lend only the
already-published map/arena pair to one fresh test worker that has entered the
existing later-main attachment: the worker owns one scoped engine, must return
it empty, and then completes the normal no-page attachment teardown before
ticket zero may reactivate. The seam is not called by libc, admits no
concurrent or general later-worker page engine, and does not alter the C
backend or repair a fork child. A separate `no_std` evidence staticlib,
`compat/allocator/runtime-ticket-zero-adapter`, exposes six prefixed C calls to
a fresh test process: init with `AT_PAGESZ`, malloc, zalloc, realloc, free,
and a pointer-free worker round trip. Its exact-symbol audit rejects ordinary
`malloc`/`free` and `mi_*` exports, and its direct fixture proves first-page
activation, replacement copying, zeroing, exact free, all-free dormant
handoff, the worker's scoped allocation/free plus normal attachment teardown,
same-arena ticket-zero reactivation, and successful-path `errno` preservation.
It intentionally has no shutdown because the source owner is process-lifetime.
That test ABI does not make the runtime seam a
crabc libc ABI, a selected backend, a pointer-domain fallback, or a fork
repair mechanism. `main_heap_page.rs` now binds one current
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

`MainHeapThreadProcessPageExitDrain::abandon_full_singleton_pages_to_process_route`
is a separately typed aggregate boundary for two or more full arena
`PageKind::Singleton` members in `BIN_FULL`. Its complete preflight requires
every direct entry and every other queue to be empty; each member has its own
rounded singleton block size, `reserved == used == 1`, a zero retirement
countdown, an empty local free list, and an exact selected-arena span. It then
preserves source force -> false collection, full-queue/page-count detach, and
ordinary unmapped abandonment for every member before old-Theap/TLD teardown.
The linear route keeps no raw page list or static-main abandoned bitmap/count
pair: each later free re-resolves one PageMap member, revalidates its own
geometry, recovers only its canonical singleton allocation, and must take the
raw failed-reclaim empty decision. Its terminal order is that member's complete
PageMap span -> the ordinary `pages_main` bit at its first slice -> metadata ->
arena slices; the last member closes the map route. Sole pages, non-singletons,
OS-backed members, allocation-time adoption, reclaim, requeue, scanning, and
concurrent routing reject or remain absent.

`MainHeapThreadProcessPageExitDrain::abandon_full_os_singleton_pages_to_process_route`
is a separate aggregate boundary for two or more same-rounded-size
`MemoryKind::Os` singleton pages in `BIN_FULL`. Its complete preflight requires
`reserved == used == 1`, a zero retirement countdown, an empty local free list,
a valid clipped PageMap/alias release image, every direct entry and every other
queue empty, and an initially empty static-main `Heap::os_abandoned_pages`
list. It preserves source force -> false collection, full-queue/page-count
detach, private OS-list insertion, and unmapped unown for every member before
old-Theap/TLD teardown. Full-queue removal clears `PAGE_IN_FULL_QUEUE`, but the
private list owns the page's intrusive links until the exact later client free
removes that member. The route holds no separate raw member list: each free
re-resolves one current PageMap member, recovers only its canonical singleton
allocation, must take the raw failed-reclaim empty decision, then performs
private-list removal -> clipped PageMap -> aliases -> metadata -> mapping
release. The final member closes the map route. Sole or differently rounded
OS members, non-OS members, nonempty initial list state, list traversal, retry
after failed `munmap`, adoption, reclaim, requeue, scanning, allocation-time,
and concurrent routing reject or remain absent; a failed mapping release
retains the exact `OsAlignedPageOwner` terminally.

`MainHeapThreadProcessPageExitDrain::abandon_full_medium_pages_to_process_route`
is a separate aggregate boundary for two or more full medium arena pages in
`BIN_FULL`. Its preflight requires every direct entry and every other queue to
be empty, and every full member to have its own rounded block size/static-main
bin, `reserved > 1`, `used == reserved`, a zero retirement countdown, and one
paired-arena span. It then preserves source force -> false collection,
full-queue/page-count detach, and ordinary unmapped abandonment for every
member before old-Theap/TLD teardown. The resulting linear route retains no raw
page list: each client free re-resolves a PageMap member under a short lock,
claims its low owner bit, then selects that member's exact static-main
bitmap/count capability and unmapped or mapped failed-reclaim tail. A terminal
free releases only that member through PageMap -> `pages_main` -> metadata ->
arena slice; the final member closes the map route. A sole page rejects before
mutation, and the route neither adopts, reclaims, requeues, scans,
allocation-routes, nor accepts a mixed class or concurrent free.

`MainHeapThreadProcessPageExitDrain::abandon_full_large_pages_to_process_route`
is a parallel but separate aggregate boundary for two or more full large arena
pages in `BIN_FULL`. It has the same complete direct/queue, per-member rounded
block-size/static-main-bin, full-state, and zero-retirement preflight, but
also proves every member's exact 64-slice arena and PageMap span. Source force
-> false collection, full-queue/page-count detach, and ordinary unmapped
abandonment run for every member before old-Theap/TLD teardown. Its linear
route again stores no raw member list: each sequential client free re-resolves
its PageMap member, claims the low owner bit, then selects that member's exact
static-main bitmap/count capability and unmapped or mapped tail. It can publish
that member's pair only after its mostly-used boundary. A terminal free
proves and releases only that member's complete span through PageMap ->
`pages_main` -> metadata -> arena slices; the final member closes the map
route. Sole pages and heterogeneous medium/large full queues reject before
mutation. It exposes no allocation-time adoption, reclaim, requeue, scanning,
or concurrent free routing.

`MainHeapThreadProcessPageExitDrain::abandon_full_medium_or_large_pages_to_process_route`
is a third, separately typed `BIN_FULL` aggregate for the bounded source mix:
two or more full arena members with at least one `PageKind::Medium` and one
`PageKind::Large`. Every direct entry and every other queue must be empty, and
each member independently proves its rounded static-main bin, `reserved > 1`,
`used == reserved`, zero retirement countdown, empty local free list, and exact
paired-arena span (one slice for medium or 64 slices for large). It preserves
source force -> false collection, full-queue/page-count detach, and initially
unmapped abandonment before old-Theap/TLD teardown. The linear route keeps no
raw member list: each sequential free re-resolves one PageMap member, claims
its low owner bit, derives that member's static-main bitmap/count pair, and
uses the shared normal-collector unmapped or mapped failed-reclaim tail. A
terminal free validates and releases only that member through PageMap ->
`pages_main` -> metadata -> its exact arena span; the last member closes the
map route. Homogeneous queues, small/direct-small, singleton, OS, huge,
malformed spans, remote-force nonfull state, allocation-time adoption, reclaim,
requeue, scans, producers, and concurrent routing remain absent.

`MainHeapThreadProcessPageExitDrain::abandon_full_singleton_or_regular_pages_to_process_route`
is a fourth, separately typed `BIN_FULL` aggregate for one narrower
heterogeneous source mix: two or more full arena members with at least one
`PageKind::Singleton` and at least one regular `PageKind::Medium` or
`PageKind::Large`. Every direct entry and every other queue must be empty. A
singleton proves `BIN_HUGE`, `reserved == used == 1`, zero retirement, an
empty local free list, and its exact rounded span; every regular member proves
an ordinary static-main bin, `reserved > 1`, `used == reserved`, zero
retirement, an empty local free list, and its exact medium or large span. It
preserves source force -> false collection, full-queue/page-count detach, and
initially-unmapped abandonment before old-Theap/TLD teardown. The linear route
keeps no raw member list: each free classifies a current PageMap member, then a
singleton takes its raw empty terminal tail while a regular member claims its
low owner bit before selecting its exact static-main bitmap/count pair and
normal collector tail. A terminal free releases only that member through
PageMap -> `pages_main` -> metadata -> its exact arena span; the aggregate map
route closes only after both source-tail counts reach zero. Homogeneous,
regular-only medium/large, small/direct-small, OS, huge, allocation-time
adoption, reclaim/requeue, scanning, producer, and concurrent routing remain
outside this boundary.

`MainHeapThreadProcessPageExitDrain::abandon_full_non_direct_small_pages_to_process_route`
is a fourth, separately typed aggregate boundary for two or more full arena
`PageKind::Small` members across ordinary source bins. Every member has its own
rounded `SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE` and static-main bin,
`reserved > 1`, `used == reserved`, zero retirement countdown, empty local free
list, and one exact paired-arena slice; every direct entry and `BIN_FULL` must
be empty, and no other class may occupy a populated ordinary bin. It preserves
source force -> false collection, ordinary-bin removal with the proven no-op
direct-cache update, page-count detach, and ordinary unmapped abandonment for
every member before old-Theap/TLD teardown. Its linear route stores no raw page
list: each sequential free re-resolves its PageMap member, claims the low owner
bit, then derives that member's static-main bitmap/count pair and chooses the
normal-collector unmapped or mapped tail. It independently publishes only that
member's pair after its mostly-used boundary. A terminal free releases only
that member through PageMap -> `pages_main` -> metadata -> one arena slice; the
last member closes the map route. Sole pages, direct-small geometry/cache
images, mixed classes, remote-force nonfull state, allocation-time adoption,
reclaim, requeue, scanning, and concurrent routing remain absent.

`MainHeapThreadProcessPageExitDrain::abandon_full_direct_small_pages_to_process_route`
is a fifth, separately typed aggregate boundary for two or more full arena
`PageKind::Small` members across ordinary source bins. Every member has its own
rounded `block_size <= SMALL_SIZE_MAX`, static-main bin, `reserved >= 16`,
`used == reserved`, zero retirement countdown, empty local free list, and one
exact paired-arena slice. The complete rounded `pages_free_direct` image must
name every populated ordinary-queue head. It preserves source force -> false
collection, bin-order ordinary-bin removal, direct-cache-head advance before
each page-count detach, and ordinary unmapped abandonment for every member
before old-Theap/TLD teardown. Its linear route stores no raw member list: each
sequential free re-resolves its PageMap member, claims the low owner bit before
deriving that member's static-main bitmap/count capability, uses the sealed
direct-small witness and claimed abandoned identity to choose the partial-
collector unmapped or mapped tail, and keeps the just-pushed expected head
through the source accounting lag. A member stays unmapped through `reserved /
8 + 1` frees; the next may publish only that member's bitmap/count pair. A
terminal free releases only that member through PageMap -> `pages_main` ->
metadata -> one arena slice; the last member closes the map route. Sole pages,
stale/mixed cache images, non-direct geometry, mixed classes, remote-force
nonfull state, allocation-time adoption, reclaim, requeue, scanning, and
concurrent routing remain absent.

`MainHeapThreadProcessPageExitDrain::abandon_full_medium_after_force_collect_to_mapped_process_route`,
`MainHeapThreadProcessPageExitDrain::abandon_full_large_after_force_collect_to_mapped_process_route`,
`MainHeapThreadProcessPageExitDrain::abandon_full_non_direct_small_after_force_collect_to_mapped_process_route`,
and
`MainHeapThreadProcessPageExitDrain::abandon_full_direct_small_after_force_collect_to_mapped_process_route`
are separate, source-specific predecessors of the eighth mapped route rather
than new full-page state machines. Each admits exactly one joined remote free
and requires force then false collection to leave `used == reserved - 1`.
The medium and large predecessors start from their respective sole full
`BIN_FULL` members: force collection leaves each linked and marked full, then
`_mi_page_abandon` removes that member, clears its full flag and page count,
and immediately publishes the ordinary medium or large mapped-abandoned
identity plus its exact static-main bitmap/count pair. The large predecessor
retains the complete 64-slice span through its mapped terminal release. The
non-direct-small predecessor starts from the sole full ordinary-bin
`PageKind::Small` member with
`SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE` and every direct entry
empty. It stays out of `BIN_FULL`; after force and false collection, source
removes that regular member, performs the source no-op direct-cache update, and
immediately publishes the ordinary small mapped-abandoned identity plus the
same paired static-main capability. The direct-small predecessor instead
requires `block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, and its complete
rounded direct-cache range; source clears that range before page-count detach.
All four old Theap/TLD owners tear down before remaining
linear client frees enter `MainHeapThreadProcessPageExitMappedRegularRoute`.
Their full origins remain client-free-only: final nonfull geometry cannot grant
the initially-nonfull-medium allocation-time adoption edge. Malformed regular,
nonfull, wrong page class, or stale direct-cache input rejects before mutation,
while a collector fault retains the drain terminally. They deliberately exclude multiple joined
frees, local-free variants, all-free release, normal full-page unmapped
abandonment, allocation-time adoption/requeue, mixed traversal, and concurrent
frees.

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
accepts either an exact `PageKind::Medium` route, or an exact
`PageKind::Small` direct-cache route whose source force/false collection left
an immediate local free block, the exhausted fully committed scalar-extension
shape (`free` null, `capacity < reserved`, and `slice_pcommitted == 0`), or
the separately proven exhausted prefix-covered extension shape (`free` null,
`capacity < reserved`, `slice_pcommitted != 0`, and a
`page_area_commit_plan` with nonzero `extend`, zero `commit_size`, and an
unchanged next prefix count), or
the separately proven exhausted on-demand page-area-commit shape (`free` null,
`capacity < reserved`, `slice_pcommitted != 0`, and a
`page_area_commit_plan` with nonzero `extend` and `commit_size`). Both require a fresh
`MainHeapThreadAttachment` whose subprocess, frozen configuration, stable
PageMap root, static main Heap, and selected arena all match. The handoff turns
the route's `ProcessPageMapPostExitAccess` back into a
`ProcessPageMapMutationLease`, so the new engine owns one continuous
source-plain map lifecycle. `ThreadExitMappedRegularPostExitParts` keeps a
non-dereferencing page identity solely to reject a foreign PageMap entry before
the source low-owner claim. The handoff then follows
`src/arena.c:631-778,951-1153` and `src/page.c:245-302`: it claims the exact
static-main bitmap member and paired count, collects while abandoned,
reassociates the page with the new Theap/thread identity, collects live state,
re-proves the complete PageMap span and exact source geometry, and appends the
queue-detached page with `page_queue_push_at_end_metadata` at the target queue
tail. A direct-small target restores its complete rounded direct-cache range
before its target page-count increment, matching `mi_page_queue_push_at_end`.
The medium branch accepts either an immediate head or an exhausted nonfull
medium page (`capacity < reserved`). A fully committed medium page
(`slice_pcommitted == 0`) performs scalar
`mi_page_extend_free` free-list/capacity mutation after that tail restoration.
The direct-small branch accepts its immediate head, the exact exhausted fully
committed scalar-extension shape, the exact exhausted prefix-covered extension
shape, or the exact exhausted page-area-commit shape. A prefix-covered plan
restores the direct-cache range before page-count increment, retains its
recorded prefix count, and publishes the source free-list/capacity extension
without a direct mapping operation. The page-area-commit shape instead performs
the same source direct commitment before it publishes the new prefix count or
free-list/capacity state. These three no-immediate direct-small outcomes are
exhaustive for valid frozen-profile metadata; the remaining defensive
classifier rejects only malformed or out-of-profile state.
The bounded test-only `commit == false` seam creates one actual reserved medium
or direct-small page with the source initial callback-committed prefix. For the
commit-requiring nonzero-prefix case, `page_area_commit_plan` separates OS-page
counts from byte ranges, then the paired retained mapping performs the direct
`_mi_os_commit`-shape extension before
`Page::set_slice_pcommitted_after_commit` or `LocalFreeList::extend_count` may
publish state. The separate prefix-covered fixture arms that commit fault before
adoption; its success proves the zero-delta plan skips the mapping operation
while still extending the source free list. If a direct commit fails,
`reabandon_after_page_commit_failure` follows source false collection, queue
detach, direct-cache/page-count repair, and mapped identity/bit/count/unown
publication. The resulting consuming owner can retry only the same candidate
through its long lifecycle; it cannot reopen short map access, scan, or take a
fresh fallback. This proves no production page-on-demand option. A bitmap miss,
malformed state, scalar extension error, or any other post-transfer failure
likewise retains the target owner. Non-direct-small, malformed or
out-of-profile no-immediate direct-small metadata, full, multi-member aggregate-registry, singleton,
unmapped, huge, foreign,
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
ordinary drain instead of creating an empty registry. When that completed
source traversal itself leaves exactly one initially-nonfull medium page with
an immediate local head, it captures that exact page/span/bin witness while
the queues are still source-owned and returns the established one-page mapped
route instead of constructing this registry. Its reclaim revalidates the
immediate head, so no extension, direct commitment, fresh-page fallback, or
bitmap/PageMap search is available. Fresh engines may serialize independent
PageMap operations between frees, but the current engine surface exposes no
allocation-time adoption, reclaim, or requeue capability for a registered
aggregate member, including a registry that becomes one member only after a
client free. Apart from the explicit one-page medium handoffs, it exposes no
allocation-time claim, reclaim, or requeue for a post-exit route.

The nonfull regular aggregate continues to reject full, singleton, huge,
unmapped, foreign, malformed, or non-source-derived direct-cache state before
detach. The separate full-singleton, homogeneous full-OS-singleton, full-medium,
full-large, mixed-medium-large, non-direct-small, and direct-small aggregates are the only full aggregate
exceptions. The direct
aggregate requires two or more same-bin full arena small pages, its exact
rounded direct-cache range to name the current queue head, every other direct
slot and queue empty, and `reserved >= 16`; each removal advances the range
before its page-count decrement, while its later frees use the partial
collector's retained expected head. Mixed-class full queues, stale cache
images, remote-force nonfull state, and every other owner-exit class remain
separate work. The full-medium route is the narrow exception to same-bin
geometry: it accepts distinct rounded medium bins only, and selects each
member's bitmap/count capability after its low-owner claim.
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
exit, page-bearing pthread/TLS hooks, process shutdown, or public allocator
routing.

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

A `cfg(test)`-only ordinary fixture validates the same frozen source `true`/`2`
image to construct the otherwise sealed `MI_ABANDON` regular-bin aggregate
state below. It does not alter the production rejection above or grant an
ordinary dynamic allocation/page-engine API.

After that same attachment clears its regular backing, a distinct
`DynamicTheapPageDrainSession` retains the cached root, both list memberships,
the dynamic arena image, and the PageMap until its pages are resolved. The
current drain is intentionally a set of source-reachable owner-exit cases,
not a general traversal: its finishing boundary force-collects an already-retired all-free
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

`DynamicThreadExitDrain::abandon_full_singleton_pages` is the distinct
post-TLS dynamic aggregate boundary. It admits exactly two or more full
`MemoryKind::Arena` `PageKind::Singleton` members in `BIN_FULL`; each has its
own rounded block size, `reserved == used == 1`, zero retirement countdown,
empty local free list, exact arena span, and every other queue/direct entry
empty. It preserves the source `MI_ABANDON` order for every member: force
collection, false collection, full-queue removal, page-count decrement, then
unmapped abandonment. The returned `DynamicThreadExitFullSingletonPagesRoute`
stores no raw former-Theap member pointer and publishes no dynamic bitmap/count
pair; it retains the `DynamicThreadExitDrain` until each sequential canonical
free re-resolves and validates its PageMap entry before it reaches only the raw
empty failed-reclaim tail. That free releases exactly its PageMap span ->
dynamic ordinary bit -> metadata -> arena slices. The final member returns the
empty drain for the existing root/list/key teardown. A sole, non-singleton,
OS-backed, preexisting queue/direct state, allocation-time, reclaim/adoption/
requeue, scan, or concurrent case is not this route, and collection ambiguity
retains the drain.

`DynamicThreadExitDrain::abandon_full_os_singleton_pages` is a separate,
bounded post-TLS dynamic aggregate boundary. It admits exactly two or more
full `MemoryKind::Os` singleton members in `BIN_FULL`, each with its own
rounded block size, `reserved == used == 1`, zero retirement countdown, empty local free list,
valid clipped PageMap/alias release image, an initially empty dynamic
`Heap::os_abandoned_pages` list, and every other queue/direct entry empty. It
preserves source force collection -> false collection -> full-queue removal ->
page-count decrement -> private OS-list insertion -> unmapped unown for every
member. The returned `DynamicThreadExitFullOsSingletonPagesRoute` stores only
the dynamic drain and member count rather than a raw former-Theap
list or dynamic bitmap/count pair. Each sequential canonical free re-resolves
its PageMap entry, reaches only the raw empty failed-reclaim tail, removes that
exact private-list member, then releases its own clipped PageMap -> alias ->
primary metadata -> mapping image. The final member returns the empty drain for
the existing root/list/key teardown. A sole, arena-backed, non-singleton,
preexisting-list, allocation-time, reclaim/adoption/requeue,
scan, producer, concurrent, huge, or general owner-exit case is not this route;
collection, private-list, or mapping-release ambiguity retains the sole owner.

`DynamicThreadExitDrain::abandon_full_medium_pages` is a third, separately
typed post-TLS dynamic aggregate boundary. It admits exactly two or more full
`MemoryKind::Arena` `PageKind::Medium` members in `BIN_FULL`, each with its own
rounded block size and regular bin, `reserved > 1`, `used == reserved`, zero
retirement countdown, empty local free list, exact arena span, and exact
dynamic bitmap/count capability. Every other queue/direct entry is empty. It
preserves source force -> false collection -> full-queue removal -> page-count
decrement -> unmapped abandonment for every member. The returned
`DynamicThreadExitFullMediumPagesRoute` stores no raw former-Theap member
pointer or per-member mapped state: each sequential canonical free re-resolves
PageMap, claims its member's source low owner bit, then selects that member's
exact dynamic bitmap/count capability and unmapped or mapped full-medium
failed-reclaim tail. It publishes that member's pair only after its own
mostly-used boundary. A terminal free releases only that member through PageMap
-> dynamic ordinary bit -> metadata -> arena slices; the final member returns
the empty drain for existing root/list/key teardown. Sole, mixed-class,
non-medium, OS-backed,
preexisting queue/direct state, allocation-time, reclaim/adoption/requeue,
scan, producer, and concurrent cases reject before detach; a collection fault
retains the drain.

`DynamicThreadExitDrain::abandon_full_large_pages` is a fourth, separately
typed post-TLS dynamic aggregate boundary. It admits exactly two or more full
`MemoryKind::Arena` `PageKind::Large` members in `BIN_FULL`, each with its own
rounded block size and regular bin, `reserved > 1`, `used == reserved`, zero
retirement countdowns, empty local free lists, the exact dynamic bitmap/count
capability for every member, every other queue/direct entry empty, and every member's
exact 64-slice arena/PageMap span. It preserves source force -> false
collection -> full-queue removal -> page-count decrement -> unmapped
abandonment for every member. The returned
`DynamicThreadExitFullLargePagesRoute` stores no raw former-Theap member
pointer or per-member mapped state: each sequential canonical free re-resolves
PageMap, claims its member's low owner bit, then selects its exact dynamic
bitmap/count capability and unmapped or mapped full-large failed-reclaim tail.
It publishes that member's pair only after its own mostly-used boundary. A terminal free
releases only that member through PageMap -> dynamic ordinary bit -> metadata
-> its complete 64-slice arena span; the final member returns the empty drain
for existing root/list/key teardown. Sole, mixed-class, non-large,
OS-backed, malformed-span, preexisting queue/direct state, allocation-time,
reclaim/adoption/requeue, scan, producer, and concurrent cases reject before
detach; a collection fault retains the drain.

`DynamicThreadExitDrain::abandon_full_medium_or_large_pages` is a fifth,
separately typed post-TLS dynamic aggregate boundary. It admits a complete
two-or-more member `BIN_FULL` queue only when every member is a full arena
medium or large page and at least one member has each kind. Every direct slot
and other queue must be empty; each member independently proves its rounded
dynamic bin, zero retirement countdown, empty local free list, matching
dynamic bitmap/count capability, and exact one-slice medium or 64-slice large
PageMap span. Source force -> false collection -> full-queue/page-count detach
-> unmapped abandonment runs for each member. The returned
`DynamicThreadExitFullMediumOrLargePagesRoute` retains only the dynamic drain
and count: each sequential canonical free re-resolves its PageMap member,
claims the low owner bit before deriving that member's dynamic map, follows the
normal unmapped or mapped failed-reclaim tail, and releases only that member's
exact PageMap -> dynamic ordinary bit -> metadata -> arena span. The final
release returns the empty drain. Homogeneous queues, small/direct-small,
singleton, OS, malformed spans, allocation-time reclaim/adoption/requeue,
scans, producers, and concurrent routing remain absent.

`DynamicThreadExitDrain::abandon_full_singleton_or_regular_pages` is a sixth,
separately typed post-TLS dynamic aggregate boundary. It admits the complete
two-or-more member `BIN_FULL` image only when it contains at least one full
arena singleton and at least one full arena medium or large page; every direct
slot and other queue is empty. Singleton members independently prove
`BIN_HUGE`, `reserved == used == 1`, and their rounded arena span. Regular
members independently prove their rounded dynamic bin, `reserved > 1`, `used
== reserved`, matching dynamic bitmap/count capability, and exact one-slice
medium or 64-slice large span. Source force -> false collection -> full-queue/
page-count detach -> unmapped abandonment runs for every member. The returned
`DynamicThreadExitFullSingletonOrRegularPagesRoute` retains only the drain and
count: a singleton free takes the raw terminal failed-reclaim tail, whereas a
regular free claims its low owner bit before selecting the normal unmapped or
mapped tail. Each release is limited to its exact PageMap -> dynamic ordinary
bit -> metadata -> arena span. Homogeneous queues, regular-only mixed
medium/large queues, small/direct-small, OS, malformed spans, allocation-time,
reclaim/adoption/requeue, scans, producers, and concurrent routing remain
absent.

`DynamicThreadExitDrain::abandon_full_non_direct_small_pages` is a seventh,
separately typed post-TLS dynamic aggregate boundary. It is exercised only by
the exact ordinary dynamic `true`/`2` fixture, while the production ordinary
page-session boundary remains sealed. It admits exactly two or more full
`MemoryKind::Arena` `PageKind::Small` members across ordinary source bins, each
with its own rounded `SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE`, `reserved > 1`,
`used == reserved`, zero retirement countdowns, empty local free lists, no
direct-cache entry, the exact dynamic bitmap/count capability for every member,
and one exact arena slice/PageMap span per member. It preserves source force ->
false collection -> ordinary-bin removal with the no-op direct-cache update ->
page-count decrement -> unmapped abandonment for every member. The returned
`DynamicThreadExitFullNonDirectSmallPagesRoute` stores no raw former-Theap
member pointer or per-member mapped state: each sequential canonical free
re-resolves PageMap, claims its member's abandoned identity, selects the normal
unmapped or mapped failed-reclaim tail, and releases only that member through
PageMap -> dynamic ordinary bit -> metadata -> one arena slice. The final
member returns the empty drain for existing root/list/key teardown. Sole,
mixed-bin/class, direct-small, `BIN_FULL`, OS-backed, malformed-span,
allocation-time, reclaim/adoption/requeue, scan, producer, and concurrent cases
reject before detach; a collection fault retains the drain.

`DynamicThreadExitDrain::abandon_full_direct_small_pages` is an eighth,
separately typed post-TLS dynamic aggregate boundary. It is exercised only by
the exact ordinary dynamic `true`/`2` fixture, while the production ordinary
page-session boundary remains sealed. It admits exactly two or more full
`MemoryKind::Arena` `PageKind::Small` members across ordinary source bins, each
with its own rounded `block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, `used ==
reserved`, zero retirement countdown, empty local free list, exact dynamic
bitmap/count capability, and one exact arena slice/PageMap span. The complete
rounded `pages_free_direct` image must name every populated ordinary queue
head. It preserves source force -> false collection -> bin-order ordinary-bin
removal -> direct-cache refresh before each page-count decrement -> unmapped
abandonment for every member. The returned
`DynamicThreadExitFullDirectSmallPagesRoute` stores no raw former-Theap member
pointer, cached direct image, or per-member mapped state: each sequential
canonical free re-resolves PageMap, claims its member's abandoned identity,
derives that member's bitmap/count capability, selects the partial-collector
unmapped or mapped failed-reclaim tail, and preserves the just-pushed expected
head through the source accounting lag. A member remains unmapped through
`reserved / 8 + 1` frees; the next may publish only that member's dynamic
bitmap/count pair. A terminal free releases only that member through PageMap ->
dynamic ordinary bit -> metadata -> one arena slice; the final member returns
the empty drain for existing root/list/key teardown. Sole, stale/mixed direct-
cache, mixed class, non-direct-small, `BIN_FULL`, OS-backed, malformed-span,
allocation-time, reclaim/adoption/requeue, scan, producer, concurrent, and
joined-remote nonfull cases reject before detach; a collection fault retains
the drain.

`DynamicThreadExitDrain::abandon_full_medium` is a separate source-unmapped
dynamic handoff. It accepts only the drain's sole full `MemoryKind::Arena`
medium page in `BIN_FULL`, with `reserved > 1`, `used == reserved`, and no
direct-cache entry. Force then false collection precedes full-queue/page-count
detach and ordinary abandoned unown; unlike the nonfull endpoints below, this
does not publish a bitmap at abandonment. The linear
`DynamicThreadExitFullMediumHandoff` follows the failed-reclaim tail for each
client free: it stays unmapped while `mi_page_is_mostly_used` holds, then the
first free beyond `reserved / 8` publishes the matching heap-local
`pages_abandoned[bin]` bit and paired `Heap::abandoned_count[bin]`. The mapped
tail clears that pair before queue-detached PageMap span -> dynamic ordinary
bit -> metadata -> arena-slice release. It is not a reclaim, adoption,
requeue, scan, full-small/full-large, multi-page, or general traversal route.

`DynamicThreadExitDrain::abandon_full_medium_after_force_collect_to_mapped`
is the separate source branch for that same sole full medium `BIN_FULL` member
when exactly one joined remote free exists before owner exit. Force collection
must leave the page linked and marked full with `used == reserved - 1`; false
collection preserves that geometry, full-queue/page-count removal clears the
flag, and mapped abandonment immediately publishes the matching dynamic
bitmap/count pair. `DynamicThreadExitFullMediumHandoff` starts mapped and
allows only sequential failed-reclaim client frees through its ordinary
one-slice terminal release. It does not add normal full-medium unmapped
abandonment, multiple frees, other classes, reclaim, adoption, requeue, scans,
or general dynamic owner-exit traversal.

`DynamicThreadExitDrain::abandon_full_large` is a fifth, separate
source-unmapped dynamic handoff. It accepts only the drain's sole full
`MemoryKind::Arena` large page in `BIN_FULL`, with `reserved > 1`,
`used == reserved`, and no direct-cache entry. Force then false collection
precedes full-queue/page-count detach and ordinary abandoned unown; like the
medium route, this does not publish a bitmap at abandonment. The linear
`DynamicThreadExitFullLargeHandoff` follows the normal failed-reclaim tail for
each client free: it remains unmapped through the source mostly-used prefix,
the first free beyond `reserved / 8` publishes the matching heap-local
`pages_abandoned[bin]` bit plus paired `Heap::abandoned_count[bin]`, and the
mapped tail clears that pair before PageMap -> dynamic ordinary bit -> metadata
-> complete 64-slice arena release. It is not a reclaim, adoption, requeue,
scan, full-small/full-medium, multi-page, or general traversal route.

`DynamicThreadExitDrain::abandon_full_large_after_force_collect_to_mapped` is
the separate source branch for that same sole full large `BIN_FULL` member when
exactly one joined remote free exists before owner exit. Force collection must
leave it linked and marked full with `used == reserved - 1`; false collection
preserves that one-free geometry; full-queue/page-count detach clears its full
flag; then mapped abandonment immediately publishes the matching dynamic
bitmap/count pair. The returned `DynamicThreadExitFullLargeHandoff` begins in
its mapped state and permits only sequential failed-reclaim client frees, which
clear that pair before the same complete 64-slice release. It does not widen
the normal unmapped full-large route to additional frees, other classes,
reclaim, adoption, requeue, scans, or general dynamic owner-exit traversal.

`DynamicThreadExitDrain::abandon_full_non_direct_small` is a sixth, separate
source-unmapped dynamic handoff. It accepts only the drain's sole full
`MemoryKind::Arena` small page in its ordinary regular bin, with
`SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE`, `reserved > 1`,
`used == reserved`, `!page_is_in_full`, and an empty direct-cache image.
Force then false collection precedes ordinary-bin/page-count detach and
ordinary abandoned unown; it deliberately does not publish a bitmap at
abandonment. `DynamicThreadExitFullNonDirectSmallHandoff` takes the normal
failed-reclaim collector for each sequential client free: it stays unmapped
through the same mostly-used prefix, publishes only the matching heap-local
`pages_abandoned[bin]` bit plus paired `Heap::abandoned_count[bin]` on the
first free beyond `reserved / 8`, and clears that pair before PageMap ->
dynamic ordinary bit -> metadata -> arena-slice release. It rejects direct
small before collection, and it neither reclaims, adopts, requeues, scans, nor
covers full medium/direct-small/large, multi-page, or general traversal state.

`DynamicThreadExitDrain::abandon_full_non_direct_small_after_force_collect_to_mapped`
is the separate source branch for that same sole full non-direct-small
ordinary-bin member when exactly one joined remote free exists before owner
exit. Force collection leaves the member linked with `used == reserved - 1`;
false collection preserves that geometry; regular-bin/page-count removal then
immediately publishes the matching dynamic bitmap/count pair. The source
direct-cache update remains a no-op because every direct slot is empty and the
rounded block size exceeds `SMALL_SIZE_MAX`. Its
`DynamicThreadExitFullNonDirectSmallHandoff` starts mapped and allows only
sequential failed-reclaim client frees through its ordinary one-slice terminal
release. It does not add normal full-page unmapped abandonment, multiple frees,
direct-small or other classes, reclaim, adoption, requeue, scans, or general
dynamic owner-exit traversal.

`DynamicThreadExitDrain::abandon_full_direct_small_after_force_collect_to_mapped`
is the separate source branch for that same sole full direct-small ordinary-bin
member when exactly one joined remote free exists before owner exit. Force
collection leaves the member linked with `used == reserved - 1`; false
collection preserves that geometry; regular-bin removal clears its complete
rounded direct-cache range before page-count detachment; then mapped
abandonment immediately publishes the matching dynamic bitmap/count pair. Its
`DynamicThreadExitFullDirectSmallHandoff` starts mapped and allows only
sequential failed-reclaim client frees through the source partial collector,
which clears that pair before its ordinary one-slice terminal release. It does
not add normal full-page unmapped abandonment, multiple frees, non-direct-small
or other classes, reclaim, adoption, requeue, scans, or general dynamic
owner-exit traversal.

`DynamicThreadExitDrain::abandon_full_direct_small` is a seventh, separate
source-unmapped dynamic handoff. It accepts only the drain's sole full
`MemoryKind::Arena` small page in its ordinary regular bin, with
`block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, `used == reserved`,
`!page_is_in_full`, and its complete rounded source direct-cache range naming
the page while every other direct slot is empty. Force then false collection
precedes ordinary-bin removal; that removal clears the entire rounded range
before the Theap page-count decrement, then ordinary abandoned unown leaves
the page unmapped. `DynamicThreadExitFullDirectSmallHandoff` uses the source
partial failed-reclaim collector for each sequential client free. Its retained
just-published head delays the unmapped-to-mapped transition by one client free
relative to the normal full-page classes; the later mapped tail clears the
matching heap-local `pages_abandoned[bin]` bit plus paired
`Heap::abandoned_count[bin]` before PageMap -> dynamic ordinary bit ->
metadata -> arena-slice release. A stale range, non-direct small, additional
page, or collection fault cannot cross the pre-detach boundary. This endpoint
neither reclaims, adopts, requeues, scans, nor covers full medium/non-direct
small/large, multi-page, or general dynamic owner exit.

The same drain has four separately bounded mapped endpoints,
`DynamicThreadExitDrain::abandon_mapped_one_block` for a medium page,
`DynamicThreadExitDrain::abandon_mapped_one_block_large` for a large page,
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
witness and receives only the exact final client free: medium, large, and
non-direct small use the normal collector, while direct small consumes the
partial collector head; each becomes empty before any reclaim branch, clears
the dynamic bit/count pair, then releases the queue-detached PageMap span ->
dynamic ordinary bit -> metadata -> arena slices. The large route validates
its complete 64-slice span before that release. It cannot adopt, requeue, scan,
reclaim the departed Theap, or handle multiple pages or frees.

`DynamicThreadExitDrain::abandon_mapped_two_block_medium` deliberately remains
a distinct post-TLS dynamic handoff. It admits only one sole nonfull
`MemoryKind::Arena` `PageKind::Medium` page with `block_size > SMALL_SIZE_MAX`,
`reserved > 2`, `used == 2`, zero retirement countdown, one regular queue
member, an empty direct-cache image, and no other queue/direct entry. It
preserves source force -> false collection -> regular-queue removal ->
page-count decrement -> non-direct no-op cache update -> mapped
identity/bit/count/unown. Its token retains no client pointer/list: the first
exact canonical free must take `UnownedMapped` and preserve the dynamic
bit/count with one block live; the final free alone may take `Empty`, clear
that pair, and release PageMap -> dynamic ordinary bit -> metadata -> arena
slices. It cannot reclaim, adopt, requeue, scan, retain a general multi-free
route, or cover another page, source class, producer, concurrent free, or
owner-exit traversal.

`DynamicThreadExitDrain::abandon_mapped_medium_pair` is a separate bounded
post-TLS aggregate, not a generic two-page extension of that handoff. It
requires the complete source image to contain exactly two nonfull
`MemoryKind::Arena` `PageKind::Medium` pages in distinct regular bins: one
sole queue member has `reserved > 2` and `used == 2`; the other has
`reserved > 1` and `used == 1`. Every direct entry and every other queue must
be empty. Preflight proves both exact arena spans and dynamic bitmap/count
capabilities before source bin-order force -> false collection -> regular
queue removal -> page-count decrement -> non-direct no-op cache update ->
mapped identity/bit/count/unown. Its
`DynamicThreadExitMappedMediumPairRoute` retains only the drain plus sealed
remaining-page/free counts. Each later canonical free re-resolves its PageMap
member and acquires that page's low owner bit before its memory/size chooses
the matching dynamic bitmap/count pair; `UnownedMapped` retains the route,
while `Empty` releases only that queue-detached member through PageMap ->
dynamic ordinary bit -> metadata -> arena slices. The final release returns
the empty drain. It retains no raw page, bin, bitmap, or client list and adds
no scans, reclaim/adoption/requeue, allocation-time, producer, concurrent, or
general owner-exit authority.

`DynamicThreadExitDrain::abandon_mapped_two_block_large` is a separate
post-TLS dynamic handoff, not a widened medium or small token. It admits only
one sole nonfull `MemoryKind::Arena` `PageKind::Large` page with
`MEDIUM_MAX_OBJ_SIZE < block_size <= LARGE_MAX_OBJ_SIZE`, `reserved > 2`,
`used == 2`, zero retirement countdown, one regular queue member, an empty
direct-cache image, and an exact 64-slice arena/PageMap span. It preserves
source force -> false collection -> regular-queue removal -> page-count
decrement -> large no-op direct-cache update -> dynamic
identity/bit/count/unown. Its private first/final-free state requires the
first exact canonical free to return `UnownedMapped`, retain the dynamic
bit/count and every span mapping with one block live, and permits only the
final free to return `Empty`, clear that pair, and release PageMap -> dynamic
ordinary bit -> metadata -> all 64 arena slices. Medium/non-direct-small
normal collector siblings, direct-small's partial collector, one or three live
blocks, another source member, stale direct-cache state, reclaim/adoption/
requeue/scans, producers, concurrent routing, and general owner-exit traversal
remain out of scope. Any collection error or post-collection shape/span/queue
mismatch poisons the retained drain rather than exposing a retryable different
source classification.

`DynamicThreadExitDrain::abandon_mapped_two_block_non_direct_small` is a
separate post-TLS dynamic handoff, not a widening of the medium token. It
admits only one sole nonfull one-slice `MemoryKind::Arena` `PageKind::Small`
page with `SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE`, `reserved > 2`,
`used == 2`, zero retirement countdown, one regular queue member, and an empty
direct-cache image. It preserves source force -> false collection -> ordinary
queue removal -> page-count decrement -> non-direct no-op cache update ->
dynamic identity/bit/count/unown. Its private first/final-free state requires
the first exact canonical free to return `UnownedMapped` while retaining the
dynamic bit/count and the final free alone to return `Empty`, clear that pair,
and release the PageMap -> dynamic ordinary bit -> metadata -> one arena slice.
Direct-small's rounded cache-range collector, medium/large geometry, one or
three live blocks, another source member, reclaim/adoption/requeue/scans,
producers, concurrent routing, and general owner-exit traversal remain out of
scope.

`DynamicThreadExitDrain::abandon_mapped_two_block_direct_small` is a separate
post-TLS dynamic handoff, not a widening of the normal small token. It admits
only one sole nonfull one-slice `MemoryKind::Arena` `PageKind::Small` page with
`block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, `used == 2`, zero retirement
countdown, one regular queue member, its complete rounded direct-cache range
naming that page, and every other direct entry empty. It preserves source force
-> false collection -> ordinary queue removal -> exact direct-range clear ->
page-count decrement -> dynamic identity/bit/count/unown. Its private
first/final-free state deliberately does not model `used` as `2 -> 1`: the
first exact canonical free returns `UnownedMapped` while the direct partial
collector leaves its just-published head atomic, so the observed count remains
two and the dynamic bit/count remains set. Only the final free supplies the
next head, consumes the retained predecessor plus final head, returns `Empty`,
clears that pair, and releases PageMap -> dynamic ordinary bit -> metadata ->
one arena slice. Non-direct-small's normal collector, stale/mixed cache images,
one or three live blocks, another source member, reclaim/adoption/requeue/
scans, producers, concurrent routing, and general owner-exit traversal remain
out of scope.

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
medium/large/non-direct-small/direct-small one-block handoffs above likewise
have no adoption/reclaim/requeue or general
dynamic traversal. General producer routing, multiple arena images, OS-list
traversal/reclaim/requeue, and general heap destruction remain deferred.

`PrivateLock` preserves the TLD field's private-lock meaning but is not a
byte-identical pthread mutex, so no C `sizeof(mi_tld_t)` claim is made.
General cached-root switching/reference ownership, general remote-free/page
routing or abandonment integration beyond these bounded handoffs, full
heap/Theap/arena/subprocess APIs,
pthread/process hooks, general fork repair beyond the limited no-page
quiescent-child case, process shutdown, and general lock destruction remain
outside this slice.

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
OS-aligned singleton handoffs, full-singleton/homogeneous-full-OS-singleton/full-medium/full-large/
full-non-direct-small/full-direct-small aggregates, and the separate dynamic sole full-medium, full-large,
full-non-direct-small, and full-direct-small handoffs above; all other
initially-unmapped pages retain the raw terminal decision for a later
lifecycle. A test-only Loom model executes the
live-owner remote-head publication/detach loops and the abandoned
owner-claim/unown races under bounded schedules; deterministic native
regressions cover the bitmap-field quiescence and full one-page abandonment
interleavings. A dedicated pinned-target probe proves that the TLS
roots are hidden `STT_TLS` objects accessed through initial-exec relocations
without `__tls_get_addr`; its negative control explicitly clears the
production target flags and proves the pinned compiler default emits TLSDESC.
Rust has no per-static model annotation. The private
runtime bridge therefore makes initial-exec target-wide in `.cargo/config.toml`
and in `scripts/build_owned_sysroot.py`'s sealed runtime flags. The sysroot
builder then checks the actual post-LTO static runtime root by name:
`THREAD_LIFECYCLE` must be a nonzero local `STT_TLS` object with the exact
TLSIE relocation pair, while dynamic-TLS forms are rejected. It separately
checks the final shared `libc.so` for `R_AARCH64_TLS_TPREL64` and rejects
TLSDESC and `__tls_get_addr`. The probe remains a narrow compiler negative
control; the named static-root and final-shared-ELF audits bind this specific
private lifecycle to the installed production images. These slices do not
provide page-bearing allocator thread lifecycle, general terminal page
release, or metadata reuse while a remote producer can exist.
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

The production integration profile is Linux/AArch64 little-endian, with Linux
5.10 as the kernel floor and support for valid Linux/AArch64 page sizes. The
user has explicitly reopened a second, native Linux/x86-64 little-endian
parity profile for the fixed allocator port. That profile is evidence-only:
it has no public `crabc` allocator integration or default-promotion claim,
must run on native x86-64 Linux, and must not use AArch64 emulation. RISC-V,
macOS, Windows, big-endian, 32-bit, and portability scaffolds remain out of
scope. Both allocator profiles must be `#![no_std]`, must not depend on
`alloc` or libc, and must not compile C or C++ in the production allocator.

The x86-64 profile's bounded artifact evidence separately compiles the pinned
normal-release static source set, observes its archive members, and compiles
the upstream `src/static.c` override object before compile-linking two selected
consumers. That is neither consumer execution nor a CMake configure/install or
behavior claim. Its separate 13-field unmapped-full-medium differential uses a
real pinned-C full-queue page and public `mi_free` to observe the source
threshold reabandon/map publication tail. The Rust record intentionally models
only `abandoned::free_unmapped_after_failed_reclaim` after the reclaim decision
has failed, using synthetic metadata; it is not a Rust full-medium routing,
owner-exit, general abandonment, or public API claim. A separate 18-field
post-Theap-teardown lane uses a real pinned-C worker `mi_thread_done()` followed
by `pthread_join()` before consumer `mi_free`, and observes PageMap, ordinary
arena-page bitmap, and exact 8-slice-span release after the final free. The Rust
side remains one bounded process-owned mapped regular handoff with equivalent
release observations; it does not claim general thread exit, routing/concurrency,
adoption/reclaim, public behavior, backend, public x86, or AArch64 support.
The retired-page prepass is only a narrow antecedent to broader
retirement/teardown/routing work, not a general lifecycle result.
The separate 25-field aggregate post-exit lane is likewise bounded: it starts
with exactly two distinct live nonfull medium pages in distinct bins: one real
worker runs `mi_thread_done()` and returns, then the consumer calls
`pthread_join()` before proving only the second-first selective terminal release while the
first page remains
registered, bit-set, mapped-abandoned, and `used == 1`, followed by the first
terminal release and empty route. It is not general teardown, routing,
concurrency, public API/runtime, backend, public x86, or AArch64 evidence.

The port preserves mimalloc v3.5.0's algorithms, data structures, memory
orderings, lifecycle behavior, and valid-program observable behavior until
parity is established. It is not permitted to replace those mechanisms with
more idiomatic but materially different Rust algorithms. Any such divergence
requires all of the following before acceptance:

- a written design note explaining the upstream behavior and the divergence;
- deterministic differential evidence against the exact pinned C source; and
- performance and memory evidence on the same native architecture profile
  showing that the divergence is justified.

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
its compiler-resistant primitive. The selected production Linux/AArch64 external graph
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
or fat-LTO consequence. The native x86-64 profile requires the same dependency
graph to be checked independently for `x86_64-unknown-linux-musl`; passing that
check does not make the x86 profile a production backend.
`scripts/check_structure.py` pins this test boundary and rejects any
additional allocator dev-dependency.

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

Track the outcomes separately for each architecture profile:

1. AArch64 readiness to back crabc's `malloc` family without changing its C
   ABI;
2. parity for every Linux/AArch64-applicable public mimalloc v3.5.0 `mi_*`
   interface and compile-time mode; and
3. native x86-64 parity for the explicitly selected mimalloc profile.

The x86-64 parity outcome is never a libc-readiness or public-platform
outcome. It cannot promote an x86 allocator backend or change the public
Linux/AArch64 support boundary.

No outcome follows from basic allocation tests. Promotion requires focused
invariants, layout/configuration probes, upstream-test evidence, deterministic
C differential traces, concurrency-model evidence, fault injection,
process-isolated misuse tests, pthread/TLS/fork and ABI/interposition tests,
and real-program/corpus evidence. It also requires C-vs-Rust throughput,
latency, RSS, virtual-mapping, startup, and allocation-path evidence on the
same native architecture measurement contract. See
[`compat/allocator/README.md`](../../compat/allocator/README.md) and
[`docs/design/performance.md`](performance.md).

The current C backend remains the default until every stated correctness,
memory, latency, throughput, ABI, TLS, fork, and real-program gate passes.
