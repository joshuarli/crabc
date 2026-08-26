# Project status

The general Linux/AArch64 little-endian runtime profile is closed. One active,
narrowly scoped compatibility program is open on two explicit profiles: the
Linux/AArch64 production-oriented track and the native Linux/x86-64
little-endian parity/evidence track. The x86-64 track does not reopen public
`crabc` platform support, x86 libc/loader/`crabc-rs` support, public allocator
integration, or default-backend promotion. Both tracks are the
provenance-preserving Rust semantic port of fixed mimalloc v3.5.0 defined by
[`docs/design/allocator.md`](docs/design/allocator.md) and measured through
[`compat/allocator/README.md`](compat/allocator/README.md). It does not reopen
allocator invention, emulation, or a generic portability layer.
[`COMPATIBILITY.md`](COMPATIBILITY.md)
remains the generated record of current compatibility evidence and
measurements; it is not edited by hand.

The Rust-owned Linux/AArch64 application CRT/sysroot is also complete current
evidence. `./scripts/dev.sh sysroot` produces two clean reproducible installed
trees with `crabc-cc`, Rust CRT objects, Rust compiler helpers, the canonical
crabc loader, and explicit source/dependency/link/artifact purity accounting.
`./scripts/dev.sh lua` consumes that installed tree for the pinned Lua
source-build gate; the static pthread/TLS gate and static integration fixtures
do the same. This completed boundary is documented in
[`docs/design/crt-and-sysroot.md`](docs/design/crt-and-sysroot.md). It is
precisely **CRT/sysroot** purity: the report keeps complete target-runtime
purity `blocked_by_native_allocator` until the separate mimalloc port replaces
the current `libmimalloc-sys` backend. The sole recorded native closure is the
pinned allocator source and its direct pinned `cc` compiler-discovery helper;
the sysroot audit rejects any other native production input, including
compiler-rt target objects.

The same native x86-64 profile has a 75-field direct C/Rust fundamental trace
that includes the fixed no-padding `mi_expand` nonzero null-pointer, zero-size,
below-half, exact-fit, oversize, and state-preservation cases plus checked
`mi_recalloc` growth/tail-zeroing, zero-product, and overflow-preservation
outcomes. This remains private engine evidence, not public allocator API or
AArch64 production evidence.

It also has one separate 25-field native C/Rust differential for two
live-owner remote-free publications from one quiescent `pthread` followed by
the pinned private owner false collector. It proves only the source-specific
owner-bit, LIFO, exact-used-count, and post-join local-list merge transition;
it is not general remote-free routing or concurrent collection, abandonment,
thread teardown, public `mi_*` API, libc integration, backend, or AArch64
evidence.

The same native x86-64 profile separately has a 28-field C/Rust differential
for one real small direct-cache page filled to its current capacity, one
joined/quiescent `pthread` remote free, and the owner direct-cache miss falling
through the regular queue search to collect and reuse that exact block. Its
selected normal-release source API assessment also records per-item native
object/dynamic-symbol presence for 194 distinct C functions and marks 183
non-object source forms explicitly. A separate eight-field C/Rust differential
now covers one arena-backed mapped page's queue-detach abandonment and
same-origin nonempty `mi_free` reclaim/requeue transition. A separate 18-value
C/Rust differential covers one arena-backed, same-origin, one-thread nonfull
medium page. The pinned-C next same-heap allocation claims its exact
mapped-abandoned PageMap/ordinary-arena-bitmap-preserved page, clears
bitmap/count state, restores original-Theap association, and requeues it at
the regular tail; Rust models that claim/reassociation with its test-only
consuming handoff immediately before its matching third allocation. This is
private native x86 evidence only, not general or cross-thread
abandonment/adoption, public API/runtime behavior, backend promotion, public
x86 support, or AArch64 evidence. A separate
32-value C/Rust differential covers one arena-backed, same-origin,
same-thread/same-Theap nonfull 1024-byte direct-small page with two live
blocks. `_mi_page_abandon` clears its complete rounded direct-cache range while
retaining PageMap and ordinary-arena-bitmap registration; the pinned C next
same-heap `mi_heap_malloc_small` claims that exact mapped-abandoned page,
clears bitmap/count state, restores the original Theap, requeues at the
regular tail, restores the full range, and allocates the third block. Rust
explicitly consumes its private test-only handoff immediately before its
matching third allocation rather than making generic allocation scan abandoned
pages. This remains private native x86 evidence only, not general or
cross-thread abandonment/adoption, remote routing, lifecycle, public API/runtime
behavior, backend promotion, public x86 support, or AArch64 evidence. A separate
six-mode staged public-header gate compile-links selected C/C++ forms against
the pinned C release shared object, including one C11 compile/link-only probe
that instantiates the five base-header `*_csize` static-inline dispatch helpers,
and records all ELF identities. A further
two-mode static gate observes every selected static archive member and the
`src/static.c` override object's required symbols before C consumer
compile/linking. A separate native CMake gate configures, builds, and installs
the selected normal-release shared profile with Unix Makefiles and musl; it
records resolved cache/compiler selections, installed header bytes and manifest,
and shared-object ELF, SONAME, and dynamic-dependency identity. It does not
compile/link or execute a consumer, establish behavior or Rust implementation
parity, cover static/object or unselected CMake modes, or create public x86 or
AArch64 runtime support. A separate 13-field C/Rust differential covers one real C
full-medium arena page forced from the full queue to unmapped abandonment, then
through the `mi_free` threshold that republishes its mapped bitmap; its Rust
side exercises the same bounded real post-Theap-teardown full-medium route.
A separate 18-field C/Rust differential uses a real pinned-C worker `pthread`
to run `mi_thread_done()` and return; the consumer calls `pthread_join()`
before its two public `mi_free` calls. It records the selected mapped failed-reclaim/unown
transition and terminal checks for
`page_map_unregistered_after_final_free`,
`arena_page_bitmap_clear_after_final_free`, and
`arena_slice_released_after_final_free` on the exact eight-slice medium-page
span. Rust covers only one bounded process-owned mapped regular handoff after
teardown and directly observes its PageMap, ordinary arena-page bitmap, and
free-slice bitmap release.
A separate 21-field native x86-only C/Rust differential is a retired-page
prepass: a real worker-local `mi_free` retires one medium page, real
`mi_thread_done()` and `pthread_join()` force-release it before one distinct
live medium page is mapped-abandoned, and one consumer `mi_free` terminally
releases the live page. It records retired/local-retirement state, retired
teardown PageMap/ordinary arena bitmap/exact slice-span release, then live
mapped-abandoned and terminal PageMap/ordinary bitmap/exact slice-span release
plus an empty route. This is a narrow private native x86 engine antecedent and
does not claim general retirement, teardown, routing or concurrency, public
`mi_*` behavior, libc integration, backend promotion, public x86 support, or
AArch64 evidence.
A separate 25-field native x86-only C/Rust differential covers exactly two
distinct live nonfull medium arena pages in distinct bins. The real worker runs
`mi_thread_done()` and returns; the consumer calls `pthread_join()` before any
free. Both selected pages are mapped-abandoned after teardown. The consumer
frees the second page first and
records only its PageMap unregister, ordinary arena-page bitmap clear, and
exact slice-span release while the first remains PageMap-registered,
arena-bitmap-set, mapped-abandoned, and `used == 1`; the final consumer free
releases the first page and records an empty route. This is a narrow private
native x86 engine trace, not general teardown, routing or concurrency, public
`mi_*` behavior or runtime, libc integration, backend promotion, public x86
support, or AArch64 evidence.
A separate 46-field native x86-only C/Rust differential covers two distinct
clients on one nonfull medium arena page A plus a one-client medium arena page
B in a distinct bin. The real worker runs `mi_thread_done()` and returns; the consumer
calls `pthread_join()` before any free. Both selected pages are mapped-abandoned
after teardown. The first A free returns `StillLive`, preserving A, B, and the
route; the B free returns `ReleasedPage`, terminally releasing only B; and the
second A free returns `ReleasedAll`, completing the route. This remains narrow
private native x86 engine evidence, not general teardown, routing or
concurrency, public `mi_*` behavior or runtime, libc integration, backend
promotion, public x86 support, or AArch64 evidence.
A separate 53-field native x86-only C/Rust differential covers two distinct
clients on one nonfull medium arena page A plus a one-client medium arena page
B in the same bin. The real worker fills A before it creates B, locally
restores A to two clients, runs `mi_thread_done()`, and returns; the consumer
calls `pthread_join()` before every free. It proves the selected same-bin
queue count/link/saved-successor traversal before teardown and mapped-abandoned
count/bitmap transitions `2 -> 2 -> 1 -> 0`. A's first free returns
`StillLive`, B's free returns `ReleasedPage`, and A's second free returns
`ReleasedAll`. This remains narrow private native x86 engine evidence, not
general teardown, routing or concurrency, public `mi_*` behavior or runtime,
libc integration, backend promotion, public x86 support, or AArch64 evidence.
These bounded results do not claim general routing or concurrent collection,
general behavior or Rust implementation parity, a Rust full-medium route, general
abandonment/adoption, cross-thread reclaim, general thread teardown, CMake
unselected-mode coverage, consumer execution, public API/runtime support, libc integration,
backend promotion, public x86 support, or AArch64 evidence.

The allocator program currently has one bounded executable vertical slice:
an explicit pinned default theap can allocate, reallocate, and locally free
small, medium, large, singleton, aligned, and offset-aligned blocks from a
caller-managed external arena and page map. Large alignments use separately
owned OS singleton mappings below the source's 256 MiB metadata limit, with
allocation-free retry ownership when an injected terminal unmap fails. The
slice includes checked counted allocation, full-page retention, retirement,
and one private linear scoped `RemoteFreeProducer` for an exact active matching
regular non-huge-bin or `BIN_FULL` allocation. Its exclusive owner borrow
prevents safe allocator mutation while a scoped `Send`/`!Sync` worker may
publish the canonical block or cancel back to the original client pointer.
After caller-proved joined/quiescent publication, regular generic search
(including a small direct-cache miss) consumes the remote list before extension
or full classification, and the non-abandoning full-page pass consumes it
before exact release-or-unfull. Every non-abandoning move to `BIN_FULL` also
performs the source's post-enqueue false-force collection. Detached metadata
sessions have no remote producer path and perform only the local false-force
portion. Any false-force collection error permanently poisons this private
allocator, retaining the exact page, error, and any already-popped block; all
later allocation, inspection, free, producer preparation, and collection
entry points reject without further queue or page-map mutation. This bounded
slice also retains unregister-before-release and injected rollback. Unpinned
external arenas now schedule the pinned 4-second `purge_decommits=1` path
before slice reuse. Forced collection claims the free bitmap while applying a
non-owning decommit, preserves the external mapping owner, and retains retry state after
an injected decommit failure. The ordinary allocator gate
matches 447 Rust-owned layout/configuration values, 378 address-independent
small-allocation trace values, and 51 fundamental-operation values against
exact pinned C v3.5.0. The native x86-64-only 75-field expansion extension
recorded above does not revalidate this AArch64 production-oriented result.
A standalone default-off test package now exports 16
strictly prefixed `crabc_test_*` symbols, passes the existing crabc allocator
fixture, and passes 33 reviewed checks from pinned upstream `test-api.c` in an
explicit creating-thread lifecycle. It exports no `malloc`, `mi_*`, or other
production allocator symbol. Separately, the bounded production metadata-owner
prerequisite from `src/subproc.c:19-88` now has one process-static detached
theap backed by direct OS page-map and external-arena bootstrap state. It
requires a caller-supplied frozen `MemoryConfig`, checks a live AArch64 thread
pointer before its private lock, preserves `MemoryId::Malloc` owner-bound
capabilities, and leaves compiler-TLS roots untouched. It supports zeroed and
aligned zeroed allocation, source-ordered replacement, and serialized
cross-thread free, with deterministic retryable and retained initialization
failure states. It neither attaches a live TLD/theap nor implements the
source's null/needs-no-free/non-Malloc release paths. This is not a production
backend or readiness claim. The active allocator scope includes the exact AArch64
16-bit-index/48-bit-generation TLS key and caller-owned slot contract, its
older caller-storage registry substrate, and one allocator-owned process-global
regular-key registry; five private compiler-TLS roots with direct `TPIDR_EL0`
identity; live-owner and
abandoned-page remote-free head transitions; one private scoped active regular
or full remote producer and caller-proved joined/quiescent false-force regular
candidate/full-collection paths (with the detached no-remote local branch);
a one-page mapped/unmapped
abandonment/adoption protocol with failed-reader bitmap restoration,
clear-once-set quiescence, and the failed-reclaim expected-head/unown tail; an
unsafe current-thread-only regular TLS backing
owner; one bounded source-order process-main initializer; one ticket-zero
process-static main heap/default-Theap attachment; one no-page later-thread
attachment to that shared main Heap; one process-static page-map root
publication owner plus one caller-selected, process-shared single-arena
sidecar; bounded ticket-zero and later-thread page engines over that matched
process pair; one all-free later-main thread-exit drain; nine sole-page
later-main owner-exit handoffs (a full arena singleton, an OS-aligned
singleton that links through `Heap::os_abandoned_pages` and removes that list
member before clipped PageMap/alias/metadata/mapping release, a mapped medium page
with one live block, full medium and full large `BIN_FULL` pages plus full
non-direct-small and direct-small regular-bin pages that remain unmapped until
their mostly-used free boundary then reabandon to the static-main bitmap, and a sole nonfull
small-or-medium page whose process-owned route survives old-Theap/TLD teardown,
and a separately bounded exactly-two-block large page whose complete 64-slice
PageMap span and leading static-arena bit survive until its second client free,
including exact full-medium, full-large, full-non-direct-small, and
full-direct-small predecessors where one joined remote free is force-collected
before immediate mapped publication (the medium and large pages remain in
`BIN_FULL`; the non-direct-small page remains in its ordinary bin with every
direct slot empty; the direct-small page remains in its ordinary bin until its
rounded direct-cache range is cleared during removal));
and seven separate later-main full-page aggregate post-exit routes: full arena
singleton, full OS singleton, full-medium, full-large, and bounded mixed
medium/large `BIN_FULL` members, plus full non-direct-small and direct-small
members across ordinary bins. The
arena singleton route admits each member's own rounded
`PageKind::Singleton` size with `reserved == used == 1`; the non-direct route requires
`SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE` and every direct slot empty;
the direct route requires `block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, and
the complete direct-cache image naming every populated queue head. The direct
route advances each affected range before its page-count detach and uses
free.c's partial collector; both retain one exact arena slice per member.
Alongside them is one aggregate
regular-pages post-exit registry that can route every qualifying surviving
regular small, medium, or large page through sequential client frees. No full
aggregate keeps a separate raw member registry: each later free re-resolves
its PageMap member. The OS aggregate's private Heap list deliberately reuses
member links until that exact free removes them. The arena singleton aggregate
must take the raw empty failed-reclaim result
and has no static-main abandoned bitmap/count pair; every regular aggregate
independently crosses the source unmapped-to-mapped threshold under its exact
static-main bitmap/count pair, while the large route also proves
each terminal member's complete 64-slice span. When the completed nonfull
aggregate traversal itself
releases every other member and leaves exactly one initial nonfull medium with
an immediate local head, it returns the existing one-page mapped route before
registry construction; multi-member routes and routes later reduced to one
member remain sequential client-free-only. A fresh later-main owner can
explicitly reclaim a sole mapped medium route that began owner exit nonfull, or a sole
direct-small route that retains an immediate local free block, the exhausted
fully committed scalar-extension shape, the exact exhausted prefix-covered
extension shape, or the exact exhausted on-demand page-area-commit shape after
source collection; all force-collected full-origin predecessors remain
sequential client-free-only. The reserved fixtures cover both medium and
direct-small prefixes, prefix-covered direct-small reuse without a direct
commit, direct page-area commitment, and failed-commit mapped reabandonment
before a same-candidate retry; non-direct-small, malformed or out-of-profile
no-immediate direct-small metadata, and aggregate registry members remain
sequential client-free-only.
The regular owner uses the process-static metadata allocator for the exact
flexible `mi_thread_locals_t` request, source growth rule, header-before-root
publication, generation-checked regular slots, and free-before-dynamic-root-
null teardown. It leaves fast/default/cached roots alone and becomes terminal
after an internal metadata error whose consumption cannot be distinguished,
rather than claiming a false retry capability. The allocator-owned registry
uses the selected main subprocess's aligned Malloc metadata route for one
retained typed bitmap image (plus one temporary replacement while locked),
grows by 1,024 bits through the 64,512-bit/63-block source ceiling, and keeps
`BitmapView` transient under its private registry lock. Ordinary claim uses
`tseq = 0`, advances generation
only after a one-bit claim, and copy growth preserves old claims before marking
only the appended range free. Linear leases require explicit release; bounded
shutdown refuses live leases and late access without writing compiler TLS or
attaching a key to a thread. Allocation failure before commit preserves state;
typed-image invariant or post-commit ownership ambiguity terminally poisons
with retained process-static ownership. This is not the source's full process
shutdown, fast-key management, or key-to-thread integration. Separately,
`subproc.rs` holds one bounded process-static main-subprocess identity: only
relaxed `thread_total_count`, relaxed live `thread_count`, the real first
static TLD slot, and a Rust-only first-ticket selector—not full
`mi_subproc_t`, its heaps/arenas/stats, or a general process-init API. The
unsafe current-thread TLD owner receives an old-counter-value ticket only after
that selector chooses the generic branch; static startup reserves ticket zero
instead. Metadata failure consumes a later source sequence but never a live
registration. The generic TLD image records the same main identity as detached
metadata bootstrap state and its selected arena registry/published arena,
direct `TPIDR_EL0`, Linux NUMA, the exact Unix non-threadpool result, a null
theap list, and exact provenance. It remains **subprocess-attached, no-theap**.

`process_init.rs` is a deliberately bounded source-order coordinator. After a
pure root/current-thread preflight, it reserves static ticket zero, initializes
the static `Heap`, prepares detached metadata without exposing metadata's
private map/arena, publishes the distinct process PageMap, and then attaches
the static TLD/Theap roots. Its `ProcessMainReadyLease` is immutable and it
does not choose options, reserve the process-shared arena, initialize
pthread/TLS keys, route allocation/free, or implement shutdown/fork.
Preflight failure remains cold; every failure after static selection retains
the process image rather than reopening ticket zero.

`runtime_lifecycle.rs` is the intentionally smaller production bridge over
those no-page owners. `__libc_start_main` invokes it after initial TLS and the
stack guard but before constructors, retaining the ticket-zero owner and its
main-thread-minted `MainStaticHeapLease` for the process lifetime. A pthread
child attaches before its user routine; its parent waits for that result and
returns `EAGAIN` if attachment fails. Normal return, `pthread_exit`, and
cancellation finish only after libc cleanup and TSD destructors. The bridge
itself exposes no C symbol, uses no pthread key, routes no C allocation, and
leaves `libmimalloc-sys` as the active backend with its existing private key
outside the 128-key application capacity. The main owner is retained at normal
exit. On libc's direct `fork` path, a private allocation-free gate preserves a
copied no-page process owner only for the original ticket-zero `TPIDR_EL0`
image with zero live or retained later bridge owners; that child can attach a
fresh pthread. Any other child disables the bridge without attempting lock,
root, page, or general fork repair.

The adjacent permanent ticket-zero page owner remains outside that production
bridge. `compat/allocator/runtime-ticket-zero-adapter` is a separate `no_std`
C evidence staticlib, not an installed or selected libc
interface: in one fresh process it exports only six prefixed operations
(init with `AT_PAGESZ`, malloc, zalloc, realloc, free, and a pointer-free
worker round trip) against that exact owner. Its fixture proves first-page
activation, realloc prefix copying, zeroing, exact free, the all-free release
of only the Rust PageMap lifecycle lease, one fresh worker's scoped page
engine and normal attachment teardown, same-arena ticket-zero reactivation,
and successful-path `errno` preservation; its symbol audit rejects normal
`malloc`/`free` and `mi_*` exports. The permanent session and arena remain
retained after that handoff, so it has no shutdown, concurrent/general
later-thread route, fork repair, pointer-domain fallback, or backend-promotion
meaning.

`main_theap.rs` is the sole static-TLD exception. It owns one private,
process-static owner whose aligned/address-stable `Heap` and default `Theap`
field slots are current-thread-only (`!Send`/`!Sync`). The coordinator splits
static Heap foundation from ticket-zero attachment so the PageMap stage sits
between them. It preflights dynamic as its immutable empty image, fast as null,
and default/cached as the empty Theap before it consumes ticket zero; rejection
therefore does not advance the counter or touch metadata/mapping. Its main
`Heap` uses kind-only `_mi_memid_create(MI_MEM_STATIC)` provenance (zero
union/flags); the TLD and Theap retain concrete pinned/committed static image
memids. It preserves `_mi_theap_init`'s
copy/TLD/refcount/subprocess/options/TLD-list/random-cookie/Release-heap/
heap-list order, then publishes default followed by fast. Cached and dynamic
remain empty. A busy freshly owned TLD/heap list, subsequent list-attachment
failure, or post-mutation private unlock error is terminal
initialization-invalid-owner handling: the already registered static TLD and
live count remain in process-static storage, roots remain pristine when the
TLD-list attach fails before publication, and no teardown owner is returned.
After exact live-root ownership validation, teardown checks zero pages as a
Rust pre-mutation invariant; that rejection preserves every live
root/list/image and registration. After that check passes, the valid path
matches `_mi_thread_done`'s `src/init.c:448-481` call order: it clears fast
through `_mi_thread_locals_thread_done`, then clears default/cached and
detaches heap then TLD lists under their locks, Release-clearing `theap.heap`,
clears links/TLD/random/cookie/subprocess,
invalidates and quiesces the TLD, then releases live registration and
terminally retires the static TLD slot. A post-root-reset private lock/list
failure, including a post-mutation unlock error, requires invalid concurrency
or a kernel/private-lock failure outside the valid owner contract. It is a
terminal invalid-owner state that retains process-static storage and its live
registration rather than retrying or claiming completed teardown. The
represented `Heap` ends at the source `memid`; its abandoned fields remain
valid zero/deferred state, while one separately bounded static page owner may
install an arena's in-place `pages_main` in its source arena-pages table. This
is not a full C-size or heap API claim.

`main_heap_thread.rs` separately owns the source ordinary later-thread
`_mi_thread_init_with_heap(mi_heap_main())` attachment. A borrow-tied lease
serializes short projections of the live static main Heap; each later owner gets
a nonzero metadata TLD and metadata Theap, links it to that heap, and publishes
default then the fixed fast slot while dynamic remains the immutable count-zero
backing and cached remains empty. It allows overlapping later attachments and
gates static teardown on their linked membership. `main_heap_page.rs` may borrow
one such current owner alongside a matched process map/arena pair: it uses the
same static Heap and the arena's in-place `pages_main`, holds the one map
lifecycle through allocation/free and a joined scoped producer, then returns to
the existing post-user-destructor teardown. It can also consume that engine
into one post-fast-slot exit drain: after user destructors it clears the fixed
fast slot, force-collects every queue (including full), and releases only pages
that become all-free through PageMap removal -> `pages_main` clear -> metadata
retirement -> slice release. The pass continues beyond an earlier live page,
then retains that post-fast-slot owner instead of queue-detaching or abandoning
the general live page. Eight explicit sole-page exceptions remain after
fast-slot clear, each requiring no other queue/direct/page state. The full
one-block arena singleton false-collects, detaches, and unmapped-abandons while
retaining its PageMap lifecycle and registration through its exact final client
free; that failed-reclaim empty result performs PageMap removal -> `pages_main`
clear -> metadata retirement -> slice release. The OS-aligned singleton
exception permits the source `BIN_HUGE` route while remaining semantically full,
even for a small ordinary block size: it links its one `MemoryKind::Os` page in
`Heap::os_abandoned_pages` before unown, removes it before clipped PageMap ->
alias -> metadata -> mapping release, and retains an injected failed-unmap
owner terminally. It provides no OS-list search, reuse, or general routing.
The separate medium regular page exception requires `reserved > 1` and `used == 1`, force- then
false-collects, detaches, and publishes its exact main
`pages_abandoned[bin]` bit plus paired `Heap::abandoned_count[bin]`. Its final
client free takes only the source mapped empty-before-reclaim outcome, clears
that bit/identity, consumes the paired count, and performs the same terminal
release; a still-live result is terminally retained rather than reclaimed or
requeued. Normal full medium and full large `BIN_FULL` exceptions force- then
false-collect, queue/page-count-detach, and deliberately become ordinary
unmapped abandonment before old-Theap/TLD teardown. Their separately bounded
one-joined-remote predecessors collect exactly one free while remaining linked
in `BIN_FULL`, then the same removal clears the full flag and immediately
publishes the mapped bit/count pair; the large mapped route retains its full
64-slice terminal-release proof. The full non-direct small exception follows
the normal unmapped tail but detaches from its ordinary small size bin, requires
`block_size > SMALL_SIZE_MAX`, has no direct-cache range, and uses the ordinary
failed-reclaim collector. The full direct small exception is the complementary
ordinary-bin shape: it requires `block_size <= SMALL_SIZE_MAX`, `reserved >=
16`, `used == reserved`, and the complete rounded source direct-cache range
with every other slot empty. Queue removal clears that range before page-count
detach. Its partial collector retains the just-published atomic head, so the
source free count has its one-head lag before the same below-mostly-used
reabandonment decision. Their normal sequential client frees remain unmapped through
`free <= reserved / 8`; the first
below-mostly-used free publishes the exact static-main `pages_abandoned[bin]`
bit plus paired `Heap::abandoned_count[bin]`, and the mapped tail preserves
that pairing until the same terminal release. The full-large route validates
its complete 64-slice span before release. Separately,
`abandon_full_singleton_pages_to_process_route` accepts only two or more full
arena `PageKind::Singleton` members in `BIN_FULL`; each has its own rounded
block size, `reserved == used == 1`, zero retirement countdown, empty local
free list, exact paired-arena span, and every direct slot and other queue
empty. Source force -> false collection then detaches and unmapped-abandons
every member before old-Theap/TLD teardown. Later canonical client frees
re-resolve and validate PageMap membership without a raw list or static-main
bitmap/count pair, take only the raw empty failed-reclaim outcome, and release
one member in PageMap -> `pages_main` first-bit -> metadata -> arena-slice
order. Sole pages, OS or other non-singleton members, allocation-time
adoption/reclaim/requeue, scanning, and concurrent routing remain absent.
Separately,
`abandon_full_os_singleton_pages_to_process_route` accepts only two or more
`MemoryKind::Os` singleton members in `BIN_FULL`, each with its own rounded
block size, `reserved == used == 1`, zero retirement countdowns, empty local free lists,
valid clipped PageMap/alias release images, every direct slot and other queue
empty, and an initially empty static-main `Heap::os_abandoned_pages` list.
Source force -> false collection -> full-queue/page-count detach -> private
OS-list insertion -> unmapped unown runs for every member before old-Theap/TLD
teardown. Full-queue removal clears `PAGE_IN_FULL_QUEUE`, while the private
list deliberately owns the page's raw intrusive links until an exact later
client free removes that member. Each free re-resolves PageMap membership,
takes only the raw empty failed-reclaim outcome, then releases that one member
in private-list removal -> clipped PageMap -> aliases -> metadata -> mapping
order. A sole page, non-OS member, nonempty initial private list, list
traversal, retry/reclaim/requeue, allocation-time, and concurrent
routing remain absent; collection failure retains the drain and failed `munmap`
retains its `OsAlignedPageOwner` terminally. Separately,
`abandon_full_medium_pages_to_process_route` accepts only two or more full
arena medium members in `BIN_FULL`, each with an independent rounded block
size/bin, every direct slot and other queue empty, zero retirement countdowns,
and an exact paired arena span. Its source force -> false collection then
detaches every member and leaves each source-unmapped before old-Theap/TLD
teardown. Later client frees re-resolve PageMap membership without a raw list,
claim the member low owner bit, then choose that member's exact static-main
bitmap/count capability and unmapped or mapped tail. They release one member at
a time through PageMap -> `pages_main` -> metadata -> slice; a sole full page
rejects before mutation. The separate
`abandon_full_large_pages_to_process_route` has the same bounded aggregate
shape only for `PageKind::Large`: every member has one exact 64-slice
arena/PageMap span, and terminal release proves that complete span before the
same PageMap -> `pages_main` -> metadata -> slice order. The medium route
rejects a mixed class while the large route keeps its large-only full queue
with per-member bins;
neither exposes adoption, reclaim, requeue, allocation-time, or concurrent
routing. Separately,
`abandon_full_non_direct_small_pages_to_process_route` accepts two or more full
arena `PageKind::Small` members across ordinary bins, each with its own
`SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE` and static-main bin, zero
retirement countdown, empty local free list, and exact paired-arena slice.
Every direct slot and `BIN_FULL` must be empty, and no other page class may
occupy a populated ordinary bin. It preserves force -> false collection,
ordinary-bin removal with the proven no-op direct-cache update, page-count
detach, and ordinary unmapped abandonment. Its normal-collector client-free
tail re-resolves each PageMap member, claims its low owner bit before selecting
only that member's paired bit/count and unmapped or mapped tail, and releases
one member at a time. A sole page, direct-small geometry/cache image, mixed
class, or collection failure refuses or retains the route; it grants no
direct-small partial-head, adoption, reclaim, requeue, scanning, or concurrent
authority. The corresponding full non-direct-small and
direct-small aggregate is instead admitted only by
`abandon_full_direct_small_pages_to_process_route`: two or more full arena
`PageKind::Small` members in one ordinary bin with the same rounded
`block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, zero retirement countdowns,
empty local free lists, and one paired-arena slice each. Its complete rounded
direct-cache range names the current ordinary-queue head while every other
direct slot and queue is empty. It preserves force -> false collection,
ordinary-bin removal, direct-cache-head advance before page-count detach, and
ordinary unmapped abandonment. Later frees re-resolve one PageMap member at a
time, keep the partial collector's just-pushed expected head through the source
accounting lag, then independently publish/release only that member's paired
bit/count and one-slice span. Sole pages, stale/mixed cache images, non-direct
geometry, mixed bins/classes, collection failures, adoption, reclaim, requeue,
scanning, and concurrent routing refuse or retain the route. The corresponding
full non-direct-small and
direct-small one-joined-remote predecessors remain linked in their ordinary
bins while force collection makes them nonfull; the former keeps its empty
direct image, while the latter clears its rounded direct range before
page-count detach. Both immediately publish their mapped bit/count pairs and
remain client-free-only through terminal release. The sole nonfull small-or-medium
process route preserves the same
mapped publication, tears down the old Theap/TLD, and routes its linear client
frees through short PageMap access. A separate client-free-only large route
requires exactly two live blocks and retains its complete 64-slice PageMap and
`pages_main` span until the second free. Its sole mapped medium member, or its sole
direct-small member with an immediate local free block, the exhausted fully
committed scalar-extension shape, the exact exhausted prefix-covered extension
shape, or the exact exhausted on-demand page-area-commit shape after source
collection, may instead be
explicitly consumed by a fresh later-main owner after exact
subprocess/configuration/PageMap-root/static-main-Heap/arena/page-identity
preflight: the short map access becomes one long lifecycle, the matching
bitmap/count member is claimed, source abandoned/live collection and Theap
reassociation run, and the page returns at the target queue tail. A direct-
small target restores its complete rounded direct-cache range before target
page-count increment and immediately reuses that same page; its exhausted fully
committed scalar shape extends after tail insertion, its exact prefix-covered
shape retains its prefix count and extends without direct commitment, while its
exact on-demand shape directly commits its page area before
prefix-count/free-list/capacity publication. The medium slice
accepts an immediate head or an exhausted nonfull medium page
(`capacity < reserved`). A fully committed medium page (`slice_pcommitted == 0`)
extends after tail insertion. The bounded test-only `commit == false` fixtures
instead start from real reserved medium and direct-small pages with source
callback-committed prefixes. Their direct `_mi_os_commit`-shape extensions precede both the
monotonic prefix-count update and free-list/capacity writes. A direct-commit
failure repeats source false collection, queue detach, direct-cache/page-count
repair, and mapped identity/bit/count/unown publication, then permits only a
same-candidate retry through the retained long lifecycle. This is not a
production page-on-demand policy or fresh fallback. A bitmap miss, malformed
state, scalar extension error, or other post-transfer failure remains
terminally retained. Non-direct-small and malformed or out-of-profile
no-immediate direct-small metadata remain client-free-only. A direct small member must prove the exact rounded
source direct-cache range before collection; queue removal clears that range
before page-count detach. The route retains the source `reserved >= 16`
small partial-collection invariant and excludes full small pages through its
explicit `used < reserved` guard; the separate full-small exceptions above own
the direct and non-direct classes.

`abandon_mapped_regular_pages_to_process_route` is the bounded source-traversal
extension: before any mutation, every direct slot must match its source queue
head and every queue member must be a nonfull regular small, medium, or large
arena page. Direct small members retain `reserved >= 16` for the source partial
collector; an empty member is admitted only when normal local free left its
source retirement countdown nonzero. The route
then ports `_mi_theap_collect_retired(theap, true)`'s regular-bin pass, so an
already-empty retired span releases before the remaining
`mi_theap_page_collect` / `_mi_page_abandon` decisions: force-collect, release
pages made all-free, false-collect still-live pages, queue detach, direct-cache
refresh, page-count detach, and publish the exact static-main mapped
identity/bit/count pair. Its typed
aggregate registry retains no old-Theap pointer or raw page list; every later
linear client free re-resolves one PageMap entry, selects its bin only after
the source low owner-bit claim, preserves map/bit/count while nonempty, and
re-derives the supported page's complete regular span before the terminal
PageMap -> `pages_main` -> metadata -> slice release on empty. The current
small, medium, and large cases therefore prove their one-, 8-, and 64-slice
releases. The direct-small retirement regression retains the exact rounded
cache image through ordinary local retirement, then proves the source prepass
clears it as the one-slice span releases before a live medium member is
published. If retirement/force collection empties every page, it returns the
ordinary drain. If the completed source traversal instead leaves exactly one
initial nonfull medium page with an immediate local head, it captures that
exact page/span/bin fact before registry construction and returns the existing
one-page mapped route. Its reclaim revalidates the immediate head and cannot
extend, commit, scan, or take a fresh-page fallback. Fresh engines may
serialize independent PageMap operations between client frees, but no current
path can adopt, reclaim, or requeue an aggregate registry member, including a
registry later reduced to one member by a client free. The nonfull regular
registry continues to reject full/singleton/unmapped/huge/foreign pages and
malformed direct-cache images; the separate full-singleton,
full-medium, full-large, non-direct-small, and direct-small aggregates enforce
their route-specific class and geometry preflights; full-medium members may use
distinct rounded bins, while stale direct-cache images and remote-force nonfull
state remain absent. Concurrent client routes, deferred callbacks, arena
collection, and retry/reuse
as a normal allocator remain outside this owner. Only an empty drain permits
`finish_after_page_drain` to reset default/cached, detach its shared heap list
member before its TLD list member, and retire metadata/TLD. A force/release
failure or root/list mismatch remains terminally retained; this is not general
abandonment, later-free/reclaim, concurrent routing, or a `pthread` lifecycle.

The later-main drain also has one separate mixed full singleton/regular route:
`abandon_full_singleton_or_regular_pages_to_process_route` accepts only a
complete `BIN_FULL` image with two or more arena members, at least one
`PageKind::Singleton`, and at least one regular `PageKind::Medium` or
`PageKind::Large`. Singleton geometry remains `BIN_HUGE` with `reserved ==
used == 1`; regular geometry remains ordinary-bin with `reserved > 1` and
`used == reserved`; every direct entry and other queue must be empty. The
source transition force- then false-collects, detaches, and unmapped-abandons
each member before old-Theap/TLD teardown. Its composed route keeps no raw
member list: a singleton takes only the raw terminal-empty tail, while a
regular member claims its low owner bit before selecting its exact static-main
bitmap/count pair and normal collector tail. Each terminal free releases only
its own PageMap -> `pages_main` -> metadata -> exact arena span; the map route
closes only after both source tails release. This does not authorize a general
heterogeneous queue traversal, regular-only mix, allocation-time adoption,
reclaim/requeue, producer, or concurrent-free path.

`process_page_map.rs` owns the global source-page-map prerequisite. It freezes
one `MemoryConfig` and selected main subprocess, initializes a `PageMap` in
its final static slot, and Release-publishes its root exactly once.
`process_arena.rs` retains one caller-selected, complete external in-place
arena mapping and adds one explicit caller-selected regular OS reservation
after binding either form to that same map/root/configuration/subprocess tuple.
The regular entry accepts only a nonzero request that rounds to exactly one
complete arena and normal reserved or committed mapping access; it records
`MemoryKind::Os`. Its separately bounded `reserve_default_os_arena` entry
ports the first lazy `mi_arena_reserve` decision: source max-page headroom, the
frozen 1-GiB Linux/AArch64 default, the overcommit eager-map condition, and the
128-MiB retry after an unpublished attempt returns COLD.
`MainStaticFirstArenaPageAllocator` now calls it only for an empty ticket-zero
Theap's first valid ordinary fresh-page miss: it derives the exact
small/medium/large/singleton span, revalidates the zero-page static image before
mapping, retains the PageMap lifecycle through activation, then delegates to
the established static engine. `ProcessMainThread` is the owner’s only
production-shaped factory, transferring its retained attachment plus the
immutable ready-map witness without reserving or mapping at startup. It is not
called at process startup. An
unpublished metadata failure unmaps that exact regular map before leaving the
sidecar cold for a matching retry, while a failed unmap retains the mapping
terminally. The external entry continues to return an unpublished rejected map
to its caller. A reserved map first enters the final owner slot, so the retained
arena callback commits metadata and later selected ranges through the exact
same `Mapping`; frozen Linux decommit reports no recommit requirement. This
establishes the external-map ownership prerequisite, one bounded first
fresh-page connection, and one narrow paired direct page-area commit operation;
it does not enable existing-arena search, later arena scaling, option mutation,
large-page/exclusive/NUMA policy, page-on-demand policy, or itself maintain
`slice_pcommitted` or page reabandonment.
`ProcessPageArenaLease` proves that exact tuple before `main_static_page.rs`
or `main_heap_page.rs` may bind an already selected source Theap to it. The
private ticket-zero and later-thread engines each hold the only process-map
plain-entry lifecycle for their complete engine and joined scoped producer,
install the arena's embedded `pages_main` bitmap in the shared static Heap, and
use the existing engine's source bitmap -> map publication and map -> bitmap ->
metadata -> slice release order. They reject a foreign subprocess before page
mutation, and an unfinished engine terminally poisons both owners rather than
manufacturing cleanup. Their normal `realloc` delegates preserve source
failure ownership and replacement copying; only the ticket-zero null case may
activate the completed first-arena policy. This remains a caller-initialized, single-arena,
sequential-owner slice. The bounded coordinator can now provide its map
predecessor, the private ticket-zero owner can make the first fresh-page
connection to the completed default reservation, and a completed reservation
can reconstruct only its immutable matching pair for one subsequent bounded
owner. That pair does not scan arenas, select free slices, reserve, or map.
The coordinator still supplies neither
the C static empty-map pre-root, existing-arena search, later automatic arena
reservation, concurrent or general later-thread page routing, general
abandonment/owner exit, process destruction, pthread integration, nor public
allocator routing. Map setup failure is once-terminal rather than a null root
or retry.

`dynamic_theap.rs` adds one private later-ticket current-thread attachment.
It atomically refuses ticket zero, then retains the caller-pinned first-class
Heap, metadata TLD/live registration, typed Malloc Theap, dynamic backing, and
linear regular-key lease. Dynamic `_mi_theap_init` completes TLD-list/random/
cookie/Release-heap/heap-list order, then publishes the regular TLS slot and
the cached root from the canonical empty source image, with the exact dynamic
Theap reference transition `1 -> 2`; default and fast remain unchanged. Begin
rejects any other cached predecessor before ticket issuance. No-page teardown
prevalidates that slot/root/refcount pair, clears the slot and backing, restores
that exact canonical empty cached root with `2 -> 1`, then detaches lists and
frees metadata. Root/list/page failures before mutation leave authority
unchanged; an after-publication or after-root-reset private failure returns a
retained poisoned owner with only known-valid capabilities. The one retryable
exception is a pre-mutation key-release lock error after other teardown: it
retains only the lease until `AwaitingKeyRelease` succeeds. General cached-root
switching/refcount ownership, general remote-free routing/concurrency, general
page routing or abandonment integration, full heap/Theap/arena/subprocess APIs,
pthread/fork/process shutdown, stats/options/callbacks, and public ABI remain
open. Ordinary dynamic begin stores the source abandoning `true`/`2` profile
and rejects a page session. A crate-private unsafe non-abandoning begin instead
stores `false`/`-1` before Release heap publication; its sealed borrowed
`DynamicTheapPageSession` alone instantiates the shared private
`PageAllocatorEngine`. Consuming finish requires a drained page lifecycle, and
an unfinished engine Drop terminally latches the attachment rather than
allowing teardown to claim quiescence.

The exact ordinary `true`/`2` queue image is also admitted through a
`cfg(test)`-only fixture for a source-shaped `MI_ABANDON` aggregate proof. That
fixture leaves `DynamicTheapAttachment::page_session` unchanged: production
ordinary dynamic attachments still cannot create a general page engine.

Its post-TLS `DrainingPages` state is now also a bounded source owner-exit
state, not an alternate allocator. It clears the regular dynamic backing before
page abandonment while retaining the cached root, TLD/Heap list membership,
PageMap, and heap-local arena image. `DynamicThreadExitDrain` first
force-collects an already-retired all-free regular page. Its singleton
transition admits one full one-block arena or OS-aligned page; the source
force-only local-list append is unreachable under its `reserved == used == 1`
and no-producer proof. The raw local-list substrate now separately ports and
tests that force append, including cycle rejection before relinking; the
separately recorded later-main all-free exit drain invokes it, but no current
page-engine lifecycle invokes it for a general traversal. The singleton
handoff queue-detaches and unmapped-abandons its page, then a final client free
necessarily fails reclaim through the cleared regular slot and owns its raw
all-free release. The OS form additionally links/removes its exact dynamic
`Heap::os_abandoned_pages` member around clipped PageMap -> alias -> primary
metadata -> mapping release.

`DynamicThreadExitDrain::abandon_full_singleton_pages` separately admits one
bounded dynamic aggregate: two or more full `MemoryKind::Arena`
`PageKind::Singleton` members in `BIN_FULL`, each with its own rounded block
size, `reserved == used == 1`, zero retirement countdown, an empty local free
list, exact arena span, and no other queue/direct state. It follows source
force -> false collection -> full-queue/page-count detach -> unmapped
abandonment for every member. `DynamicThreadExitFullSingletonPagesRoute`
retains the existing dynamic drain instead of a raw member list or dynamic
bitmap/count pair; each sequential canonical free re-resolves and validates
the PageMap entry, takes only the raw empty failed-reclaim result, and releases
that member through PageMap -> dynamic ordinary bit -> metadata -> arena
slices. The final free returns the empty drain for existing teardown. Sole,
non-singleton, OS-backed, allocation-time, reclaim/adoption/requeue, scan, and
concurrent cases reject before detach; a collection failure retains the drain.

`DynamicThreadExitDrain::abandon_full_os_singleton_pages` separately admits a
bounded homogeneous dynamic aggregate: two or more same-rounded-size full
`MemoryKind::Os` singleton members in `BIN_FULL`, each with
`reserved == used == 1`, zero retirement countdown, empty local free list,
valid clipped PageMap/alias release image, an initially empty dynamic
`Heap::os_abandoned_pages` list, and no other queue/direct state. It preserves
source force -> false collection -> full-queue/page-count detach -> private
OS-list insertion -> unmapped unown for every member.
`DynamicThreadExitFullOsSingletonPagesRoute` retains only the dynamic drain
and member count; every sequential canonical free re-resolves
PageMap, takes only the raw empty failed-reclaim result, removes its exact
private-list member, then releases its clipped PageMap -> alias -> primary
metadata -> mapping image. The final free returns the empty drain for existing
teardown. Sole, arena-backed, mixed-size, non-singleton, preexisting-list,
allocation-time, reclaim/adoption/requeue, scan, producer, concurrent, huge,
and general owner-exit cases reject before detach; collection, list, or mapping
release failure retains the only owner terminally.

`DynamicThreadExitDrain::abandon_full_medium_pages` separately admits a third
bounded dynamic aggregate: two or more full `MemoryKind::Arena`
`PageKind::Medium` members in `BIN_FULL`, each with an independent rounded
block size and regular bin, `reserved > 1`, `used == reserved`, zero retirement
countdown, empty local free list, exact arena span, and matching dynamic
bitmap/count capability. No other queue/direct state is admitted. It follows
source force -> false collection -> full-queue/page-count detach -> unmapped
abandonment for every member. `DynamicThreadExitFullMediumPagesRoute` retains
the existing dynamic drain rather than raw member pointers or per-member mapped
state; each sequential canonical free re-resolves PageMap, claims its member
low owner bit, then selects that member's exact dynamic bitmap/count capability
and unmapped or mapped failed-reclaim tail. It releases that member through
PageMap -> dynamic ordinary bit -> metadata -> arena slices. The final free
returns the empty drain for existing teardown. Sole, mixed-class, non-medium,
OS-backed, allocation-time,
reclaim/adoption/requeue, scan, producer, and concurrent cases reject before
detach; a collection failure retains the drain.

`DynamicThreadExitDrain::abandon_full_large_pages` separately admits a fourth
bounded dynamic aggregate: two or more full `MemoryKind::Arena`
`PageKind::Large` members in `BIN_FULL`, each with its own rounded block size
and regular bin, `reserved > 1`, `used == reserved`, zero retirement
countdowns, empty local free lists, the matching dynamic bitmap/count
capability for every member, no other queue/direct state, and every member's exact 64-slice
arena/PageMap span. It follows source force -> false collection ->
full-queue/page-count detach -> unmapped abandonment for every member.
`DynamicThreadExitFullLargePagesRoute` retains the existing dynamic drain
rather than raw member pointers or per-member mapped state; each sequential
canonical free re-resolves PageMap, claims its member low owner bit, then
selects its exact dynamic bitmap/count capability and unmapped or mapped
full-large failed-reclaim tail, and releases that member through PageMap -> dynamic ordinary bit -> metadata ->
its complete 64-slice arena span. The final free returns the empty drain for
existing teardown. Sole, mixed-class, non-large, OS-backed,
malformed-span, allocation-time, reclaim/adoption/requeue, scan, producer,
and concurrent cases reject before detach; a collection failure retains the
drain.

`DynamicThreadExitDrain::abandon_full_singleton_or_regular_pages` separately
admits one bounded mixed dynamic aggregate: two or more full
`MemoryKind::Arena` members in `BIN_FULL`, including at least one
`PageKind::Singleton` and at least one regular `PageKind::Medium` or
`PageKind::Large` member. Every direct slot and other queue is empty. Each
singleton proves `BIN_HUGE`, `reserved == used == 1`, and its own rounded arena
span; each regular member proves its rounded regular bin, `reserved > 1`,
`used == reserved`, matching dynamic bitmap/count capability, and exact
one-slice medium or 64-slice large span. Source force -> false collection ->
full-queue/page-count detach -> unmapped abandonment runs for every member.
`DynamicThreadExitFullSingletonOrRegularPagesRoute` retains only the dynamic
drain and a count. Each canonical free re-resolves PageMap: singleton members
take the raw terminal failed-reclaim tail, while regular members claim the low
owner bit before selecting their normal unmapped-or-mapped tail. Each releases
only its PageMap -> dynamic ordinary bit -> metadata -> exact arena span.
Homogeneous queues, regular-only mixed medium/large queues, small/direct-small,
OS, malformed spans, allocation-time, reclaim/adoption/requeue, scan,
producer, concurrent, and general owner-exit cases remain absent; a collection
or terminal-release failure retains the sole owner.

`DynamicThreadExitDrain::abandon_full_non_direct_small_pages` separately admits
a sixth bounded per-member dynamic aggregate, proved only through that exact
ordinary source fixture: two or more full `MemoryKind::Arena` `PageKind::Small`
members across ordinary bins, each with its own rounded
`SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE`, `reserved > 1`,
`used == reserved`, zero retirement countdown, empty local free list, exact
one-slice arena/PageMap span, and matching dynamic bitmap/count capability. No
direct-cache entry or `BIN_FULL` member may remain, and a populated ordinary
bin may contain no other page class. It preserves source force -> false
collection -> ordinary-bin removal with the proven no-op direct-cache update ->
page-count detach -> unmapped abandonment for every member.
`DynamicThreadExitFullNonDirectSmallPagesRoute` retains the dynamic drain, not
a raw member list or per-member mapped state. Each sequential canonical free
re-resolves PageMap, claims its abandoned identity, then derives its normal
unmapped or mapped failed-reclaim tail and dynamic bitmap/count capability; it
releases only that member through PageMap -> dynamic ordinary bit -> metadata
-> one arena slice. The final free returns the empty drain for existing
teardown. Sole, mixed-class, direct-small, `BIN_FULL`, OS-backed,
allocation-time, reclaim/adoption/requeue, scan, producer, and concurrent cases
reject before detach; a collection failure retains the drain. This does not
expose ordinary dynamic allocation or a
general owner-exit traversal.

`DynamicThreadExitDrain::abandon_full_direct_small_pages` separately admits a
seventh bounded homogeneous dynamic aggregate, proved only through that exact
ordinary source fixture: two or more full `MemoryKind::Arena` `PageKind::Small`
members in one ordinary bin, with one rounded `block_size <= SMALL_SIZE_MAX`,
`reserved >= 16`, `used == reserved`, zero retirement countdowns, empty local
free lists, exact one-slice arena/PageMap spans, matching dynamic bitmap/count
capabilities, and the complete rounded direct-cache range naming the ordinary
queue head while every other direct entry and queue is empty. It preserves
source force -> false collection -> ordinary-bin removal -> direct-cache
refresh before page-count detach -> unmapped abandonment for every member.
`DynamicThreadExitFullDirectSmallPagesRoute` retains the dynamic drain, not a
raw member list, cached direct image, or per-member mapped state. Each
sequential canonical free re-resolves PageMap, uses its claimed abandoned
identity to select the partial-collector unmapped or mapped failed-reclaim
tail, preserves the just-pushed head through the source accounting lag, and
releases only that member through PageMap -> dynamic ordinary bit -> metadata
-> one arena slice; the final free returns the empty drain for existing
teardown. A member remains unmapped through `reserved / 8 + 1` frees; only the
next may publish its matching dynamic bitmap/count pair. Sole, stale/mixed
direct-cache, mixed-bin/class, non-direct-small, `BIN_FULL`, OS-backed,
allocation-time, reclaim/adoption/requeue, scan, producer, concurrent, and
joined-remote nonfull cases reject before detach; a collection failure retains
the drain. This does not expose ordinary dynamic allocation or a general
owner-exit traversal.

`DynamicThreadExitDrain::abandon_full_medium` separately admits one sole full
`MemoryKind::Arena` medium page in `BIN_FULL`, with `reserved > 1` and
`used == reserved`. It preserves source force -> false collection ->
full-queue/page-count detach -> ordinary unmapped abandonment. Its linear
`DynamicThreadExitFullMediumHandoff` consumes sequential failed-reclaim frees:
the page stays unmapped through the source mostly-used prefix, the first free
beyond `reserved / 8` publishes the matching dynamic `pages_abandoned[bin]`
bit plus `Heap::abandoned_count[bin]`, and the mapped tail clears that pair
before PageMap -> dynamic ordinary bit -> metadata -> arena-slice release.
This one route neither reclaims, adopts, requeues, scans, nor covers full
large, non-direct-small, direct-small, multi-page, or general dynamic owner
exit.

`DynamicThreadExitDrain::abandon_full_large` separately admits one sole full
`MemoryKind::Arena` large page in `BIN_FULL`, with `reserved > 1` and
`used == reserved`. It preserves source force -> false collection ->
full-queue/page-count detach -> ordinary unmapped abandonment. Its linear
`DynamicThreadExitFullLargeHandoff` consumes sequential failed-reclaim frees:
the page stays unmapped through the source mostly-used prefix, the first free
beyond `reserved / 8` publishes the matching dynamic `pages_abandoned[bin]`
bit plus `Heap::abandoned_count[bin]`, and the mapped tail clears that pair
before PageMap -> dynamic ordinary bit -> metadata -> complete 64-slice
arena release. This one route neither reclaims, adopts, requeues, scans, nor
covers full medium/non-direct-small/direct-small, multi-page, or general
dynamic owner exit.

`DynamicThreadExitDrain::abandon_full_medium_after_force_collect_to_mapped`
separately preserves the source full-medium branch with exactly one joined
remote free. The sole `BIN_FULL` page starts with `used == reserved`; force
collection consumes that free but leaves the member linked and marked full with
`used == reserved - 1`; false collection preserves it; full-queue/page-count
detach clears the full flag; and mapped abandonment immediately publishes its
dynamic bitmap/count pair. The returned `DynamicThreadExitFullMediumHandoff`
starts mapped and consumes sequential failed-reclaim frees only, clearing that
pair before the ordinary arena release. It does not add multiple frees, other
classes, reclaim, adoption, requeue, scans, or general dynamic owner exit.

`DynamicThreadExitDrain::abandon_full_large_after_force_collect_to_mapped`
separately preserves the source full-large branch with exactly one joined
remote free. The sole `BIN_FULL` page starts with `used == reserved`; force
collection consumes that free but leaves the member linked and marked full with
`used == reserved - 1`; false collection preserves it; full-queue/page-count
detach clears the full flag; and mapped abandonment immediately publishes its
dynamic bitmap/count pair. The returned `DynamicThreadExitFullLargeHandoff`
starts mapped and consumes sequential failed-reclaim frees only, clearing that
pair before the complete 64-slice release. It does not add multiple frees,
other classes, reclaim, adoption, requeue, scans, or general dynamic owner
exit.

The native x86-only track also has a separate 31-field dynamic full-large
one-remote force-collect-to-mapped differential. A pinned-C worker fills one
sole full `BIN_FULL` large arena page (request 86706, 98304-byte blocks,
capacity/reserved 42, a 64-slice arena span with 63 PageMap-registered source
page-area slices), publishes exactly one joined remote
`mi_free`, runs real `mi_thread_done()`, and joins before consumer frees.
Rust uses only the corresponding private typed drain. Force collection records
`used == 41`, mapped dynamic abandonment, and terminal PageMap, ordinary arena
bitmap, dynamic bitmap/count, and complete 64-slice release; the final
PageMap-null arena slice is slack but remains terminally released. This
remains private native x86-64 engine evidence only: it does not establish
general lifecycle/routing/concurrent collection, public x86 support, backend
promotion, or AArch64 evidence.

The native x86-only track also has a separate 34-field dynamic full-large
unmapped-reabandon differential. The pinned-C oracle's worker fills one sole full
`BIN_FULL` large arena page from request 86706 (98304-byte blocks,
capacity/reserved 42, 64 arena slices); only 63 source page-area slices are
PageMap-registered, and the final PageMap-null arena slice is slack but remains
part of terminal release. In the C oracle, no remote `mi_free` is published;
real `mi_thread_done()` and `pthread_join()` precede sequential consumer frees.
Rust independently executes the bounded typed owner-exit route on its owning
test thread and does not claim a literal worker-thread/join counterpart.
Five normal-collector frees retain unmapped abandonment at `used == 37` with
dynamic bitmap/count zero, then the sixth maps it at `used == 36` with dynamic
bitmap/count one. The mapped tail clears PageMap, the ordinary arena bitmap,
and dynamic bitmap/count before releasing the complete 64-slice span. This is
private native x86-64 engine evidence only: it does not establish general
lifecycle/routing/concurrent collection, abandonment/adoption, public API or
runtime, public x86 support, libc integration, backend promotion, or AArch64
evidence.

The native x86-only track now also has a separate dynamic homogeneous
full-large aggregate differential. Its pinned-C worker fills exactly two
same-bin full `BIN_FULL` arena large pages from request 86706 (98304-byte
blocks, capacity/reserved 42, 64 arena slices each, with 63 registered
PageMap source slices and one null slack slice), performs real
`mi_thread_done()`, and the consumer joins before any sequential free. Both
members begin unmapped-abandoned with dynamic abandoned bitmap/count clear;
each member independently remains at `used == 37` after five frees, maps at
`used == 36` on the sixth with its dynamic bitmap/count publication, then
releases its complete 64-slice PageMap/arena span. Rust exercises only the
corresponding bounded dynamic aggregate owner-exit route. This is private
native x86-64 engine evidence only and does not establish general lifecycle,
routing, concurrency, abandonment/adoption, public x86 support, backend
promotion, libc integration, or AArch64 evidence.

The native x86-only track also has a separate 67-field dynamic homogeneous
full-medium aggregate differential. Its pinned-C worker fills exactly two same-bin full
`BIN_FULL` arena medium pages from request 10248 (12288-byte blocks,
capacity/reserved 42, eight arena slices each), performs real
`mi_thread_done()`, and the consumer joins before any sequential free. Both
members begin unmapped-abandoned with dynamic abandoned bitmap/count clear;
each member independently remains at `used == 37` after five frees, maps at
`used == 36` on the sixth with its dynamic bitmap/count publication, then
releases its complete eight-slice PageMap/arena span. Rust exercises only the
corresponding bounded dynamic aggregate owner-exit route. This is private
native x86-64 engine evidence only and does not establish general lifecycle,
routing, concurrency, abandonment/adoption, public x86 support, backend
promotion, libc integration, or AArch64 evidence.

The native x86-only track also has a separate 69-field dynamic homogeneous
full non-direct-small aggregate differential. Its pinned-C worker fills exactly
two same-bin full ordinary-bin arena pages from request 1032 (1280-byte blocks,
capacity/reserved 51, one arena slice each), performs real `mi_thread_done()`,
and the consumer joins before any sequential free. Both members begin
ordinarily unmapped-abandoned with dynamic abandoned bitmap/count clear; each
member independently remains at `used == 45` after six normal-collector frees,
maps at `used == 44` on the seventh with its dynamic bitmap/count publication,
then releases its one-slice PageMap/arena span. Rust exercises only the
corresponding bounded dynamic aggregate owner-exit route. This is private
native x86-64 engine evidence only and does not establish general lifecycle,
routing, concurrency, abandonment/adoption, public x86 support, backend
promotion, libc integration, or AArch64 evidence.

The native x86-only track also has a separate 32-field dynamic full direct-small
one-remote force-collect-to-mapped differential. A pinned-C worker fills one
sole full direct-small ordinary regular-bin arena page (request/block size 1024,
capacity/reserved 64, one slice) and preflights its exact rounded direct-cache
range `[113, 128]`. The consumer/main thread publishes exactly one joined
remote `mi_free`; the worker later runs real `mi_thread_done()`, and the
consumer joins before sequential frees; Rust uses only the corresponding
private typed drain. Force collection records
`used == 63`, mapped dynamic abandonment, and dynamic bitmap/count state.
Pinned source anchors plus the Rust handoff establish direct-cache
clear-before-page-count-detach; only the source partial collector serves the
mapped tail through terminal PageMap, ordinary arena bitmap, dynamic
bitmap/count, and one-slice release. This remains private native x86-64 engine
evidence only: it does not establish general lifecycle/routing/concurrent
collection, abandonment/adoption, public x86 support, backend promotion, or
AArch64 evidence.

The native x86-only track also has a separate 38-field dynamic full direct-small
unmapped-reabandon differential. A pinned-C worker fills one sole full
direct-small ordinary regular-bin arena page (request/block size 1024,
capacity/reserved 64, one slice) and preflights its exact rounded direct-cache
range `[113, 128]`. No remote `mi_free` is published; the worker runs real
`mi_thread_done()`, and the consumer joins before sequential frees. Force then
false collection clears that range before page-count detach and leaves the page
unmapped-abandoned with PageMap and ordinary arena bitmap retained, ordinary
queue detached, dynamic bitmap/count clear, and `used == 64`. The first
partial-collector consumer free retains `used == 64`; nine partial-collector
frees retain that route at `used == 56`; the tenth partial collector takes
`used` to 55, then generic unown consumes the retained current head and maps
it at `used == 54` with dynamic bitmap/count one. The mapped tail clears
PageMap, ordinary arena bitmap, dynamic bitmap/count, and the one slice. This
remains private native x86-64 engine evidence only: it does not establish
general lifecycle/routing/concurrent collection, abandonment/adoption, public
x86 support, backend promotion, or AArch64 evidence.

The native x86-only track also has a separate 30-field dynamic full
non-direct-small one-remote force-collect-to-mapped differential. A pinned-C
worker fills one sole full non-direct-small ordinary regular-bin arena page
(request 1032, 1280-byte blocks, capacity/reserved 51, one slice, and an empty
direct-cache image). The consumer/main thread publishes exactly one joined
remote `mi_free`; the worker later runs real `mi_thread_done()`, and the
consumer joins before sequential frees; Rust uses only the corresponding
private typed drain. Force collection records `used == 50`, mapped dynamic
abandonment, and bitmap/count state. The first sequential failed-reclaim free
follows normal `used + 2 == reserved` geometry while retaining the mapped
route; the final free clears PageMap, ordinary arena bitmap, dynamic
bitmap/count, and the one slice. This remains private native x86-64 engine
evidence only: it does not establish general lifecycle/routing/concurrent
collection, abandonment/adoption, public x86 support, backend promotion, or
AArch64 evidence.

The native x86-only track also has a separate 35-field dynamic full
non-direct-small unmapped-reabandon differential. A pinned-C worker fills one
sole full non-direct-small ordinary regular-bin arena page (request 1032,
1280-byte blocks, capacity/reserved 51, one slice, and an empty direct-cache
image), publishes no remote free, runs real `mi_thread_done()`, and the
consumer joins before sequential frees. It initially remains full and
unmapped-abandoned with PageMap and ordinary arena bitmap retained, dynamic
bitmap/count clear, and `used == 51`. Six normal-collector frees retain the
unmapped route at `used == 45`; the seventh maps it at `used == 44` and sets
the dynamic bitmap/count to one. The terminal mapped tail clears PageMap,
ordinary arena bitmap, dynamic bitmap/count, and the one slice. This remains
private native x86-64 engine evidence only: it does not establish general
lifecycle/routing/concurrent collection, abandonment/adoption, public x86
support, backend promotion, or AArch64 evidence.

`DynamicThreadExitDrain::abandon_full_non_direct_small` is a sixth, separate
dynamic full-page endpoint. It admits one sole full `MemoryKind::Arena` small
page only in its ordinary regular bin, with
`SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE`, `reserved > 1`,
`used == reserved`, `!page_is_in_full`, and an empty direct-cache image.
It preserves source force -> false collection -> regular-bin/page-count detach
-> ordinary unmapped abandonment. Its linear
`DynamicThreadExitFullNonDirectSmallHandoff` consumes sequential normal
failed-reclaim frees: the page stays unmapped through the source mostly-used
prefix, the first free beyond `reserved / 8` publishes the matching dynamic
`pages_abandoned[bin]` bit plus `Heap::abandoned_count[bin]`, and the mapped
tail clears that pair before PageMap -> dynamic ordinary bit -> metadata ->
arena-slice release. It rejects direct-small before collection and neither
reclaims, adopts, requeues, scans, nor covers full medium/direct-small/large,
multi-page, or general dynamic owner exit.

`DynamicThreadExitDrain::abandon_full_non_direct_small_after_force_collect_to_mapped`
separately preserves the source full non-direct-small branch with exactly one
joined remote free. The sole ordinary-bin page starts with `used == reserved`;
force collection consumes that free while retaining its queue membership with
`used == reserved - 1`; false collection preserves it; regular-bin/page-count
detach leaves the page nonfull; and mapped abandonment immediately publishes
its dynamic bitmap/count pair. The returned
`DynamicThreadExitFullNonDirectSmallHandoff` starts mapped and consumes
sequential failed-reclaim frees only, clearing that pair before the ordinary
arena release. Its source direct-cache update is a no-op because the rounded
block size exceeds `SMALL_SIZE_MAX` and the full preflight requires an empty
direct image. It does not add multiple frees, direct-small or other classes,
reclaim, adoption, requeue, scans, or general dynamic owner exit.

`DynamicThreadExitDrain::abandon_full_direct_small` is a seventh, separate
dynamic full-page endpoint. It admits one sole full `MemoryKind::Arena` small
page only in its ordinary regular bin, with `block_size <= SMALL_SIZE_MAX`,
`reserved >= 16`, `used == reserved`, `!page_is_in_full`, and its complete
rounded direct-cache range naming the page while every other direct slot is
empty. Source force -> false collection -> ordinary-bin removal clears that
range before page-count detach, then ordinary unmapped abandonment. Its linear
`DynamicThreadExitFullDirectSmallHandoff` uses the source partial
failed-reclaim collector: the retained just-published head keeps the page
unmapped for one additional client free before the below-mostly-used boundary
publishes the matching dynamic `pages_abandoned[bin]` bit plus
`Heap::abandoned_count[bin]`. The mapped tail clears that pair before PageMap
-> dynamic ordinary bit -> metadata -> arena-slice release. A stale cache
range, non-direct small, additional page, or collection failure cannot bypass
the pre-detach contract. This one route neither reclaims, adopts, requeues,
scans, nor covers full medium/non-direct-small/large, multi-page, or general
dynamic owner exit.

A separate `DynamicThreadExitMappedOneBlockHandoff` accepts only a sole,
nonfull `MemoryKind::Arena` medium, large, non-direct-small, or direct-small
page with `reserved > 1`, `used == 1`, and one regular queue member. The
medium endpoint remains `DynamicThreadExitDrain::abandon_mapped_one_block`;
the large endpoint is `DynamicThreadExitDrain::abandon_mapped_one_block_large`
and retains its complete 64-slice span; the non-direct-small endpoint is
`DynamicThreadExitDrain::abandon_mapped_one_block_non_direct_small` and
requires `SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE` with an empty
direct-cache image; the direct-small endpoint is
`DynamicThreadExitDrain::abandon_mapped_one_block_direct_small` and requires
`block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, and its complete rounded
source direct-cache range. Direct-small preflight rejects a stale cache image
before collection or detach, then source queue removal clears that exact range
before page-count detach. The handoff keeps the post-TLS dynamic arena image
only long enough to form the exact heap-local `pages_abandoned[bin]` bit plus
paired `Heap::abandoned_count[bin]`. Source force then false collection
precedes queue/page-count detach and mapped identity/bit/count/unown
publication. Its exact final free reaches empty before any source reclaim
branch—through the normal collector for medium/large/non-direct small and the
partial collector for direct small—clears the dynamic bit/count pair, then
releases PageMap -> dynamic ordinary bit -> metadata -> arena slices. The
large endpoint validates its 63 PageMap-registered source page-area slices;
the final PageMap-null arena slice is slack but remains part of the terminal
64-slice release. Neither dynamic handoff scans, reclaims, adopts, requeues,
accepts a second free, or generalizes thread exit. Only an empty drain may
resume the existing cached-root/list/key teardown.

`DynamicThreadExitDrain::abandon_mapped_two_block_medium` is a separate
post-TLS dynamic handoff for exactly one sole nonfull `MemoryKind::Arena`
`PageKind::Medium` page with `block_size > SMALL_SIZE_MAX`, `reserved > 2`,
`used == 2`, zero retirement countdown, one regular queue member, an empty
direct-cache image, and no other queue/direct entry. It preserves source force
-> false collection -> queue removal -> page-count decrement -> non-direct
no-op cache update -> dynamic mapped identity/bit/count/unown. The private
handoff retains no client pointer/list: its first exact canonical free must
produce `UnownedMapped` and keep the bit/count with one live block, while only
the final free may produce `Empty`, clear that pair, and release the
queue-detached PageMap -> dynamic ordinary bit -> metadata -> arena-slice
span. One or three live blocks, another page, other source classes, reclaim,
adoption, requeue, scanning, producers, concurrency, and general owner exit
remain excluded.

`DynamicThreadExitDrain::abandon_mapped_medium_pair` now records one separate
bounded post-TLS aggregate: exactly two nonfull `MemoryKind::Arena`
`PageKind::Medium` pages in distinct regular bins, one with `reserved > 2`,
`used == 2` and one with `reserved > 1`, `used == 1`. Preflight proves both
sole queue members, their arena spans and dynamic bitmap/count capabilities,
the total three live blocks, an empty direct image, and no other queue/page
before source bin-order force -> false collection -> queue removal ->
page-count decrement -> non-direct no-op update -> mapped publication. The
returned `DynamicThreadExitMappedMediumPairRoute` keeps only the drain plus
remaining page/free counts; every client free re-resolves PageMap membership
and acquires the source low owner bit before selecting its dynamic map. An
`UnownedMapped` result retains the route, while each `Empty` result clears its
exact pair and releases only that member; the final release returns the empty
drain. It adds no raw member registry, scan, reclaim/adoption/requeue,
allocation-time, producer, concurrent, or general owner-exit routing.

The first fresh page in that private non-abandoning dynamic session now owns
one exact source-shaped heap-local `mi_arena_pages_t` image. Creation first
requires the registry-published arena's non-null `Arena::subprocess` to equal
the attachment's selected main subprocess; the retained BCHUNK-aligned
metadata capability is then Release-published only in the bound Heap's exact
arena slot and is used for fresh/rollback/release page bits. It remains
disjoint from the arena's `pages_main`. Empty attachment
teardown removes the exact slot before freeing it, while a nonempty image is a
pre-mutation rejection and post-mutation lock/free ambiguity terminally
retains owner state. One consuming same-owner handoff now moves a mapped
regular dynamic arena page through its heap-local abandoned bitmap/count. The
same token can adopt it or consume one still-live client block through the
source mapped `allow_collect=true` same-origin remote-free branch: the small
path preserves its published head until reassociation, clears the exact
bitmap/count, live-collects, and requeues. Its all-free dynamic-arena outcome
now releases in source order—PageMap span, heap-local ordinary bit, metadata,
then arena slices—and returns the drained engine; an existing owner remains a
terminal handoff. Separately, `free_unmapped_after_failed_reclaim` remains the
source terminal-empty/reabandon/unown substrate after failed reclaim, including
the expected-head CAS and no-second-reclaim conflict path. The post-TLS full
singleton and full-singleton/homogeneous-full-OS-singleton/full-medium/full-large/full-non-direct-small/full-direct-small
aggregates above, the separate dynamic full-medium, full-large,
full-non-direct-small, and full direct-small handoffs, and the bounded later-main normal full-medium,
full-large, full non-direct-small, and full direct-small process routes are its lifecycle-integrated raw-release
callers; other regular or
nonempty unmapped pages, general producer routing, terminal reuse, multi-arena dynamic heap
support, and general heap destruction remain absent.

Separately, the exact source-layout `mi_random_ctx_t` image now lives directly
in `Theap::random`: it preserves source input/output word order, counter
carries, consumed-output clearing, direct random-field-address nonce identity,
and in-place split. It calls direct Linux `getrandom` and continues weakly on
an error or short read, then retries only while weak. The source local
`_mi_random_shuffle` core is deliberately replaced by one domain-separated
approved RustCrypto expansion of transparent weak observations; this
non-entropy-adding degraded-path difference is recorded in
`compat/allocator/known-differences.md`. The static main-Theap slice initializes
this exact image; both static and private dynamic Theap attachment use it, and
the narrow non-abandoning dynamic session reuses the private page engine.
General allocator routing and page-bearing production thread/process
integration remain absent; only the bounded no-page lifecycle bridge is live.
Five bounded Loom
schedules execute the shared live-owner and abandoned owner-claim/unown head
transitions. The compiler-TLS evidence proves private initial-exec AArch64 code
generation in a dedicated crate probe and proves that the pinned compiler
default would instead emit TLSDESC. The bridge applies initial-exec target-wide
in both normal and sealed-sysroot Rust flags; its installed static archive is
audited for the named `THREAD_LIFECYCLE` TLSIE root, and final `libc.so` must
use TPREL relocations with no TLSDESC or `__tls_get_addr`. The bounded
dynamic engine consumes one stable, queue-detached mapped regular handoff and
one same-origin mapped `allow_collect` remote free; its all-free dynamic-arena
result performs the bounded PageMap/ordinary-bit/metadata/slice release while
an existing-owner result remains terminal. It additionally proves one post-TLS
  dynamic owner-exit singleton, full-singleton/homogeneous-full-OS-singleton/full-medium/full-large/full-non-direct-small/full-direct-small aggregates,
  sole full-medium, full-large, full-non-direct-small, and
  full-direct-small normal unmapped-to-mapped handoffs, four one-joined-remote
  full-medium/full-large/full-non-direct-small/full-direct-small immediate-mapped predecessors, and sole mapped
medium/large/non-direct-small/direct-small
one-block handoffs: clearing the regular backing prevents reclaim; the singleton
  final free takes the raw failed-reclaim all-free release, the four normal
  full routes cross the source mostly-used boundary before dynamic bitmap
  publication, and the medium/large `BIN_FULL` plus non-direct-small/direct-
  small ordinary-bin one-remote full routes map immediately after source
  force/false collection and queue detach, with direct-small clearing its
  rounded cache range before count detach. Each mapped
  endpoint clears its dynamic bitmap/count before terminal arena release. The raw
protocol remains
otherwise unintegrated: regular/nonempty pages, general producer routing,
terminal reuse, actual process/thread lifecycle hooks, full teardown traversal,
and reusable abandoned-page lifetime remain absent.
The bounded two-block dynamic owner-exit evidence is likewise split by source
class: medium and one-slice non-direct-small each admit only a sole nonfull
arena page with `reserved > 2`, `used == 2`, an empty direct image, and exactly
two sequential canonical frees. The first retains the dynamic mapped
bit/count through `UnownedMapped`; the final `Empty` free alone releases the
page. The separate large handoff admits only `PageKind::Large` geometry with
`MEDIUM_MAX_OBJ_SIZE < block_size <= LARGE_MAX_OBJ_SIZE`, an empty direct
image, and an exact 64-slice arena/PageMap span; its normal first free retains
that entire mapped span with `used == 1`, and its final `Empty` free alone
clears the pair and releases all 64 slices. The separate direct-small handoff
admits only `block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, its complete
rounded direct-cache range, and `used == 2`; it clears that range before
page-count detach. Its first partial-collector free deliberately leaves the
published head atomic and the observed `used` count at two, then the final free
consumes both heads and releases the page. Extra live blocks/pages, stale/mixed
cache images, reclaim, adoption, requeue, scans, producers, and concurrent
traversal remain open.
Process state, general allocator TLS lifecycle, full/singleton/unmapped/huge
later-thread owner exit beyond the bounded sole
full-medium/full-large/full-non-direct-small/full-direct-small routes, seven
bounded full-page aggregates, sole small-or-medium route, and regular-pages
aggregate, allocation-time
claim/reclaim/requeue after later-thread exit beyond the exact mapped one- and
two-block handoffs, general dynamic heap/Theap
attachment and remote-free routing, complete concurrency modeling and stress,
libc integration, the remaining upstream suites, and performance promotion
gates remain open.

Future acceptance contracts are deliberately specific:

- [`docs/roadmap/performance-completion.md`](docs/roadmap/performance-completion.md)
  governs performance completion.
- [`docs/roadmap/software-corpus-validation.md`](docs/roadmap/software-corpus-validation.md)
  governs real-software and native-application validation.
- [`docs/roadmap/source-build.md`](docs/roadmap/source-build.md) governs the
  remaining CPython source-build progression on the completed sysroot.

Historical documents preserve provenance only; they are never an active
backlog. No chronological microtask list is a project authority. Read the
governing scope and compatibility profile before selecting work, then use the
relevant roadmap or machine-readable contract for its acceptance boundary.
