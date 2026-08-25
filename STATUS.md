# Project status

The general Linux/AArch64 little-endian runtime profile is closed. One active,
narrowly scoped compatibility program is open: the provenance-preserving Rust
semantic port of fixed mimalloc v3.5.0 defined by
[`docs/design/allocator.md`](docs/design/allocator.md) and measured through
[`compat/allocator/README.md`](compat/allocator/README.md). It does not reopen
allocator invention or another platform. [`COMPATIBILITY.md`](COMPATIBILITY.md)
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
exact pinned C v3.5.0. A standalone default-off test package now exports 16
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
process pair; one all-free later-main thread-exit drain; eight sole-page
later-main owner-exit handoffs (a full arena singleton, an OS-aligned
singleton that links through `Heap::os_abandoned_pages` and removes that list
member before clipped PageMap/alias/metadata/mapping release, a mapped medium page
with one live block, full medium and full large `BIN_FULL` pages plus full
non-direct-small and direct-small regular-bin pages that remain unmapped until
their mostly-used free boundary then reabandon to the static-main bitmap, and a sole nonfull
small-or-medium page whose process-owned route survives old-Theap/TLD teardown,
including exact full-medium, full-large, full-non-direct-small, and
full-direct-small predecessors where one joined remote free is force-collected
before immediate mapped publication (the medium and large pages remain in
`BIN_FULL`; the non-direct-small page remains in its ordinary bin with every
direct slot empty; the direct-small page remains in its ordinary bin until its
rounded direct-cache range is cleared during removal));
and one aggregate regular-pages post-exit
registry that can route every qualifying surviving regular small, medium, or large page
through sequential client frees. A fresh later-main owner can explicitly
reclaim a sole mapped medium route that began owner exit nonfull, or a sole
direct-small route that retains an immediate local free block, the exhausted
fully committed scalar-extension shape, or the exact exhausted on-demand
page-area-commit shape after source collection; all force-collected full-origin
predecessors remain sequential client-free-only. The reserved fixtures cover
both medium and direct-small prefixes, direct page-area commitment, and failed-
commit mapped reabandonment before a same-candidate retry; non-direct-small,
other no-immediate direct-small cases, and aggregate members remain sequential
client-free-only.
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
exception permits the source `BIN_FULL` route even for a
small ordinary block size: it links its one `MemoryKind::Os` page in
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
its complete 64-slice span before release. The corresponding full non-direct-
small and direct-small one-joined-remote predecessors remain linked in their
ordinary bins while force collection makes them nonfull; the former keeps its
empty direct image, while the latter clears its rounded direct range before
page-count detach. Both immediately publish their mapped bit/count pairs and
remain client-free-only through terminal release. The sole nonfull small-or-medium
process route preserves the same
mapped publication, tears down the old Theap/TLD, and routes its linear client
frees through short PageMap access. Its sole mapped medium member, or its sole
direct-small member with an immediate local free block, the exhausted fully
committed scalar-extension shape, or the exact exhausted on-demand page-area-
commit shape after source collection, may instead be
explicitly consumed by a fresh later-main owner after exact
subprocess/configuration/PageMap-root/static-main-Heap/arena/page-identity
preflight: the short map access becomes one long lifecycle, the matching
bitmap/count member is claimed, source abandoned/live collection and Theap
reassociation run, and the page returns at the target queue tail. A direct-
small target restores its complete rounded direct-cache range before target
page-count increment and immediately reuses that same page; its exhausted fully
committed scalar shape extends after tail insertion, while its exact on-demand
shape directly commits its page area before prefix-count/free-list/capacity
publication. The medium slice
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
terminally retained. Non-direct-small and other no-immediate direct-small
members remain client-free-only. A direct small member must prove the exact rounded
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
releases. If retirement/force collection empties every page, it returns the
ordinary drain. Fresh engines may serialize independent PageMap operations
between client frees, but no current path can adopt, reclaim, or requeue an
aggregate registry member. Full/singleton/unmapped/huge/foreign pages, malformed
direct-cache images, concurrent client routes, deferred callbacks, arena
collection, and retry/reuse
as a normal allocator remain outside this owner. Only an empty drain permits
`finish_after_page_drain` to reset default/cached, detach its shared heap list
member before its TLD list member, and retire metadata/TLD. A force/release
failure or root/list mismatch remains terminally retained; this is not general
abandonment, later-free/reclaim, concurrent routing, or a `pthread` lifecycle.

`process_page_map.rs` owns the global source-page-map prerequisite. It freezes
one `MemoryConfig` and selected main subprocess, initializes a `PageMap` in
its final static slot, and Release-publishes its root exactly once.
`process_arena.rs` separately admits one caller-selected, complete in-place
arena mapping only after binding its registry to that same
map/root/configuration/subprocess tuple; it retains the published mapping for
process lifetime and returns an unpublished rejected mapping to its caller. A
reserved mapping first enters that final owner slot, so the retained arena
callback commits metadata and later selected ranges through the exact same
`Mapping`; frozen Linux decommit reports no recommit requirement. An injected
metadata-commit failure returns the exact map with the registry empty and the
sidecar cold. This establishes the external-map ownership prerequisite and one
narrow paired direct page-area commit operation; it does not enable
page-on-demand policy or itself maintain `slice_pcommitted` or page
reabandonment.
`ProcessPageArenaLease` proves that exact tuple before `main_static_page.rs`
or `main_heap_page.rs` may bind an already selected source Theap to it. The
private ticket-zero and later-thread engines each hold the only process-map
plain-entry lifecycle for their complete engine and joined scoped producer,
install the arena's embedded `pages_main` bitmap in the shared static Heap, and
use the existing engine's source bitmap -> map publication and map -> bitmap ->
metadata -> slice release order. They reject a foreign subprocess before page
mutation, and an unfinished engine terminally poisons both owners rather than
manufacturing cleanup. This remains a caller-initialized, single-arena,
sequential-owner slice. The bounded coordinator can now provide its map
predecessor, but it still supplies neither the C static empty-map pre-root,
automatic reservation, concurrent or general later-thread page routing, general
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
large endpoint validates the complete 64-slice PageMap span before that
terminal release. Neither dynamic handoff scans, reclaims, adopts, requeues,
accepts a second free, or generalizes thread exit. Only an empty drain may
resume the existing cached-root/list/key teardown.

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
singleton above, the separate dynamic full-medium, full-large,
full-non-direct-small, and full direct-small handoffs, and the bounded later-main normal full-medium,
full-large, and full non-direct-small process routes are its lifecycle-integrated raw-release
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
General allocator routing and production thread/process integration remain
absent.
Five bounded Loom
schedules execute the shared live-owner and abandoned owner-claim/unown head
transitions. The compiler-TLS evidence proves private initial-exec AArch64 code
generation in a dedicated crate probe and proves that the pinned compiler
default would instead emit TLSDESC; public runtime integration must still apply
the required per-crate model and audit the final linked ELF. The bounded
dynamic engine consumes one stable, queue-detached mapped regular handoff and
one same-origin mapped `allow_collect` remote free; its all-free dynamic-arena
result performs the bounded PageMap/ordinary-bit/metadata/slice release while
an existing-owner result remains terminal. It additionally proves one post-TLS
  dynamic owner-exit singleton, full-medium, full-large, full-non-direct-small, and
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
Process state, general allocator TLS lifecycle, full/singleton/unmapped/huge
later-thread owner exit beyond the bounded sole
full-medium/full-large/full-non-direct-small/full-direct-small routes, sole small-or-medium
route, and regular-pages aggregate, allocation-time
claim/reclaim/requeue after later-thread exit beyond the exact sole mapped
medium handoff, general dynamic heap/Theap
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
