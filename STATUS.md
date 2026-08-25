# Project status

The general Linux/AArch64 little-endian runtime profile is closed. One active,
narrowly scoped compatibility program is open: the provenance-preserving Rust
semantic port of fixed mimalloc v3.5.0 defined by
[`docs/design/allocator.md`](docs/design/allocator.md) and measured through
[`compat/allocator/README.md`](compat/allocator/README.md). It does not reopen
allocator invention or another platform. [`COMPATIBILITY.md`](COMPATIBILITY.md)
remains the generated record of current compatibility evidence and
measurements; it is not edited by hand.

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
backend or readiness claim. Milestone 5 currently includes the exact AArch64
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
process pair; one all-free later-main thread-exit drain; three sole-page
later-main owner-exit handoffs (a full arena singleton, a mapped medium page
with one live block, and a sole nonfull non-direct small-or-medium page whose
process-owned route survives old Theap/TLD teardown); and one aggregate medium-and-large post-exit
registry that can route every qualifying surviving medium-or-large page
through sequential client frees.
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
the general live page. Three explicit sole-page exceptions remain after
fast-slot clear, each requiring no other queue/direct/page state. The full
one-block arena singleton false-collects, detaches, and unmapped-abandons while
retaining its PageMap lifecycle and registration through its exact final client
free; that failed-reclaim empty result performs PageMap removal -> `pages_main`
clear -> metadata retirement -> slice release. The separate medium regular
page exception requires `reserved > 1` and `used == 1`, force- then
false-collects, detaches, and publishes its exact main
`pages_abandoned[bin]` bit plus paired `Heap::abandoned_count[bin]`. Its final
client free takes only the source mapped empty-before-reclaim outcome, clears
that bit/identity, consumes the paired count, and performs the same terminal
release; a still-live result is terminally retained rather than reclaimed or
requeued. The older sole nonfull non-direct-small-or-medium process route
preserves the same mapped publication, tears down the old Theap/TLD, and
routes its linear client frees through short PageMap access. Direct-cache and
full small pages remain excluded from that route.

`abandon_mapped_medium_large_pages_to_process_route` is the bounded
source-traversal extension: before any mutation, every direct slot must be
empty and every queue member must be a nonfull medium-or-large arena page. An
empty member is admitted only when normal local free left its source retirement
countdown nonzero. The route
then ports `_mi_theap_collect_retired(theap, true)`'s regular-bin pass, so an
already-empty retired span releases before the remaining
`mi_theap_page_collect` / `_mi_page_abandon` decisions: force-collect, release
pages made all-free, false-collect still-live pages, queue/page-count detach,
and publish the exact static-main mapped identity/bit/count pair. Its typed
aggregate registry retains no old-Theap pointer or raw page list; every later
linear client free re-resolves one PageMap entry, selects its bin only after
the source low owner-bit claim, preserves map/bit/count while nonempty, and
re-derives the supported page's complete regular span before the terminal
PageMap -> `pages_main` -> metadata -> slice release on empty. The current
medium and large cases therefore prove their respective 8- and 64-slice
releases. If retirement/force collection empties every page, it returns the
ordinary drain. Fresh engines may serialize independent PageMap operations
between client frees, but no current path can adopt, reclaim, or requeue a
registered route page. Small/full/singleton/unmapped/huge/foreign pages,
concurrent client routes, deferred callbacks, arena collection, and retry/reuse
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
process lifetime and returns an unpublished rejected mapping to its caller.
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
force-collects an already-retired all-free regular page. Its only live-page
transition admits one full one-block arena singleton; the source force-only
local-list append is unreachable under its `reserved == used == 1` and
no-producer proof. The raw local-list substrate now separately ports and tests
that force append, including cycle rejection before relinking; the separately
recorded later-main all-free exit drain invokes it, but no current page-engine
lifecycle invokes it for a general traversal. Its consuming handoff queue-detaches and unmapped-abandons
that page, then a final client free necessarily fails reclaim through the
cleared regular slot and owns the raw all-free release: PageMap span unregister,
exact dynamic ordinary-bit clear, metadata retirement, and arena-slice release.
Only an empty drain may resume the existing cached-root/list/key teardown.

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
singleton above is its sole lifecycle-integrated raw-release caller; regular or
nonempty unmapped pages, general producer routing, terminal reuse, multi-arena
dynamic heap support, and general heap destruction remain absent.

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
dynamic owner-exit singleton: clearing the regular backing prevents reclaim,
and its final free takes the raw failed-reclaim all-free release before
attachment teardown. The raw protocol remains otherwise unintegrated:
regular/nonempty pages, general producer routing, terminal reuse, actual
process/thread lifecycle hooks, full teardown traversal, and reusable
abandoned-page lifetime remain absent.
Process state, general allocator TLS lifecycle, direct-small/full/singleton/
unmapped/huge later-thread owner exit beyond the bounded non-direct-small-or-
medium sole route and medium-and-large aggregate, allocation-time
claim/reclaim/requeue after later-thread exit, general dynamic heap/Theap
attachment and remote-free routing, complete concurrency modeling and stress,
libc integration, the remaining upstream suites, and performance promotion
gates remain open.

Future acceptance contracts are deliberately specific:

- [`docs/roadmap/performance-completion.md`](docs/roadmap/performance-completion.md)
  governs performance completion.
- [`docs/roadmap/software-corpus-validation.md`](docs/roadmap/software-corpus-validation.md)
  governs real-software and native-application validation.
- [`docs/roadmap/source-build.md`](docs/roadmap/source-build.md) governs
  source-build and sysroot progression.

Historical documents preserve provenance only; they are never an active
backlog. No chronological microtask list is a project authority. Read the
governing scope and compatibility profile before selecting work, then use the
relevant roadmap or machine-readable contract for its acceptance boundary.
