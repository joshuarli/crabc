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
roots. The recursive allocation-free once protocol is present as a
coordination primitive, but no general process initialization state machine is
claimed.

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
crate still has no production public operation, libc integration, process/TLS
lifecycle, integrated remote-free routing, thread teardown, fork protocol, or
backend selection. The present Milestone 5 foundations are intentionally
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
portion. A false-force collection error permanently poisons this private
allocator with the exact page, error, and any already-popped block; all later
allocation, inspection, free, producer preparation, and collection entry
points reject without another queue or page-map transition. A bounded one-page
abandonment/adoption protocol, a current-thread-only regular TLS backing owner,
one ticket-zero process-static main heap/default-Theap attachment, and one
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
**subprocess-attached, no-theap**. Process bootstrap must choose it or
`MainStaticTheapAttachment` as the owner of that `MainSubprocess`'s ticket
zero: a generic owner can consume ticket zero first, after which static
attachment terminally rejects. Shared process-init selection authority is
explicitly deferred. `MainStaticTheapAttachment` is the sole static exception:
after dynamic-empty/fast-null/default-empty/cached-empty root preflight, it
consumes that process-static ticket-zero TLD. Its one process-static owner has
cache-aligned, address-stable `Heap` and `Theap` field slots, not separate Rust
statics. The main `Heap` follows `mi_heap_main_init_once` with kind-only
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

`DynamicTheapAttachment` uses `MainSubprocess::issue_later_thread_ticket` so
it atomically refuses ticket zero rather than racing static process-main
selection. It is `!Send`/`!Sync`, holds the caller-pinned Heap plus exact
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
abandoned bit, increments `Heap::abandoned_count[bin]`, and unowns it. Only
the same token can claim that exact bit, decrement the count before the
source abandoned then live-owner collections, and append the page back to the
same Theap queue. Forgetting or post-claim failure retains the engine rather
than exposing normal free/allocation. Full, singleton/huge, non-arena,
foreign, and ordinary abandoning-session pages remain rejected; abandoned
free/reabandon, terminal release/reuse, multiple arena images, and general
heap destruction remain deferred.

`PrivateLock` preserves the TLD field's private-lock meaning but is not a
byte-identical pthread mutex, so no C `sizeof(mi_tld_t)` claim is made.
General cached-root switching/reference ownership, general remote-free/page
routing or abandonment integration beyond that one handoff, full
heap/Theap/arena/subprocess APIs,
pthread/process hooks, fork repair, process shutdown, and general lock
destruction remain outside this slice.

The abandonment/adoption protocol preserves mapped versus unmapped source
classification, publishes the abandoned bitmap/count before releasing
ownership, restores a failed reader's bit, waits for reader quiescence before
unabandoning, drains after source bitmap claim while still abandoned, then
reassociates a claimed page and performs the live-owner collection before
queue insertion. It requires queue-detached, address-stable page/arena/theap
metadata and intentionally does not release or reuse the page. A test-only
Loom model executes the live-owner remote-head publication/detach loops and
the abandoned owner-claim/unown races under bounded schedules; deterministic
native regressions cover the bitmap-field quiescence and full one-page
abandonment interleavings. A dedicated pinned-target probe proves that the TLS
roots are hidden `STT_TLS` objects accessed through initial-exec relocations
without `__tls_get_addr`; its negative control proves the pinned compiler
default emits TLSDESC. Rust has no per-static model annotation, so this is a
bounded crate-codegen proof: production integration must apply the same
per-crate setting and audit the final linked static and shared images. These
slices do not provide integrated allocator thread lifecycle, terminal page
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
