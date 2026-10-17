# Fixed mimalloc semantic-port contract

## Purpose

`crabc` may replace the C allocator implementation in its production graph
with a provenance-preserving, pure-Rust semantic port of a fixed mature
allocator. This is a narrow compatibility exception to the project rule
against allocator research. It does not authorize a new allocator design.

The target is mimalloc v3.5.0, pinned at
`18b08671c9302247bfb682286e6bf3cc1773f801`. Its pin, license, source-to-Rust
mapping, and update procedure are in
[`crabc-mimalloc/UPSTREAM.md`](../../crabc-mimalloc/UPSTREAM.md). Deliberate
differences from the pinned source are registered in
[`compat/allocator/known-differences.md`](../../compat/allocator/known-differences.md).
The execution plan, milestones, and progress are in [`plan.md`](../../plan.md);
the evidence harness is described in
[`compat/allocator/README.md`](../../compat/allocator/README.md) and the
performance contract in [`performance.md`](performance.md).

The production backend, on both targets, is the C `libmimalloc-sys` 0.1.49,
which bundles mimalloc v3.3.2. It stays the default until a qualified,
target-specific promotion. It is not the v3.5.0 oracle: the pinned v3.5.0
archive is built separately for the Rust-port differential and the performance
baseline. The native Rust engine in `crabc-mimalloc` is reachable only through
explicit non-default features (see
[Integration](#integration-and-dependency-direction)). Where this document
describes a mechanism that only test or audit builds compile, it says so; the
production x86 owner-exit and free paths are in
[Thread attach and owner exit](#thread-attach-and-owner-exit).

## Scope and fidelity rules

- Active target: native Linux/x86-64, little-endian, kernel 5.10 or newer. The
  paused AArch64 port's page-size and ABI contracts are preserved without
  resuming its implementation or qualification; AArch64 is never emulated.
  RISC-V, macOS, Windows, big-endian, 32-bit, and portability scaffolds are out
  of scope.
- `crabc-mimalloc` is `#![no_std]`, depends on neither `alloc` nor libc, and
  compiles no C or C++ in the production allocator.
- The port preserves mimalloc v3.5.0's algorithms, data structures, memory
  orderings, lifecycle behavior, and valid-program observable behavior. It may
  not replace them with more idiomatic but materially different Rust
  algorithms. A divergence needs all of: a written design note naming the
  upstream behavior and the divergence, deterministic differential evidence
  against the exact pinned C source, and performance and memory evidence on the
  same native architecture profile. Record it in `known-differences.md`.
- The pinned C implementation remains the source, differential, and
  performance oracle even after it leaves the production dependency graph.
  Glibc is never an allocator or C-runtime oracle.
- Outcomes are tracked independently for the active profile: (1) readiness to
  back crabc's `malloc` family without changing its C ABI, (2) parity for every
  applicable public `mi_*` interface and compile-time mode, (3) qualified
  integration and default promotion in the owned x86 runtime. A standalone
  allocator parity result is not libc readiness. Basic allocation tests imply
  none of them; promotion needs the gates in `plan.md`.

## Integration and dependency direction

```text
crabc-mimalloc -> crabc-core + chacha20 + zeroize + rand_xoshiro
crabc-libc     -> crabc-core + crabc-mimalloc + libmimalloc-sys (+ other leaf dependencies)
```

On x86-64 every `crabc-libc` edge above is optional: `libmimalloc-sys` is
selected by `x86-allocator-runtime` or an owned product, `crabc-mimalloc` by
`native-mimalloc-shadow`. On AArch64 `libmimalloc-sys` is an unconditional
dependency.

`crabc-mimalloc -> crabc-libc` is forbidden. Raw Linux primitives belong in
`crabc-core`; the allocator must not duplicate syscall assembly or call public
pthread APIs, and integrates with crabc pthread startup, thread teardown, and
fork directly. The engine never touches `errno`; the embedder supplies a
`SourceErrnoStore` writer (`process_init.rs`).

`crabc-libc` retains the musl/POSIX C allocation ABI: weak and preemptible
symbols, interposition, `errno`, zero-size behavior, alignment, overflow,
reallocation preservation, and aligned-allocation output rules. `crabc-rs`
uses ordinary Rust allocation and exposes no C `malloc`/`free` API.

There is no runtime allocator-selection framework. Backend selection is
compile time. The C implementation is the default and, during validation, a
build- or test-selected shadow; the Rust implementation becomes the default
only in a final isolated promotion change.

`libc` features (`libc/Cargo.toml`):

- `x86-allocator-runtime` selects the C backend (`libmimalloc-sys`).
- `native-mimalloc-shadow` (`dep:crabc-mimalloc`) selects the Rust-engine
  wrapper instead of the C one: `libc/src/c_abi/x86_64/allocator_native_mimalloc.rs`
  on x86-64 (the AArch64 route includes `libc/src/allocator_native_mimalloc.rs`).
  On Linux/x86-64 it requires an owned native runtime, and
  `libc/src/c_abi/x86_64/static_c_abi.rs` rejects it otherwise; `libc/build.rs`
  rejects it together with `x86-allocator-runtime`.
- `x86-owned-static-native-shadow` and `x86-owned-dynamic-native-shadow` are the
  explicit owned-product selections. The dynamic one is described in
  [`x86-dynamic-native-allocator.md`](x86-dynamic-native-allocator.md).
- `native-mimalloc-shadow-test-audit`,
  `native-mimalloc-shadow-process-done-exit-test-audit`, and
  `x86-owned-allocator-lifecycle-test-audit` expose scalar audits only.

`crabc-mimalloc` features (`crabc-mimalloc/Cargo.toml`):

- Pinned compile-time modes keep the release layout by default:
  `mi-stat-1`/`mi-stat-2`, `mi-debug-1..3`, `mi-show-errors`, `mi-xmalloc`,
  `mi-secure-1..5`, `mi-guarded`, and `mi-opt-simd` (AVX2 bitmap searches;
  `bitmap.rs` refuses to compile it unless the crate targets AVX2, and the
  default stays scalar).
- On native x86-64, `mi-secure-1..5` use the pinned CMake default
  `MI_FREE_IS_CHECKED=1`; the M4 operation and M7 configuration producers
  select the same checked-free mode in their pinned C builds.
  Their Page layout omits the aligned self pointer:
  levels 1–2 use 120 bytes and levels 3–5 use 136 bytes, including two keys.
  Arena Page metadata follows the bitmaps in the initial info reservation;
  arena alignment is 64 KiB. OS-backed Pages instead place metadata before
  their clients. High alignment uses the source offset allocation while the
  owner retains the original mapping base and complete extent for release.
  Pointer lookup projects fields from the actual Page type without borrowing
  concurrently mutable owner fields. Default secure-0 retains its 128-byte
  Page, 256 MiB arena alignment and aligned metadata aliases.
  `native_secure_page_layout` exercises actual Heap creation, 6464-byte
  allocation extent, arena and forced-OS clients, zeroing, local free, worker
  exit and post-join aligned free without test or audit features. Its
  `mincore` checks cover pages at the mapping base and client address;
  they do not inspect every page in the mapping.
- Test seams, absent from production builds: `test-adapter` (an
  allocation-backed, creating-thread-only context for the prefixed C evidence
  adapter), `loom`, `tls-codegen-probe`, `native-runtime-test-audit` (read-only
  scalar lifecycle and fork-admission audits and the retired ticket-zero
  scheduler friend seam), and `native-runtime-test-fault` (the next `munmap`
  fails during a pointer-first terminal release).

## Module map

All paths are under `crabc-mimalloc/src/`.

| Layer | Modules |
| --- | --- |
| Source arithmetic and layout | `config`, `types`, `size_class`, `bits`, `atomic`, `provenance`, `free_list`, `bitmap`, `invariants` |
| OS and memory policy | `os`, `os_page`, `lock` (private futex lock), `once`, `random`, `statistics` |
| Arenas and PageMap | `arena`, `arena_owned`, `arena_huge`, `arena_destroy`, `arena_purge`, `arena_selection`, `page_map`, `process_page_map`, `process_arena`, `page_backing` |
| Metadata and subprocess | `meta`, `subproc`, `subproc_main_heaps`, `subproc_registry`, `tld`, `heap_registry` |
| Pages and queues | `page`, `page_queue`, `page_validity`, `alloc`, `aligned`, `remote_free`, `deferred_free`, `abandoned` |
| Threads and TLS | `thread_local`, `compiler_tls`, `owned_tls_key_registry`, `main_theap`, `main_heap_thread`, `main_heap_page`, `main_static_page`, `dynamic_theap`, `single_thread` |
| Process and runtime | `process_init`, `runtime_lifecycle`, `runtime_admission`, `runtime_destroy`, `bootstrap`, `diagnostic_output` |
| Source-shaped API and libc boundary (x86 only, doc-hidden) | `source_api`, `source_options_api`, `source_heap_api`, `local_fast_path`, `arena_print`, `support`, and `__crabc_runtime` (declared in `lib.rs`), the re-export libc consumes |
| Test and audit builds only | `test_process`, `test_context` (`test-adapter`), `theap_trace_audit` (`native-runtime-test-audit`), `native_local_trace`, `mapped_large_owner_exit`, `arena_singleton_regular_exit`, `arena_singleton_split_exit` |

`arena_owned`, `arena_huge`, `arena_destroy`, `arena_purge`, `arena_selection`,
`subproc_*`, `heap_registry`, `page_queue`, `heap_destroy`, `metadata_session`,
`runtime_admission`, and `runtime_destroy` are declared by `#[path]` from
`arena`, `subproc`, `types`, and `runtime_lifecycle` rather than from `lib.rs`.

## Architecture and ownership

### Process-static identity and startup

`subproc.rs` represents the process-static identity of `mi_process_subproc_main`:
the relaxed `thread_total_count` sequence, the relaxed live `thread_count`, the
real static `mi_process_tld_main` slot, and one private one-way atomic
detached-Theap identity admission slot. That slot maps only the identity role
of `subproc_main->theap_meta`: it is compared, never dereferenced. It is not a
claim about the layout of `mi_subproc_t`, `theap_meta_lock`, or normal C
metadata backing.

A linear non-`Send` ticket records the old value of
`thread_total_count.fetch_add(Relaxed)` before any storage choice. Ticket zero
initializes the actual `MemoryKind::Static` TLD slot without touching
`MetaAllocator`; later tickets use the direct-zeroed metadata route. An
allocation failure consumes its sequence value but never increments the live
count. Only a fully initialized TLD consumes its ticket into a registration
lease, whose explicit consuming release performs exactly one live-count
decrement.

`process_init.rs` owns one bounded source-order startup transition
(`init.c:505-579`): reserve the static ticket-zero branch, initialize the static
Heap, bind the static detached metadata image, Release-CAS publish that Theap
identity through the `MainSubprocess` admission slot before `BOUND`, publish the
distinct global PageMap, and only then attach the static TLD/Theap roots. A cold
metadata request (`zalloc`, aligned `zalloc`, `rezalloc(None)`) is rejected with
a typed unpublished-identity error before any lock, mapping, or capability.
`ProcessMainInitializationStorage` selects this path and blocks generic ticket
issuance once the static branch is selected.

The coordinator distinguishes source-attached allocation inputs from completed
startup. `ProcessMainAllocationLease` admits the initializing thread after
static Theap attachment and before reservations, exposing only frozen memory
configuration, the canonical PageMap, and VM policy/subprocess;
`ProcessMainReadyLease` requires completed startup. `ProcessMainStartup` is the
linear, thread-confined remainder: the runtime moves its `ProcessMainThread`
into the permanent owner slot, stores the shared main-Heap witness, and
Release-publishes `PROCESS_ALLOCATABLE` before consuming the continuation.
Worker attachment, shutdown, and fork preservation require final
`PROCESS_ACTIVE`. Startup runs huge reservation, regular reservation, and
diagnostic post-init before final readiness. Like C, an ignored reservation
failure leaves the continuation usable, and dropping an unfinished
continuation retains the published source state. No mutable owner, Theap, or
random-field reference is held across VM or output callbacks.

`StartupArenaReservationOutcomes` retains successful startup arena ids while
preserving C's scalar failure behavior (`init.c:566-579`). Page ownership does
not require that arena to be the only registry member: the canonical process
binding searches the published registry with the stored TLD NUMA value and
preserves `arena.c:470-569,781-821` suitability, reservation, and direct-OS
fallback decisions. `disallow_os_alloc` and `disallow_arena_alloc` remain
independent controls; no absent outcome is fabricated.
`disallow_os_alloc` blocks only a fresh OS reservation: a free-slice search of an
already registered arena runs first, so a registered parent still serves
allocations. `disallow_arena_alloc` skips the arena search and the startup
reservation but leaves the registered parent in place for the direct-OS
fallback. With both set the direct OS attempt is refused with `ENOMEM`. A
request that names an arena never reserves and returns `ENOMEM` on a miss;
the unrequested object form returns `EINVAL`, because pinned v3.5.0's only
caller always passes `heap->exclusive_arena`.

The x86 libc bridge is `libc/src/c_abi/x86_64/native_mimalloc_lifecycle.rs`.
`initialize_selected_process` runs after initial TLS, the validated environment
and `AT_PAGESZ` exist and before preinit or constructors (static startup calls it
from `static_startup.rs`, the dynamic product from `owned_dynamic_runtime::prepare`).
It publishes `NativeProcessStartupFacts` (page size, environment reader, stderr
output, `SourceErrnoStore`), calls `initialize_process`, and pins the initial
thread's source owner with `prepare_native_initial_thread_owner`, which reserves
no arena: the first allocation activates the owner and reserves one only if its
page claim needs it. A false result rejects startup; the C backend is never a
fallback. Each pthread child attaches before its start routine runs; the parent
waits and returns `EAGAIN` for a rejected attach, and a fatal mismatch
terminates the process. Normal return, `pthread_exit`, and cancellation finish
the Rust owner only after cleanup handlers and POSIX TSD destructors. (The
paused AArch64 `c_abi::__libc_start_main` instead retains a ticket-zero owner and,
under `native-mimalloc-shadow`, calls `prepare_native_later_thread_arena` to
establish the first arena before any later thread is admitted.)

### Metadata, TLD and Theap

`MetaAllocator` is one process-static, `!Unpin` owner. Preparation binds the
static detached Heap/TLD/Theap image and publishes its identity through the
subprocess before `BOUND`. Internal operations require
`Pin<&'static MetaAllocator>`, validate the current thread-pointer identity
(a Rust safety strengthening of C's non-null precondition), take a
nonrecursive `PrivateLock`, then lazily build a direct-OS page map and aligned
external arena in their final static slots. The ordinary page lifecycle
supplies metadata blocks; no `alloc`, libc, pthread, compiler-TLS root, slab,
or mmap-per-block path participates. A must-use, non-`Copy`
`MetaAllocation<'owner>` records owner address, size, and a `MemoryId` of kind
`MemoryKind::Malloc`, and owners (TLD, dynamic Theap, regular TLS backing, key-registry
bitmaps) retain and move it as a field, never reconstructing it from a raw
pointer. Every safe typed projection first checks that the capability's atomic
lifecycle is live. `rezalloc` keeps the source allocation-under-lock,
unlock-before-copy/free ordering. `PrivateLock` preserves the TLD field's
private-lock meaning but is not a pthread mutex, so no `sizeof(mi_tld_t)`
claim is made.

`ThreadLocalDataOwner` takes its ticket internally. Its TLD image names the
same process-main identity as the metadata bootstrap and records the direct
thread pointer, Linux NUMA, `is_in_threadpool = false`, an initialized private
lock, and a null theap list: it is **subprocess-attached, no-theap**.
`MainStaticTheapAttachment` is the sole static exception to generic ticket
zero. It owns cache-aligned, address-stable `Heap` and `Theap` field slots,
follows `mi_heap_main_init_once` with kind-only `MI_MEM_STATIC` provenance for
the Heap, and `_mi_theap_init` order for the Theap: empty-image copy,
TLD/refcount/subprocess, live options, locked TLD-list attachment with
random/cookie setup, Release heap publication, locked heap-list attachment. It
publishes the default root and then the fast root; cached and dynamic roots
stay immutable empties. Teardown follows `_mi_thread_done`
(`init.c:448-481`): `_mi_thread_locals_thread_done` first, then fast-root
clear, default/cached reset, heap-list then TLD-list detach, invalidate the TLD,
release the registration, and retire the static slot. `page_count == 0` is a
Rust pre-mutation requirement; a nonzero count poisons but preserves every live
root. Fallible lock or list failures after a root is reset are terminal
invalid-owner states (they need invalid concurrency or a kernel failure),
retaining process-static storage; heap-busy retry is not implemented.

`DynamicTheapAttachment` (the `_mi_theap_alloc` nonexclusive branch) is
`!Send`/`!Sync`. It holds a caller-pinned Heap and exact TLD, registration,
Theap, regular-backing, and key capabilities; it refuses ticket zero while the
static bootstrap is active or retained, publishes the regular-key slot after the
TLD and heap lists, replaces only the canonical empty cached root, and performs
the owner-only Theap reference `1 -> 2` transition. No-page teardown runs in this
order: clear the regular TLS backing root, restore the cached root (Theap
reference `2 -> 1`), detach the Theap from the Heap and TLD lists, release the
Theap metadata, tear down the TLD, retire the Heap's dynamic binding, and release
the key lease last.
The ordinary constructor stores the source abandoning option image
(`allow_page_abandon = true`, `page_full_retain = 2`); `page_session` rejects it
without touching an arena. A crate-private unsafe constructor stores the
non-abandoning image used by sealed page sessions. An unfinished engine `Drop`
latches the attachment terminally rather than allowing teardown to claim
quiescence. Failures after list publication retain a poisoned owner; a
pre-mutation key-release lock error (`AwaitingKeyRelease`) and a Malloc
backing release that rejects before its LIVE-to-RELEASING claim
(`AwaitingBackingRelease`, which keeps the backing root, key lease, TLD, Theap,
Heap binding, and any sealed engine and resumes only that release) are the sole
retry states; every post-claim error stays terminal. `MetaRelease`'s Malloc
branch returns the live capability as `MallocRetryable` only for the same
pre-claim rejections. `ArenaSliceClaim::release_for_subprocess` returns a claim
unchanged, before any purge or bitmap mutation, when the `MainSubprocess`
identity does not match (a fail-closed form of C's internal assertion).

The default-Theap allocation path for a native child uses the same phased
deferred-free protocol. When a callback is registered, an oversized request
runs the forced callback before returning the allocation miss. Callback
reentry can allocate through the child main Heap, while nested collection does
not invoke the callback recursively.

The regular TLS backing (`thread_local.rs`, `compiler_tls.rs`) is a
`mi_thread_locals_t`-shaped zeroed flexible image from `MetaAllocator`: 16
slots, doubling below 1024, plus 1024 at and above, a least-index override, a
derived count capped at 65535, `memid` then `count` published before the
dynamic root. Teardown clears only that root. If an internal metadata free or
replacement reports ownership-consumption ambiguity, the owner clears the root
and becomes terminal. `owned_tls_key_registry.rs` ports the process-global
regular-key bitmap (`threadlocal.c:221-315`) as allocator metadata, not
compiler TLS: a 16-bit-index/48-bit-generation stream under a private lock, a
1,024-bit first image growing by 1,024 bits per step to the 64,512-bit ceiling,
claims the lowest free index (the `tseq = 0` case), generation advanced only
after the one-bit claim, copy growth that Release-publishes the larger count before
marking the append free. A linear lease requires explicit release (drop does
not return a key). Lock order is registry then `MetaAllocator`.

### Statistics

`Theap`, `Heap`, and `MainSubprocess` each retain the complete v3.5.0
`mi_stats_t` image (source `size`/`version`, every `MI_STAT_FIELDS()` member in
declaration order, reserved records, 74 allocation, 74 page, and six chunk
bins). The native layout differential compares it with the C release image;
it does not claim an outer `mi_theap_t`/`mi_heap_t`/`mi_subproc_t` layout or a
public statistics ABI. `MainSubprocess` owns the sole subprocess image; its VM
and arena snapshot APIs are relaxed typed projections into it, with no
duplicate counters. Merges (Theap to Heap, non-main Heap to main Heap, main
Heap to subprocess) perform only the source declaration-order merge and reset;
callers own list, count, and lifetime. Aggregation follows `src/stats.c`'s
relaxed total/current/peak algorithm and is deliberately not a transactional
snapshot. The `MI_STAT=0` page engine records each event at its source boundary
(PageMap registration and release, retirement, queue scans, mapped
abandoned-page reclaim, abandonment publication, bitmap clear-once busy waits,
the five mapped `chunk_bins`). Fields whose producers are not attached
(thread/Heap lifecycle counts, free-side reclaim, `MI_STAT>0` producers) stay
zero by intent, not as alternate counters.

### Arenas, PageMap and page backing

- `process_page_map.rs` owns process-static source-page-map publication: it
  freezes one `MemoryConfig` and selected `MainSubprocess`, initializes a
  `PageMap` in its final slot, then Release-publishes the header root.
- `process_arena.rs` retains the `mi_manage_os_memory_ex2` sidecar for an
  external mapping and one explicit regular `mi_reserve_os_memory_ex2` entry (a
  caller-selected nonzero request that rounds to exactly one arena, binding the
  same map/root/main identity before publication). The final sidecar slot gives
  the in-place arena a stable callback to commit metadata and later ranges
  through that exact owner; with default features Linux decommit reports no
  recommit requirement (`mi-debug-1` or `mi-secure-3` on x86-64 changes that).
- `reserve_default_os_arena` ports the first lazy `mi_arena_reserve` decision:
  source max-page headroom, the frozen 1-GiB default, eager mapping only under
  overcommit, and a 128-MiB retry after an unpublished first attempt returns
  COLD. On native x86 the initial thread's lazy first-arena owner is
  `MainStaticRuntimeFirstArenaPageAllocator::begin_for_process`, formed from one
  coordinator-issued `ProcessMainBackingBinding` (policy and PageMap together); it
  never falls back to the explicit-config `begin_legacy` route, which compiles
  only for tests and non-x86 builds. Creating it has no reservation or mapping
  side effect. An
  unpublished metadata failure unmaps the exact regular map before returning
  COLD; a failed unmap retains the mapping terminally.
- `ProcessPageArenaLease` validates the immutable (map, arena) tuple before
  `main_static_page.rs` or `main_heap_page.rs` may borrow the selected Theap.
  Each owner holds the map's nonrecursive lifecycle lease for its complete
  engine, installs the arena's in-place `pages_main` bitmap in the shared static
  main Heap, and preserves the source order: bitmap -> PageMap publication on
  allocation, and PageMap -> bitmap -> metadata -> slice release on free.
  Fork, shutdown, and failure handling treat an unfinished engine as poisoning
  both the owner and the map root rather than fabricating a release route.
- `MainHeapThreadOwnerLocalPageEngine::begin_for_process` is the shared
  activation seam. `ArenaCandidates` shares the `mi_forall_suitable_arenas`
  traversal between fresh allocation and mapped-abandoned reclaim. Per-page
  release resolves the actual registry arena and reconciles its committed
  prefix before retiring metadata. The legacy paired-arena constructor remains
  for typed fixtures and the paused architecture; it is not the x86 fallback.
- Commit on demand: with `page_commit_on_demand=1`, regular metadata pages
  commit an arena claim's initial prefix through the retained owner before page
  capacity or free-list links publish; a failed extension takes C's false
  collection and fresh-page retry before the outer forced collection
  (`arena.c:951-1120`, `page.c:630-729,845-863`). `page_make_immediate`
  performs the direct mapping before `set_slice_pcommitted_after_commit` and
  `extend_count`.
- Delayed purge: slice release schedules the pinned four-second purge delay for
  unpinned arenas (`schedule_purge` in `arena_purge.rs`). Nothing is scheduled
  for a pinned arena, a negative delay, or while the process is still preloading
  (before startup completes or after process-done); a zero delay purges synchronously; expiry is set by
  a per-arena CAS and the global expiry only if that CAS won. `collect_purge`
  returns early while preloading or when the delay is not positive. Forced
  collection owns the free-bitmap range while
  applying the non-owning decommit, and a decommit advisory error leaves the
  mapping accessible and committed. Only the external owner unmaps its mapping.
- `ProcessArenaBacking::destroy_all` ports `arena.c:1542-1565` registry
  retirement after exclusive subprocess quiescence: snapshot owner identities
  while parent and child headers are mapped, then source index-order Release
  clears and OS frees. External mappings are unpublished without callbacks.
  Huge-failure bitmap storage is checked before the first mutation without
  calling the metadata allocator; `DestroyedArenas` retains failed maps and
  exact failed huge-page sets, and dropping it performs no syscall. The
  caller sequence is in [Process destruction](#process-destruction); default
  process-done retains backing.
- Aligned requests: `aligned.rs` picks the plan. For offset 0, an alignment above
  `PAGE_MAX_OVERALLOC_ALIGN` (64 KiB) takes the `HugeSingleton` plan
  (a request of at least `SMALL_SIZE_MAX + 1`). Aligned metadata profiles
  reject alignments at or above `PAGE_META_ALIGNMENT` (256 MiB); checked
  secure profiles use the source offset mapping there. Any nonzero offset
  with an alignment above 64 KiB has no plan and fails.
- Huge: `install_owned_huge_allocation` is the `arena.c:2167-2191` manage
  boundary; the registry retains one `ArenaBacking` per arena (`Regular` mapping, `Huge`
  allocation, published views, or external memory with only a callback lease and
  no unmap capability) and a huge owner never grants commit/decommit/purge. A span over the 16-GiB arena
  geometry is split by the source manage loop with one huge owner retained for
  all children. `arena_huge.rs` holds `reserve_huge_at` and
  `reserve_huge_interleaved` (node normalization, remainder distribution,
  per-node timeouts, first-error exit, successful partial prefixes). Only an
  unpublished manage rejection allocates failed-page tracking
  (`HugeReleaseMetadata`, from the detached metadata allocator, outside the
  regular reserve lock); `HugeOsAllocation::release_with_tracker` transfers it
  to `HugeOsRawReleaseRetry`, which touches only failed pages and never repeats
  statistics.
- Startup order: huge options run before explicit regular reservation, using
  only the default Theap random field for huge and regular aligned hints in
  that order, and both source outcomes are recorded before READY.

### Process destruction

Default process-done retains arena backing so later destructors and buffered-stdio
callbacks can still allocate. A nonzero `destroy_on_exit` option selects physical
destruction (`runtime_destroy.rs`): `native_process_done_action` reads the signed
option (`>= 2` makes the automatic finalizer skip process-done entirely; explicit
`mi_process_done` still destroys), `capture_native_process_destroy_request`
snapshots the process witnesses before libc takes its worker-registry pin,
`prepare_native_process_destroy` transfers every TLS owner under that pin, and
`NativePreparedProcessDestroy::finish` runs after the pin is released. `finish`
follows source order: unlink the terminal subprocess, force-destroy the main
Heap's Theaps, close the metadata engine, seal the coordinator, destroy the
subprocess arenas (`ProcessArenaBacking::destroy_all`, from external tracking
storage outside the retiring arenas), emit the final statistics, retire the
PageMap, then the `process done` tail. Any failure retains its exact owner and
is terminal; libc must not fall back to the retaining path or to C cleanup.

On the first native x86-64 child-destruction pass, an empty arena registry skips
arena-release retry storage. If arenas exist, the parent metadata allocator
supplies retry storage outside the child arenas before teardown; the child
record keeps that storage and the child owner across raw release failures, so
retries preserve custody of the remaining child state.

Main-Heap destruction (`heap_destroy.rs`, `force_destroy_main_heap_theaps_quiescent`)
runs after whole-process quiescence. Pinned `arena.c:2640-2643` returns early
for a main Heap in `_mi_heap_destroy_pages`, so its pages are released with the
arenas, and `mi_heap_free_theaps` does not free the TLDs: both stay in tracking
storage until arena destruction. The order is: recover every dynamic Theap, TLD
and registration into tracking slots (capacity checked first); detach every
Theap from its TLD list; then clear the Heap list, merge each Theap's statistics,
and decrement its reference. A Theap whose count reaches zero has its metadata
freed; a failed free is `Retryable` and `retry_theap_metadata_release` retries
that free only, never the list mutation or decrement. A Theap still referenced by
a cache is kept (`Cached`), and an error after a release was claimed is terminal.
No error permits releasing arenas or retrying the whole transition.

### Remote free and the Loom model

A remote free pushes onto the page's atomic `mi_thread_free_t` head with low-bit
state, touching only that page's atomic fields; the owner collects it during
ordinary operation or at finish. The production source of remote frees is the
pointer-first `native_free` path below. The regular generic scan consumes
publication before it extends or classifies a page full, and every non-abandoning
move to `BIN_FULL` performs the source's second false-force collection. The raw
owner-local projection ports the force-only list append and rejects a malformed
cycle before linking. An owner-side collection error permanently poisons the
allocator with the exact page, error, and popped block. A private linear
`RemoteFreeProducer` (`Send`/`!Sync`, with `publish` and `cancel`) borrows an
allocator for one scoped worker so tests can drive a controlled remote free; its
constructors have no non-test caller.

The test-only Loom model (`remote_free_loom.rs`, `cfg(all(test, feature =
"loom"))`) executes remote-head publication/detach and abandoned
owner-claim/unown races with PageMap entry, page metadata, owner fields, and
block links as Loom cells, so a release unordered with a legal client read
fails. The bitmap bfield operations, the identity replacement, and the
reader-quiescence loop are the shared production functions; only the atomic word
and the thread-yield boundary are substituted. Raw-pointer lifetime, owner-local
mutation, page identity, TLS, and page release are outside the proof.
`loom = "=0.7.2"` (defaults off) is optional and selected only by the `loom`
feature; its graph uses `std`, allocation, global scheduler state, and TLS and
brings a build script of its own (`generator`). `scripts/check_structure.py` pins
Loom's optional manifest shape and the `loom` feature and rejects any dev-dependency
table in the allocator manifest, so the graph is absent from every production
build. No check traverses the Loom graph for `x86_64-unknown-linux-musl`, and
passing Loom would not make x86 a production backend.

### Abandonment protocol

The protocol preserves mapped versus unmapped classification; publishes the
abandoned bitmap/count before releasing ownership; restores a failed reader's
bit; waits for reader quiescence before unabandoning; drains after the source
bitmap claim while still abandoned; and reassociates a claimed page and
performs the live-owner collection before queue insertion.
`abandoned::free_unmapped_after_failed_reclaim` runs only after the source
reclaim decision failed: it preserves a small partial head through the
expected-head CAS, collects a conflict without retrying reclaim, and selects
terminal-empty, mapped reabandonment, or unmapped unownership by the source
integer mostly-used boundary (`free <= reserved / 8` stays unmapped). It never
releases or reuses a page itself; terminal releases belong to the callers that
own the raw-release tail.

### Thread attach and owner exit

Worker attach: `runtime_lifecycle.rs::attach_current_thread` takes a
compiler-TLS entry claim that refuses recursive attachment before borrowing the
lifecycle slot or claiming a fork admission. The claim is released when the
outer call returns. The metadata/TLD/Theap constructor runs without a mutable
lifecycle-slot reference, so an allocator callback can observe the unattached
thread without aliasing. Presence checks copy only independent TLS flags and
lifecycle state through raw field projections and never form a mutable
reference to the whole TLS record. This is Rust ownership protection, not a
port of `MI_TLS_RECURSE_GUARD`, which the pinned Linux release does not enable.
The pthread handshake treats a recursive entry as a fatal lifecycle mismatch.

`main_heap_thread.rs` ports the later-thread branch of
`_mi_thread_init_with_heap(mi_heap_main())`. A shared-main-heap lease is
borrow-tied to the live initial owner and grants only short, lock-serialized
mutable projections of the main `Heap`; it cannot publish or retire the initial
thread's roots. A later thread obtains a metadata TLD and Theap, links the Theap
into the shared Heap, and publishes default before the fixed fast slot. After
user destructors, finish clears fast, resets default/cached, detaches heap list
then TLD list, frees the Theap metadata, tears down the TLD, and releases the
shared-main lifetime count; the main attachment rejects teardown while that count
is nonzero.

The C-facing boundary is the doc-hidden `crabc_mimalloc::__crabc_runtime`
re-export of `runtime_lifecycle.rs::{native_allocate, native_allocate_aligned,
native_reallocate, native_free, native_usable_size}`.
`libc/src/c_abi/x86_64/allocator_native_mimalloc.rs` calls the first four;
`static_c_abi.rs` calls `native_usable_size`.

- The initial thread's owner is `NativeInitialPersistentThreadOwner`; each
  attached worker keeps a compiler-TLS `NativePersistentThreadOwner`. Neither
  holds a client ledger: the Page and PageMap state are the allocation record.
- `native_free`, `native_usable_size`, and `native_reallocate` start from one
  PageMap lookup that captures the page, the canonical block (an aligned interior
  pointer is recovered from source-constant geometry), and an `xthread_id`
  snapshot. A match with the calling thread uses only its local engine. Every
  other live, abandoned, or mapped-abandoned state, including a page of the
  initial thread, takes the single `mi_free_block_mt(..., allow_collect=true)`
  publication in the remote-free tail: it touches only page atomics, borrows no
  owner TLD, Theap, or engine, and consults the process PageMap/arena and main
  Heap only after the CAS claims an abandoned head, as `mi_free_try_collect_mt`
  does (`remote_free::push_post_owner_exit_live_allocation`, then
  `abandoned::continue_post_owner_exit_remote_claim`). A claimed, still-used page
  is offered to the freeing thread's engine by `mi_abandoned_page_try_reclaim`
  before it is reabandoned or unowned, and an emptied one takes the terminal
  release. A `Detached` PageMap observation has no source producer; it is rejected
  before the CAS and is fail-closed: `native_free` returns `Retained`, and a
  `Detached` source of `native_reallocate` is refused the same way.
- A noncurrent `realloc` allocates and copies on the caller's persistent owner,
  frees the source pointer-first, and returns the replacement only after that
  succeeds; otherwise it rolls the unpublished replacement back and returns
  `Retained`. Only a current owner may enter the local realloc engine.
- There is no production exact-client post-exit registry, route, or admission held
  for an exited owner. `TicketZeroOwnerExitFreeRoute`, `NativePostExitRouteStorage`,
  `PreparedOwnerExitClients`, the detached client ledger,
  `CurrentThreadPageOwnerSession`, and the source-shaped publisher pairs are
  `#[cfg(test)]` oracles only (see
  [Test and audit builds](#test-and-audit-builds-exit-drains-and-the-retired-scheduler)).

`NativePersistentThreadOwner` performs owner exit in three phases around
`PageAllocatorEngine::collect_abandon_owner_exit`: phase A clears the fixed fast
TLS root and selects the deferred-free callback; phase B runs the value-only
deferred-free token through the allocator operation and fork admission boundary
after every owner, engine, attachment, Theap, and TLD projection has ended; phase
C revalidates the attachment generation before forming the exclusive drain. Phase
B marks the owner `RetainedTerminal` before it runs the prefix, so an error there is
terminal. Pinned `threadlocal.c` clears only `mi_slot_fast`; `alloc.c` keeps using
`_mi_theap_default()` until `init.c` resets it after all collect-abandon calls
return, so a callback's nested allocation stays on the old default Theap.
`ProductionOwnerExitCallbacks` begins after phase C and carries only the thread
id, the Theap pointer, PageMap/arena/Heap facts, and terminal scalar slots, so a
live remote producer retains only its page atomic projection and owner-side links
are accessed through disjoint raw projections; whole-page mutable access starts
only after the `used == 0` proof excludes the producer. Failure is one-way. The
collect result is `PreDrain` (retryable before the fast-slot transition),
`RetainedTerminalEngine` (fail-closed, never drains again), or `AttachmentOnly`
(only the no-page finish remains); the owner phase adds `DeferredFreePending`
(blocks teardown while phase B is live). The initial thread's owner stays
independent of a worker's exit.

`page_queue.rs::theap_collect_abandon_queues` is the queue half of
`mi_theap_collect_ex`: deferred frees, then retired pages, then every queue
through `MI_BIN_FULL`. For every callback-selected page the sequence is fixed:
force/false collection -> queue removal -> direct-cache update -> Theap
page-count decrement -> terminal release or abandonment. The callback cannot
choose geometry, alter queue state, or reorder the terminal transition. The
production callbacks (`ProductionOwnerExitCallbacks`) decide per page:

- `collect_page` force-collects; a page with `used == 0` is released, otherwise a
  false-force collection follows and a page now empty is released and any other
  is abandoned.
- Abandonment of an arena page that is not a singleton and has `used < reserved`
  is mapped: `abandoned::abandon_after_collect` publishes the exact bitmap/count
  pair (the main Heap's per-arena pair, or a non-main Heap's own
  `pages_abandoned[bin]` and count) before the source unown. A non-arena OS page
  is linked into the Heap's `os_abandoned_pages` list after its abandoned identity
  is visible and before the unown loop. A full regular page or an arena singleton
  stays source-unmapped. If the unown loop finds the page empty the owner finishes
  the terminal tail itself (OS-list removal precedes PageMap and mapping
  release). Any other memory kind is `UnsupportedPage`. OS pages of a
  child-subprocess Theap cannot yet be abandoned.
- Retirement (the `_mi_page_retire` fast path in `local_fast_path.rs`): an emptied
  page is retained on its queue and direct cache only if its bin is below
  `BIN_HUGE`, it has more than one reserved block (or is the eight-word class), and
  its queue holds exactly one page or at most `RETIRE_MAX_PAGES` (3) pages of
  blocks below `SMALL_SIZE_MAX`. Its countdown is `RETIRE_CYCLES` (16) for the
  eight-word class or blocks up to `SMALL_MAX_OBJ_SIZE`, `RETIRE_CYCLES / 4`
  above that.

### Test and audit builds: exit drains and the retired scheduler

Production owner exit is the generic coordinator above. The rest of this section
describes machinery that compiles only under `cfg(test)` or the default-off
`native-runtime-test-audit` feature. It stays because it pins the source order the
generic coordinator must reproduce, and because the ticket-zero C soak adapter
drives it; no production path calls it.

- The retired ticket-zero scheduler: a process-static staging engine and a state
  word (`READY`, `PARKED(n)`, `BUSY`) once serialized every native page operation,
  and a suspended engine was a counted parked session
  (`suspend_persistent`, `ProcessPageMapSuspendedEngineAccess`).
  `MainStaticProcessPageSession` bridged a ticket-zero page session to a
  shared-main lease with short `shared_heap_projection_lock` views. Production
  selects none of it.
- Typed per-geometry exit drains: `MainHeapThreadProcessPageExitDrain` (over the
  shared main `Heap`'s `pages_main`/`pages_abandoned`) and `DynamicThreadExitDrain`
  (over a dynamic Heap's `arena_pages` image) expose `abandon_*` handoffs for sole
  and aggregate full pages, mapped one- and two-block pages, and the direct-small,
  non-direct-small, medium, large, arena-singleton, and OS-aligned-singleton
  classes, with allocation-time adoption (`adopt_into_later_main`,
  `adopt_remaining_mapped_regular_into_later_main`,
  `DynamicMappedPageHandoff::adopt`, `reabandon_after_page_commit_failure`).
  They are bounded source-reachable cases, not a page traversal. Only test and
  audit code calls their `abandon_*` and adoption methods, and
  `PageAllocatorEngine::allocate` itself never scans abandoned pages.

The invariants they check, which the generic coordinator must also satisfy:

1. Admission is a complete non-mutating preflight of the whole queue/direct
   image; each member independently proves its rounded block size, bin,
   `reserved`/`used`, zero retirement countdown, empty local free list, and
   exact arena/PageMap span (1 slice small, 8 medium, 64 large; the large route
   has 63 PageMap-registered page-area slices plus one PageMap-null arena slice
   that is slack but released). Every queue's doubly linked image is validated.
   Unsupported or mixed images reject before any mutation.
2. The mutation order is the source order: retired-page prepass (releasing
   already-empty retired spans), then per page force collect, immediately release
   an all-free page, else false collect, queue detach, direct-cache refresh,
   page-count detach, and mapped publication or source-unmapped abandonment. The
   direct-small class requires `reserved >= 16` and the complete rounded
   `pages_free_direct` image. Direct-small frees use the partial collector, whose
   retained just-pushed head delays the unmapped-to-mapped transition by one free.
3. Abandoned identity is either unmapped (full pages, until a later free crosses
   `reserved / 8`) or mapped (exact `pages_abandoned[bin]` bit plus paired
   `Heap::abandoned_count[bin]`, published before unowning). A full page made
   nonfull by one joined remote free during force collection publishes mapped
   immediately; a full origin remains client-free-only and is never eligible for
   allocation-time adoption.
4. The old Theap/TLD is detached and freed before any later client free. A later
   client free re-resolves one PageMap member under a short lock, claims the
   source low owner bit, derives that member's bitmap/count capability, and takes
   the unmapped or mapped failed-reclaim tail. A terminal free releases only that
   member in the fixed order PageMap -> `pages_main` (dynamic: heap-local ordinary
   bit) -> metadata -> arena slices.
5. An arena singleton has no bitmap pair and takes a sealed raw terminal tail. An
   OS-aligned singleton lives in `BIN_HUGE` (not `BIN_FULL`) even if its object is
   small; it is linked into the Heap's `os_abandoned_pages` list before unown and
   removed before the clipped PageMap/alias/metadata/mapping release. A failed
   `munmap` retains the unique mapping owner terminally; there is no OS-list
   scanning, reclaim, or retry.
6. Any force/release failure after a source mutation latches a page-specific
   poison and retains the drain; a drain cannot allocate, run a public deferred
   callback or arena collection, or resume as a normal engine. `finish` retains
   the long PageMap lease rather than inferring all-free from queue detachment
   while a page may still be published.
7. Before the retirement prepass, the `MI_ABANDON` edge enters the deferred-free
   invocation phase while the old Theap/TLD pairing is live (heartbeat advance).

Allocation-time adoption is narrower than the release routes: it requires a fresh
attachment whose subprocess, configuration, PageMap root, main Heap and arena all
match, follows `arena.c:631-778,951-1153` and `page.c:245-302` (bitmap claim and
paired count, collect while abandoned, reassociate, collect live, re-prove span and
geometry, tail-enqueue, restore the direct-cache range before the page-count
increment), retains the target owner on any bitmap miss or post-claim failure,
and on a failed direct commit reabandons so the owner may retry only the same
candidate.

The dynamic drain additionally retains the cached root, both list memberships, the
dynamic arena image, and the PageMap until pages are resolved. On the first fresh
dynamic page its session lazily creates one `DynamicArenaPagesOwner`: it proves the
registry arena's non-null `Arena::subprocess` equals the selected main subprocess,
retains one zeroed `BCHUNK_SIZE`-aligned `MetaAllocation`, initializes the
`mi_arena_pages_t` header and ordinary bitmap, and Release-publishes the bound
Heap's `arena_pages[arena_index]` slot. Allocation order is page metadata,
heap-local bit, PageMap registration; rollback and release run the inverse. A
dynamic page leaves `Arena::pages_main` untouched; empty teardown removes the slot
before freeing the typed image, and a nonempty image is a pre-mutation rejection.
The ordinary `true`/`2` abandoning-handoff fixtures are `cfg(test)`.

### Diagnostic output owner

`diagnostic_output.rs` is a deliberately partial owner for the output side of
`options.c` (`15-16,111-178,347-549`; startup edge `init.c:505-550`; stderr
primitive `prim.c:862-866`) and the final-statistics text of `stats.c`. The x86
runtime retains it in `ProcessMainInitializationStorage` and initializes its
descriptors before VM, OS, and arena work. Its option defaults are
`show_errors=0`, `verbose=0`, and `max_warnings=32` (the initial warning limit is
16 until `initialize_source_options` installs the selected value).
`HugePageWarningRoute` (`MbindWarningRoute` is its legacy alias) lends it to the
huge-page reservation chain for each pinned huge-page warning: the one-GiB retry,
timeout, reservation failure, and `mbind` failure (`prim.c:630-645`).

- `OutputOwner` keeps the 16 KiB delayed buffer plus a NUL byte, a private lock,
  an independently Release-published callback and opaque argument, and the
  AcqRel warning counter. Messages go through `SourceFormattedMessage`, a
  992-byte stack buffer matching `mi_vfprintf` (at most 990 payload bytes plus
  NUL); it is not a general formatter.
- `_mi_fputs`' two deliveries are preserved: a custom callback first gets the
  `mimalloc: warning: thread 0x<THREAD-POINTER>: ` prefix, then the body. The
  thread pointer is `crabc_core::thread::thread_pointer_identity()` (the musl TCB
  self pointer, not `gettid`). With `verbose == 0` a disabled `show_errors`
  suppresses a warning; an enabled one is suppressed only when its
  pre-increment count exceeds a nonnegative maximum (cap 32 admits 33). With
  `verbose != 0` every warning is emitted regardless of `show_errors` and the cap.
- A custom registration flushes the delayed bytes once under the buffer lock and
  terminally stops the buffer; a null registration selects stderr without
  flushing; post-init flushes to stderr and selects stderr-plus-buffer.
- The callback and argument are non-owning. `register_output`, `raw_message`,
  and `warning` are unsafe: the caller keeps them alive through every in-flight
  delivery and serializes registration against dispatch. The source stores the
  pair independently, so a racing dispatch may see a mismatch (a source
  constraint, not a new framework). A registration-flush callback may reenter
  default dispatch but must not re-register or invoke post-init.
- Source-option reads take the private lock and release it before foreign
  output, so the staged invalid-`verbose` path restores the descriptor before
  delivery. A FILE primitive or callback may synchronously reenter the warning
  route (`warning_from_source_options`, `HugePageWarningRoute`), as in pinned C;
  a test covers a nested huge-page warning.
- Default stderr is `DefaultStderrOutput`, the caller-supplied
  `fputs(message, stderr)` capability held for process life
  (`RuntimeStderrOutput`); a single `write(2)` does not preserve musl's
  short-write behavior. The runtime adapter enters the descriptor-local
  diagnostic callback boundary before taking the FILE lock, so a refused or
  nested scope makes no `fputs` delivery.
- Final statistics: `RuntimeProcessStorage::finish_selected_default_release_process_after_user_atexit`
  (`runtime_lifecycle.rs`) evaluates the signed `show_stats || verbose` condition
  after its state checks and before its retaining merges. A source-disabled
  decision (skip) is distinct from an unavailable option owner (permanently
  retains the claimed process-done transition). A one-shot permit renders the
  fixed `MI_STAT=0` view in 255-byte fragments. `NativePreparedProcessDestroy::finish`
  re-evaluates the same gate after arena retirement and before PageMap
  retirement, then emits the `process done` tail after PageMap retirement.

### Random state

`random.c` is a ChaCha20 PRNG/DRBG, so it may not be translated locally.
`crabc-core::rand` supplies raw entropy. The dependency is `chacha20 = "=0.10.1"`
(defaults off; `legacy` and `zeroize`) plus `zeroize = "=1.9.0"` (defaults
off). A third direct dependency, `rand_xoshiro = "=0.8.1"` (defaults off, plus
`rand_core`), supplies `SplitMix64` for the source's page shuffle
(`random::shuffle`, compiled for x86-64 only; see `crabc-mimalloc/UPSTREAM.md`).
The selected x86-64 graph beyond `crabc-core` is exactly: `chacha20`, `cfg-if`,
`cipher`, `block-buffer`, `hybrid-array`, `typenum`, `crypto-common`, `inout`,
`zeroize`, `cpufeatures` (chacha20's `no_std` x86 CPUID helper), `rand_xoshiro`,
and `rand_core`. No `libc` package is selected. On the paused AArch64 target the
expected graph is the first nine and excludes `cpufeatures` and the
`rand_xoshiro` pair. `allocator --quick` traverses Cargo metadata for the target
and rejects any selected package, version, edge, source, build script, or proc
macro outside that list (`EXPECTED_*_DEPENDENCY_*` in `compat/allocator/run.py`).

`random::TheapRandomImage` is the authoritative `#[repr(C)]` `mi_random_ctx_t`
layout (sigma/key in `input[0..12]`, 64-bit counter in `[12..14]`, 64-bit nonce
in `[14..16]`, then output/availability/weak fields). `ChaCha20LegacyCore` runs
one block at a time, preserving the counter carry into only the low nonce word,
output word ordering, immediate clearing of consumed words, and the eager child
block after `split_into`. Initialization and split derive nonces from the stable
random-field address; they never return a movable child. `initialize` calls
`getrandom` once; an error or short fill marks the image weak. The source's
`_mi_random_shuffle` core cannot be translated under the crypto policy, so
`WeakObservations` (address, monotonic clock, thread pointer, pid/tid, fixed-zero
extra seed) feeds a domain-separated `ChaCha20LegacyCore` expansion: an accepted
difference that adds no entropy and no second PRNG. `reinitialize_if_weak`
retries entropy only for a weak image. Images and temporary key/output copies are
zeroized; metadata release bypasses Rust drop glue, so the owner must call
`TheapRandomImage::clear` before returning a live Theap image.
`CurrentDefaultTheapRandom` resolves compiler TLS at each OS-hint draw with a
short exclusive projection that ends before any VM action or diagnostic
delivery; it never projects the immutable empty Theap mutably.

### Fork

Two paths exist because a raw process copy cannot repair locks held by vanished
threads.

- Prepared copy (`fork`, static and dynamic native-shadow products). Full `fork`
  runs public prepare handlers, takes every libc fork lock including the
  selected worker-list lock (which is the registry pin), and closes the
  allocator epoch last, immediately before the syscall; nothing allocates until
  completion. `begin_native_allocator_source_fork_quiescence` drains source
  entries and reads each pinned owner; a callback-pending, poisoned, or retained
  owner refuses before copying and reopens only the same precommit epoch, and
  `fork` then fails with `EAGAIN` after its parent handlers. The parent reopens
  the exact generation right after the syscall, even on failure.
  Callback markers are published before entry can be suspended. The wiring is
  `libc/src/c_abi/x86_64/pthread_atfork.rs` (`NativeAllocatorCopy`) and
  `pthread_create_join.rs`.
- In the child, `NativeAllocatorForkChildContinuation` retains authority over
  the copied descriptor/control/TLS graph. Libc postpones allocation, registry
  reset, caller adoption, unmapping, and thread creation until
  `repair_source_owners` returns; repair takes no libc lock and emits no foreign
  output. The survivor is identified once and never retired; each vanished owner
  runs the existing retired-page, remote-free, queue-detach, and abandonment
  algorithms through the borrow-scoped `TheapCollectAbandonFieldAccess`, then
  retires its Theap/TLD capabilities. No foreign deferred callback runs for a
  vanished thread. A vanished initial owner enters
  `ProcessMainThreadState::MainThreadDetached`. Just before reopening, repair
  re-roots `native_allocator_initial_thread_descriptor` to the survivor. Partial
  failure keeps its residual owners, never re-roots, seals entry, and the child
  calls `_Exit(127)`. Public parent and child handlers run with allocation open.
  mimalloc v3.5.0 has no Linux atfork owner-repair to port; this is crabc
  runtime integration around the source collection algorithms.
- Raw copy (`_Fork`, non-VM `clone`): `begin_native_allocator_raw_fork_copy`.
  Nothing drained the other owners, so the child trusts none of them; its own
  owner stays usable. When the survivor is a worker, `complete_child` marks the
  copied initial descriptor retained so a later prepared fork or terminal
  writer refuses instead of waiting on a copied entry. A raw copy from the sole
  owner is a complete image.

### Thread-local access model

The allocator's compiler-TLS roots are hidden `STT_TLS` objects accessed with
initial-exec relocations and no `__tls_get_addr`. Rust has no per-static TLS
model annotation, so initial-exec is target-wide: the x86-64 owned-sysroot
builders (`scripts/build_x86_64_owned_sysroot.py`,
`scripts/build_x86_64_owned_dynamic_sysroot.py`) pass `-Ztls-model=initial-exec`.
`./compat/allocator/run-x86_64.sh allocator-tls` checks the access shape on a
probe object (`R_X86_64_GOTTPOFF` for every root, an exact `%fs:0` load for the
ownership identity), not on the linked products; the builders' flag is what
applies the model to them. Cargo
passes target rustflags to dynamically loaded build scripts and proc macros
too, which breaks proc-macro crates on a raw native build; the paused AArch64
`scripts/rustc_test_host_tool_wrapper.sh` strips that flag for host tools only.

## Intentional differences and safety corrections

The authoritative register is `compat/allocator/known-differences.md`. The design
invariants behind the ones this document touches:

- On-demand OS fallback: with `disallow_arena_alloc=1` and
  `page_commit_on_demand=1`, `arena.c:819-855` reserves the OS span with
  `commit == false`, commits only metadata, then unconditionally sets
  `initially_committed`, so `_mi_page_init` writes free-list links into a
  `PROT_NONE` area. `OsAlignedPageClaim::allocate_on_demand_for_process` keeps
  the reservation and metadata commit, but `commit_initial_page_prefix` must
  succeed before the Page is published with nonzero `slice_pcommitted` or any
  capacity/free-list state; terminal release subtracts exactly the recorded
  prefix.
- The weak-entropy key expansion (above) and the Rust recursion guard on worker
  attach are Rust-side substitutes, not source ports.

## Test seams and invocation

Run a focused unit test through the x86 launcher, for example
`./compat/allocator/run-x86_64.sh allocator-unit --filter module::tests::exact_name`;
`allocator-native-integration` runs every `crabc-mimalloc/tests/native_*`
runtime witness (each target is a separate process, built with the audit and
fault seams those targets require). Under `cfg(miri)` the unchanged `os.rs`
runs over `crabc-core`'s Miri kernel model (`crabc-core/src/miri_model.rs`),
which replaces the raw syscall seams, the `%fs:0` thread-pointer read, and the
typed pointer-returning seams; `allocator-m3` includes the Miri components.
Other subcommands are listed by `./compat/allocator/run-x86_64.sh --help`.

`compat/allocator/test-adapter` exports 16 `crabc_test_*` symbols by default (19
with its `test-arena-diagnostics` feature) and no standard allocation or `mi_*`
symbols; the evidence lane uses it for the
crabc allocator fixture, 33 reviewed checks from the hash-pinned `test-api.c`,
and the reviewed `adapted/test-stress-creating-thread.patch` applied to
`test-stress.c` (single creating thread, `1 1 2` workload; unsupported modes
hard-reject). Contracts and omissions live in `adapted-tests-v3.5.0.json` and
`adapted-stress-test-v3.5.0.json`, not in copied upstream source.
`compat/allocator/runtime-ticket-zero-adapter` is a `no_std` evidence staticlib
exposing prefixed C calls to a fresh test process; it is not a crabc libc ABI,
backend, or fork repair mechanism.

Installed-product checks for the native-shadow libc, in the pinned native
environment: `./scripts/dev-x86_64.sh owned-native-allocator-fork` (fork and
atfork allocation against musl, including repeated forks under cross-thread
churn) and `owned-native-allocator-stress` (the unmodified pinned
`test/test-stress.c` bound to `calloc`/`realloc`/`free`, plus the seeded
`compat/x86_64/owned_native_allocator_soak_probe.c`).

Differential traces are address-independent facts compared between the pinned C
oracle and the Rust engine; a trace establishes only the private route it
exercises. Many test-only seams (for example
`PageAllocatorEngine::test_bind_page_area_commit_lease`, and
`test_enable_page_commit_on_demand` on the main-Heap allocator types) are
`cfg(test)` and are not production options.
