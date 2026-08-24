# mimalloc v3.5.0 upstream provenance

## Fixed source

The incomplete `crabc-mimalloc` engine is a semantic port of this exact source;
it must never follow upstream `main`.

| Field | Pinned value |
| --- | --- |
| Repository | `https://github.com/microsoft/mimalloc` |
| Release | v3.5.0, released 2026-08-19 |
| Tag object | `438b0c4b78d2599aede7fca3ddacc28863b0eae8` |
| Peeled tag commit | `18b08671c9302247bfb682286e6bf3cc1773f801` |
| Source archive | `https://codeload.github.com/microsoft/mimalloc/tar.gz/refs/tags/v3.5.0` |
| Archive SHA-256 | `1e432f0559a4ab512143b9bff7a700541a2c8d4712b26a72de3e0222790da305` |

The archive hash identifies the bytes at the listed URL. Any fetch must verify
both that the annotated tag peels to the recorded commit and that the fetched
archive has this SHA-256 before it is used as source or an oracle.

## License provenance

The pinned upstream repository's `LICENSE` is MIT. The exact notice at the
pinned commit is reproduced here because the future translated source is a
substantial derivative of that distribution:

```text
MIT License

Copyright (c) 2018-2025 Microsoft Corporation, Daan Leijen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

Every translated module preserves the applicable pinned source-specific
copyright and MIT notice. The `crabc-mimalloc` package is consequently
MIT-only.
Before translating another source file, add its actual upstream file/function
provenance and preserve that file's source-specific copyright and MIT notice
together with this license notice. Do not substitute the workspace `MIT OR
Apache-2.0` header for upstream-derived code, and do not invent or merge
copyright lines when the source file states a different one.
Original crabc-only files continue to follow their own applicable licensing.

For example, the pinned root `LICENSE` notice above names “Microsoft
Corporation, Daan Leijen” and years 2018–2025, while pinned `src/alloc.c`
states “Copyright (c) 2018-2026, Microsoft Research, Daan Leijen.” A module
translated from that file must preserve the latter file-specific notice and
the MIT permission notice; it must not normalize the two notices into an
invented third form.

## Source-to-Rust mapping

| Upstream path and function group | Rust module | Provenance/notice status |
| --- | --- | --- |
| `include/mimalloc/bits.h`: `mi_popcount`, `mi_ctz`, `mi_clz`, `mi_bsf`, `mi_bsr`, `mi_rotr`, `mi_rotl`, `mi_rotl32` | `src/bits.rs` | Source-specific 2019–2024 Microsoft Research/Daan Leijen MIT notice preserved |
| `include/mimalloc/atomic.h`: word/pointer `mi_atomic_{load,store,exchange,cas,add,sub,and,or}_*`, increment/decrement forms, `mi_atomic_addi`/`mi_atomic_subi`, signed-64-bit statistics/timer forms, and `mi_atomic_guard` | `src/atomic.rs` | Source-specific 2018–2024 Microsoft Research/Daan Leijen MIT notice preserved; exact Relaxed/Acquire/Release/AcqRel pairs retained |
| `include/mimalloc/types.h`, `include/mimalloc/bits.h`, `include/mimalloc/internal.h`, and `src/bitmap.h`: normal-release Linux/AArch64 constants | `src/config.rs` | Applicable 2018–2026 and 2019–2024 source-specific Microsoft Research/Daan Leijen MIT notices preserved; resolved values are frozen, not runtime policy |
| `include/mimalloc/types.h`: memory/page/queue/arena layouts and the `mi_heap_t`, `mi_tld_t`, and `mi_theap_t` bootstrap prefixes; `src/init.c`: empty page, queue, direct-table, detached-TLD, and empty-theap images | `src/types.rs` | Source-specific 2018–2026 Microsoft Research/Daan Leijen MIT notice preserved; arena layouts and the represented theap prefix offsets are C-oracle checked, and disjoint raw page projections cover the selected live-owner and abandoned-page atomic protocols, while the omitted heap/TLD/theap tails, subprocess, and statistics layouts remain unclaimed |
| `include/mimalloc/internal.h`: `_mi_align_up`, `_mi_align_down`, `_mi_divide_up`, `_mi_wsize_from_size`, slice conversions | `src/invariants.rs` | Source-specific 2018–2026 Microsoft Research/Daan Leijen MIT notice preserved; invalid caller preconditions and overflow are explicit `Option` results |
| `include/mimalloc/types.h` and `include/mimalloc/internal.h`: memory-kind classification, `_mi_memid_create*`, and `_mi_memid_size` | `src/provenance.rs` with representations in `src/types.rs` | Source-specific 2018–2026 Microsoft Research/Daan Leijen MIT notice preserved; integer address arithmetic never reconstructs a pointer |
| `src/page-queue.c`: `mi_bin`, `_mi_bin`, `_mi_bin_size`, `mi_good_size`; `include/mimalloc/internal.h`: alignment/count/word-size checks; `src/arena.c`: regular/singleton size selection | `src/size_class.rs` | Source-specific 2018–2024 and 2018–2026 Microsoft Research/Daan Leijen MIT notices preserved; exact default `MI_ALIGN2W` small-bin behavior retained |
| `include/mimalloc/internal.h`: `_mi_page_map_index`; `src/page-map.c`: mapped header sizing, virtual-bit bounds, incremental commitment, locked lazy submap publication, range registration/rollback/lookup, and destruction | `src/page_map.rs` | Source-specific 2023–2026 Microsoft Research/Daan Leijen MIT notice preserved; the header uses the allocator-private futex lock rather than pthread ABI layout, and explicit unsafe destruction carries root-clear/quiescence obligations; global once/empty-root policy remains absent |
| `src/bitmap.h`: 64-bit field/chunk plus ordinary and binned dynamic bitmap representations; `src/bitmap.c`: masks, set/clear/query/popcount, exact claims, source-ordered search, size-bin maps, rollback, scalar Relaxed observers, caller-owned sizing/initialization, cross-chunk operations, conservative chunk maps, abandoned-page single-bit claim visitor, and clear-once-set reader quiescence | `src/bitmap.rs` | Source-specific 2019–2026 and 2019–2024 Microsoft Research/Daan Leijen MIT notices preserved; `BitmapView` and `BinnedBitmapView` bind C flexible layouts to caller-owned storage, while general visitors, statistics counters, and allocator-backed metadata remain absent |
| `src/arena.c`: arena identity/suitability/registry, metadata and bitmap sizing, in-place initialization, external-region alignment, 16-GiB splitting, single-arena contiguous claims, aligned page-metadata commitment, claim rollback, slice release, frozen-default delayed purge collection, and the main-heap abandoned-page bitmap capability | `src/arena.rs` with fixed layouts in `src/types.rs` | Source-specific 2019–2026 Microsoft Research/Daan Leijen MIT notice preserved; unpinned release schedules the source four-second `purge_decommits=1` path, forced collection claims the free bitmap during decommit, pinned backing skips it, and failures retain availability/retry state; registry-wide search, default OS reservation, alternate purge policy, statistics, and allocator-backed heap-local arena-pages metadata remain absent |
| `src/page-queue.c`: queue predicates and intrusive link/count/flag transition kernels from remove/push/move/enqueue operations | `src/page_queue.rs`, nested under `src/types.rs` | Source-specific 2018–2024 Microsoft Research/Daan Leijen MIT notice preserved; `_metadata` names make absent theap direct-cache/page-count/full-size accounting explicit |
| `include/mimalloc/internal.h`, `src/page.c`, and `src/arena.c`: regular/singleton slice counts, separated-metadata starts, object counts/offsets, and default scalar capacity-extension arithmetic | `src/page.rs` | Source-specific 2018–2024 and 2019–2026 Microsoft Research/Daan Leijen MIT notices preserved; pure geometry only, with no live page/theap ownership or free-list writes |
| `src/init.c`, `src/theap.c`, `include/mimalloc/types.h`, and `include/mimalloc/internal.h`: empty/default-theap bootstrap, source initialization predicate, direct cache, queues, page accounting, and retired-bin bounds | `src/bootstrap.rs` with prefixes and page publication in `src/types.rs` | Source-specific 2018–2026 Microsoft Research/Daan Leijen MIT notice preserved; caller pinning and an explicit validated thread identity replace absent TLS installation, and this bounded mode deliberately disables abandonment |
| `src/subproc.c:19-88`: `_mi_meta_zalloc`, `_mi_meta_zalloc_aligned`, `_mi_meta_rezalloc`, the successful `MI_MEM_MALLOC` release route, and `_mi_meta_is_meta_page`; with static ordering context from `src/init.c:15-145,184-208` | `src/meta.rs` over `src/os.rs`, `src/page_map.rs`, `src/arena.rs`, `src/bootstrap.rs`, and `src/single_thread.rs` | Source-specific 2018–2026 Microsoft Research/Daan Leijen MIT notice preserved; the process-static, `!Unpin` owner is usable only through `Pin<&'static MetaAllocator>`, validates a live TP identity before its private lock, retains owner-bound `MetaAllocation` capabilities, and uses the existing detached ordinary-page lifecycle rather than a bespoke metadata allocator. It deliberately omits source null/needs-no-free and non-Malloc arena-release branches, subprocess state/destruction, full process initialization, and all public allocator integration. |
| `include/mimalloc/internal.h`, `src/page.c`, `src/alloc.c`, and `src/free.c`: scalar unencoded block links, capacity extension, allocation pop/zero, quick/local collection, and owner-local `local_free` | `src/free_list.rs` | Applicable source-specific 2018–2026 notices preserved; the shared borrowed core mutates the real live-page projection, while encoded links, padding/security, cross-thread `xthread_free`, and queue policy remain outside this module. Pinned v3.5.0 has no separate delayed-free state; `_mi_deferred_free` is an unrelated user callback. |
| `include/mimalloc/types.h`, `src/free.c`, and `src/page.c`: low-bit `mi_thread_free_t`, normal and abandoned `allow_collect` remote push, atomic owner detach/claim/unown, and merge into the owner local list | `src/remote_free.rs` with disjoint raw projections in `src/types.rs` | Applicable source-specific 2018–2026 notices preserved; AcqRel/Acquire publication and collection operate on stable live page metadata without a concurrent whole-`Page` reference, and the exact head transitions are shared with four bounded Loom schedules; allocation/free routing, `_mi_deferred_free`, TLS attachment, terminal retirement/release, and raw-pointer lifetime modeling remain absent |
| `src/page.c:_mi_page_abandon`, `src/arena.c` abandoned-page claim/publication/unown paths, `src/free.c` abandoned owner acquisition, and `include/mimalloc/internal.h` page identity/ownership helpers | `src/abandoned.rs`, `src/arena.rs`, `src/bitmap.rs`, `src/remote_free.rs`, and raw projections in `src/types.rs` | Applicable source-specific 2018–2026 and 2019–2026 notices preserved; one queue-detached stable page can publish mapped/unmapped abandonment, release or claim its low owner bit, restore a failed reader bit, wait for reader quiescence, and reassociate before collection. Queue integration, terminal release/reuse, live arena metadata lookup, heap-local arena-page images, TLS/theap lifecycle, and producer-owned reclaim policy remain absent. |
| `src/alloc.c`, `src/alloc-aligned.c`, `src/free.c`, `src/page.c`, `src/page-queue.c`, and `src/arena.c`: explicit default-theap ordinary/counted/aligned allocation, free, usable-size and realloc composition, page publication and full-span registration, direct/generic candidate/regular/full queues, small/medium/large/singleton geometry, retirement, terminal release, and external-arena purge collection | `src/single_thread.rs` | Applicable 2018–2026, 2018–2024, and 2019–2026 source-specific notices preserved; exact small and fundamental C logical traces are matched, OS-aligned singleton mappings retain failed terminal release ownership for retry, and the private bounded lifecycle deliberately excludes TLS integration, remote-free routing, abandonment, default OS arena reservation, and production public API policy |
| `src/alloc.c`: ordinary realloc reuse and replacement extents | `src/alloc.rs` | Source-specific 2018–2026 Microsoft Research/Daan Leijen MIT notice preserved; floor-half reuse, copy extent, last-word zero start, and zero-size clear are pure policy kernels, not yet a live realloc operation |
| `src/alloc-aligned.c` and `src/free.c`: natural/overallocated/huge aligned request selection, adjustment, base recovery, aligned usable size, and aligned realloc reuse | `src/aligned.rs` with live composition in `src/single_thread.rs` and the page flag in `src/types.rs` | Source-specific 2018–2026 Microsoft Research/Daan Leijen MIT notice preserved; checked kernels retain the ordinary-versus-aligned half-threshold distinction, and the bounded default-theap slice composes live aligned allocation/free/realloc through the source's 256-MiB metadata-alignment limit |
| `src/random.c`: `chacha_init`, `chacha_block`, `chacha_next32`, `chacha_split`, `_mi_random_next`, `_mi_random_split`, and conditional weak-context reinitialization | `src/random.rs` over RustCrypto `ChaCha20LegacyCore` and `zeroize` | Source-specific 2019–2021 Microsoft Research/Daan Leijen MIT notice preserved; the approved dependency owns all ChaCha rounds, while this module retains the source counter/nonce, buffering, clearing, output-order, split, and weak-state contracts; OS entropy acquisition and weak-key synthesis remain outside this slice |
| `include/mimalloc/prim.h`, `src/prim/prim.c`, `src/prim/unix/prim.c`: Linux memory observations, regular and aligned maps, mapping transitions, and clock/process/thread/NUMA/yield/entropy observations; `src/os.c`: immutable memory configuration, allocation-size policy, page-range alignment, and non-owning arena decommit | `src/os.rs` over `crabc-core` raw primitives | Source-specific 2018–2026 Microsoft Research/Daan Leijen MIT notice preserved; MAP_NORESERVE, aligned overmapping/trimming, explicit published ownership, retryable terminal-release ownership, and `MADV_DONTNEED` without external unmap are present, while randomized hints, option-driven THP/huge-page policy, statistics, and full OS allocation lifecycle remain absent |
| `include/mimalloc/prim-tls.h` and `src/threadlocal.c:23-214,249-315`: AArch64 16-bit index/48-bit version key encoding, generation transition, stale-key rejection, locked global key registry, and regular slot get/set expansion semantics | `src/compiler_tls.rs`, `src/meta.rs`, and `src/thread_local.rs` | Source-specific 2019–2026 Microsoft Research/Daan Leijen MIT notice preserved; the regular current-thread owner maps the source flexible backing through an owner-bound typed metadata capability, uses exact allocation/growth/root-publication order, and clears the dynamic root after the regular free attempt. The registry blocks remain caller-owned; no TLD/theap attachment, global allocator-backed key registry, real process/pthread lifecycle hook, or production ELF integration is claimed. An internal metadata free/replacement error with consumption-ambiguous ownership terminally clears the root rather than retaining a false retry capability. |
| `include/mimalloc/atomic.h`: active `MI_USE_PTHREADS` private normal-mutex capability | `src/lock.rs` over `crabc-core` private futex primitives | Source-specific 2018–2024 Microsoft Research/Daan Leijen MIT notice preserved; the no-libc boundary uses a documented 0/1/2 futex state machine and makes no once or fork-repair claim |
| `src/libc.c`: bounded byte-string helpers; `include/mimalloc/internal.h`: byte copy/fill/zero helpers and aligned forms | `src/support.rs` | Source-specific 2018–2026 Microsoft Research/Daan Leijen MIT notice preserved; the support slice excludes getenv, once, pthread, CPU detection, and formatting |
| `src/libc.c`: `_mi_atomic_once_enter`/`_mi_atomic_once_release`; `include/mimalloc/atomic.h`: `mi_atomic_once_t` | `src/once.rs` over `src/lock.rs` | Source-specific 2018–2024 and 2018–2026 Microsoft Research/Daan Leijen MIT notices preserved; thread identity is an explicit validated input and a non-Send completion token owns the release obligation |
| Test-only mapping transitions corresponding to `src/prim/unix/prim.c` and `src/os.c` | `src/os_host_model.rs` under `cfg(miri)` | Original crabc verification instrument; fixed-capacity atomically owned static slots preserve pointer provenance, concurrent page-map commitment, non-owning arena decommit, and logical transitions but do not model protection faults, RSS, delayed clock progression, or kernel reclamation |

The completed mapping records the exact upstream path, relevant functions or
types, target Rust module, source-specific notice, and every intentional
deviation. It is a reviewable translation ledger, not an aspirational module
plan.

## Configuration profile

The only frozen production profile in Milestone 0 is Linux/AArch64
little-endian with Linux >= 5.10 and valid Linux/AArch64 page sizes; 4-KiB page
size is not assumed. The engine is `#![no_std]`, uses neither `alloc`
nor libc, compiles no C/C++, and has no native build script.

Actual mimalloc v3.5.0 configuration options, public API modes, and
Linux/AArch64 applicability must be mechanically inventoried from the pinned
headers, declarations, symbols, and upstream tests before they are selected.
No undocumented configuration default or feature reduction is implied by this
document.

## Intentional deviations

There are no accepted semantic or algorithmic deviations. `src/bits.rs` maps
the upstream compiler-builtin selection to Rust integer intrinsics and maps
the `mi_bsf`/`mi_bsr` boolean-plus-out-parameter result to `Option<usize>`;
exhaustive and boundary tests preserve the same value semantics. `src/atomic.rs`
maps C macro type polymorphism to concrete `AtomicUsize`, `AtomicIsize`,
`AtomicI64`, and `AtomicPtr<T>` functions while retaining every selected
success/failure ordering pair; its RAII guard preserves the macro's AcqRel
acquisition and Release scope exit. These are language-boundary adaptations,
not algorithmic deviations. Foundation arithmetic similarly maps internal C
assertion preconditions and checked overflow outcomes to private `Option`
results; `Address` retains only an address number and never manufactures a
pointer. The allocator-private lock maps the active normal process-private
mutex capability to an allocation-free private futex lock because the engine
cannot depend on public pthread APIs; it retains Acquire/Release exclusion but
does not imply fork repair. The once protocol similarly takes an explicit
validated thread identity and represents the valid C enter/body/release scope
with a completion token; it does not execute callbacks or define initializer
failure policy. The bounded string helpers avoid the C source's
condition-order re-read after N equal bytes, without changing any
valid-program result. The Miri host model is test instrumentation rather than
a production backend. The port must preserve upstream behavior until a
deviation is entered in
[`compat/allocator/known-differences.md`](../compat/allocator/known-differences.md)
with its design note, exact-C differential evidence, and Linux/AArch64
performance evidence.

The required crabc integration boundaries are not engine divergences:
`crabc-libc` owns C ABI and `errno`; `crabc-mimalloc` remains errno-free; and
thread/fork hooks integrate directly with crabc runtime lifecycle rather than
through public pthread APIs.

## Upstream update procedure

1. Do not change this pin as part of allocator implementation work.
2. Propose a separate upstream-update change naming the new release and commit.
3. Download its immutable archive, record and verify its SHA-256, and generate
   a source, public-API, and configuration diff against v3.5.0.
4. Review license notices and update the source-to-Rust mapping for every
   affected translation.
5. Re-run the complete correctness, differential, and Linux/AArch64
   performance/memory evidence before any promotion claim.

A later tag is not evidence that this fixed-port contract has changed.
