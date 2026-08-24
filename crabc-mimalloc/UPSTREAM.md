# mimalloc v3.5.0 upstream provenance

## Fixed source

The planned `crabc-mimalloc` engine is a semantic port of this exact source;
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
| `include/mimalloc/types.h`: `mi_memkind_t`, `mi_memid_t`, page flags, `mi_page_t`, `mi_page_kind_t`, and `mi_page_queue_t`; `src/init.c`: `mi_page_empty` and `MI_PAGE_QUEUES_EMPTY` | `src/types.rs` | Source-specific 2018–2026 Microsoft Research/Daan Leijen MIT notice preserved; heap/theap/TLD layouts remain absent until their lifecycle slices |
| `include/mimalloc/internal.h`: `_mi_align_up`, `_mi_align_down`, `_mi_divide_up`, `_mi_wsize_from_size`, slice conversions | `src/invariants.rs` | Source-specific 2018–2026 Microsoft Research/Daan Leijen MIT notice preserved; invalid caller preconditions and overflow are explicit `Option` results |
| `include/mimalloc/types.h` and `include/mimalloc/internal.h`: memory-kind classification, `_mi_memid_create*`, and `_mi_memid_size` | `src/provenance.rs` with representations in `src/types.rs` | Source-specific 2018–2026 Microsoft Research/Daan Leijen MIT notice preserved; integer address arithmetic never reconstructs a pointer |
| `src/page-queue.c`: `mi_bin`, `_mi_bin`, `_mi_bin_size`, `mi_good_size`; `include/mimalloc/internal.h`: alignment/count/word-size checks; `src/arena.c`: regular/singleton size selection | `src/size_class.rs` | Source-specific 2018–2024 and 2018–2026 Microsoft Research/Daan Leijen MIT notices preserved; exact default `MI_ALIGN2W` small-bin behavior retained |
| `include/mimalloc/internal.h`: `_mi_page_map_index`; `src/page-map.c`: virtual-bit bounds, reserve count, and `mi_page_map_set_range_prim` span arithmetic | `src/page_map.rs` | Source-specific 2023–2026 Microsoft Research/Daan Leijen MIT notice preserved; this slice is address/range arithmetic only and grants no pointer provenance |
| `src/bitmap.h`: 64-bit field/chunk and dynamic bitmap representation; `src/bitmap.c`: masks, set/clear/query/popcount, exact claims, source-ordered run search, rollback, scalar Relaxed chunk observers, caller-owned bitmap sizing/initialization, cross-chunk range operations, and conservative chunk-map maintenance | `src/bitmap.rs` | Source-specific 2019–2026 and 2019–2024 Microsoft Research/Daan Leijen MIT notices preserved; `BitmapView` binds the dynamic C layout to caller-owned storage, while binned policy, visitors, statistics, and allocator metadata ownership remain absent |
| `src/page-queue.c`: queue predicates and intrusive link/count/flag transition kernels from remove/push/move/enqueue operations | `src/page_queue.rs`, nested under `src/types.rs` | Source-specific 2018–2024 Microsoft Research/Daan Leijen MIT notice preserved; `_metadata` names make absent theap direct-cache/page-count/full-size accounting explicit |
| `include/mimalloc/internal.h`, `src/page.c`, and `src/arena.c`: regular/singleton slice counts, separated-metadata starts, object counts/offsets, and default scalar capacity-extension arithmetic | `src/page.rs` | Source-specific 2018–2024 and 2019–2026 Microsoft Research/Daan Leijen MIT notices preserved; pure geometry only, with no live page/theap ownership or free-list writes |
| `include/mimalloc/prim.h`, `src/prim/prim.c`, `src/prim/unix/prim.c`: regular Linux maps and transitions, clock/process/thread/NUMA/yield/entropy observations; `src/os.c`: covering/conservative page-range alignment | `src/os.rs` over `crabc-core` raw primitives | Source-specific 2018–2026 Microsoft Research/Daan Leijen MIT notice preserved; this is a private primitive boundary, not yet overcommit/THP/huge/aligned-hint/NUMA-topology policy |
| `include/mimalloc/atomic.h`: active `MI_USE_PTHREADS` private normal-mutex capability | `src/lock.rs` over `crabc-core` private futex primitives | Source-specific 2018–2024 Microsoft Research/Daan Leijen MIT notice preserved; the no-libc boundary uses a documented 0/1/2 futex state machine and makes no once or fork-repair claim |
| `src/libc.c`: bounded byte-string helpers; `include/mimalloc/internal.h`: byte copy/fill/zero helpers and aligned forms | `src/support.rs` | Source-specific 2018–2026 Microsoft Research/Daan Leijen MIT notice preserved; the support slice excludes getenv, once, pthread, CPU detection, and formatting |
| `src/libc.c`: `_mi_atomic_once_enter`/`_mi_atomic_once_release`; `include/mimalloc/atomic.h`: `mi_atomic_once_t` | `src/once.rs` over `src/lock.rs` | Source-specific 2018–2024 and 2018–2026 Microsoft Research/Daan Leijen MIT notices preserved; thread identity is an explicit validated input and a non-Send completion token owns the release obligation |
| Test-only mapping transitions corresponding to `src/prim/unix/prim.c` and `src/os.c` | `src/os_host_model.rs` under `cfg(miri)` | Original crabc verification instrument; fixed-capacity static storage preserves pointer provenance and logical transitions but does not model protection faults, RSS, or `MADV_FREE` reclamation |

The completed mapping records the exact upstream path, relevant functions or
types, target Rust module, source-specific notice, and every intentional
deviation. It is a reviewable translation ledger, not an aspirational module
plan.

## Configuration profile

The only frozen production profile in Milestone 0 is Linux/AArch64
little-endian with Linux >= 5.10 and valid Linux/AArch64 page sizes; 4-KiB page
size is not assumed. The future engine is `#![no_std]`, uses neither `alloc`
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
