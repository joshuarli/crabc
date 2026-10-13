# mimalloc v3.5.0 upstream provenance

## Fixed source

The `crabc-mimalloc` engine is a semantic port of this exact source;
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
archive has this SHA-256 before it is used as source or an oracle. An offline
run performs no fetch: absent a cached remote tag observation, it accepts a
cached archive only when the SHA-256 matches and the archive's `git archive`
pax global `comment` names the peeled tag commit above. The tag object is then
this reviewed record, not a new remote observation
(`compat/allocator/run.py` `pinned_archive_tag_identity`).

## License provenance

The pinned upstream repository's `LICENSE` is MIT. The exact notice at the
pinned commit is reproduced here because the translated source is a
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

## Dependency-owned allocation shuffle and random stream

`rand_xoshiro` is pinned to **0.8.1**, with default features disabled, to supply
`SplitMix64` for the pinned allocator's page shuffle. Its normal dependency
graph contains only `rand_core` **0.10.1**, already in the workspace lockfile.
Both crates are `no_std`; this configuration has no allocation, mutable global
state, native code, build scripts or procedural macros. The crate is licensed
MIT OR Apache-2.0 and its published archive has SHA-256
`662effc7698e08ea324d3acccf8d9d7f7bf79b9785e270a174ea36e56900c91d`.

The source adapter uses one caller-owned eight-byte state and the dependency's
inline output operation; it does not maintain a local PRNG core. LTO can see
the dependency's Rust implementation. The shuffle does not acquire entropy.

The allocator's random stream (`src/random.c` ChaCha20) uses the reviewed
`chacha20` **0.10.1** (`legacy` and `zeroize` features) and `zeroize` **1.9.0**,
both pinned in `crabc-mimalloc/Cargo.toml`; no cipher core is implemented
locally.

## Source-to-Rust mapping

`compat/allocator/port-map.toml` owns the exact mapping: every pinned source
unit and function group, its Rust module and item, its status and its evidence
flags. The table gives only the file-level summary of the `[[unit]]` rows.
Each Rust module's header carries the source-specific copyright and MIT notice
of the pinned file(s) it translates, as the license rule above requires; a
module that merges two source files carries both.

| Pinned source | Rust module(s) in `crabc-mimalloc/src` unless prefixed |
| --- | --- |
| `include/mimalloc.h` | api |
| `include/mimalloc-stats.h` | stats |
| `include/mimalloc/types.h` | types |
| `include/mimalloc/atomic.h` | atomic |
| `include/mimalloc/bits.h` | bits and config |
| `include/mimalloc/prim.h` | os |
| `include/mimalloc/prim-tls.h` | compiler_tls, thread_local, main_theap, dynamic_theap, and runtime_lifecycle |
| `include/mimalloc/internal.h` | invariants, page, free_list, bootstrap, aligned, alloc, os_page, and single_thread |
| `src/alloc.c` | alloc, single_thread, free_list, process_page_map, runtime_lifecycle, and source_api |
| `src/alloc-aligned.c` | aligned, os_page, and single_thread |
| `src/alloc-posix.c` | source_api |
| `src/alloc-override.c` | crabc_libc::allocator_boundary |
| `src/free.c` | free_list, process_page_map, remote_free, runtime_lifecycle, and single_thread |
| `src/arena.c` | arena, os_page, and single_thread |
| `src/bitmap.c` | bitmap |
| `src/bitmap.h` | bitmap |
| `src/heap.c` | types, main_theap, main_heap_thread, main_heap_page, and dynamic_theap |
| `src/init.c` | bootstrap, meta, subproc, tld, types, main_theap, process_init, main_static_page, main_heap_thread, main_heap_page, and dynamic_theap |
| `src/libc.c` | support |
| `src/options.c` | config, diagnostic_output, os, types, main_theap, main_heap_thread, runtime_lifecycle, runtime_destroy, and libc::c_abi::x86_64::native_mimalloc_lifecycle |
| `src/os.c` | os |
| `src/page-map.c` | page_map, process_page_map, and main_static_page |
| `src/page.c` | page, free_list, remote_free, abandoned, types, and single_thread |
| `src/page-queue.c` | types::page_queue and single_thread |
| `src/random.c` | random |
| `src/stats.c` | stats |
| `src/static.c` | crabc_mimalloc crate module graph |
| `src/subproc.c` | subproc, meta, tld, types, main_theap, process_init, and dynamic_theap |
| `src/theap.c` | bootstrap, types, single_thread, main_theap, main_static_page, main_heap_thread, main_heap_page, and dynamic_theap |
| `src/threadlocal.c` | compiler_tls, meta, thread_local, owned_tls_key_registry, main_theap, main_heap_thread, and dynamic_theap |
| `src/prim/prim.c` | os |
| `src/prim/prim-tls.c` | compiler_tls and runtime_lifecycle |
| `src/prim/unix/prim.c` | os |
| `src/prim/unix/prim-tls.c` | thread_local |

The Miri kernel model (`crabc-core/src/miri_model.rs`, `cfg(miri)`) is original crabc code with no upstream counterpart.

### Source ranges not yet in `port-map.toml`

The following pinned ranges were mapped here but no `port-map.toml` row
contains them. They need rows or should be dropped.

| Pinned range | Rust owner |
| --- | --- |
| `src/alloc.c:379-417`, `src/alloc-aligned.c:347-388` | `runtime_lifecycle::{native_reallocate_zeroed, native_reallocate_aligned_zeroed, native_reallocate_aligned}` |
| `src/arena.c:1794-1869`, `src/arena.c:2167-2191` | `arena_owned::ProcessArenaBacking::install_owned_huge_allocation`, `arena::manage_in_place` |
| `src/arena.c:2167-2222`, `src/os.c:772-853`, `src/init.c:566-579` | `arena_huge` |
| `src/options.c:133-134` | `config::VmOption` (`reserve_os_memory`) |
| `src/prim/unix/prim.c:419-449`, `src/os.c:781-814` | `diagnostic_output::HugePageWarningRoute`, `os::HugeOsAllocation` |
| `src/page.c:359-388` | `single_thread::PageAllocatorEngine::move_regular_to_full`, `abandoned::abandon_after_collect` |
| `src/arena.c:630-651`, `src/arena.c:761-765` | `remote_free::collect_abandoned_false`, `abandoned::unown_with` |
| `src/arena.c:870-1037`, `src/arena.c:1316-1337` | `arena` |
| `src/subproc.c:19-88`, `src/subproc.c:149-193`, `src/subproc.c:253-255` | `meta`, `subproc_registry` |
| `src/heap.c:148-170`, `src/heap.c:161-183`, `src/theap.c:347-376` | `heap_destroy`, `subproc_registry` |
| `src/page.c:987-1117` | `deferred_free`, `single_thread` (`_mi_deferred_free`, `mi_malloc_generic_fallback`) |
| `src/os.c:240-430` | `os` (aligned overmap) |
| `src/init.c:151-214` | `process_init`, `bootstrap` |
| `src/threadlocal.c:23-315` | `thread_local`, `owned_tls_key_registry` |
| `include/mimalloc/atomic.h:544-557` | `once` over `lock` |
| `include/mimalloc/internal.h:1316-1344` | `types` (static memory-ID construction) |
| `src/bitmap.c:1616-1634` | `bitmap::BinnedBitmapView::highest_clear_relaxed` |
| `src/os.c:690-712`, `src/prim/unix/prim.c:600-604` | `os` (`_mi_os_protect`/`_mi_os_unprotect`) |
| `src/theap.c:381-412`, `src/heap.c:162-185`, `src/heap.c:209-225`, `src/arena.c:2640-2643` | `heap_destroy::Heap::force_destroy_main_heap_theaps_quiescent`, `main_theap` `force_destroy_source_owned_theaps` / `force_destroy_source_owned_main_heap` |
| `src/init.c:200-205`, `src/subproc.c:233-255` | `meta::MetaAllocator::prepare_for_main_heap`, `close_process_engine_quiescent`; `bootstrap::bind_detached_for_main_heap`; `metadata_session::CanonicalMetadataTheapSession`; `heap_registry::SubprocessHeapList` |

### Differences not yet registered

Language-boundary adaptations that `port-map.toml` rows state but
`compat/allocator/known-differences.md` has no entry for:

- The allocator-private lock (`lock.rs`) is a no-libc futex lock in place of
  the upstream normal process-private pthread mutex. It keeps Acquire/Release
  exclusion and implies no fork repair. `ThreadLocalData` therefore keeps the
  source field order and meaning but is not a C `sizeof` claim.
- The once protocol (`once.rs`) takes an explicit validated thread identity and
  models the enter/body/release scope with a completion token; it runs no
  callbacks and defines no initializer-failure policy.
- The bounded string helpers (`support.rs`) skip the C source's condition-order
  re-read after N equal bytes; no valid-program result changes.
- `bits.rs` returns `Option<usize>` for `mi_bsf`/`mi_bsr`, and `atomic.rs` uses
  concrete atomic types in place of C macro polymorphism with the same
  orderings. These are type-level adaptations, not algorithmic differences.

Integration boundaries are not engine differences: `crabc-libc` owns the C ABI
and `errno`, `crabc-mimalloc` is errno-free, and thread and fork hooks use the
crabc runtime lifecycle rather than public pthread APIs.

## Configuration profile

The engine is `#![no_std]`, uses neither `alloc` nor libc, compiles no C or
C++ and has no native build script. The selected profiles are Linux >= 5.10
little-endian AArch64 (frozen production record; valid page sizes, 4 KiB not
assumed) and native x86-64 (parity evidence only; it grants no public
allocator integration or default-backend promotion). Rows naming AArch64
constants or TLS are AArch64 records; x86-64 needs its own classification and
evidence.

## Upstream update procedure

1. Do not change this pin as part of allocator implementation work.
2. Propose a separate upstream-update change naming the new release and commit.
3. Download its immutable archive, record and verify its SHA-256, and generate
   a source, public-API, and configuration diff against v3.5.0.
4. Review license notices and update the source-to-Rust mapping for every
   affected translation.
5. Re-run the complete correctness, differential, and native profile-specific
   performance/memory evidence before any promotion claim. The x86-64 parity
   profile cannot by itself produce a public `crabc` support or allocator
   promotion claim.

A later tag is not evidence that this fixed-port contract has changed.
