# Fixed-C mimalloc producer metadata

`owned_mimalloc_producer_metadata.toml` accounts for the private C producer
selected by the native owned products: `libmimalloc-sys` 0.1.49 carrying
mimalloc v3.3.2. It is deliberately separate from the fixed mimalloc v3.5.0
Rust-port oracle in `crabc-mimalloc/`, and from public malloc ABI and
interposition evidence.

The contract starts with
`libc/src/c_abi/x86_64/owned_mimalloc_hidden.list`: its SHA-256 and sorted
424-name roster select this component. It never uses a `mi_*` or `_mi_*`
prefix. The same contract seals all 32 pinned v3 C source/header dependency
hashes, highlighting `src/static.c`, public `include/mimalloc.h`, and
`src/alloc.c`; it also records the exact static and shared compiler flags and
the one local-only version-script policy.

The four non-function layouts record two different facts. Their C source
requires size/alignment `(1,64)`, `(4,4)`, `(4368,8)`, and `(8,8)` for
`_mi_cpu_has_popcnt`, `_mi_heap_default_key`, `_mi_stats_main`, and
`mi_thread_locals`. The static producer places those symbols in sections
aligned `64`, `4`, `32`, and `8`. The 32-byte section for `_mi_stats_main` is
compiler/producer over-alignment; it does not change the source requirement
of 8. The contract pins each defining C spelling, source line, type/size
basis, and alignment authority. In particular, `pthread_key_t` follows the
x86-selected `include/pthread.h:26,30` route to
`include/bits/alltypes.h:322`, where it is `unsigned`.

`owned_mimalloc_producer_metadata.py` accepts ELF facts already authenticated
by `native_abi_elf_facts.py`, plus the static and shared owned-product
provenance records. It does not replay those receipts or build a product.
That boundary lets selection reuse verified evidence without adding another
builder or generic receipt system.

`selected_metadata()` exposes the validated finite policy as an exact
424-name mapping to static/shared type, binding, and visibility expectations.
Its four data/TLS rows also carry source-selected `size_bytes` and
`alignment_bytes`: static uses the producer section contract, while shared
uses the C source minimum. It does not expose observed ELF values or turn
these private names into public exports.

The reader requires these finite producer facts:

- 419 strong `FUNC GLOBAL DEFAULT` definitions in the selected static C member
  become `FUNC LOCAL DEFAULT` definitions in shared `libc.so`.
- `_ZSt15get_new_handlerv` is a **defined** `FUNC WEAK DEFAULT` static
  fallback and a `FUNC LOCAL DEFAULT` shared definition. Pinned
  `src/alloc.c` returns null from that fallback; it is not treated as an
  optional undefined C++ import or given an invented provider.
- `_mi_cpu_has_popcnt`, `_mi_heap_default_key`, and `_mi_stats_main` retain
  their exact object size, source-required alignment, and static producer
  section alignment. Shared placement must meet the source requirement.
- `mi_thread_locals` retains its TLS size and initial-exec section alignment.
  Both static and shared `st_value` fields must themselves be divisible by the
  source-required alignment. Shared TLS `st_value` is a TLS-relative offset;
  the reader does not subtract the `.tdata` virtual address.
- None of the 424 identities has a shared `.dynsym` row.
- The archive map retains the raw Cargo allocator archive identity, the
  reconstructed `libc.a` identity, exactly one C `*-static.o` member, and one
  static Rust root. Its seven C imports — `_mi_auto_process_done`,
  `_mi_auto_process_init`, `mi_free`, `mi_malloc_aligned`,
  `mi_realloc_aligned`, `mi_usable_size`, and `mi_zalloc` — resolve through
  that static C member and through the final local shared definition. The
  shared-link provenance must select the same C-member bytes. Those generic
  Rust-to-C import obligations remain separate from the metadata/layout
  projection until their installed consumer/map proof is selected.
- The final shared ELF identity must equal the `usr/lib/libc.so` entry in the
  authenticated dynamic-product manifest. Matching source or archive-member
  bytes alone never identify a final linked DSO.

Use the focused receipt adapter after the existing fact/product readers have
authenticated their inputs:

```
python3 -B compat/x86_64/owned_mimalloc_producer_metadata.py \
  --elf-facts ELF_FACTS_REPORT \
  --static-provenance STATIC_PRODUCT/share/crabc/libc-static.provenance.json \
  --shared-provenance DYNAMIC_PRODUCT/share/crabc/libc-shared.provenance.json \
  --shared-manifest DYNAMIC_PRODUCT/share/crabc/manifest.json \
  --output RECEIPT.json
```

The receipt seals the ELF facts, both provenance records, and dynamic manifest
before and after accounting, then records their identities. It remains
`component-pass-not-qualification`: its family-completion, promotion, and
public-support flags are all false. A qualified Rust-backend promotion removes
this fixed-C producer contract, its 424-name localization list, and its seven
Rust-to-C joins. It does not transfer this private metadata to Rust or change
the separate public allocation boundary.
