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

`owned_mimalloc_producer_metadata.py` accepts ELF facts already authenticated
by `native_abi_elf_facts.py`, plus the static and shared owned-product
provenance records. It does not replay those receipts or build a product.
That boundary lets selection reuse verified evidence without adding another
builder or generic receipt system.

The reader requires these finite producer facts:

- 419 strong `FUNC GLOBAL DEFAULT` definitions in the selected static C member
  become `FUNC LOCAL DEFAULT` definitions in shared `libc.so`.
- `_ZSt15get_new_handlerv` is a **defined** `FUNC WEAK DEFAULT` static
  fallback and a `FUNC LOCAL DEFAULT` shared definition. Pinned
  `src/alloc.c` returns null from that fallback; it is not treated as an
  optional undefined C++ import or given an invented provider.
- `_mi_cpu_has_popcnt`, `_mi_heap_default_key`, and `_mi_stats_main` retain
  their exact object size and static alignment, with shared alignment at least
  the source-required lower bound.
- `mi_thread_locals` retains its TLS size and initial-exec section alignment.
- None of the 424 identities has a shared `.dynsym` row.
- The archive map retains the raw Cargo allocator archive identity, the
  reconstructed `libc.a` identity, exactly one C `*-static.o` member, and one
  static Rust root. Its seven C imports — `_mi_auto_process_done`,
  `_mi_auto_process_init`, `mi_free`, `mi_malloc_aligned`,
  `mi_realloc_aligned`, `mi_usable_size`, and `mi_zalloc` — resolve through
  that static C member and through the final local shared definition. The
  shared-link provenance must select the same C-member bytes.

Use the focused receipt adapter after the existing fact/product readers have
authenticated their inputs:

```
python3 -B compat/x86_64/owned_mimalloc_producer_metadata.py \
  --elf-facts ELF_FACTS_REPORT \
  --static-provenance STATIC_PRODUCT/share/crabc/libc-static.provenance.json \
  --shared-provenance DYNAMIC_PRODUCT/share/crabc/libc-shared.provenance.json \
  --output RECEIPT.json
```

The receipt records source and input identities and remains
`component-pass-not-qualification`: its family-completion, promotion, and
public-support flags are all false. A qualified Rust-backend promotion removes
this fixed-C producer contract, its 424-name localization list, and its seven
Rust-to-C joins. It does not transfer this private metadata to Rust or change
the separate public allocation boundary.
