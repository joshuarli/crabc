# D16: Reuse relocation results within a transaction

## Evidence

The R0 installed product was profiled in the pinned image through the static
timing launcher and its candidate chroot. The `instructions:u` profiles had no
lost samples. `lookup_result_at` accounts for 6.96% of startup samples, 33.08%
of `dlopen_graph`, and 22.79% of loader TLS-growth samples. Startup also spends
8.79% in `__crabc_x86_64_self_relocate`. The matched-LLVM counts remain the
acceptance evidence: 1.8917, 1.5993, and 2.5682 for those three rows.

## Design

Keep lookup results inside one immutable relocation transaction. Key a local
cache by requestor, dynsym index, and `LookupMode` (ordinary, jump slot, TLS,
or COPY). Validate the requestor record and bounded name before checking the
cache. Cache the full `SymbolLookup`, including the distinction between
undefined weak and missing strong symbols. Drop the cache when that
transaction ends. Keep GNU and SysV hash lookup as the cache-miss path; do not
add a process-global index.

Make runtime `relocate_new` retain each preflighted word result in relocation
order. Its current write pass calls `word_resolution` again after preflight
discarded the first result. Apply retained values after the complete new-object
graph passes preflight. Represent a deferred PLT/GOT entry separately from a
resolved value so lazy binding keeps its existing queue behavior.

Cache hits still validate each requestor record and each relocation target.
Keep BFS scope order, first-definition binding, version visibility, TLS and
COPY rules, symbol extent checks, RELRO admission, and writable-load bounds.
The cache must not outlive its scope or retained mappings. Existing lookup
paths for named runtime symbol queries and later lazy retries stay unchanged.

## Review outcome

The independent reviewer found the cache key and retain-then-apply ordering
semantically feasible, but rejected R1 approval. Startup at 1.8917 needs about
41.8% fewer candidate instructions to reach 1.10. `lookup_result_at` accounts
for 6.96% of startup samples, and the proposed design does not address the
8.79% in `__crabc_x86_64_self_relocate`. No code changed. A revised design
needs an in-scope startup mechanism with credible headroom before code work.
