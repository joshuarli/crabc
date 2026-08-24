# Pinned mimalloc Rust/C known differences

This is the durable register of observable or algorithmic differences between
the incomplete `crabc-mimalloc` Rust port and exact pinned mimalloc v3.5.0 C.
The source pin is defined in
[`crabc-mimalloc/UPSTREAM.md`](../../crabc-mimalloc/UPSTREAM.md).

## Current status

No valid-program observable or algorithmic differences are recorded. The
current Rust crate contains source-mapped
foundations plus a private, explicit single-thread ordinary-allocation
lifecycle across small, medium, large, and singleton pages. Its small path has
exact address-independent trace parity with pinned C v3.5.0, and a separate
51-key exact differential record covers the bounded fundamental page-kind,
calloc, realloc, aligned/offset-aligned, usable-size, preservation, and failure
slice. This includes live arena-backed alignment through 64 KiB and separately
owned OS-aligned singleton mappings below 256 MiB. The lifecycle is not
exported and does not imply parity for the absent process/TLS, remote-free,
teardown, purge, or public-API regions. The private regular TLS owner records
one internal recovery limitation in the source map: `MetaAllocator::free` may
report an error after consuming a capability, so an error clears the dynamic
root and terminally poisons the owner rather than retaining a capability that
could name freed storage. That state is not a valid C-program observable
difference and has no C differential entry; a richer metadata-free result may
refine it only when it can prove retained ownership.

## Entry requirements

Each entry must state:

- a stable difference identifier and status (`observed`, `pending`, `accepted`,
  or `rejected`);
- the upstream source path/function or type and the Rust module/function;
- whether the difference affects engine semantics, C ABI integration,
  configuration, performance, diagnostics, or invalid-use handling;
- a minimal reproducer and exact-C differential result for valid programs;
- its written design note, when it is algorithmic or behavioral;
- Linux/AArch64 performance and memory evidence; and
- the decision and conditions that would remove the difference.

`crabc-libc` ownership of C ABI and `errno`, and direct crabc lifecycle wiring
for threads and fork, are integration boundaries rather than implicit
differences. They still require tests. Invalid use must not be copied merely to
reproduce C memory unsafety; document a deliberate safe difference here if one
is necessary.

An entry cannot replace the exact pinned C implementation as a differential
oracle or justify a runtime fallback. Accepted differences require the design,
differential, and performance evidence specified in
[`docs/design/allocator.md`](../../docs/design/allocator.md).
