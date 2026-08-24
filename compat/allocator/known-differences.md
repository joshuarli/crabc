# Pinned mimalloc Rust/C known differences

This is the durable register of observable or algorithmic differences between
the incomplete `crabc-mimalloc` Rust port and exact pinned mimalloc v3.5.0 C.
The source pin is defined in
[`crabc-mimalloc/UPSTREAM.md`](../../crabc-mimalloc/UPSTREAM.md).

## Current status

No differences are recorded. The current Rust crate contains source-mapped
foundations plus a private, explicit single-thread small-allocation lifecycle.
That bounded path has exact address-independent trace parity with pinned C
v3.5.0, but it is not exported and does not imply parity for the absent
process/TLS, remote-free, medium/large/aligned, reallocation, teardown, or
public-API regions.

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
