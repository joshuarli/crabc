# Project status

The general Linux/AArch64 little-endian runtime profile is closed. One active,
narrowly scoped compatibility program is open: the provenance-preserving Rust
semantic port of fixed mimalloc v3.5.0 defined by
[`docs/design/allocator.md`](docs/design/allocator.md) and measured through
[`compat/allocator/README.md`](compat/allocator/README.md). It does not reopen
allocator invention or another platform. [`COMPATIBILITY.md`](COMPATIBILITY.md)
remains the generated record of current compatibility evidence and
measurements; it is not edited by hand.

The allocator program currently has one bounded executable vertical slice:
an explicit pinned default theap can allocate, reallocate, and locally free
small, medium, large, singleton, aligned, and offset-aligned blocks from a
caller-managed external arena and page map. Large alignments use separately
owned OS singleton mappings below the source's 256 MiB metadata limit, with
allocation-free retry ownership when an injected terminal unmap fails. The
slice includes checked counted allocation, full-page retention, retirement,
unregister-before-release, and injected rollback. Unpinned external arenas now
schedule the pinned 4-second `purge_decommits=1` path before slice reuse;
forced collection claims the free bitmap while applying a non-owning
decommit, preserves the external mapping owner, and retains retry state after
an injected decommit failure. The ordinary allocator gate
matches 447 Rust-owned layout/configuration values, 378 address-independent
small-allocation trace values, and 51 fundamental-operation values against
exact pinned C v3.5.0. A standalone default-off test package now exports 16
strictly prefixed `crabc_test_*` symbols, passes the existing crabc allocator
fixture, and passes 33 reviewed checks from pinned upstream `test-api.c` in an
explicit creating-thread lifecycle. It exports no `malloc`, `mi_*`, or other
production allocator symbol. This is not a production backend or readiness
claim. Milestone 5 has only two bounded foundations: the exact AArch64
16-bit-index/48-bit-generation TLS key and caller-owned slot contract, plus
live-owner remote-free publication/collection using the source low-bit atomic
head. Neither is integrated into allocation, thread, abandonment, teardown,
or page-release lifecycle. Process/TLS lifecycle, remote-free routing,
abandonment/adoption, concurrency modeling and stress, libc integration, the
remaining upstream suites, and performance promotion gates remain open.

Future acceptance contracts are deliberately specific:

- [`docs/roadmap/performance-completion.md`](docs/roadmap/performance-completion.md)
  governs performance completion.
- [`docs/roadmap/software-corpus-validation.md`](docs/roadmap/software-corpus-validation.md)
  governs real-software and native-application validation.
- [`docs/roadmap/source-build.md`](docs/roadmap/source-build.md) governs
  source-build and sysroot progression.

Historical documents preserve provenance only; they are never an active
backlog. No chronological microtask list is a project authority. Read the
governing scope and compatibility profile before selecting work, then use the
relevant roadmap or machine-readable contract for its acceptance boundary.
