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
owned OS singleton mappings below the source's 256 MiB metadata limit. The
slice includes checked counted allocation, full-page retention, retirement,
unregister-before-release, and injected rollback. The ordinary allocator gate
matches 447 Rust-owned layout/configuration values, 378 address-independent
small-allocation trace values, and 51 fundamental-operation values against
exact pinned C v3.5.0. This is not a production backend or readiness claim;
the process-owned C test adapter, process/TLS and remote-free lifecycle, libc
integration, stress, full upstream tests, and performance promotion gates
remain open.

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
