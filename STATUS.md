# Project status

The general Linux/AArch64 little-endian runtime profile is closed. One active,
narrowly scoped compatibility program is open: the provenance-preserving Rust
semantic port of fixed mimalloc v3.5.0 defined by
[`docs/design/allocator.md`](docs/design/allocator.md) and measured through
[`compat/allocator/README.md`](compat/allocator/README.md). It does not reopen
allocator invention or another platform. [`COMPATIBILITY.md`](COMPATIBILITY.md)
remains the generated record of current compatibility evidence and
measurements; it is not edited by hand.

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
