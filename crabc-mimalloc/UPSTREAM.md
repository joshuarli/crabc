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
flags. `[[unit]]` rows cover source files, and `[[item]]` rows name narrower
function groups and their Rust routes. This file does not keep a second source
inventory. The Miri kernel model (`crabc-core/src/miri_model.rs`, `cfg(miri)`)
is original crabc code with no upstream counterpart.

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
