# Native x86 unwind provider

`build.py` compiles the approved `unwinding` configuration and extracts only
Rust objects from its three dependency archives into `libcrabc-unwind.a`.
The separate archive provides the 17 `_Unwind_*` functions in `UNWIND_ABI`;
the consuming Rust standard library supplies its own personality, panic runtime
and matching Rust core. The archive is not a standalone C unwinder: core
references must resolve from the Rust consumer graph.

Build from the checkout through the pinned native dispatcher:

```sh
./scripts/dev-x86_64.sh unwinder-build
./scripts/dev-x86_64.sh unwinder-metadata-bounds
./scripts/dev-x86_64.sh unwinder-eh-frame-bounds
./scripts/dev-x86_64.sh unwinder-dynamic-bounds
python3 -B -m unittest discover -s unwinder/tests
```

Each build uses a fresh checkout-local `.work/x86_64/unwinder-builds/run-*`
directory and the dispatcher's contained Cargo and temporary state. Explicit
nonempty output directories are rejected before running tools, preserving old
receipts and artifacts. It does not install or select
the archive in either runtime product. The Python dependency-audit tests can
also run on the host without compiling target code.

`provenance.json` records the exact source-file digests, licenses, enabled
features, compiler identity, archive members and archive digest. `cargo.jsonl`
and the defined/undefined symbol inventories retain build evidence.
The artifact embeds LLVM bitcode, uses PIC and preserves unwind tables. This
alone does not prove consumer or cross-runtime LTO qualification.

Before compiling, `build.py` verifies the normal checked-in registry lock and
the complete cached `unwinding 0.2.10` source tree. It creates or reuses only
an exact content-addressed input beneath `.work/x86_64/unwinder-source-inputs/`,
copies that verified source, and replaces
`src/unwinder/find_fde/phdr.rs` with the checked-in MIT OR Apache-2.0 bounds
overlay. Cargo resolves the same version/features from that local staged source
only for this producer input. The original registry source is never modified.
`provenance.json` separately records the pristine-tree and patched-tree hashes,
overlay/license/digests, staged input identity, and the actual compiled source
file inventory.

`unwinder-metadata-bounds` links the selected provider into a guard-page
fixture with a one-byte `PT_GNU_EH_FRAME` header. Its declared readable
`PT_LOAD` deliberately extends into the guard page, proving that the header's
own `p_memsz`, not the remaining load range, bounds the header read. The overlay
requires checked program-header arithmetic, a nonempty non-null header no
larger than Rust's slice limit, and complete containment in a readable
`PT_LOAD`; the fixture then proves that lookup returns no FDE instead of
faulting. Header-slice formation remains explicitly unsafe because only the
loader can guarantee the mapping's lifetime and actual readability. This is one
malformed-header behavior only. It does not exercise the separate decoded
`.eh_frame` pointer path, `PT_DYNAMIC` scan, later DWARF/LSDA references,
callback reentrancy, or runtime DSO mapping lifetime.

`unwinder-eh-frame-bounds` exercises the next, separate decoded-pointer
boundary. It rejects a direct `.eh_frame` target outside a readable `PT_LOAD`,
forms `EhFrame` only from the target through that load's end, and checks the
full native-word range of an indirect pointer cell before its unaligned read.
Null, arithmetic-overflow, and slice-limit values are rejected. The fixture
places the direct target at the final readable byte and an indirect cell in the
following guard page; both return no FDE without a fault. This does not prove
that FDE/CIE/DWARF records within the selected load are well formed, that every
later indirect pointer is safe, or that loader mappings remain live.

`unwinder-dynamic-bounds` exercises the independent `PT_DYNAMIC` tag boundary.
The overlay accepts only a nonempty, non-null declared dynamic range wholly in
one readable `PT_LOAD`, whose length is a whole number of native `Elf*_Dyn`
records. It uses checked record advancement and unaligned reads, stops on
`DT_NULL`, and retains the upstream first-`DT_PLTGOT` GOT selection. The fixture
places an unterminated record at a guard-page boundary, then separately proves
a valid `DT_NULL` table without a GOT and a `DT_PLTGOT` table supplying the
data-relative FDE base. It does not validate later pointer-derived metadata or
loader mapping lifetime.

## Standalone cleanup regression

Run the existing full cleanup fixture through the pinned native dispatcher:

```sh
./scripts/dev-x86_64.sh unwinder-cleanup
```

The fixture captures a backtrace, unwinds a `panic_any(73usize)` through two
`Drop` frames, checks the payload and cleanup count, and repeats that behavior
on a worker thread. The runner first creates a fresh provider receipt, then
links the complete pinned Rust standard-library input graph with that selected
archive. It replaces exactly one pinned target `libunwind-*.rlib` input and
Rust's direct `-lunwind`/`-lgcc*` fallback request with the selected provider;
every other libgcc/libunwind input, alternate linker-library spelling, and
response file is rejected. The retained link receipt records the command,
resolved-link trace, selected archive path and SHA-256.

Each fresh `.work/x86_64/unwinder-cleanup-runs/run-*` receipt records the
fixture/provider/binary digests, `GNU_EH_FRAME`, the selected provider ABI, and
the three ABI entries exercised by this fixture. This is standalone pinned-musl
Rust-std cleanup evidence only. It neither installs nor selects the provider
in a crabc runtime product, and does not qualify installed/extracted consumers,
build-std, DSO discovery, LTO, or malformed-metadata behavior.

## Supplied owned-product cleanup consumer

The intermediate owned consumer has a separate command because its two runtime
products are caller-supplied physical inputs, not an installation format for
the provider:

```sh
./scripts/dev-x86_64.sh unwinder-owned-cleanup \
  --static-sysroot .work/x86_64/RUN/static-product \
  .work/x86_64/RUN/dynamic-product
```

The existing static preparation producer is, for example:

```sh
./scripts/dev-x86_64.sh owned-posix-static-products \
  .work/x86_64/rust-std-unwinder-static-products
```

Its primary product is
`.work/x86_64/rust-std-unwinder-static-products/products/primary`. The
existing `materialized-dynamic-sysroot` command produces and validates an
independently materialized dynamic product; retain a physical dynamic product
root from its existing evidence before using this replay. The consumer refuses
missing, duplicate, symlinked, or manifest-mismatched roots, and revalidates
both complete payloads after collection.

For each mode the runner invokes the existing `unwinder/build.py` producer into
a fresh checkout-local evidence directory, retains the exact provider archive
and provenance, then compiles the unmodified full `fixtures/cleanup.rs`
stock-Rust fixture. Its finite linker wrapper omits the one stock
`libunwind-*.rlib` and compiler-builtins archive, replaces Rust's native
libc/libgcc requests with explicit product files, and rejects ambient libc,
CRT, libgcc, libunwind, response-file, and native-library-search inputs. The
static link uses supplied `crt1.o`/`libc.a`; the dynamic link uses supplied
`Scrt1.o`, attach object, `libc.so`, and selected loader. Both retain product
roots/manifests, provider provenance/archive, complete linker command/trace,
and executable digest before checking main and worker-thread panic cleanup plus
backtrace behavior.

This is non-promoting consumer-development evidence: its receipt keeps all
qualification, family-completion, promotion, and public-support flags false.
The separately supplied archive/provenance is **not** installed-product
packaging. Installing it into a product and then repeating source-bound
consumer qualification remains required, as do build-std/core matching, LTO,
runtime DSO discovery, and complete malformed-metadata handling.

## Source and ownership

The exact normal graph is:

- `unwinding 0.2.10`, upstream commit
  `0e2de8fb536b1ca42066024609f58d708cf80e69`, MIT OR Apache-2.0;
- `gimli 0.34.0`, MIT OR Apache-2.0, `read-core` only;
- `libc 0.2.186`, MIT OR Apache-2.0, `default` and `std` features inherited
  from unwinding. Despite that feature spelling libc remains `#![no_std]`;
  it supplies bindings and adds no normal dependencies or std linkage.

All three registry checksums are pinned in `Cargo.lock` and independently
checked by `PINS`. The direct gimli/libc declarations constrain upstream's
otherwise floating transitive version ranges. `FEATURES` rejects additional
features rather than silently admitting Cargo feature unification.

Upstream `src/unwinder/mod.rs` owns the exported unwind ABI;
`src/unwinder/arch/x86_64.rs` owns register save/restore through audited Rust
inline/naked assembly. `src/unwinder/find_fde/phdr.rs` obtains frame metadata
from owned `dl_iterate_phdr`, `PT_LOAD` and `PT_GNU_EH_FRAME`. Consumers must
request `--eh-frame-hdr`. No C/C++/standalone assembly object, prebuilt target
unwinder, libgcc or compiler-rt archive is included. libc's Rust cfg-discovery
build script is the sole admitted build executable. The selected path has no
allocation, registry, mutable global frame state, thread creation, personality
or panic-handler implementation.

## Qualification boundary

The producer records `qualified: false`. Stock-std ordinary application and
main/worker-thread panic cleanup/backtrace checks have run against the owned
runtime during development; reproducible consumer qualification is separate.
`fixtures/cleanup.rs` preserves both cleanup frames, payload identity and
backtrace capture as observable requirements.

Build-std requires matching core linkage. Initial/runtime DSO unwind,
installed/extracted PIE/non-PIE, consumer LTO and malformed metadata checks
remain required by the approved design before qualification is complete.
The local overlay bounds the declared `PT_GNU_EH_FRAME` header, decoded
`.eh_frame` entry range, and `PT_DYNAMIC` tag table only. It does not validate
every FDE/CIE/DWARF record, every later indirect pointer, or later metadata
read. Source pinning and the guarded metadata regressions do not establish safe
failure for malicious or truncated mapped unwind metadata generally. Those
boundaries must be fixed and tested before this provider is promoted.
Enumeration is not claimed async-signal-safe.
