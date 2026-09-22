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
./scripts/dev-x86_64.sh unwinder-indirect-personality-bounds
./scripts/dev-x86_64.sh unwinder-metadata-target-bounds
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
`src/unwinder/find_fde/phdr.rs` and `src/unwinder/frame.rs` with checked-in
MIT OR Apache-2.0 bounds overlays. Cargo resolves the same version/features
from that local staged source only for this producer input. The original
registry source is never modified. `provenance.json` separately records the
pristine-tree and patched-tree hashes, overlays/licenses/digests, staged input
identity, and the actual compiled source-file inventory.

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

`unwinder-indirect-personality-bounds` exercises the later CIE `zP` indirect
personality and FDE `zL` indirect LSDA boundaries. The selected finder has no
retained `PT_LOAD` identity once it hands an FDE to `Frame`, where upstream
would otherwise dereference the encoded cell. `Frame::from_context` re-enumerates
program headers, resolves and caches each present cell only when its complete
native word is within a readable `PT_LOAD` during that callback, and propagates
an unresolved present cell through the existing phase error path. An absent
personality remains absent; an absent or resolved-zero LSDA remains zero. The
fixture separately routes `_Unwind_RaiseException` through matching FDEs with a
guarded personality cell and a guarded LSDA cell. Each returns
`FATAL_PHASE1_ERROR` without a fault. The cleanup fixture continues to use its
valid indirect metadata. This does not validate the target's ABI or LSDA
contents, DWARF-expression memory reads, later CFI register loads, or loader
mapping lifetime.

`unwinder-metadata-target-bounds` covers the next target boundary. After
resolving a present pointer cell, the frame overlay requires a non-null CIE
personality target in an executable `PT_LOAD`, and a nonzero FDE LSDA target in
a readable `PT_LOAD`; a target outside those ranges propagates through the
existing phase error path. The fixture first proves that an absent personality
and a direct zero LSDA still return `END_OF_STACK`. It then requires
`FATAL_PHASE1_ERROR` for direct-null and indirect-null personalities, a direct
personality target in a guarded page, and a direct LSDA target in that guarded
page. The check covers the target's one-byte entry range only. It does not
validate a personality's ABI, an LSDA's contents, DWARF-expression memory
reads, later CFI register loads, or loader mapping lifetime.

`unwinder/frame_bounds.py` exercises CFI and DWARF-expression evaluation
through the selected provider. Metadata register IDs must belong to the actual
x86 context (integer registers 0–16, MXCSR and FCW); unsupported IDs, expression
states and result kinds return a phase error instead of invoking a panic inside
the unwinder. Expression slice errors also propagate. `DW_OP_addr` resumes
with the relocated address itself; it does not dereference that address.
`DW_OP_deref_size` reads exactly 1–8 specified bytes and zero-extends them for
the little-endian target. Non-default address spaces and typed operations
remain unsupported and return an error.

The expression interpreter permits at most 4096 evaluator iterations per expression
(gimli may process two operations in one iteration).
This finite bound supplements its existing 64-value stack and single-result
storage, leaves room for compiler-generated CFI arithmetic, and prevents an
unconditional backward branch from hanging an unwind phase. Exhaustion returns
`gimli::Error::TooManyIterations` through the existing phase error path. The
fixture checks invalid CFA/source/destination/expression registers, unsupported
states/results, a backward loop, valid register arithmetic, an address pointing
into a guard page without dereferencing it, and every 1–8-byte read width ending
exactly at that page boundary, including nonzero value and zero-extension checks. These corrections do **not** establish arbitrary
address readability: CFI register restoration and expression memory reads still
need a fault-contained memory owner, and LSDA parsing remains the consuming
personality's responsibility. No broader malformed-metadata safety claim
follows from this regression.

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

For each stock-Rust mode the runner invokes the existing `unwinder/build.py`
producer into a fresh checkout-local evidence directory, retains the exact
provider archive and provenance, then compiles the unmodified full
`fixtures/cleanup.rs` fixture. Its finite linker wrapper omits the one stock
`libunwind-*.rlib` and compiler-builtins archive, replaces Rust's native
libc/libgcc requests with explicit product files, and rejects ambient libc,
CRT, libgcc, libunwind, response-file, and native-library-search inputs. The
static link uses supplied `crt1.o`/`libc.a`; the dynamic link uses supplied
`Scrt1.o`, attach object, `libc.so`, and selected loader. Both retain product
roots/manifests, provider provenance/archive, complete linker command/trace,
and executable digest before checking main and worker-thread panic cleanup plus
backtrace behavior.

The same run then builds two checked-in Cargo fixtures with
`--locked -Zbuild-std=std,panic_unwind`, fresh checkout-local Cargo home,
target, and temporary directories, `CARGO_BUILD_JOBS=1`, and fat LTO. The
source-built static fixture repeats the complete cleanup/backtrace check. The
dynamic fixture builds a Rust `cdylib` plugin which performs that check itself;
its Rust host resolves the plugin's exported entry with `dlopen`/`dlsym` and
loads the plugin by basename through the selected loader's explicit library
path. This exercises owned dynamic DSO discovery without a direct-path open.

For a source-built final link the wrapper admits only the Cargo application
root and its declared target `release/deps` root. It requires the freshly
built `std`, `core`, `alloc`, and `panic_unwind` archives, omits the
source-built `libunwind` and compiler-builtins archives in favor of the
selected provider and product archive, and records a separate schema-2 link
receipt. Stock target rlibs are outside that boundary. Cargo artifact JSON,
verbose build records, the pinned `rust-src` library lock, and the linker-side
receipt bind the build to the final executable or plugin even where Cargo
hard-links an artifact into its release directory.

This is non-promoting consumer-development evidence: its receipt keeps all
qualification, family-completion, promotion, and public-support flags false.
The separately supplied archive/provenance is **not** installed-product
packaging. Installing it into a product and then repeating source-bound
consumer qualification remains required, as do installed/extracted executable
modes, broader initial/runtime DSO behavior, and complete malformed-metadata
handling.

## Source and ownership

The owned consumer disables rustc's musl self-contained link inputs and
`crt-static` selection before invoking its explicit owned linker. That linker
selects the installed static or dynamic crabc runtime itself; bundled Rust
CRT objects remain rejected. The abort-only x86 libc supplies no
`rust_eh_personality` definition or fallback. Rust std supplies the real
personality, while the selected provider supplies `_Unwind_*`. The complete
cleanup fixture is the regression for this boundary: admitting both libc's
former placeholder and std's personality produced a duplicate-symbol error.

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
from owned `dl_iterate_phdr`, `PT_LOAD` and `PT_GNU_EH_FRAME`; the frame overlay
also resolves late indirect personality and LSDA cells, then checks their
non-null targets during bounded `dl_iterate_phdr` callbacks. Consumers must
request `--eh-frame-hdr`. No C/C++/standalone assembly object, prebuilt target
unwinder, libgcc or compiler-rt archive is included. libc's Rust cfg-discovery
build script is the sole admitted build executable. The selected path has no
allocation, registry, mutable global frame state, thread creation, personality
or panic-handler implementation.

## Qualification boundary

The producer records `qualified: false`. The development receipt covers stock
std static/dynamic cleanup, source-built full-std fat-LTO static cleanup, and
a source-built fat-LTO Rust plugin discovered by the owned dynamic loader. The
stock and plugin fixtures preserve both cleanup frames, payload identity,
worker cleanup, and backtrace capture as observable requirements. Reproducible
consumer qualification is separate.

Initial/runtime DSO unwind beyond the loaded plugin, installed/extracted
PIE/non-PIE, provider packaging, and malformed metadata checks remain required
by the approved design before qualification is complete.
The local overlay bounds the declared `PT_GNU_EH_FRAME` header, decoded
`.eh_frame` entry range, `PT_DYNAMIC` tag table, and complete native words of
late indirect CIE personality and FDE LSDA cells before they are dereferenced.
Present cells that cannot be resolved produce the existing phase error; they are
not treated as absent metadata. A non-null personality target must occupy an
executable `PT_LOAD`, and a nonzero LSDA target a readable `PT_LOAD`; this
one-byte target check does not validate the called ABI or LSDA contents. It does
not validate every FDE/CIE/DWARF record, DWARF-expression memory reads, later
CFI register loads, or loader mapping lifetime. Source pinning and the guarded
metadata regressions do not establish safe failure for malicious or truncated
mapped unwind metadata generally. Those boundaries must be fixed and tested
before this provider is promoted. Enumeration is not claimed async-signal-safe.
