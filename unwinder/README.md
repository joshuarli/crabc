# Native x86 unwind provider

`build.py` compiles the approved `unwinding` configuration into
`libcrabc-unwind.a`, an ordinary archive with one localized C-ABI member,
`crabc-unwind.o`. The source-built cleanup path instead stages that exact
patched provider graph below its consumer evidence directory and makes
`crabc-unwinder` a normal Cargo dependency. Both forms provide the 17
`_Unwind_*` functions in `UNWIND_ABI`; Rust std supplies its own personality
and panic runtime.

The archive member is one fat-LTO `staticlib` compilation of
`crabc-unwinder` and its three dependencies against the pinned target `core`.
Rust's compiler-builtins members are dropped (compiler helpers resolve against
the consumer's owned `libcrabc-builtins.a`), and `llvm-objcopy` localizes every
definition except `UNWIND_ABI`. `audit_provider_symbols` then requires the
defined globals to equal that ABI and the imports to be C ABI only
(`dl_iterate_phdr`, `abort`, and memory primitives). The provider therefore
carries its own copy of the `core` code it uses: a consumer whose `core` has
different crate hashes, such as a `-Zbuild-std` graph, still resolves only the
`_Unwind_*` names against it, and a linker extracts the member exactly as it
would from an installed `libunwind.a`. Only this standalone build passes
`--cfg crabc_unwinder_standalone`, which adds a panic handler that calls C
`abort`: a bounds or arithmetic panic inside the unwinder has no consumer std
to report it. An earlier archive of the raw rlib objects depended on the
stock `core` crate hashes and could not link into a build-std consumer.

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
features, compiler identity, the fused staticlib member and dropped
compiler-builtins member count, the archive member and archive digest, and
the C imports. `cargo.jsonl` and the defined/undefined symbol inventories
retain build evidence. The member is PIC native code with unwind tables. This
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
  --provider-vendor .work/x86_64/RUN/provider-vendor \
  --static-sysroot .work/x86_64/RUN/static-product \
  --dynamic-sysroot .work/x86_64/RUN/dynamic-product
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

The caller supplies `--provider-vendor` as a physical checkout-local Cargo
directory source containing exactly the locked `unwinding`, `gimli`, and
`libc 0.2.186` provider packages. Each Cargo checksum manifest and every
listed file is rehashed against `PINS` before use. For the standalone provider
build, it derives a private registry-shaped `unwinding` source from that
authenticated vendor package so the original upstream tree hash remains the
source boundary while Cargo stays offline. The runner separately
audits Rust's pinned `rust-src/library/.cargo/config.toml`, complete
`rust-src/library/vendor` roster, and `rust-src/library/Cargo.lock`; it merges
only the extra provider `libc 0.2.186` source into a fresh private composite
vendor. This preserves the complete source-built standard-library closure,
including its own pinned dependencies, while keeping the provider graph
exact. The patched-provider staging input is derived from the verified
directory source by replacing only Cargo's directory-source checksum transport
file with the two fixed registry transport markers, then checking the existing
pinned upstream tree hash. Cargo's private source replacement has `net.offline = true`, and every
metadata, lock, and build command passes `--offline`; registry/cache/network
state is never an admitted input.

Before admitting that compiler/linker round trip, the same pinned native
container can run the exact generated-workspace preflight with a fresh output:

```sh
python3 -B unwinder/owned_cleanup.py \
  --provider-vendor .work/x86_64/RUN/provider-vendor \
  --source-graph-preflight-only \
  --output .work/x86_64/RUN/source-graph-preflight
```

It records the authenticated composite vendor, patched source staging, both
Cargo metadata streams, and offline generated lock. It does not compile, link,
or execute a consumer, so its development receipt cannot replace the static
source-built round trip.

After a generated-fixture change, a separate development-only compile
diagnostic may use retained supplied static and dynamic products to compile the
static fixture and the DSO host/plugin pair before a fresh producer cohort is
started:

```sh
./scripts/dev-x86_64.sh unwinder-owned-cleanup \
  --provider-vendor .work/x86_64/RUN/provider-vendor \
  --static-sysroot .work/x86_64/OLD/static-product \
  --dynamic-sysroot .work/x86_64/OLD/dynamic-product \
  --mixed-source-generated-compile-diagnostics-only
```

Its `generated-source-compile-diagnostics.json` records the mixed source/product
relation and all promotion flags as false; the command prints its fresh output
directory. It executes neither fixture and cannot reuse those older products
for the required fresh same-source full consumer matrix. The DSO host's
post-close condition and the plugin's worker condition each accept only their
expected `Ok` value. They keep a panic distinct from a nonzero plugin result
without relying on `PartialEq` for its panic payload.

The dispatcher mounts the checkout and each supplied vendor, static product,
and dynamic product read-only at their canonical paths. Only the fresh
`.work/x86_64/owned-rust-std-cleanup` evidence root is writable, so collection
preserves supplied input modes while it rehashes those inputs after Cargo.

Cargo may also pass the pinned toolchain target library directory with
`-L`. The runner derives that one directory from the same `rustc --print
target-libdir` invocation and records it solely as an unused search path.
Rust archives supplied to the primary Cargo graph remain confined to the fresh
source-built target directory, and no linker search path is forwarded to the
owned LLD command. Cargo still
builds its source `libunwind` archive for build-std, which the receipt records
as unselected; the final normal Cargo graph instead retains the Cargo provider
archive. A stock `std`, `core`, `unwind`, or other target archive, and any
direct final `libunwind` archive, remains rejected.

The same run then builds two checked-in Cargo fixtures with
`--locked --offline -Zbuild-std=std,panic_unwind`, fresh checkout-local Cargo
home, target, and temporary directories, `CARGO_BUILD_JOBS=1`, and fat LTO.
Both fixtures depend on the pinned local `cleanup-dependency` crate. Its
no-inline frame catches and resumes the panic payload while its `Drop` guard
remains live. The static executable and DSO plugin therefore prove resumed
cleanup across an application-crate boundary in addition to the root frame;
the locked Cargo graph, source path, selected dependency archive, and fused LTO
`--extern` input are bound in the consumer evidence. The
source-built static fixture repeats the complete cleanup/backtrace check.
The dynamic fixture builds a Rust `cdylib` plugin which performs that check itself;
its Rust host resolves the plugin's exported entry with `dlopen`/`dlsym` and
loads the plugin by basename through the selected loader's explicit library
path. The host starts the plugin's first internal cleanup, has a host worker
`dlclose` its final handle, then uses saved release and entry pointers to
complete and repeat internal cleanup after close. This exercises retained
owned-loader mapping discovery without a direct-path open or an exception
crossing the DSO ABI.

For a source-built final link the wrapper admits only the Cargo application
root, target `release/deps` library root, and target `release/build` root.
Cargo's compiler-artifact
records identify the fresh `std`, `core`, `alloc`, `panic_unwind`,
`compiler_builtins`, `proc_macro`, and `crabc-unwinder` rlibs by their pinned
source paths.

Rustc still passes the source-built `compiler_builtins` rlib to the native
link after fat LTO; the wrapper omits it in favor of the owned product's
builtins and records the omitted file. Cargo's build-dir layout gives that
package three unit directories with one shared package id: the host
build-script compile (`release/build/compiler_builtins/<hash>/out/build_script_build`),
the build-script run whose `out` is its `OUT_DIR`, and the library compile
whose `out` holds `libcompiler_builtins-<hash>.rlib`. The wrapper can check
only the library unit's shape. `cargo_compiler_builtins_identity` in
`owned_cleanup.py` requires the exact pinned rust-src package id, one record
of each unit, a verbose run command that executes that host script with the
reported `OUT_DIR`, and a library `rustc` command that reads the same
`OUT_DIR` and writes the declared archive to its own unit. The link-receipt
reader then requires the omitted archive to be exactly that library archive.
The retained primary `rustc` command must pass those exact records through
`--extern` and must not pass its separately built `libunwind`. Fat LTO then
absorbs that graph into one native object, so the final owned LLD command
contains no direct Rust rlib; the wrapper records that object's complete
`_Unwind_*` ABI and `rust_eh_personality` before linking. The fixture's real
`_Unwind_RaiseException` address keeps the provider live in the same Cargo/LTO
graph as the source-built `core`; no standalone provider archive is passed to
this link. Before Cargo can remove its transient `*.rcgu.o`, the wrapper makes
one exclusive confined copy, verifies that its digest matches the Cargo input,
and supplies that copy to LLD; the reader rehashes the durable copy while the
receipt retains the original Cargo path. The generated workspace lock, exact pinned provider features and
staged overlay sources are audited before compiling. The provider therefore
inherits the consumer's `panic=unwind`, fat-LTO, and codegen-unit profile
rather than its standalone producer profile. A schema-6 link receipt excludes
stock target rlibs and direct source rlibs. For a plugin it binds Cargo's
transient version script to the retained link input before Cargo may erase it,
and records the exact three cleanup exports plus the provider's 17
`_Unwind_*` exports from the linked cdylib. Cargo artifact JSON, verbose build
records, the pinned `rust-src` library lock, and the linker-side receipt bind
the source graph to the final executable or plugin even where Cargo hard-links
an artifact into its release directory.

For the generated Rust `cdylib`, rustc supplies a confined export version
script and its exact `--no-undefined-version` safety flag. The wrapper accepts
that flag only with the shared export script and retains it in the owned LLD
command; it does not open a general linker-option path.

The native toolchain's host and requested target are both x86_64-musl, so
Cargo also routes its `build_script_build-*` host executables through the
target-linker setting. The runner admits that finite host `release/build`
subtree only to the pinned container `/usr/bin/gcc`, records every such host
link in an exclusive per-artifact receipt. Resolved inputs under Cargo's target
tree are copied into that receipt's private directory before Cargo can erase
transient build objects; the reader rehashes each retained copy and checks any
original that still exists. System linker inputs remain hashed in place. A
generated manifest binds the
receipts by hard-link identity to the exact `compiler-artifact` custom-build
records from Cargo's machine-readable stream, and records the pinned
`rust-src` lock plus every declared package manifest and build source. Each
host-link receipt also hashes the resolved files reported by GNU ld, while
GCC receives a minimal environment with no inherited compiler or library
search overrides. Cargo's build-dir layout links some pinned build scripts as
`<package>/<hash>/out/build_script_build`, without Cargo's usual hash suffix;
that `out` is the compile unit's output directory, not the script's `OUT_DIR`.
The linker admits this shape only when the crate and output directory match
and Cargo's manifest/source pair is one of the `compiler_builtins` or `std`
scripts in the pinned rust-src lock, or an explicitly recorded provider or
composite-vendor build script.
Receipt closure still requires the matching Cargo artifact and exact source
identity.
The only extra provider build executable is the already-audited pinned `libc`
cfg build script; its manifest/source pair is recorded separately and must
match the resolved provider graph. It rejects unmatched, duplicate, forged,
or target-lookalike records before it accepts a consumer. Those host tools do
not become target inputs: the final executable and cdylib link receipts still require fresh source-built
`std`/`core`/`alloc`/`panic_unwind` rlibs and contain no stock target rlib.

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
allocation, registry, mutable global frame state, thread creation or
personality; its only panic handler is the standalone archive's local abort.

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
