# Native x86 unwind provider

Design, dependency graph and trust boundary: [`docs/design/unwinder.md`](../docs/design/unwinder.md).
This page covers building and running the provider and its fixtures. Everything
here is development evidence: receipts keep qualification, promotion and
public-support flags false.

`build.py` compiles the pinned `unwinding` configuration into
`libcrabc-unwind.a`, an ordinary archive with one localized C-ABI member,
`crabc-unwind.o`, providing the `_Unwind_*` functions in `UNWIND_ABI`.
The source-built cleanup path instead stages the same patched provider graph
below its consumer evidence directory and makes `crabc-unwinder` a normal
Cargo dependency.

## Standalone archive

The member is one fat-LTO `staticlib` compilation of `crabc-unwinder` and its
three dependencies against the pinned target `core`. Rust's compiler-builtins
members are dropped (compiler helpers resolve against the consumer's
`libcrabc-builtins.a`) and `llvm-objcopy` localizes every definition except
`UNWIND_ABI`. `audit_provider_symbols` then requires the defined globals to
equal that ABI and the imports to be C ABI only (`dl_iterate_phdr`, `abort`,
memory primitives, plus the optional debug personality reference below). The
archive carries its own copy of the `core` code it uses, so a consumer whose
`core` has different crate hashes (a `-Zbuild-std` graph) still resolves only
the `_Unwind_*` names against it. Only this build passes
`--cfg crabc_unwinder_standalone`, which adds a panic handler that calls C
`abort`.

Before compiling, `build.py` verifies the checked-in registry lock and the
complete cached `unwinding` and `gimli` source trees, then stages the
`unwinder/patches/` overlays beneath a content-addressed
`.work/x86_64/unwinder-source-inputs/` directory. Original registry sources are
never modified.

Each build writes a fresh `.work/x86_64/unwinder-builds/run-*` directory;
explicit nonempty `--output` directories are rejected before any tool runs.
It does not install or select the archive in a runtime product.
`provenance.json` records source-file digests and licenses, features, compiler
identity, pristine and patched tree hashes, the archive member and digest, and
the C imports; `cargo.jsonl` and the symbol inventories retain build output.

```sh
./scripts/dev-x86_64.sh unwinder-build
./scripts/dev-x86_64.sh unwinder-metadata-bounds
./scripts/dev-x86_64.sh unwinder-eh-frame-bounds
./scripts/dev-x86_64.sh unwinder-dynamic-bounds
./scripts/dev-x86_64.sh unwinder-indirect-personality-bounds
./scripts/dev-x86_64.sh unwinder-metadata-target-bounds
./scripts/dev-x86_64.sh unwinder-frame-bounds
python3 -B -m unittest discover -s unwinder/tests
```

The bounds commands are described in the trust-boundary table of the design
page. The Python dependency-audit tests also run on the host without compiling
target code.

### Debug profile

The build defaults to `release`. For focused debug work, in the pinned native
environment:

```sh
scripts/lanes/rust-check.sh env CARGO_PROFILE_DEV_OPT_LEVEL=0 CARGO_PROFILE_TEST_OPT_LEVEL=0 \
  python3 -B unwinder/build.py --profile debug --output .work/x86_64/unwinder-debug
```

`--profile debug` selects Cargo's `dev` profile and enforces opt level zero,
abort-only standalone panic handling and one codegen unit. After localization
the pinned relocatable linker discards unreachable sections with the `UNWIND_ABI` exports
as roots. The debug partial link uses the image's GNU `ld.bfd`: it prunes each
unneeded FDE while keeping unwind records for the provider's live capture
frames, whereas LLD's relocatable section GC discards the whole `.eh_frame` and
ordinary panic searches then stop inside the provider with `END_OF_STACK`.

At opt level zero the target `core` keeps one personality-bearing FDE for its
`panic_nounwind_fmt` abort guard. The standalone panic handler always aborts, so
that guard never enters a personality call. Its `rust_eh_personality` reference
is weak and optional in debug archives: C-only backtrace clients link without
Rust std, and Rust std clients bind their strong personality. The symbol audit
rejects a strong debug import, a provider personality definition and any
weakened required C import. The release import contract is unchanged.

## Standalone cleanup regression

```sh
./scripts/dev-x86_64.sh unwinder-cleanup
```

Builds a fresh provider, then links the complete pinned Rust standard-library
input graph with that archive, replacing exactly one pinned target
`libunwind-*.rlib` and Rust's `-lunwind`/`-lgcc*` request; any other
libgcc/libunwind input, alternate linker-library spelling or response file is
rejected. The fixture (`fixtures/cleanup.rs`) captures a backtrace, unwinds a
`panic_any(73usize)` through two `Drop` frames, checks payload and cleanup
count, and repeats this on a worker thread. Receipts land in
`.work/x86_64/unwinder-cleanup-runs/run-*`. This is standalone pinned-musl
evidence only.

## Owned-product cleanup consumer

`unwinder-owned-cleanup` takes caller-supplied physical inputs; it is not an
installation format for the provider:

```sh
./scripts/dev-x86_64.sh owned-posix-static-products .work/x86_64/rust-std-unwinder-static-products
./scripts/dev-x86_64.sh unwinder-owned-cleanup \
  --provider-vendor .work/x86_64/RUN/provider-vendor \
  --static-sysroot .work/x86_64/rust-std-unwinder-static-products/products/primary \
  --dynamic-sysroot .work/x86_64/RUN/dynamic-product
```

A dynamic product comes from `materialized-dynamic-sysroot`. The runner
refuses missing, duplicate, symlinked or manifest-mismatched roots and
revalidates both payloads after collection. The dispatcher mounts the checkout
and each supplied input read-only; only
`.work/x86_64/owned-rust-std-cleanup` is writable.

`--provider-vendor` is a physical checkout-local Cargo directory source
containing exactly the locked `unwinding`, `gimli` and `libc 0.2.186` packages.
Every Cargo checksum manifest and listed file is rehashed against `PINS`. The
runner separately audits Rust's pinned `rust-src` library config, complete
`vendor` roster and `Cargo.lock`, merges only the provider's extra `libc`
source into a fresh private composite vendor, and runs every Cargo command with
`--offline`; registry, cache and network state are never admitted inputs.

Two optional development modes:

```sh
# generated-workspace preflight: vendor/staging/metadata/lock only, no compile or link
python3 -B unwinder/owned_cleanup.py --provider-vendor .work/x86_64/RUN/provider-vendor \
  --source-graph-preflight-only --output .work/x86_64/RUN/source-graph-preflight

# compile-only diagnostic against older retained products (cannot stand in for a fresh cohort)
./scripts/dev-x86_64.sh unwinder-owned-cleanup --provider-vendor ... --static-sysroot ... \
  --dynamic-sysroot ... --mixed-source-generated-compile-diagnostics-only
```

For each stock-Rust mode the runner builds the provider with `build.py` into a
fresh evidence directory and compiles the unmodified `fixtures/cleanup.rs`
through a finite linker wrapper. The wrapper omits the stock `libunwind-*.rlib`
and compiler-builtins archive, replaces Rust's native libc/libgcc requests with
explicit product files, and rejects ambient libc, CRT, libgcc, libunwind,
response-file and native-library-search inputs. Static links use the supplied
`crt1.o`/`libc.a`; dynamic links use `Scrt1.o`, the attach object, `libc.so`
and the selected loader. Main-thread and worker panic cleanup and backtrace
behavior are checked, and product roots, provider provenance, the full linker
command and trace, and the executable digest are retained.

The same run then builds two checked-in Cargo fixtures with
`--locked --offline -Zbuild-std=std,panic_unwind`, fresh Cargo home/target/temp
directories, `CARGO_BUILD_JOBS=1` and fat LTO. Both depend on the local
`cleanup-dependency` crate, whose no-inline frame catches and resumes the panic
while its `Drop` guard stays live, so cleanup is proven across an
application-crate boundary.

- The static fixture repeats the complete cleanup/backtrace check with the
  provider as a normal Cargo dependency. The provider therefore inherits the
  consumer's `panic=unwind`, fat-LTO and codegen-unit profile.
- The dynamic fixture is a Rust `cdylib` plugin that performs the check itself.
  Its host `dlopen`s it by basename through the selected loader's library path,
  starts the plugin's cleanup, has a worker `dlclose` the final handle, then
  uses saved pointers to complete and repeat cleanup after close, exercising
  retained mapping discovery.

Source-built link constraints, enforced by the wrapper and its receipt reader:

- Only the Cargo application root, target `release/deps` and `release/build`
  roots are admitted. Cargo `compiler-artifact` records identify the fresh
  `std`, `core`, `alloc`, `panic_unwind`, `compiler_builtins`, `proc_macro` and
  `crabc-unwinder` rlibs by pinned source path; stock target rlibs and direct
  source rlibs are rejected (schema-6 link receipt).
- Rustc still passes `compiler_builtins` to the native link after fat LTO. The
  wrapper omits it for the owned builtins, after `cargo_compiler_builtins_identity`
  in `owned_cleanup.py` has checked the exact pinned package id, one record per
  unit (host build-script compile, build-script run, library compile), and that
  the omitted archive is the library unit's. Fat LTO absorbs the graph into one
  object, so the final LLD command has no direct rlib. The wrapper records that
  object's `_Unwind_*` ABI and `rust_eh_personality`, and links an exclusive
  confined copy made before Cargo can erase it (digest checked against the
  Cargo input).
- A `cdylib` link gets rustc's confined export version script, with its
  `--no-undefined-version` flag admitted only alongside that script. The
  receipt binds the script and records the cleanup exports plus the
  `_Unwind_*` exports.
- Cargo may pass the toolchain target libdir with `-L`; it is recorded as an
  unused search path and no search path reaches the owned LLD command. Cargo
  also builds its source `libunwind` for build-std, which the receipt records as
  unselected.
- Host and target are both x86_64-musl, so Cargo routes `build_script_build-*`
  host executables through the target linker setting. The runner admits that
  finite host subtree only to the container's `/usr/bin/gcc`, with a minimal
  environment, and keeps an exclusive per-artifact receipt (inputs copied before
  Cargo can erase them, GNU ld's resolved files hashed). Receipts bind by
  hard-link identity to Cargo's custom-build records and the pinned `rust-src`
  lock; unmatched, duplicate, forged or target-lookalike records are rejected.
  The only extra provider build executable is the `libc` cfg script. Host tools
  never become target inputs.

The owned consumer disables rustc's musl self-contained link inputs and
`crt-static` selection before invoking its own linker; bundled Rust CRT objects
remain rejected.

## Consumer gate

`compat/x86_64/consumer_rust_std_lto.py` is the `consumer.rust-std-lto` leaf. It
builds a fresh provider from the authenticated vendor and links every frozen
stock-std, dependency-bearing, build-std and LTO consumer through
`owned_rust_link.py` (`link_cargo`), which keeps Rust's `unwind` bindings rlib
(members audited as Rust objects only), omits Rust's `compiler_builtins`, and
maps the `-lunwind`/`-lgcc_s` request to the provider archive placed after the
Rust inputs and before `libc`. The gate requires LLD to have extracted exactly
`crabc-unwind.o`. `-static-pie` links use the static product's `rcrt1.o`;
rustc's `-plugin-opt=O*`/`mcpu=` values are the only forwarded LTO options.

It then runs `owned_cleanup.run` against the installed and the extracted
product pair of the same cohort, and builds `fixtures/cross_dso` for each: C
`frame.c` linked twice by the installed `crabc-cc-dynamic
--dynamic-shared-object`, once as a `DT_NEEDED` dependency and once as a
`dlopen`ed runtime DSO. A stock-std and a build-std executable pass Rust
callbacks through both C frames, with a backtrace, a `Drop` guard, and a panic
or catch-and-`resume_unwind`, on the main thread and a worker. The panic must
cross the C frame, run both sides' guards and keep its payload. The provider
finds the C frame's FDE only through that DSO's `PT_GNU_EH_FRAME`, so the lane
first reports a DSO linked without `--eh-frame-hdr`.

`--retained-runtime` additionally has a `dl_iterate_phdr` callback find the
runtime C frame's load and EH header, close the final `dlopen` handle, and
reread the program header before returning nonzero; the saved entry then gets
the same backtrace, cleanup and resume calls. This checks retained mappings, not
an unloading implementation.

`tests/provider_abi_frame.c` keeps RBX and R12-R15 live across the provider's
`_Unwind_Backtrace` capture trampoline and checks them on return, along with
the completion reason and compiler-frame count, using only owned C headers and
the actual provider, in executable, static-PIE and interpreted dynamic modes.

Each Rust image carries its own statically extracted provider; the gate requires
that no image's dynamic symbol table defines or imports an `_Unwind_*` name.
Finally the gate runs the six standalone malformed-metadata regressions once;
they inject their own `dl_iterate_phdr` images in the pinned-musl harness and
supplement the owned-product lanes.

`fixtures/installed_panic_static.rs` and `fixtures/cross_dso/frame.c` are also
linked into a fresh static executable (`installed_backtrace.py`) that checks
main and worker panic cleanup and resume across the C frame with pinned stock
Rust std.
