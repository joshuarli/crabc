# Native static source-runtime closure experiment

## Purpose and boundary

`run_libc_native_mimalloc_shadow_pthread_teardown.sh` builds a private,
selected-native `crabc-libc` static archive and links it into a freestanding C
pthread fixture.  It is not an installed sysroot producer, a public allocator
selection, a dynamic-product proof, or a terminal/fork-quiescence claim.

The existing target-runtime archive is not a valid closed input for that
fixture.  The retained `da2` diagnosis records one `alloc` object, one `core`
object, and seventeen `compiler_builtins` objects with an undefined
`rust_eh_personality`; the old final
`-nostdlib -static --no-undefined --gc-sections` link selected a `core` object
and failed before the probe.  The raw archive list is an input diagnostic, not
a reachability result: it does not identify which of the remaining archive
members a garbage-collected final link would select.

This experiment replaces that **entire three-crate runtime set** with one
source-built Cargo graph.  It must never splice a source `core` or `alloc`
archive into the current staticlib, leave a stock `alloc` beside source `core`,
or add a personality provider.  `rust_eh_personality`, `panic_abort`,
`panic_unwind`, `unwind`, a stock target runtime archive, a foreign compiler
runtime, and a direct source rlib at the final C link are rejected inputs.
Compiler search paths printed by Cargo are recorded, but only selected artifact
and final-link inputs establish provenance.

## Source graph and profile

The development producer will create private state below
`.work/x86_64/native-mimalloc-shadow-pthread-teardown/run.*/source-runtime-*/`
and invoke the pinned nightly's Cargo once for `crabc-libc`, using the existing
workspace lock and a fresh, authenticated offline vendor view.  The Rust standard-library source
comes only from the pinned toolchain's
`lib/rustlib/src/rust/library`, whose `Cargo.lock`, vendor configuration,
package checksums, and selected source files are recorded.  Workspace and
registry dependencies are resolved from the checked lock through that private
vendor; Cargo runs `--locked --offline` with a private `CARGO_HOME`, target,
and `TMPDIR`.

The exact target graph is:

```text
crabc-libc + crabc-mimalloc
  ├── source-built core
  ├── source-built alloc
  └── source-built compiler_builtins
```

It is built with:

```text
cargo -Zbuild-std=core,alloc,compiler_builtins rustc --locked --offline \
  -p crabc-libc --lib --target x86_64-unknown-linux-musl \
  --features x86-owned-static-native-shadow,native-mimalloc-shadow-test-audit
```

The producer supplies and records the target-wide encoded Rust flags
`-Ztls-model=initial-exec`, `-Zunstable-options`,
`-Cpanic=immediate-abort`, `-Cforce-unwind-tables=no`,
`-Crelocation-model=static`, and `-Ccode-model=small`.  It rejects a Cargo
stream that does not show those flags for the source-built runtime crates and
the selected libc graph.  The required immediate-abort mode is the supported
`-Zunstable-options -Cpanic=immediate-abort` build-std profile; the obsolete
`panic_immediate_abort` build-std feature is not an alternative.

`builtins/build.py` supplies the nearest pinned `rust-src` and
`compiler_builtins` source-build mechanics.  `unwinder/owned_cleanup.py`
supplies the nearest private-vendor, compiler-artifact, and primary-rustc
`--extern` closure checks.  This experiment reuses their evidence shape; it
does not repurpose either builder's product or unwinder-provider contract.

## Evidence required before the C probe is accepted

The producer records Cargo JSON artifacts, verbose diagnostics, resolved
paths, and digests.  For `core`, `alloc`, and `compiler_builtins`, each
compiler artifact must have the pinned rust-src root as its source, and every
artifact path must be under the private target root.  The primary `crabc-libc`
rustc record and the selected `crabc-mimalloc` record must bind their exact
`--extern core=`, `--extern alloc=`, and `--extern compiler_builtins=` inputs
to those recorded Cargo artifacts.  Any extra target-runtime extern or a
stock-target artifact is a failure.

The emitted staticlib is then unpacked and compared against the selected
source-built runtime artifacts.  Every included Rust member is classified and
hashed; no member may come from the toolchain target library directory or a
stock `core`, `alloc`, or `compiler_builtins` archive.  The raw undefined
symbol inventory is retained for diagnosis but does not by itself decide link
reachability.

The existing C fixture is linked with its owned CRT objects and its unchanged
`-nostdlib -static -Wl,--no-undefined -Wl,--gc-sections` closure.  The producer
retains the linker map and `rust_eh_personality` trace, records every selected
archive member, and rejects a selected personality, `_Unwind_*`, panic runtime,
stock runtime, foreign runtime, or direct rlib input.  It also audits the
final ELF for no unresolved symbol, no selected dynamic runtime, no dynamic
TLS route, and no personality or unwinder symbols.  Only after those checks do
the existing musl reference and native normal-return, explicit-exit,
cancellation, and pre-start-rejection/reclaim probes count.

## Immediate-abort semantic difference

The current x86 static C root has a local `#[panic_handler]` in
`libc/src/c_abi/x86_64/static_c_abi.rs` that never returns and spins.  A source
runtime built with `panic=immediate-abort` bypasses that handler for a Rust
panic and terminates immediately through the compiler's abort path.  The
fixture has no supported Rust-panic entry point, so this is a deliberately
observable development-profile difference rather than an asserted C/POSIX
behavior change.  A retained controlled-panic witness must record the
termination behavior before any product builder can adopt this profile.

No installed static or dynamic product, C ABI panic policy, Rust consumer
unwinder/provider contract, or current descriptor lifecycle claim changes
until a separate review accepts a product-specific source-runtime closure and
its real static and dynamic evidence.
