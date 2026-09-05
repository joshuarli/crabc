# Proposed native x86 Rust unwinder

Status: dependency proposal, awaiting user decision. No dependency or runtime
provider has been added. AArch64 remains paused.

## Required behavior

The `consumer.rust-std-lto` family requires ordinary stock Rust `std`,
build-std, dependent applications and LTO through the owned x86 runtime.
The exploratory link in `.work/x86_64/rust-std-frontier/owned-link.log`
shows stock std retaining backtrace and personality references even with
`panic=abort`. The owned CRT, libc and compiler-builtins do not define the
required `_Unwind_*` ABI. The existing AArch64 runner's copied `libgcc_s`
is outside the x86 owned-product purity contract.

## Proposed provider and source audit

Use [unwinding v0.2.10](https://github.com/nbdd0121/unwinding/tree/v0.2.10),
commit `0e2de8fb536b1ca42066024609f58d708cf80e69`, MIT OR Apache-2.0,
with this exact feature boundary:

```toml
unwinding = { version = "=0.2.10", default-features = false, features = ["unwinder", "fde-phdr-dl", "dwarf-expr"] }
```

The reviewed upstream lock resolves the normal graph to `unwinding 0.2.10`
→ `gimli 0.34.0` (`default-features=false`, `read-core`) and `libc 0.2.186`.
Those selected dependencies have no further normal dependencies. An actual
integration must lock and audit that exact graph; upstream's version ranges
alone are not an exact transitive pin.

`src/unwinder/mod.rs` supplies the missing resume, backtrace, context-query
and context-update ABI. `src/unwinder/arch/x86_64.rs` uses Rust naked and
inline assembly for SysV register save/restore. `src/unwinder/find_fde/phdr.rs`
locates DWARF unwind information through `dl_iterate_phdr`, `PT_LOAD` and
`PT_GNU_EH_FRAME`. The captured owned link already requests `--eh-frame-hdr`.

The selected path is `no_std`, uses no allocation or mutable global frame
registry, and creates no threads. Disable the default `fde-registry` feature
and all personality, panic-handler, printing and allocator features. Rust std
retains its personality owner. `dwarf-expr` admits DWARF expressions without
adding dependencies or global state.

There are no C/C++/standalone-assembly build products or proc macros.
`unwinding` and `gimli` have no build scripts. The `libc` bindings dependency
has a Rust cfg-discovery build script and a broad cross-platform source tree;
the x86 build would select bindings to crabc's own exported ABI. All selected
Rust is available to LLVM/LTO; naked/inline assembly remains a local optimizer
boundary. The crate requires Rust 1.88 or newer and unstable compiler features,
which must be tested with this repository's exact pinned nightly.

## Decision and qualification boundary

This is a focused candidate, but DWARF parsing and machine-context restoration
replace a critical runtime component. The broad transitive bindings and the
absence of an identified upstream fuzz corpus prevent assuming the dependency
meets every standing-approval criterion in `SCOPE.md` §21. That section says:
“Ask before importing a framework-scale, native-code, unusually broad, or
otherwise difficult-to-audit dependency.” Approval would authorize integration
and qualification of this configuration, not a completion or support claim.

Required qualification includes:

- Exact dependency, license, source and feature provenance; no additional
  native objects, libgcc/compiler-rt, allocator or registration providers.
- Exact exported unwind ABI and stock std personality ownership, including
  static archive extraction and shared-library symbol resolution.
- Owned EH-frame discovery for executable and admitted initial/runtime DSOs,
  with installed/extracted PIE and non-PIE consumers and LTO.
- Backtrace and panic cleanup/resume behavior across ordinary calls, threads
  and DSOs, plus malformed/truncated unwind metadata failure behavior.
- Loader graph/callback reentrancy and mapping-lifetime evidence during frame
  enumeration. Do not infer async-signal safety from `dl_iterate_phdr` support.
- Final stock-std and build-std consumer gates without suppressing unresolved
  symbols or removing the behavior those gates require.

Handwritten dummy unwind symbols, an ambient unwinder, or a reduced fixture
would not satisfy the selected contract.
