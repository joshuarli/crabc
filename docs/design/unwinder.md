# Native x86 Rust unwinder

Build and run commands: [`unwinder/README.md`](../../unwinder/README.md).
The provider is not qualified: the producer records `qualified: false`.
AArch64 remains paused.

## Why a provider exists

The `consumer.rust-std-lto` family requires ordinary stock Rust `std`,
build-std, dependent applications and LTO through the owned x86 runtime. Stock
`std` retains backtrace and personality references even with `panic=abort`.
The owned CRT, libc and compiler-builtins do not define the `_Unwind_*` ABI,
and a copied `libgcc_s` (the AArch64 runner's approach) violates the x86
owned-product purity contract.

## Provider and dependency graph

[`unwinding` 0.2.10](https://github.com/nbdd0121/unwinding/tree/v0.2.10),
commit `0e2de8fb536b1ca42066024609f58d708cf80e69`, MIT OR Apache-2.0, with
the feature boundary in `unwinder/Cargo.toml`:

```toml
unwinding = { version = "=0.2.10", default-features = false, features = ["unwinder", "fde-phdr-dl", "dwarf-expr"] }
```

The normal graph is `unwinding 0.2.10` -> `gimli 0.34.0`
(`default-features = false`, `read-core`) and `libc 0.2.186`, with registry
checksums pinned in `unwinder/Cargo.lock` and independently in `PINS` in
`unwinder/build.py`. The direct gimli/libc declarations constrain upstream's
floating version ranges; `FEATURES` rejects additional features instead of
admitting Cargo feature unification. `libc` keeps its `default`/`std` feature
spelling inherited from `unwinding` but remains `#![no_std]`, supplies bindings
only, and adds no normal dependencies.

- `src/unwinder/mod.rs` supplies the resume, backtrace, context-query and
  context-update ABI (17 `_Unwind_*` functions, `UNWIND_ABI` in `build.py`).
- `src/unwinder/arch/x86_64.rs` saves and restores SysV registers with Rust
  naked and inline assembly.
- `src/unwinder/find_fde/phdr.rs` finds DWARF unwind data through
  `dl_iterate_phdr`, `PT_LOAD` and `PT_GNU_EH_FRAME`; consumers must link with
  `--eh-frame-hdr`.

The path is `no_std`, allocates nothing, keeps no mutable global frame
registry (the default `fde-registry` feature is off), creates no threads and
supplies no personality, panic handler (apart from the standalone archive's
local abort), printing or allocator. Rust `std` keeps its personality owner;
the abort-only x86 libc defines no `rust_eh_personality`, because supplying
both produced a duplicate-symbol error. There is no C, C++ or standalone
assembly, no proc macro, and no build script in `unwinding` or `gimli`; the
`libc` cfg-discovery script is the sole admitted build executable. All Rust is
visible to LLVM/LTO; naked/inline assembly is a local optimizer boundary. The
crate needs Rust 1.88 or newer plus unstable compiler features, so it is built
only with the repository's pinned nightly.

## Trust boundary: local overlays

Unwinding parses DWARF and restores machine context from memory the loader
mapped, so malformed or truncated metadata must fail with an unwind phase
error, never a provider fault. `unwinder/patches/` holds checked-in overlays
(and one one-line gimli change: `Reader::cannot_implement` gets its existing
private return value as a default body so an external fault-contained reader
works with `read-core`; `gimli/read` would need a global allocator). Upstream
sources are never modified; `build.py` verifies the pristine trees against the
pins and stages patched copies. Each boundary has its own fixture:

| Boundary | Rule | Fixture command |
| --- | --- | --- |
| `PT_GNU_EH_FRAME` header | checked program-header arithmetic; nonempty, non-null, at most 1 MiB, wholly inside a readable `PT_LOAD`; the header's own `p_memsz`, not the rest of the load, bounds the read; remote reader uses `process_vm_readv` so an unreadable header is an error or short read | `unwinder-metadata-bounds` |
| decoded `.eh_frame` pointers | direct target must be in a readable `PT_LOAD`; `EhFrame` spans target to load end; indirect cell checked as a full native word before the unaligned read; null, overflow and slice-limit values rejected | `unwinder-eh-frame-bounds` |
| `PT_DYNAMIC` | nonempty, non-null, whole `Elf*_Dyn` records in one readable `PT_LOAD`; checked advancement; stops at `DT_NULL`; first `DT_PLTGOT` still selects the GOT | `unwinder-dynamic-bounds` |
| CIE `zP` personality and FDE `zL` LSDA cells | `Frame::from_context` re-enumerates program headers and resolves each present cell only if the whole word lies in a readable `PT_LOAD` during that callback; an unresolved present cell is a phase error, an absent one stays absent | `unwinder-indirect-personality-bounds` |
| personality and LSDA targets | non-null personality target in an executable `PT_LOAD`, nonzero LSDA target in a readable `PT_LOAD` (one-byte entry range only) | `unwinder-metadata-target-bounds` |
| CFI and DWARF expressions | register IDs must exist in the x86 context (integer 0-16, MXCSR, FCW); unsupported states, results, non-default address spaces and typed operations are errors; at most 4096 evaluator iterations per expression (plus gimli's 64-value stack); `DW_OP_addr` yields the address without dereference; `DW_OP_deref_size` reads exactly 1-8 bytes zero-extended; register offsets, register expressions and expression memory are read through an exact-length kernel self-read, so an inaccessible or partial read is a phase error | `unwinder-frame-bounds` |
| EH-frame lifetime | declared section capped at 16 MiB; physical readability probed after `dl_iterate_phdr` returns and every later DWARF read guarded (128-byte value cache, 4 KiB probe buffer, no allocator) | `unwinder-frame-bounds` (`eh_frame_lifetime.rs`) |

Limits of these checks: they do not validate that every FDE/CIE/DWARF record
inside a selected load is well formed, a personality's ABI, LSDA contents,
later CFI register loads beyond the guarded reads, or loader mapping lifetime.
The self-read can fail under kernel policy; the provider then returns a phase
error. Enumeration through `dl_iterate_phdr` is not claimed async-signal-safe.
`compat/x86_64/general_dynamic_iterate_consumer.c` is the separate loader
witness for callback reentrancy and mapping lifetime; it does not qualify the
provider.

## Qualification required before promotion

- Exact dependency, license, source and feature provenance; no additional
  native objects, libgcc/compiler-rt, allocator or registration providers.
- The exact exported unwind ABI and stock-std personality ownership,
  including static archive extraction and shared-library symbol resolution.
- EH-frame discovery for the executable and admitted initial/runtime DSOs,
  with installed and extracted PIE and non-PIE consumers, and LTO.
- Backtrace and panic cleanup/resume across ordinary calls, threads and DSOs,
  and failure behavior for malformed or truncated unwind metadata beyond the
  fixtures above.
- Loader callback reentrancy and mapping-lifetime evidence during frame
  enumeration.
- Final stock-std and build-std consumer gates without suppressing unresolved
  symbols or removing the behavior those gates require.

Handwritten dummy unwind symbols, an ambient unwinder, or a reduced fixture
do not satisfy the contract. The broad transitive `libc` bindings and the
lack of an identified upstream fuzz corpus remain audit concerns.
