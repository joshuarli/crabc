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
Upstream phdr discovery constructs unbounded metadata slices and does not
validate every indirect DWARF pointer. Source pinning does not establish safe
failure for malicious or truncated mapped unwind metadata. That boundary must
be fixed and tested before this provider is promoted. Enumeration is not
claimed async-signal-safe.
