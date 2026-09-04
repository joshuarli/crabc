# crabc-ldso

A `no_std` Rust dynamic linker (`ldso`) for crabc's focused Linux AArch64
musl-compatible runtime profile. It produces `libldso.so`, which can be used
as `--dynamic-linker` for selected unmodified musl-linked executables.

## Compatibility profile

The supported target is Linux AArch64 on Linux kernel versions 5.10 and
newer. This is a focused modern-runtime loader, not a general loader for
other architectures or a promise of complete historical musl or glibc
behavior.

A private Linux/x86-64 little-endian `x86_64-initial-interpreter` feature
exists only for the staged native evidence lane. It builds one bounded ET_DYN
interpreter root for a fixed graph; it is not an installed loader target or
x86-64 support claim.

The separate private `x86_64-general-initial-interpreter` feature is the first
loader-owned x86 initial-graph package. It discovers an arbitrary bounded
non-TLS `DT_NEEDED` topology, deduplicates opened DSO identities by
`(st_dev, st_ino)`, searches only explicit absolute RUNPATH components, maps
and relocates its admitted objects, and rolls them back on a failed
transaction. Its direct evidence is
`compat/x86_64/run_ldso_general_initial_graph.sh`; the target-root variant is
`compat/x86_64/run_ldso_general_initial_graph_target_root.sh`. It does not
yet select TLS, dlfcn, process finalization, CRT handoff, an installed
dynamic product, or x86-64 support.

`x86_64_general_relocation.rs` owns the general graph's relocation transaction:
breadth-first symbol scope, whole-graph preflight, library/main word fixups,
then variable-sized executable COPY. Initial-TLS compositions additionally
admit general TPOFF64 against retained Variant-II module placements. The
[general relocation contract and native gate](../compat/x86_64/general_relocations.md)
record supported forms, exact ownership checks, and the protected-TLS
ABI-versus-musl distinction; fixed/private roots remain separate regressions.

The additive `x86_64-general-initial-lifecycle` integration feature uses that
same general graph and retains dependency legacy init/fini plus init/fini
arrays in its canonical owner. Initialization follows dependency order;
process finalization reverses that order and claims each object once. The
loader passes its private finalizer address through the conventional x86-64
`rdx` entry register. With the general dynamic-main-thread RuntimeV1 feature,
it defers initialization to the authenticated owned CRT/libc composition,
after libc state and executable preinit are ready. This does not select
runtime `dlopen`/`dlclose`, worker TLS, or installed dynamic products. See the
[native lifecycle contract and evidence](../compat/x86_64/general_loader_lifecycle.md).
The [owned dynamic startup/exit evidence](../compat/x86_64/general_dynamic_lifecycle.md)
specifies the real startup composition and its remaining product boundary.

## Usage

Build with:
```bash
cargo build -p crabc-ldso
```

Output is in `target/debug/libldso.so`.

Run a supported AArch64 musl-linked binary:
```bash
LD_LIBRARY_PATH=target/debug ./target/debug/loader my_binary
```

Or directly:
```bash
./my_binary  # if ldso is set as PT_INTERP
```

## Features

- Self-relocating `_start` entry point
- Loads `DT_NEEDED` dependencies
- Handles AArch64 TLS (Thread-Local Storage) with TLS_ABOVE_TP
- Processes the supported AArch64 ELF relocation types
- TLSDESC resolver for aarch64

Startup vectors are copied without fixed argv/envp/auxv limits, and failed
dependency closures roll back their DSO mappings.  In secure execution
(`AT_SECURE`), `LD_LIBRARY_PATH` and `LD_PRELOAD` are ignored and removed from
the environment handed to the program.  Bare
`DT_NEEDED` names are searched through configured and system library paths;
the current working directory is never an implicit search directory.

Runtime `dlopen`, `dlsym`, and `dlclose` operations use a recursive loader lock
and keep `dlerror()` state separate for each thread. Error storage is allocated
per thread; if that allocation fails, the defined result is no pending error
(`dlerror()` returns null) rather than another thread's message.

Consumers that reclaim a TLS block belonging to another thread should use
`__rc_tls_block_size_for(fs_base)` and `__rc_tls_base_offset_for(fs_base)`;
the parameterless compatibility helpers describe the calling thread/process
default only.

## License

MIT OR Apache-2.0
