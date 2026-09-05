# Source-build design

## Purpose and current boundary

The completed Lua 5.4.8 gate proves that a nontrivial upstream C application
graph can compile, link, extend dynamically, and run through the installed
Linux/AArch64 crabc sysroot. Its canonical command is:

```bash
./scripts/dev.sh lua
```

The command first builds and proves `target/crabc-sysroot/`, then builds Lua
with `target/crabc-sysroot/bin/crabc-cc`. The installed driver owns the target
include directories, CRT objects, default C library/helper archive, linker,
and canonical interpreter path. It does not borrow musl CRT objects, GCC
`crtbegin`/`crtend`, `libgcc`, compiler-rt, `libatomic`, or `libssp`.

The result is a source-build and application-CRT proof, not a CPython result
or a claim of a self-hosting compiler. The host compiler, linker, Python, and
Docker remain build tools outside the target-runtime claim. Lua source and its
C extensions are application inputs, not target-runtime implementation code.

The target-runtime purity boundary is deliberately split:

| Claim | Current result | Meaning |
| --- | --- | --- |
| CRT/sysroot purity | Passed | The Rust CRT, builtins archive, installed runtime inputs, driver, and final Lua links are owned and audited. |
| Complete target-runtime purity | Blocked by native allocator | `libmimalloc-sys` remains the current libc allocator backend. The report records this rather than calling the complete runtime pure. |

`compat/reports/sysroot/latest.json` and the installed
`share/crabc/purity.json` are the machine-readable records. See
[`crt-and-sysroot.md`](crt-and-sysroot.md) for the production/runtime design.

## Historical adapter evidence

Earlier Lua adapter-sysroot lanes that borrowed a musl CRT are retained only
as historical differential evidence. They are neither the default build path
nor evidence for the installed crabc sysroot, and they must not be used to
turn a missing crabc startup or runtime input into a passing candidate result.
Musl continues to be the behavior oracle in the explicitly separate reference
lane described below.

## Lua build graph

The hash-pinned Lua archive is extracted into a temporary application tree.
`crabc-cc` compiles its C translation units and links this graph:

```text
Lua C sources
    ├── liblua.so.5.4       shared language runtime
    ├── lua                 dynamically linked interpreter
    ├── luac                upstream-valid private-unit composition
    ├── crabc_probe.so      separate loadable C extension
    └── crabc_fail.so       controlled module-init failure extension

lua + require("crabc_probe")
    └── crabc loader + crabc libc + liblua.so.5.4 + crabc_probe.so
```

`luac` intentionally composes Lua-private translation units instead of
linking to `liblua.so.5.4`, matching upstream's valid topology. `lua` and the
extensions remain separate dynamic objects so the gate exercises ordinary DSO
loading, symbol lookup, failure cleanup, and runtime TLS/constructor state.

Every candidate link includes `-Wl,--trace`. The runner classifies every
resolved path as an installed crabc runtime input or an explicit Lua
application object/library. Any other target runtime input rejects the build.
The header probe similarly permits only the installed public headers and the
configured Clang resource headers.

## Native x86-64 dynamic source graph

`./scripts/dev-x86_64.sh lua-dynamic-source-build` is the native counterpart
for the selected installed dynamic product. It materializes an owned dynamic
sysroot, packages and extracts that exact product, and builds the frozen Lua
graph through each tree with `crabc-cc-dynamic`. The candidate contains the
versioned `liblua.so.5.4`, PIE `lua`, private-unit PIE `luac`, and independent
`crabc_probe.so` and `crabc_fail.so` modules; `crabc_missing.so` is a separate
copy used to exercise the missing-init-symbol path.

Every candidate link has an installed-driver receipt that binds the manifest,
output hash, exact application DSO hashes, owned CRT/libc/builtins inputs, and
link trace. The runner rejects a foreign loader or libc in the ELF, trace, or
candidate mappings. It runs source and bytecode workloads through the normal
owned x86 loader, including successful, failing, and missing-symbol C-module
loads and `io.popen`.

A fresh pinned-musl 1.2.6 dynamic Lua graph is built from the same pinned
sources as the execution oracle. It is never a candidate input. A pass also
requires the six declared candidate artifact hashes to match between the
installed and package-extracted sysroot lanes. The result records
`compat/reports/lua/x86_64-dynamic-latest.json`; it proves this consumer slice
and does not promote any incomplete runtime family.

## Reference comparison

Candidate execution uses the normal kernel path through
`/lib/ld-crabc-aarch64.so.1`; the disposable native container temporarily
stages only that otherwise-absent canonical loader and removes the exact file
afterward. Candidate maps must contain hashes for the installed crabc loader
and `libc.so`, plus `liblua.so.5.4` and `crabc_probe.so`, with no musl or glibc
runtime identity.

The same candidate executable and application DSOs also run under the pinned
musl 1.2.6 loader as a behavior oracle. This reference lane uses a copied musl
`libc.so` and no startup shim: the owned-CRT capability is a private ELF note,
not an unresolved libc lifecycle symbol. Musl therefore supplies its ordinary
direct x0 finalizer and handles its dependency graph before application entry,
while the exact candidate program and DSO bytes remain unchanged.

Source and `luac` bytecode executions compare raw status, stdout, and stderr
without normalization. The workload covers repeated module loads, missing
symbol and initialization failure paths, allocation/buffer C API crossings,
files and descriptor-relative I/O, stdio, strings/tables/UTF-8/math,
environment/time, and a controlled child/pipe. `strace` remains diagnostic
only, never a performance result.

## Failure taxonomy

| Classification | Examples | Response |
| --- | --- | --- |
| Header/API gap | Missing declarations, macro/typedef behavior, feature-test mismatch. | Add a focused public-header regression and repair the C ABI boundary. |
| Link/sysroot gap | A foreign input appears in a linker trace, wrong CRT ordering, wrong interpreter. | Repair `crabc-cc` or installed sysroot inputs; do not add ambient search paths. |
| Loader/DSO gap | Relocation, constructor, `dlopen`, `dlsym`, TLS, visibility, or unload failure. | Add the smallest loader regression before repairing ownership/state. |
| C runtime gap | File, stdio, allocation, math, locale, process, signal, errno, or thread behavior differs. | Add a focused observable C regression and retain Lua as integration evidence. |
| Reference harness gap | The musl lane lacks a documented private-ABI shim or execution inputs are asymmetric. | Make the reference-only boundary explicit and rerun both lanes. |
| Upstream/dependency gap | Lua requires an out-of-scope third-party library or policy. | Record the limitation and request a scope decision. |

## Future source-build work

CPython remains unimplemented. Its activation conditions and narrow
acceptance contract are in [`docs/roadmap/source-build.md`](../roadmap/source-build.md).
It starts from this owned-sysroot boundary; it must not introduce a portability
layer, a package-management framework, or unproved optional dependencies.
