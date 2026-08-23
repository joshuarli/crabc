# Source-build adapter-sysroot design

## Purpose and current status

The Lua 5.4.8 adapter-sysroot gate is completed current evidence. It proves a
substantial upstream C project can build, link, dynamically extend, and run
through a controlled crabc development surface. It does not make an Alpine
interpreter package or a Lua result into proof of a crabc-owned C toolchain or
the future CPython source-build contract.

Lua is deliberately small enough to diagnose yet exercises the important
interpreter shape:

> Build a pinned Lua 5.4 shared runtime and dynamically linked interpreter
> against crabc, compile its bytecode tool with the required Lua-private
> translation units, then load separately built C extension DSOs through Lua's
> normal module loader under crabc's dynamic linker.

Lua is chosen over a simple command-line utility because it resembles the
critical CPython shape: an interpreter plus language runtime, math and string
libraries, files/stdio/process/time behavior, a dynamic shared library, and
loadable extension modules. It is deliberately more demanding than compiling
a Lua static binary, while remaining small enough to diagnose quickly.

BusyBox and the existing Alpine corpus remain valuable broad C consumers, but
they do not make dynamic extension loading central. Lua is the adapter-sysroot
boundary for later CPython work, whose unimplemented acceptance contract is in
[`docs/roadmap/source-build.md`](../roadmap/source-build.md). It does not wait
for or change the performance targets in
[`docs/roadmap/performance-completion.md`](../roadmap/performance-completion.md).

## Current result

The Lua 5.4.8 gate is complete and remains a permanent regression command:
`./scripts/dev.sh lua`. It source-builds the shared interpreter graph and C
extensions through the generated adapter sysroot, compares source and bytecode
execution byte-for-byte with the pinned musl reference, and records candidate
loader/libc/module mappings with no musl runtime mapping. The generated result
is [`compat/reports/lua/latest.json`](../../compat/reports/lua/latest.json).

## What is already known

- Crabc exposes 1,647 required musl dynamic exports with no current ABI
  metadata mismatch, has 194 public headers, and passes the selected
  libc-test, POSIX, loader, and real-Alpine evidence. See
  [`COMPATIBILITY.md`](../../COMPATIBILITY.md).
- The pinned Alpine CPython package carries `libpython3.14` and many extension
  modules. The current corpus proves only a normal startup and a small
  stateful-file Python case; it is not an import or source-build claim. See
  [`compat/corpus/README.md`](../../compat/corpus/README.md).
- Existing C and static tests use the pinned `musl-gcc` frontend and, in some
  paths, musl CRT objects. Crabc does not yet publish its own application CRT
  start/end objects or a complete compiler/sysroot wrapper. See
  [`compat/static-pthread-tls/run.py`](../../compat/static-pthread-tls/run.py).

The last point defines the required honesty boundary. A result produced with
crabc `libc.so` and loader but inherited pinned-musl `Scrt1.o`, `crti.o`, and
`crtn.o` plus compiler CRT support is a valuable **adapter-sysroot** result.
It is not a claim that crabc already provides a fully self-hosting, musl-free C
toolchain.

## The adapter sysroot contract

The first gate uses a disposable, generated adapter sysroot inside the native
Linux/AArch64 Docker container. It must be made by a dedicated Python harness,
not by unrecorded shell setup.

| Component | Required source | Rule |
| --- | --- | --- |
| Headers | `crabc/include/` only, plus compiler builtin headers explicitly discovered and recorded. | A configure/header probe may not fall through to musl headers. |
| C runtime | Current staged `crabc` `libc.so`, `libc.a`, and `libldso.so`. | Every dynamic test must run through crabc's loader and C runtime. |
| Link-name compatibility | `libm`, `libdl`, `libpthread`, `librt`, `libutil`, and similar musl-compatible link names resolve to the staged crabc C runtime where the ABI requires them. | Every symlink and its purpose is recorded; no musl `libc.so` may satisfy a target link. |
| CRT bridge | Pinned musl `Scrt1.o`, `crti.o`, and `crtn.o`, plus the native compiler's `crtbeginS.o` and `crtendS.o`, only if required for this first gate. | Report them as external toolchain compatibility objects, hash them, and prove the final process maps no musl libc. |
| Compiler frontend | Pinned native AArch64 compiler. | The wrapper supplies only explicit include, library, startup, interpreter, and linker arguments; its fully expanded commands are retained. |
| Third-party libraries | None for the first Lua gate. | Do not mask a libc failure behind a system dependency graph. |

The harness must reject a build if `config.log`, compiler diagnostics, dynamic
section, link map, or `/proc/<pid>/maps` shows musl `libc.so` mapped or used as
a target library. The compiler driver and the declared CRT bridge are allowed
only as recorded build support; they do not become runtime dependencies.

## Lua shared-runtime gate

### Build artifact graph

The harness pins one Lua 5.4 release tarball and SHA-256, extracts it into a
temporary directory, and builds this graph using the adapter sysroot:

```text
Lua sources
    ├── liblua.so       (shared language runtime)
    ├── lua             (interpreter dynamically linked to liblua.so)
    ├── luac            (bytecode compiler with Lua-private units statically composed)
    ├── crabc_probe.so  (separately compiled loadable C extension)
    └── crabc_fail.so   (controlled load/init failure extension)

lua + require("crabc_probe")
    └── crabc libldso + crabc libc + liblua.so + crabc_probe.so
```

`liblua.so` must be real, not a static archive hidden inside the interpreter.
`crabc_probe.so` must be compiled in a separate command after `liblua.so` is
built and loaded via the normal Lua module search path. That forces the
dynamic loader to resolve a foreign extension DSO rather than merely run one
linked-in function.

Lua's `luac` uses compiler internals that upstream deliberately does not export
from `liblua.so`; requiring a dynamic `luac` would therefore test an invalid
upstream link topology. It instead statically composes those same source units
and runs through crabc's dynamic loader and C runtime. The shared-runtime
requirement applies to the `lua` interpreter and separately loaded modules.

### Required Lua program behavior

The test program and extension must emit one deterministic structured result
and validate all results before printing it. It must cover:

- source execution and `luac`-compiled bytecode execution;
- `require` of the extension, repeated `require`, module symbol lookup, and
  a deliberate missing-symbol/init failure with correct Lua error handling;
- strings, tables, UTF-8 library behavior, and nontrivial `math` operations;
- buffered file creation, read, seek, rename, directory-relative setup, and
  cleanup in a disposable fixture directory;
- standard input/output/error buffering and formatted numeric/string output;
- time, environment lookup, a controlled child command or pipe where Lua's
  supported OS library path permits it, and normal process exit;
- extension allocation/free, error propagation, and a caller-owned byte
  buffer round trip across the Lua C API.

The extension should be intentionally small and auditable. It is a loader/C
ABI witness, not a new production dependency or a hand-rolled performance
library. The failure module exists so that success does not conceal an invalid
`dlerror`, cleanup, or DSO-rollback path.

### Required evidence

For every build/run, retain:

1. Lua tarball URL/version/SHA-256; fully expanded compiler/link commands;
   compiler, Docker image, kernel, crabc revision, and artifact hashes.
2. `config`/make output and a configure-style header/link probe log. Lua's
   upstream build is make-based, so the harness itself supplies these small
   explicit probes rather than pretending it ran CPython's Autoconf checks.
3. ELF headers, `DT_NEEDED`, interpreter path, loader search paths, dynamic
   symbol/relocation summaries, and a proof that the interpreter and extension
   are AArch64 PIE/shared objects as intended.
4. `/proc/<pid>/maps` evidence that the launched process maps crabc's loader
   and libc, `liblua.so`, and the requested extension, with no musl libc.
5. Exact stdout/stderr/status comparisons between a pinned-musl reference
   lane and the crabc candidate lane. No output normalization is allowed.
6. A separate `strace` diagnostic for normal load and controlled failure;
   it is not a timing result.

The Lua gate passes only when both reference and candidate have the expected
semantic result, the candidate output matches the reference byte-for-byte,
the module success/failure behavior is correct, and the isolation proof holds.

## Failure taxonomy

Every failure gets one primary classification before any workaround:

| Classification | Examples | Correct response |
| --- | --- | --- |
| Header/API gap | Missing declaration, macro, typedef, feature-test behavior, or C11 probe mismatch. | Fix/validate crabc's public header surface, then retain the probe. |
| Link/sysroot gap | `-lm`/`-ldl` resolves musl, CRT order is wrong, interpreter name is wrong, or a static archive leaks musl objects. | Fix the generated adapter sysroot/wrapper; do not add ambient search paths. |
| Loader/DSO gap | Relocation, `dlopen`, `dlsym`, constructor, TLS, visibility, `dlerror`, or unload failure. | Add the smallest loader regression before repairing the root cause. |
| C runtime gap | File, stdio, allocation, math, locale, process, signal, errno, or thread semantics differ. | Add a focused C regression and preserve the Lua witness. |
| Upstream/dependency gap | A documented Lua assumption cannot be met without a non-scope feature. | Record it and request a scope decision; do not disguise it as success. |
| Harness defect | Reference and candidate are not actually symmetric or inputs are nondeterministic. | Repair the harness and rerun both lanes; retain the invalid evidence. |

## Completed Lua gate

The Lua gate is complete because the adapter sysroot builds the shared graph
from a pinned source archive, runs all required behavior under crabc, loads
both extension outcomes correctly, and produces the isolation evidence above.
It is a permanent fast compatibility gate.

The unimplemented CPython promotion and crabc-owned CRT/sysroot stages are
intentionally not folded into this completed result. Their activation
conditions, acceptance criteria, and non-goals are in
[`docs/roadmap/source-build.md`](../roadmap/source-build.md).
