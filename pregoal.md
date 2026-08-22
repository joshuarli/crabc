# Pre-goal — source-build surface gate before CPython

## Purpose and order

Before starting the focused performance work in [`goal.md`](goal.md), crabc
needs one strong source-build compatibility gate. The existing Alpine Python
3.14.7 package already starts and performs deterministic file work under
crabc, but that proves an interpreter *runs* after Alpine built it against
musl. It does not prove that a substantial upstream C project can configure,
compile, link, dynamically extend, and run through a crabc-controlled
development surface.

The ultimate gate is a pinned CPython 3.14.3 source build. CPython is
expensive to compile and its full optional-module graph obscures the first
failure. This pre-goal establishes the same important boundaries with a
smaller, independently useful project first:

> Build a pinned Lua 5.4 interpreter as a shared runtime, link its executable
> against that runtime and crabc, then load separately built C extension DSOs
> through Lua's normal module loader under crabc's dynamic linker.

Lua is chosen over a simple command-line utility because it resembles the
critical CPython shape: an interpreter plus language runtime, math and string
libraries, files/stdio/process/time behavior, a dynamic shared library, and
loadable extension modules. It is deliberately more demanding than compiling
a Lua static binary, while remaining small enough to diagnose quickly.

BusyBox and the existing Alpine corpus remain valuable broad C consumers, but
they do not make dynamic extension loading central. Lua is the better bridge to
`libpython` plus CPython's extension-module system. This pre-goal is
compatibility/surface work; it does not wait for or change the performance
targets in `goal.md`.

## What is already known

- Crabc exposes 1,647 required musl dynamic exports with no current ABI
  metadata mismatch, has 194 public headers, and passes the selected
  libc-test, POSIX, loader, and real-Alpine evidence. See
  [`COMPATIBILITY.md`](COMPATIBILITY.md).
- The pinned Alpine CPython package carries `libpython3.14` and many extension
  modules. The current corpus proves only a normal startup and a small
  stateful-file Python case; it is not an import or source-build claim. See
  [`compat/corpus/README.md`](compat/corpus/README.md).
- Existing C and static tests use the pinned `musl-gcc` frontend and, in some
  paths, musl CRT objects. Crabc does not yet publish its own application CRT
  start/end objects or a complete compiler/sysroot wrapper. See
  [`compat/static-pthread-tls/run.py`](compat/static-pthread-tls/run.py).

The last point defines the required honesty boundary. A result produced with
crabc `libc.so` and loader but inherited pinned-musl `Scrt1.o`, `crti.o`, and
`crtn.o` is a valuable **adapter-sysroot** result. It is not a claim that
crabc already provides a fully self-hosting, musl-free C toolchain.

## The adapter sysroot contract

The first gate uses a disposable, generated adapter sysroot inside the native
Linux/AArch64 Docker container. It must be made by a dedicated Python harness,
not by unrecorded shell setup.

| Component | Required source | Rule |
| --- | --- | --- |
| Headers | `crabc/include/` only, plus compiler builtin headers explicitly discovered and recorded. | A configure/header probe may not fall through to musl headers. |
| C runtime | Current staged `crabc` `libc.so`, `libc.a`, and `libldso.so`. | Every dynamic test must run through crabc's loader and C runtime. |
| Link-name compatibility | `libm`, `libdl`, `libpthread`, `librt`, `libutil`, and similar musl-compatible link names resolve to the staged crabc C runtime where the ABI requires them. | Every symlink and its purpose is recorded; no musl `libc.so` may satisfy a target link. |
| CRT bridge | Pinned musl `Scrt1.o`, `crti.o`, and `crtn.o`, only if required for this first gate. | Report them as external toolchain compatibility objects, hash them, and prove the final process maps no musl libc. |
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
    ├── luac            (bytecode compiler)
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

## Exit criteria and CPython promotion

The Lua pre-goal is complete when the adapter sysroot builds the shared Lua
graph from a pinned source archive, runs all required behavior under crabc,
loads both extension outcomes correctly, and produces the isolation evidence
above. It becomes a permanent fast compatibility gate.

Only then create `compat/cpython/` for CPython 3.14.3. Its first phase uses the
same adapter sysroot and starts deliberately narrow:

1. build the interpreter and shared `libpython` with no optional third-party
   extension dependencies;
2. prove source build, startup, import of the built-in/available standard
   modules, extension loading, files, threads, subprocesses, Unicode, and
   deterministic error paths;
3. add optional libraries one at a time—OpenSSL, zlib, bzip2, xz, libffi,
   SQLite, expat, readline/ncurses, and others—only after each dependency is
   itself rebuilt or otherwise proved against the adapter sysroot;
4. use a hermetic selected CPython test subset before considering a full test
   matrix.

The CPython source build occurs in native Linux/AArch64 Docker, so it is not a
cross compilation and does not need a same-version `--with-build-python`
bootstrap interpreter. If the harness is ever run in a true cross-build mode,
it must follow CPython's documented build-Python and `CONFIG_SITE` contract
explicitly rather than guessing configure answers.

## Follow-on: a crabc-owned sysroot

Passing the adapter-sysroot gate is not the end of toolchain work. A later,
separately scoped stage replaces the borrowed CRT bridge with crabc-owned
application start/end objects and a documented compiler wrapper/sysroot
package. That stage must prove `__libc_start_main`, TLS, constructors,
destructors, stack protector setup, dynamic-interpreter selection, static and
PIE start behavior, and compiler-runtime boundaries. It must also demonstrate
that a source build such as Lua or CPython links and runs without musl headers,
CRT objects, or musl libc artifacts in the target sysroot.

Do not let this later purity goal delay the immediate Lua or CPython adapter
evidence. Equally, do not call adapter evidence a pure crabc sysroot result.
