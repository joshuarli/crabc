# Source-build progression roadmap

## Status and ownership

The Lua 5.4.8 adapter-sysroot gate is complete current evidence; its design,
isolation boundary, and failure taxonomy are in
[`docs/design/source-build.md`](../design/source-build.md) and
[`docs/evidence/lua-source-build.md`](../evidence/lua-source-build.md).

This document owns the detailed future acceptance contract for source-build
work. [`STATUS.md`](../../STATUS.md) routes current status and related
roadmaps. The present performance contract remains in
[`performance-completion.md`](performance-completion.md); source-build work
does not weaken, delay, or replace its scorecard.

## Activation conditions

CPython promotion may begin only from the verified Lua adapter-sysroot
boundary. The crabc-owned sysroot is a later, separately scoped stage; neither
its purity goal nor optional CPython dependencies may be used to relabel the
completed Lua adapter evidence as a pure crabc toolchain result.

## CPython adapter-sysroot promotion

The next source-build target is a pinned CPython 3.14.3 build in native
Linux/AArch64 Docker. Its first phase retains the Lua adapter sysroot and is
deliberately narrow:

1. Build the interpreter and shared `libpython` with no optional third-party
   extension dependencies.
2. Prove source build, startup, import of the built-in/available standard
   modules, extension loading, files, threads, subprocesses, Unicode, and
   deterministic error paths.
3. Add optional libraries one at a time—OpenSSL, zlib, bzip2, xz, libffi,
   SQLite, expat, readline/ncurses, and others—only after each dependency is
   itself rebuilt or otherwise proved against the adapter sysroot.
4. Use a hermetic selected CPython test subset before considering a full test
   matrix.

The build is native Linux/AArch64, not a cross compilation, and does not need
a same-version `--with-build-python` bootstrap interpreter. If this harness is
ever used for a real cross build, it must follow CPython's documented
build-Python and `CONFIG_SITE` contract explicitly rather than guessing
configure answers.

### CPython acceptance criteria

- The adapter sysroot remains generated, disposable, and fully recorded.
- Public headers come from crabc plus explicitly discovered compiler builtins;
  no probe falls through to musl headers.
- Dynamic targets run through staged crabc loader/libc and map no musl libc.
- Every build/link command, CRT bridge object, ELF result, dynamic dependency,
  process mapping, status, stdout, and stderr result is retained as evidence.
- Optional dependencies enter only after an independent adapter-sysroot proof;
  no ambient system dependency may mask a C-runtime, loader, header, or link
  failure.
- Failures retain the source-build taxonomy rather than being converted into a
  successful partial claim.

## Crabc-owned CRT and sysroot

Passing the adapter-sysroot gate does not complete toolchain work. A later,
separately scoped stage replaces the borrowed CRT bridge with crabc-owned
application start/end objects and a documented compiler wrapper/sysroot
package.

It must prove all of the following:

- `__libc_start_main`, TLS, constructors, destructors, stack-protector setup,
  dynamic-interpreter selection, static and PIE start behavior, and
  compiler-runtime boundaries;
- source builds such as Lua or CPython link and run with no musl headers, CRT
  objects, or musl libc artifacts in the target sysroot; and
- the wrapper's include, library, startup, interpreter, and linker choices are
  explicit, recorded, and tested rather than ambient compiler search paths.

## Non-goals

- Do not call adapter-sysroot evidence a pure crabc-owned sysroot result.
- Do not use source-build work to introduce an unreviewed production
  dependency, broad package matrix, or ambient dependency graph.
- Do not use a successful interpreter launch as proof of source build,
  extension loading, or a complete CPython test matrix.
- Do not let this roadmap change the Linux/AArch64 scope, musl oracle, or
  performance acceptance contract.
