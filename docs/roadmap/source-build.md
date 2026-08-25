# Source-build progression roadmap

## Current prerequisite

The Rust-owned application CRT/sysroot and Lua 5.4.8 source-build gate are
completed current evidence. Their implementation and evidence boundaries are
in [`docs/design/crt-and-sysroot.md`](../design/crt-and-sysroot.md),
[`docs/design/source-build.md`](../design/source-build.md), and
[`docs/evidence/lua-source-build.md`](../evidence/lua-source-build.md).

This document owns the remaining CPython source-build contract. It does not
reopen the completed CRT/sysroot scope, broaden platform support, or alter the
separate allocator and performance programs.

## CPython promotion

The next source-build target, if selected, is pinned CPython 3.14.3 in native
Linux/AArch64 Docker through the installed `crabc-cc` sysroot.

1. Build the interpreter and shared `libpython` with no optional third-party
   extension dependencies.
2. Prove source build, startup, selected built-in/available module imports,
   extension loading, files, threads, subprocesses, Unicode, and deterministic
   error paths.
3. Add optional libraries one at a time—OpenSSL, zlib, bzip2, xz, libffi,
   SQLite, expat, readline/ncurses, and others—only after each has independent
   owned-sysroot evidence.
4. Use a hermetic selected CPython test subset before considering a broader
   test matrix.

This is native Linux/AArch64 work, not a cross build. A future true cross
build must follow CPython's documented build-Python and `CONFIG_SITE` contract
instead of guessing configure answers.

## Acceptance criteria

- All candidate C compilation and linking use the installed `crabc-cc` wrapper
  and pass resolved linker-input auditing.
- Public headers come only from the installed crabc sysroot plus configured
  compiler intrinsic headers; no probe falls through to musl or ambient system
  headers.
- Dynamic candidates name the canonical crabc interpreter, execute through
  crabc loader/libc, and map no musl/glibc runtime identity.
- The report retains source pins, commands, CRT/runtime choices, ELF facts,
  dynamic dependencies, process maps, statuses, stdout, and stderr.
- Optional dependencies enter only after an independent owned-sysroot proof;
  no ambient system dependency may mask a header, linker, loader, or C-runtime
  gap.
- Failures retain the source-build taxonomy rather than becoming an undocumented
  compatibility workaround.

## Non-goals

- Do not treat a successful interpreter launch as proof of broad CPython
  compatibility or a full CPython test matrix.
- Do not add a package-management system, general toolchain framework,
  portability layer, or unreviewed production dependency graph.
- Do not call complete target-runtime purity passed while the current native
  allocator dependency remains; the sysroot report must keep that distinction.
