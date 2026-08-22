# Lua source-build adapter-sysroot gate

This harness implements the prior-to-performance source-build gate described
in [`pregoal.md`](../../pregoal.md). It builds pinned Lua 5.4.8 from source as
a real `liblua.so.5.4`, links `lua` dynamically to it, and loads separately
compiled extension DSOs through normal Lua `require` behavior. `luac` cannot
link against the shared library because its upstream implementation uses Lua
compiler internals that are intentionally not exported; it statically composes
the same Lua translation units while retaining the crabc dynamic loader/C
runtime boundary.

The build is native Linux/AArch64 only. Run it through the Docker entry point:

```bash
./scripts/dev.sh lua
./scripts/dev.sh lua --offline
python3 -m unittest discover -s compat/lua/tests -p 'test_*.py'
```

`scripts/dev.sh lua` creates current release crabc artifacts before invoking
the runner. The runner downloads the source archive only when its verified
cache entry is absent; `--offline` refuses a cache miss. The cache is local and
ignored: `compat/lua/.cache/`.

## Adapter-sysroot boundary

The generated disposable sysroot uses crabc public headers and staged crabc
`libc.so`, `libc.a`, and `libldso.so`. Its compatibility link names (`libm`,
`libdl`, `libpthread`, `librt`, and `libutil`) deliberately resolve to crabc's
unified C runtime. The test uses the pinned musl `Scrt1.o`, `crti.o`, and
`crtn.o`, plus the native compiler's `crtbeginS.o` and `crtendS.o`, only as
explicitly recorded compiler-support bridge objects.

That makes this a useful source/header/link/runtime test while remaining
honest: it is **not** a claim that crabc already ships a fully owned C CRT or
compiler wrapper. The runner rejects target links or runtime mappings that use
musl `libc.so`; its report hashes and records the borrowed CRT objects.

## Evidence

The generated report lives at `compat/reports/lua/latest.json`. It records:

- source pin and archive hash, expanded compiler/link commands, include path,
  build ID and artifact hashes;
- header probe output proving the crabc header boundary;
- dynamic ELF information for `liblua`, `lua`, `luac`, and all extension DSOs;
- raw musl-reference/crabc-candidate stdout, stderr, and status comparisons;
- candidate `/proc/<pid>/maps` evidence for crabc loader/libc, `liblua`, and
  the extension, plus an explicit no-musl-libc check;
- separate non-timing `strace` diagnostics for normal and failure module paths.

The fixtures cover compiled bytecode, repeated module load, C API allocation
and caller-buffered bytes, files/stdio, strings/tables/UTF-8/math, environment
and time, a controlled child/pipe, plus both missing-symbol and module-init
failure behavior. They are test fixtures, never crabc production code.
