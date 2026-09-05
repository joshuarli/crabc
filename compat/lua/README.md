# Lua owned-sysroot source-build gate

This harness has two deliberately separate source-build lanes for pinned Lua
5.4.8. The established AArch64 lane builds a dynamic graph: a real
`liblua.so.5.4`, dynamically linked `lua`, an upstream-valid private-unit
`luac`, and separate success/failure loadable C extensions. The native x86-64
lane builds complete static ET_EXEC and static-PIE `lua`/`luac` programs from
the same source roster through the installed sealed static driver. Every
candidate compile and link uses `crabc-cc`; resolved linker traces must contain
only installed crabc runtime inputs and explicit Lua application objects or
libraries.

Run it through the architecture-specific Docker entry point:

```bash
./scripts/dev.sh lua
./scripts/dev.sh lua --offline
./scripts/dev-x86_64.sh lua-static-source-build
./scripts/dev-x86_64.sh lua-dynamic-source-build
python3 -m unittest discover -s compat/lua/tests -p 'test_*.py'
```

The AArch64 command builds `target/crabc-sysroot/` first. The x86 static and
dynamic commands materialize their corresponding sealed sysroots first. Each
x86 dispatcher invocation gets a distinct physical
`.work/x86_64/lua-*-source-build/run-*` root with its own producer logs,
sysroot, source extraction/cache, build state, and authoritative report. The
dynamic dispatcher also packages and extracts its sysroot, then builds the
same complete dynamic graph through both roots and requires exact hashes for
`liblua`, `lua`, `luac`, the success/failure modules, and the missing-symbol
copy. The conventional latest x86 report is atomically replaced only after the
whole invocation passes. Both offline paths require a verified Lua archive
cache entry; neither downloads on a cache miss.

## Candidate boundary

The dynamic candidate uses the installed public headers, Rust CRT objects,
`libc.so`/`libc.a`, loader, and `libcrabc-builtins.a`. The static candidate
uses only its selected installed `crt1.o` or `rcrt1.o`, `crti.o`, `crtn.o`,
`libc.a`, `libcrabc-builtins.a`, and explicit Lua application objects. Neither
lane copies or accepts musl startup objects, GCC `crtbegin`/`crtend`, `libgcc`,
compiler-rt, `libatomic`, or `libssp` as a candidate input. The runner records
header selection, every static link receipt/map/trace, and ELF facts. The
dynamic lane additionally records candidate `/proc/<pid>/maps` hashes for the
owned loader/libc, `liblua`, and loaded probe extension.

Candidate execution temporarily stages the otherwise-absent canonical
`/lib/ld-crabc-aarch64.so.1` or `/lib/ld-crabc-x86_64.so.1`, according to the
lane, only inside the disposable native container. It is hash-checked and
removed after execution.

## Musl oracle lanes

Musl 1.2.6 is an execution oracle, not a candidate build or runtime fallback.
The dynamic lane launches the exact candidate executable/application DSOs
under musl's loader with copied musl `libc.so`, with no preload shim. The
crabc-owned CRT uses a private ELF note to select its loader handoff; under
musl it preserves the ordinary direct loader-finalizer ABI and musl's normal
dependency startup.

The x86 lane separately links and launches fresh pinned-musl ET_EXEC `lua` and
`luac` source builds for both owned candidate modes. It never executes a
candidate byte under musl or uses a musl object in a candidate link. The
pinned wrapper's current `-static-pie` route selects `Scrt1.o` and crashes a
tiny independently linked program; that reproducible diagnostic is retained
in the x86 report. It is a wrapper limitation, not a claim that the owned
static-PIE candidate shares ET_EXEC startup: the candidate still has its own
`rcrt1.o`, ET_DYN/relocation, closed-link, source, and bytecode execution
checks.

## Static C-module boundary

The native static lane builds `crabc_probe`, `crabc_fail`, and the small
`static_preload` adapter into each Lua executable. A private copy of upstream
`linit.c` registers their existing `luaopen_*` entry points in
`package.preload`. This proves the same C-module functional and protected
error paths without claiming runtime DSO loading. Dynamic-only DSO map and
missing-symbol cases are explicitly not applicable in static mode. `io.popen`
is not omitted: source and bytecode workloads in every candidate and oracle
arm require it to succeed.

The reports at `compat/reports/lua/latest.json`,
`compat/reports/lua/x86_64-static-latest.json`, and
`compat/reports/lua/x86_64-dynamic-latest.json` compare source and bytecode
streams/status byte-for-byte. The dynamic reports retain non-timing `strace`
diagnostics for normal and controlled-failure module paths. The native dynamic
lane builds a fresh pinned-musl source graph as its oracle; musl artifacts are
never candidate inputs. The fixtures cover dynamic module loading where
applicable, repeated `require`, missing-symbol and init-failure behavior, Lua
C API allocation/buffers, descriptor-relative I/O, stdio, strings/tables/UTF-8,
math, environment/time, and a controlled child/pipe.
