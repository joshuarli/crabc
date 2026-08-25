# Lua owned-sysroot source-build gate

This harness builds pinned Lua 5.4.8 through the installed crabc application
sysroot. It produces a real `liblua.so.5.4`, a dynamically linked `lua`, an
upstream-valid private-unit `luac`, and separate success/failure loadable C
extensions. Every candidate compile and link uses `crabc-cc`; resolved linker
traces must contain only installed crabc runtime inputs and explicit Lua
application objects/libraries.

Run it through the native Docker entry point:

```bash
./scripts/dev.sh lua
./scripts/dev.sh lua --offline
python3 -m unittest discover -s compat/lua/tests -p 'test_*.py'
```

The command builds `target/crabc-sysroot/` first. `--offline` requires a
verified `compat/lua/.cache/lua-5.4.8.tar.gz` cache entry; it intentionally
does not download on a cache miss.

## Candidate boundary

The candidate uses the installed public headers, Rust CRT objects,
`libc.so`/`libc.a`, loader, and `libcrabc-builtins.a`. It never copies or
accepts musl startup objects, GCC `crtbegin`/`crtend`, `libgcc`, compiler-rt,
`libatomic`, or `libssp`. The runner records a header trace, every link trace,
ELF facts, and candidate `/proc/<pid>/maps` hashes for the owned loader/libc,
`liblua`, and loaded probe extension.

Candidate execution temporarily stages the otherwise-absent canonical
`/lib/ld-crabc-aarch64.so.1` only inside the disposable native container. It
is hash-checked and removed after execution.

## Musl oracle lane

Musl 1.2.6 is an execution oracle, not a candidate build or runtime fallback.
The lane launches the exact candidate executable/application DSOs under musl's
loader with copied musl `libc.so`, with no preload shim. The crabc-owned CRT
uses a private ELF note to select its loader handoff; under musl it preserves
the ordinary direct loader-finalizer ABI and musl's normal dependency startup.

The report at `compat/reports/lua/latest.json` compares source and bytecode
streams/status byte-for-byte and retains non-timing `strace` diagnostics for
normal and controlled-failure module paths. The fixtures cover dynamic module
loading, repeated `require`, missing-symbol and init-failure behavior, Lua C
API allocation/buffers, descriptor-relative I/O, stdio, strings/tables/UTF-8,
math, environment/time, and a controlled child/pipe.
