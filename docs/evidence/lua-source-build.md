# Lua adapter-sysroot evidence

The pinned Lua 5.4.8 source-build gate is completed current evidence. Run it
through `./scripts/dev.sh lua` (or `--offline` with a warm verified cache).
The owning design and exact boundary are in
[`docs/design/source-build.md`](../design/source-build.md); this note records
what the completed gate proves and does not prove.

## Completed contract

The generated adapter sysroot uses crabc public headers and staged `libc.so`,
`libc.a`, and `libldso.so`. The harness builds a real shared `liblua.so`, a
dynamically linked `lua` interpreter, a statically composed upstream-valid
`luac`, and separately compiled success and controlled-failure extension DSOs.
It compares source and bytecode execution with the pinned musl reference
byte-for-byte, validates module success/failure behavior, and proves the
candidate maps crabc loader/libc, `liblua`, and the requested extension with no
musl libc mapping.

The generated report at `compat/reports/lua/latest.json` retains source and
artifact pins, expanded commands, header/link probes, ELF and dynamic-link
information, raw streams/status, process maps, and non-timing normal/failure
`strace` diagnostics.

## Boundary retained by the evidence

The gate deliberately uses pinned musl `Scrt1.o`, `crti.o`, and `crtn.o`, plus
the compiler's CRT support objects, as explicitly recorded build support. It
does not provide a crabc-owned C CRT or compiler wrapper. The harness rejects
musl `libc.so` as a target link or runtime mapping, but borrowed CRT objects do
not become crabc runtime artifacts or establish a self-hosting toolchain.

The precise adapter-sysroot design and failure taxonomy remain stable current
documentation because later CPython and owned-sysroot work must classify a
failure before attempting a workaround. Their future acceptance contracts are
in [`docs/roadmap/source-build.md`](../roadmap/source-build.md).
