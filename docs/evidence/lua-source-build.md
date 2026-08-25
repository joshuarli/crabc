# Lua owned-sysroot evidence

`./scripts/dev.sh lua` is the completed native Linux/AArch64 Lua 5.4.8
source-build gate. It first produces the two-clean-build owned sysroot proof,
then invokes `target/crabc-sysroot/bin/crabc-cc` for every candidate Lua
compile and link.

The generated report is `compat/reports/lua/latest.json`. It retains the
tarball pin, compiler commands, header traces, resolved linker-input audits,
ELF metadata, raw stdout/stderr/status comparisons, candidate process maps,
and diagnostic `strace` records. A passing report requires all of the
following:

- every candidate target link is limited to installed crabc runtime artifacts
  and declared Lua application objects/libraries;
- candidate `lua` and `luac` name `/lib/ld-crabc-aarch64.so.1`, and candidate
  maps hash-match the installed crabc loader/libc plus `liblua` and the loaded
  probe extension;
- no musl libc, glibc loader, GCC runtime, or compiler-runtime target input
  appears in the candidate boundary;
- source and bytecode workloads match pinned musl 1.2.6 byte-for-byte; and
- module success, cached reload, missing-symbol, and controlled-init-failure
  cases all follow the fixture contract.

The musl lane is an execution oracle only. It launches the exact candidate
executable/application DSOs under musl's loader and copied musl `libc.so`
without a preload shim. The owned CRT advertises its crabc-only lifecycle
handoff through a private ELF note; under musl it accepts the ordinary direct
loader finalizer and musl's normal dependency construction path.

`--offline` requires the verified archive cache at
`compat/lua/.cache/lua-5.4.8.tar.gz`; a cache miss is intentionally an error.
The cache and reports are ignored generated artifacts.
