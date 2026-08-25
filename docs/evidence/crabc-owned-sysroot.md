# Owned CRT/sysroot evidence

Run the native proof with:

```bash
./scripts/dev.sh sysroot
```

The dispatcher builds two clean installed trees,
`target/crabc-sysroot/` and `target/crabc-sysroot-repro/`, then writes
`compat/reports/sysroot/latest.json`. The report passes only when the two trees
match after normalized provenance, the CRT/sysroot purity audit passes, and
the native harness passes all supported driver and runtime contracts.

The evidence includes:

- archive/ELF inventory and source/dependency/link-input purity accounting;
- a locked, source-built `compiler_builtins` lane for AArch64 binary128
  compiler helpers, including source/build-script hashes, exact features, a
  sealed no-native-build log audit, hash-bound producer commands, and a
  no-external-runtime archive-closure audit;
- CRT object hashes bound to direct pinned-rustc commands and emitted AArch64
  entry-machine checks, including `rcrt1.o`'s no-pre-relocation GOT/TLS
  relocation boundary;
- `crabc-cc` plans and actual linker traces for all supported modes;
- canonical interpreter, RELRO/NOW, no-text-relocation, and no-executable
  stack checks;
- dynamic process-map hashes for the owned loader and libc, after startup has
  completed rather than from a loader-only early snapshot;
- initial stack/auxv, constructor/destructor (including executable and DSO
  finalizer bypass through `_Exit`), `atexit`/`__cxa_finalize`, TLS, stack
  guard, dynamic loading, and static-PIE relocation witnesses; and
- two-clean-build reproducibility.

The canonical loader is staged only when absent in the disposable Docker
container and is hash-checked before removal. This makes ordinary kernel
`exec` evidence possible without modifying a persistent host filesystem.

The report distinguishes `crt_sysroot_pure_rust` from
`full_runtime_pure_rust`. The former is the completed scope. The latter stays
`blocked_by_native_allocator` until the separately owned mimalloc port replaces
the current native allocator dependency.
