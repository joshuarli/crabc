# Private x86-64 owned static sysroot artifact

`./scripts/dev-x86_64.sh owned-static-sysroot` proves one bounded installed
Linux/x86-64 static consumer. It is a verified prerequisite inside the
still-planned `sysroot.static-tls` family and
the still-planned `sysroot.owned-artifact` family, not either family’s
completion and not public
x86-64 support.

## Installed contract

`scripts/build_x86_64_owned_sysroot.py` uses the pinned
`nightly-2026-07-24` Rust toolchain in a sealed build environment and installs
only regular files:

```text
usr/include/
usr/lib/{crt1.o,Scrt1.o,rcrt1.o,crti.o,crtn.o}
usr/lib/libc.a
usr/lib/libcrabc-builtins.a
share/crabc/{manifest,headers,crt,libc-static,libcrabc-builtins,build}*.json
```

The CRT objects come from `crt/build_x86_64.py`. Cargo’s intermediate
`libc.a` is not installed directly: the builder classifies every member,
extracts only crabc `c.*.rcgu.o` objects, and excludes stock Rust core,
compiler-builtins, and native compiler-rt members before deterministic
re-archiving. `builtins/build_x86_64.py` supplies the separate one-member
Rust-only helper archive. The manifest hash-binds the installed payload and
records the excluded inputs and unselected scope. Final publication is atomic,
and two clean builds in distinct roots must have identical regular-file bytes.

## Consumer and rejection evidence

`compat/x86_64/run_owned_static_sysroot.sh` first runs the pinned musl 1.2.6
behavior reference. The candidate then compiles all three translation units
with `-nostdinc -isystem <installed>/usr/include`; dependency records admit
only each named source and that installed header tree. A forged host-header
record must fail.

The final application links by direct LLD from an exact allowlist: installed
`crt1.o`, `crti.o`, `crtn.o`, `libc.a`, `libcrabc-builtins.a`, and the three
consumer objects. `compat/x86_64/owned_static_sysroot_builtins.c` forces an
undefined `__udivti3`; omitting the installed helper archive must fail at that
symbol, while the successful linker trace must attribute its member to the
owned archive. Forged trace entries for an ambient CRT, pinned-musl libc,
libgcc/compiler runtime, and loader must each fail.

The executed `ET_EXEC` preserves the existing `PIMBCAF` preinit/init/main,
selected pthread, LIFO ordinary-exit, and fini observation over initialized,
TBSS, and 4096-byte-aligned Variant-II static TLS. Its ELF has GNU RELRO, one
non-executable stack segment, exactly one `PT_TLS`, no interpreter or dynamic
dependency, no unresolved symbol, and no dynamic TLS relocation. Mutating
`PT_TLS.p_filesz` must still fail closed with status 127.

## Deliberately unselected

This tree has no compiler driver, shared libc, dynamic loader, compatibility
loader alias, dynamic link mode, complete libc archive closure, complete
compiler-helper profile, distribution archive, or extracted-artifact smoke
gate. Those remain requirements of the planned families in
`compat/x86_64/parity.toml`. The artifact does not change x86 promotion or
public-support state.
