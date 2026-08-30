# Native x86-64 private dynamic-PIE CRT startup

`Scrt1.o` is a private Linux/x86-64 dynamic-PIE entry artifact built by
`crt/build_x86_64.py`. It is one prerequisite inside the still-planned
`crt.dynamic-startup` family, not an installed CRT, `crabc-libc`,
`crabc-ldso`, an owned sysroot, or public x86-64 support.

The entry in `crt/src/x86_64_Scrt1.rs` preserves the untouched initial stack
in `r15`, clears `rbp`, realigns `rsp` for the x86-64 SysV call ABI, passes the
original stack to `__crabc_x86_64_dynamic_start`, and has one direct
`R_X86_64_PLT32` handoff. Before that handoff it reads neither the GOT nor TLS
and deliberately does not capture entry `%rdx`.

That last rule is a pinned-musl fact, not a guessed glibc convention. The
musl 1.2.6 x86-64 `Scrt1.o` entry passes its initial stack and `_DYNAMIC` to
its private `_start_c`; its `_start_c` calls `__libc_start_main` with a null
sixth `rtld_fini` argument. `crt/src/x86_64_dynamic_startup.rs` preserves the
same six-argument convention: after bounded raw parsing of `argc`, `argv`,
and the environment terminator, it calls
`__libc_start_main(main, argc, argv, init, fini, NULL)`. It does not install
TLS, parse loader state, or invent a `%rdx` finalizer path.

The callback arguments retain the conventional executable order: preinit
array, `_init`, init array; then reverse fini array and `_fini`. Pinned musl's
dynamic `__libc_start_main` owns that lifecycle internally and does not use
these callback arguments, so the musl launch test does not purport to prove
their execution. A separate freestanding candidate-only fixture supplies a
test-local six-argument boundary, requires a null finalizer, invokes the
callbacks, and proves `PQIJKMYXF` for two forward preinit/init entries, main,
two reverse fini entries, and `_fini`.

The private `.note.crabc.owned-crt` marker is exact `CRABC` type
`0x43525401`, revision one. The builder rejects a forged object marker, and
the linked candidate PIE retains its exact allocated `SHT_NOTE` inside a
`PT_NOTE` range. That is final-note retention only: no current x86 loader
consumes the marker or admits the process through it. GNU-property/CET/ISA
metadata parity with pinned musl's `Scrt1.o` is also deliberately outside this
private artifact.

Run the native evidence on Linux/x86-64:

```bash
./scripts/dev-x86_64.sh crt-dynamic-startup
```

The command first verifies the pinned musl 1.2.6 x86 oracle. It then builds a
normal dynamic PIE twice: first with pinned-musl `Scrt1.o`/`crti.o`/`crtn.o`,
then with Rust-produced `Scrt1.o`/`crti.o`/`crtn.o`, while the pinned musl
interpreter and `libc.so` remain the only dynamic runtime. That launch route
proves constructor → main → destructor output (`IMF`), exact `EM_X86_64`
`ET_DYN`, the pinned `PT_INTERP`, a single `DT_NEEDED` entry for `libc.so`, and
candidate-note retention. It observes musl's lifecycle, not consumption of
the candidate callbacks. The separate no-interpreter `ET_EXEC` fixture proves
the candidate callback bridge and forward/reverse array order. The builder
also rejects a copied `Scrt1.o` with its private note forged.

This does not select a candidate dynamic loader, loader-to-libc RuntimeV1,
loader finalizer handoff, main-image initialization through `crabc-ldso`,
static-link helper closure, candidate libc, loader TLS, `dl*`, installed CRT
objects, an owned sysroot, or promotion. Those obligations remain explicit in
`compat/x86_64/parity.toml`.
