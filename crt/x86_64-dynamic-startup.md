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

An owned x86 interpreter has one separate post-relocation option. `Scrt1.o`
weakly imports the record symbol `__crabc_x86_64_owned_crt_handoff`; normal
Rust startup reaches a tiny GOT-reading helper only after the direct entry
handoff. An absent weak symbol is null, preserving the pinned-musl call. A
non-null value is the private v1 record: magic `0x43524142435f4831`, version
one, a complete `abi_size`, and non-null dependency-constructor and
process-finalizer callbacks. Invalid non-null data fails with status 127. The
executable runs the dependency callback after its preinit array and before
`_init`, while libc receives the process finalizer as its sixth argument. This
is a CRT acceptance wire only. The separate private
`ldso-owned-crt-handoff` artifact now publishes it to one fixed graph; that
does not select a general x86 interpreter or dynamic-CRT path.

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

The ordinary CRT artifact does not select a candidate dynamic loader,
loader-to-libc RuntimeV1, loader finalizer handoff, main-image initialization
through `crabc-ldso`, static-link helper closure, candidate libc, loader TLS,
`dl*`, installed CRT objects, an owned sysroot, or promotion. One separate
private evidence configuration,
`crt/build_x86_64.py --dynamic-main-thread-runtime-v1`, builds only `Scrt1.o`
with a direct main-resident RuntimeV1 attachment immediately before
`__libc_start_main`. Its companion loader root accepts only Scrt1's exact null
weak owned-CRT record and its fixture-local DSO supplies only the narrow
six-argument startup/errno boundary. It remains distinct from the owned-CRT
carrier and from any installed loader/libc product, lifecycle, `dl*`, worker,
DTV-growth, sysroot, or promotion claim. Those obligations remain explicit in
`compat/x86_64/parity.toml`.

## Installed owned product

`crt/build_x86_64.py --owned-dynamic-sysroot` builds the installed dynamic
entries: `Scrt1.o` (PIC, dynamic PIE) and a dynamic `crt1.o` (static
relocation, dynamic non-PIE) from the same `x86_64_Scrt1.rs` owner. That mode
adds `crabc_owned_dynamic_runtime` to the lifecycle and RuntimeV1 cfgs. The
entry keeps the untouched stack in `r15`, captures `%rdx`, and the Rust
startup authenticates it against the owned loader's `OwnedCrtHandoffV1`
process finalizer, attaches the RuntimeV1 TLS descriptor, and calls
`__libc_start_main(main, argc, argv, init, fini, rtld_fini)` in the installed
`libc.so`. Libc validates the vectors, publishes the stack guard, environment,
auxv and security state, and then calls `init`.

Main lifecycle ownership follows pinned musl 1.2.6 `ldso/dynlink.c`, whose
`__libc_start_init` runs `do_init_fini(main_ctor_queue)` and whose
`__libc_exit_fini` walks one reverse finalizer list:

1. `init` (`__crabc_x86_64_dynamic_executable_init`) runs the executable
   `DT_PREINIT_ARRAY`, then the record's initial-constructor callback. The
   loader constructs each initial dependency in postorder and finally the main
   image (`DT_INIT`, then `DT_INIT_ARRAY`). Every object joins the finalizer
   list when its construction starts, before its constructors run.
2. `exit` and return from `main` run `atexit` handlers, then `fini` (empty in
   this mode), then `rtld_fini`. The loader finalizes in reverse
   construction-start order: an object loaded by `dlopen` from `main` or a main
   constructor is finalized before the main image; one loaded from a
   dependency constructor after it. An object whose construction did not
   complete, including main after `exit` from any constructor, is skipped.
   Libc flushes stdio last; `_Exit` skips all of these.

The legacy private routes (`--general-dynamic-lifecycle`,
`--dynamic-main-thread-runtime-v1`, the default `Scrt1.o`) keep their
CRT-owned `_init`/init-array and fini-array/`_fini` walk; their loaders keep the
main image outside the callback plan.

Musl never dispatches a dynamic executable's `DT_PREINIT_ARRAY`. The owned CRT
does, as the ELF gABI requires; that single leading `P` is the only admitted
difference in the evidence transcripts.

Run the installed-product evidence against one supplied product, or omit the
argument to build one clean product first:

```bash
./scripts/dev-x86_64.sh owned-crt-dynamic-startup [/abs/checkout/.work/.../installed]
```

`crt/x86_64_owned_dynamic_startup.py` builds `fixtures/owned_dynamic_startup_*.c`
with the product's sealed driver (PIE and non-PIE mains, one initial
dependency, one runtime plugin) and with the pinned musl compiler profile. It
runs eight scenarios per mode through kernel entry and a direct interpreter
command: ordinary return, `exit`, `_Exit`, `exit` from a main or dependency
constructor, `dlopen` from a main or dependency constructor, and compiler
helpers. Every callback checks 16-byte frame alignment, initialized TLS and
TBSS, errno, the masked `AT_RANDOM` stack guard, and the published environment;
`main` checks argv, envp/`environ`, program names, `AT_PAGESZ`, `AT_RANDOM`, and
after kernel entry that `AT_ENTRY` names the installed `_start`. Both final
executables must carry the owned `PT_INTERP`, exact `DT_NEEDED`, nonempty
preinit/init/fini tags, their entry at the installed `_start`, the owned CRT
note, RELRO, NOW binding and a non-executable stack. The driver receipt must
name exactly `Scrt1.o`/`crt1.o`, `crabc-dynamic-attach.o`, `crti.o`, the
application object and DSO, `libc.so`, `libcrabc-builtins.a` and `crtn.o` in
that order, and LLD's trace must extract `crabc-builtins.o` at the archive's
position. Relinking the same object is byte-identical, and the same link
without `libcrabc-builtins.a` fails on `__udivti3`. The dynamic qualification
case `crt-dynamic-startup` replays this leaf on the installed, second, and
extracted products.

Open conditions, recorded rather than asserted:

- Helper definitions extracted into an application DSO are exported `GLOBAL
  DEFAULT`, so an executable linked against that DSO imports them instead of
  extracting its own. Musl's `libgcc.a` helpers are hidden. The fixture keeps
  helper use out of the main image's link-time dependency so each image's own
  extraction stays observable.
- The loader copies at most 16 entries per init or fini array into its
  callback plan and rejects larger main (`mainelf`) or dependency (`graph`)
  arrays; musl has no such bound.
- After a direct interpreter command the owned loader rewrites the process
  auxv (`AT_PHDR`, `AT_ENTRY`, ...), while musl changes only its private copy.
  This loader policy is outside the CRT transcript.

`crt/src/x86_64_dynamic_startup.rs::startup_reject` uses Linux `exit_group`
with status 127. Rejection can occur while checking a later executable array
after a dependency constructor started workers; thread-only `exit` would leave
those workers and the process alive. The freestanding owned-handoff fixture
forces that order with a raw-clone worker and a malformed init-array bound.
