# Native x86-64 static CRT foundation

This private, target-specific evidence slice proves only the Linux/x86-64
ordinary-static and static-PIE bootstrap objects built by
`crt/build_x86_64.py`. It proves an ordinary `ET_EXEC` direct entry handoff,
plus checked static-PIE relative relocation and GNU RELRO sealing. It does not
add a supported x86-64 `crabc` platform, dynamic CRT, dynamic linker, libc,
sysroot, or Rust facade.

The builder emits exactly these Rust-produced objects:

- `crt1.o`: preserves the Linux entry stack, establishes the SysV call frame,
  and makes one direct `R_X86_64_PLT32` handoff to the shared static startup.
  It has no self-relocation phase and must not read the GOT or TLS before the
  libc-owned bootstrap has installed the initial image.
- `rcrt1.o`: parses Linux's initial stack for `AT_PHDR`, `AT_PHENT`, and
  `AT_PHNUM`; derives the load bias from `PT_PHDR`; validates dynamic and
  relocation ranges against `PT_LOAD`; applies only symbol-free
  `R_X86_64_RELATIVE` RELA/RELR records to writable mappings; seals
  `PT_GNU_RELRO`; then calls the static-only lifecycle handoff. Its
  pre-relocation assembly never reads TLS or the GOT.
- `crti.o` and `crtn.o`: ordered `.init`/`.fini` frame fragments consumed by
  the static lifecycle handoff.

`crt/src/x86_64_startup.rs` is the shared private static-startup path.
`rcrt1.o` reaches it after relocation and RELRO through an
`R_X86_64_RELATIVE` slot; `crt1.o` reaches it through the final static link.
Both paths pass the original entry stack to the hidden static-link boundary
`__crabc_x86_static_tls_bootstrap` before any lifecycle callback or
libc-shaped startup boundary. The libc owner in
`libc/src/c_abi/x86_64/static_tls.rs` validates auxv and `PT_TLS`, materializes
the x86 Variant-II main-thread image, and installs `%fs`. Neither entry object
duplicates that owner or defines a general TCB, DTV, module ID,
`__tls_get_addr`, dynamic-TLS growth, `dlopen` interaction, clone `SETTLS`,
pthread lifecycle, or allocation reclamation.

Run the no-TLS CRT foundation evidence only on a native Linux/x86-64 host:

```bash
./crt/run-x86_64.sh static-pie
```

The launcher rejects a non-x86-64 host before Docker, requests an amd64 image,
and checks the image identity. The checkout is read-only in the container.
The focused unit test proves no-`PT_TLS` RELA and packed-RELR static PIE links
are ET_DYN with no interpreter, needed library, or non-relative dynamic
relocation. Its fixture supplies a test-local successful TLS-bootstrap stub
only to prove the call boundary while keeping this no-TLS foundation linkable
without libc. Both executions preserve lifecycle order, receive distinct ASLR
bases, and reject a mutated non-relative RELA with status 127. It makes no TLS
materialization claim.

The separate composed evidence is the only proof of the real first-thread TLS
handoff:

```bash
./scripts/dev-x86_64.sh libc-crt-static-tls
```

It links the real `rcrt1.o`/`crti.o`/`crtn.o` with the selected libc archive,
requires the hidden libc boundary to resolve from that archive, and verifies a
real initialized/TBSS/high-alignment `PT_TLS` image before archive-owned
preinit, init, main, bounded ordinary exit, and fini. It proves 32 fixed
no-allocation C/C++-ABI callback registrations, LIFO `atexit`/`__cxa_atexit`
dispatch, and no-op `__cxa_finalize`, then rejects malformed `PT_TLS.p_filesz`
with status 127. This remains one private static-PIE composition artifact, not
complete CRT, stdio/C++/DSO or concurrent-exit lifecycle, pthread/TLS, loader,
sysroot, or public x86 support.

The parallel ordinary-static composition evidence is:

```bash
./scripts/dev-x86_64.sh libc-crt1-static-tls
```

It links the real `crt1.o`/`crti.o`/`crtn.o` with the selected static libc
archive, proves that an archive-free static link fails at both hidden TLS and
startup boundaries, and verifies a real `ET_EXEC` with one
initialized/TBSS/4096-byte-aligned `PT_TLS` image. The shared startup calls
libc's bootstrap before archive-owned preinit, init, main, bounded ordinary
exit, and fini. The fixture proves its 32 fixed no-allocation
`atexit`/`__cxa_atexit` LIFO registrations, a no-op `__cxa_finalize`, one
fresh selected worker, and malformed `PT_TLS.p_filesz` rejection with status
127. It does not promote general CRT/startup, libc entry ABI, pthread/TLS,
loader TLS, sysroot, or public x86 support.

Remaining work is intentionally out of this slice: dynamic `crt1.o` and
`Scrt1.o` contracts beyond this static `ET_EXEC` entry, owned-loader startup
handoff, x86-64 ldso relocation/TLS support, pthread TLS lifecycle, sysroot
installation, and all public-support promotion evidence.
