# Native x86-64 static-PIE CRT foundation

This private, target-specific evidence slice proves only the Linux/x86-64
static-PIE bootstrap objects built by `crt/build_x86_64.py`. It proves checked
relative relocation, GNU RELRO sealing, and the static lifecycle handoff. It
does not add a supported x86-64 `crabc` platform, dynamic CRT, dynamic linker,
libc, sysroot, or Rust facade.

The builder emits exactly these Rust-produced objects:

- `rcrt1.o`: parses Linux's initial stack for `AT_PHDR`, `AT_PHENT`, and
  `AT_PHNUM`; derives the load bias from `PT_PHDR`; validates dynamic and
  relocation ranges against `PT_LOAD`; applies only symbol-free
  `R_X86_64_RELATIVE` RELA/RELR records to writable mappings; seals
  `PT_GNU_RELRO`; then calls the static-only lifecycle handoff. Its
  pre-relocation assembly never reads TLS or the GOT.
- `crti.o` and `crtn.o`: ordered `.init`/`.fini` frame fragments consumed by
  the static lifecycle handoff.

`crt/src/x86_64_startup.rs` is deliberately static-PIE-only. After relocation
and RELRO it passes the original entry stack to the hidden static-link
boundary `__crabc_x86_static_tls_bootstrap` through an
`R_X86_64_RELATIVE` slot before any lifecycle callback or
libc-shaped startup boundary. The libc owner in
`libc/src/c_abi/x86_64/static_tls.rs` validates auxv and `PT_TLS`, materializes
the x86 Variant-II main-thread image, and installs `%fs`. `rcrt1.o` does not
duplicate that owner or define a general TCB, DTV, module ID,
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
real initialized/TBSS/high-alignment `PT_TLS` image before preinit, init, main,
and fini. It also rejects malformed `PT_TLS.p_filesz` with status 127. This
remains one private static-PIE composition artifact, not complete CRT,
pthread/TLS, loader, sysroot, or public x86 support.

Remaining work is intentionally out of this slice: dynamic `crt1.o` and
`Scrt1.o`, owned-loader startup handoff, x86-64 ldso relocation/TLS support,
pthread TLS lifecycle, sysroot installation, and all public-support promotion
evidence.
