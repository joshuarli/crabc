# Native x86-64 static-PIE CRT foundation

This private, target-specific evidence slice proves only the Linux/x86-64
static-PIE bootstrap objects built by `crt/build_x86_64.py`. It does not add a
supported x86-64 `crabc` platform, dynamic CRT, dynamic linker, libc, sysroot,
or Rust facade.

The builder emits exactly these Rust-produced objects:

- `rcrt1.o`: parses Linux's initial stack for `AT_PHDR`, `AT_PHENT`, and
  `AT_PHNUM`; derives the load bias from `PT_PHDR`; validates dynamic and
  relocation ranges against `PT_LOAD`; applies only symbol-free
  `R_X86_64_RELATIVE` RELA/RELR records to writable mappings; seals
  `PT_GNU_RELRO`; then calls the static-only lifecycle handoff.
- `crti.o` and `crtn.o`: ordered `.init`/`.fini` frame fragments consumed by
  the static lifecycle handoff.

`crt/src/x86_64_startup.rs` is deliberately static-PIE-only. It parses the
initial process vectors, invokes the executable preinit/init/fini arrays, and
calls the libc-shaped `__libc_start_main` boundary. It has no dynamic-loader
handoff wire contract.

Run the evidence only on a native Linux/x86-64 host:

```bash
./crt/run-x86_64.sh static-pie
```

The launcher rejects a non-x86-64 host before Docker, requests an amd64 image,
and checks the image identity. The checkout is read-only in the container.
The focused test proves RELA and packed-RELR static PIE links are ET_DYN with
no interpreter or needed libraries, execute native constructor/main/finalizer
order, receive different ASLR bases across executions, and reject a mutated
non-relative RELA entry with status 127.

Remaining work is intentionally out of this slice: dynamic `crt1.o` and
`Scrt1.o`, owned-loader startup handoff, x86-64 ldso relocation/TLS support,
sysroot installation, and all public-support promotion evidence.
