# Native x86-64 static-PIE CRT foundation

This private, target-specific evidence slice proves only the Linux/x86-64
static-PIE bootstrap objects built by `crt/build_x86_64.py`. It includes one
owned first-thread static-TLS setup step for a static executable. It does not
add a supported x86-64 `crabc` platform, dynamic CRT, dynamic linker, libc,
sysroot, or Rust facade.

The builder emits exactly these Rust-produced objects:

- `rcrt1.o`: parses Linux's initial stack for `AT_PHDR`, `AT_PHENT`, and
  `AT_PHNUM`; derives the load bias from `PT_PHDR`; validates dynamic and
  relocation ranges against `PT_LOAD`; applies only symbol-free
  `R_X86_64_RELATIVE` RELA/RELR records to writable mappings; seals
  `PT_GNU_RELRO`; then calls the static-only lifecycle handoff. Its
  pre-relocation assembly never reads TLS or the GOT.
- `crti.o` and `crtn.o`: ordered `.init`/`.fini` frame fragments consumed by
  the static lifecycle handoff.

`crt/src/x86_64_startup.rs` is deliberately static-PIE-only. It parses the
initial process vectors, invokes the executable preinit/init/fini arrays, and
calls the libc-shaped `__libc_start_main` boundary. Before any lifecycle hook,
it calls the private `crt/src/x86_64_static_tls.rs` bootstrap. That bootstrap
rechecks the bounded auxiliary-vector/program-header contract, requires one
`PT_PHDR`, accepts at most one `PT_TLS`, and validates an initialized TLS image
against a readable, file-backed `PT_LOAD` range and its full allocation against
a mapped `PT_LOAD` range. A `PT_TLS` image is copied below an aligned x86
Variant-II thread pointer, its TBSS tail is zeroed, and the only private TCB
field is written at `%fs:0` before `arch_prctl(ARCH_SET_FS)`. A program with no
`PT_TLS` receives only that private self word and remains a valid static-PIE
case.

The TLS bootstrap owns exactly one initial main-executable image. It does not
define a general TCB ABI, stack guard, DTV, module ID, `__tls_get_addr`,
dynamic-TLS growth, `dlopen` interaction, clone `SETTLS`, pthread lifecycle,
or allocation reclamation. Those remain future libc/ldso contracts. This
source has no dynamic-loader handoff wire contract.

Run the evidence only on a native Linux/x86-64 host:

```bash
./crt/run-x86_64.sh static-pie
```

The launcher rejects a non-x86-64 host before Docker, requests an amd64 image,
and checks the image identity. The checkout is read-only in the container.
The focused test proves both no-TLS and high-alignment local-exec-TLS RELA and
packed-RELR static PIE links are ET_DYN with no interpreter, needed library, or
non-relative dynamic relocation. The TLS form has initialized data plus TBSS,
checks `%fs:0 == ARCH_GET_FS`, and observes its values through preinit, init,
main, and fini in order. Both forms receive distinct ASLR bases across
executions; mutated non-relative RELA and malformed `PT_TLS.p_filesz` records
fail closed with status 127. A compile-time nonzero-image-phase witness guards
the Variant-II layout arithmetic that a page-aligned fixture alone cannot
exercise.

Remaining work is intentionally out of this slice: dynamic `crt1.o` and
`Scrt1.o`, owned-loader startup handoff, x86-64 ldso relocation/TLS support,
pthread TLS lifecycle, sysroot installation, and all public-support promotion
evidence.
