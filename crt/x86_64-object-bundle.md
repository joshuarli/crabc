# Native x86-64 CRT object-bundle provenance

`./scripts/dev-x86_64.sh crt-object-bundle` creates the private generated tree
`target/crt-x86_64-object-bundle/`.  Its `objects/` directory contains exactly
the five direct-Rust x86-64 CRT objects: `crt1.o`, `Scrt1.o`, `rcrt1.o`,
`crti.o`, and `crtn.o`.  `manifest.json` records target/toolchain, portable
producer commands, source paths, hashes, and the builder's individual ELF
contracts.

The command performs two independently created clean builds before staging.
Every corresponding object and its machine-readable producer/ELF record must
be byte-identical.  The bundle builder accepts only direct `rustc --emit=obj`
producers with no library search, extern crate, linker argument, CRT, or
compiler-runtime input.  It verifies that the output contains no file other
than the manifest and those five objects.

This is deliberately a private provenance artifact.  It installs no headers,
libraries, builtins/compiler helpers, dynamic loader, linker driver, or
sysroot, and it does not link or execute an application.  It therefore does
not establish x86 dynamic startup, an owned x86 sysroot, Rust-std/LTO support,
or public x86-64 support.  Those remain separate promotion requirements in
`x86-64.md`.
