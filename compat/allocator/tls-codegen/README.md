# Allocator compiler-TLS codegen judge

Run this bounded evidence through the pinned native image:

```sh
./scripts/dev.sh allocator-tls
```

The runner enables the default-off `tls-codegen-probe` feature only long
enough to retain seven named access witnesses. It compiles `crabc-mimalloc` for
the native `aarch64-unknown-linux-musl` target with the pinned nightly and
`-Ztls-model=initial-exec`, then inspects the single codegen-unit object.

The judge requires all five roots to be eight-byte `STT_TLS` symbols with
Rust's private `GLOBAL HIDDEN` object binding and rejects any root in dynamic
symbols. The three nonzero ELF initializers must reside in `.tdata`; the two
zero initializers must reside in `.tbss`. Every root and every root-access
witness must use the AArch64 `R_AARCH64_TLSIE_*` relocation pair, and no
witness may contain
`__tls_get_addr`, TLSDESC, general-dynamic, local-dynamic, DTPMOD, or DTPREL
access. The selected ownership-identity witness is the one exception to the
relocation requirement: it must directly read `TPIDR_EL0` without accessing a
TLS variable. A separate witness retains and inspects the source-declared
identity-helper TLS root, which is unused by pinned Linux/AArch64 mimalloc.

The runner also compiles the identical witnesses with the pinned nightly's
default TLS model as a negative control. That object must contain
`R_AARCH64_TLSDESC_CALL` for every root. This demonstrates that the explicit
initial-exec flag is required; it is not redundant source documentation.

This proves the exact bounded rlib codegen shape, not production integration.
Rust has no per-static TLS-model attribute: the initial-exec choice is a crate
codegen setting. The future `crabc-libc` integration must apply the same
per-crate flag and separately audit the final linked allocator/runtime ELF.
