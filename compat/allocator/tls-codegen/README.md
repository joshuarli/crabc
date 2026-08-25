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
default TLS model as a negative control. It explicitly clears
`CARGO_ENCODED_RUSTFLAGS` for that one build, overriding the production
target-wide setting in `.cargo/config.toml`; that object must contain
`R_AARCH64_TLSDESC_CALL` for every root. This demonstrates that the explicit
initial-exec flag is required; it is not redundant source documentation.

This proves the exact bounded rlib codegen shape, not production integration.
Rust has no per-static TLS-model attribute: the initial-exec choice is a crate
codegen setting. The private `crabc-libc` bridge applies it target-wide, and
the sealed sysroot separately audits the final linked allocator/runtime ELF.

## Native x86-64 proof path

The x86-64 proof is intentionally a separate runner so target-specific ELF
relocations and register evidence cannot be confused with the AArch64 judge.
Run it through the private native x86-64 evidence runner (which refuses
non-x86-64 hosts and exposes no generic shell):

```sh
./compat/allocator/run-x86_64.sh allocator-tls
```

The native runner requires the `x86_64-unknown-linux-musl` target, validates
an ELF64 little-endian x86-64 relocatable object, and requires every private
root to use `R_X86_64_GOTTPOFF`. The
ownership-identity witness alone must perform an exact `%fs:0` load and have
no TLS relocation. Each private-root witness instead proves an FS-segment TLS
access together with `R_X86_64_GOTTPOFF`; its offset may be register-derived
and is not claimed to be zero. The `crabc-core` `%fs:0` test is a
compilation/runtime regression for that source boundary, not independent
oracle evidence. The object and relocation inspection in this runner is the
native x86-64 codegen evidence. The report is written separately to
`compat/reports/allocator/tls-codegen-x86_64.json`.

The probe build uses `--locked` but deliberately not `--offline`: its first
native run may populate the architecture-local Cargo volume from the checked-in
lockfile. It never updates that lockfile or relies on an unrelated prior Cargo
command to warm the cache.
