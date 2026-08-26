# Native x86_64 foundation evidence

This closed, native Linux/x86_64 lane is foundation evidence named by
[`x86-64.md`](../../x86-64.md). It runs the fixed `crabc-core` lib suite and
the separately admitted direct `crabc-rs` subset for the
`x86_64-unknown-linux-musl` target; it is not public x86_64 runtime support.

Run it only on a native Linux x86_64 host:

```sh
./scripts/dev-x86_64.sh image
./scripts/dev-x86_64.sh core
./scripts/dev-x86_64.sh facade
./scripts/dev-x86_64.sh libc-syscall
./scripts/dev-x86_64.sh ldso-relocation
```

The runner rejects non-Linux and non-x86_64 hosts before Docker, requests
`linux/amd64` for both image build and execution, and validates the image
identity. Its exact evidence command is:

```sh
cargo test --locked --target x86_64-unknown-linux-musl -p crabc-core --lib --no-default-features -- --test-threads=1
```

After the suite passes, `core` finds the single freshly built `crabc-core`
test executable in its ephemeral native target directory and disassembles it.
The gate rejects any `fxrstor`/`fxrstor64` instruction: fenv mutations may
change only x87 control/status and MXCSR, never restore a saved XMM register
file without a Rust register-clobber contract.

`libc-syscall` compiles only `libc/src/c_abi/x86_64/syscall.rs` with a temporary
native probe. It checks raw `openat`, `setsockopt`, and `mmap` calls so the
fourth through sixth x86 syscall registers are behavior-tested without
selecting `crabc-libc` or a public C ABI.

`facade` runs exactly the no-default-feature `crabc-rs` lib tests plus the
`fenv` and `x86_64_foundation` tests. It verifies the explicitly admitted
direct Rust subset only; it does not make omitted kernel-record-owning facade
families selectable or supported on x86-64.

`ldso-relocation` compiles and runs only the unintegrated
`ldso/src/x86_64_relocation.rs` source tests under the pinned native image. It
proves checked symbol-free `R_X86_64_RELATIVE` RELA and ELF64 RELR handling,
including no-mutation rejection of malformed, overlapping-table, and duplicate
targets. It does not select `crabc-ldso`, an ELF interpreter, or dynamic loader
entry point.

The lane owns no allocator evidence and exposes no generic Cargo, shell,
crabc-libc artifact, dynamic-loader artifact, CRT, or sysroot command. Those
remain separate future completion work under `x86-64.md`; passing any command
must not be reported as x86_64 runtime parity.
