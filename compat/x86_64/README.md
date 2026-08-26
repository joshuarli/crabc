# Native x86_64 foundation evidence

This closed, native Linux/x86_64 lane is foundation evidence named by
[`x86-64.md`](../../x86-64.md). It runs the fixed `crabc-core` lib suite and
the separately admitted direct `crabc-rs` subset for the
`x86_64-unknown-linux-musl` target; it is not public x86_64 runtime support.

Run it only on a native Linux x86_64 host:

```sh
./scripts/dev-x86_64.sh image
./scripts/dev-x86_64.sh musl-oracle
./scripts/dev-x86_64.sh header-abi-reference
./scripts/dev-x86_64.sh header-abi-project
./scripts/dev-x86_64.sh sys-reg-header-abi
./scripts/dev-x86_64.sh types-header-abi
./scripts/dev-x86_64.sh syscall-header-abi
./scripts/dev-x86_64.sh mm-abi-reference
./scripts/dev-x86_64.sh core
./scripts/dev-x86_64.sh facade
./scripts/dev-x86_64.sh libc-syscall
./scripts/dev-x86_64.sh libc-errno-tls
./scripts/dev-x86_64.sh libc-setjmp
./scripts/dev-x86_64.sh ldso-relocation
```

The runner rejects non-Linux and non-x86_64 hosts before Docker, requests
`linux/amd64` for both image build and execution, and validates the image
identity. Its exact evidence command is:

```sh
cargo test --locked --target x86_64-unknown-linux-musl -p crabc-core --lib --no-default-features -- --test-threads=1
```

`musl-oracle` source-builds the SHA-verified upstream musl 1.2.6 release under
`/opt/musl-1.2.6` in the x86 image (with the immutable release-commit fallback)
and proves that its compiler, interpreter, and running `libc.so` are exactly
that tree. It is C/POSIX oracle provenance only: it neither builds a crabc
artifact nor constitutes a musl differential result.

`header-abi-reference` compiles a C reference fixture only with that pinned
toolchain. It locks down the x86 SysV LP64 and x87 `long double`/`fenv` baseline
which the future target-split crabc headers must meet. It deliberately does
not compile crabc headers and is not public x86 C-header support.

`header-abi-project` places the project headers first and compile-checks only
the staged x86 `fenv`, `float`, and fundamental-type declarations, in both SSE
and x87 evaluation modes. It deliberately has no link step: the declarations
are a source-only ABI slice, not a selected `crabc-libc` artifact or general
x86 C-header support.

`sys-reg-header-abi` places the project headers first and compile-checks the
27 Linux/x86-64 ptrace register-index macros in `<sys/reg.h>`. It is another
declaration-only header ratchet, not a ptrace runtime or `crabc-libc` claim.

`types-header-abi` compiles the C and C++ project-header-first
`<bits/alltypes.h>`/`<sys/types.h>` declarations and opaque pthread layouts,
then compiles the same assertions against pinned musl. It covers only the
named `nlink_t`, `blksize_t`, `pthread_t`, and layout declarations; it does
not select a pthread implementation or `crabc-libc`.

`syscall-header-abi` places project `<sys/syscall.h>` first and compares its
complete 384-pair `__NR_*`/`SYS_*` macro surface with pinned musl 1.2.6. It is
compile-only and provides no syscall behavior or C runtime artifact.

`mm-abi-reference` compile-checks pinned-musl x86 `mmap`/`mprotect`/`munmap`
numbers and the closed constants used by the native Rust mapping facade. It
does not compile project C headers or select a C ABI artifact.

[`parity.toml`](parity.toml) is the closed machine-readable x86 completion
ledger. Its validator and focused tests account for the AArch64-equivalent
capability/gate families separately from these foundation measurements.

After the suite passes, `core` finds the single freshly built `crabc-core`
test executable in its ephemeral native target directory and disassembles it.
The gate rejects any `fxrstor`/`fxrstor64` instruction: fenv mutations may
change only x87 control/status and MXCSR, never restore a saved XMM register
file without a Rust register-clobber contract.

`libc-syscall` compiles only `libc/src/c_abi/x86_64/syscall.rs` with a temporary
native probe. It checks raw `openat`, `setsockopt`, and `mmap` calls so the
fourth through sixth x86 syscall registers are behavior-tested without
selecting `crabc-libc` or a public C ABI.

`libc-errno-tls` compiles only `libc/src/c_abi/x86_64/errno.rs` and links a
native C fixture through the installed project `errno.h`. It proves a
local initial-TLS datum with `R_X86_64_TPOFF*`, no `__tls_get_addr` path, zero
initialization, and independent main/pthread `errno` slots. It remains a
source-only leaf rather than a selected `crabc-libc` artifact or a general C
ABI claim; it is not a musl differential or compatibility-oracle gate.

`libc-setjmp` compiles only `libc/src/c_abi/x86_64/setjmp.rs`, then runs the
same C continuation fixture once against pinned musl and once against that
isolated object with the project `<setjmp.h>` first. It proves the 200-byte
x86 machine/signal-mask record, direct aliases, callee-saved register and
stack restoration, zero-to-one return conversion, and `sigsetjmp` mask
restore behavior. It remains a source-only control-transfer leaf, not a
selected `crabc-libc` artifact or general x86 C ABI claim.

`facade` runs exactly the no-default-feature `crabc-rs` lib tests plus the
`fenv`, `x86_64_foundation`, `x86_64_eventfd`, `x86_64_param`, and
`x86_64_io`, `x86_64_mm`, and `x86_64_pipe` tests. The I/O regression proves vector segment
and short-read behavior, 64-bit positioned/vector offsets, `preadv2`/
`pwritev2` flags and current-offset sentinel, plus descriptor duplication and
`fcntl` flags. The eventfd regression proves `NONBLOCK`/`CLOEXEC`, counter
accumulation and reset, semaphore reads, and Linux's reserved all-ones counter
error through direct kernel seams. The parameter regression proves stable
scalar aux-vector observations while retaining the x86 exclusion of the
pointer-valued `AT_EXECFN` API. The pipe regression proves Linux/x86-64's
distinct `O_DIRECT` packet-mode bit, packet-tail discard, and descriptor
`CLOEXEC`. The mapping regression proves only closed anonymous/file mapping,
protection, and unmapping calls, including a sparse 4 GiB file offset; it
permits `PROT_NONE` and rejects `MAP_32BIT`, fixed-map, and wider
map/protection flags before the raw seam. It verifies the
explicitly admitted direct Rust subset only; it does not make polling, epoll,
signalfd, remapping, mapping policy, other kernel-record-owning facade
families, or a general x86-64 facade selectable or supported.

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
