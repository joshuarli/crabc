# Owned native kernel-administration C ABI component

This is private native Linux/x86-64 foundation evidence. It contributes three
real libc providers to the owned static and dynamic product feature closure;
it does not complete `system.kernel-admin`, `libc.posix-runtime`, a sysroot
family, qualification, promotion, or public x86 support.

`libc/Cargo.toml` defines `x86-kernel-admin` as the component feature. The
owned static aggregate selects it, and the owned dynamic aggregate inherits
that aggregate. The feature selects the existing `x86-io-permissions` leaf and
the native `arch_prctl` leaf. The default static archive selects neither
feature, and the standalone `x86-io-permissions` feature retains its exact
two-symbol negative-path archive boundary.

The pinned musl 1.2.6 release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417` is the C ABI oracle:

- `src/linux/arch_prctl.c::arch_prctl` is the direct
  `syscall(SYS_arch_prctl, code, addr)` wrapper with `int` status and
  `unsigned long` word arguments.
- `src/linux/iopl.c::iopl` and `src/linux/ioperm.c::ioperm` are direct Linux
  syscall 172/173 wrappers.

Musl exports `arch_prctl` as an x86 ELF compatibility spelling without a
declaration in pinned `<sys/prctl.h>`. The component’s C probe therefore binds
the source signature explicitly and traces the installed `<sys/syscall.h>` and
`<bits/syscall.h>` headers for `SYS_arch_prctl = 158`. It uses the installed
`<sys/io.h>` declarations for `iopl` and `ioperm`.

`run_libc_kernel_admin.sh` first traces the installed headers with GCC's
ambient and builtin include roots disabled, then compiles one C object through
the sealed installed dynamic driver. It links that unchanged object with
pinned musl, owned static ET_EXEC, owned static PIE, owned dynamic PIE, and
owned dynamic non-PIE products, and compares the same execution fingerprint.
Dynamic products run through both normal kernel interpreter dispatch and the
installed interpreter’s direct path. The runner checks the extracted static
archive member and shared-provider ELF tables for exactly one `FUNC GLOBAL
DEFAULT` provider per spelling, then checks executable ELF shape, retained
provider references, and each provider’s raw syscall instruction and number.

The behavior matrix reads `ARCH_GET_FS` and `ARCH_GET_GS` through valid output
storage and checks the non-mutating invalid-operation/null-output failures. It
retains only invalid `iopl` levels and out-of-range `ioperm` spans, comparing
the kernel’s `EINVAL`/`EPERM` ordering with musl under the same container
security context. It neither requests a successful permission change nor
executes a port-I/O instruction, and it does not alter Docker capabilities,
seccomp policy, or host permission configuration.
