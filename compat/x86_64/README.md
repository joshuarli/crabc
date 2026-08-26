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
./scripts/dev-x86_64.sh stat-header-abi
./scripts/dev-x86_64.sh time-header-abi
./scripts/dev-x86_64.sh poll-header-abi
./scripts/dev-x86_64.sh fcntl-header-abi
./scripts/dev-x86_64.sh unistd-header-abi
./scripts/dev-x86_64.sh system-header-abi
./scripts/dev-x86_64.sh syscall-header-abi
./scripts/dev-x86_64.sh signal-header-abi
./scripts/dev-x86_64.sh mman-header-abi
./scripts/dev-x86_64.sh mm-abi-reference
./scripts/dev-x86_64.sh rand-reference
./scripts/dev-x86_64.sh time-abi-reference
./scripts/dev-x86_64.sh time-observation-reference
./scripts/dev-x86_64.sh poll-reference
./scripts/dev-x86_64.sh ppoll-reference
./scripts/dev-x86_64.sh process-identity-reference
./scripts/dev-x86_64.sh process-session-reference
./scripts/dev-x86_64.sh pidfd-open-reference
./scripts/dev-x86_64.sh fstat-reference
./scripts/dev-x86_64.sh system-reference
./scripts/dev-x86_64.sh thread-reference
./scripts/dev-x86_64.sh core
./scripts/dev-x86_64.sh facade
./scripts/dev-x86_64.sh libc-syscall
./scripts/dev-x86_64.sh libc-errno-tls
./scripts/dev-x86_64.sh libc-setjmp
./scripts/dev-x86_64.sh ldso-relocation
./scripts/dev-x86_64.sh ldso-image
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

`stat-header-abi` compiles project and pinned-musl C/C++ `<sys/stat.h>`
declarations, including the x86-64 144-byte `struct stat` layout and selected
mode/timestamp contracts. It is source-only header evidence; it does not
provide filesystem behavior or select `crabc-libc`.

`time-header-abi` compiles project and pinned-musl C/C++ `<time.h>`
declarations, including LP64 time types, `timespec`, `itimerspec`, `tm`, GNU
aliases, clock values, and selected timer declarations. It is source-only
header evidence; it does not provide C time behavior or select `crabc-libc`.

`poll-header-abi` compiles project and pinned-musl C/C++ `<poll.h>`
declarations, including `nfds_t`, `pollfd`, and the x86 extension values. It
is source-only header evidence; it does not provide polling behavior or select
`crabc-libc`.

`fcntl-header-abi` compiles project and pinned-musl C/C++ `<fcntl.h>`
declarations, including x86 open/fcntl flags, `flock`, GNU owner/file-handle
records, selected extensions, and large-file aliases including `lockf64`. It
is source-only header evidence; it does not provide descriptor behavior or
select `crabc-libc`.

`unistd-header-abi` compiles project and pinned-musl C/C++ `<unistd.h>`
declarations, including the staged x86 LP64 POSIX/GNU selectors, process and
system helper declarations, lock constants, and large-file aliases. It is
source-only and does not select C process, filesystem, or descriptor behavior.

`system-header-abi` compiles project and pinned-musl C/C++ `<sys/utsname.h>`
and `<sys/sysinfo.h>` declarations, including the public 368-byte sysinfo
compatibility record. It is source-only and distinct from the bounded Rust
kernel-prefix system-information slice.

`syscall-header-abi` places project `<sys/syscall.h>` first and compares its
complete 384-pair `__NR_*`/`SYS_*` macro surface with pinned musl 1.2.6. It is
compile-only and provides no syscall behavior or C runtime artifact.

`signal-header-abi` compile-checks staged GNU and POSIX x86 `<signal.h>`
signal-frame layouts, including general-register, floating-state, context, and
alternate-stack records, against pinned musl. It is source-only and does not
select C signal behavior or `crabc-libc`.

`mman-header-abi` compile-checks staged C and C++ `<sys/mman.h>` declarations
and selected Linux/x86 mapping values, including `MAP_32BIT`, against pinned
musl. It is source-only and does not select mapping behavior or `crabc-libc`.

`mm-abi-reference` compile-checks pinned-musl x86 `mmap`/`mremap`/`mprotect`/
`munmap` numbers and the closed mapping/remapping constants used by the native
Rust facade. It does not compile project C headers or select a C ABI artifact.

`rand-reference` runs a pinned-musl native x86 reference executable for
`getrandom` syscall/flag values and initialized-length behavior. It does not
link or select a crabc artifact.

`time-abi-reference` pins the musl x86 `timespec` shape,
realtime/monotonic/monotonic-raw/process-CPU clock IDs, and
`clock_gettime`/`clock_getres` syscall values used by the bounded native Rust
time facade. It does not compile a project C header or select a C ABI artifact.

`time-observation-reference` executes pinned-musl x86 realtime and
process-CPU observations used by typed `timespec_get`, `realtime_millis`, and
`process_cpu_time` helpers. It does not compile a project C header or select a
C ABI artifact.

`poll-reference` executes a pinned-musl x86 pipe fixture through `poll(2)` to
pin empty, readable, and hangup states used by the bounded typed Rust poll
facade. It does not compile a project C header or select a C ABI artifact.

`ppoll-reference` executes a pinned-musl x86 pipe and signal fixture through
`ppoll(2)` and `pause(2)`, pinning readiness, temporary signal-mask
restoration, and `EINTR` completion. It is evidence for only the typed Rust
readiness slice, not C polling support or `crabc-libc` selection.

`process-identity-reference` executes pinned-musl scalar and
real/effective/saved UID/GID observations. It is an oracle for the bounded
typed Rust read-only identity facade, not C process API support.

`process-session-reference` executes pinned-musl `getpgid`, `getpgrp`, and
`getsid` observations. It is an oracle for the typed read-only process
group/session slice, not process control support.

`pidfd-open-reference` executes pinned-musl `pidfd_open(2)` calls, pinning
descriptor ownership, `PIDFD_NONBLOCK`, and direct kernel error behavior. It
is evidence for only the typed Rust pidfd-creation slice, not process control
or C process support.

`fstat-reference` records the pinned-musl x86 144-byte `fstat` record and
regular-file behavior for the bounded descriptor `fs::fstat` slice. It does
not complete the broader filesystem path-core capability.

`system-reference` records the pinned-musl `uname` and `sysinfo` behavior used
by bounded typed system name/status/load observations. It does not select
`crabc-libc` or establish C system-information behavior.

`thread-reference` records pinned-musl `gettid`, `sched_getcpu`, and
`sched_yield` behavior for the bounded typed thread slice. It does not
establish pthread, affinity, or scheduling-policy support.

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
`fenv`, `x86_64_foundation`, `x86_64_eventfd`, `x86_64_fs`,
`x86_64_io`, `x86_64_mm`, `x86_64_param`, `x86_64_pipe`, `x86_64_poll`,
`x86_64_process_identity`, `x86_64_process_session`, `x86_64_pidfd_open`,
`x86_64_rand`, `x86_64_system`, `x86_64_thread`, and `x86_64_time` tests. The
I/O regression proves vector segment and short-read behavior, 64-bit
positioned/vector offsets, `preadv2`/`pwritev2` flags and current-offset
sentinel, plus descriptor duplication and `fcntl` flags. The eventfd regression
proves `NONBLOCK`/`CLOEXEC`, counter accumulation and reset, semaphore reads,
and Linux's reserved all-ones counter error through direct kernel seams. The
parameter regression proves stable scalar aux-vector observations while
retaining the x86 exclusion of the pointer-valued `AT_EXECFN` API. The pipe
regression proves Linux/x86-64's distinct `O_DIRECT` packet-mode bit,
packet-tail discard, and descriptor `CLOEXEC`. The mapping regression proves
closed anonymous/file mapping, bounded remap growth/shrink/fixed replacement,
protection, and unmapping calls, including a sparse 4 GiB file offset; it
permits `PROT_NONE`, rejects `MAP_32BIT` and wider map/protection policy, and
leaves `MREMAP_DONTUNMAP` deferred. The readiness regression proves typed
borrowed-record empty/readable/hangup pipe behavior, temporary `ppoll`
signal-mask restoration, signal-only `pause` completion, requested-flag
retention, and timeout-range rejection. The filesystem regression proves only a
typed descriptor `fstat` record. The process regressions prove typed
PID/identity/session observations plus owned nonblocking pidfds, and the system
and thread regressions prove the named bounded kernel observations. It verifies
the explicitly admitted Rust subset only; it does not make pselect, epoll,
signalfd, broader filesystem path-core behavior, mapping locking or policy,
other kernel-record-owning facade families, or a general x86-64 facade
selectable or supported.

The random regression proves raw Linux `getrandom` flag values and initialized
prefix handling, musl's bounded 256-byte `getentropy` behavior, and owned
deterministic state without C random globals. It does not broaden the facade
or make the C random API selectable.

The time regression proves only x86 `timespec` shape, admitted realtime,
monotonic, monotonic-raw, and process-CPU clock IDs, normalized results,
truncated realtime-millisecond observations, and nondecreasing CPU-time
observations through the validated vDSO/direct-syscall seam. Calendar, timer,
timezone, sleep, and clock-mutation APIs remain outside this direct slice.

`ldso-relocation` compiles and runs only the unintegrated
`ldso/src/x86_64_relocation.rs` source tests under the pinned native image. It
proves checked symbol-free `R_X86_64_RELATIVE` RELA and ELF64 RELR handling,
including no-mutation rejection of malformed, overlapping-table, and duplicate
targets. It does not select `crabc-ldso`, an ELF interpreter, or dynamic loader
entry point.

`ldso-image` compiles and runs only the unintegrated checked x86 ELF image
parser. It validates file-facing ELF/program-header and RELA/RELR metadata
before a future mapper or relocation engine can consume it; it neither maps an
image nor selects `crabc-ldso`.

The lane owns no allocator evidence and exposes no generic Cargo, shell,
crabc-libc artifact, dynamic-loader artifact, CRT, or sysroot command. Those
remain separate future completion work under `x86-64.md`; passing any command
must not be reported as x86_64 runtime parity.
