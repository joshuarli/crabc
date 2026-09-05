# Owned signal helpers

The installed Linux/x86-64 static and dynamic products provide the eight
signal spellings already required by the selected `process.signal` roster:
`__sysv_signal`, `bsd_signal`, `psiginfo`, `psignal`, `sighold`, `sigignore`,
`sigrelse`, and `sigset`. This installed-product completion leaves the frozen
private feature archives, their reporting limitations, and AArch64 unchanged.

The source oracle is musl 1.2.6, release revision
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, under its MIT license; archive
provenance is recorded in `compat/upstreams.toml`. Source mappings are:

| Musl source/function | Owned implementation |
| --- | --- |
| `src/signal/signal.c` aliases | `libc/src/c_abi/x86_64/signal_control.rs` |
| `src/signal/sighold.c`, `sigrelse.c`, `sigignore.c`, `sigset.c` | `libc/src/c_abi/x86_64/owned_signal_helpers.rs` |
| `src/signal/psignal.c`, `psiginfo.c` | `libc/src/c_abi/x86_64/owned_signal_reporting.rs`, a child of `owned_static_stdio.rs` |

Both aliases have the same address as `signal` and install `SA_RESTART` as
musl does, despite the historical `__sysv_signal` name. The owned product
preserves the source's overridable weak ELF binding, as does the frozen
feature. The differential checks both alias bindings and their shared address
and size against `signal` in the oracle, installed static executables, and
dynamic libc provider. The System V helpers
compose the existing public signal-set, action and mask owners. Their
reserved-signal validation, sticky interrupting-handler bookkeeping and
SIGABRT action serialization therefore remain on the application path.
`sigset` queries or replaces the action before changing the mask. If the
second operation fails, the installed action remains, matching musl; a
previously blocked signal returns `SIG_HOLD`. The inherited action owner
retains its existing boundary: this slice adds no separate handler cache or
first-handler reserved-signal unmasking algorithm.

Reporting takes the existing recursive stderr FILE lock and calls the owned
`fprintf` once with musl's format. It restores the stream orientation and
captured C/POSIX or C.UTF-8 encoding state on success and failure, and restores
errno only on formatting success. The formatter retains its temporary
80-byte buffer for an unbuffered stream, including partial-write behavior.
`psiginfo` forwards only `si_signo`, as musl does. These routines are not
async-signal-safe. Locale scope remains C, POSIX and C.UTF-8.

Run `./scripts/dev-x86_64.sh owned-signal-helpers [DYNAMIC_SYSROOT]` for the
existing dispatcher interface. Inside the pinned native environment,
`run_owned_signal_helpers.sh [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]`
also accepts a supplied static product. Both supplied products invoke neither
producer. Static-only builds the dynamic product that owns compilation;
no arguments builds both products; dynamic-only retains its four dynamic cells.
Supplied paths and complete product payloads are validated before any evidence
output or build. Invalid arguments exit 2; product and runtime failures exit 1.

The selected installed `crabc-cc-dynamic` compiles one ordinary application
object with installed headers, `--dynamic-pie -std=c11 -fno-builtin`, and its
implicit `-fPIE -fstack-protector-strong` policy. Previously the standalone path
compiled through the static-PIE driver, whose implicit stack-protection policy
was `-fno-stack-protector`; supplied dynamic runs already used strong protection.
All invocation forms now share the latter policy. There are no fixture macros
that select different oracle, candidate or linkage behavior. A separate header
dependency audit uses the installed compiler and exact compilation flags without
replacing the application object. `compile.json` records the actual driver
command and compiler, source, driver, manifest, installed-header and object hashes.

That immutable object links to pinned musl and the supplied owned static,
static-PIE, dynamic PIE and dynamic non-PIE products. Static and oracle scenarios
retain their ordinary execution; dynamic forms run through kernel and direct
interpreter entry in a disposable root. Each link passes the shared
`owned_posix_product_evidence.validate_link` audit for its exact product,
receipt, runtime inputs, trace and ELF contract. All eight scenarios retain and
compare raw status, stdout and stderr. The `signal-helpers.json` receipt records
the link identities, object identity, oracle hashes and all 48 comparisons when
static cells are selected (32 in dynamic-only mode). Input identities are
checked again after replay. Existing ELF weak-alias address/size checks remain.

`owned_dynamic_qualification.py` registers `signal-helpers` for each dynamic
product. The family collector separately owns replay across primary,
reproduction and extracted static products and the cross-product object check.
This runner supports those six static cells without asserting family closure.
Artifacts remain under the reported `.work/x86_64/tmp` evidence directory.

The eight isolated scenarios cover alias identity and restart flags; queued
signal delivery and disposition/mask transitions; invalid and reserved signal
rejection; successful and failed action-installation EINTR bookkeeping;
mask-syscall failure after an installed action; cancellation after helper use;
reporting bytes, null and empty prefixes, retained locale/orientation, and
EBADF; and nonblocking pipe partial-write EAGAIN behavior. The initial
regression passed all eight musl cases and failed the owned static link on
all eight missing providers. Pipe-capacity setup uses raw `SYS_fcntl` because
the current owned `fcntl(F_GETPIPE_SZ)` returns `EINVAL`; descriptor-control
completion is separate work. All helper behavior itself crosses installed C
boundaries. The fixture does not attempt asynchronous-handler reporting or
exhaustively qualify the underlying signal, FILE, or cancellation owners.

The private `libc-signal-legacy-aliases`, `libc-psignal`, and repaired
`libc-signal-sysv-helpers` gates also pass.
The initial private `libc-signal-sysv-helpers` run stopped at a stale header
judge expecting X/Open-800 legacy-XSI hiding. Its focused C/C++ declaration
matrix now requires the native x86 project's declarations to match pinned
musl in X/Open-800 as well as X/Open-700, GNU, BSD, and default-source modes.
Strict ANSI and POSIX-only profiles still reject those declarations. This
repairs the evidence owner. The private XSI runtime fixture also uses the
concrete handler pointer type instead of assuming GNU-only `sighandler_t`
visibility. Public headers and the separate architecture
branch retain their existing visibility contracts.

The private syscall-body judge accepts either an inline instruction or one
direct call to the existing private `raw_syscall::syscall4` leaf, whose body
must contain the instruction. The caller must still contain the named syscall
number; unrelated providers, unresolved symbols and dynamic linkage remain
rejected. This accounts for the compiler retaining the private leaf in the
single-feature build while inlining it in the combined-feature build.
