# Owned POSIX signal evidence

The `signal-full` dynamic case supplies the residual installed-product signal
workload for the frozen 34-name `process.signal` capability. It combines with
the existing cases named in `owned-posix-signals.toml`; it does not replace
their fixtures or claim that one residual probe proves all signal behavior.
This is core Unix runtime and bounded C ABI evidence. It leaves AArch64,
private static profiles, family promotion, and public platform support unchanged.

## Exact evidence owners

`owned-posix-signals.toml` partitions all 34 frozen spellings into these primary
owners. Its validator rejects omissions, duplicate spellings, and unregistered
reused cases. The family coordinator must run each reused case for each required
product; naming it here does not manufacture an execution receipt.

| Owner | Exact primary spellings | Behavior |
| --- | --- | --- |
| `sets` | `__libc_current_sigrtmax`, `__libc_current_sigrtmin`, `sigaddset`, `sigandset`, `sigdelset`, `sigemptyset`, `sigfillset`, `sigisemptyset`, `sigismember`, `sigorset` | Realtime limits 35/64, invalid and reserved signal ordering, one-word operations with untouched public tails, and operand/destination aliasing. |
| `actions-masks` | `raise`, `sigaction`, `siginterrupt`, `sigpending`, `sigprocmask`, `signal` | Disposition replacement, restart flags, mask preservation, pending/handled delivery, unmaskable bits, and null-set/invalid-how ordering. |
| `queue-delivery` | `kill`, `killpg`, `sigqueue` | FIFO realtime payloads, realtime priority, sender identity, invalid signals/groups, and delivery to a contained child process group. |
| `suspend-delivery` | `sigpause`, `sigsuspend` | Atomically unblocking a pending signal and restoring the calling mask; invalid/reserved `sigpause` inputs. |
| `alternate-stack` | `sigaltstack` | Query, install, actual handler entry, in-handler disable rejection, invalid flags, disable, and size-before-flags error ordering. |
| `signalfd` | `signalfd` | Descriptor flags, empty nonblocking reads, exact 128-byte queued records, too-short read, in-place mask replacement, preservation after invalid flags, and descriptor-type errors. |
| Existing `signal-helpers` | `__sysv_signal`, `bsd_signal`, `psiginfo`, `psignal`, `sighold`, `sigignore`, `sigrelse`, `sigset` | Alias identity, action/mask transactions, interruption bookkeeping, cancellation, reporting bytes, FILE orientation/locale, partial writes and errors. |
| Existing `io-cancellation` | `sigtimedwait`, `sigwait`, `sigwaitinfo` | Pending/blocked/disabled cancellation, queued success, EINTR retry without errno mutation, output preservation and cleanup state. |

The existing `pthread-signal` and `posix-timers` cases remain additional positive
evidence for worker and timer delivery. Signal operations used by spawn, process,
PTY, fcntl, and other cases remain supporting evidence as described in
`owned-posix-runtime.md`; they do not replace this exact spelling partition.

Three additional residual subcases isolate owned composition regressions:
`sigpause-cancellation`, `sigsuspend-cancellation`, and
`interrupt-bookkeeping`. The suspend cases synchronize at the actual blocked
syscall using the existing read-only `/proc` descriptor witness, and also test
pending and disabled cancellation without a scheduling delay. The action case
forces only futex to return EINTR after changing SA_RESTART. The child process
used for `killpg` first creates its own session, blocks its delivery signal,
and acknowledges readiness over a pipe; its alarm only bounds harness failure.
All ordinary scenarios run in separate processes with an explicitly empty
initial application mask.

## Source and selected behavior

The oracle is musl 1.2.6, release revision
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, under its MIT license. The release
archive SHA-256 is
`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`;
`compat/upstreams.toml` records the pin. No new dependency is introduced.

| Musl source | Native implementation |
| --- | --- |
| `src/signal/sigpause.c` | `libc/src/c_abi/x86_64/owned_signal_pause.rs` composes the existing mask, set mutation, and cancellation-aware suspend owners. |
| `src/signal/siginterrupt.c` | `libc/src/c_abi/x86_64/owned_siginterrupt.rs` composes both calls through the existing `signal_control` action transaction. |
| `src/signal/sigaltstack.c`, `src/conf/sysconf.c` signal-stack selectors | `signal_altstack.rs` uses the owned configuration module's shared minimum; the private static branch keeps its fixed 2048-byte profile. |
| `src/signal/sigaction.c`, `signal.c`, `sigemptyset.c`, `sigismember.c`, `sigprocmask.c`; `src/thread/pthread_sigmask.c` | Existing `signal_foundation.rs` and `signal_control.rs`. |
| `src/signal/sigaddset.c`, `sigdelset.c`, `sigfillset.c`, `sigandset.c`, `sigorset.c`, `sigisemptyset.c`, `sigrtmin.c`, `sigrtmax.c` | Existing `signal_set_mutation.rs`, `signal_set_binary.rs`, `signal_set_isempty.rs`, and `signal_realtime_{min,max}.rs`. |
| `src/signal/kill.c`, `killpg.c`, `raise.c`, `sigqueue.c`, `sigtimedwait.c`, `sigwaitinfo.c`, `sigwait.c` | Existing `signal_execution.rs`. |
| `src/signal/sigpending.c`, `sigsuspend.c`; `src/linux/signalfd.c` | Existing `signal_pending.rs`, `readiness_waits.rs`, and `signal_fd.rs`. |

Musl's `sigpause` reaches a cancellation point through `sigsuspend`. Its
`siginterrupt` calls `sigaction` twice, so changing restart behavior also
updates the runtime's sticky EINTR-validity flag and uses SIGABRT serialization.
Owned selection now follows those compositions. The unchanged private adapters
remain selected outside `x86-owned-static-runtime`.

The pre-existing Rust adapters return a defined error if the initial local
mask/action query is rejected. Musl ignores that failed query and may read an
indeterminate local record. The owned adapters retain the Rust boundary's early
error, rather than reproducing undefined source behavior. `signalfd` retains the
Linux 5.10 direct `signalfd4` path without musl's pre-baseline ENOSYS fallback.

The isolated first differential passed all ten musl scenarios and failed all
four dynamic entry modes in exactly three places: `sigpause` returned to user
code before pending/blocked cancellation; a `siginterrupt` change left a forced
futex EINTR turning into ETIMEDOUT; and a 2048-byte alternate stack succeeded
where musl returned ENOMEM, with SS_ONSTACK also exposing size-validation order.
The retained subcases are the regressions for those owned corrections. All ten
scenarios subsequently match musl in all six installed entry cells. The three
corrected entries are owned-static replacement callables; their frozen default
providers and public spelling roster remain unchanged.

## Runner and qualification boundary

Run `./scripts/dev-x86_64.sh owned-posix-signals [DYNAMIC_SYSROOT]`. Without an
argument, it builds installed static and dynamic products and runs ordinary
static, static PIE, dynamic PIE and dynamic non-PIE; both dynamic forms use
kernel and direct interpreter entry. A supplied installed/extracted dynamic
product drives compilation and all four dynamic cells. Its physical directory
must be under this checkout's `.work` tree. The family coordinator separately
owns second static builds and static package extraction.

`owned_posix_signals.py` compiles one workload object with the selected installed
`crabc-cc-dynamic` and links that exact object to musl and every candidate.
A separate dependency audit uses the same pinned compiler, clean environment,
mode flags and installed include root; every header must come from that product,
except the exact workload source and existing proc-witness header. The probe
uses installed public declarations without replacement signal records.

Reference and candidate run in a disposable root. Each subcase retains raw
process return code, stdout, stderr, and explicit errno observations. All three
raw artifacts participate in comparison; neither a successful exit alone nor
a symbol-table result can pass. The runner retains object/header identities,
link input/output receipts, ELF inspection, source identity and oracle hashes
under its printed `evidence:` path. Reused cases are recorded as requirements,
not as results produced by this runner. The installed/second/extracted dynamic
matrix remains owned by `owned_dynamic_qualification.py`.
