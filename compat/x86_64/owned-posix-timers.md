# Owned POSIX timers

This useful POSIX runtime component implements `timer_create`, `timer_delete`,
`timer_gettime`, `timer_settime`, and `timer_getoverrun` in the installed native
Linux/x86-64 products. `SIGEV_NONE`, `SIGEV_SIGNAL`, `SIGEV_THREAD_ID`, null
notification defaults, and `SIGEV_THREAD` use the Linux 5.10 baseline. The frozen
private rejected-handle leaves and all AArch64 paths retain their selection and
contracts. This component does not close a parity family or promote x86 support.

`./scripts/dev-x86_64.sh owned-posix-timers` compiles an application object and
a distinct TLS-DSO object against the installed headers using
`crabc-cc-dynamic`. The application object links to pinned musl, owned static,
static PIE, dynamic PIE and dynamic non-PIE. Both dynamic forms run through
kernel and direct loader entry. The dynamic workload loads the TLS DSO at
callback-time, on the first live callback; the TLS DSO has no initial `DT_NEEDED`
edge from the application. Its exact object is shared with the musl
comparison, while the application object remains the one object in every
executable link.

The runner accepts `[--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]` for
the `posix-timers` qualification case. With neither product supplied, it builds
and checks both products. A supplied static product is used for both static
links; a supplied dynamic product supplies compilation and dynamic links. When
both are supplied, it starts no product producer and checks all six executable
forms. A dynamic product without a supplied static product retains the aggregate
dynamic-only boundary and skips static execution. It always retains products,
objects, compile/header audits, receipts, raw stdout/stderr/status, outputs and
failure observations, printing `evidence: PATH` on exit.

The four executable links retain the shared
`owned_posix_product_evidence.validate_link` identities: static, static PIE,
dynamic PIE and dynamic non-PIE. The callback-loaded DSO has a separate
shared-mode receipt audit in `owned_posix_timers_evidence.py`. It binds the TLS
source and object hashes, installed driver and manifest, installed-header trace,
DSO output and receipt hashes, exact shared-mode command and real link trace,
SONAME `libtimer-tls.so`, and `DT_NEEDED` exactly `libc.so`. Its receipt and the
four executable receipts keep `application_dsos` empty; passing the TLS DSO as
`--application-dso` would incorrectly create an initial dependency.

The shared workload also isolates pending creator cancellation in disposable
children, containing musl's resulting orphan timer. It requires cancellation
before output-handle publication, tests disabled cancellation and the
non-thread branch, and observes kernel-error errno in creator cleanup. A
reserved-signal interruption with no pending request proves that the worker
wait retries EINTR without changing callback errno.

The shared workload covers kernel timer creation, relative and absolute arms,
periodic overruns, delivery values, defaults, disarm/query/delete errors;
callback identity and copied attributes; ordinary return, `pthread_exit`,
self-cancellation, external cancellation at a syscall and in asynchronous mode,
then normal callback reuse, and deletion from the callback; cleanup handlers, repeated
three-pass TSD destruction, cancellation-state/type restoration, errno
continuity, initialized/TBSS TLS restoration, TSD-owned allocation reclamation and fresh timers
after fork. Candidate-only failure stress performs 32,768 rejected creations
under a 64-MiB address-space limit: even a single leaked 4-KiB mapping per call
would exceed the limit. Every installed entry mode runs that stress. Two native
loader tests check current/initial TLS reset without TCB/DTV replacement and
exact private import admission before relocation writes.

## Source and ownership map

The fixed oracle is musl 1.2.6, revision
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, archive SHA-256
`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
These source files carry musl's MIT license in its `COPYRIGHT`. No dependency
or foreign production implementation is added.

| Musl source | Owned implementation |
| --- | --- |
| `src/time/timer_create.c::timer_create`, `start`, `cleanup_fromsig`, `timer_handler` | `libc/src/c_abi/x86_64/owned_posix_timers.rs` |
| `src/time/timer_{delete,gettime,settime,getoverrun}.c` | Same module's five C exports and tagged-handle decoding |
| `src/env/__reset_tls.c::__reset_tls` | `static_tls.rs::reset_current_thread_images`, `dynamic_tls.rs` adapter, `ldso/src/x86_64_runtime_registry.rs::reset_current_tls`, `x86_64_runtime_tls_view.rs::reset_module_image` |
| `src/thread/pthread_key_create.c::__pthread_tsd_run_dtors` | Existing destructor iteration plus `pthread_tsd.rs::run_timer_callback_tsd_destructors` reopening the task's teardown guard |
| `timer_create.c::cleanup_fromsig` cancellation field resets | `pthread_cancel.rs::reset_timer_callback_cancellation` |
| `src/signal/block.c` and `src/thread/sem_{post,wait,timedwait}.c` | Timer mask and release/acquire two-way futex handshake, including creator cancellation |
| `src/signal/{sigwaitinfo,sigtimedwait}.c` | Cancellation-aware worker wait; raw EINTR retry before errno translation |

A `TimerWorker` mapping replaces musl's `pthread.timer_id` field. Its negative
opaque `timer_t` tags that mapping's address shifted right one bit. Nonnegative
handles remain kernel timer IDs. This is a private representation adaptation:
applications cannot inspect timer handles or use them after deletion. The
worker alone releases its timer mapping, after the creator has acknowledged
argument consumption or after timer deletion. The existing detached pthread
owner reclaims stack/TLS/control memory only after kernel clear-child-TID.
There is no extra fixed timer or worker ceiling.

The creator copies attributes, forces detached state and blocks application
signals plus SIGTIMER (32) around pthread creation. A release/acquire ready
handshake publishes the kernel ID/TID; its reverse acknowledgement retires the
creator's stack arguments. Musl's sem2 wait tests cancellation even when its
token is already available. The candidate delivers deferred creator
cancellation after acquiring the reverse acknowledgement, before publishing
the output handle; kernel creation errors have already reached errno for user
cleanup handlers. This intentionally postpones cleanup until the worker can
no longer reference the creator's stack. Notifications target this one retained task. An
assembly-owned setjmp continuation encloses each callback; its cleanup runs
TSD destructors, blocks application/SIGTIMER signals, resets cancellation and
ELF TLS, then longjmps to assembly. Rust never resumes a returns-twice frame.
Callback `pthread_exit` or cancellation reaches that cleanup before pthread
result publication, robust-owner death or actual thread retirement.

Deletion atomically marks the worker's timer ID and sends SIGTIMER. After any
active callback completes cleanup, the worker observes the mark, deletes the
kernel timer and exits. No fresh thread substitutes for notification reuse.
For nonnegative handles, `timer_delete` preserves musl's unusual raw negative
errno result without changing C errno; other timer wrappers translate errors.
Musl stores errno in its TCB. Since crabc stores it in ELF TLS, callback cleanup
saves/restores errno around image reset to preserve the source behavior. The
kernel sigevent buffer includes zeroed padding to the complete 64-byte UAPI
size rather than allowing a kernel copy beyond a shortened stack record.

The private versioned loader function
`__crabc_x86_64_reset_current_tls_v1: unsafe extern "C" fn() -> i32` owns dynamic
reset. After callback/TSD cleanup and signal blocking, it validates the current
registered TP under the loader mutation guard, validates all retained modules,
then restores relocated template/TBSS bytes without allocation or callbacks.
Initial and current DTV/TCB/token storage remain unchanged. A private invariant
failure returns `-EINVAL`; libc terminates with status 127 rather than invoking
a callback with incomplete reset. The exact signature and preconditions live
in `loader-libc-tls-runtime-v1.toml` and its validator. Production C allocator
thread teardown runs through the existing TSD phase before its TLS is reset.

## Recorded source difference: creation failure startup race

Musl's `timer_create.c` writes `td->cancel = 1` when the kernel rejects timer
creation, posts `sem1`, and waits for `sem2`. Its worker enters `sem_wait(sem1)`;
`sem_wait.c` delegates to `sem_timedwait.c`, whose first operation is
`pthread_testcancel()`. If the parent publishes failure before that first
cancellation check, the worker exits without acknowledging `sem2`. The creator
then remains in a futex wait after the worker has disappeared.

The runner isolates this in fresh processes using `failure-once`: one invalid
clock, one SIGEV_THREAD creation, no earlier timer, key or callback state. It
records the stopped caller's `/proc/PID/task` status, wait channel and syscall
when the race occurs, then kills and reaps only its own child. The original
shared workload also reproduced the hang before candidate execution. These
are retained oracle observations, not a weakened success expectation.

The candidate uses a separate negative creation-result ID after the ready
handshake, never a pending pthread-cancellation request. The worker always
acknowledges the arguments before returning on failure. This deliberately
fixes that source race while preserving positive error translation, detached
reclamation, the two-way lifetime handshake and every valid callback lifecycle.
The shared normal/exit/cancel workload remains a direct musl comparison;
failure stress requires bounded successful reclamation only from the candidate.

Development verification for this component passed with retained evidence at
`.work/x86_64/tmp/owned-posix-timers.5ONJge`: the complete six-entry workload,
failure stress, and both native loader checks. The first fresh oracle process
had one task remaining in syscall 202, `FUTEX_WAIT_PRIVATE`, matching the
source failure handshake. The missing-provider, TLS-errno, creator-cancellation and interrupted-wait
errno regressions were observed before their fixes. The wire, product-contract,
qualification-receipt and dispatcher checks also passed (41 Python tests).
Full three-product receipt production and family qualification remain separate
integration gates; this development run makes no promotion claim.

The aggregate runner accepts only physical product directories inside the
checkout’s `.work` tree. A supplied extracted dynamic product drives compilation
of both roles; the oracle and candidate links reuse the application object, and
the oracle and callback-loaded candidate DSO reuse the TLS object. Ordinary
static output is compared only to ordinary musl output; kernel/direct dynamic
output is compared only to dynamic musl output. Failure reclamation and the
isolated `failure-once` race retain raw observations without becoming musl byte
comparisons.
`timer_create` is an owned-static additive callable; the four other timer entry
points replace their frozen default-static providers in the owned profile.
