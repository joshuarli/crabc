# Installed POSIX message queues

The owned Linux/x86-64 runtime provides the complete `mqueue.h` callable set:
`mq_open`, `mq_close`, `mq_unlink`, `mq_getattr`, `mq_setattr`, `mq_send`,
`mq_receive`, `mq_timedsend`, `mq_timedreceive`, and `mq_notify`, including
`SIGEV_THREAD`. This is useful POSIX runtime functionality. The existing
standalone `mq_setattr` selection and frozen AArch64 implementation stay intact.

## Source and ABI ownership

The source oracle is musl 1.2.6, release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, archive SHA-256
`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
Its root `COPYRIGHT` supplies the MIT license for the `src/mq` files.

| Pinned source | Native owner |
| --- | --- |
| `src/mq/mq_open.c` | `owned_message_queues.rs::open_existing`, `open_create`, and the variadic `mq_open` entry |
| `src/mq/mq_unlink.c` | `kernel_name` and `mq_unlink` |
| `src/mq/mq_close.c` | Raw non-cancelling `mq_close` |
| `src/mq/mq_getattr.c`, `mq_setattr.c` | `mq_getattr` composes the existing `mq_setattr.rs` record/syscall owner |
| `src/mq/mq_send.c`, `mq_receive.c` | Non-timed entries supply null deadlines to timed entries |
| `src/mq/mq_timedsend.c`, `mq_timedreceive.c` | Native LP64 syscall cancellation entries |
| `src/mq/mq_notify.c::mq_notify`, `start`, `struct args` | `mq_notify`, `notify_start`, and `NotifyArguments` |

`syscall.rs` owns the native numbers 240–245. The existing cancellation,
pthread attribute/create/join/detach, signal-set/mask, socket, and semaphore
owners supply the notification worker's runtime boundaries. No dependency,
application worker registry, queue-size cap, or callback framework is added.
`mqd_t` is signed 32-bit; `mq_attr` is 64 bytes aligned to 8; native timespec is
16 bytes. `SignalEvent` records the exact 64-byte sigevent layout and callback,
value, and attribute-pointer offsets. The unused kernel-event payload bytes
are initialized to zero rather than copying unspecified source stack bytes;
Linux ignores them for the socket notification selector. The fixture independently asserts the
installed public C layouts. Legal two-argument `mq_open` calls do not consume
absent creation arguments.

Name translation removes exactly one optional leading slash and then preserves
kernel validation/error precedence. It does not introduce the named semaphore
namespace validator: a missing leading slash is accepted by the pinned source,
while an additional slash reaches Linux's `EACCES`. `mq_unlink` converts raw
`EPERM` to `EACCES`, as musl does. All other direct error results remain intact,
including `mq_close` returning `EINTR` without retry or the ordinary C close
wrapper's successful-EINTR conversion. Successful direct syscalls retain stale
errno. Linux owns priorities/FIFO order, queue bounds and attributes, umask,
descriptor flags, unlink-after-open lifetime, and process notification rules.

Both timed and non-timed send/receive forms are cancellation points, even if a
transfer is immediately possible. They share `pthread_cancel::syscall_cp` and
pass the caller's absolute `CLOCK_REALTIME` deadline directly. Linux/x86-64's
native 64-bit time ABI is present in the Linux 5.10 baseline; the source's
32-bit/time64 compatibility branches do not apply. The other queue entries do
not add cancellation points. They do not retry application-visible `EINTR` or
emulate queue transfers.

## Notification state and lifetime

Null, `SIGEV_NONE`, `SIGEV_SIGNAL`, and other kernel selectors go directly to
`mq_notify`. For `SIGEV_THREAD`, the source protocol is preserved:

1. Open one `AF_NETLINK`, raw, close-on-exec socket. Copy an optional complete
   pthread attribute image, or initialize it through the attribute owner, and
   force the worker initially joinable.
2. Initialize a caller-stack semaphore. Block application signals during
   pthread creation so the worker inherits the source mask, then restore the
   caller's mask. Any pthread creation failure closes the socket and returns
   the source's `EAGAIN`.
3. The worker copies the callback and value, registers the socket and static
   32-byte cookie with the kernel, writes the raw registration error, and posts
   the semaphore. It never reads caller-owned arguments after that post.
4. The caller disables cancellation around the semaphore handshake. A failed
   registration closes the socket and joins the still-joinable worker before
   restoring cancellation and publishing errno.
5. On successful registration the worker detaches itself, receives with
   `MSG_WAITALL|MSG_NOSIGNAL`, and closes its socket. Exactly a 32-byte cookie
   with final byte 1 invokes the copied callback. Removal/close cookies retire
   the worker without a callback.

The callback runs on that pthread with the source-inherited signal mask, can
rearm notification, and receives its copied `sigval`. The application owns
callback code, value pointees, supplied stack lifetime, and any synchronization
with asynchronous callback completion. Queue registration and worker retirement
remain separate events. Kernel notification ownership handles fork; no new
libc fork lock or cross-process registry is needed.

## Evidence and accounting

Run `./scripts/dev-x86_64.sh owned-message-queues`, optionally followed by a
materialized dynamic product path. The selected dynamic product is built or
validated first; its installed `crabc-cc-dynamic --dynamic-pie` driver compiles
the workload once using its installed headers and driver-owned code-generation
flags. `compile.json` records the actual driver command, product manifest,
translation inputs, and resulting object digest. That object is linked
unchanged to pinned musl, installed static ET_EXEC/static PIE, and dynamic
PIE/non-PIE; both dynamic forms execute through kernel and direct loader entry.
The optional product route runs musl plus the four dynamic entries. The
`message-queues` case is mandatory in the three-product qualification catalog.

Docker supplies a disposable private IPC namespace. Chroots isolate executable
payloads; POSIX queue syscalls need no mqueuefs mount or `/dev/mqueue` path in
those roots. No host IPC namespace, new mount authority, or host kernel setting
is used. Queue names contain process identity and a per-process sequence, and
fixtures unlink every created queue. A read-only inherited proc descriptor
allows exact blocked-syscall witnesses and task/descriptor retirement checks.
Builds, logs, object digest, and output comparisons remain under `.work`.

The fixture proves name and creation bounds, optional default attributes,
mode/umask, close-on-exec, attribute replacement, priority and equal-priority
FIFO ordering, message/receive-buffer bounds, zero-length messages, full/empty
errors, expired/future/invalid/64-bit deadlines, unlink/recreate and inherited
queue lifetime. For all four transfer entries it covers pending cancellation
before a ready transfer, cancellation of a witnessed blocked syscall, EINTR,
and SA_RESTART continuation.

Notification evidence covers signal payload/origin and one-shot behavior,
`SIGEV_NONE`, duplicate registration, caller event mutation after the worker
copy, custom attributes, inherited signal masks, self-detach, callback rearm,
registration failure joins, withdrawal and close without callback, child close
preserving parent notification, and pending caller cancellation. Actual task
and descriptor counts prove retirement. Child-local seccomp injects pthread
creation failure, `mq_unlink` EPERM, and `mq_close` EINTR to prove cleanup and
source error translation.

The nine additional providers are recorded in the owned feature archive and
removed from the deferred POSIX owner group. Derived callable inventory,
disposition, visibility, and x86 comparison views are regenerated; frozen
AArch64 inputs and capability/family completion states are unchanged. These
component results do not promote the entire POSIX family, dynamic product, or
public x86-64 support. They do not claim every resource exhaustion/kernel error
injection or invalid application callback/storage lifetime.
