# Owned pthread scheduling and default attributes

This Linux/x86-64 component implements useful POSIX runtime behavior and GNU
pthread compatibility machinery in the installed owned products. It does not
change AArch64 or the frozen private x86 scheduler rejection/default policy.

`./scripts/dev-x86_64.sh owned-pthread-scheduling` builds a single PIC object
against the project headers, then links that exact object to pinned musl 1.2.6,
owned static ET_EXEC, static PIE, dynamic PIE and dynamic non-PIE. Both dynamic
products run through kernel and direct loader entry. The runner also accepts an
already-built dynamic sysroot, as used by `owned_dynamic_qualification.py`'s
`pthread-scheduling` case. Generated objects, build metadata and per-entry
stdout remain under `.work/x86_64/tmp/owned-pthread-scheduling.*`.

## Source and ownership map

The compatibility oracle is musl 1.2.6, release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, release archive SHA-256
`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
The translated thread sources carry musl's MIT license in its `COPYRIGHT`.
No new production dependency or foreign implementation is introduced.

| Musl source | Owned Rust implementation |
| --- | --- |
| `src/thread/pthread_getschedparam.c::pthread_getschedparam` | `pthread_scheduling.rs::pthread_getschedparam` |
| `src/thread/pthread_setschedparam.c::pthread_setschedparam` | `pthread_scheduling.rs::pthread_setschedparam` |
| `src/thread/pthread_setschedprio.c::pthread_setschedprio` | `pthread_scheduling.rs::pthread_setschedprio` |
| `src/thread/pthread_setattr_default_np.c` get/set functions, `pthread_attr_init.c`, `default_attr.c` | `pthread_attr.rs` default snapshot and update functions |
| `src/thread/pthread_create.c::__pthread_create`, `start`, `start_c11` | `pthread_create_join.rs::create_selected_worker_with_attributes`, `worker_entry` |
| `src/signal/block.c::__block_app_sigs` | C11 startup application-mask image in `pthread_create_join.rs` |

Scheduler operations reuse `with_selected_pthread_signal_target`: registry
lookup pins the control mapping, drops the registry lock, and acquires the
target's kill lock before using its Linux TID. Retirement uses that same lock;
join/reaping withdraws the mapping and drains leases before unmapping it.
Scheduling reports `ESRCH` for retired joinable targets, whereas signal delivery
accepts a retired target. The scheduler adapter explicitly distinguishes a
skipped callback from a successful live syscall. Caller errno is unchanged.
As in musl, a successful getparam followed by a failed raw getscheduler stores
the negative raw result in the policy output while returning success.

The owned adapter blocks internal signals as well as application signals while
holding leases/locks, so asynchronous cancellation cannot abandon ownership.
This is an intentional safety refinement over musl's application-only mask.
Public Rust unsafe entry points require still-valid process-local handles and
properly initialized/readable or writable public objects; they do not validate
arbitrary stale pointers as safe handles.

## Creation and defaults

Explicit scheduler setup uses musl's atomic control states: 1 pending, 2 child
waiting, 0 admitted, 3 failed. The child waits with a private futex; the creator
sets the child's scheduler before admitting application code and wakes a
waiting child. Failed setup never calls the callback, publishes no public
handle, and waits for kernel task exit before reclaiming private resources.

The existing owned lifecycle keeps the kernel clear-child-tid destination in
`ThreadControl.child_tid`; musl redirects it to its stack control word on setup
failure. Both establish task exit before unmapping. The owned creator retains
its unpublished control via the creator-handoff flag, withdraws the registry
entry, drains outstanding leases, and reuses normal TLS/stack/control cleanup.
A caller-supplied stack remains owned and mapped by the caller. Allocation or
clone failure retains musl's `EAGAIN`; scheduler failure returns its own error.

GNU defaults accept only stack and guard sizes: every other record byte must
be zero. Updates are monotonic maxima, capped at 8 MiB stack and 1 MiB guard;
zero or smaller inputs do not decrease defaults. A packed atomic pair replaces
musl's pthread-create lock for coherent snapshots and avoids inheriting a held
default lock across fork. `pthread_attr_init`, null-attribute `pthread_create`
and `thrd_create` all consume the current pair. Initial values remain 128 KiB
and 8 KiB. C11 does not synthesize a scheduler request and preserves musl
`start_c11`'s blocked application signals; pthread start restores the caller's
inherited mask with SIGCANCEL unblocked.

## Evidence and remaining boundaries

The focused probe checks live main/worker scheduling, priority/policy errors,
retired-target precedence and untouched outputs, caller errno, explicit
SCHED_OTHER admission, 512 invalid-policy and 512 permission-denied creations
alternating joinable/detached state, unchanged output handles, no callbacks,
caller-stack retention, parent/child signal masks, inherited creation after
failed explicit setup, default validation/maxima/caps, live stack/guard sizes,
and C11 defaults/mask semantics.

Each failed request allocates a 1 MiB stack under a process-local 256 MiB
address-space bound, so retained failed-child mappings exhaust the bound and
turn the expected scheduler error into a failing `EAGAIN`. Permission failure
uses a process-local seccomp filter; the test does not acquire realtime
scheduling, change host policy, or require elevated scheduling privilege.

The focused matrix is component evidence. Final clean-revision three-product
qualification, pthread family completion, realtime privileged-success evidence
where required, allocator promotion, and public x86 support remain governed by
the owning execution plans. No AArch64 runs are performed by this component.
