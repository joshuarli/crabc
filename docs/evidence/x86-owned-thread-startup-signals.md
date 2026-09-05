# Application signals during native thread startup

An application signal sent immediately after `pthread_create` must not enter
its new worker before the runtime can recognize that worker. The owned
`pthread_create_join.rs` creation path now blocks application signals before
list publication and clone. `worker_entry` publishes its Linux TID and FS+32
cancellation-state pointer before restoring the inherited pthread mask.
SIGCANCEL is cleared in that restored mask; C11 retains its application-signal
block. Parent completion restores the exact saved mask on success and failure.
The frozen private lifecycle retains its cancellation-only startup policy.

## Failure and source contract

The pinned libc-test `regression/raise-race.c` queues signals to a new pthread;
its handler forks while that worker repeatedly calls `raise`. The failing
installed product reported 100 `fork` failures with `EAGAIN` followed by 100
`ECHILD` waits. The kernel was not refusing process creation. Default pthread
creation blocked only SIGCANCEL, allowing an application handler to interrupt
startup while `worker_tid` was still its unpublished sentinel. The fork
boundary correctly rejected that incomplete current-worker identity.

The isolated regression pins creator and worker to one allowed CPU, sends a
signal immediately after each creation, and forks one child from its handler.
It reaps that child before the next iteration, keeping at most one outstanding
child. Before the fix, all 32 candidate attempts returned `EAGAIN`; musl passed
all 32. Calling raw `SYS_fork` from the same candidate handler also passed all
32. Both sides recorded UID/EUID zero and unlimited `RLIMIT_NPROC`. Direct
worker fork and self-raised signals after callback entry already passed.
These observations distinguish startup admission from process/resource limits.

The ordering follows MIT-licensed musl 1.2.6 release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`,
`src/thread/pthread_create.c:341-355,380-381` (block, copy mask, clone, parent
restore) and `:194-215` (`start`/`start_c11`). This runtime additionally blocks
SIGCANCEL until its own cancellation cache is published. The existing explicit
scheduler/C11 setup interval retains its all-signal block. No fork admission
check, loader ownership rule, FILE lock, or cancellation implementation is
weakened to admit an incomplete worker.

## Focused proof

`compat/x86_64/run_owned_signal_handler_fork.sh` compiles the isolated probe
once through the installed dynamic driver and links those unchanged bytes
against pinned musl and owned static/static-PIE/dynamic PIE/non-PIE products.
Both kernel and direct-interpreter dynamic entries run the same cases. The
probe checks early and ordinary handler entry, raw-kernel comparison, default
and explicit pthread masks, C11 masks, and exact creator-mask restoration after
a seccomp-injected clone failure. Mask cases first create and join a worker
to complete musl's one-time internal-signal initialization before installing
the raw mask being measured. The fault filter affects only the dedicated
child-creation test process; it is not a runtime fallback or policy feature.

The runner also acquires and verifies the existing pinned libc-test source
owner, stages unchanged `raise-race.c`, `print.c`, `test.h`, and license files,
and compiles its two required objects once. Those same objects run against
musl and every candidate link/entry mode. The source revision remains
`68edb8bd73dab8147ee54c8bec638f4d2b3cff37` from `compat/upstreams.toml`.
Source/object hashes, binaries, stdout/stderr, and status records remain below
the worktree's `.work` directory. A supplied dynamic product selects only its
four entries. This runner does not execute or claim the full libc-test corpus.

The focused matrix passed pinned musl and all six owned link/entry cells.
The supplied-product rerun passed all four dynamic entries. Existing
`run_owned_pthread_scheduling.sh` and `run_owned_pthread_join_cancel.sh` also
passed against that same dynamic product, covering scheduler failure
reclamation, C11/default attributes, and cancellation/join transitions.
