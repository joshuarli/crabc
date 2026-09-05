# Installed pthread CPU-clock IDs

`pthread_getcpuclockid` is a bounded Linux/x86-64 pthread compatibility
boundary in the installed owned products. It does not establish general
pthread/TLS or x86 platform support.

`./scripts/dev-x86_64.sh owned-pthread-cpuclock` runs one project-header C
consumer through pinned musl 1.2.6, installed static ET_EXEC, static PIE,
dynamic PIE, and dynamic non-PIE products. Dynamic entries run through both
the kernel interpreter and the owned loader directly. The runner accepts an
already-built dynamic sysroot for focused reuse. Its mutable evidence remains
under `.work/x86_64/tmp/owned-pthread-cpuclock.*`.

## Source and ownership map

The behavior oracle is musl 1.2.6 release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, release archive SHA-256
`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
The source carries musl's MIT license recorded in `COPYRIGHT`.

| Musl source | Owned Rust implementation |
| --- | --- |
| `src/thread/pthread_getcpuclockid.c::pthread_getcpuclockid` | `pthread_cpuclock.rs::pthread_getcpuclockid` |
| `src/thread/pthread_create.c::__pthread_create` target-TID publication | `pthread_create_join.rs::selected_worker_linux_thread_id` and the selected-worker registry |

Musl reads `t->tid` from its full pthread record and encodes Linux's
per-thread clock as `(~tid << 3) | 6`. The owned runtime never dereferences a
public `pthread_t`. For the bootstrapped initial task it requires the current
`%fs:0` value plus the initial-task TID discriminator, then reads
`gettid=186`. For a selected worker it searches the registry under its
lifecycle lock and copies only the positive parent-written
`CLONE_PARENT_SETTID` child-TID before releasing that lock.

The copied worker TID is a snapshot. The caller must keep the target executing
and must not race completion, `pthread_join`, `pthread_detach`, or later
reaping that can clear the child-TID word, withdraw the mapping, or permit
Linux TID reuse. The consumer makes that condition concrete: its worker
publishes readiness, spins until the parent releases it, and only then exits.
It checks worker-self and parent-to-live-worker IDs, their exact 32-bit
encoding, `clock_gettime` acceptance, and separate caller-errno preservation.

Null, foreign, finished, and withdrawn handles fail closed with positive
`ESRCH` before the output slot is observed. This is candidate behavior outside
musl's valid-TCB dereference precondition. The component excludes arbitrary
foreign handles, completed-target and lifecycle races, a public TCB or
all-thread list, `clock_getcpuclockid`, general clock APIs, affinity or
scheduling attributes, cancellation, synchronization, TSS, dynamic TLS
policy, CRT/sysroot completion, pthread-family completion, promotion, and
public x86 support.
