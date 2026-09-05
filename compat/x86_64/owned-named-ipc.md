# Installed named POSIX IPC

The owned x86-64 runtime provides `sem_open`, `sem_close`, `sem_unlink`,
`shm_open`, and `shm_unlink`. Named semaphore storage composes with the existing
`posix_semaphore` value/waiter/futex protocol. The standalone unnamed archive
and frozen AArch64 boundary keep their existing scope.

## Source and ownership

The oracle is musl 1.2.6, release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, release archive SHA-256
`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
The relevant files carry musl's MIT license in its root `COPYRIGHT`.

| Pinned source | Owned implementation |
| --- | --- |
| `src/mman/shm_open.c::__shm_mapname` | `owned_named_ipc.rs::map_name` |
| `src/mman/shm_open.c::shm_open`, `shm_unlink` | Corresponding C entries in `owned_named_ipc.rs` |
| `src/thread/sem_unlink.c::sem_unlink` | Shared namespace unlink entry |
| `src/thread/sem_open.c::sem_open` | C variadic entry, `reserve_slot`, `acquire_mapping`, and `open_named_semaphore` |
| `src/thread/sem_open.c::sem_close` | Reference decrement and final mapping release |
| `src/thread/__lock.c`, `__unlock.c` | Registry congestion counter and private futex lock |
| `src/process/fork.c::__sem_open_lockptr` integration | `pthread_atfork.rs` named IPC prepare/parent/child calls |

`stat_compat.rs::fstat_inode` keeps the kernel stat layout in its existing
owner. The registry uses the existing internal allocator. No new dependency,
foreign runtime, or persistent record format is introduced.

Both object kinds resolve to `/dev/shm/name`, without a `sem.` prefix. Leading
slashes are stripped. Empty names, dot/dotdot, and interior slashes return
`EINVAL`; an interior slash takes precedence over an overlong component.
Otherwise names longer than 255 bytes return `ENAMETOOLONG`. The kernel owns
permissions, umask, link/unlink visibility, and backing-file lifetime.
`shm_open` adds `O_NOFOLLOW`, `O_CLOEXEC`, and `O_NONBLOCK` to the supplied flags.
`sem_open` uses those flags plus read/write access and recognizes only
`O_CREAT|O_EXCL` from its input. Existing objects ignore the creation value;
exclusive existing objects fail with `EEXIST` before value validation.

The source-shaped semaphore registry allocates 256 entries lazily, matching
musl's `SEM_NSEMS_MAX` and the installed `limits.h`. An open reserves capacity
before creating a file. Even an additional reference to an already mapped
inode requires a free reservation slot; saturation returns `EMFILE`. Completed
opens deduplicate by inode and return the same pointer with an additional
reference. The final `sem_close` removes the registry entry and unmaps its
32-byte semaphore mapping. Unlinking a name leaves live mappings valid;
recreation yields a distinct inode and semaphore value.

Creation initializes a temporary file and atomically links it to the requested
name. Temporary names use the realtime nanosecond field, as in the source;
collisions retry exclusive creation. The semaphore file uses mode masked by
`0666` and then umask. There is no allocation after publication. Failed opens
release reservations and failed creation removes temporary files. The Rust
translation initializes the five unspecified reserved semaphore words to zero
rather than copying unspecified C stack bytes. The three defined words retain
the exact shared semaphore representation. It also bounds an unmatched
`sem_close` lookup rather than reading outside the table; callers still must
supply a live named handle and coordinate final close with users/waiters.

Open operations disable cancellation around descriptor/mapping work.
`sem_close` and unlink operations do not create cancellation points. Existing
`sem_wait`/`sem_timedwait` retain their cancellation and shared futex behavior.
Fork acquires the registry lock before stdio/syslog/timezone and worker-list
locks. Completion follows the source array in forward order, before
stdio/syslog/timezone. Parent completion releases it; child completion preserves the inherited
table, references, mappings, and source reservations, resetting only the copied
lock before callbacks. No vanished-thread reference reconstruction is added.

## Evidence

Run `./scripts/dev-x86_64.sh owned-named-ipc`. One PIC object built against
project headers links unchanged to pinned musl, owned static ET_EXEC, static
PIE, and dynamic PIE/non-PIE. Both dynamic forms run through kernel and direct
loader entry. Each process uses a private chroot `/dev/shm` directory below the
checkout's ignored work tree; the harness does not modify host IPC names or
mount a filesystem. A read-only inherited proc directory descriptor permits an
exact shared-futex blocked-wait witness. An optional materialized dynamic
product argument runs the oracle and four dynamic entries, and `named-ipc` is
a required case in the three-product qualification contract.

The fixture covers namespace/error precedence, maximum names, symlink refusal,
mode/umask and descriptor flags, shared namespace and hardlink aliases,
reference lifetime, final unmapping, unlink/recreate, shared-memory-backed
semaphores, thread/process creator races, inherited and contended fork,
256-entry saturation/reuse, repeated failed opens, pending deferred
cancellation, and witnessed blocked-wait cancellation. A child-local seccomp
filter rejects mapping 300 times to verify failed creation releases every
reservation without publishing a name. The runner checks all private IPC
directories are empty afterward, including temporary-file cleanup. Logs,
object digest, outputs, and products remain below `.work/x86_64/tmp`.

The focused component evidence does not qualify the entire dynamic product or
expand public x86-64 support. It does not claim every kernel/filesystem error
injection, asynchronous cancellation, invalid semaphore lifetime, or unrelated
POSIX IPC facility.
