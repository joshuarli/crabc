# Private x86-64 owned static sysroot artifact

`./scripts/dev-x86_64.sh owned-static-sysroot` proves one bounded installed
Linux/x86-64 static TLS, allocator, and POSIX consumers in ordinary `ET_EXEC`
and static-PIE `ET_DYN` modes, then repeats them from one extracted package. It is a
verified prerequisite inside the still-planned `sysroot.static-tls` family and
the still-planned `sysroot.owned-artifact` family, not either family’s
completion and not public
x86-64 support.

## Installed contract

`scripts/build_x86_64_owned_sysroot.py` uses the pinned
`nightly-2026-07-24` Rust toolchain in a sealed build environment and installs
only regular files:

```text
usr/include/
bin/crabc-cc
usr/lib/{crt1.o,Scrt1.o,rcrt1.o,crti.o,crtn.o}
usr/lib/libc.a
usr/lib/libcrabc-builtins.a
share/crabc/{manifest,headers,crt,libc-static,libcrabc-builtins,build}*.json
```

The CRT objects come from `crt/build_x86_64.py`. Cargo’s intermediate
`libc.a` is not installed directly: the builder classifies every member,
extracts crabc `c.*.rcgu.o` objects plus the accepted C allocator object, and excludes stock Rust core,
compiler-builtins, and native compiler-rt members before deterministic
re-archiving. `builtins/build_x86_64.py` supplies the separate one-member
Rust-only helper archive. The manifest hash-binds the complete installed
regular-file payload; both the installed driver and private package helper
reject an unlisted regular file, symlink, non-regular entry, missing payload,
or hash mismatch before compilation, packaging, or extraction. It records the
excluded inputs and unselected scope. Final publication is atomic, and two
clean builds in distinct roots must have identical regular-file bytes.

The `x86-owned-static-runtime` composition includes the Cargo-locked
`libmimalloc-sys` 0.1.49 backend, not the incomplete native Rust port. The
builder verifies its single object against the dependency producer archive,
binds the crate checksum and compiler identity, and records source/header
hashes from the actual C compilation. `-nostdinc` permits only project headers
and that pinned backend's own sources. Owned `syscall`, `prctl`, `realpath`,
and `abort` providers remove the earlier musl support-object tail. This is
an accepted C dependency, not full target-runtime Rust purity.

`bin/crabc-cc` is an installed, sealed static-driver seed. Its deterministic
`--print-link-plan -static` contract selects `crt1.o` and `ET_EXEC`; its
`--print-link-plan -static-pie` contract selects `rcrt1.o` and `ET_DYN`. Both
plans name only the installed headers, `crti.o`, `crtn.o`, `libc.a`, and
`libcrabc-builtins.a` around explicitly admitted application objects. It
rejects ambient header/CRT/library search, linker injection, libgcc,
compiler-rt, loader, and dynamic-mode flags before translating or linking.
Receipt-bearing links accept only caller-owned object inputs, reserve their
JSON/map/trace sidecars before linking, and reject output aliases of those
sidecars or any installed-tree path. The source translator remains a
fixed-image development-environment tool; it is not a target runtime input.

The private package helper creates a normalized `tar.xz` only from that
manifest-bound regular-file payload. It rejects archive/extraction paths through existing
symlinks, bounds untrusted extraction to 4096 members, 128 MiB per regular
member, and 512 MiB aggregate regular payload, and validates an archive into a
private staging directory before Linux `renameat2(RENAME_NOREPLACE)` atomically
publishes extraction. An invalid archive or competing destination therefore
leaves no partial or replaced output tree.

## Consumer and rejection evidence

`compat/x86_64/run_owned_static_sysroot.sh` first runs the pinned musl 1.2.6
behavior reference. It separately records `-nostdinc -isystem
<installed>/usr/include` dependencies for all five source files, where
only each named source and that installed header tree are admitted. A forged
host-header record must fail. The installed driver then compiles, links, and
executes those objects in each static mode through the same installed-tree
boundary.

The driver's link receipt, map, and trace establish the exact allowlist:
installed `crt1.o` or `rcrt1.o`, `crti.o`, `crtn.o`, `libc.a`,
`libcrabc-builtins.a`, and the three caller-owned consumer objects.
`compat/x86_64/owned_static_sysroot_builtins.c` forces an
undefined `__udivti3`; omitting the installed helper archive must fail at that
symbol, while the successful linker trace must attribute its member to the
owned archive. Forged trace entries for an ambient CRT, pinned-musl libc,
libgcc/compiler runtime, and loader must each fail.

Both executed images preserve the existing `PIMBCAF` preinit/init/main,
selected pthread, LIFO ordinary-exit, and fini observation over initialized,
TBSS, and 4096-byte-aligned Variant-II static TLS. Their ELF images have GNU
RELRO, one non-executable stack segment, exactly one `PT_TLS`, no interpreter
or dynamic dependency, no unresolved symbol, and no dynamic TLS relocation.
The static PIE additionally retains only relative dynamic relocations and no
unrelaxed initial-TLS access. Mutating `PT_TLS.p_filesz` must still fail closed
with status 127. Two normalized packages are byte-identical, and a safely
extracted copy must reproduce the same per-mode output, receipt, map, and
trace evidence.

The static TLS owner explicitly reserves the x86 compiler guard at `%fs:40`,
initializes it from `AT_RANDOM` before preinit, and copies it into each worker.
The consumer checks the pinned musl guard transformation and executes real
compiler-protected code in the initial thread and worker. A child corrupts
only its own guard and must fault through the owned failure handler; core
dumps are disabled for this negative test.

Each TLS job also links `libc_pthread_tls_aggregate_probe.c` through the installed
CRT in both modes and the extracted package. Two workers compose errno isolation,
mutex/condition handoff, rwlock exclusion, once publication, and clear-before-call
TSD destructors before join. This reuses the existing differential body without
its private startup object. The separate lifecycle consumer below covers
attributes, C11 adapters, explicit and private-condition deferred cancellation,
and selected-runtime fork repair. Allocator-wide fork recovery and dynamic
TLS remain separate qualification boundaries.

The existing `libc_allocator_basic_runtime_v1_probe.c` also runs through both
installed modes and the extracted package: allocation/reallocation/alignment
and failure behavior, worker teardown, allocation across a joined-worker fork,
and allocation during ordinary exit. It additionally exercises the support
providers' variadic ABI, pathname/symlink, and SIGABRT behavior. The same
sealed link-receipt and reproducibility checks apply. This does not qualify
fork while other threads are allocating or concurrent signal-disposition
mutation; those remain runtime integration obligations.

`owned_static_posix_probe.c` adds environment ownership/mutation, a real
fork/`execve` environment round trip, and pipe/vector-I/O/readiness/descriptor
lifecycle through that same installed archive. It uses ordinary C interfaces,
not fixture-local startup or syscall substitutes. Its musl reference, both
static modes, and extracted copies share the same source. PATH search,
spawn/vfork, concurrent environment mutation, and cancellation are not proved
by this consumer.

`owned_static_stdio_probe.c` exercises the owned descriptor-stream engine in
`owned_static_stdio.rs`: simultaneous dynamic streams, buffered and terminal
output, positioning/pushback, errors, append/cloexec, recursive stream locking
across threads, unlocked byte/block I/O, and bounded formatting/scanning. Both installed
modes and extracted copies must match pinned musl and flush an unclosed
dynamic stream at ordinary exit. The final image must select the strong
`__stdio_exit` hook. Scratch files are private to each consumer run.
Reopen preserves the FILE/buffer identity and tests descriptor replacement and
failure retirement; allocated line input covers growth, embedded NULs, EOF,
and errors. Each stdio job also links `owned_stdio_backends_probe.c`: 29 binary
records compare fixed/growing memory streams, cookie callbacks, short/error
writes, descriptor buffering, and formatter error state with pinned musl.
The separately receipted binary must flush its unclosed cookie stream at
ordinary exit. `owned_stdio_process_probe.c` separately exercises `popen`,
`pclose`, and `system`: read/write streams, prior-process descriptor closure,
CLOEXEC and same-descriptor dup2, worker-thread spawn, signal status/restoration,
interrupted wait, and exec/pipe failure cleanup without leaked descriptors or
zombies. Its child shell and scratch are private to each run.
`owned_wide_stdio_probe.c` adds stream orientation and captured locale,
multibyte decoding and pushback, callback locale restoration, worker isolation,
and growing wide-memory streams with overflow/ownership checks.
`owned_stdio_extensions_probe.c` checks active buffer direction, borrowed
read/line views, FILE-owned line allocation, flush/purge/error transitions,
setbuf-family configuration, and unlocked compatibility entries against musl.
All reuse the same FILE owner and receive separate installed link evidence.
Ordinary FILE descriptor I/O remains non-canceling, as in pinned musl. Explicit
FILE locks belong to a current-task intrusive list; cleanup handlers may release
them, while non-final task retirement marks remaining locks orphaned before
clearing the FS+32 cancellation-state pointer. Allocator-wide fork recovery
remains unqualified.

`owned_static_printf_probe.c` additionally covers positional integer/string/
count/pointer/errno/hex-float formatting and FILE, descriptor, allocated, and
caller-buffer destinations. Its 71-record binary matrix must match pinned
musl in both modes and extracted copies; defined invalid-format checks remain
candidate-specific. Each formatting job also links a separately receipted
`owned_static_printf_float_probe.c` binary: 1,920 records compare decimal and
hex binary64/binary80 output, errno, floating exceptions, and all four rounding
modes with pinned musl. It covers spilled/positional arguments and FILE,
descriptor, allocated, and caller-buffer destinations with private scratch.
Each formatting job also runs a separately receipted
`owned_static_scanf_probe.c` binary: 940 fixed records compare byte grammar,
scansets, widths, suppression, positional arguments, integer and binary32/64/80
conversion, errno, fenv, and stream lookahead/EOF/error state. Allocation checks
exercise `%m` growth, cleanup, partial failure, and ENOMEM; each process owns
its scratch and restores its resource limit. `owned_wide_format_probe.c`
compares byte/wide conversions and wide printf/scanf grammar, including
standard streams, forwarded va_lists, long strings, and allocated results.
The digest-checked wide parser source and owned FILE callbacks are mapped in
`owned_wide_format.rs`; there is no foreign FILE representation. Both wide
probes run unchanged against pinned musl and all four installed product arms.
The 24 bounded jobs now include separately receipted syscall-cancellation consumers.

Each TLS job also runs `owned_pthread_lifecycle_consumer.c` through a separate
installed link: initialized attributes, private guarded and caller-owned
stacks, 96 simultaneously live workers, concurrent detached creator/reaper
handoffs, typed C11 results, cleanup/TSD teardown at explicit and blocked
private-condition deferred cancellation points, and atfork order. Condition
cancellation repairs the waiter and relocks its mutex before user cleanup;
owned waits use musl's automatic waiter and MASKED syscall boundary. The
frozen archive keeps its separate mapped-waiter wake-lease protocol.
Fork repairs the selected pthread/TSD, stdio, timezone, and shared process-lock
state; a worker becomes the child's adopted main thread. Logical task exit is
serialized separately from kernel clear-child-TID: the final live task owns
ordinary exit, including when the adopted main returns while a child worker
remains alive. Controls remain owned until creator handoff and kernel
clear-child-TID both complete. The same consumer proves normal robust-mutex
owner death, `EOWNERDEAD` recovery with `pthread_mutex_consistent`,
`ENOTRECOVERABLE` after an unrecovered unlock, and process-shared owner death
across `fork`. The separate mutex gate covers recursive/error-checking and
priority-inheritance private/process-shared robust owner death. Explicit
scheduling, remaining syscall cancellation points, priority-protect mutexes,
allocator-wide fork recovery, and dynamic TLS lifetime remain open.

The focused `./scripts/dev-x86_64.sh owned-pthread-lifecycle` gate runs this
consumer with pinned musl and installed ET_EXEC/static-PIE. It also blocks
reserved SIGCANCEL (33) in the creator through the raw kernel mask interface
and proves a new worker unblocks it. `pthread_create_join::worker_entry`
publishes the owned FS+32 cancellation pointer before that unmask.

The focused `./scripts/dev-x86_64.sh owned-pthread-getattr` gate observes live
attributes through `pthread_getattr_np` followed by `pthread_attr_getstack`,
`pthread_attr_getguardsize`, and `pthread_attr_destroy`, the sequence used by
Rust std's Unix stack-overflow owner. Worker records report actual aligned
usable stack bounds and page-rounded private guards; caller-owned stacks have
no guard. TLS and runtime control mappings are separate and excluded. Registry
snapshots preserve current detach state and completed joinable records; static
fork copies the surviving worker's bounds into the adopted main record.
Unknown or withdrawn handles return `ESRCH` without changing output or errno.

The original main stack follows musl 1.2.6 `pthread_getattr_np.c`: round the
initial auxiliary-vector anchor upward to a page boundary, then probe downward
with `mremap` until an error other than `ENOMEM`. Raw failure updates errno even
when the API succeeds. A seccomp-denied `EPERM` probe proves this terminating
error and forbids an invented fallback. Tests also grow the main stack before
re-querying it, inspect default/custom/caller stacks, prove guard accessibility,
and observe detach transitions and fork adoption against pinned musl. The
live-attribute implementation is `pthread_attr::pthread_getattr_np`; lifecycle
snapshots belong to `pthread_create_join::selected_thread_attributes`. This
qualifies the stack-observation boundary, not the complete Rust std runtime.

The fork child also registers process-lifetime clear-child-TID storage before
user callbacks, following musl `_Fork::__post_Fork`. Dynamic linkage reuses
these libc adoption steps inside its separate loader graph/TLS transaction;
its installed evidence is `run_general_dynamic_fork.sh`, described in
[materialized-dynamic-sysroot.md](materialized-dynamic-sysroot.md).

`pthread_create_join::with_selected_pthread_signal_target` is the private
signal-delivery lifetime boundary: registry lookup acquires a mapping lease,
then releases the registry before taking the per-target kill lock. The
callback owns pending publication and raw delivery under that lock; callers
must block every signal until the lease is dropped. Non-final task exit
retires its target TID under the same lock, and post-withdrawal reclamation
drains earlier leases before unmapping. Initial-task target state has process
lifetime; fork adopts the surviving task's existing cancellation pointer and
refreshes its TID. This seam alone does not qualify signal-driven cancellation;
the cancellation owner must supply and test its handler and delivery callback.

Each TLS job also links `owned_io_cancellation_probe.c` in both installed modes
and extracted copies. The pinned-musl reference observes workers blocked in
`read`, `readv`, `write`, and `writev` through `/proc`, then requires signal-driven
cancellation with LIFO cleanup. It checks disabled and masked requests, a request
before syscall entry, asynchronous delivery, explicit FILE cleanup and orphan
locks, initial-task cancellation, and fork inheritance of pending state, type,
and cleanup for initial and adopted-worker tasks. `owned_syscall_cancel.rs` maps
musl's SIGCANCEL **33** and x86 PC window; FS+32 is a separate private TCB slot.
The target lifecycle lease protects both TID delivery and mapped cancellation
state after registry lookup. Its companion `owned_descriptor_cancellation_probe.c`
checks pending, disabled, and masked requests at `pread`, `pwrite`, `preadv`,
`pwritev`, `close`, `fsync`, and `fdatasync`, including cancellation before
positioned-write mutation and close's masked-state bypass. It observes workers
blocked in `poll`, `ppoll`, `select`, `pselect`, `pause`, `sigsuspend`,
`epoll_wait`, `epoll_pwait`, `eventfd_read`, and `eventfd_write`, then verifies
cancellation cleanup and restoration of the temporary signal mask. `fclose`
remains non-canceling even with a pending request.

The static and dynamic cancellation runners share only the explicit fixture
roster, project-header requirements, and scratch arguments in
`owned_io_cancellation_fixtures.sh`. Each product retains its own link and
execution proof. `owned_cancellation_proc_witness.h` preserves ordinary static
proc access and accepts an inherited read-only proc descriptor for contained
dynamic runs; the expected syscall and blocking resource remain fixture-owned.

The focused command is
`./scripts/dev-x86_64.sh owned-io-cancellation`; the aggregate remains the
installed/extracted product judge.

The same jobs include `owned_socket_cancellation_probe.c` and
`owned_sleep_wait_cancellation_probe.c`. The socket fixture covers pending,
disabled, masked, and observed blocked calls for `connect`, `accept`/`accept4`,
all send/receive forms, and musl's LP64 `sendmmsg` loop. It checks socket-timeout
cancellation and ordinary `SA_RESTART`/`EINTR` behavior. The sleep/wait fixture
covers `nanosleep`, relative and absolute `clock_nanosleep`, `sleep`, `usleep`,
and `thrd_sleep` called by a pthread, plus `wait`, `waitpid`, and `waitid`.
It preserves positive-error/no-errno clock sleep results and proves that the
source-defined `wait3`/`wait4`, CPU-clock rejection, and empty `sendmmsg` paths
do not check cancellation. Each controlled child is released and reaped even
after the waiting worker is canceled. Other syscall cancellation points and
dynamic initial-task/fork cancellation are separate work.

`owned_open_lock_cancellation_probe.c` runs in those same TLS jobs with a
runner-owned directory beneath `.work/`. Pending `open`, `openat`, and `creat`
requests cancel before creating or truncating a file, while disabled requests
retain mode selection and close-on-exec behavior. FIFO opens and a child-held
POSIX record lock establish actual blocking cancellation boundaries. The owned
`fcntl` dispatch now admits `F_SETLKW`; standalone archive selections retain
their prior rejection. `F_GETLK`, `F_SETLK`, and descriptor/status commands
remain non-canceling, including masked requests. Handled signals preserve the
source's `EINTR`/`SA_RESTART` behavior for FIFO opens and blocking locks. The
fixture also qualifies pending `msync` cancellation before kernel validation;
it makes no file-durability claim. Every fixture child is released and reaped,
and successful fixtures remove their scratch directory.

`owned_sysv_message_cancellation_probe.c` qualifies owned `msgsnd` and `msgrcv`
as cancellation points, including pending requests before `IPC_NOWAIT` and
invalid-queue errors. Actual blocked sends and receives preserve message
contents and queue capacity when canceled. With cancellation disabled, the
cancellation signal still interrupts these non-restarting Linux syscalls with
`EINTR`; ordinary handled signals do the same with or without `SA_RESTART`.
A supervisor owns the fixture's private queue and removes it after every child
outcome, including failed assertions and timeout. The implementation preserves
musl's caller-owned queue lifetime and adds no rollback or removal cleanup.
The standalone archive retains its raw syscall profile.

`owned_entropy_cancellation_probe.c` checks the source distinction between
`getrandom` and `getentropy`. Pending `getrandom` requests cancel even for
zero-length reads and invalid flags; masked requests return `ECANCELED`
without writing the buffer. `getentropy` suppresses cancellation during the
fill and restores enabled, disabled, or masked state on success and `EFAULT`.
The 256-byte limit still rejects larger requests with `EIO` before the state
guard. The fixture checks completion, errno, untouched buffer suffixes, and
state transitions; it never compares random bytes or asserts their values.

`owned_signal_wait_cancellation_probe.c` qualifies the shared `sigtimedwait`,
`sigwaitinfo`, and `sigwait` cancellation boundary. Pending enabled and masked
requests leave queued signals and caller output untouched; disabled requests
consume the queued signal. Actual blocked waits cover all three cancellation
states, while an ordinary interrupt retries without publishing `EINTR`.
The fixture also preserves musl's `sigwait` error convention and timeout
validation order. Signal masks remain intact through user cleanup.

`owned_semaphore_wait_cancellation_probe.c` isolates the source's mandatory
cancellation check before consuming an available token. Its companion
`owned_semaphore_cancellation_probe.c` qualifies owned `sem_wait` and the new
owned-only `sem_timedwait` in every TLS job. Waiter accounting uses explicit
pthread cleanup registration because signal-driven cancellation bypasses Rust
Drop. Tests check cleanup-before-user ordering, multiple waiters after one is
canceled, private and shared futex modes, a process-shared wake, and token
conservation under post/cancel and post/timeout races. Absolute realtime
nanosecond validation and expiry follow both initial token attempts; available
tokens bypass invalid or expired deadlines. The source's sticky signal-handler
flag preserves timed-wait `EINTR` behavior, including `SA_RESTART` after an
interrupting handler was previously installed and a kernel-rejected handler
installation. Overflow leaves the semaphore unchanged. The default standalone
six-function semaphore archive retains its earlier raw wait boundary and does
not export `sem_timedwait`; named semaphore operations remain unselected.

Each POSIX job separately links `owned_spawn_probe.c`: spawn/spawnp file-action
ordering, working-directory and PATH search, signal/process attributes, worker
calls, and failure cleanup compare against pinned musl. The installed and
extracted binaries own their scratch paths and receive the same sealed-link
and ELF checks. This qualifies the selected spawn boundary, not dynamic fork
or implicit cancellation.

Each POSIX job includes `owned_temp_objects_probe.c`, separately linked through
the installed driver. The five `mkstemp`/`mkostemp`/`mkstemps`/`mkostemps`/
`mkdtemp` entries create exclusive objects, preserve suffixes, force read/write
file access, retain requested CLOEXEC/append flags, and restore templates on
failure. The musl reference and both installed modes check permissions, invalid
lengths, missing parents, and descriptor ownership after unlink. Every pathname
is beneath that consumer's private directory; this is not a racy name-only API.

`owned_static_filesystem_consumer.c` composes `scandir`, `ftw`, and `nftw`
through installed allocation/directory/thread owners. Its private directory
tree checks sorting, traversal, and musl's cancellation-disabled walk followed
by restored-state delivery. It does not invent a cancellation guard for `scandir`.

`owned_static_ipc_readiness_consumer.c` composes worker-owned Unix socketpairs
and ephemeral loopback TCP endpoints with poll/epoll, scatter/gather I/O,
half-close, and error cleanup. It uses no external service or fixed port and
does not establish syscall cancellation behavior.

Each POSIX job also links the calendar and TZif probes described in
[`owned_calendar.md`](owned_calendar.md). Local conversion, normalization,
formatting, cache changes, and concurrent caller-buffer conversions compare
427,712 bytes with pinned musl. Six separate RFC/POSIX valid-file invariants
cover documented oracle defects; the musl diagnostic is retained separately,
never accepted as parity. Both binaries own their synthetic timezone pathname
and receive the same installed-link, ELF, and extracted-package checks.

`x86-owned-static-runtime` is a planned archive profile, routed through this
runner but selected by `scripts/build_x86_64_owned_sysroot.py`. Its direct
header-callable additions are the owned `abort`/`syscall`/`prctl`/`realpath`
support, descriptor-stream lifecycle and lock entries, allocated-line input,
the eight unlocked byte/block entries, `asprintf`/`dprintf` plus their
`va_list` forms, and the conventional local `/etc/group` C APIs documented in
`owned-group.md`. It replaces the selected default stream and byte-buffer
formatting implementations where `owned_static_stdio.rs` and `owned_printf.rs`
select a different owner; the feature's allocator, environment, exec,
permanent-format, and resolver dependencies retain their own feature-provider
rows. The installed consumer evidence is not a complete callable-provider
archive audit, so this profile remains planned and does not promote a family,
the default export roster, or public x86 support.

The aggregate also selects the existing C-owned resolver runtime. The
`libc_resolver_runtime_probe.c` fixture runs through its sealed installed
ET_EXEC and static-PIE drivers, including per-thread `h_errno`, hosts/search,
CNAME answers, and missing-name behavior. Each fixture reserves a distinct
loopback DNS address and uses a private chroot configuration; the concurrent
isolation check also occupies the former shared endpoint and verifies early
failure reaps the server. This proves no external DNS behavior or full resolver
family closure. Both modes and extracted copies now run in the same bounded
24-job consumer matrix. Cold producer reproducibility remains a separate
mandatory check; serial-versus-parallel timing is opt-in, not extra default work.

## Deliberately unselected

This tree has a deliberately narrow planned static driver and one private
dual-mode package/extracted-smoke seed, but no shared libc, dynamic loader,
compatibility loader alias, dynamic link mode, complete libc archive closure,
complete compiler-helper profile, or complete static-and-dynamic distribution
artifact. The driver has not yet proven the full static product's coverage
suite, including complete allocator lifecycle, pthread, stdio, filesystem, socket, and
resolver obligations. Those remain requirements of the planned families in
`compat/x86_64/parity.toml`. The artifact does not change x86 promotion or
public-support state.

The focused `owned-pthread-join-cancel` command qualifies `pthread_join`,
`pthread_tryjoin_np`, and `pthread_timedjoin_np` against pinned musl through
one fixture object compiled by the selected dynamic product, then linked in
static ET_EXEC/static-PIE and dynamic PIE/non-PIE entries. Both dynamic modes
are checked through kernel and direct-loader entries. The owned GNU pair uses the existing
selected worker claim/reclamation transaction: `pthread_tryjoin_np` reports `EBUSY`
before a cancellation point while the target has a live clear-child-TID, then
uses ordinary join once it has exited. `pthread_timedjoin_np` tests
cancellation before it reads the absolute `CLOCK_REALTIME` deadline, converts
the deadline locally for the shared clear-child-TID futex, and returns
`ETIMEDOUT` or `EINVAL` without consuming the target or changing result
storage. A completed target succeeds before an invalid deadline is read. Musl
times its private `detach_state` wait before an untimed `__tl_sync`; the
selected lifecycle instead times the shared clear-child-TID until it reaches
zero, then enters its existing result/reclamation transaction. This is a
state-transition adaptation, not a claim that the two private records have
byte identity. The owned public GNU spellings are weak same-address aliases of
hidden strong `__pthread_tryjoin_np` and `__pthread_timedjoin_np` bodies.

`owned_pthread_join_cancel_probe.c` checks result and errno preservation on
busy/timeout/invalid-deadline paths, user cleanup, continued target joinability
after cancellation, cleanup rejoin and exact target reclamation, cancellation
after a completed tryjoin delegates to `pthread_join`, and disabled/masked
state restoration. Blocked ordinary and timed joins are observed in their exact
shared `FUTEX_WAIT` through a read-only inherited `/proc` directory descriptor;
the target cannot complete during observation. The runner supplies the
oracle's private-futex versus owned shared-futex expectation at execution time
without rebuilding the fixture object. `run_pthread_wait_witness.py` retains
that descriptor across private chroot execution without requiring a proc mount.
The same runner witnesses the weak alias graph in pinned musl, the owned static
archive and static executables, and the dynamic `libc.so` provider.
The owned join boundary registers an explicit private cleanup node before
enabling cancellation while waiting; Rust destructors cannot restore ownership
when cancellation exits the task. Retirement and cleanup-node removal run with
cancellation disabled.

The focused `owned-pthread-cond-cancel` command qualifies ordinary private
`pthread_cond_wait` in original main tasks and pthread workers against pinned
musl through both static and both dynamic executable entries. The fixture
`owned_pthread_cond_cancel_probe.c` covers pending entry and kernel-observed
blocked cancellation, disabled and masked callers, mutex ownership during
cleanup, and reuse of the same condition after cancellation. A signaled waiter
is held at the exact mutex relock futex before cancellation: it consumes the
signal and returns normally, leaving cancellation pending for the next point.
An unsignaled MASKED caller instead observes `ECANCELED` with cancellation
disabled, as at musl's `__pthread_cond_timedwait` done label. The owned syscall
boundary replaces the old worker-only signal-free route, so the original main
task participates in the same list repair and mutex reacquisition contract.
The later timed/shared component extends these owned transactions and their
mutex admission as described below; the frozen archive keeps its prior boundary.

`owned-pthread-cond-timed` qualifies the owned timed/private/shared condition
transaction against pinned musl in all four executable modes. Initialization
consumes the existing condition attribute word, including its clock and sharing
fields. `owned_pthread_cond.rs` maps musl's private linked waiters, shared
sequence/count accounting, relative deadline conversion, cancellation repair,
relock precedence, and signal/broadcast/destruction transitions. Its typed
`pthread_mutex::ConditionMutex` seam admits normal, robust-normal, recursive,
error-checking, and priority-inheritance mutex kinds, with private/shared futex
selection added for cross-process condition use. Recursive waits retain musl's
one-unlock, one-relock depth behavior; they do not widen into a full
recursive-depth release. PI condition handoff wakes the waiter barrier instead
of requeuing an ordinary futex waiter onto the kernel-owned PI lock state.

`owned_pthread_cond_timed_probe.c` checks realtime/monotonic expiration, invalid
nanoseconds, invalid-clock errno, validation before cancellation, C11
`thrd_timedout`/`thrd_error`, and robust relock owner death overriding timeout or
cancellation, plus unrecoverable mutex state overriding a pending request. A private-condition broadcast onto a shared mutex proves that
successors are woken on their private barriers instead of incorrectly requeued
to a shared futex key. The cancellation fixture also runs timed-private,
ordinary-shared, and timed-shared variants with exact kernel wait observation.
`owned_pthread_cond_shared_probe.c` moves inherited shared storage to different
virtual addresses in each child, then proves signal, broadcast, and ordinary
or timed wait without process-local waiter pointers. The same fixture is used
for pinned musl and installed static/dynamic products.

`owned-pthread-mutex` qualifies recursive/error-checking and
priority-inheritance state transitions, plus the owned-only
`pthread_mutex_timedlock`/`mtx_timedlock` exports, against pinned musl in
static ET_EXEC/static-PIE and dynamic PIE/non-PIE products.
`owned_pthread_mutex_probe.c` checks recursive depth and contention,
error-checking self- and wrong-owner results, realtime timeout/invalid-deadline
ordering without errno publication, private/shared robust recursive,
error-checking, and PI owner death/recovery, recursive and PI condition relock,
and C11 recursive/timed kind status. Its PI path checks musl's
`PTHREAD_PRIO_NONE`/`PTHREAD_PRIO_INHERIT` protocol transition, contention and
deadline results, `PTHREAD_PRIO_PROTECT` rejection, and direct `EINVAL` with no
ceiling-slot write for both mutex priority-ceiling entries. The declared
mutex-attribute ceiling pair remains unprovided because pinned musl has no
provider. Its source-form PI regressions reject only `FUTEX_TRYLOCK_PI` with a
fixture-local seccomp filter, proving that a held `pthread_mutex_trylock`
returns direct `EBUSY` without inventing that kernel fallback; a separately
isolated robust-PI nonzero-waiter state proves musl's `ENOTRECOVERABLE` guard
before a raw owner record is linked. Each dynamic scenario separately enters
the installed consumer by
its `PT_INTERP` path and by `/lib/ld-crabc-x86_64.so.1 /consumer-$mode`; those
two owned-consumer streams are compared, while the pinned-musl executable
remains the separate oracle.

The pinned Rust nightly's `std/src/sys/sync/condvar/mod.rs` selects futexes for
Linux. Its Unix pthread fallback uses monotonic condition attributes and timed
waiting, but is not the selected Linux `std::Condvar` path; this component's
evidence is direct POSIX/C11 coverage, not Rust-std qualification.

`./scripts/dev-x86_64.sh owned-system-cancellation` qualifies the distinct
source waits in `owned_stdio_process.rs`: `system` calls public `waitpid` and
retains its `EINTR` errno across retries, while `pclose` calls
`wait_process_stream_raw` and retries without publishing the interrupted raw
result. The fixture observes the worker inside wait4 before cancellation.
Enabled cancellation leaves the system child alive and does not run the
source's later signal-disposition/mask restoration; masked cancellation
returns `ECANCELED` through the normal restoration path. Disabled waits and
all pclose waits finish and reap their child before a later explicit
cancellation check. Pending null commands preserve the initial source check.

`owned_system_cancellation_child.c` is a test protocol executable installed
at `/bin/sh` only inside private roots. It checks the exact `sh`, `-c`, command
argument sequence, environment, reset/ignored dispositions, and inherited
signal mask, then publishes its PID and waits for a release byte. It does not
implement shell language. Pinned musl and each owned entry run the same
consumer and child source in separate roots. A fixture supervisor adopts
orphan descendants and retains its waitable tester identity through cleanup;
normal completion, injected tester failure, and timeout all prove child-group
removal and reaping. This harness cleanup is separate from libc's source
contract. Ordinary shell semantics remain covered by the existing process
stream composition.

Owned `pthread_atfork` registrations use an allocation-backed process-lifetime
list rather than the frozen private archive's 32-record table. The source
contract and installed ordering/child/error evidence are documented in
[`owned-atfork-registry.md`](owned-atfork-registry.md).

The installed process creation trio (`clone`, `vfork`, and `daemon`) has a
separate source mapping and ordinary application differential gate in
[`owned-process-trio.md`](owned-process-trio.md). It includes static and
static-PIE entry, child thread identity/lifecycle, and process-error rollback.

The residual installed POSIX process-control providers have separate
same-object evidence in [`owned-process-control.md`](owned-process-control.md):
exec aliases, `nice`, group/session mutation, wait spellings, and spawn
attributes run across musl and every owned linkage mode. Its 31-name workload
is only one part of the 44-name process-control accounting; existing trio,
fork, spawn, and file-action workloads remain separate evidence.

The installed signal aliases, System V helpers, and FILE-owned signal reporting
are qualified by `owned-signal-helpers`; source mappings, inherited boundaries,
and the same-object musl differential are recorded in
[`owned-signal-helpers.md`](owned-signal-helpers.md). The frozen private
`process.signal` reporting limitations describe its older artifact, while
the installed reporting pair owns the real stderr lock and restores its
orientation and encoding state.

The installed PTY allocation/naming and controlling-terminal handoff component
is qualified by `owned-pty`, including same-object musl evidence through static
and dynamic entries. [`owned-pty.md`](owned-pty.md) records source mappings,
static-name buffer ownership, cancellation/mask and error-pipe order, and the
fixture's isolated devpts/session boundary.

The installed local passwd C APIs are qualified by `owned-passwd`, including
reentrant lookups, shared enumeration and FILE records, and literal `putpwent`
formatting. [`owned-passwd.md`](owned-passwd.md) records the pinned source,
local-only provider boundary, storage/cancellation contracts, and same-object
musl/static/dynamic evidence. The Rust facade's snapshot semantics and the
remaining `users.databases` C roster are separate contracts.

The installed C filename-pattern entries are qualified by `owned-pattern`.
[`owned-pattern.md`](owned-pattern.md) records the musl source mapping,
multibyte/classification, `glob_t` allocation, local passwd lookup, directory,
and dropped-privilege error boundaries, along with the same-object
musl/static/dynamic product evidence. They do not complete the broader C
pattern, locale, filesystem, or account contracts.

The installed POSIX filesystem composition is qualified by
`owned-posix-filesystem`: historical stat aliases, directory cursor/comparator
and `scandir` ownership, `ftw`/`nftw` callbacks and deferred cancellation,
legacy temporary names, caller-owned Linux file handles, and the selected
`lchmod` source path share one pinned-musl/static/dynamic object matrix.
[`owned-posix-filesystem.md`](owned-posix-filesystem.md) records its source
mapping, contained filesystem outcomes, provider audit, and required dynamic
qualification case. It retains the separate feature leaves' ownership and does
not establish a general filesystem or temporary-file policy.

The installed Linux/filesystem/terminal C mechanism block is qualified by
`owned-unix-mechanisms`: `get_current_dir_name`, mount lifecycle spellings,
`tcdrain`, `vhangup`, `vmsplice`, and Linux's `isastream` behavior share
pinned-musl/static/dynamic same-object evidence. [`owned-unix-mechanisms.md`](owned-unix-mechanisms.md)
records its source mapping, syscall/cancellation boundary, and contained
privileged-error evidence. It does not select mount policy, STREAMS emulation,
or a general filesystem or terminal runtime.
