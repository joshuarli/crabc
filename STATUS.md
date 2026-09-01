# Project status

The current implementation program is staged native Linux/x86-64 little-endian
runtime parity, defined by [`x86-64.md`](x86-64.md). It covers `crabc-core`,
`crabc-libc`, `crabc-ldso`, CRT/sysroot artifacts, and `crabc-rs`, beginning
with explicit target-specific foundations and native evidence. Public support
remains Linux/AArch64 little-endian until every x86 promotion gate passes.

The x86 lane has three private ET_DYN interpreter artifacts inside still-planned
`ldso.dynamic-runtime`. `ldso-initial-graph` is limited to
one main PIE -> mid.so -> leaf.so graph, RELATIVE/GLOB_DAT/JUMP_SLOT ELF64
RELA plus one bounded packed leaf `DT_RELR` direct-and-bitmap stream with
independent 512-record/512-target caps; the pre-Rust interpreter bootstrap
remains `DT_RELA`-only. It also covers
dependency-only leaf-before-mid init arrays, final interpreter-and-graph RELRO
sealing, and main/leaf RELRO-fault plus fail-closed malformed-file-range/TLS/
unsupported-relocation/RELR inputs. It deliberately rejects main-image
constructors pending CRT handoff and is not a general loader, CRT/sysroot, or
public x86 support claim.

The separate `ldso-initial-tls` artifact keeps that original no-TLS proof
unchanged while adding one fixed TLS-free main PIE -> two GNU-Dynamic TLS DSO
graph. It proves checked DSO `PT_TLS` parsing and Variant-II copying,
initialized/TBSS/high-alignment values, a two-entry private DTV, DTPMOD/DTPOFF
and interpreter-owned `__tls_get_addr`, and reject-only TPOFF/static-TLS
inputs. It remains neither a general loader/TLS/pthread implementation nor a
dynamic CRT/sysroot, full x86-64 parity, or public x86 support claim.

The third `ldso-owned-crt-handoff` sibling keeps both prior interpreter
artifacts unchanged while proving one fixed no-TLS main PIE -> mid.so -> leaf.so
post-relocation publication to a Rust-produced Scrt1-owned dynamic main. Its
only extra main lookup is the weak `R_X86_64_GLOB_DAT`
`__crabc_x86_64_owned_crt_handoff` v1 record: the self-relocated interpreter
RELRO-seals it, never uses `%rdx`, and defers only the existing leaf-before-mid
init arrays until after executable preinit. The native no-libc fixture proves
`PDdIMFL` under `env -i`; pinned musl proves the absent-record null-finalizer
`A` route; malformed record data and an early finalizer fail status 127. It
does not select another executable/root, general loader lifecycle or DSO
finalization, candidate libc, RuntimeV1, dynamic CRT/sysroot, or public x86
support.

The x86 lane now has fifteen private static artifacts inside still-planned
`libc.pthread-tls`. `./scripts/dev-x86_64.sh libc-static-tls-v1` passes a
freestanding final-static-executable fixture's untouched Linux entry stack to
a hidden libc hook. That hook validates the final executable's program-header
view and optional `PT_TLS` image, materializes one x86 Variant-II main-thread
image, and retains its immutable template. Its fixture links initialized,
TBSS, and high-alignment TLS definitions from two C translation units plus
libc `errno`; after mutating the main image, two sequential workers prove they
each receive fresh template values. The existing private static
`pthread_create`/`pthread_exit`/`pthread_join` artifacts consume independent
copies of that template for a null-attribute worker that returns normally or
uses the selected worker-only explicit-exit path, with result handoff and
clear-child-tid join reclamation. A fixed private 64-worker registry
serializes explicit-exit publication with join withdrawal and validates
`%fs:0`, the child kernel TID, and its still-live clear-child-tid word; the
candidate-only cap check exhausts all slots and proves reuse after joining.
The separate `./scripts/dev-x86_64.sh libc-pthread-identity` artifact proves
the bounded opaque x86 identity contract: weak same-address
`pthread_self`/`thrd_current` and `pthread_equal`/`thrd_equal` pairs, direct
Variant-II `%fs:0` identity, and canonical one-or-zero macro/function
equality for the main thread plus two live normal workers and one selected
explicit-exit worker. `pthread_create` returns that child TP and
`pthread_join` resolves it under the existing private registry lock; no
dereferenceable TCB or broader C11 thread lifecycle is selected. The separate
`./scripts/dev-x86_64.sh libc-c11-lifecycle` artifact admits only typed
`thrd_create`/`thrd_join`/`thrd_exit` over that same static worker seam. It
preserves normal and explicit signed `int` results, including `INT_MIN` and
`INT_MAX`, and checks the opaque TP identity while the handle is still live.
The pinned-musl portion covers only those standard C11 paths; candidate-only
null-start and bidirectional unsupported C11/pthread-exit crossover checks
fail closed after reclamation without decoding an incompatible result. It does
not select detachment or sleep beyond their separately recorded private artifacts, C11
synchronization/TSS/cancellation, dynamic or loader TLS, or general
pthread/C11 behavior. The separate `./scripts/dev-x86_64.sh
libc-pthread-detach` artifact selects only prompt state-only
`pthread_detach`/`thrd_detach` ownership for those selected workers. A
successful detach neither waits nor reclaims the still-live worker mappings;
only a later selected create/join boundary may reap an exited detached worker
after `CLONE_CHILD_CLEARTID` clears its child TID. Its pinned-musl comparison
covers external workers before and after the fixture's callback-completion
signal, not a detach call after kernel exit. Self-detach, null/repeated/racing
ownership attempts, join-after-detach, and 64-slot delayed reuse are
candidate-only diagnostics, not pthread/C11 parity. The separate
`./scripts/dev-x86_64.sh libc-thrd-sleep` artifact selects only the direct C11
`thrd_sleep` status adapter over the existing non-cancellation
`clock_nanosleep(CLOCK_REALTIME, 0, ...)` seam: zero succeeds, `EINTR` maps to
`-1`, and invalid or null duration requests map to `-2` without changing
`errno`. Its pinned-musl/reference and static-candidate route also proves a
SIGALRM interruption with a positive remaining interval. It does not select
`thrd_yield`, cancellation cleanup, C11 lifecycle/synchronization/TSS,
dynamic/loader TLS, CRT, sysroot, or public x86 support. The separate
`./scripts/dev-x86_64.sh libc-pthread-mutex-normal` artifact is a tenth private static
`verified_artifact` in the same still-planned `libc.pthread-tls` family. It admits only an all-zero or
`pthread_mutex_init(..., NULL)` process-private `PTHREAD_MUTEX_NORMAL` record
through `pthread_mutex_init`/`destroy`/`lock`/`trylock`/`unlock`. Its exact
lock word progresses from `0` to `EBUSY` and, under contention, to
`EBUSY|INT_MIN`; private `FUTEX_WAIT_PRIVATE`/`FUTEX_WAKE_PRIVATE` handoff
coordinates the selected workers. The pinned-musl and true static-candidate
fixture proves held-lock `EBUSY`, caller-`errno` preservation, and mutual
exclusion across six bounded two-worker rounds. Non-null attributes or a
nonzero type word return `ENOTSUP` rather than selecting another mutex type.
It excludes mutex attributes, recursive/error-checking/robust/PI/
process-shared/timed mutexes, C11 mutex or condition behavior beyond the
separately selected plain adapter, general condition variables, cancellation,
dynamic/loader TLS, CRT/sysroot integration, general pthread synchronization,
full pthread/TLS or x86-64 parity, and public x86 support. The separate
`./scripts/dev-x86_64.sh libc-pthread-rwlock` artifact is a fifteenth private
static `verified_artifact` in the same still-planned `libc.pthread-tls`
family. Its pinned-musl/reference and true static-candidate routes select the
complete installed `pthread_rwlock_*` and `pthread_rwlockattr_*` family over
the 56-byte, eight-byte-aligned rwlock and eight-byte, four-byte-aligned
attribute records: init/destroy, reader and writer lock/try/timed-lock,
unlock, and attribute init/destroy/get/set process sharing. The seven
lock-operation public names are weak same-address aliases of hidden
`__pthread_rwlock_*` definitions. The fixture proves static and private or
process-shared initialization, concurrent readers, reader/writer exclusion,
expired and future absolute `CLOCK_REALTIME` timeout status including musl's
initial-try ordering, wake-before-deadline handoff, caller-`errno` preservation, and
cross-process shared-futex reader and writer wakeups. Its raw time, mapping,
fork, wait, and exit plumbing is fixture-local rather than a C process-runtime
claim. It does not select cancellation, priority or fairness guarantees,
general pthread synchronization or runtime ownership, dynamic/loader TLS,
CRT/sysroot integration, full pthread/TLS or x86-64 parity, promotion, or
public x86 support. The separate
`./scripts/dev-x86_64.sh libc-pthread-cond-private` artifact is an eleventh
private static `verified_artifact` in that same still-planned
`libc.pthread-tls` family. It admits only a 48-byte, eight-byte-aligned
all-zero or `pthread_cond_init(..., NULL)` process-private condition record,
paired only with the selected all-zero or NULL-initialized normal mutex. Its
pinned-musl/reference and true static-candidate routes preserve the private
stack waiter/list/barrier/requeue protocol and use
`FUTEX_WAIT_PRIVATE`/`FUTEX_WAKE_PRIVATE`/`FUTEX_REQUEUE_PRIVATE` for the
selected handoff. They prove static and NULL initialization, one deterministic
signal, a two-waiter broadcast, four bounded 64-handoff ping-pong rounds,
caller-`errno` preservation, and quiescent destruction. Candidate-only
evidence requires every non-NULL condition attribute to return `ENOTSUP`;
that rejection is a selected-boundary diagnostic, not a musl-parity claim.
Condition attributes, process-shared or timed waits, cancellation, C11
condition behavior beyond the selected plain adapter, general condition
behavior, non-selected mutex kinds, destruction with live
waiters, dynamic/loader TLS, CRT/sysroot integration, general pthread
synchronization, full pthread/TLS or x86-64 parity, promotion, and public x86
support remain excluded. The separate `./scripts/dev-x86_64.sh
libc-c11-plain-sync` artifact is a twelfth private static
`verified_artifact` in that same still-planned `libc.pthread-tls` family. It
admits only the installed header's distinct 40-byte, eight-byte-aligned
`mtx_t` and 48-byte, eight-byte-aligned `cnd_t` records: `mtx_plain`
initialization, mutex init/destroy/lock/trylock/unlock, and condition
init/destroy/wait/signal/broadcast. The C11 boundary routes directly through
the selected private normal-mutex and condition waiter/barrier/requeue engines
without calling an interposable pthread C symbol; a held trylock maps to
`thrd_busy`. Recursive and timed kinds are candidate-only `thrd_error`
rejections before their records are interpreted, not musl-differential
behavior. Timed calls, static C11 initialization, cancellation, TSS, once,
process-shared synchronization, C11-family completion, pthread/TLS or x86-64
parity, promotion, and public x86 support remain excluded. The separate
`./scripts/dev-x86_64.sh libc-pthread-c11-once` artifact is a thirteenth private
static `verified_artifact` in that same still-planned `libc.pthread-tls`
family. Its pinned-musl/reference and true static-candidate routes select only
the normal-return `pthread_once` and C11 `call_once` path for the installed
four-byte, zero-initialized `pthread_once_t` and `once_flag` records. The
shared private state machine changes `0` to initializer state `1`; two selected
contenders start while the control reaches state `3` and selected waiters use
`FUTEX_WAIT_PRIVATE`; a normal
initializer release-publishes state `2` and uses `FUTEX_WAKE_PRIVATE` only
when waiters were recorded. Static and local zero initialization, exactly one
initializer, post-completion relaxed-payload visibility without a separate
release/acquire edge, and caller-`errno`
preservation are evidence boundaries; `call_once` reaches the shared private
machine rather than an interposable pthread C symbol. Cancellation reset,
initializer `pthread_exit`/`thrd_exit`, recursive same-control entry,
fork/atfork, TSS, dynamic/loader TLS, musl's weak `pthread_once` ELF binding,
general pthread/C11 synchronization,
full pthread/TLS or x86-64 parity, promotion, and public x86 support remain
excluded. The separate `./scripts/dev-x86_64.sh libc-pthread-c11-tsd` artifact
is a fourteenth private static `verified_artifact` in the same still-planned
`libc.pthread-tls` family. It selects only
`pthread_key_create`/`pthread_key_delete`/`pthread_getspecific`/
`pthread_setspecific` and `tss_create`/`tss_delete`/`tss_get`/`tss_set` over
a private 128-key table, a process-main value table, and one value table in
each already selected worker control. A null destructor still reserves its
key; deletion clears only those selected value tables and calls no old
destructor. For normal pthread/C11 return, `pthread_exit`, and `thrd_exit`,
the worker clears a non-null value before calling its destructor, releases the
private metadata lock for that callback, allows rearming for at most four
ascending-key passes, and completes the phase before publishing the join result
or reaching `SYS_exit`. The pinned-musl/reference and true static-candidate
fixture proves main/worker isolation, 128-key exhaustion and numeric-slot
reuse after deletion, four clear-before-callback rearming passes, and all four
selected exit routes. Invalid/deleted keys and non-selected callers fail
closed deliberately rather than inheriting musl's unchecked internal fast
paths; selected-main admission requires the bootstrapped `%fs:0` plus Linux
TID pair, so an inherited FS base alone is insufficient. Main-thread
process-exit destructors, foreign threads beyond that admission boundary,
cancellation and cleanup handlers, concurrent key-deletion/destructor
interaction, fork/atfork, detached-thread lifecycle beyond the existing
selected-worker exit seam, dynamic/loader TLS/DTV, allocator ordering, a
general TCB or all-thread list, weak/same-address TSD aliases, exact ELF
parity, general pthread/C11 behavior, full pthread/TLS or x86-64 parity,
promotion, and public x86 support remain excluded. The CRT-composition artifact,
`./scripts/dev-x86_64.sh libc-crt-static-tls`, composes
the real `rcrt1.o`/`crti.o`/`crtn.o` with that hidden libc owner: after checked
relocation and RELRO, `rcrt1.o` calls
`__crabc_x86_static_tls_bootstrap(original_entry_stack)` before libc's bounded
static `__libc_start_main`. It proves one initialized/TBSS/high-alignment
`PT_TLS` image, preinit/init/main/ordinary-exit/fini order, a 32-registration
no-allocation LIFO callback block, one fresh selected worker, and malformed
`PT_TLS.p_filesz` rejection. `libc.pthread-tls` remains planned: this is not
general pthread/TLS parity, dynamic or loader TLS, a general CRT/libc startup
ABI, broader C11 lifecycle or synchronization, stdio/C++/DSO or concurrent-exit
lifecycle, sysroot support, or public x86 support.

`./scripts/dev-x86_64.sh libc-crt1-static-tls` is the companion private
ordinary-static composition artifact. It links real Rust
`crt1.o`/`crti.o`/`crtn.o` into an `ET_EXEC` final executable, proves the
archive-free link fails at both hidden TLS and archive-startup boundaries, and
then proves the same TLS-first shared handoff before archive-owned bounded
preinit/init/main/ordinary-exit/fini. Its two-C-unit initialized/TBSS/4096-byte
aligned `PT_TLS` image, fixed 32-registration no-allocation LIFO callback
block, fresh selected worker, and malformed `PT_TLS.p_filesz` status-127
rejection are private evidence only. It does not complete general CRT or libc
startup ABI, pthread/TLS parity, loader TLS, a sysroot, or public x86 support.

The x86 direct Rust facade also has verified allocation-free
`pattern::{fnmatch, FnmatchFlags}` and alloc-gated explicit-root
`pattern::{GlobPath, glob, glob_at}` slices. Their x86 no-std archive proofs
reject C pattern, directory-stream, errno-TLS, and public C allocator
boundaries; the glob probe intentionally supplies a fixed Rust allocator.
They remain private Rust-facade evidence, not C `fnmatch`/`glob`/`globfree` ABI
support, complete facade/platform parity, or public x86 support.

The x86 static C archive also has one private caller-owned mapping-core
artifact: `./scripts/dev-x86_64.sh libc-mapping-core` runs the project-header
C/C++ `sys/mman.h` gate and then one pinned-musl/freestanding-static proof for
exactly `mmap`, `munmap`, `mprotect`, `madvise`, `posix_madvise`, and `mincore`.
It preserves the selected musl mapping prechecks/fallback, page-rounded
`mprotect`, POSIX advice convention, and residency behavior. Its `__vm_wait`
site is deliberately local/no-op because the archive does not own loader or
allocator VM state. This is a bounded `static-c-mman-mapping-core` artifact
inside planned `libc.posix-runtime`, not full `sys/mman.h`, C-runtime,
family/platform parity, or public x86 support; its separate direct `msync`
sibling still excludes musl cancellation, while `mremap`, shared memory, and
process-wide VM synchronization remain unselected.

The same archive separately has a private planned mapping-synchronization
evidence artifact: `./scripts/dev-x86_64.sh memory-sync-header-abi` and
`./scripts/dev-x86_64.sh libc-memory-sync` compare unconditional C/C++
`msync`/`MS_*` declarations across eight project-header/pinned-musl profiles,
then run one pinned-musl/freestanding-static candidate. It proves only the
direct no-cancellation x86 `msync=26` route, stale-`errno` success, and Linux
5.10's flag and page-alignment validation before a zero-length success on a
disposable private anonymous mapping. Pinned musl's `syscall_cp` cancellation
path is deliberately absent. This bounded `static-c-memory-sync` artifact is
not full musl `msync`, file-backed shared-map writeback or invalidation,
persistence or durability, complete `sys/mman.h`, C-runtime/family/platform
parity, promotion, or public x86 support.

The same archive separately has a private per-range memory-locking artifact:
`./scripts/dev-x86_64.sh memory-locking-header-abi` and
`./scripts/dev-x86_64.sh libc-memory-locking` prove exactly `mlock`,
`munlock`, and GNU `mlock2(MLOCK_ONFAULT)` through a six-profile
project-header/pinned-musl C/C++ declaration matrix plus one
pinned-musl/freestanding-static candidate. It retains musl's `flags=0`
`mlock2` delegation to `mlock`, direct x86 `mlock=149`, `munlock=150`, and
`mlock2=325`, stale-errno success, first-fault locking, and Linux's
environment-dependent `EPERM`/`EAGAIN`/`ENOMEM` memlock outcome. This is a
bounded `static-c-memory-locking` artifact inside planned
`libc.posix-runtime`, not full `sys/mman.h`, C-runtime, family/platform parity,
or public x86 support; `mlockall`/`munlockall`, the separate direct `msync`
sibling, `mremap`, cancellation, and mapping policy remain unselected here.

The same archive also has a private planned GNU memory-file-descriptor
creation evidence artifact: `./scripts/dev-x86_64.sh memfd-create-header-abi`
and `./scripts/dev-x86_64.sh libc-memfd-create` compare the GNU-only
`memfd_create`/`MFD_*` C/C++ surface across eight project-header/pinned-musl
profiles, including non-GNU hiding and unmangled C++ linkage, then run one
pinned-musl/freestanding-static candidate. It proves only direct x86
`memfd_create=319`, the selected initial-TLS `errno` boundary, ordinary and
249-byte labels, creation-flag forwarding, and Linux's 250-byte/all-ones flag
word `EINVAL` and invalid-pointer `EFAULT` outcomes. This bounded
`static-c-memfd-create` artifact does not establish sealing or C `fcntl`
behavior, `memfd_secret`, huge-page resource/page-size policy, descriptor
lifecycle or close ownership, broad filesystem behavior, C-runtime/family/
platform parity, promotion, or public x86 support.

The same archive has a private direct time-observation artifact:
`./scripts/dev-x86_64.sh libc-time-observation` proves only `clock`, `time`,
`difftime`, C11 `timespec_get`, `clock_getres`, and `gettimeofday` through a
pinned-musl/reference plus freestanding-static candidate. It records the
direct x86 `clock_gettime=228`, `clock_getres=229`, and `gettimeofday=96`
paths, normalized outputs, stale-errno behavior, invalid-clock handling, and
the `TIME_UTC`/unsupported-base boundary. It has no vDSO resolver, calendar or
timezone state, clock mutation, POSIX timer, cancellation, libc.so, CRT,
loader, sysroot, family/platform parity, or public-x86-support claim.

`./scripts/dev-x86_64.sh libc-system-information` is a separate private
`static-c-system-information` artifact inside planned `libc.posix-runtime`.
Its project-header C/C++ gate and pinned-musl/freestanding-static fixture prove
only `get_nprocs_conf`, `get_nprocs`, `get_phys_pages`, and
`get_avphys_pages`: musl's fixed 128-byte affinity mask and child-forced
affinity-error CPU-zero fallback, plus successful `sysinfo` physical and
free-plus-buffer page arithmetic. The safe selected page-helper error return
does not claim an output contract for musl's uninitialized-record failure
path. This is not processor-affinity control, topology, general `sysconf`,
load observation, a general system-information capability, C-runtime/family
parity, AArch64 parity, or public x86 support.

`./scripts/dev-x86_64.sh libc-fcntl-record-locks` is a separate private
`static-c-fcntl-record-locks` artifact inside planned `libc.posix-runtime`.
Its project-header C/C++ gate and pinned-musl/freestanding-static fixture prove
only pointer-bearing nonblocking `fcntl(F_GETLK)`/`fcntl(F_SETLK)` over the
public 32-byte `struct flock`: unlocked query, child-observed parent conflict
and PID, release, stale `errno`, and direct `EBADF`/`EINVAL` outcomes. It does
not select `F_SETLKW` cancellation, OFD locks, `lockf`, `flock`, generic
`fcntl`, descriptor/filesystem policy, family/platform parity, or public x86
support.

`./scripts/dev-x86_64.sh libc-flock` is a separate private `static-c-flock`
artifact inside planned `libc.posix-runtime`. Its project-header C/C++ gate and
pinned-musl/freestanding-static fixture prove only direct nonblocking
`flock`: public operation bits, duplicate open-file-description release state,
a separately opened child conflict and later exclusive reacquisition, stale
`errno`, and direct `EWOULDBLOCK`/`EAGAIN`, `EBADF`, and `EINVAL` outcomes. It
does not select `fcntl` record-lock interaction, `lockf`, descriptor/pathname
policy, network/distributed-filesystem semantics, family/platform parity, or
public x86 support.

`./scripts/dev-x86_64.sh libc-sendfile` is a separate private
`static-c-sendfile` artifact inside planned `libc.posix-runtime`. Its
project-header C/C++ gate and pinned-musl/freestanding-static fixture prove
only direct regular-file `sendfile`: an explicit signed `off_t` advances while
leaving the input position unchanged, a null offset advances that shared
position through short-transfer and EOF-zero cases, and stale `errno`,
`EINVAL`, and `EBADF` are translated directly. It does not select pathname,
socket/pipe, splice, copy-file-range, vector-I/O, durability, cancellation,
family/platform parity, or public x86 support.

`./scripts/dev-x86_64.sh libc-posix-fallocate` is a separate private
`static-c-posix-fallocate` artifact inside planned `libc.posix-runtime`. Its
strict and large-file-only project-header C/C++ profiles, plus its
pinned-musl/freestanding-static fixture, prove only mode-zero C
`posix_fallocate`: signed LP64 offset/length forwarding, an unlinked regular
file range [4096, 8192) with retained prefix, zero-filled extension,
and stable position, plus direct positive `EINVAL`/`EBADF` returns that leave
stale `errno` unchanged. It does not select general `fallocate` flags,
pathname allocation, filesystem fallback/policy, durability, cancellation,
family/platform parity, or public x86 support.

`./scripts/dev-x86_64.sh libc-descriptor-advice` is a separate private
`static-c-descriptor-advice` artifact inside the same planned family. Its
strict/no-feature, GNU-only, and large-file-only project-header C/C++
`<fcntl.h>` profiles prove unconditional `posix_fadvise`, the six
`POSIX_FADV_*` values, GNU-only `readahead`, and the LF64-only
`posix_fadvise64` macro alias to the unmangled base. Its pinned-musl and
freestanding-static fixture proves only `fadvise64=221` direct positive
`EINVAL`/`EBADF` returns with stale `errno` unchanged, and `readahead=187`
`-1`/published-`EINVAL`/`EBADF` behavior, across an unlinked regular file
with zero-length advice and stable position/size. It makes no cache-residency
or cache-effect claim. Cache policy/effects, allocation, pathname and
filesystem policy, durability, cancellation, family/platform parity, and
public x86 support remain unselected.

`./scripts/dev-x86_64.sh libc-filesystem-capacity` is a separate private
`static-c-filesystem-capacity` artifact inside planned `libc.posix-runtime`.
Its seven-base-plus-two-LF64 project-header C/C++ `sys/statfs.h`/
`sys/statvfs.h` matrix proves only the four declarations, x86 LP64 records,
mount flags, unmangled C++ references, and LF64 macro aliases. Its
pinned-musl/freestanding-static fixture then proves only `statfs`/`fstatfs`
through `statfs=137`/`fstatfs=138`, plus musl `src/stat/statvfs.c`'s derived
`statvfs`/`fstatvfs` conversion: public statfs zeroing, successful statvfs
zero-and-map results (including fragment-size fallback, `f_favail`, and fsid
mapping), stale errno on success, and direct ENOENT/EBADF errors. It does not
select capacity/quota/accounting policy, pathname behavior, general filesystem
support, family/platform parity, or public x86 support.

`./scripts/dev-x86_64.sh libc-vector-io` is a separate private
`static-c-vector-io` artifact inside the same planned family. Its fourteen
project-header/pinned-musl C/C++ `<sys/uio.h>` profiles prove only x86 LP64
`iovec`, `UIO_MAXIOV`, base and GNU/BSD-positioned declarations, GNU-only
v2/RWF/process-vm declarations and hiding, LF64 aliases, and unmangled C++
linkage. Its pinned-musl/freestanding-static fixture proves only direct
`readv`/`writev`/`preadv`/`pwritev`: segment order, unchanged positioned
offsets, invalid count/signed-offset errno results, an independently observed
offset above 4 GiB, and musl's selected pwritev append boundary. It does not
select cancellation, v2/process-vm runtime, scalar descriptor I/O, stdio,
family/platform parity, or public x86 support.

`./scripts/dev-x86_64.sh socket-messages-header-abi` and
`./scripts/dev-x86_64.sh libc-socket-messages` are a separate private
`static-c-socket-messages` artifact inside still-planned `libc.posix-runtime`.
The POSIX/GNU/BSD project-header/pinned-musl C/C++ matrix and freestanding
fixture cover exactly `setsockopt`, `getsockopt`, `sendmsg`, `recvmsg`,
`sendmmsg`, `recvmmsg`, and `sockatmark`: the padded public x86 message
records, a bounded 1056-byte ancillary-control copy, `sendmmsg`'s padded
`sendmsg` loop rather than raw `SYS_sendmmsg`, and direct `recvmmsg`/
`SIOCATMARK`. Cancellation, resolver/netdb, generic socket or ioctl behavior,
family/platform parity, and public x86 support remain outside this leaf.

`./scripts/dev-x86_64.sh libc-access` is another private
`static-c-filesystem-access` artifact inside planned `libc.posix-runtime`.
It proves only static C `access`, `faccessat`, `euidaccess`, and weak
same-address `eaccess` through pinned-musl and freestanding-archive runs:
real versus effective credentials, zero-flag legacy and flags-bearing Linux
paths, direct errno behavior, and strong caller alias override. It is not
filesystem capability or C-runtime parity; pathname policy, `fchmodat`/
`lchmod`, broader C credential/process behavior, and public x86 support remain
planned.

`./scripts/dev-x86_64.sh libc-descriptor-lifecycle` is a separate private
`static-c-descriptor-lifecycle` composition artifact inside that same planned
family. It runs one project-header C body through pinned musl and then a
freestanding static archive, composing the already selected descriptor-entry,
fcntl-status, descriptor-I/O, and `fstat`/`fstatat` leaves through a
PID-isolated relative-directory lifecycle. Raw syscalls only make and remove
the test directory. It proves no descriptor/filesystem capability, general
C runtime, cancellation behavior, family completion, AArch64 parity, or
public x86 support.

`./scripts/dev-x86_64.sh libc-timestamp-updates` is a separate private
`static-c-timestamp-updates` artifact inside planned `libc.posix-runtime`.
It runs one project-header C body through pinned musl and then through the
archive-owned `rcrt1`/`crti`/`crtn` static-PIE startup route. It proves only
`utimensat`, `futimens`, strong `__futimesat` with its weak same-address
`futimesat` alias, `futimes`, `lutimes`, `utimes`, and `utime`, including the
selected `UTIME_NOW`/`UTIME_OMIT` and legacy conversion boundaries. It does
not establish filesystem policy, a general C runtime, dynamic libc, loader,
CRT/sysroot, family completion, AArch64 parity, or public x86 support.

`./scripts/dev-x86_64.sh libc-signal-execution` is one further private
`static-c-process-signal-execution` artifact inside planned
`libc.posix-runtime`. Its pinned-musl/freestanding-static C proof composes the
existing simple signal action/set/mask boundary with exactly `kill`, `killpg`,
`raise`, `sigqueue`, `sigtimedwait`, `sigwaitinfo`, and `sigwait`, including
the application-signal mask transaction, queued `siginfo_t` layout, stale
`errno`, EINTR retry, and musl `sigwait` `-1`/`errno` failure convention. A
fixture-only raw child makes the interrupted wait deterministic. It does not
select general process lifecycle, `tgkill`, alternate stacks, signalfd, legacy
signal APIs, pthread signal policy, libc.so, CRT, loader, sysroot, family or
platform parity, or public x86 support.

`./scripts/dev-x86_64.sh libc-ioctl` is a private
`static-c-generic-ioctl` artifact inside planned `libc.posix-runtime`. It
proves the direct signed `int ioctl(int, int, ...)` C boundary through pinned
musl and a freestanding static archive for `FIONREAD`, `FIONBIO`, and the two
safe no-vararg calls `FIOCLEX`/`FIONCLEX`; its assembly shim supplies `rdx=0`
only for those two forms. It does not establish generic device/request
behavior, terminal/session policy, socket options, C-runtime parity, family
completion, or public x86 support.

`./scripts/dev-x86_64.sh sysv-semaphore-header-abi` is the paired
eight-profile C11/C++17 project-header/pinned-musl `sys/ipc.h` and `sys/sem.h`
gate: selected declarations, feature visibility, command values, x86 LP64
records, and unmangled C++ references. The accompanying
`./scripts/dev-x86_64.sh libc-sysv-semaphore` command records the private
`static-c-sysv-semaphore` artifact inside planned `libc.posix-runtime`. Its
pinned-musl and freestanding-static C fixture selects exactly `semget`,
`semop`, GNU `semtimedop`, and variadic `semctl`, including the application
`union semun` scalar/pointer forms, no-vararg cleanup, the musl oversized-count
precheck, direct syscall/errno behavior, and the x86 fourth-argument route.
It is a bounded semaphore ABI/archive vertical, not closure of
`libc.headers-layouts` or `libc.posix-runtime`. The paired
`./scripts/dev-x86_64.sh sysv-message-shared-memory-header-abi` gate now
compares selected `sys/ipc.h`/`sys/msg.h`/`sys/shm.h` declarations,
feature-visible member spellings, x86 LP64 layouts and constants, and C++
linkage across the same eight project-header/pinned-musl profiles. Its
accompanying `./scripts/dev-x86_64.sh libc-sysv-message-shared-memory` command
records the separate private `static-c-sysv-message-shared-memory` artifact
inside planned `libc.posix-runtime`: its pinned-musl and freestanding-static C
fixture selects exactly `ftok`, `msgget`, `msgsnd`, `msgrcv`, `msgctl`,
`shmget`, `shmat`, `shmdt`, and `shmctl`. It proves one local nonblocking
message-queue lifecycle, one local shared-memory attach/status/detach/remove
lifecycle, raw errors and stale `errno`, the x86 `r10`/`r8` message argument
paths, musl's oversized-`shmget` rewrite, and `shmat`'s `(void *)-1` failure
sentinel. The direct `msgsnd`/`msgrcv` leaves intentionally omit musl's
pthread cancellation machinery. These are two bounded private ABI/archive
verticals, not complete SysV IPC or closure of either planned family: POSIX
message queues/shared memory/semaphores, broader SysV operations and
namespace/permission policy, `SEM_UNDO` lifecycle, cancellation, libc.so,
CRT, loader, sysroot, family or platform parity, promotion, full x86-64
parity, and public x86 support remain unselected.

`./scripts/dev-x86_64.sh event-descriptors-header-abi` adds an artifact-local
eight-profile C/C++ project-header/pinned-musl matrix. It records that the
selected direct `sys/eventfd.h` and `sys/inotify.h` surface is unconditional,
with x86 LP64 `eventfd_t`/`inotify_event` layouts, selected direct flags, and
header-requested unmangled C++ C-linkage spellings. Because both headers
immediately include `fcntl.h`, the same narrow matrix records only
`AT_EMPTY_PATH` as GNU/BSD/default-C-visible and strict/POSIX/XOPEN-hidden,
including macro-free C++17. Its `nm` check is only header-requested external
symbol spelling, not actual callable artifact linkage; the global
feature-visibility facet remains planned. The existing `epoll-header-abi`
matrix remains its own packed `sys/epoll.h` proof. The paired
`./scripts/dev-x86_64.sh libc-event-descriptors` command records a separate
private `static-c-event-descriptors` artifact in planned `libc.posix-runtime`.
Its pinned-musl and freestanding-static C fixture selects exactly
`epoll_create`, `epoll_create1`, `epoll_ctl`, `epoll_wait`, `epoll_pwait`,
`eventfd`, `eventfd_read`, `eventfd_write`, `inotify_init`, `inotify_init1`,
`inotify_add_watch`, and `inotify_rm_watch`. It proves the packed 12-byte x86
epoll record, the `epoll_ctl` fourth argument in `r10`, and the `epoll_pwait`
`r10`/`r8`/`r9` path with BPF-verified temporary-mask pointer and eight-byte
kernel sigset size, plus bounded eventfd/inotify lifecycles. This direct static
leaf intentionally omits pthread cancellation and musl's pre-Linux-5.10
`ENOSYS` fallbacks. It is a private non-promoting artifact, not
event-descriptor-family closure: `epoll_pwait2`, timerfd, signalfd, fanotify,
AIO, watcher policy, libc.so, startup, allocator, loader, sysroot, family or
platform parity, and public x86 support remain unselected.

`./scripts/dev-x86_64.sh pathname-lifecycle-header-abi` adds an artifact-local
eight-profile C11/C++17 project-header/pinned-musl matrix for `fcntl.h`,
`stdio.h`, `sys/stat.h`, and `unistd.h` pathname declarations, LP64 types,
selected mode/`O_PATH` constants, and unmangled C++ references. The paired
`./scripts/dev-x86_64.sh libc-pathname-lifecycle` command records a separate
private `static-c-pathname-lifecycle` artifact in planned
`libc.posix-runtime`. Its pinned-musl and freestanding-static C fixture selects
only `chdir`, caller-buffer `getcwd`, `mkdir`, `unlink`, `rmdir`, `remove`,
`rename`, `link`, `symlink`, `readlink`, `chmod`, `fchmod`, and `truncate`.
It proves direct x86 syscall paths, `remove`'s raw-`EISDIR` retry,
zero-capacity `readlink`, and a live-`O_PATH` `fchmod` procfs fallback. The
no-allocation candidate intentionally rejects musl's null-buffer `getcwd`
extension with `EINVAL`. This remains a bounded private ABI/archive vertical,
not general pathname/canonicalization, directory, xattr/ACL, mount/namespace,
filesystem-family, C-runtime, AArch64-parity, or public-x86-support evidence.

`./scripts/dev-x86_64.sh libc-header-layouts-baseline` now adds one private
`static-c-header-layouts-baseline` artifact within still-planned
`libc.headers-layouts`. It composes the existing selected archive through a
project-header C fixture and a separately compiled freestanding C++17
companion, after both pass with pinned musl. The C++ entry has unmangled C
linkage and is called from C; the evidence rejects C++ runtime, constructor,
exception, RTTI, and dynamic-TLS paths while retaining only existing selected
C API references. It adds no export or installed-header edit, and is not
all-header closure, general C/C++ runtime support, libc.so, CRT, loader,
sysroot, family/platform parity, or public x86 support.

`compat/x86_64/headers-layouts-foundation.toml` is now the separate planned
v8 accounting contract for eventually closing that header family. It resolves
the 183 pinned-musl paths and eight project-only headers into exact classes,
names `sys/kd.h` -> `linux/kd.h`, `sys/soundcard.h` ->
`linux/soundcard.h`, and `sys/vt.h` -> `linux/vt.h` through one fixed Linux
5.10 x86 UAPI export: the source SHA-256, 935 exported-header count, and
derived header-manifest SHA-256 are owned by
`compat/upstreams.toml#linux_5_10_uapi` and independently checked in the image
and at runtime. Its 21-row `uapi-wrapper-matrix` resolves the three direct
wrappers across five C11 and two C++17 feature profiles through both pinned
musl and raw-GCC project-header-first roots, checking selected constants, ioctl
encodings, and x86 LP64 layouts. Its separate seven-row `ioctl-header-abi`
matrix resolves direct `sys/ioctl.h`'s signed `int ioctl(int, int, ...)`
declaration, C++ C-linkage spelling, selected `_IOC` composition, direct
8-byte align-2 `struct winsize`, and selected request values only; it does not
prove artifact linkage or generic device/request behavior. Its separate
seven-row `epoll-header-abi`
matrix resolves only `sys/epoll.h`'s packed x86 event record, selected
declarations/values, and the direct `_IOC`/`_IOR`/`_IOW` encoding subset from
`sys/ioctl.h`. Its separate 16-row `event-descriptors-header-abi` matrix
resolves the selected direct `sys/eventfd.h` and `sys/inotify.h` surface as
unconditional across default-C plus seven C11/C++17 profiles, with x86 LP64
`eventfd_t`/`inotify_event` layouts, selected direct constants, and
header-requested C++ C-linkage spelling. Both headers immediately include
`fcntl.h`, so it also records only `AT_EMPTY_PATH` as
GNU/BSD/default-C-visible and strict/POSIX/XOPEN-hidden, including macro-free
C++17; this leaves the global feature-visibility facet planned. Its separate
private `dirent-header-abi` matrix
(`./scripts/dev-x86_64.sh dirent-header-abi`) compares the project-header-first
candidate with pinned musl 1.2.6 across seven base C11/C++17 profiles and
four `_LARGEFILE64_SOURCE` profiles: GNU and strict C11/C++17. It checks only
selected `<dirent.h>` declarations, feature visibility, x86 LP64 `dirent` and
`posix_dent` layouts, and the C spellings requested by C++ declarations. The
fixed boundary includes C++ `extern "C"` declaration spelling, the `d_fileno`
compatibility spelling, GNU-only `versionsort`, and the large-file aliases:
strict LFS exposes the aliases without exposing `seekdir`/`telldir`, `getdents`,
or `versionsort`. `IFTODT`, `DTTOIF`, and `getdents` are GNU-or-BSD-visible,
while `versionsort` is GNU-only. The C++ `nm` inspection proves only
header-requested unmangled C names. This compile-only header slice excludes
actual archive linkage, directory-stream runtime behavior, header-family
completion or promotion, and public x86 support; full x86-64 parity remains
the stated promotion goal.
The separate private `libc-directory-streams` command
(`./scripts/dev-x86_64.sh libc-directory-streams`) adds one actual static C
runtime leaf after that header matrix: the same project-header C body runs
through pinned musl and then a `-nostdlib -static` `crabc-libc` candidate. It
checks only `opendir`/`fdopendir`/`closedir`/`dirfd`,
`readdir`/`readdir_r`/cursor operations, C-locale `alphasort`, and
`getdents`/`posix_getdents`, including 255-byte names, close-on-exec transfer,
raw record framing, and the x86 `openat=257`, `fstat=5`, `fcntl=72`, `mmap=9`,
`munmap=11`, `close=3`, `getdents64=217`, and `lseek=8` paths. The private
`DIR` state uses one anonymous mapping rather than selecting a C allocator;
`scandir`, `versionsort`, walking policy, broad collation, cancellation, and
the rest of C directory/POSIX runtime parity remain out of this leaf. It does
not complete either the header or POSIX-runtime family, change promotion
status, or establish public x86 support.
Its separate
35-row `timeval-transitive-header-abi` matrix
checks five fixed headers (`sys/time.h`, `utmpx.h`, `utmp.h`, `lastlog.h`, and
`sys/timex.h`) across seven isolated C11/C++17 profiles for complete
`struct timeval` visibility and named x86 LP64 embedded-record layouts only.
It does not require an identical private include graph or dependent feature
surface.
It excludes direct `sys/time.h` callable declaration/linkage, other
`sys/time.h` feature or macro parity, dependent-header callable linkage, and
runtime behavior. Its separate seven-row `sys-time-direct-header-abi` matrix
checks selected unconditional and GNU/BSD/GNU-only declarations, x86 LP64
`timeval`/`itimerval`/`timezone` layouts, interval-timer values,
timer/conversion macros, and C++ declaration C-linkage spelling. That spelling
check proves only the external name requested by a header declaration, not a
crabc artifact export. Its separate eight-row `access-header-abi` matrix
checks selected `access`/`faccessat` declarations, access and `AT_*` values,
GNU-only `eaccess`/`euidaccess` visibility across default-C and isolated
C11/C++17 profiles, and C++ declaration C-linkage spelling. It likewise
proves only header-requested names, not an artifact export. All seven are
compile-only evidence: callable linkage,
device behavior, all-header closure, runtime completion, family promotion, and
public x86 support all remain planned. Its live `candidate-header-closure`
diagnostic now resolves 1,337 rows across seven isolated C11/C++17 profiles
for all 183 pinned-musl paths and eight project-only headers. It records
exactly two auditable pinned-musl `reference-not-applicable` rows
(`aio.h:c11-strict` and `aio.h:cxx17-strict`), while requiring the candidate
arm to compile them. This verifies isolated empty-TU consumer closure only;
feature visibility, declaration/layout parity, callable linkage, runtime
completion, family promotion, and public x86 support remain planned.

The separate private `installed-header-tree-closure` artifact materializes the
same 191 candidate headers into a temporary `usr/include` tree and resolves
the same 1,337 empty-TU rows across `c11-gnu`, `cxx17-gnu`, `c11-strict`,
`c11-posix-2008`, `c11-xopen-700`, `c11-bsd`, and `cxx17-strict`. Its candidate
include traces reject repository `include/` source-tree leakage and every host
include path: only the temporary installed tree, raw-GCC builtin headers, and
the fixed Linux 5.10 UAPI root are admitted. The two pinned-musl strict
`aio.h` `reference-not-applicable` rows remain explicit, never a candidate
waiver. This is a header-tree closure artifact distinct from source-tree
closure, not full declaration, layout, feature-visibility, or linkage parity;
an archive/runtime artifact; CRT, loader, driver, or owned-sysroot evidence;
promotion; or public x86 support.

Fixed Rust mimalloc work is paused. Its AArch64 and private native x86-64
evidence remains preserved in [`native-mimalloc.md`](native-mimalloc.md),
[`docs/design/allocator.md`](docs/design/allocator.md), and
[`compat/allocator/README.md`](compat/allocator/README.md); the detailed
allocator checkpoint record below is retained context, not an active backlog.
The pause does not reopen allocator invention, emulation, or a generic
portability layer. [`COMPATIBILITY.md`](COMPATIBILITY.md) remains the generated
record of current compatibility evidence and measurements; it is not edited by
hand.

Within that allocator program, the direct native-engine owner-exit lifecycle
Gate 5C is complete: `allocator --full` executes the reviewed
[`native-owner-exit-lifecycle-v3.5.0.json`](compat/allocator/native-owner-exit-lifecycle-v3.5.0.json)
suite and records its source-shaped traversal/terminal-release evidence as
passed. Milestone 5 remains open because Gate 5D churn/stability and Gate 5E
selected shadow-ABI acceptance are still blocked; the C allocator remains the
default backend.

The Rust-owned Linux/AArch64 application CRT/sysroot is also complete current
evidence. `./scripts/dev.sh sysroot` produces two clean reproducible installed
trees with `crabc-cc`, Rust CRT objects, Rust compiler helpers, the canonical
crabc loader, and explicit source/dependency/link/artifact purity accounting.
`./scripts/dev.sh lua` consumes that installed tree for the pinned Lua
source-build gate; the static pthread/TLS gate and static integration fixtures
do the same. This completed boundary is documented in
[`docs/design/crt-and-sysroot.md`](docs/design/crt-and-sysroot.md). It is
precisely **CRT/sysroot** purity: the report keeps complete target-runtime
purity `blocked_by_native_allocator` until the separate mimalloc port replaces
the current `libmimalloc-sys` backend. The sole recorded native closure is the
pinned allocator source and its direct pinned `cc` compiler-discovery helper;
the sysroot audit rejects any other native production input, including
compiler-rt target objects.

The same native x86-64 profile has a 75-field direct C/Rust fundamental trace
that includes the fixed no-padding `mi_expand` nonzero null-pointer, zero-size,
below-half, exact-fit, oversize, and state-preservation cases plus checked
`mi_recalloc` growth/tail-zeroing, zero-product, and overflow-preservation
outcomes. This remains private engine evidence, not public allocator API or
AArch64 production evidence.

It also has one separate 25-field native C/Rust differential for two
live-owner remote-free publications from one quiescent `pthread` followed by
the pinned private owner false collector. It proves only the source-specific
owner-bit, LIFO, exact-used-count, and post-join local-list merge transition;
it is not general remote-free routing or concurrent collection, abandonment,
thread teardown, public `mi_*` API, libc integration, backend, or AArch64
evidence.

A separate 43-field native C/Rust differential now covers one live owner with
a non-abandoning full-medium arena page (10248-byte request, 12288-byte blocks,
capacity/reserved 42, eight slices) and one regular successor. A real pinned-C
`pthread` publishes exactly one remote `mi_free` and joins before owner
observation; false collection requeues the full page behind the successor,
then ordinary allocation exhausts the successor's remaining capacity and
reuses the exact remotely freed block. Rust uses only a joined scoped producer
for common typed private facts. This remains private native x86-64 engine
evidence only: it does not claim pthread/TLS ABI parity, generic remote
routing/collection, teardown, abandonment, public `mi_*` behavior or runtime,
libc integration, backend promotion, public x86 support, or AArch64 evidence.

A separate 35-field native C/Rust differential now covers one live owner with
a non-abandoning full-medium arena page (10248-byte request, 12288-byte blocks,
capacity/reserved 42, eight slices) and one regular successor. A real pinned-C
`pthread` worker frees all 42 first-page blocks, then `pthread_join()` completes
before the still-live owner observes the non-atomic remote list or invokes
`mi_heap_collect(heap, false)`. The false collector empties the full queue and
releases only the first page's PageMap span, ordinary arena bitmap, and eight
slices, while the successor remains regular and PageMap-published. Rust uses
only 42 joined, staged scoped test workers for shared typed private facts; it
does not claim pthread/TLS ABI parity, thread teardown, or broad remote-free
routing/collection. This remains private native x86-64 engine evidence only,
not public `mi_*` behavior or runtime, public x86 support, libc integration,
backend promotion, or AArch64 evidence.

The same native x86-64 profile separately has a 28-field C/Rust differential
for one real small direct-cache page filled to its current capacity, one
joined/quiescent `pthread` remote free, and the owner direct-cache miss falling
through the regular queue search to collect and reuse that exact block. Its
selected normal-release source API assessment also records per-item native
object/dynamic-symbol presence for 194 distinct C functions and marks 183
non-object source forms explicitly. A separate eight-field C/Rust differential
now covers one arena-backed mapped page's queue-detach abandonment and
same-origin nonempty `mi_free` reclaim/requeue transition. A separate 18-value
C/Rust differential covers one arena-backed, same-origin, one-thread nonfull
medium page. The pinned-C next same-heap allocation claims its exact
mapped-abandoned PageMap/ordinary-arena-bitmap-preserved page, clears
bitmap/count state, restores original-Theap association, and requeues it at
the regular tail; Rust models that claim/reassociation with its test-only
consuming handoff immediately before its matching third allocation. This is
private native x86 evidence only, not general or cross-thread
abandonment/adoption, public API/runtime behavior, backend promotion, public
x86 support, or AArch64 evidence. A separate
32-value C/Rust differential covers one arena-backed, same-origin,
same-thread/same-Theap nonfull 1024-byte direct-small page with two live
blocks. `_mi_page_abandon` clears its complete rounded direct-cache range while
retaining PageMap and ordinary-arena-bitmap registration; the pinned C next
same-heap `mi_heap_malloc_small` claims that exact mapped-abandoned page,
clears bitmap/count state, restores the original Theap, requeues at the
regular tail, restores the full range, and allocates the third block. Rust
explicitly consumes its private test-only handoff immediately before its
matching third allocation rather than making generic allocation scan abandoned
pages. This remains private native x86 evidence only, not general or
cross-thread abandonment/adoption, remote routing, lifecycle, public API/runtime
behavior, backend promotion, public x86 support, or AArch64 evidence. A separate
six-mode staged public-header gate compile-links selected C/C++ forms against
the pinned C release shared object, including one C11 compile/link-only probe
that instantiates the five base-header `*_csize` static-inline dispatch helpers,
and records all ELF identities. A further
two-mode static gate observes every selected static archive member and the
`src/static.c` override object's required symbols before C consumer
compile/linking. A separate native CMake gate configures, builds, and installs
the selected normal-release shared profile with Unix Makefiles and musl; it
records resolved cache/compiler selections, installed header bytes and manifest,
and shared-object ELF, SONAME, and dynamic-dependency identity. It does not
compile/link or execute a consumer, establish behavior or Rust implementation
parity, cover static/object or unselected CMake modes, or create public x86 or
AArch64 runtime support. A separate 13-field C/Rust differential covers one real C
full-medium arena page forced from the full queue to unmapped abandonment, then
through the `mi_free` threshold that republishes its mapped bitmap; its Rust
side exercises the same bounded real post-Theap-teardown full-medium route.
A separate 18-field C/Rust differential uses a real pinned-C worker `pthread`
to run `mi_thread_done()` and return; the consumer calls `pthread_join()`
before its two public `mi_free` calls. It records the selected mapped failed-reclaim/unown
transition and terminal checks for
`page_map_unregistered_after_final_free`,
`arena_page_bitmap_clear_after_final_free`, and
`arena_slice_released_after_final_free` on the exact eight-slice medium-page
span. Rust covers only one bounded process-owned mapped regular handoff after
teardown and directly observes its PageMap, ordinary arena-page bitmap, and
free-slice bitmap release.
A separate 21-field native x86-only C/Rust differential is a retired-page
prepass: a real worker-local `mi_free` retires one medium page, real
`mi_thread_done()` and `pthread_join()` force-release it before one distinct
live medium page is mapped-abandoned, and one consumer `mi_free` terminally
releases the live page. It records retired/local-retirement state, retired
teardown PageMap/ordinary arena bitmap/exact slice-span release, then live
mapped-abandoned and terminal PageMap/ordinary bitmap/exact slice-span release
plus an empty route. This is a narrow private native x86 engine antecedent and
does not claim general retirement, teardown, routing or concurrency, public
`mi_*` behavior, libc integration, backend promotion, public x86 support, or
AArch64 evidence.
A separate 25-field native x86-only C/Rust differential covers exactly two
distinct live nonfull medium arena pages in distinct bins. The real worker runs
`mi_thread_done()` and returns; the consumer calls `pthread_join()` before any
free. Both selected pages are mapped-abandoned after teardown. The consumer
frees the second page first and
records only its PageMap unregister, ordinary arena-page bitmap clear, and
exact slice-span release while the first remains PageMap-registered,
arena-bitmap-set, mapped-abandoned, and `used == 1`; the final consumer free
releases the first page and records an empty route. This is a narrow private
native x86 engine trace, not general teardown, routing or concurrency, public
`mi_*` behavior or runtime, libc integration, backend promotion, public x86
support, or AArch64 evidence.
A separate 46-field native x86-only C/Rust differential covers two distinct
clients on one nonfull medium arena page A plus a one-client medium arena page
B in a distinct bin. The real worker runs `mi_thread_done()` and returns; the consumer
calls `pthread_join()` before any free. Both selected pages are mapped-abandoned
after teardown. The first A free returns `StillLive`, preserving A, B, and the
route; the B free returns `ReleasedPage`, terminally releasing only B; and the
second A free returns `ReleasedAll`, completing the route. This remains narrow
private native x86 engine evidence, not general teardown, routing or
concurrency, public `mi_*` behavior or runtime, libc integration, backend
promotion, public x86 support, or AArch64 evidence.
A separate 53-field native x86-only C/Rust differential covers two distinct
clients on one nonfull medium arena page A plus a one-client medium arena page
B in the same bin. The real worker fills A before it creates B, locally
restores A to two clients, runs `mi_thread_done()`, and returns; the consumer
calls `pthread_join()` before every free. It proves the selected same-bin
queue count/link/saved-successor traversal before teardown and mapped-abandoned
count/bitmap transitions `2 -> 2 -> 1 -> 0`. A's first free returns
`StillLive`, B's free returns `ReleasedPage`, and A's second free returns
`ReleasedAll`. This remains narrow private native x86 engine evidence, not
general teardown, routing or concurrency, public `mi_*` behavior or runtime,
libc integration, backend promotion, public x86 support, or AArch64 evidence.
A separate 21-value native x86-only pinned-C/Rust differential now covers one
full arena singleton post-exit route: request 524289, 589824-byte block size,
capacity/reserved 1, nine arena slices, real C `mi_thread_done()` and
join-before-terminal-consumer-free ordering, source unmapped/unowned/detached
state, all-nine-slice PageMap and ordinary arena-bitmap preconditions, and
terminal PageMap/bitmap/slice cleanup. Rust observes a scoped test worker and
join while comparing only matching common typed private owner-exit facts,
distinct from the Rust-only route. It does not establish crabc pthread/TLS
callback parity, general lifecycle/routing/concurrency, public x86/crabc
API/runtime, backend promotion, or AArch64 evidence.
These bounded results do not claim general routing or concurrent collection,
general behavior or Rust implementation parity, a Rust full-medium route, general
abandonment/adoption, cross-thread reclaim, general thread teardown, CMake
unselected-mode coverage, consumer execution, public API/runtime support, libc integration,
backend promotion, public x86 support, or AArch64 evidence.

The allocator program currently has one bounded executable vertical slice:
an explicit pinned default theap can allocate, reallocate, and locally free
small, medium, large, singleton, aligned, and offset-aligned blocks from a
caller-managed external arena and page map. Large alignments use separately
owned OS singleton mappings below the source's 256 MiB metadata limit, with
allocation-free retry ownership when an injected terminal unmap fails. The
slice includes checked counted allocation, full-page retention, retirement,
and one private linear scoped `RemoteFreeProducer` for an exact active matching
regular non-huge-bin or `BIN_FULL` allocation. Its exclusive owner borrow
prevents safe allocator mutation while a scoped `Send`/`!Sync` worker may
publish the canonical block or cancel back to the original client pointer.
After caller-proved joined/quiescent publication, regular generic search
(including a small direct-cache miss) consumes the remote list before extension
or full classification, and the non-abandoning full-page pass consumes it
before exact release-or-unfull. Every non-abandoning move to `BIN_FULL` also
performs the source's post-enqueue false-force collection. Detached metadata
sessions have no remote producer path and perform only the local false-force
portion. Any false-force collection error permanently poisons this private
allocator, retaining the exact page, error, and any already-popped block; all
later allocation, inspection, free, producer preparation, and collection
entry points reject without further queue or page-map mutation. This bounded
slice also retains unregister-before-release and injected rollback. Unpinned
external arenas now schedule the pinned 4-second `purge_decommits=1` path
before slice reuse. Forced collection claims the free bitmap while applying a
non-owning decommit, preserves the external mapping owner, and retains retry state after
an injected decommit failure. The ordinary allocator gate
matches 447 Rust-owned layout/configuration values, 378 address-independent
small-allocation trace values, and 51 fundamental-operation values against
exact pinned C v3.5.0. The native x86-64-only 75-field expansion extension
recorded above does not revalidate this AArch64 production-oriented result.
A standalone default-off test package now exports 16
strictly prefixed `crabc_test_*` symbols, passes the existing crabc allocator
fixture, and passes 33 reviewed checks from pinned upstream `test-api.c` in an
explicit creating-thread lifecycle. It exports no `malloc`, `mi_*`, or other
production allocator symbol. Separately, the bounded production metadata-owner
prerequisite from `src/subproc.c:19-88` now has one process-static detached
theap backed by direct OS page-map and external-arena bootstrap state. It
requires a caller-supplied frozen `MemoryConfig`, checks a live AArch64 thread
pointer before its private lock, preserves `MemoryId::Malloc` owner-bound
capabilities, and leaves compiler-TLS roots untouched. It supports zeroed and
aligned zeroed allocation, source-ordered replacement, and serialized
cross-thread free, with deterministic retryable and retained initialization
failure states. It neither attaches a live TLD/theap nor implements the
source's null/needs-no-free/non-Malloc release paths. This is not a production
backend or readiness claim. The active allocator scope includes the exact AArch64
16-bit-index/48-bit-generation TLS key and caller-owned slot contract, its
older caller-storage registry substrate, and one allocator-owned process-global
regular-key registry; five private compiler-TLS roots with direct `TPIDR_EL0`
identity; live-owner and
abandoned-page remote-free head transitions; one private scoped active regular
or full remote producer and caller-proved joined/quiescent false-force regular
candidate/full-collection paths (with the detached no-remote local branch);
a one-page mapped/unmapped
abandonment/adoption protocol with failed-reader bitmap restoration,
clear-once-set quiescence, and the failed-reclaim expected-head/unown tail; an
unsafe current-thread-only regular TLS backing
owner; one bounded source-order process-main initializer; one ticket-zero
process-static main heap/default-Theap attachment; one no-page later-thread
attachment to that shared main Heap; one process-static page-map root
publication owner plus one caller-selected, process-shared single-arena
sidecar; bounded ticket-zero and later-thread page engines over that matched
process pair; one all-free later-main thread-exit drain; nine sole-page
later-main owner-exit handoffs (a full arena singleton, an OS-aligned
singleton that links through `Heap::os_abandoned_pages` and removes that list
member before clipped PageMap/alias/metadata/mapping release, a mapped medium page
with one live block, full medium and full large `BIN_FULL` pages plus full
non-direct-small and direct-small regular-bin pages that remain unmapped until
their mostly-used free boundary then reabandon to the static-main bitmap, and a sole nonfull
small-or-medium page whose process-owned route survives old-Theap/TLD teardown,
and a separately bounded exactly-two-block large page whose complete 64-slice
PageMap span and leading static-arena bit survive until its second client free,
including exact full-medium, full-large, full-non-direct-small, and
full-direct-small predecessors where one joined remote free is force-collected
before immediate mapped publication (the medium and large pages remain in
`BIN_FULL`; the non-direct-small page remains in its ordinary bin with every
direct slot empty; the direct-small page remains in its ordinary bin until its
rounded direct-cache range is cleared during removal));
The historical direct-test suite also covers seven later-main full-page
aggregate post-exit routes: full arena
singleton, full OS singleton, full-medium, full-large, and bounded mixed
medium/large `BIN_FULL` members, plus full non-direct-small and direct-small
members across ordinary bins. The
arena singleton route admits each member's own rounded
`PageKind::Singleton` size with `reserved == used == 1`; the non-direct route requires
`SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE` and every direct slot empty;
the direct route requires `block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, and
the complete direct-cache image naming every populated queue head. The direct
route advances each affected range before its page-count detach and uses
free.c's partial collector; both retain one exact arena slice per member.
Alongside them is one aggregate
regular-pages post-exit registry that can route every qualifying surviving
regular small, medium, or large page through sequential client frees. No full
aggregate keeps a separate raw member registry: each later free re-resolves
its PageMap member. The OS aggregate's private Heap list deliberately reuses
member links until that exact free removes them. The arena singleton aggregate
must take the raw empty failed-reclaim result
and has no static-main abandoned bitmap/count pair; every regular aggregate
independently crosses the source unmapped-to-mapped threshold under its exact
static-main bitmap/count pair, while the large route also proves
each terminal member's complete 64-slice span. When the completed nonfull
aggregate traversal itself
releases every other member and leaves exactly one initial nonfull medium with
an immediate local head, it returns the existing one-page mapped route before
registry construction. A registry that sequential client frees later reduce
to exactly one mapped regular member, with no arena or OS singleton tail, can
also cross one explicit source bitmap claim into a fresh later-main engine;
the opaque selected client never becomes a stored page identity, and no
residual route survives the long PageMap lease. Aggregates with multiple
members, source-unmapped/full/singleton tails, scans, fallbacks, and concurrent
reclamation remain sequential client-free-only. The former pointer-private
runtime ledger and `TicketZeroOwnerExitFreeRoute` are now `#[cfg(test)]`
historical oracles. Selected native post-exit operations derive their source
from the supplied pointer and use PageMap/W03 and abandoned-state behavior;
they do not retain A's admission through B's teardown. A fresh later-main owner can
explicitly reclaim a sole mapped medium route that began owner exit nonfull, or a sole
direct-small route that retains an immediate local free block, the exhausted
fully committed scalar-extension shape, the exact exhausted prefix-covered
extension shape, or the exact exhausted on-demand page-area-commit shape after
source collection; all force-collected full-origin predecessors remain
sequential client-free-only. The reserved fixtures cover both medium and
direct-small prefixes, prefix-covered direct-small reuse without a direct
commit, direct page-area commitment, and failed-commit mapped reabandonment
before a same-candidate retry; non-direct-small, malformed or out-of-profile
no-immediate direct-small metadata, and aggregate registry members outside the
separately recorded final mapped-regular edge remain sequential client-free-only.
The regular owner uses the process-static metadata allocator for the exact
flexible `mi_thread_locals_t` request, source growth rule, header-before-root
publication, generation-checked regular slots, and free-before-dynamic-root-
null teardown. It leaves fast/default/cached roots alone and becomes terminal
after an internal metadata error whose consumption cannot be distinguished,
rather than claiming a false retry capability. The allocator-owned registry
uses the selected main subprocess's aligned Malloc metadata route for one
retained typed bitmap image (plus one temporary replacement while locked),
grows by 1,024 bits through the 64,512-bit/63-block source ceiling, and keeps
`BitmapView` transient under its private registry lock. Ordinary claim uses
`tseq = 0`, advances generation
only after a one-bit claim, and copy growth preserves old claims before marking
only the appended range free. Linear leases require explicit release; bounded
shutdown refuses live leases and late access without writing compiler TLS or
attaching a key to a thread. Allocation failure before commit preserves state;
typed-image invariant or post-commit ownership ambiguity terminally poisons
with retained process-static ownership. This is not the source's full process
shutdown, fast-key management, or key-to-thread integration. Separately,
`subproc.rs` holds one bounded process-static main-subprocess identity: only
relaxed `thread_total_count`, relaxed live `thread_count`, the real first
static TLD slot, and a Rust-only first-ticket selector—not full
`mi_subproc_t`, its heaps/arenas/stats, or a general process-init API. The
unsafe current-thread TLD owner receives an old-counter-value ticket only after
that selector chooses the generic branch; static startup reserves ticket zero
instead. Metadata failure consumes a later source sequence but never a live
registration. The generic TLD image records the same main identity as detached
metadata bootstrap state and its selected arena registry/published arena,
direct `TPIDR_EL0`, Linux NUMA, the exact Unix non-threadpool result, a null
theap list, and exact provenance. It remains **subprocess-attached, no-theap**.

`process_init.rs` is a deliberately bounded source-order coordinator. After a
pure root/current-thread preflight, it reserves static ticket zero, initializes
the static `Heap`, prepares detached metadata without exposing metadata's
private map/arena, publishes the distinct process PageMap, and then attaches
the static TLD/Theap roots. Its `ProcessMainReadyLease` is immutable and it
does not choose options, reserve the process-shared arena, initialize
pthread/TLS keys, route allocation/free, or implement shutdown/fork.
Preflight failure remains cold; every failure after static selection retains
the process image rather than reopening ticket zero.

`runtime_lifecycle.rs` is the intentionally smaller production bridge over
those no-page owners. `__libc_start_main` invokes it after initial TLS and the
stack guard but before constructors, retaining the ticket-zero owner and its
main-thread-minted `MainStaticHeapLease` for the process lifetime. A pthread
child attaches before its user routine; its parent waits for that result and
returns `EAGAIN` if attachment fails. Normal return, `pthread_exit`, and
cancellation finish only after libc cleanup and TSD destructors. The bridge
itself exposes no C symbol, uses no pthread key, routes no C allocation, and
leaves `libmimalloc-sys` as the active backend with its existing private key
outside the 128-key application capacity. The main owner is retained at normal
exit. On libc's direct `fork` path, a private allocation-free gate first
excludes later bridge owners. It preserves the copied original ticket-zero
`TPIDR_EL0` image only when that admission count is zero and the ticket-zero
owner is either still cold or has returned to `AwaitingFreshPage` or
`DormantExistingArena`, with no live native client or PageMap operation. That
child resets the copied gate and may reactivate the dormant owner or attach a
fresh pthread. Any other child disables the bridge without attempting lock,
root, pointer, page, or general fork repair.

The adjacent permanent ticket-zero page owner remains outside that production
bridge. `compat/allocator/runtime-ticket-zero-adapter` is a separate `no_std`
C evidence staticlib, not an installed or selected libc
interface: in one fresh process it exports only nine prefixed operations
(init with `AT_PAGESZ`, a scalar lifecycle audit, malloc, zalloc, realloc,
free, a retained narrow worker witness, a persistent mixed-local worker
witness, and a bounded live-owner remote-free witness)
against that exact owner. The mixed witness
keeps one page engine through simultaneously live small, medium, large,
singleton, and multi-page singleton blocks; frees and reissues local
small/medium requests; then frees every block before normal attachment
teardown. Those mixed-local and live-owner remote-free calls now use the
runtime's typed `READY -> BUSY -> READY` operation; their C ABI remains
unchanged. The remote witness makes a fresh worker A fill one small page, then
starts B/C with opaque publication capabilities for two distinct blocks; after
both join, A's ordinary allocation collects and reuses both blocks before it
tears down. The remaining exact-client owner-exit narrative in this section is
historical `#[cfg(test)]` provenance only: it describes neither current
production behavior nor a C adapter export. Current post-exit free,
reallocation, and usable-size start from the supplied pointer and use PageMap/
W03 or abandoned-state operations; the C fixture schedules only mixed-local
and live-owner remote-free workers. Its Rust state audit proves PageMap registrations, arena ownership,
permanent process/page-owner state, every static-main abandoned count, and the
private OS-abandoned list stay at the retained process baseline while live-TLD,
caller-visible metadata-capability, and later-Theap counts return to baseline
across repeated mixed-local and live-owner remote-free workers. Each mixed audit now attaches and retires B after it
consumes A's opaque route, explicitly holding two admissions, releasing B's
own claim after that finish, and releasing A only from the terminal proof;
both owner-exit metadata high-water marks plateau
after warmup. The C
fixture proves the same repeated pthread boundary, same-arena ticket-zero
reactivation, and successful-path `errno` preservation; its `allocator
--churn` lane executes its two scheduled mixed-local and live-owner
remote-free workers exactly once per 128 bounded C cycles, in a deterministic seed-shuffled order
(`0xd1b54a32d192ed03`) in one fresh process under a 30-second watchdog without
widening the C ABI. Its mixed
owner-exit witness keeps a direct-small page, a non-direct-small page, two
distinct `BIN_FULL` medium pages, a one-client force-empty large page, a
distinct two-client live large page, one live arena singleton, and one live
OS-aligned singleton in one mixed regular workload: one medium has an opaque
pre-exit remote free that source collection makes nonfull, while the
force-empty large page's sole opaque remote client makes that page empty and
releases it during the same traversal; the other full medium remains
source-unmapped. The arena member stays PageMap-only through its raw-terminal
tail, while the OS member stays in the static main Heap's private list through
its clipped-mapping tail.
It moves the combined post-exit route to one joined fresh B without exposing
client addresses. After every regular, arena, and OS member releases, B
completes its own no-page runtime attachment; only that completed B lifecycle
may return A's final typed PageMap-release proof for its worker-admission
claim. On B's first direct post-exit free of an existing direct-small client,
or of one of three remaining clients on the pre-exit-normalized mapped,
non-full medium page, B first claims the source low owner bit and then issues
joined C and D the matching nominal scoped producers for two distinct
same-page private clients. C and D atomically publish them in separate joined
turns; B's existing collector consumes the resulting two-node remote chain
before B may unown or terminally release the page. The direct runtime
regressions pause after the opaque route transfer and prove ticket zero remains
unavailable until B returns that proof; the eight-cycle audit and prefixed C
fixture execute the existing direct-small bounded B/C/D handoff. A missing or
mismatched publisher retains its route rather than falling through B's
ordinary no-page finalizer. A retained route or poisoned wake retains the
process boundary and its exact admission claim. The direct-only
`native_post_exit_failed_os_release` witness makes B's next OS source `munmap`
fail after that same mixed aggregate has detached. It proves the exact free
returns `Retained`, the stable post-exit entry stays terminal after B completes
its own no-page finish, and ticket zero remains unavailable because A's parked
route token and admission claim have no terminal proof. Clearing the injection
cannot create a retry or a fallback. A scalar-only audit proves B's ordinary
finish removes only B's own admission claim while A's exact retained claim
remains counted; the matching successful route reaches zero only after B
consumes the typed completion. The separate
sole-medium witness leaves A with two private medium
clients and one returned local free; source exit collection makes the route's
immediate head before A's Theap/TLD tears down. Its opaque route gives joined B
only the source route, paired process state, and A's admission. B attaches,
adopts and uses the exact page, frees and drains every A/B client, and finishes
its page engine and attachment before its typed proof can release A's claim.
The focused direct-small reclaim witness likewise suspends A's live engine
into `ThreadLifecycleSlot`, but enters the existing
`abandon_mapped_small_or_medium_to_process_route` source boundary: that
boundary validates and clears its rounded direct-cache image plus immediate
local head before B receives the same opaque adoption route. All three active
owner-exit witnesses invoke the ordinary post-destructor finish dispatch; it
resumes only the exact prepared owner. The TLS slot also has one active
generation-checked `CurrentThreadPageOwnerSession`: its private handle resumes
and re-parks the same engine across ordinary allocation, local-free, and
joined pre-exit-publication operations while its bounded linear ledger remains
in TLS. Its consuming `prepare_sequential_exit` transfers every still-local
entry into the typed route without a workload-shaped client list;
source-published entries remain with source collection. For either bounded
source-valid B/C/D interleaving it may instead move exactly three
generation-checked opaque keys and their direct-small or mapped-medium kind
into the scoped post-exit publication group, validating all three before the
transfer can change the parked session ledger. The fixed preparation
path follows the same accounting rule: every allocation must be locally
freed, joined-published before exit, or transferred exactly once into the
route; omitted, duplicate, and over-capacity sets reject before suspension.
An active session with no locally live client takes its own page-drain/
attachment teardown before it releases A's admission: locally freed entries
are already free, while joined source-published entries are force-collected
there before the all-free test. A live session does not permit A to fall
through the no-page finalizer, and neither does a typed post-exit route or its
admission claim. Isolated source-published-session regressions warm ticket
zero, publish either one or two joined private clients, and prove that normal
finish force-collects them before it tears down A and reopens ticket zero.
When a joined source-published client coexists with a distinct live native
client, the native finish still selects the typed route for the live subset:
the source drain consumes the published head before A detaches, and only B's
terminal route proof plus B's own finish releases A's admission. The direct
`native_source_published_live_owner_exit` regression proves that split. Its
selected-C companion
`native_mimalloc_source_published_live_owner_exit_test.c` makes the same
boundary observable through the shadow ABI: B publishes the direct-small
client, fresh C frees only the surviving medium client, and C's normal finish
is required before the initial owner can resume.
The selected-C
`native_mimalloc_post_exit_source_published_successor_test.c` composes that
boundary with B's held terminal proof for an earlier A route: B's own
source-published small client stays with B's source drain while its distinct
medium client enters B's successor route. B's teardown then settles A's proof;
fresh C must terminally free and normally finish B's medium route before
ticket zero resumes. It remains a serialized exact-address witness, not a
general route chain.
The selected-C
`native_mimalloc_post_exit_source_published_all_free_proof_test.c` covers the
complementary no-successor composition: D source-publishes B's only small
client, B terminally frees A's routed medium, and B makes no further allocator
operation. B's typed all-free drain and own teardown complete before it
settles A's proof, after which ticket zero can resume. No B client is exposed
through another route.
While B holds that proof, its local client set is frozen: native allocation
and local `realloc` replacement return unavailable, while an exact local
`free` remains available to complete B's source-defined exit. The direct
local-session regression preserves sentinel bytes across the refused
replacement before it proves the later successor or all-free completion.
The selected C pointer-refusal fixture verifies that a valid foreign request
maps to `ENOMEM` while preserving A's original client and bytes until generic
pointer-first free. It then keeps B-local replacement coverage through B's
TSD destructor, which reallocates and frees B's existing local client before
B's native all-free finish can settle A's proof. B exits through
`pthread_exit`: its cleanup handler makes and frees a new local allocation,
then the TSD destructor continues B's local client before freeing it. The same
selected fixture also proves normal return runs the TSD destructor without a
cleanup handler and repeats the cleanup/TSD ordering through deferred
cancellation at a real cancellation point.
The retired-page session regression separately leaves a normal direct-small page
locally free and retired while one medium client stays live in another source
bin. Its prepared aggregate route releases that retired span before B receives
the remaining opaque medium route. Before B can attempt the existing
final-member reclaim, A records the page's immediate local-head fact while it
still owns the engine; without that private fact B takes ordinary sequential
free, avoiding an irreversible post-claim retention. B's terminal route proof
and independent attachment finish still gate A's admission release and
ticket-zero reactivation. The direct-small path has a held-route Rust lifecycle regression plus eight direct-small
normal-finish/reclaim cycles; its integration test also shuffles all eight
core pointer-private lifecycle routes for eight epochs
from seed `0x9e3779b97f4a7c15` and proves ticket-zero reactivation after each.
The state audit and existing prefixed C reclamation symbol alternate the
direct-small source with the sole-medium source without exposing a
direct-specific C ABI. Those bounded witnesses do not make it a general
later-thread reclamation route. The opt-in `allocator --soak` lane repeats the
same two-worker C schedule 1,024 times from seed `0x94d049bb133111eb` under a
180-second watchdog: two routes per cycle and exactly 2,048 route invocations.
Only a completed run with byte-identical clean Git source states before its
pin, contract, and header reads and immediately before publication atomically
replaces
`.work/reports/allocator/runtime-ticket-zero-soak-1024.json`; it does not
write the shared allocator `latest.json`. The format-1 stable report retains
the live contract digest, pinned archive, adapter archive/shared library,
fixture, oracle/target identity, commands, schedule, and all 13 scalar audit
fields. It re-attests the fixed raw contract/archive/adapter/fixture paths
without symlink indirection, binds the fixture executable/build inputs to those
records, and requires a live pin-matched annotated-tag cache. Every later
cycle and the final ticket-zero allocation/free must match
the first complete cycle's process/page-owner readiness, PageMap
registration/capacity, arena registry, live-TLD, metadata, shared-Theap, and
regular/OS-abandonment baseline. The audit exposes no pointer, page, route,
allocator, or release capability; the separate native-shadow registry
high-water remains owned by the focused Rust regression. This report remains
bounded stability evidence: the current M5 gate does not consume it, it
unblocks no gate, and it establishes neither a selected/default libc backend
nor general cross-thread/post-exit, upstream pthread, or large-object
acceptance. `allocator --full` additionally runs one
separate source-derived pinned `test/test-stress.c` route through the same
16-symbol test adapter: `NTHREADS=1` and fixed `1 1 2` inputs keep the
upstream allocation/cookie/realloc/retained-transfer cleanup workload on the
creating thread. The patch rejects libc, heap, theap-walk, subprocess, leak,
and large-object modes, and the source scheduler creates no pthread. It is
preliminary scalar upstream stress evidence, not acceptance of upstream
cross-thread transfer, remote-free, thread recreation, or Gate 5D. Its
symbol audit rejects
normal `malloc`/`free` and `mi_*` exports. The permanent session and
arena remain retained after that handoff, so it has no shutdown,
concurrent/general later-thread route, fork repair, pointer-domain fallback,
or backend-promotion meaning.

The same private runtime module also has one lower live-engine scheduling
regression that is deliberately separate from the typed post-exit route
variants in `ThreadLifecycleSlot` and from the C adapter. A later worker may split a live ordinary engine into
an attachment-bound, non-sendable parked token; the runtime moves only
`READY -> BUSY -> PARKED`, continues to reject ticket-zero activation, admits
one all-free non-parkable B operation as `PARKED -> BUSY -> PARKED`, and lets
only A reassemble its exact engine through `PARKED -> BUSY -> READY`. The
tokens carry no client address, raw PageMap, detached-owner finalizer, or
general worker scheduling authority. Drop and unrecoverable handoff failures
retain the permanent page owner.

`main_theap.rs` is the sole static-TLD exception. It owns one private,
process-static owner whose aligned/address-stable `Heap` and default `Theap`
field slots are current-thread-only (`!Send`/`!Sync`). The coordinator splits
static Heap foundation from ticket-zero attachment so the PageMap stage sits
between them. It preflights dynamic as its immutable empty image, fast as null,
and default/cached as the empty Theap before it consumes ticket zero; rejection
therefore does not advance the counter or touch metadata/mapping. Its main
`Heap` uses kind-only `_mi_memid_create(MI_MEM_STATIC)` provenance (zero
union/flags); the TLD and Theap retain concrete pinned/committed static image
memids. It preserves `_mi_theap_init`'s
copy/TLD/refcount/subprocess/options/TLD-list/random-cookie/Release-heap/
heap-list order, then publishes default followed by fast. Cached and dynamic
remain empty. A busy freshly owned TLD/heap list, subsequent list-attachment
failure, or post-mutation private unlock error is terminal
initialization-invalid-owner handling: the already registered static TLD and
live count remain in process-static storage, roots remain pristine when the
TLD-list attach fails before publication, and no teardown owner is returned.
After exact live-root ownership validation, teardown checks zero pages as a
Rust pre-mutation invariant; that rejection preserves every live
root/list/image and registration. After that check passes, the valid path
matches `_mi_thread_done`'s `src/init.c:448-481` call order: it clears fast
through `_mi_thread_locals_thread_done`, then clears default/cached and
detaches heap then TLD lists under their locks, Release-clearing `theap.heap`,
clears links/TLD/random/cookie/subprocess,
invalidates and quiesces the TLD, then releases live registration and
terminally retires the static TLD slot. A post-root-reset private lock/list
failure, including a post-mutation unlock error, requires invalid concurrency
or a kernel/private-lock failure outside the valid owner contract. It is a
terminal invalid-owner state that retains process-static storage and its live
registration rather than retrying or claiming completed teardown. The
represented `Heap` ends at the source `memid`; its abandoned fields remain
valid zero/deferred state, while one separately bounded static page owner may
install an arena's in-place `pages_main` in its source arena-pages table. This
is not a full C-size or heap API claim.

`main_heap_thread.rs` separately owns the source ordinary later-thread
`_mi_thread_init_with_heap(mi_heap_main())` attachment. A borrow-tied lease
serializes short projections of the live static main Heap; each later owner gets
a nonzero metadata TLD and metadata Theap, links it to that heap, and publishes
default then the fixed fast slot while dynamic remains the immutable count-zero
backing and cached remains empty. It allows overlapping later attachments and
gates static teardown on their linked membership. `main_heap_page.rs` may borrow
one such current owner alongside a matched process map/arena pair: it uses the
same static Heap and the arena's in-place `pages_main`, holds the one map
lifecycle through allocation/free and a joined scoped producer, then returns to
the existing post-user-destructor teardown. It can also consume that engine
into one post-fast-slot exit drain: after user destructors it clears the fixed
fast slot, force-collects every queue (including full), and releases only pages
that become all-free through PageMap removal -> `pages_main` clear -> metadata
retirement -> slice release. The pass continues beyond an earlier live page,
then retains that post-fast-slot owner instead of queue-detaching or abandoning
the general live page. Eight explicit sole-page exceptions remain after
fast-slot clear, each requiring no other queue/direct/page state. The full
one-block arena singleton false-collects, detaches, and unmapped-abandons while
retaining its PageMap lifecycle and registration through its exact final client
free; that failed-reclaim empty result performs PageMap removal -> `pages_main`
clear -> metadata retirement -> slice release. The OS-aligned singleton
exception permits the source `BIN_HUGE` route while remaining semantically full,
even for a small ordinary block size: it links its one `MemoryKind::Os` page in
`Heap::os_abandoned_pages` before unown, removes it before clipped PageMap ->
alias -> metadata -> mapping release, and retains an injected failed-unmap
owner terminally. It provides no OS-list search, reuse, or general routing.
The separate medium regular page exception requires `reserved > 1` and `used == 1`, force- then
false-collects, detaches, and publishes its exact main
`pages_abandoned[bin]` bit plus paired `Heap::abandoned_count[bin]`. Its final
client free takes only the source mapped empty-before-reclaim outcome, clears
that bit/identity, consumes the paired count, and performs the same terminal
release; a still-live result is terminally retained rather than reclaimed or
requeued. Normal full medium and full large `BIN_FULL` exceptions force- then
false-collect, queue/page-count-detach, and deliberately become ordinary
unmapped abandonment before old-Theap/TLD teardown. Their separately bounded
one-joined-remote predecessors collect exactly one free while remaining linked
in `BIN_FULL`, then the same removal clears the full flag and immediately
publishes the mapped bit/count pair; the large mapped route retains its full
64-slice terminal-release proof. The full non-direct small exception follows
the normal unmapped tail but detaches from its ordinary small size bin, requires
`block_size > SMALL_SIZE_MAX`, has no direct-cache range, and uses the ordinary
failed-reclaim collector. The full direct small exception is the complementary
ordinary-bin shape: it requires `block_size <= SMALL_SIZE_MAX`, `reserved >=
16`, `used == reserved`, and the complete rounded source direct-cache range
with every other slot empty. Queue removal clears that range before page-count
detach. Its partial collector retains the just-published atomic head, so the
source free count has its one-head lag before the same below-mostly-used
reabandonment decision. Their normal sequential client frees remain unmapped through
`free <= reserved / 8`; the first
below-mostly-used free publishes the exact static-main `pages_abandoned[bin]`
bit plus paired `Heap::abandoned_count[bin]`, and the mapped tail preserves
that pairing until the same terminal release. The full-large route validates
its complete 64-slice span before release. Separately,
`abandon_full_singleton_pages_to_process_route` accepts only two or more full
arena `PageKind::Singleton` members in `BIN_FULL`; each has its own rounded
block size, `reserved == used == 1`, zero retirement countdown, empty local
free list, exact paired-arena span, and every direct slot and other queue
empty. Source force -> false collection then detaches and unmapped-abandons
every member before old-Theap/TLD teardown. Later canonical client frees
re-resolve and validate PageMap membership without a raw list or static-main
bitmap/count pair, take only the raw empty failed-reclaim outcome, and release
one member in PageMap -> `pages_main` first-bit -> metadata -> arena-slice
order. Sole pages, OS or other non-singleton members, allocation-time
adoption/reclaim/requeue, scanning, and concurrent routing remain absent.
Separately,
`abandon_full_os_singleton_pages_to_process_route` accepts only two or more
`MemoryKind::Os` singleton members in `BIN_FULL`, each with its own rounded
block size, `reserved == used == 1`, zero retirement countdowns, empty local free lists,
valid clipped PageMap/alias release images, every direct slot and other queue
empty, and an initially empty static-main `Heap::os_abandoned_pages` list.
Source force -> false collection -> full-queue/page-count detach -> private
OS-list insertion -> unmapped unown runs for every member before old-Theap/TLD
teardown. Full-queue removal clears `PAGE_IN_FULL_QUEUE`, while the private
list deliberately owns the page's raw intrusive links until an exact later
client free removes that member. Each free re-resolves PageMap membership,
takes only the raw empty failed-reclaim outcome, then releases that one member
in private-list removal -> clipped PageMap -> aliases -> metadata -> mapping
order. A sole page, non-OS member, nonempty initial private list, list
traversal, retry/reclaim/requeue, allocation-time, and concurrent
routing remain absent; collection failure retains the drain and failed `munmap`
retains its `OsAlignedPageOwner` terminally. Separately,
`abandon_full_medium_pages_to_process_route` accepts only two or more full
arena medium members in `BIN_FULL`, each with an independent rounded block
size/bin, every direct slot and other queue empty, zero retirement countdowns,
and an exact paired arena span. Its source force -> false collection then
detaches every member and leaves each source-unmapped before old-Theap/TLD
teardown. Later client frees re-resolve PageMap membership without a raw list,
claim the member low owner bit, then choose that member's exact static-main
bitmap/count capability and unmapped or mapped tail. They release one member at
a time through PageMap -> `pages_main` -> metadata -> slice; a sole full page
rejects before mutation. The separate
`abandon_full_large_pages_to_process_route` has the same bounded aggregate
shape only for `PageKind::Large`: every member has one exact 64-slice
arena/PageMap span, and terminal release proves that complete span before the
same PageMap -> `pages_main` -> metadata -> slice order. The medium route
rejects a mixed class while the large route keeps its large-only full queue
with per-member bins;
neither exposes adoption, reclaim, requeue, allocation-time, or concurrent
routing. Separately,
`abandon_full_non_direct_small_pages_to_process_route` accepts two or more full
arena `PageKind::Small` members across ordinary bins, each with its own
`SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE` and static-main bin, zero
retirement countdown, empty local free list, and exact paired-arena slice.
Every direct slot and `BIN_FULL` must be empty, and no other page class may
occupy a populated ordinary bin. It preserves force -> false collection,
ordinary-bin removal with the proven no-op direct-cache update, page-count
detach, and ordinary unmapped abandonment. Its normal-collector client-free
tail re-resolves each PageMap member, claims its low owner bit before selecting
only that member's paired bit/count and unmapped or mapped tail, and releases
one member at a time. A sole page, direct-small geometry/cache image, mixed
class, or collection failure refuses or retains the route; it grants no
direct-small partial-head, adoption, reclaim, requeue, scanning, or concurrent
authority. The corresponding full non-direct-small and
direct-small aggregate is instead admitted only by
`abandon_full_direct_small_pages_to_process_route`: two or more full arena
`PageKind::Small` members in one ordinary bin with the same rounded
`block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, zero retirement countdowns,
empty local free lists, and one paired-arena slice each. Its complete rounded
direct-cache range names the current ordinary-queue head while every other
direct slot and queue is empty. It preserves force -> false collection,
ordinary-bin removal, direct-cache-head advance before page-count detach, and
ordinary unmapped abandonment. Later frees re-resolve one PageMap member at a
time, keep the partial collector's just-pushed expected head through the source
accounting lag, then independently publish/release only that member's paired
bit/count and one-slice span. Sole pages, stale/mixed cache images, non-direct
geometry, mixed bins/classes, collection failures, adoption, reclaim, requeue,
scanning, and concurrent routing refuse or retain the route. The corresponding
full non-direct-small and
direct-small one-joined-remote predecessors remain linked in their ordinary
bins while force collection makes them nonfull; the former keeps its empty
direct image, while the latter clears its rounded direct range before
page-count detach. Both immediately publish their mapped bit/count pairs and
remain client-free-only through terminal release. The sole nonfull small-or-medium
process route preserves the same
mapped publication, tears down the old Theap/TLD, and routes its linear client
frees through short PageMap access. A separate client-free-only large route
requires exactly two live blocks and retains its complete 64-slice PageMap and
`pages_main` span until the second free. Its sole mapped medium member, or its sole
direct-small member with an immediate local free block, the exhausted fully
committed scalar-extension shape, the exact exhausted prefix-covered extension
shape, or the exact exhausted on-demand page-area-commit shape after source
collection, may instead be
explicitly consumed by a fresh later-main owner after exact
subprocess/configuration/PageMap-root/static-main-Heap/arena/page-identity
preflight: the short map access becomes one long lifecycle, the matching
bitmap/count member is claimed, source abandoned/live collection and Theap
reassociation run, and the page returns at the target queue tail. A direct-
small target restores its complete rounded direct-cache range before target
page-count increment and immediately reuses that same page; its exhausted fully
committed scalar shape extends after tail insertion, its exact prefix-covered
shape retains its prefix count and extends without direct commitment, while its
exact on-demand shape directly commits its page area before
prefix-count/free-list/capacity publication. The medium slice
accepts an immediate head or an exhausted nonfull medium page
(`capacity < reserved`). A fully committed medium page (`slice_pcommitted == 0`)
extends after tail insertion. The bounded test-only `commit == false` fixtures
instead start from real reserved medium and direct-small pages with source
callback-committed prefixes. Their direct `_mi_os_commit`-shape extensions precede both the
monotonic prefix-count update and free-list/capacity writes. A direct-commit
failure repeats source false collection, queue detach, direct-cache/page-count
repair, and mapped identity/bit/count/unown publication, then permits only a
same-candidate retry through the retained long lifecycle. This is not a
production page-on-demand policy or fresh fallback. A bitmap miss, malformed
state, scalar extension error, or other post-transfer failure remains
terminally retained. Non-direct-small and malformed or out-of-profile
no-immediate direct-small metadata remain client-free-only. A direct small member must prove the exact rounded
source direct-cache range before collection; queue removal clears that range
before page-count detach. The route retains the source `reserved >= 16`
small partial-collection invariant and excludes full small pages through its
explicit `used < reserved` guard; the separate full-small exceptions above own
the direct and non-direct classes.

`abandon_mapped_regular_pages_to_process_route` is the bounded source-traversal
extension: before any mutation, every direct slot must match its source queue
head and every queue member must be either a nonfull regular small, medium, or
large arena page; a full `BIN_FULL` medium or large page; an ordinary-bin
direct/non-direct full small page; or a live full arena singleton in
`BIN_FULL`/`BIN_HUGE`. A joined remote free makes a full regular member nonfull
during source force collection, so removal publishes its ordinary bitmap/count
pair. An unchanged full regular member instead queue-detaches into
source-unmapped abandonment and retains its PageMap span until a later client
free crosses the source mostly-used predicate or releases it. A live arena
singleton remains PageMap-only for its raw terminal release; a live OS-aligned
singleton links through the static main Heap's private list and retains its
clipped-mapping terminal tail. An arena or OS-aligned singleton with one joined
remote free force-empties and follows the ordinary terminal release before the
remaining registry is exposed; a failed OS unmap retains the typed route.
Direct small members retain `reserved >= 16` for the source partial collector;
an empty member is admitted only when normal local free left its source
retirement countdown nonzero. The route
then ports `_mi_theap_collect_retired(theap, true)`'s regular-bin pass, so an
already-empty retired span releases before the remaining
`mi_theap_page_collect` / `_mi_page_abandon` decisions: force-collect, release
pages made all-free, false-collect still-live pages, queue detach, direct-cache
refresh, page-count detach, and either publish the exact static-main mapped
identity/bit/count pair, retain source-unmapped full identity, retain a live
arena singleton's raw PageMap-only tail, or retain a live OS singleton's
private-list/clipped-mapping tail. Its typed aggregate registry
retains no old-Theap pointer or raw page list; every later linear client free
re-resolves one PageMap entry, selects a regular bin only after the source low
owner-bit claim, preserves map/bit/count while nonempty after mapped
publication, and re-derives the selected page's complete regular or singleton
span before the terminal PageMap -> `pages_main` -> metadata -> slice release
on empty. The current small, medium, large, arena-singleton, and OS-singleton
cases therefore prove their one-, 8-, 64-, source-singleton, and clipped-map
releases. The direct-small retirement regression retains the exact rounded
cache image through ordinary local retirement, then proves the source prepass
clears it as the one-slice span releases before a live medium member is
published. If retirement/force collection empties every page, it returns the
ordinary drain. If the completed source traversal instead leaves exactly one
initial nonfull medium page with an immediate local head, it captures that
exact page/span/bin fact before registry construction and returns the existing
one-page mapped route. Its reclaim revalidates the immediate head and cannot
extend, commit, scan, or take a fresh-page fallback. Fresh engines may
serialize independent PageMap operations between client frees, but no current
path can adopt, reclaim, or requeue a live multi-member aggregate registry.
After every sibling and singleton tail has terminally released, its one final
mapped regular member may instead take the separately recorded consuming
bitmap-claim edge into a fresh later-main engine; every other aggregate member
remains sequential client-free-only. That edge neither scans alternative
members nor exposes general reclaim or requeue authority. The general registry
accepts unchanged full regular medium/large/direct-small/non-direct-small
members as its source-unmapped tail plus live arena and OS singletons as their
separate raw-terminal classes. A live OS singleton requires an initially empty
private list and is rejected if that list already owns a member; foreign pages
and malformed direct-cache images still reject before mutation. Its full regular cases are the joined
remote-force `BIN_FULL` medium/large and ordinary-bin direct/non-direct small
mapped cases plus the unchanged full source-unmapped cases; force-empty
arena/OS singleton cases remain private to the traversal.
The separate full-singleton, full-medium, full-large, non-direct-small, and
direct-small aggregates retain their route-specific class and geometry
preflights. Full-medium members may use distinct rounded bins, while stale
direct-cache images and every other remote-force full state remain absent.
Before its retired-page prepass and queue traversal, the aggregate takes the
pinned deferred-free invocation phase while the old Theap/TLD pairing is
still live; the direct small-or-medium and all-free runtime continuations take
the same phase before their first page inspection. The all-free continuation
then shares the aggregate's source `_mi_theap_collect_retired(theap, true)`
prepass before it begins generic force collection, so an already-empty
retired page releases directly rather than consuming a generic collector. If
that release has already detached queue/count or PageMap state before it
fails, the shared prepass records a terminal page-specific lifecycle poison;
neither continuation can retry it or imitate no-page teardown.
Likewise, every source-mutated `RetainedEngine` becomes a terminal retained
drain at the `MainHeapThreadProcessPageExitDrain` wrapper: that boundary
latches the post-fast-slot attachment before the retained drain returns. Its
`finish` method then retains the same PageMap mutation lease instead of
treating an empty old queue/count image as an all-free/no-page result while a
page can remain PageMap-published.
Production advances the Theap heartbeat, and an attachment-local test observer
proves the force flag, recursion guard, and ordering. Public callback
registration/re-entry, arena collection, and retry/reuse as a normal allocator
remain outside this owner.
Only an empty drain permits
`finish_after_page_drain` to reset default/cached, detach its shared heap list
member before its TLD list member, and retire metadata/TLD. A force/release
failure or root/list mismatch remains terminally retained; this is not general
abandonment, later-free/reclaim, concurrent routing, or a `pthread` lifecycle.

The source-valid sole-immediate-medium result is deliberately distinct from
that aggregate registry. Its typed route now moves from A to a fresh B OS
thread, where B reclaims the exact PageMap/arena identity, reuses its immediate
head, frees A's inherited clients, drains B's page engine, and completes B's
ordinary attachment before a typed terminal proof can release A's admission.
That is the bounded cross-thread adoption witness. Separately, the direct
mixed-route regression proves an aggregate's final mapped regular member can
transfer only after every sibling terminally releases. The same pointer-private
runtime route now exercises that one edge after its arena/OS singleton
subregistries have terminally cleared; it still exposes no client identity,
page scan, general allocation, or later-thread routing surface.

The later-main drain also has one separate mixed full singleton/regular route:
`abandon_full_singleton_or_regular_pages_to_process_route` accepts only a
complete `BIN_FULL` image with two or more arena members, at least one
`PageKind::Singleton`, and at least one regular `PageKind::Medium` or
`PageKind::Large`. Singleton geometry remains `BIN_HUGE` with `reserved ==
used == 1`; regular geometry remains ordinary-bin with `reserved > 1` and
`used == reserved`; every direct entry and other queue must be empty. The
source transition force- then false-collects, detaches, and unmapped-abandons
each member before old-Theap/TLD teardown. Its composed route keeps no raw
member list: a singleton takes only the raw terminal-empty tail, while a
regular member claims its low owner bit before selecting its exact static-main
bitmap/count pair and normal collector tail. Each terminal free releases only
its own PageMap -> `pages_main` -> metadata -> exact arena span; the map route
closes only after both source tails release. This does not authorize a general
heterogeneous queue traversal, regular-only mix, allocation-time adoption,
reclaim/requeue, producer, or concurrent-free path.

`process_page_map.rs` owns the global source-page-map prerequisite. It freezes
one `MemoryConfig` and selected main subprocess, initializes a `PageMap` in
its final static slot, and Release-publishes its root exactly once.
`process_arena.rs` retains one caller-selected, complete external in-place
arena mapping and adds one explicit caller-selected regular OS reservation
after binding either form to that same map/root/configuration/subprocess tuple.
The regular entry accepts only a nonzero request that rounds to exactly one
complete arena and normal reserved or committed mapping access; it records
`MemoryKind::Os`. Its separately bounded `reserve_default_os_arena` entry
ports the first lazy `mi_arena_reserve` decision: source max-page headroom, the
frozen 1-GiB Linux/AArch64 default, the overcommit eager-map condition, and the
128-MiB retry after an unpublished attempt returns COLD.
`MainStaticFirstArenaPageAllocator` now calls it only for an empty ticket-zero
Theap's first valid ordinary fresh-page miss: it derives the exact
small/medium/large/singleton span, revalidates the zero-page static image before
mapping, retains the PageMap lifecycle through activation, then delegates to
the established static engine. `ProcessMainThread` is the owner’s only
production-shaped factory, transferring its retained attachment plus the
immutable ready-map witness without reserving or mapping at startup. It is not
called at process startup. An
unpublished metadata failure unmaps that exact regular map before leaving the
sidecar cold for a matching retry, while a failed unmap retains the mapping
terminally. The external entry continues to return an unpublished rejected map
to its caller. A reserved map first enters the final owner slot, so the retained
arena callback commits metadata and later selected ranges through the exact
same `Mapping`; frozen Linux decommit reports no recommit requirement. This
establishes the external-map ownership prerequisite, one bounded first
fresh-page connection, and one narrow paired direct page-area commit operation;
it does not enable existing-arena search, later arena scaling, option mutation,
large-page/exclusive/NUMA policy, page-on-demand policy, or itself maintain
`slice_pcommitted` or page reabandonment.
`ProcessPageArenaLease` proves that exact tuple before `main_static_page.rs`
or `main_heap_page.rs` may bind an already selected source Theap to it. The
private ticket-zero and later-thread engines each hold the only process-map
plain-entry lifecycle for their complete engine and joined scoped producer,
install the arena's embedded `pages_main` bitmap in the shared static Heap, and
use the existing engine's source bitmap -> map publication and map -> bitmap ->
metadata -> slice release order. They reject a foreign subprocess before page
mutation, and an unfinished engine terminally poisons both owners rather than
manufacturing cleanup. Their normal `realloc` delegates preserve source
failure ownership and replacement copying; only the ticket-zero null case may
activate the completed first-arena policy. This remains a caller-initialized, single-arena,
sequential-owner slice. The bounded coordinator can now provide its map
predecessor, the private ticket-zero owner can make the first fresh-page
connection to the completed default reservation, and a completed reservation
can reconstruct only its immutable matching pair for one subsequent bounded
owner. That pair does not scan arenas, select free slices, reserve, or map.
The coordinator still supplies neither
the C static empty-map pre-root, existing-arena search, later automatic arena
reservation, concurrent or general later-thread page routing, general
abandonment/owner exit, process destruction, pthread integration, nor public
allocator routing. Map setup failure is once-terminal rather than a null root
or retry.

`dynamic_theap.rs` adds one private later-ticket current-thread attachment.
It atomically refuses ticket zero, then retains the caller-pinned first-class
Heap, metadata TLD/live registration, typed Malloc Theap, dynamic backing, and
linear regular-key lease. Dynamic `_mi_theap_init` completes TLD-list/random/
cookie/Release-heap/heap-list order, then publishes the regular TLS slot and
the cached root from the canonical empty source image, with the exact dynamic
Theap reference transition `1 -> 2`; default and fast remain unchanged. Begin
rejects any other cached predecessor before ticket issuance. No-page teardown
prevalidates that slot/root/refcount pair, clears the slot and backing, restores
that exact canonical empty cached root with `2 -> 1`, then detaches lists and
frees metadata. Root/list/page failures before mutation leave authority
unchanged; an after-publication or after-root-reset private failure returns a
retained poisoned owner with only known-valid capabilities. The one retryable
exception is a pre-mutation key-release lock error after other teardown: it
retains only the lease until `AwaitingKeyRelease` succeeds. General cached-root
switching/refcount ownership, general remote-free routing/concurrency, general
page routing or abandonment integration, full heap/Theap/arena/subprocess APIs,
pthread/fork/process shutdown, stats/options/callbacks, and public ABI remain
open. Ordinary dynamic begin stores the source abandoning `true`/`2` profile
and rejects a page session. A crate-private unsafe non-abandoning begin instead
stores `false`/`-1` before Release heap publication; its sealed borrowed
`DynamicTheapPageSession` alone instantiates the shared private
`PageAllocatorEngine`. Consuming finish requires a drained page lifecycle, and
an unfinished engine Drop terminally latches the attachment rather than
allowing teardown to claim quiescence.

The exact ordinary `true`/`2` queue image is also admitted through a
`cfg(test)`-only fixture for a source-shaped `MI_ABANDON` aggregate proof. That
fixture leaves `DynamicTheapAttachment::page_session` unchanged: production
ordinary dynamic attachments still cannot create a general page engine.

Its post-TLS `DrainingPages` state is now also a bounded source owner-exit
state, not an alternate allocator. It clears the regular dynamic backing before
page abandonment while retaining the cached root, TLD/Heap list membership,
PageMap, and heap-local arena image. `DynamicThreadExitDrain` first
force-collects an already-retired all-free regular page. Its singleton
transition admits one full one-block arena or OS-aligned page; the source
force-only local-list append is unreachable under its `reserved == used == 1`
and no-producer proof. The raw local-list substrate now separately ports and
tests that force append, including cycle rejection before relinking; the
separately recorded later-main all-free exit drain invokes it, but no current
page-engine lifecycle invokes it for a general traversal. The singleton
handoff queue-detaches and unmapped-abandons its page, then a final client free
necessarily fails reclaim through the cleared regular slot and owns its raw
all-free release. The OS form additionally links/removes its exact dynamic
`Heap::os_abandoned_pages` member around clipped PageMap -> alias -> primary
metadata -> mapping release.

For exactly one arena-backed full singleton, a separate Rust-only
`DynamicThreadExitArenaSingletonPostExitRoute` now completes the source-side
dynamic TLS, cached-root, Theap/TLD, and key teardown before it exists. The
source worker transfers only an inert pinned Heap plus its one dynamic arena
image; after the worker joins and the caller proves whole-PageMap quiescence,
one receiver may consume the exact client free and release PageMap -> dynamic
arena bit -> metadata -> arena span -> image -> Heap binding. The live
`DynamicTheapAttachment` and its ordinary singleton handoff remain `!Send`;
this is not a crabc pthread/TLS callback, C/Rust
destructor differential, general client routing, concurrent collection, or
public x86/runtime claim.

`DynamicThreadExitDrain::abandon_full_singleton_pages` separately admits one
bounded dynamic aggregate: two or more full `MemoryKind::Arena`
`PageKind::Singleton` members in `BIN_FULL`, each with its own rounded block
size, `reserved == used == 1`, zero retirement countdown, an empty local free
list, exact arena span, and no other queue/direct state. It follows source
force -> false collection -> full-queue/page-count detach -> unmapped
abandonment for every member. `DynamicThreadExitFullSingletonPagesRoute`
retains the existing dynamic drain instead of a raw member list or dynamic
bitmap/count pair; each sequential canonical free re-resolves and validates
the PageMap entry, takes only the raw empty failed-reclaim result, and releases
that member through PageMap -> dynamic ordinary bit -> metadata -> arena
slices. The final free returns the empty drain for existing teardown. Sole,
non-singleton, OS-backed, allocation-time, reclaim/adoption/requeue, scan, and
concurrent cases reject before detach; a collection failure retains the drain.

`DynamicThreadExitDrain::abandon_full_os_singleton_pages` separately admits a
bounded homogeneous dynamic aggregate: two or more same-rounded-size full
`MemoryKind::Os` singleton members in `BIN_FULL`, each with
`reserved == used == 1`, zero retirement countdown, empty local free list,
valid clipped PageMap/alias release image, an initially empty dynamic
`Heap::os_abandoned_pages` list, and no other queue/direct state. It preserves
source force -> false collection -> full-queue/page-count detach -> private
OS-list insertion -> unmapped unown for every member.
`DynamicThreadExitFullOsSingletonPagesRoute` retains only the dynamic drain
and member count; every sequential canonical free re-resolves
PageMap, takes only the raw empty failed-reclaim result, removes its exact
private-list member, then releases its clipped PageMap -> alias -> primary
metadata -> mapping image. The final free returns the empty drain for existing
teardown. Sole, arena-backed, mixed-size, non-singleton, preexisting-list,
allocation-time, reclaim/adoption/requeue, scan, producer, concurrent, huge,
and general owner-exit cases reject before detach; collection, list, or mapping
release failure retains the only owner terminally.

`DynamicThreadExitDrain::abandon_full_medium_pages` separately admits a third
bounded dynamic aggregate: two or more full `MemoryKind::Arena`
`PageKind::Medium` members in `BIN_FULL`, each with an independent rounded
block size and regular bin, `reserved > 1`, `used == reserved`, zero retirement
countdown, empty local free list, exact arena span, and matching dynamic
bitmap/count capability. No other queue/direct state is admitted. It follows
source force -> false collection -> full-queue/page-count detach -> unmapped
abandonment for every member. `DynamicThreadExitFullMediumPagesRoute` retains
the existing dynamic drain rather than raw member pointers or per-member mapped
state; each sequential canonical free re-resolves PageMap, claims its member
low owner bit, then selects that member's exact dynamic bitmap/count capability
and unmapped or mapped failed-reclaim tail. It releases that member through
PageMap -> dynamic ordinary bit -> metadata -> arena slices. The final free
returns the empty drain for existing teardown. Sole, mixed-class, non-medium,
OS-backed, allocation-time,
reclaim/adoption/requeue, scan, producer, and concurrent cases reject before
detach; a collection failure retains the drain.

`DynamicThreadExitDrain::abandon_full_large_pages` separately admits a fourth
bounded dynamic aggregate: two or more full `MemoryKind::Arena`
`PageKind::Large` members in `BIN_FULL`, each with its own rounded block size
and regular bin, `reserved > 1`, `used == reserved`, zero retirement
countdowns, empty local free lists, the matching dynamic bitmap/count
capability for every member, no other queue/direct state, and every member's exact 64-slice
arena/PageMap span. It follows source force -> false collection ->
full-queue/page-count detach -> unmapped abandonment for every member.
`DynamicThreadExitFullLargePagesRoute` retains the existing dynamic drain
rather than raw member pointers or per-member mapped state; each sequential
canonical free re-resolves PageMap, claims its member low owner bit, then
selects its exact dynamic bitmap/count capability and unmapped or mapped
full-large failed-reclaim tail, and releases that member through PageMap -> dynamic ordinary bit -> metadata ->
its complete 64-slice arena span. The final free returns the empty drain for
existing teardown. Sole, mixed-class, non-large, OS-backed,
malformed-span, allocation-time, reclaim/adoption/requeue, scan, producer,
and concurrent cases reject before detach; a collection failure retains the
drain.

`DynamicThreadExitDrain::abandon_full_singleton_or_regular_pages` separately
admits one bounded mixed dynamic aggregate: two or more full
`MemoryKind::Arena` members in `BIN_FULL`, including at least one
`PageKind::Singleton` and at least one regular `PageKind::Medium` or
`PageKind::Large` member. Every direct slot and other queue is empty. Each
singleton proves `BIN_HUGE`, `reserved == used == 1`, and its own rounded arena
span; each regular member proves its rounded regular bin, `reserved > 1`,
`used == reserved`, matching dynamic bitmap/count capability, and exact
one-slice medium or 64-slice large span. Source force -> false collection ->
full-queue/page-count detach -> unmapped abandonment runs for every member.
`DynamicThreadExitFullSingletonOrRegularPagesRoute` retains only the dynamic
drain and a count. Each canonical free re-resolves PageMap: singleton members
take the raw terminal failed-reclaim tail, while regular members claim the low
owner bit before selecting their normal unmapped-or-mapped tail. Each releases
only its PageMap -> dynamic ordinary bit -> metadata -> exact arena span.
Homogeneous queues, regular-only mixed medium/large queues, small/direct-small,
OS, malformed spans, allocation-time, reclaim/adoption/requeue, scan,
producer, concurrent, and general owner-exit cases remain absent; a collection
or terminal-release failure retains the sole owner.

`DynamicThreadExitDrain::abandon_full_non_direct_small_pages` separately admits
a sixth bounded per-member dynamic aggregate, proved only through that exact
ordinary source fixture: two or more full `MemoryKind::Arena` `PageKind::Small`
members across ordinary bins, each with its own rounded
`SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE`, `reserved > 1`,
`used == reserved`, zero retirement countdown, empty local free list, exact
one-slice arena/PageMap span, and matching dynamic bitmap/count capability. No
direct-cache entry or `BIN_FULL` member may remain, and a populated ordinary
bin may contain no other page class. It preserves source force -> false
collection -> ordinary-bin removal with the proven no-op direct-cache update ->
page-count detach -> unmapped abandonment for every member.
`DynamicThreadExitFullNonDirectSmallPagesRoute` retains the dynamic drain, not
a raw member list or per-member mapped state. Each sequential canonical free
re-resolves PageMap, claims its abandoned identity, then derives its normal
unmapped or mapped failed-reclaim tail and dynamic bitmap/count capability; it
releases only that member through PageMap -> dynamic ordinary bit -> metadata
-> one arena slice. The final free returns the empty drain for existing
teardown. Sole, mixed-class, direct-small, `BIN_FULL`, OS-backed,
allocation-time, reclaim/adoption/requeue, scan, producer, and concurrent cases
reject before detach; a collection failure retains the drain. This does not
expose ordinary dynamic allocation or a
general owner-exit traversal.

`DynamicThreadExitDrain::abandon_full_direct_small_pages` separately admits a
seventh bounded homogeneous dynamic aggregate, proved only through that exact
ordinary source fixture: two or more full `MemoryKind::Arena` `PageKind::Small`
members in one ordinary bin, with one rounded `block_size <= SMALL_SIZE_MAX`,
`reserved >= 16`, `used == reserved`, zero retirement countdowns, empty local
free lists, exact one-slice arena/PageMap spans, matching dynamic bitmap/count
capabilities, and the complete rounded direct-cache range naming the ordinary
queue head while every other direct entry and queue is empty. It preserves
source force -> false collection -> ordinary-bin removal -> direct-cache
refresh before page-count detach -> unmapped abandonment for every member.
`DynamicThreadExitFullDirectSmallPagesRoute` retains the dynamic drain, not a
raw member list, cached direct image, or per-member mapped state. Each
sequential canonical free re-resolves PageMap, uses its claimed abandoned
identity to select the partial-collector unmapped or mapped failed-reclaim
tail, preserves the just-pushed head through the source accounting lag, and
releases only that member through PageMap -> dynamic ordinary bit -> metadata
-> one arena slice; the final free returns the empty drain for existing
teardown. A member remains unmapped through `reserved / 8 + 1` frees; only the
next may publish its matching dynamic bitmap/count pair. Sole, stale/mixed
direct-cache, mixed-bin/class, non-direct-small, `BIN_FULL`, OS-backed,
allocation-time, reclaim/adoption/requeue, scan, producer, concurrent, and
joined-remote nonfull cases reject before detach; a collection failure retains
the drain. This does not expose ordinary dynamic allocation or a general
owner-exit traversal.

`DynamicThreadExitDrain::abandon_nonfull_medium_pages_distinct_bins` separately
admits exactly two initially nonfull `MemoryKind::Arena` `PageKind::Medium`
pages in distinct ordinary non-`BIN_FULL` bins. The source image is exactly
`allow_page_abandon == true` and `page_full_retain == 2`; each member has one
live client, `reserved > 1`, zero retirement countdown, a canonical eight-slice
span, a clear matching dynamic map/count capability, and an owner-only empty
remote-free word. Source force -> false collection -> queue/count detach ->
dynamic map/count publication -> unown creates a route with sealed witnesses,
not a raw page list. Its two sequential terminal frees release one member and
then return the drain. Full, direct-small, same-bin, retired, nonterminal,
adoption, reclaim, requeue, allocation-scan, producer, and concurrent cases
remain outside this private owner-exit model.

`DynamicThreadExitDrain::abandon_full_medium` separately admits one sole full
`MemoryKind::Arena` medium page in `BIN_FULL`, with `reserved > 1` and
`used == reserved`. It preserves source force -> false collection ->
full-queue/page-count detach -> ordinary unmapped abandonment. Its linear
`DynamicThreadExitFullMediumHandoff` consumes sequential failed-reclaim frees:
the page stays unmapped through the source mostly-used prefix, the first free
beyond `reserved / 8` publishes the matching dynamic `pages_abandoned[bin]`
bit plus `Heap::abandoned_count[bin]`, and the mapped tail clears that pair
before PageMap -> dynamic ordinary bit -> metadata -> arena-slice release.
This one route neither reclaims, adopts, requeues, scans, nor covers full
large, non-direct-small, direct-small, multi-page, or general dynamic owner
exit.

`DynamicThreadExitDrain::abandon_full_large` separately admits one sole full
`MemoryKind::Arena` large page in `BIN_FULL`, with `reserved > 1` and
`used == reserved`. It preserves source force -> false collection ->
full-queue/page-count detach -> ordinary unmapped abandonment. Its linear
`DynamicThreadExitFullLargeHandoff` consumes sequential failed-reclaim frees:
the page stays unmapped through the source mostly-used prefix, the first free
beyond `reserved / 8` publishes the matching dynamic `pages_abandoned[bin]`
bit plus `Heap::abandoned_count[bin]`, and the mapped tail clears that pair
before PageMap -> dynamic ordinary bit -> metadata -> complete 64-slice
arena release. This one route neither reclaims, adopts, requeues, scans, nor
covers full medium/non-direct-small/direct-small, multi-page, or general
dynamic owner exit.

`DynamicThreadExitDrain::abandon_full_medium_after_force_collect_to_mapped`
separately preserves the source full-medium branch with exactly one joined
remote free. The sole `BIN_FULL` page starts with `used == reserved`; force
collection consumes that free but leaves the member linked and marked full with
`used == reserved - 1`; false collection preserves it; full-queue/page-count
detach clears the full flag; and mapped abandonment immediately publishes its
dynamic bitmap/count pair. The returned `DynamicThreadExitFullMediumHandoff`
starts mapped and consumes sequential failed-reclaim frees only, clearing that
pair before the ordinary arena release. It does not add multiple frees, other
classes, reclaim, adoption, requeue, scans, or general dynamic owner exit.

`DynamicThreadExitDrain::abandon_full_large_after_force_collect_to_mapped`
separately preserves the source full-large branch with exactly one joined
remote free. The sole `BIN_FULL` page starts with `used == reserved`; force
collection consumes that free but leaves the member linked and marked full with
`used == reserved - 1`; false collection preserves it; full-queue/page-count
detach clears the full flag; and mapped abandonment immediately publishes its
dynamic bitmap/count pair. The returned `DynamicThreadExitFullLargeHandoff`
starts mapped and consumes sequential failed-reclaim frees only, clearing that
pair before the complete 64-slice release. It does not add multiple frees,
other classes, reclaim, adoption, requeue, scans, or general dynamic owner
exit.

The native x86-only track also has a separate 31-field dynamic full-large
one-remote force-collect-to-mapped differential. A pinned-C worker fills one
sole full `BIN_FULL` large arena page (request 86706, 98304-byte blocks,
capacity/reserved 42, a 64-slice arena span with 63 PageMap-registered source
page-area slices), publishes exactly one joined remote
`mi_free`, runs real `mi_thread_done()`, and joins before consumer frees.
Rust uses only the corresponding private typed drain. Force collection records
`used == 41`, mapped dynamic abandonment, and terminal PageMap, ordinary arena
bitmap, dynamic bitmap/count, and complete 64-slice release; the final
PageMap-null arena slice is slack but remains terminally released. This
remains private native x86-64 engine evidence only: it does not establish
general lifecycle/routing/concurrent collection, public x86 support, backend
promotion, or AArch64 evidence.

The native x86-only track also has a separate 34-field dynamic full-large
unmapped-reabandon differential. The pinned-C oracle's worker fills one sole full
`BIN_FULL` large arena page from request 86706 (98304-byte blocks,
capacity/reserved 42, 64 arena slices); only 63 source page-area slices are
PageMap-registered, and the final PageMap-null arena slice is slack but remains
part of terminal release. In the C oracle, no remote `mi_free` is published;
real `mi_thread_done()` and `pthread_join()` precede sequential consumer frees.
Rust independently executes the bounded typed owner-exit route on its owning
test thread and does not claim a literal worker-thread/join counterpart.
Five normal-collector frees retain unmapped abandonment at `used == 37` with
dynamic bitmap/count zero, then the sixth maps it at `used == 36` with dynamic
bitmap/count one. The mapped tail clears PageMap, the ordinary arena bitmap,
and dynamic bitmap/count before releasing the complete 64-slice span. This is
private native x86-64 engine evidence only: it does not establish general
lifecycle/routing/concurrent collection, abandonment/adoption, public API or
runtime, public x86 support, libc integration, backend promotion, or AArch64
evidence.

The native x86-only track now also has a separate 51-field dynamic homogeneous
full-singleton aggregate differential. Its pinned-C worker fills exactly two
same-size full `BIN_FULL` arena singleton pages from request 524289 (589824-byte
blocks, capacity/reserved 1, nine arena slices each), performs real
`mi_thread_done()`, and the consumer joins before any sequential free. Both
members begin unmapped-abandoned, unowned, PageMap-registered across all nine
slices, ordinary-arena-bitmap-set, and full-queue-detached; no dynamic
abandoned bitmap/count is involved. The first terminal free releases only page
0 while page 1 remains PageMap-registered, unmapped-abandoned, unowned, and
`used == 1`; the second terminal free releases page 1 and closes the route.
Rust exercises only the corresponding typed current-thread owner-exit model and
does not claim a Rust worker thread or join. This is private native x86-64
engine evidence only: it does not establish general lifecycle, routing,
concurrency, abandonment/adoption, public x86 support, libc integration,
backend promotion, or AArch64 evidence.

The native x86-only track now also has a separate dynamic homogeneous
full-large aggregate differential. Its pinned-C worker fills exactly two
same-bin full `BIN_FULL` arena large pages from request 86706 (98304-byte
blocks, capacity/reserved 42, 64 arena slices each, with 63 registered
PageMap source slices and one null slack slice), performs real
`mi_thread_done()`, and the consumer joins before any sequential free. Both
members begin unmapped-abandoned with dynamic abandoned bitmap/count clear;
each member independently remains at `used == 37` after five frees, maps at
`used == 36` on the sixth with its dynamic bitmap/count publication, then
releases its complete 64-slice PageMap/arena span. Rust exercises only the
corresponding bounded dynamic aggregate owner-exit route. This is private
native x86-64 engine evidence only and does not establish general lifecycle,
routing, concurrency, abandonment/adoption, public x86 support, backend
promotion, libc integration, or AArch64 evidence.

The native x86-only track also has a separate 67-field dynamic homogeneous
full-medium aggregate differential. Its pinned-C worker fills exactly two same-bin full
`BIN_FULL` arena medium pages from request 10248 (12288-byte blocks,
capacity/reserved 42, eight arena slices each), performs real
`mi_thread_done()`, and the consumer joins before any sequential free. Both
members begin unmapped-abandoned with dynamic abandoned bitmap/count clear;
each member independently remains at `used == 37` after five frees, maps at
`used == 36` on the sixth with its dynamic bitmap/count publication, then
releases its complete eight-slice PageMap/arena span. Rust exercises only the
corresponding bounded dynamic aggregate owner-exit route. This is private
native x86-64 engine evidence only and does not establish general lifecycle,
routing, concurrency, abandonment/adoption, public x86 support, backend
promotion, libc integration, or AArch64 evidence.

The native x86-only track also has a separate 69-field dynamic homogeneous
full non-direct-small aggregate differential. Its pinned-C worker fills exactly
two same-bin full ordinary-bin arena pages from request 1032 (1280-byte blocks,
capacity/reserved 51, one arena slice each), performs real `mi_thread_done()`,
and the consumer joins before any sequential free. Both members begin
ordinarily unmapped-abandoned with dynamic abandoned bitmap/count clear; each
member independently remains at `used == 45` after six normal-collector frees,
maps at `used == 44` on the seventh with its dynamic bitmap/count publication,
then releases its one-slice PageMap/arena span. Rust exercises only the
corresponding bounded dynamic aggregate owner-exit route. This is private
native x86-64 engine evidence only and does not establish general lifecycle,
routing, concurrency, abandonment/adoption, public x86 support, backend
promotion, libc integration, or AArch64 evidence.

The native x86-only track also has a separate 67-field later-main homogeneous
full direct-small aggregate differential. Its real pinned-C pthread worker fills
exactly two same-bin full ordinary regular-bin arena pages from request/block
size 1024 (capacity/reserved 64, one arena slice each), verifies the complete
direct-cache range `[113, 128]` with no remote free, runs `mi_thread_done()`,
and the consumer joins before every sequential free. Both members begin
unmapped-abandoned with PageMap and ordinary arena bitmap retained and ordinary
queues detached. The C source dynamic and Rust typed later-main static-main
abandoned bitmap/count are both clear through each nine-free partial-collector
prefix at `used == 56`, then both publish the normalized common `abandoned_*`
state at the mapped `used == 54` boundary. Page 0 releases independently before
page 1 closes the route. Rust observes only a scoped test worker and join for
common typed private facts, not crabc pthread/TLS callback parity. This private
native x86-64 engine evidence does not establish general lifecycle, routing,
concurrency, abandonment/adoption, allocation-time claim/reclaim/requeue,
public x86 support, backend promotion, libc integration, or AArch64 evidence.

The native x86-only track also has a separate 43-field dynamic nonfull
regular-pages distinct-bin aggregate differential. Its pinned-C probe uses a
real worker pthread to establish exactly two initially nonfull arena medium
pages in distinct ordinary bins, runs real `mi_thread_done()`, and joins before
the consumer frees either page. Rust exercises only the matching private typed
dynamic owner-exit model; it does not claim a Rust pthread/TLS callback or
general process/pthread/TLS lifecycle integration. This remains private native
x86-64 engine evidence only and does not establish public `mi_*` behavior,
runtime integration, public x86 support, backend promotion, or AArch64
evidence.

The native x86-only track also has a separate 37-field pinned-C automatic
pthread-destructor probe. Its worker creates two live 10241-byte clients on
one private arena medium page, verifies mimalloc's real pthread key points at
the initialized default Theap, then returns naturally without an explicit
`mi_thread_done()` or `pthread_exit()` call. After `pthread_join()`, the probe
records the mapped-abandoned, PageMap-registered, arena-bitmap-set, detached,
unowned page and its two-free terminal release. This source-anchored evidence
is C-oracle-only: it does not compare Rust or establish a crabc pthread/TLS
callback, Rust/private-runtime lifecycle integration, general destructor
ordering, public `mi_*` behavior, public x86 support, libc integration,
backend promotion, or AArch64 evidence.

The native x86-only track also has a separate 46-field pinned-C
cancellation-triggered automatic pthread-destructor probe. Its worker keeps
cancellation disabled through allocator setup, then enables only deferred
cancellation before publishing an atomic-ready gate. The consumer issues one
`pthread_cancel()` and opens that gate; the worker reaches one explicit
`pthread_testcancel()`, and `pthread_join()` returns `PTHREAD_CANCELED` before
the same mapped-abandoned, PageMap/arena-bitmap, detached/unowned, and
two-free terminal observations. This is also C-oracle-only: it does not prove
crabc pthread cancellation or TLS callback parity, Rust/private-runtime
lifecycle integration, general cancellation or destructor ordering, public
`mi_*` behavior, public x86 support, libc integration, backend promotion, or
AArch64 evidence.

The native x86-only track also has a separate 32-field dynamic full direct-small
one-remote force-collect-to-mapped differential. A pinned-C worker fills one
sole full direct-small ordinary regular-bin arena page (request/block size 1024,
capacity/reserved 64, one slice) and preflights its exact rounded direct-cache
range `[113, 128]`. The consumer/main thread publishes exactly one joined
remote `mi_free`; the worker later runs real `mi_thread_done()`, and the
consumer joins before sequential frees; Rust uses only the corresponding
private typed drain. Force collection records
`used == 63`, mapped dynamic abandonment, and dynamic bitmap/count state.
Pinned source anchors plus the Rust handoff establish direct-cache
clear-before-page-count-detach; only the source partial collector serves the
mapped tail through terminal PageMap, ordinary arena bitmap, dynamic
bitmap/count, and one-slice release. This remains private native x86-64 engine
evidence only: it does not establish general lifecycle/routing/concurrent
collection, abandonment/adoption, public x86 support, backend promotion, or
AArch64 evidence.

The native x86-only track also has a separate 38-field dynamic full direct-small
unmapped-reabandon differential. A pinned-C worker fills one sole full
direct-small ordinary regular-bin arena page (request/block size 1024,
capacity/reserved 64, one slice) and preflights its exact rounded direct-cache
range `[113, 128]`. No remote `mi_free` is published; the worker runs real
`mi_thread_done()`, and the consumer joins before sequential frees. Force then
false collection clears that range before page-count detach and leaves the page
unmapped-abandoned with PageMap and ordinary arena bitmap retained, ordinary
queue detached, dynamic bitmap/count clear, and `used == 64`. The first
partial-collector consumer free retains `used == 64`; nine partial-collector
frees retain that route at `used == 56`; the tenth partial collector takes
`used` to 55, then generic unown consumes the retained current head and maps
it at `used == 54` with dynamic bitmap/count one. The mapped tail clears
PageMap, ordinary arena bitmap, dynamic bitmap/count, and the one slice. This
remains private native x86-64 engine evidence only: it does not establish
general lifecycle/routing/concurrent collection, abandonment/adoption, public
x86 support, backend promotion, or AArch64 evidence.

The native x86-only track also has a separate 30-field dynamic full
non-direct-small one-remote force-collect-to-mapped differential. A pinned-C
worker fills one sole full non-direct-small ordinary regular-bin arena page
(request 1032, 1280-byte blocks, capacity/reserved 51, one slice, and an empty
direct-cache image). The consumer/main thread publishes exactly one joined
remote `mi_free`; the worker later runs real `mi_thread_done()`, and the
consumer joins before sequential frees; Rust uses only the corresponding
private typed drain. Force collection records `used == 50`, mapped dynamic
abandonment, and bitmap/count state. The first sequential failed-reclaim free
follows normal `used + 2 == reserved` geometry while retaining the mapped
route; the final free clears PageMap, ordinary arena bitmap, dynamic
bitmap/count, and the one slice. This remains private native x86-64 engine
evidence only: it does not establish general lifecycle/routing/concurrent
collection, abandonment/adoption, public x86 support, backend promotion, or
AArch64 evidence.

The native x86-only track also has a separate 35-field dynamic full
non-direct-small unmapped-reabandon differential. A pinned-C worker fills one
sole full non-direct-small ordinary regular-bin arena page (request 1032,
1280-byte blocks, capacity/reserved 51, one slice, and an empty direct-cache
image), publishes no remote free, runs real `mi_thread_done()`, and the
consumer joins before sequential frees. It initially remains full and
unmapped-abandoned with PageMap and ordinary arena bitmap retained, dynamic
bitmap/count clear, and `used == 51`. Six normal-collector frees retain the
unmapped route at `used == 45`; the seventh maps it at `used == 44` and sets
the dynamic bitmap/count to one. The terminal mapped tail clears PageMap,
ordinary arena bitmap, dynamic bitmap/count, and the one slice. This remains
private native x86-64 engine evidence only: it does not establish general
lifecycle/routing/concurrent collection, abandonment/adoption, public x86
support, backend promotion, or AArch64 evidence.

`DynamicThreadExitDrain::abandon_full_non_direct_small` is a sixth, separate
dynamic full-page endpoint. It admits one sole full `MemoryKind::Arena` small
page only in its ordinary regular bin, with
`SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE`, `reserved > 1`,
`used == reserved`, `!page_is_in_full`, and an empty direct-cache image.
It preserves source force -> false collection -> regular-bin/page-count detach
-> ordinary unmapped abandonment. Its linear
`DynamicThreadExitFullNonDirectSmallHandoff` consumes sequential normal
failed-reclaim frees: the page stays unmapped through the source mostly-used
prefix, the first free beyond `reserved / 8` publishes the matching dynamic
`pages_abandoned[bin]` bit plus `Heap::abandoned_count[bin]`, and the mapped
tail clears that pair before PageMap -> dynamic ordinary bit -> metadata ->
arena-slice release. It rejects direct-small before collection and neither
reclaims, adopts, requeues, scans, nor covers full medium/direct-small/large,
multi-page, or general dynamic owner exit.

`DynamicThreadExitDrain::abandon_full_non_direct_small_after_force_collect_to_mapped`
separately preserves the source full non-direct-small branch with exactly one
joined remote free. The sole ordinary-bin page starts with `used == reserved`;
force collection consumes that free while retaining its queue membership with
`used == reserved - 1`; false collection preserves it; regular-bin/page-count
detach leaves the page nonfull; and mapped abandonment immediately publishes
its dynamic bitmap/count pair. The returned
`DynamicThreadExitFullNonDirectSmallHandoff` starts mapped and consumes
sequential failed-reclaim frees only, clearing that pair before the ordinary
arena release. Its source direct-cache update is a no-op because the rounded
block size exceeds `SMALL_SIZE_MAX` and the full preflight requires an empty
direct image. It does not add multiple frees, direct-small or other classes,
reclaim, adoption, requeue, scans, or general dynamic owner exit.

`DynamicThreadExitDrain::abandon_full_direct_small` is a seventh, separate
dynamic full-page endpoint. It admits one sole full `MemoryKind::Arena` small
page only in its ordinary regular bin, with `block_size <= SMALL_SIZE_MAX`,
`reserved >= 16`, `used == reserved`, `!page_is_in_full`, and its complete
rounded direct-cache range naming the page while every other direct slot is
empty. Source force -> false collection -> ordinary-bin removal clears that
range before page-count detach, then ordinary unmapped abandonment. Its linear
`DynamicThreadExitFullDirectSmallHandoff` uses the source partial
failed-reclaim collector: the retained just-published head keeps the page
unmapped for one additional client free before the below-mostly-used boundary
publishes the matching dynamic `pages_abandoned[bin]` bit plus
`Heap::abandoned_count[bin]`. The mapped tail clears that pair before PageMap
-> dynamic ordinary bit -> metadata -> arena-slice release. A stale cache
range, non-direct small, additional page, or collection failure cannot bypass
the pre-detach contract. This one route neither reclaims, adopts, requeues,
scans, nor covers full medium/non-direct-small/large, multi-page, or general
dynamic owner exit.

A separate `DynamicThreadExitMappedOneBlockHandoff` accepts only a sole,
nonfull `MemoryKind::Arena` medium, large, non-direct-small, or direct-small
page with `reserved > 1`, `used == 1`, and one regular queue member. The
medium endpoint remains `DynamicThreadExitDrain::abandon_mapped_one_block`;
the large endpoint is `DynamicThreadExitDrain::abandon_mapped_one_block_large`
and retains its complete 64-slice span; the non-direct-small endpoint is
`DynamicThreadExitDrain::abandon_mapped_one_block_non_direct_small` and
requires `SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE` with an empty
direct-cache image; the direct-small endpoint is
`DynamicThreadExitDrain::abandon_mapped_one_block_direct_small` and requires
`block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, and its complete rounded
source direct-cache range. Direct-small preflight rejects a stale cache image
before collection or detach, then source queue removal clears that exact range
before page-count detach. The handoff keeps the post-TLS dynamic arena image
only long enough to form the exact heap-local `pages_abandoned[bin]` bit plus
paired `Heap::abandoned_count[bin]`. Source force then false collection
precedes queue/page-count detach and mapped identity/bit/count/unown
publication. Its exact final free reaches empty before any source reclaim
branch—through the normal collector for medium/large/non-direct small and the
partial collector for direct small—clears the dynamic bit/count pair, then
releases PageMap -> dynamic ordinary bit -> metadata -> arena slices. The
large endpoint validates its 63 PageMap-registered source page-area slices;
the final PageMap-null arena slice is slack but remains part of the terminal
64-slice release. Neither dynamic handoff scans, reclaims, adopts, requeues,
accepts a second free, or generalizes thread exit. Only an empty drain may
resume the existing cached-root/list/key teardown.

`DynamicThreadExitDrain::abandon_mapped_two_block_medium` is a separate
post-TLS dynamic handoff for exactly one sole nonfull `MemoryKind::Arena`
`PageKind::Medium` page with `block_size > SMALL_SIZE_MAX`, `reserved > 2`,
`used == 2`, zero retirement countdown, one regular queue member, an empty
direct-cache image, and no other queue/direct entry. It preserves source force
-> false collection -> queue removal -> page-count decrement -> non-direct
no-op cache update -> dynamic mapped identity/bit/count/unown. The private
handoff retains no client pointer/list: its first exact canonical free must
produce `UnownedMapped` and keep the bit/count with one live block, while only
the final free may produce `Empty`, clear that pair, and release the
queue-detached PageMap -> dynamic ordinary bit -> metadata -> arena-slice
span. One or three live blocks, another page, other source classes, reclaim,
adoption, requeue, scanning, producers, concurrency, and general owner exit
remain excluded.

`DynamicThreadExitDrain::abandon_mapped_medium_pair` now records one separate
bounded post-TLS aggregate: exactly two nonfull `MemoryKind::Arena`
`PageKind::Medium` pages in distinct regular bins, one with `reserved > 2`,
`used == 2` and one with `reserved > 1`, `used == 1`. Preflight proves both
sole queue members, their arena spans and dynamic bitmap/count capabilities,
the total three live blocks, an empty direct image, and no other queue/page
before source bin-order force -> false collection -> queue removal ->
page-count decrement -> non-direct no-op update -> mapped publication. The
returned `DynamicThreadExitMappedMediumPairRoute` keeps only the drain plus
remaining page/free counts; every client free re-resolves PageMap membership
and acquires the source low owner bit before selecting its dynamic map. An
`UnownedMapped` result retains the route, while each `Empty` result clears its
exact pair and releases only that member; the final release returns the empty
drain. It adds no raw member registry, scan, reclaim/adoption/requeue,
allocation-time, producer, concurrent, or general owner-exit routing.

The first fresh page in that private non-abandoning dynamic session now owns
one exact source-shaped heap-local `mi_arena_pages_t` image. Creation first
requires the registry-published arena's non-null `Arena::subprocess` to equal
the attachment's selected main subprocess; the retained BCHUNK-aligned
metadata capability is then Release-published only in the bound Heap's exact
arena slot and is used for fresh/rollback/release page bits. It remains
disjoint from the arena's `pages_main`. Empty attachment
teardown removes the exact slot before freeing it, while a nonempty image is a
pre-mutation rejection and post-mutation lock/free ambiguity terminally
retains owner state. One consuming same-owner handoff now moves a mapped
regular dynamic arena page through its heap-local abandoned bitmap/count. The
same token can adopt it or consume one still-live client block through the
source mapped `allow_collect=true` same-origin remote-free branch: the small
path preserves its published head until reassociation, clears the exact
bitmap/count, live-collects, and requeues. Its all-free dynamic-arena outcome
now releases in source order—PageMap span, heap-local ordinary bit, metadata,
then arena slices—and returns the drained engine; an existing owner remains a
terminal handoff. Separately, `free_unmapped_after_failed_reclaim` remains the
source terminal-empty/reabandon/unown substrate after failed reclaim, including
the expected-head CAS and no-second-reclaim conflict path. The post-TLS full
singleton and full-singleton/homogeneous-full-OS-singleton/full-medium/full-large/full-non-direct-small/full-direct-small
aggregates above, the separate dynamic full-medium, full-large,
full-non-direct-small, and full direct-small handoffs, and the bounded later-main normal full-medium,
full-large, full non-direct-small, and full direct-small process routes are its lifecycle-integrated raw-release
callers; other regular or
nonempty unmapped pages, general producer routing, terminal reuse, multi-arena dynamic heap
support, and general heap destruction remain absent.

Separately, the exact source-layout `mi_random_ctx_t` image now lives directly
in `Theap::random`: it preserves source input/output word order, counter
carries, consumed-output clearing, direct random-field-address nonce identity,
and in-place split. It calls direct Linux `getrandom` and continues weakly on
an error or short read, then retries only while weak. The source local
`_mi_random_shuffle` core is deliberately replaced by one domain-separated
approved RustCrypto expansion of transparent weak observations; this
non-entropy-adding degraded-path difference is recorded in
`compat/allocator/known-differences.md`. The static main-Theap slice initializes
this exact image; both static and private dynamic Theap attachment use it, and
the narrow non-abandoning dynamic session reuses the private page engine.
General allocator routing and page-bearing production thread/process
integration remain absent. The default libc bridge is bounded to no-page
owners, while the separate suspended-owner route is test-only evidence. The
nondefault `crabc-libc` `native-mimalloc-shadow` feature is the one narrow
exception: `libc/src/allocator_native_mimalloc.rs` routes the initial thread's
malloc family and bounded attached workers' tracked local malloc/free/realloc/
aligned/usable-size operations to the Rust runtime, with no C fallback. The
same selected boundary lets an attached worker free one exact still-live
ticket-zero normal or aligned client through the source atomic remote head.
That client keeps its page registered while the worker uses only the immutable
PageMap witness, initial owner identity, and source-constant aligned geometry;
it borrows no page engine, scheduler claim, or stored client capability, and
ticket zero collects the published head during its next ordinary operation.
This remote-publication route is free-only, not cross-thread reallocation,
owner exit, or abandoned-page routing. `native_usable_size` separately reads
an exact live client's PageMap extent without this route. The
selected evidence retains the parked session and private `NativePostExitRoute`
scenario only as `#[cfg(test)]` historical oracle code. Selected native
post-exit behavior begins from the pointer: a fresh worker can read the
source-recorded usable extent, free through generic pointer-first PageMap/W03
behavior, or perform a valid foreign `realloc` through allocate/copy/generic-
free. It does not receive an old-owner client, page, route, scheduler token,
or admission capability, and its normal teardown settles only its own
lifecycle.
The selected aggregate fixture verifies that an A-side TSD destructor can
allocate and free locally before this handoff through normal return,
`pthread_exit`, and deferred cancellation. Cancellation first runs a cleanup
handler that also allocates and frees, then the destructor, while the same
route carries direct-small, non-direct-small, medium, regular-large,
arena-singleton, and OS-singleton C clients.
Exact live remote-free witnesses now use the allocation's persistent
PageMap/page state directly. Independently attached B/C workers can read the
exact immutable usable extent or atomically publish an exact live block to its
source page's remote head without claiming A's TLS session, a scheduler token,
or a client ledger. The matching source owner collects that head during its
ordinary operation or finish. The direct and selected-C
`native_mimalloc_two_live_remote_owners` witnesses keep two independent
source pointers live while B1/B2 each operate only on the pointer they were
given. The historical `native_live_remote_owner_registry_reuse` target is
now an ungated repeated persistent-PageMap epoch witness: it exercises four
A1/A2/B1/B2 epochs without an audit or reusable owner metadata. The separate
`native_mimalloc_parallel_local_workers` fixture remains a local-admission
witness; B frees only its own client and ticket zero reactivates after both
ordinary finishes. None of these tests establishes general concurrent worker
allocation, pointer routing, or PageMap mutation.
At the direct pointer boundary, a synchronized B first derives an exact A
client's PageMap facts. `native_reallocate` rejects the foreign source as
unavailable (the C ABI reports `ENOMEM`), leaves its bytes intact, and never
allocates, copies, claims a route, or borrows A's torn-down Theap. Generic
pointer-first free is the only detached-owner continuation; B's later local
`realloc` uses only B's current owner. `native_usable_size` returns the
captured PageMap extent for any exact live native client. General single-page
adoption/reclaim exits, arbitrary concurrent worker allocation beyond the
bounded live-entry witnesses, and pointer routing beyond exact-live ticket-zero
free remain unavailable.
`./scripts/dev.sh allocator-shadow` is the artifact-order-safe allocator ABI,
pthread local-allocation, bounded owner-exit, and bounded live-remote-free
evidence. It does not close the remaining general libc, remote-free,
owner-exit, fork, or promotion gates.
Five bounded Loom
schedules execute the shared live-owner and abandoned owner-claim/unown head
transitions. The compiler-TLS evidence proves private initial-exec AArch64 code
generation in a dedicated crate probe and proves that the pinned compiler
default would instead emit TLSDESC. The bridge applies initial-exec target-wide
in both normal and sealed-sysroot Rust flags; its installed static archive is
audited for the named `THREAD_LIFECYCLE` TLSIE root, and final `libc.so` must
use TPREL relocations with no TLSDESC or `__tls_get_addr`. The bounded
dynamic engine consumes one stable, queue-detached mapped regular handoff and
one same-origin mapped `allow_collect` remote free; its all-free dynamic-arena
result performs the bounded PageMap/ordinary-bit/metadata/slice release while
an existing-owner result remains terminal. It additionally proves one post-TLS
  dynamic owner-exit singleton, full-singleton/homogeneous-full-OS-singleton/full-medium/full-large/full-non-direct-small/full-direct-small aggregates,
  sole full-medium, full-large, full-non-direct-small, and
  full-direct-small normal unmapped-to-mapped handoffs, four one-joined-remote
  full-medium/full-large/full-non-direct-small/full-direct-small immediate-mapped predecessors, and sole mapped
medium/large/non-direct-small/direct-small
one-block handoffs: clearing the regular backing prevents reclaim; the singleton
  final free takes the raw failed-reclaim all-free release, the four normal
  full routes cross the source mostly-used boundary before dynamic bitmap
  publication, and the medium/large `BIN_FULL` plus non-direct-small/direct-
  small ordinary-bin one-remote full routes map immediately after source
  force/false collection and queue detach, with direct-small clearing its
  rounded cache range before count detach. Each mapped
  endpoint clears its dynamic bitmap/count before terminal arena release. The raw
protocol remains
otherwise unintegrated: regular/nonempty pages, general producer routing,
terminal reuse, actual process/thread lifecycle hooks, full teardown traversal,
and reusable abandoned-page lifetime remain absent.
The bounded two-block dynamic owner-exit evidence is likewise split by source
class: medium and one-slice non-direct-small each admit only a sole nonfull
arena page with `reserved > 2`, `used == 2`, an empty direct image, and exactly
two sequential canonical frees. The first retains the dynamic mapped
bit/count through `UnownedMapped`; the final `Empty` free alone releases the
page. The separate large handoff admits only `PageKind::Large` geometry with
`MEDIUM_MAX_OBJ_SIZE < block_size <= LARGE_MAX_OBJ_SIZE`, an empty direct
image, and an exact 64-slice arena/PageMap span; its normal first free retains
that entire mapped span with `used == 1`, and its final `Empty` free alone
clears the pair and releases all 64 slices. The separate direct-small handoff
admits only `block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, its complete
rounded direct-cache range, and `used == 2`; it clears that range before
page-count detach. Its first partial-collector free deliberately leaves the
published head atomic and the observed `used` count at two, then the final free
consumes both heads and releases the page. Extra live blocks/pages, stale/mixed
cache images, reclaim, adoption, requeue, scans, producers, and concurrent
traversal remain open.
Process state, general allocator TLS lifecycle, full/singleton/unmapped/huge
later-thread owner exit beyond the bounded sole
full-medium/full-large/full-non-direct-small/full-direct-small routes, seven
bounded full-page aggregates, sole small-or-medium route, and regular-pages
aggregate, allocation-time
claim/reclaim/requeue after later-thread exit beyond the exact mapped one- and
two-block handoffs, general dynamic heap/Theap
attachment and remote-free routing, complete concurrency modeling and stress,
libc integration, the remaining upstream suites, and performance promotion
gates remain open.

Future acceptance contracts are deliberately specific:

- [`docs/roadmap/performance-completion.md`](docs/roadmap/performance-completion.md)
  governs performance completion.
- [`docs/roadmap/software-corpus-validation.md`](docs/roadmap/software-corpus-validation.md)
  governs real-software and native-application validation.
- [`docs/roadmap/source-build.md`](docs/roadmap/source-build.md) governs the
  remaining CPython source-build progression on the completed sysroot.

Historical documents preserve provenance only; they are never an active
backlog. No chronological microtask list is a project authority. Read the
governing scope and compatibility profile before selecting work, then use the
relevant roadmap or machine-readable contract for its acceptance boundary.
