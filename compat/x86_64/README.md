# Native x86_64 foundation evidence

This closed, native Linux/x86_64 lane is foundation evidence named by
[`x86-64.md`](../../x86-64.md).

The checked [`AArch64-to-x86 contract inventory`](../../docs/evidence/x86-aarch64-parity-inventory.md)
derives its snapshot from the immutable
[`aarch64_frozen_baseline.json`](aarch64_frozen_baseline.json) settlement
record, the live AArch64 inputs it digest-binds, and this lane's promotion
ledger. It reports currently implemented foundation, selected private, and
still-missing contract states without treating any count as a parity or
support claim. Run `python3 compat/x86_64/aarch64_parity_inventory.py`; normal
validation has no refresh mode and rejects drift in either the frozen AArch64
identity or the checked x86-derived inventory.

Use the campaign surface to inspect the current dependency-ready work rather
than treating a private focused command as a promotion result:

```sh
./scripts/dev-x86_64.sh campaign-status
./scripts/dev-x86_64.sh campaign-family libc.headers-layouts
./scripts/dev-x86_64.sh campaign-static
./scripts/dev-x86_64.sh campaign-dynamic
./scripts/dev-x86_64.sh campaign-qualification
./scripts/dev-x86_64.sh campaign-promotion-check
./scripts/dev-x86_64.sh campaign-all
```

`campaign-status` and `campaign-family` validate the frozen baseline, ledger,
and generated routine C-ABI evidence matrix before emitting JSON. The product
and promotion commands fail with their declared blockers until their actual
native gates are complete; they never promote a private artifact. The planned
[`static-product.toml`](static-product.toml) makes the owned-static requirements
machine-checkable while the current static sysroot fixture remains only a seed
artifact.
The generator also independently rejects a verified slice that escapes its
owning family, duplicate selected capabilities or record IDs, and any
capability-bearing artifact. A selected slice or artifact also needs nonempty
entirely-verified native evidence with a command and scope, so its
`selected-private` rows remain accounting rather than an inferred support
claim. That command is a canonical checked-in x86/CRT dispatcher invocation
whose final arm runs a verifier; image-building, stale, and arbitrary commands
cannot stand in for native evidence. A selected artifact cannot repeat one
command as though it were independent corroboration.

The selected private static matrix also includes `libc-rand-r` for
caller-owned `rand_r` state and `libc-pthread-*` commands for the individual
condattr and mutexattr bits/statuses, priority-ceiling status, and
get/set-concurrency status. Those commands are isolated C ABI leaves in the
still-planned `libc.posix-runtime` and `libc.pthread-tls` families, not a
pthread/TLS lifecycle vertical, family completion, owned-sysroot proof,
promotion, or public support claim.

`libc-resolver-runtime` is a separately verified opt-in static C artifact in
the still-planned `libc.resolver` family. Its hermetic pinned-musl/candidate
gate fixes fixture `/etc/hosts`, `/etc/resolv.conf`, and loopback UDP DNS
inside a disposable chroot, checks resolver aliases and TLS state, and keeps
the default static export roster unchanged. It is not the `resolver-network`
gate, resolver-family completion, or public x86 support.

This lane runs the fixed `crabc-core` lib suite and the separately admitted
direct `crabc-rs` subset for the `x86_64-unknown-linux-musl` target, including
only the proved `fs::flock` whole-file advisory locking, `fs::sendfile`
descriptor transfer,
`fs::copy_file_range` descriptor-range copying,
`fs::posix_fallocate` fixed-mode descriptor-range allocation,
`fs::fallocate` closed-mode descriptor-range allocation,
allocation-free `pattern::{fnmatch, FnmatchFlags}` byte matching and
alloc-gated explicit-root `pattern::{GlobPath, glob, glob_at}` traversal with
no C `fnmatch`/`glob`/`globfree`, C `DIR`, errno, or public C allocator
boundary,
`fs::{StatFs, StatVfs, StatVfsMountFlags, statfs, fstatfs, statvfs, fstatvfs}`
filesystem-capacity observation,
the bounded timestamp-mutation family headed by
`fs::{Timespec, Timestamps, UTIME_NOW, UTIME_OMIT, futimens}` for descriptor,
directory-relative, current-directory, final-symlink, and whole-second forms,
`fs::sync` system-wide and `fs::syncfs`
descriptor-associated filesystem synchronization and
`io::{sync_file_range, SyncFileRangeFlags}` range-writeback request, plus
typed native socket/address transport for socket lifecycle, IPv4/IPv6 endpoint
values, loopback datagrams and streams, named socket options, and
vectored/batched messages; plus the separately evidenced bounded
`net::netdevice` interface index/name and owned snapshot slice; the private
`crabc-core::resolver` UDP/TCP exchange slice; the alloc-backed
`crabc-rs::resolver`; and owned hosts/services/protocols snapshots. It is not
public x86_64 runtime support. The separate `path-core-reference` aggregate
also verifies a private `filesystem.path-core` vertical slice: typed
descriptor-relative metadata and pathname lifecycle operations, links and
rename, bounded timestamp mutation, and caller-buffered plus owned,
byte-preserving symbolic-link target reads.
The separate `xattr-reference` gate verifies a private `filesystem.xattr`
vertical slice: direct caller-buffered binary value and NUL-separated name
operations through path, no-follow-path, and descriptor forms.
The separate `directory-reference` gate verifies the private
`filesystem.directory-stream`, `filesystem.directory-position`, and
`filesystem.raw-directory` slice: caller-buffered `getdents64` records,
owned close-on-exec streams, and opaque seek/rewind cookies without a C `DIR`
ABI.
The separate `temporary-object-reference` gate verifies the private
`filesystem.named-temporary-file`, `filesystem.anonymous-temporary-file`, and
`filesystem.temporary-directory` slice: explicit-directory private named-file
cleanup, descriptor-owned `O_TMPFILE` inodes, and private `mkdirat` names with
caller-buffered or alloc-owned byte paths. It remains Rust-only evidence, not
public x86 runtime support.
The separate `statx-reference` gate verifies the private
`filesystem.extended-metadata` slice: direct `statx=332` metadata copied from
a private 256-byte Linux 5.10 record, including `AT_EMPTY_PATH` only in its
statx-specific flag vocabulary and direct `ENOSYS` rather than musl fallback.
It too remains Rust-only evidence, not public x86 runtime support.
The separate `cwd-canonicalize-reference` gate verifies the private
`filesystem.canonicalize` and `filesystem.cwd-mutation` slice: a bounded,
byte-preserving physical pathname result through direct `openat`/`readlinkat`/
`getcwd` operations, plus explicitly process-global `chdir` and `fchdir` with
descriptor-based restoration. It leaves `chroot`/`process.root-change`, C
pathname/process APIs, and public x86 runtime support unselected.
The separate `root-change-reference` gate verifies the private
`process.root-change` slice: safe `process::chroot<P: PathArg>` byte paths use
direct `chroot=161` and return direct `Errno`; success changes future absolute
path resolution process-wide, leaves CWD unchanged, and provides neither
restoration nor a route to the old root. Its focused Rust child test, existing
`no_std` `process_chroot_direct_probe`, and pinned-musl/raw C oracle keep every
successful transition in a disposable child process with `CAP_SYS_CHROOT`.
This is not a containment or sandbox claim, and it selects no C ABI/errno TLS,
`pivot_root`, mount namespaces, or public x86 runtime support.
The separate `ipc-reference` gate verifies the private `ipc` POSIX
named-message-queue slice: typed fixed-arity `mq_*` syscalls, owned queue
descriptors, queue attributes and nonblocking status, bounded priorities,
borrowed message buffers, absolute realtime deadlines, and unlink-after-open
lifetime. It leaves `mq_notify`, the general C mqueue APIs/ABI and `errno` TLS,
and public x86 runtime support unselected; the separately sealed
`static-c-mq-setattr` archive artifact does not widen this Rust-facing slice.
The separate `shm-reference` gate verifies the private `ipc.posix-shm` slice:
validated POSIX names map to `/dev/shm`, `shm::open` forces `CLOEXEC` only and
returns an owned descriptor, and unlink-after-open lifetime remains direct.
Default final-symlink resolution therefore follows the link, while an explicit
caller `O_NOFOLLOW` receives the direct `ELOOP` result.
Pinned musl's C `shm_open` wrapper additionally forces `O_NOFOLLOW` and
`O_NONBLOCK`; the fixture records that intentional AArch64/Rustix-aligned Rust
contract difference rather than asserting raw/musl flag equality. It leaves C
shared-memory ABI/`errno`/cancellation mechanics, SysV shared memory and
semaphores, mapping/sizing policy, mount fallback, global registries, wider
IPC, and public x86 runtime support unselected.
The separate `inotify-reference` gate verifies the private `system.inotify`
slice: an owned close-on-exec/nonblocking descriptor, descriptor-scoped typed
watches, and caller-buffered byte-preserving event records. It leaves C
`sys/inotify.h` APIs/ABI and `errno` TLS, legacy `inotify_init`, fanotify,
recursive/background watcher policy, global registries,
namespaces/capability mutation, wider system facilities, and public x86
runtime support unselected from the Rust facade. The separate private
`static-c-event-descriptors` artifact owns bounded static C inotify ABI/header
and legacy-init evidence; it does not broaden the Rust slice or public support.
The separate `calendar-time-reference` gate verifies the private
`time.civil-calendar` slice: direct `gettimeofday` wall-clock observation,
strict UTC Gregorian conversion, immutable caller-supplied POSIX TZ and TZif
rules, and one-way instant-to-local calendar projection. It leaves C time
APIs/ABI and `errno` TLS, libc timezone globals, `TZ`/zoneinfo discovery,
clock query/set and process/thread-clock operations, POSIX timers, inverse
ambiguous local conversion, and public x86 runtime support unselected.
The separate `advanced-time-reference` gate verifies the private
`time.clock-query`, `time.clock-process-id`, `time.clock-set`, and
`time.posix-timers` slice: closed named clock values, validated dynamic
process/descriptor clock queries, direct permission-governed clock mutation,
and owned POSIX timer lifetime. It keeps C time/timer ABI and `errno` TLS,
`SIGEV_THREAD` callback policy, timer/signal framework policy, and public x86
runtime support unselected.
The separate `child-ownership-reference` gate verifies the private
`process.child-ownership` slice: alloc-backed `PreparedExec` copies its path,
argument, and environment storage before spawn; `FdAction` and `SpawnOptions`
describe only direct child-side setup; and a successful `Child` uniquely owns
one `WaitOptions`/`WaitStatus` transition. A `CLOEXEC` error pipe reports a
child setup or exec failure to the parent, which reaps that private child
before returning the error. The paired pinned-musl/raw fixture proves the
contained clone/fork, `WNOHANG`, `WNOWAIT`, exit, exact-reap, and post-reap
`ECHILD` lifecycle. This does not select generic `fork`/`vfork`/`exec`/
`wait`/`waitpid`/`waitid`, `posix_spawn`, C process/signal headers or ABI,
errno TLS, pthread/atfork/cancellation mechanics, child supervision, or public
x86 support.
The separate `thread-kill-reference` gate verifies the private
`process.thread-kill` slice: typed `signal::kill_thread` fixes the thread group
to the calling process and invokes direct `tgkill=234` for one positive target
thread ID. It retains direct `ESRCH` for an impossible/nonmember target and
`EINVAL` for an invalid signal. Its disposable-process Rust handler regression,
no-std static probe, and pinned-musl/raw C oracle establish exact-thread
delivery: raw `tgkill` proves a live worker's pending signal, handler TID, and
delivery, while musl's adjacent `pthread_kill` behavior uses `tkill`. This does
not select a musl `tgkill` API, generic process/group signaling, signal
masks/queues/`signalfd`, C signal ABI/errno TLS, pthread cancellation, or
public x86 support.
The separate `mapping-reference` gate verifies the private `memory.mapping`
slice: unsafe `mm::{mmap, mmap_anonymous, mprotect, munmap}` use direct
`mmap=9`, `mprotect=10`, and `munmap=11` with closed mapping/protection flags
and explicit pointer-provenance/lifetime obligations. Its focused Rust test,
no-std direct probe, and child-contained raw/pinned-musl C oracle cover the
ordinary anonymous/file mapping and protection boundary only. They do not
select remapping, locking, synchronization, advice, residency, VM policy, a C
mapping ABI/errno TLS, or public x86 support.
The separate `memory-vm-reference` gate verifies the private `memory.vm`
slice: unsafe `process::kernel_brk` is tested only as a null query followed by
an exact replay, and `mm::{MlockAllFlags, mlockall, munlockall}` plus unsafe
`remap_file_pages` use direct x86 VM-control seams. `mlockall` effects and
cleanup are contained in disposable children; its valid direct limit errors
remain visible. The legacy remap proof is only anonymous-map `EINVAL`, not a
file-backed remap policy. This selects no allocator or program-break
adjustment, wider mapping/range-lock/sync/advice/residency behavior, C VM ABI
or errno TLS, or public x86 support.
The separate `pty-basic-reference` gate verifies the private
`terminal.pty-basic` slice: `pty::{openpt, grantpt, unlockpt}` and
`PtyPair::open` own the bounded master/slave allocation lifecycle, make an
explicit `O_NOCTTY` request for the peer, and supply caller-buffered or owned
devpts names. Its
focused Rust test, no-std probe, and paired raw/pinned-musl C oracle cover byte
transfer, name agreement, short-buffer `RANGE`, and non-PTY `ENOTTY`; they
record the forced peer-open request rather than assert session state. They do
not select generic ioctl or direct peer-open APIs, sessions,
controlling-terminal handoff, termios/TTY controls, C PTY/termios ABI or errno
TLS, or public x86 support.
The separate `terminal-reference` gate completes the remaining private x86
terminal vertical. It retains `PtyPair::open`'s forced `O_NOCTTY` behavior,
then admits only explicit unsafe session/controlling-terminal handoff and
named Rust termios/TTY operations. Its no-default and alloc tests, no-std
probe, and raw/pinned-musl C oracle prove the private 36-byte x86 `TCGETS`
record versus musl's 60-byte `NCCS=32` public record, attributes, queues,
flow/break, exclusive mode, tty path validation, window size, raw mode, a
distinct B0 input selector, and a child-contained `setsid`/`TIOCSCTTY`
handoff. This Rust vertical selects no general C terminal ABI, errno TLS,
generic ioctl, direct peer-open API, process supervisor, or public x86 support.
The separate static `libc-termios-control` artifact records a closed direct-C
termios boundary; it does not promote this Rust vertical or a general C
terminal capability.
The separate `users-databases-reference` gate verifies the private
`users.databases` slice: immutable owned strict UTF-8 `/etc/passwd` and
`/etc/group` snapshots retain source order and duplicate records, return the
first matching name or numeric ID, and reject an entire snapshot for malformed
non-empty or interior-NUL record fields. Its direct system loaders independently cap
both conventional files at one mebibyte, so the pair is not presented as an
atomic account transaction. It selects no C passwd/group API/static or
process-global enumeration state/ABI, errno TLS, shadow, utmp/utmpx, mntent,
login/user-shell helper, mutation or group initialization, NSS/provider
framework, or public x86 support.
The separate `mount-reference` gate verifies the private `mount.basic` error
boundary: `mount::{mount, unmount, MountFlags, UnmountFlags}` converts only
non-null checked source, target, and filesystem-type byte paths and optional
borrowed `&CStr` data, then uses direct x86 `mount=165` and `umount2=166`.
Its Rust, no-std, raw, and pinned-musl evidence exercises only unique missing
targets and direct errors: each raw/musl pair agrees on `EPERM` when permission
checking wins or `ENOENT` once target resolution follows it. It neither grants
authority nor performs successful mount-namespace mutation. Null source/type forms, arbitrary data pointers,
`pivot_root`/`unshare`/`setns` or namespace management, bind/remount/
propagation policy, filesystem-descriptor mount APIs, C ABI/errno TLS, and
public x86 support remain excluded.

The `facade` gate proves both native pattern slices as release no-std archives.
For `fnmatch`, native `readelf` requires x86-64 members and native `nm`
requires the probe entry point while rejecting public C `fnmatch`, errno-TLS,
and allocator references. For alloc-gated `glob`/`glob_at`, the fixed probe
allocator is intentionally Rust-owned; native `nm` instead rejects public C
`glob`/`globfree`/`fnmatch`, C directory-stream, errno-TLS, and public C
allocator references. The traversal accepts only an explicit pathname or
borrowed directory root, returns sorted owned raw-byte paths, and never selects
the C `glob_t` ABI or hidden CWD policy. Neither slice makes x86 public runtime
support.

Run it only on a native Linux x86_64 host:

```sh
./scripts/dev-x86_64.sh image
./scripts/dev-x86_64.sh musl-oracle
./scripts/dev-x86_64.sh header-abi-reference
./scripts/dev-x86_64.sh public-header-surface
./scripts/dev-x86_64.sh installed-header-tree-closure
./scripts/dev-x86_64.sh header-abi-project
./scripts/dev-x86_64.sh math-complex-header-abi
./scripts/dev-x86_64.sh math-complex-complete-header-abi
./scripts/dev-x86_64.sh math-elementary-long-double-header-abi
./scripts/dev-x86_64.sh sys-reg-header-abi
./scripts/dev-x86_64.sh machine-context-header-abi
./scripts/dev-x86_64.sh types-header-abi
./scripts/dev-x86_64.sh stat-header-abi
./scripts/dev-x86_64.sh ftw-header-abi
./scripts/dev-x86_64.sh utime-header-abi
./scripts/dev-x86_64.sh pthread-c11-header-abi
./scripts/dev-x86_64.sh pthread-spin-destroy-header-abi
./scripts/dev-x86_64.sh ctype-header-abi
./scripts/dev-x86_64.sh locale-profile-header-abi
./scripts/dev-x86_64.sh locale-multibyte-header-abi
./scripts/dev-x86_64.sh iconv-header-abi
./scripts/dev-x86_64.sh wide-character-header-abi
./scripts/dev-x86_64.sh wcswcs-header-abi
./scripts/dev-x86_64.sh locale-object-wide-header-abi
./scripts/dev-x86_64.sh locale-narrow-header-abi
./scripts/dev-x86_64.sh integer-arithmetic-header-abi
./scripts/dev-x86_64.sh integer-parse-header-abi
./scripts/dev-x86_64.sh float-parse-header-abi
./scripts/dev-x86_64.sh getsubopt-header-abi
./scripts/dev-x86_64.sh l64a-header-abi
./scripts/dev-x86_64.sh intmax-arithmetic-header-abi
./scripts/dev-x86_64.sh personality-header-abi
./scripts/dev-x86_64.sh setfsgid-header-abi
./scripts/dev-x86_64.sh setfsuid-header-abi
./scripts/dev-x86_64.sh credential-observation-header-abi
./scripts/dev-x86_64.sh login-name-header-abi
./scripts/dev-x86_64.sh child-reaping-header-abi
./scripts/dev-x86_64.sh immediate-termination-header-abi
./scripts/dev-x86_64.sh posix-exit-header-abi
./scripts/dev-x86_64.sh sched-cpucount-header-abi
./scripts/dev-x86_64.sh sched-getcpu-header-abi
./scripts/dev-x86_64.sh sched-yield-header-abi
./scripts/dev-x86_64.sh sched-get-priority-max-header-abi
./scripts/dev-x86_64.sh sched-get-priority-min-header-abi
./scripts/dev-x86_64.sh callback-algorithms-header-abi
./scripts/dev-x86_64.sh ffs-header-abi
./scripts/dev-x86_64.sh memccpy-header-abi
./scripts/dev-x86_64.sh aio-error-header-abi
./scripts/dev-x86_64.sh byte-strings-header-abi
./scripts/dev-x86_64.sh memory-search-header-abi
./scripts/dev-x86_64.sh memccpy-header-abi
./scripts/dev-x86_64.sh mempcpy-header-abi
./scripts/dev-x86_64.sh strsep-header-abi
./scripts/dev-x86_64.sh strtok-header-abi
./scripts/dev-x86_64.sh string-copy-header-abi
./scripts/dev-x86_64.sh error-strings-header-abi
./scripts/dev-x86_64.sh string-duplication-header-abi
./scripts/dev-x86_64.sh random-entropy-header-abi
./scripts/dev-x86_64.sh time-header-abi
./scripts/dev-x86_64.sh sleep-header-abi
./scripts/dev-x86_64.sh timerfd-header-abi
./scripts/dev-x86_64.sh signalfd-header-abi
./scripts/dev-x86_64.sh poll-header-abi
./scripts/dev-x86_64.sh select-header-abi
./scripts/dev-x86_64.sh fcntl-header-abi
./scripts/dev-x86_64.sh flock-header-abi
./scripts/dev-x86_64.sh sendfile-header-abi
./scripts/dev-x86_64.sh tee-header-abi
./scripts/dev-x86_64.sh splice-header-abi
./scripts/dev-x86_64.sh sync-file-range-header-abi
./scripts/dev-x86_64.sh copy-file-range-header-abi
./scripts/dev-x86_64.sh filesystem-capacity-header-abi
./scripts/dev-x86_64.sh vector-io-header-abi
./scripts/dev-x86_64.sh unistd-header-abi
./scripts/dev-x86_64.sh getpagesize-header-abi
./scripts/dev-x86_64.sh ualarm-header-abi
./scripts/dev-x86_64.sh usleep-header-abi
./scripts/dev-x86_64.sh system-header-abi
./scripts/dev-x86_64.sh syscall-header-abi
./scripts/dev-x86_64.sh signal-header-abi
./scripts/dev-x86_64.sh mman-header-abi
./scripts/dev-x86_64.sh memory-sync-header-abi
./scripts/dev-x86_64.sh memory-locking-header-abi
./scripts/dev-x86_64.sh memfd-create-header-abi
./scripts/dev-x86_64.sh resource-header-abi
./scripts/dev-x86_64.sh socket-header-abi
./scripts/dev-x86_64.sh inet-address-header-abi
./scripts/dev-x86_64.sh socket-messages-header-abi
./scripts/dev-x86_64.sh sysv-semaphore-header-abi
./scripts/dev-x86_64.sh mq-setattr-header-abi
./scripts/dev-x86_64.sh sysv-message-shared-memory-header-abi
./scripts/dev-x86_64.sh xattr-header-abi
./scripts/dev-x86_64.sh pathname-lifecycle-header-abi
./scripts/dev-x86_64.sh mkfifo-header-abi
./scripts/dev-x86_64.sh mkdirat-header-abi
./scripts/dev-x86_64.sh mkfifoat-header-abi
./scripts/dev-x86_64.sh readlinkat-header-abi
./scripts/dev-x86_64.sh linkat-header-abi
./scripts/dev-x86_64.sh renameat2-header-abi
./scripts/dev-x86_64.sh lchown-header-abi
./scripts/dev-x86_64.sh hasmntopt-header-abi
./scripts/dev-x86_64.sh mm-abi-reference
./scripts/dev-x86_64.sh mlock-reference
./scripts/dev-x86_64.sh msync-reference
./scripts/dev-x86_64.sh madvise-reference
./scripts/dev-x86_64.sh mincore-reference
./scripts/dev-x86_64.sh fs-advice-reference
./scripts/dev-x86_64.sh ftruncate-reference
./scripts/dev-x86_64.sh timestamp-reference
./scripts/dev-x86_64.sh posix-fallocate-reference
./scripts/dev-x86_64.sh fallocate-reference
./scripts/dev-x86_64.sh file-position-reference
./scripts/dev-x86_64.sh sync-reference
./scripts/dev-x86_64.sh syncfs-reference
./scripts/dev-x86_64.sh sync-file-range-reference
./scripts/dev-x86_64.sh memfd-reference
./scripts/dev-x86_64.sh rand-reference
./scripts/dev-x86_64.sh time-abi-reference
./scripts/dev-x86_64.sh time-observation-reference
./scripts/dev-x86_64.sh relative-sleep-reference
./scripts/dev-x86_64.sh clock-nanosleep-reference
./scripts/dev-x86_64.sh getitimer-reference
./scripts/dev-x86_64.sh setitimer-reference
./scripts/dev-x86_64.sh timerfd-reference
./scripts/dev-x86_64.sh pselect-reference
./scripts/dev-x86_64.sh poll-reference
./scripts/dev-x86_64.sh ppoll-reference
./scripts/dev-x86_64.sh epoll-reference
./scripts/dev-x86_64.sh process-identity-reference
./scripts/dev-x86_64.sh process-session-reference
./scripts/dev-x86_64.sh pidfd-open-reference
./scripts/dev-x86_64.sh fcntl-getlk-reference
./scripts/dev-x86_64.sh fcntl-status-reference
./scripts/dev-x86_64.sh flock-reference
./scripts/dev-x86_64.sh sendfile-reference
./scripts/dev-x86_64.sh copy-file-range-reference
./scripts/dev-x86_64.sh scheduler-priority-bounds-reference
./scripts/dev-x86_64.sh rr-interval-reference
./scripts/dev-x86_64.sh sched-affinity-reference
./scripts/dev-x86_64.sh sched-affinity-set-reference
./scripts/dev-x86_64.sh priority-reference
./scripts/dev-x86_64.sh setpriority-reference
./scripts/dev-x86_64.sh rlimit-reference
./scripts/dev-x86_64.sh rlimit-targeted-reference
./scripts/dev-x86_64.sh setrlimit-reference
./scripts/dev-x86_64.sh umask-reference
./scripts/dev-x86_64.sh rusage-reference
./scripts/dev-x86_64.sh times-reference
./scripts/dev-x86_64.sh fstat-reference
./scripts/dev-x86_64.sh statfs-reference
./scripts/dev-x86_64.sh socket-transport-reference
./scripts/dev-x86_64.sh interface-device-reference
./scripts/dev-x86_64.sh resolver-transport-reference
./scripts/dev-x86_64.sh resolver-facade-reference
./scripts/dev-x86_64.sh netdb-reference
./scripts/dev-x86_64.sh users-databases-reference
./scripts/dev-x86_64.sh mount-reference
./scripts/dev-x86_64.sh statat-reference
./scripts/dev-x86_64.sh getcwd-reference
./scripts/dev-x86_64.sh readlinkat-reference
./scripts/dev-x86_64.sh path-core-reference
./scripts/dev-x86_64.sh xattr-reference
./scripts/dev-x86_64.sh directory-reference
./scripts/dev-x86_64.sh temporary-object-reference
./scripts/dev-x86_64.sh statx-reference
./scripts/dev-x86_64.sh cwd-canonicalize-reference
./scripts/dev-x86_64.sh root-change-reference
./scripts/dev-x86_64.sh ipc-reference
./scripts/dev-x86_64.sh shm-reference
./scripts/dev-x86_64.sh inotify-reference
./scripts/dev-x86_64.sh calendar-time-reference
./scripts/dev-x86_64.sh advanced-time-reference
./scripts/dev-x86_64.sh child-ownership-reference
./scripts/dev-x86_64.sh thread-kill-reference
./scripts/dev-x86_64.sh mapping-reference
./scripts/dev-x86_64.sh memory-vm-reference
./scripts/dev-x86_64.sh pty-basic-reference
./scripts/dev-x86_64.sh terminal-reference
./scripts/dev-x86_64.sh system-reference
./scripts/dev-x86_64.sh thread-reference
./scripts/dev-x86_64.sh thread-credentials-reference
./scripts/dev-x86_64.sh fs-credentials-reference
./scripts/dev-x86_64.sh core
./scripts/dev-x86_64.sh facade
./scripts/dev-x86_64.sh libc-syscall
./scripts/dev-x86_64.sh libc-errno-tls
./scripts/dev-x86_64.sh libc-stat-compat
./scripts/dev-x86_64.sh libc-credentials
./scripts/dev-x86_64.sh libc-bootstrap-primitives
./scripts/dev-x86_64.sh libc-signal-control
./scripts/dev-x86_64.sh libc-signal-execution
./scripts/dev-x86_64.sh libc-signal-altstack
./scripts/dev-x86_64.sh libc-timerfd
./scripts/dev-x86_64.sh libc-signalfd
./scripts/dev-x86_64.sh libc-sigpause
./scripts/dev-x86_64.sh libc-sigisemptyset
./scripts/dev-x86_64.sh libc-sigandset-sigorset
./scripts/dev-x86_64.sh libc-sigpending
./scripts/dev-x86_64.sh libc-sigrtmax
./scripts/dev-x86_64.sh libc-sigrtmin
./scripts/dev-x86_64.sh psignal-header-abi
./scripts/dev-x86_64.sh libc-psignal
./scripts/dev-x86_64.sh libc-process-signal
./scripts/dev-x86_64.sh libc-sched-getscheduler
./scripts/dev-x86_64.sh libc-alarm
./scripts/dev-x86_64.sh libc-ualarm
./scripts/dev-x86_64.sh libc-usleep
./scripts/dev-x86_64.sh libc-sigaddset-sigdelset-sigfillset
./scripts/dev-x86_64.sh libc-static-tls-v1
./scripts/dev-x86_64.sh libc-crt-static-tls
./scripts/dev-x86_64.sh libc-crt1-static-tls
./scripts/dev-x86_64.sh owned-static-sysroot
./scripts/dev-x86_64.sh libc-pthread-create-join-tls
./scripts/dev-x86_64.sh libc-pthread-identity
./scripts/dev-x86_64.sh libc-c11-lifecycle
./scripts/dev-x86_64.sh libc-pthread-detach
./scripts/dev-x86_64.sh libc-thrd-sleep
./scripts/dev-x86_64.sh libc-thrd-yield
./scripts/dev-x86_64.sh libc-pthread-cpuclock
./scripts/dev-x86_64.sh libc-pthread-name
./scripts/dev-x86_64.sh libc-pthread-barrierattr-pshared
./scripts/dev-x86_64.sh libc-pthread-barrier
./scripts/dev-x86_64.sh libc-pthread-spin-destroy
./scripts/dev-x86_64.sh libc-pthread-mutex-normal
./scripts/dev-x86_64.sh libc-pthread-rwlock
./scripts/dev-x86_64.sh libc-pthread-cond-private
./scripts/dev-x86_64.sh libc-c11-plain-sync
./scripts/dev-x86_64.sh libc-pthread-c11-once
./scripts/dev-x86_64.sh libc-pthread-c11-tsd
./scripts/dev-x86_64.sh libc-pthread-tls-aggregate
./scripts/dev-x86_64.sh libc-pthread-atfork
./scripts/dev-x86_64.sh libc-pthread-affinity
./scripts/dev-x86_64.sh termios-header-abi
./scripts/dev-x86_64.sh libc-termios-control
./scripts/dev-x86_64.sh ctermid-header-abi
./scripts/dev-x86_64.sh libc-ctermid
./scripts/dev-x86_64.sh grantpt-header-abi
./scripts/dev-x86_64.sh libc-grantpt
./scripts/dev-x86_64.sh unlockpt-header-abi
./scripts/dev-x86_64.sh libc-unlockpt
./scripts/dev-x86_64.sh gethostid-header-abi
./scripts/dev-x86_64.sh libc-gethostid
./scripts/dev-x86_64.sh issetugid-header-abi
./scripts/dev-x86_64.sh libc-issetugid
./scripts/dev-x86_64.sh endhostent-header-abi
./scripts/dev-x86_64.sh libc-endhostent
./scripts/dev-x86_64.sh libc-sethostent
./scripts/dev-x86_64.sh gettid-header-abi
./scripts/dev-x86_64.sh libc-gettid
./scripts/dev-x86_64.sh posix-close-header-abi
./scripts/dev-x86_64.sh libc-posix-close
./scripts/dev-x86_64.sh isatty-header-abi
./scripts/dev-x86_64.sh libc-isatty
./scripts/dev-x86_64.sh ttyname-r-header-abi
./scripts/dev-x86_64.sh libc-ttyname-r
./scripts/dev-x86_64.sh tcgetpgrp-header-abi
./scripts/dev-x86_64.sh libc-tcgetpgrp
./scripts/dev-x86_64.sh tcsetpgrp-header-abi
./scripts/dev-x86_64.sh libc-tcsetpgrp
./scripts/dev-x86_64.sh bsearch-header-abi
./scripts/dev-x86_64.sh libc-bsearch
./scripts/dev-x86_64.sh linear-search-header-abi
./scripts/dev-x86_64.sh libc-linear-search
./scripts/dev-x86_64.sh intrusive-queue-header-abi
./scripts/dev-x86_64.sh libc-intrusive-queue
./scripts/dev-x86_64.sh qsort-header-abi
./scripts/dev-x86_64.sh libc-qsort
./scripts/dev-x86_64.sh getpass-header-abi
./scripts/dev-x86_64.sh libc-getpass
./scripts/dev-x86_64.sh mktemp-header-abi
./scripts/dev-x86_64.sh libc-mktemp
./scripts/dev-x86_64.sh libc-process-context
./scripts/dev-x86_64.sh libc-environment
./scripts/dev-x86_64.sh libc-secure-environment
./scripts/dev-x86_64.sh libc-login-name
./scripts/dev-x86_64.sh libc-child-reaping
./scripts/dev-x86_64.sh libc-immediate-termination
./scripts/dev-x86_64.sh libc-posix-exit
./scripts/dev-x86_64.sh libc-posix-spawnattr-init
./scripts/dev-x86_64.sh libc-posix-spawnattr-getpgroup
./scripts/dev-x86_64.sh libc-callback-algorithms
./scripts/dev-x86_64.sh libc-search-tree-intrusive
./scripts/dev-x86_64.sh libc-search-hash-table
./scripts/dev-x86_64.sh libc-clock-gettime
./scripts/dev-x86_64.sh libc-clock-adjtime
./scripts/dev-x86_64.sh libc-clock-settime
./scripts/dev-x86_64.sh libc-timer-getoverrun
./scripts/dev-x86_64.sh libc-timer-delete
./scripts/dev-x86_64.sh libc-timer-gettime
./scripts/dev-x86_64.sh libc-timer-settime
./scripts/dev-x86_64.sh libc-time-observation
./scripts/dev-x86_64.sh libc-difftime
./scripts/dev-x86_64.sh libc-timegm
./scripts/dev-x86_64.sh libc-gmtime-r
./scripts/dev-x86_64.sh libc-system-configuration
./scripts/dev-x86_64.sh libc-getpagesize
./scripts/dev-x86_64.sh libc-mapping-core
./scripts/dev-x86_64.sh libc-memory-sync
./scripts/dev-x86_64.sh libc-memory-locking
./scripts/dev-x86_64.sh libc-memfd-create
./scripts/dev-x86_64.sh libc-allocator-runtime
./scripts/dev-x86_64.sh libc-allocator-basic-runtime-v1
./scripts/dev-x86_64.sh libc-allocator-string-duplication
./scripts/dev-x86_64.sh libc-scandir
./scripts/dev-x86_64.sh libc-filesystem-traversal
./scripts/dev-x86_64.sh libc-filesystem-directory
./scripts/dev-x86_64.sh libc-allocator-observability
./scripts/dev-x86_64.sh libc-alloca
./scripts/dev-x86_64.sh libc-stack-chk-fail
./scripts/dev-x86_64.sh libc-static-c-abi-same-object-differential
./scripts/dev-x86_64.sh qualification-posix-abi-admission
./scripts/dev-x86_64.sh libc-header-layouts-baseline
./scripts/dev-x86_64.sh libc-nanosleep
./scripts/dev-x86_64.sh libc-usleep
./scripts/dev-x86_64.sh sleep-header-abi
./scripts/dev-x86_64.sh libc-sleep
./scripts/dev-x86_64.sh libc-clock-nanosleep
./scripts/dev-x86_64.sh libc-descriptor-entry
./scripts/dev-x86_64.sh libc-access
./scripts/dev-x86_64.sh libc-fcntl-status-control
./scripts/dev-x86_64.sh libc-fcntl-record-locks
./scripts/dev-x86_64.sh libc-flock
./scripts/dev-x86_64.sh libc-sendfile
./scripts/dev-x86_64.sh libc-tee
./scripts/dev-x86_64.sh libc-splice
./scripts/dev-x86_64.sh libc-sync-file-range
./scripts/dev-x86_64.sh libc-copy-file-range
./scripts/dev-x86_64.sh libc-posix-fallocate
./scripts/dev-x86_64.sh libc-filesystem-capacity
./scripts/dev-x86_64.sh libc-vector-io
./scripts/dev-x86_64.sh libc-sysv-semaphore
./scripts/dev-x86_64.sh libc-mq-setattr
./scripts/dev-x86_64.sh libc-sysv-message-shared-memory
./scripts/dev-x86_64.sh event-descriptors-header-abi
./scripts/dev-x86_64.sh libc-event-descriptors
./scripts/dev-x86_64.sh libc-pathname-lifecycle
./scripts/dev-x86_64.sh libc-mkfifo
./scripts/dev-x86_64.sh libc-mkdirat
./scripts/dev-x86_64.sh libc-mkfifoat
./scripts/dev-x86_64.sh libc-readlinkat
./scripts/dev-x86_64.sh libc-linkat
./scripts/dev-x86_64.sh libc-renameat2
./scripts/dev-x86_64.sh libc-lchown
./scripts/dev-x86_64.sh libc-hasmntopt
./scripts/dev-x86_64.sh libc-extended-attributes
./scripts/dev-x86_64.sh libc-descriptor-io
./scripts/dev-x86_64.sh libc-descriptor-lifecycle
./scripts/dev-x86_64.sh libc-descriptor-pipeline
./scripts/dev-x86_64.sh libc-timestamp-updates
./scripts/dev-x86_64.sh libc-process-resources
./scripts/dev-x86_64.sh libc-sched-cpucount
./scripts/dev-x86_64.sh libc-sched-getcpu
./scripts/dev-x86_64.sh libc-sched-yield
./scripts/dev-x86_64.sh libc-sched-get-priority-max
./scripts/dev-x86_64.sh libc-sched-get-priority-min
./scripts/dev-x86_64.sh libc-readiness-waits
./scripts/dev-x86_64.sh libc-system-observation
./scripts/dev-x86_64.sh libc-system-information
./scripts/dev-x86_64.sh getloadavg-header-abi
./scripts/dev-x86_64.sh libc-getloadavg
./scripts/dev-x86_64.sh libc-uts-identity
./scripts/dev-x86_64.sh libc-network-byte-order
./scripts/dev-x86_64.sh libc-in6addr-any
./scripts/dev-x86_64.sh libc-in6addr-loopback
./scripts/dev-x86_64.sh libc-dn-skipname
./scripts/dev-x86_64.sh libc-ns-get16
./scripts/dev-x86_64.sh libc-socket-transport
./scripts/dev-x86_64.sh libc-socket-messages
./scripts/dev-x86_64.sh libc-memccpy
./scripts/dev-x86_64.sh libc-aio-error
./scripts/dev-x86_64.sh libc-byte-strings
./scripts/dev-x86_64.sh libc-legacy-memory
./scripts/dev-x86_64.sh libc-memccpy
./scripts/dev-x86_64.sh libc-mempcpy
./scripts/dev-x86_64.sh libc-strsep
./scripts/dev-x86_64.sh libc-strtok
./scripts/dev-x86_64.sh libc-process-globals-getopt
./scripts/dev-x86_64.sh libc-auxv-observation
./scripts/dev-x86_64.sh libc-inet-address
./scripts/dev-x86_64.sh libc-inet-ntoa
./scripts/dev-x86_64.sh libc-inet-classful
./scripts/dev-x86_64.sh libc-hstrerror
./scripts/dev-x86_64.sh endservent-header-abi
./scripts/dev-x86_64.sh libc-endservent
./scripts/dev-x86_64.sh libc-numeric-netdb
./scripts/dev-x86_64.sh libc-interface-discovery
./scripts/dev-x86_64.sh libc-random-entropy
./scripts/dev-x86_64.sh libc-memory-search
./scripts/dev-x86_64.sh libc-string-copy
./scripts/dev-x86_64.sh libc-error-strings
./scripts/dev-x86_64.sh libc-ctype
./scripts/dev-x86_64.sh libc-integer-arithmetic
./scripts/dev-x86_64.sh libc-integer-parse
./scripts/dev-x86_64.sh libc-float-parse
./scripts/dev-x86_64.sh libc-getsubopt
./scripts/dev-x86_64.sh libc-l64a
./scripts/dev-x86_64.sh libc-a64l
./scripts/dev-x86_64.sh libc-intmax-arithmetic
./scripts/dev-x86_64.sh libc-personality
./scripts/dev-x86_64.sh libc-setfsgid
./scripts/dev-x86_64.sh libc-setfsuid
./scripts/dev-x86_64.sh libc-credential-observation
./scripts/dev-x86_64.sh libc-ffs
./scripts/dev-x86_64.sh libc-thread-pointer
./scripts/dev-x86_64.sh libc-foundation
./scripts/dev-x86_64.sh libc-fenv
./scripts/dev-x86_64.sh libc-math-complex
./scripts/dev-x86_64.sh libc-math-complex-complete
./scripts/dev-x86_64.sh libc-elementary-sqrt-fenv
./scripts/dev-x86_64.sh libc-fenv-rounding
./scripts/dev-x86_64.sh libc-math-minmax
./scripts/dev-x86_64.sh libc-math-bit-sign
./scripts/dev-x86_64.sh libc-math-trunc
./scripts/dev-x86_64.sh libc-math-fmod
./scripts/dev-x86_64.sh libc-math-exp2
./scripts/dev-x86_64.sh libc-math-expm1
./scripts/dev-x86_64.sh libc-math-log10
./scripts/dev-x86_64.sh libc-math-elementary-long-double
./scripts/dev-x86_64.sh libc-fdim
./scripts/dev-x86_64.sh libc-locale-profile
./scripts/dev-x86_64.sh libc-locale-multibyte
./scripts/dev-x86_64.sh libc-locale-wide-iconv
./scripts/dev-x86_64.sh libc-wide-character
./scripts/dev-x86_64.sh libc-wcswcs
./scripts/dev-x86_64.sh libc-locale-object-wide
./scripts/dev-x86_64.sh libc-locale-narrow
./scripts/dev-x86_64.sh libc-locale-error-strings
./scripts/dev-x86_64.sh libc-memory
./scripts/dev-x86_64.sh libc-setjmp
./scripts/dev-x86_64.sh libc-atomic
./scripts/dev-x86_64.sh libc-clone-raw
./scripts/dev-x86_64.sh libc-signal-foundation
./scripts/dev-x86_64.sh ldso-relocation
./scripts/dev-x86_64.sh ldso-image
./scripts/dev-x86_64.sh ldso-initial-graph
./scripts/dev-x86_64.sh ldso-target-root
./scripts/dev-x86_64.sh loader-libc-general-tls-runtime-v1
./scripts/dev-x86_64.sh loader-libc-general-tls-runtime-v1-target-root
./scripts/dev-x86_64.sh dynamic-main-thread-runtime-v1
./scripts/dev-x86_64.sh dynamic-main-thread-runtime-v1-target-root
./scripts/dev-x86_64.sh ldso-initial-tls
./scripts/dev-x86_64.sh ldso-initial-exec-tls
./scripts/dev-x86_64.sh ldso-owned-crt-handoff
./scripts/dev-x86_64.sh ldso-fixed-graph-introspection
./scripts/dev-x86_64.sh ldso-fixed-graph-dlfcn
./scripts/dev-x86_64.sh ldso-public-dlfcn
./scripts/dev-x86_64.sh ldso-dladdr-symbol-bounds
./scripts/dev-x86_64.sh ldso-dynamic-admission
```

The runner rejects non-Linux and non-x86_64 hosts before Docker, requests
`linux/amd64` for both image build and execution, and validates the image
identity. Its exact evidence command is:

```sh
cargo test --locked --target x86_64-unknown-linux-musl -p crabc-core --lib --no-default-features -- --test-threads=1
```

`musl-oracle` source-builds the SHA-verified upstream musl 1.2.6 release under
`/opt/musl-1.2.6` in the x86 image (with the immutable release-commit fallback)
and proves that its compiler, interpreter, and running `libc.so` are exactly
that tree. It is C/POSIX oracle provenance only: it neither builds a crabc
artifact nor constitutes a musl differential result.

`header-abi-reference` compiles a C reference fixture only with that pinned
toolchain. It locks down the x86 SysV LP64 and x87 `long double`/`fenv` baseline
which the future target-split crabc headers must meet. It deliberately does
not compile crabc headers and is not public x86 C-header support.

`libc-static-c-abi-differential` is the private bootstrap for the still-planned
`compat.abi-differential` family. It builds one explicit selected x86
`crabc-libc` archive, then supplies that path to a reusable comparator. The
shared `memfd_create` workload compiles once against pinned musl headers/runtime
and once against project headers plus the freestanding archive. Both lanes run
under a fixed empty environment; the workload reports stable semantic booleans
and errno constants rather than nondeterministic descriptor numbers. The
comparator performs only CRLF-to-LF normalization, requires exact output and
empty stderr from both lanes, and fails on any difference. This is real
selected-static-archive evidence for the narrow memfd/errno boundary, not an
ABI inventory, same-object closure, dynamic-runtime test, family completion,
promotion, or public x86 support.

`libc-static-c-abi-same-object-differential` is the first true same-object
artifact within that still-planned family. It compiles the bounded
`memfd_create` workload exactly once against pinned musl 1.2.6 headers, hashes
that relocatable object, then passes the same path to the pinned-musl link and
to a freestanding link against one explicitly built selected `libc.a`. The
candidate uses the archive-owned Static Initial TLS v1 bootstrap and must have
`PT_TLS` but no interpreter, `DT_NEEDED`, unresolved symbol, dynamic-TLS
resolver, or ambient libc/CRT input. The reference must name the pinned
`/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1` interpreter and `libc.so` soname and
must not acquire a glibc or search-path dependency. Both executables run under
`env -i` with fixed locale and timezone, require empty stderr and the exact
semantic record, and admit only CRLF-to-LF normalization. The same transaction
also runs the separate project-header `memfd_create` declaration gate;
pinned-header object reuse is not presented as candidate-header closure. This
remains a private static `memfd_create`/errno boundary, not the missing x86 ABI
inventory, dynamic symbol ratchet, broader differential, owned sysroot, family
completion, promotion, or public support.

`qualification-posix-abi-admission` consumes that same-object transaction and
four existing real selected-static-archive gates as the checked five-case
inventory in `qualification_posix_abi.json`: process context, bounded
process-signal execution, child reaping, and the two-worker pthread/TLS
aggregate. The standard-library runner validates the exact ordered runner,
owning-family, completion-marker, and timeout records; scrubs ambient compiler,
header, linker, and runtime overrides; starts every child in a fresh process
group; and kills the whole group on timeout. A child succeeds only with status
zero and one exact final completion marker. Each child gate continues to own
its pinned-musl comparison, selected candidate construction, ELF/TLS audit,
and runtime assertions. This is executable admission evidence, not a generated
report and not a substitute for the canonical dynamic x86 `os-test`,
`libc-test`, `pthread-stress`, or `signal-process` gates. Their runtime/sysroot
prerequisites, the remaining ABI contract, family completion, promotion, and
public x86 support remain required.

`headers-layouts.toml` is the checked-in contract for the fifty selected
native header gates. It names each dispatcher command, direct C/C++ probe and
runner, and only the project headers explicitly included by those probes. It
does not claim a transitive include closure, complete installed headers,
archive linkage, runtime completion, or public x86 support; the ledger
validator rejects a missing, renamed, or reclassified gate.

The direct `utime-header-abi` gate checks the x86 LP64 `struct utimbuf`,
`utime` declaration, and C++ C linkage. The `pthread-c11-header-abi` gate is a
28-context C11/C++17 feature-profile matrix for selected `pthread.h`,
`threads.h`, and `sched.h` layouts, macros, type identities, include orders,
GNU declarations, and unmangled C linkage. Its selected declarations include
every `pthread_rwlock_*` and `pthread_rwlockattr_*` signature plus all seven
`pthread_barrierattr_*`/`pthread_barrier_*` names, and the C++ object probe
requires their unmangled C linkage. Both are compile-only partial evidence:
they do not select archive linkage, pthread behavior, header-family completion,
or public x86 support.

`public-header-surface` adds the separate all-public-header inventory needed
before that bounded gate set can grow into a completion contract. It derives
the 183 pinned-musl public header paths, compares them to the checked-in
`public_headers.txt` inventory, requires every reference path to exist in the
project include tree, and compiles each empty C11+GNU consumer with project
headers first and then with pinned musl alone. This legacy runner intentionally
does not add the image's declared `/opt/linux-5.10-uapi/include` root, so it
records 180 jointly consumable headers, three shared UAPI-omission records
(`sys/kd.h`, `sys/soundcard.h`, and `sys/vt.h`), and eight candidate-only
headers. The report is generated under `compat/reports/`; it is a
consumability/accounting artifact, not declaration, layout, linkage, runtime,
installed-header completion, or public x86 support evidence.

`headers-layouts-foundation.toml` is the planned all-public-header accounting contract that turns those
separate inventories into a reviewable closure plan without claiming family
completion. It partitions all 183 pinned paths plus eight project-only
extensions, fixes the three `sys/*` dependencies to one Linux 5.10 x86 UAPI
export (source SHA-256
`dcdf99e43e98330d925016985bfbc7b83c66d367b714b2de0cbbfcbf83d8ca43`,
935 exported headers, and derived manifest SHA-256
`00cdc98ceb35926f68dc57dc0d84a989a6df4f60f84b1ae5981b54bb1088eb0e`),
with `compat/upstreams.toml#linux_5_10_uapi` owning that identity, and makes
`linux-5-10-uapi` verify that input independently. The live
`uapi-wrapper-matrix` command resolves exactly the three `sys/*` wrappers
across all five C11 and two C++17 profiles through both pinned-musl and
raw-GCC project-header-first roots, with selected forwarding constants, ioctl
encodings, and x86 LP64 layouts. It is compile-only and does not select
callable linkage, sound/console device behavior, general UAPI behavior, or
runtime support. The separate `ioctl-header-abi` command resolves seven
compile-only C11/C++17 profile rows for direct `sys/ioctl.h`: the signed
`int ioctl(int, int, ...)` declaration, C++ C-linkage spelling, selected
`_IOC` composition, direct 8-byte align-2 `struct winsize`, and selected
descriptor/terminal/interface request values. It proves neither artifact
linkage nor generic device/request behavior. The separate `epoll-header-abi`
command resolves seven
compile-only C11/C++17 profile rows for the pinned non-UAPI `sys/epoll.h`
header: its x86 packed event record, selected declarations/values, and only
the direct `sys/ioctl.h` `_IOC`/`_IOR`/`_IOW` encoding subset used by
`EPIOC*`. It excludes standalone ioctl declaration parity/linkage, epoll
linkage, runtime/device behavior, and header-family completion.
The direct `event-descriptors-header-abi` inventory gate resolves eight
compile-only C/C++ profiles for the selected `sys/eventfd.h` and
`sys/inotify.h` surface. Pinned musl 1.2.6 makes that direct selected surface
unconditional: `eventfd_t`, `inotify_event`, selected direct flags, and
header-requested unmangled C++ C-linkage spelling compile in every row. Because
both headers immediately include `fcntl.h`, the gate also records just one
real feature boundary: `AT_EMPTY_PATH` is visible in default-C/GNU/BSD and
hidden in strict/POSIX/XOPEN, including macro-free C++17. Its `nm` check proves
only a header-requested external spelling, not actual callable artifact
linkage. This is an explicit narrow foundation facet; global feature
visibility remains planned. Together with the retained `epoll-header-abi`
matrix, it is artifact-local header evidence and not general
descriptor-header completion or event-descriptor runtime evidence.

The separate private `dirent-header-abi` gate
(`./scripts/dev-x86_64.sh dirent-header-abi`) compares project-header-first
raw-GCC and pinned-musl 1.2.6 `<dirent.h>` declarations, feature selection,
x86 LP64 layouts, and the C spellings requested by C++ declarations. Its seven
base C11/C++17 profiles plus four `_LARGEFILE64_SOURCE` profiles—GNU and strict
C11/C++17—fix the selected `struct dirent`/`struct posix_dent` records,
`d_fileno` compatibility spelling, C++ `extern "C"` declaration boundary,
GNU-only `versionsort`, and the LFS aliases. The strict LFS profiles expose
the aliases but keep `seekdir`/`telldir`, `getdents`, and `versionsort` hidden.
`IFTODT`, `DTTOIF`, and `getdents` are GNU-or-BSD-visible; `versionsort`
remains GNU-only. The C++ `nm` check proves only header-requested unmangled C
names. It is compile-only evidence: it does not prove actual archive linkage,
directory-stream runtime behavior, directory/header-family promotion, or
public x86 support. Full x86-64 parity remains the separate promotion goal.

The separate private `ftw-header-abi` gate
(`./scripts/dev-x86_64.sh ftw-header-abi`) compares project-header-first and
pinned-musl 1.2.6 `<ftw.h>` declarations across seven base C11/C++17 feature
profiles plus GNU C11/C++17 `_LARGEFILE64_SOURCE` alias profiles. Pinned musl
exposes `ftw` in every profile, while the frozen project
header deliberately retains its legacy GNU/BSD/XOPEN-below-800 visibility
gate; the runner records that inherited divergence rather than hiding it.
`nftw` remains declared in every profile; both LFS profiles prove the `ftw64`
and `nftw64` macro aliases, and the C++ probes retain the unmangled C
spellings. This is declaration evidence only: it does not prove
archive linkage, traversal runtime behavior, promotion, or public x86 support.

The separate private `xattr-header-abi` gate
(`./scripts/dev-x86_64.sh xattr-header-abi`) compares project-header-first and
pinned-musl 1.2.6 `<sys/xattr.h>` across eleven C11/C++17 feature profiles. It
keeps all twelve selected path, no-follow-path, and descriptor
`set`/`get`/`list`/`remove` declarations unconditional, fixes LP64 scalar
types and `XATTR_CREATE=1`/`XATTR_REPLACE=2`, and verifies unmangled C++
spellings. It is compile-only declaration evidence, not xattr runtime,
header-family completion, promotion, or public x86 support.

The separate private `stdlib-header-abi` gate
(`./scripts/dev-x86_64.sh stdlib-header-abi`) compares raw-GCC
project-header-first and pinned-musl 1.2.6 `<stdlib.h>` across twelve C11/C++17
strict, POSIX.1-2008, X/Open 700, GNU, BSD, and `_LARGEFILE64_SOURCE`
profiles. It checks selected unconditional declarations and LP64 `div_t`
records; named POSIX/X/Open/GNU/BSD/GNU-only/LFS visibility and negative hidden
witnesses; requested unmangled C++ C spellings; and C++ `NULL`/`nullptr`
behavior, including strict `stdio.h`-first and `string.h`-first include orders.
It is compile-only header evidence: it does not prove callable/archive linkage,
stdlib runtime or lifecycle behavior, all-header closure, family promotion, or
public x86 support.

The paired private `stdio-standard-header-abi` and `libc-stdio-standard` gates
record only the static `static-c-stdio-standard-streams` evidence slice for the
permanent `stdin`, `stdout`, and `stderr` streams. The header gate covers
selected declarations, data, macros, and C/C++ ABI; the static fixture covers
selected byte/block/status APIs, explicit `fflush`, sticky EOF/`ungetc`
transitions, and musl-shaped discard-on-output-error behavior. It excludes
path or dynamically owned streams as a claim of that artifact and
ordinary-exit flushing, and does not
constitute general stdio, x86 support, parity, promotion, or public support.
Run `./scripts/dev-x86_64.sh stdio-standard-header-abi` for the declaration
matrix and `./scripts/dev-x86_64.sh libc-stdio-standard` for the static
runtime fixture.

The separate `stdio-permanent-byte-io-header-abi` and
`libc-stdio-permanent-byte-io` gates record a private
`static-c-stdio-permanent-byte-io` artifact without adding an export or
capability. Its pinned-musl/static differential exercises only permanent
`stdin`/`stdout`/`stderr`: `fgetc`/`getc`/`getchar` consume two bytes then EOF,
one `ungetc(-2)` returns and supplies the converted byte after EOF,
`fputc`/`putc` directly write permanent stderr, and `putchar` reaches stdout.
Its strict C11/C++17 proof ratchets the seven exact signatures and unmangled C++
spellings. An existing explicit `fflush(stdout)` only observes the `putchar`
byte; this does not select a buffering contract. The artifact never creates a
pathname `FILE *`, despite the shared implementation's separately selected
pathname sibling. It excludes `stdio.stream-io`, path/descriptor-reopen/tmpfile
or LP64/LFS behavior, `fread`/`fwrite`, general buffering, locks/unlocked APIs,
pushback capacity, multiple streams, line/formatted/wide/memory/cookie/popen
I/O, ordinary-exit flushing, general stdio, parity, promotion, and public x86
support.

The separate `stdio-permanent-status-header-abi` and
`libc-stdio-permanent-status` gates record a private
`static-c-stdio-permanent-status` artifact without an export or capability.
Its pinned-musl/static differential calls `feof`, `ferror`, and `clearerr`
only on permanent `stdin`: an empty pipe produces the EOF marker, `clearerr`
resets both predicates, and a subsequently closed descriptor produces the
error marker before a second reset. Existing `fgetc(stdin)` calls only induce
those observable markers; they do not add byte-I/O evidence. The C/POSIX
contract is zero versus nonzero, so this leaf does not claim musl's internal
numeric `1` normalization or lock behavior. The strict C11/C++17 proof
ratchets the two `int (FILE *)` predicates, `void clearerr(FILE *)`, and
unmangled C++ spellings. It never creates a pathname `FILE *` and excludes
`stdio.stream-io`, path/descriptor-reopen/tmpfile or LP64/LFS behavior,
byte/block/output/buffering/position/lock and unselected unlocked APIs,
multiple streams,
line/formatted/wide/memory/cookie/popen I/O, ordinary-exit flushing, general
stdio, parity, promotion, and public x86 support.

The separate `stdio-permanent-fsetlocking-stdin-header-abi` and
`libc-stdio-permanent-fsetlocking-stdin` gates record one private
`static-c-stdio-permanent-fsetlocking-stdin` artifact. It adds only the GNU
`__fsetlocking` C ABI spelling, without promoting a capability. Its pinned-musl/
static differential calls `__fsetlocking(stdin, request)` directly and through
a function pointer for `FSETLOCKING_QUERY`, `FSETLOCKING_INTERNAL`, and
`FSETLOCKING_BYCALLER`. Musl 1.2.6 keeps the source body as unconditional
`return 0;`, so each valid call returns exact `int` `0` without dereferencing
the FILE object or establishing a lock mode. The strict C11/C++17 `stdio_ext.h`
matrix proves its unconditional `int (FILE *, int)` declaration, the exact
`0`/`1`/`2` macro values, and unmangled C++ linkage. This is neither lock
configuration nor a general FILE claim: it excludes arbitrary FILE or request
behavior, FLOCK/FUNLOCK and lock-free behavior, input/output/buffering/cursor,
other permanent streams, every other `stdio_ext` helper except separately
selected `__freading(stdin)`, `__fseterr(stdin)`, `__freadable(stdin)`,
`__fbufsize(stderr)`, and `__flbf(stderr)`, stdio.stream-io,
path/descriptor-reopen/tmpfile/LFS behavior,
byte/block I/O including `fread`/`fwrite`, positions/status/configuration,
multiple streams, general stdio, parity, promotion, and public x86 support.

The separate `stdio-permanent-fseterr-stdin-header-abi` and
`libc-stdio-permanent-fseterr-stdin` gates record one private
`static-c-stdio-permanent-fseterr-stdin` artifact. It adds only the GNU
`__fseterr` C ABI spelling, without promoting a capability. Its pinned-musl/
static differential calls `__fseterr(stdin)` directly and through a function
pointer, then uses existing `ferror(stdin)` and `clearerr(stdin)` only to
observe and reset the selected error marker. Musl 1.2.6 `ext2.c` does exactly
`f->flags |= F_ERR`; the evidence therefore proves only a zero-to-nonzero
status observation and reset, not a numeric normalization, I/O, or general
FILE error model. The strict C11/C++17 `stdio_ext.h` matrix proves its
unconditional `void (FILE *)` declaration and unmangled C++ linkage. It
excludes arbitrary FILE, FLOCK/FUNLOCK, lock-free behavior, EOF, input/output/
buffering/cursor/configuration, other streams, every other `stdio_ext` helper
except separately selected fixed `__freading(stdin)`, `__fsetlocking(stdin)`,
`__freadable(stdin)`, `__fbufsize(stderr)`, and `__flbf(stderr)`,
`stdio.stream-io`, path/descriptor-reopen/tmpfile/LFS behavior, byte/block I/O
including `fread`/`fwrite`, positions, multiple streams, general stdio, parity,
promotion, and public x86 support.

The separate `stdio-permanent-freading-stdin-header-abi` and
`libc-stdio-permanent-freading-stdin` gates record one private
`static-c-stdio-permanent-freading-stdin` artifact. It adds only the GNU
`__freading` C ABI spelling, without promoting a capability. Its pinned-musl/
static differential calls `__freading(stdin)` directly and through a function
pointer; musl evaluates `(f->flags & F_NOWR) || f->rend`, and the permanent
stdin record fixes `F_NOWR`, so the first term makes every read-only
observation exact `int` `1`. The strict C11/C++17 `stdio_ext.h` matrix proves
its unconditional `int (FILE *)` declaration and unmangled C++ linkage. This
is neither input behavior nor a general FILE direction/cursor claim: it
excludes arbitrary FILEs, FLOCK/FUNLOCK or lock-free behavior, other permanent
streams, every other `stdio_ext` helper except the separately selected fixed
`__freadable(stdin)`, `__fwritable(stderr)`, `__fbufsize(stderr)`, and `__flbf(stderr)` siblings,
stdio.stream-io, path/descriptor-reopen/tmpfile/LFS behavior, byte/block I/O
including `fread`/`fwrite`, positions/status/configuration/buffering, multiple
streams, general stdio, parity, promotion, and public x86 support.

The separate `stdio-permanent-freadable-stdin-header-abi` and
`libc-stdio-permanent-freadable-stdin` gates record one private
`static-c-stdio-permanent-freadable-stdin` artifact. It adds only the GNU
`__freadable` C ABI spelling, without promoting a capability. Its
pinned-musl/static differential calls `__freadable(stdin)` directly and through
a function pointer; the fixed permanent stdin flags omit `F_NORD`, so each
read-only observation returns exact `int` `1`. The strict C11/C++17
`stdio_ext.h` matrix proves its unconditional `int (FILE *)` declaration and
unmangled C++ linkage. This is neither input behavior nor a general FILE
access-mode claim: it excludes arbitrary FILEs, FLOCK/FUNLOCK or lock-free
behavior, other permanent streams, every other `stdio_ext` helper except the
separately selected fixed `__freading(stdin)`, `__fwritable(stderr)`,
`__fbufsize(stderr)`, and `__flbf(stderr)` siblings,
stdio.stream-io, path/descriptor-reopen/tmpfile/LFS behavior, byte/block I/O
including `fread`/`fwrite`, positions/status/configuration/buffering, multiple
streams, general stdio, parity, promotion, and public x86 support.

The separate `stdio-permanent-fwritable-stderr-header-abi` and
`libc-stdio-permanent-fwritable-stderr` gates record one private
`static-c-stdio-permanent-fwritable-stderr` artifact. It adds only the GNU
`__fwritable` C ABI spelling, without promoting a capability. Its
pinned-musl/static differential calls `__fwritable(stderr)` directly and
through a function pointer; the fixed permanent stderr flags omit `F_NOWR`,
so each read-only observation returns exact `int` `1`. The strict C11/C++17
`stdio_ext.h` matrix proves its unconditional `int (FILE *)` declaration and
unmangled C++ linkage. This is neither output behavior nor a general FILE
access-mode claim: it excludes arbitrary FILEs, FLOCK/FUNLOCK or lock-free
behavior, other permanent streams, every other `stdio_ext` helper except the
separately selected fixed `__freading(stdin)`, `__fbufsize(stderr)`, and
`__flbf(stderr)` siblings,
stdio.stream-io, path/descriptor-reopen/tmpfile/LFS behavior, byte/block I/O
including `fread`/`fwrite`, positions/status/configuration/buffering, multiple
streams, general stdio, parity, promotion, and public x86 support.

The separate `stdio-permanent-fbufsize-stderr-header-abi` and
`libc-stdio-permanent-fbufsize-stderr` gates record one private
`static-c-stdio-permanent-fbufsize-stderr` artifact. It adds only the GNU
`__fbufsize` C ABI spelling, without promoting a capability. Its pinned-musl/
static differential calls `__fbufsize(stderr)` directly and through a function
pointer; musl's permanent stderr record fixes `buf_size = 0`, matching crabc's
fixed capacity, so every read-only observation returns exact `size_t` `0`.
The strict C11/C++17 `stdio_ext.h` matrix proves its unconditional
`size_t (FILE *)` declaration and unmangled C++ linkage. This is neither
buffering setup nor a general FILE buffer-size claim: it excludes arbitrary
FILEs, FLOCK/FUNLOCK or lock-free behavior, the separately selected
`__freading(stdin)` sibling, `__freadable(stdin)` sibling,
`__fwritable(stderr)` sibling, and `__flbf(stderr)` sibling, other permanent
streams, every other unselected
`stdio_ext` helper, stdio.stream-io, path/descriptor-reopen/tmpfile/LFS
behavior, byte/block I/O including `fread`/`fwrite`, positions/status/
configuration, multiple streams, general stdio, parity, promotion, and public
x86 support.

The separate `stdio-permanent-flbf-stderr-header-abi` and
`libc-stdio-permanent-flbf-stderr` gates record one private
`static-c-stdio-permanent-flbf-stderr` artifact. It adds only the GNU
`__flbf` C ABI spelling, without promoting a capability. Its pinned-musl/static
differential calls `__flbf(stderr)` directly and through a function pointer;
musl's permanent stderr record fixes `lbf = -1`, and this x86 leaf admits no
permanent-stream configuration, so every read-only observation returns exact
`int` `0`. The strict C11/C++17 `stdio_ext.h` matrix proves its unconditional
`int (FILE *)` declaration and unmangled C++ linkage. This is neither
line-buffer setup nor a general FILE line-buffer claim: it excludes arbitrary
FILEs, FLOCK/FUNLOCK or lock-free behavior, the separately selected
`__freading(stdin)`, `__freadable(stdin)`, `__fwritable(stderr)`, and
`__fbufsize(stderr)` siblings, other permanent streams, every other unselected `stdio_ext` helper,
stdio.stream-io, path/descriptor-reopen/tmpfile/LFS behavior, byte/block I/O
including `fread`/`fwrite`, positions/status/configuration, multiple streams,
general stdio, parity, promotion, and public x86 support.

The separate `stdio-permanent-feof-unlocked-header-abi` and
`libc-stdio-permanent-feof-unlocked` gates record one private
`static-c-stdio-permanent-feof-unlocked` artifact. It adds only musl's weak,
same-address GNU/BSD `feof_unlocked` alias of strong `feof`, without promoting
a capability. Its pinned-musl/static fixture compares both function-pointer
addresses only on permanent `stdin`, then uses an empty pipe and existing
`fgetc(stdin)` solely as EOF-marker setup: both predicates begin at zero and
become nonzero while `errno` remains zero. The C/POSIX contract is zero versus nonzero, so this does not
claim musl's internal numeric `1` normalization. The C11/C++17 matrix proves
GNU/BSD declaration visibility and unmangled C++ linkage while strict/POSIX
profiles keep it hidden. `_unlocked` does not claim a lock-free call:
FLOCK/FUNLOCK, arbitrary `FILE`, `_IO_feof_unlocked`, and `clearerr_unlocked`
remain outside this externally serialized leaf; `ferror_unlocked` is a
separately selected private alias artifact. It never
creates a pathname `FILE *` and excludes `stdio.stream-io`, path/descriptor-
reopen/tmpfile/LFS behavior, byte/block I/O beyond the marker setup,
ferror/clearerr, buffering/position, other unlocked APIs, multiple streams,
line/formatted/wide/memory/cookie/popen I/O, ordinary-exit flushing, general
stdio, parity, promotion, and public x86 support.

The separate `stdio-permanent-ferror-unlocked-header-abi` and
`libc-stdio-permanent-ferror-unlocked` gates record one private
`static-c-stdio-permanent-ferror-unlocked` artifact. It adds only musl's weak,
same-address GNU/BSD `ferror_unlocked` alias of strong `ferror`, without
promoting a capability. Its pinned-musl/static fixture compares both
function-pointer addresses only on permanent `stdin`, then closes the
descriptor so existing `fgetc(stdin)` establishes an `EBADF` error marker:
both predicates begin at zero and become nonzero. The C/POSIX contract is zero
versus nonzero, so this does not claim musl's internal numeric `1`
normalization. The C11/C++17 matrix proves GNU/BSD declaration visibility and
unmangled C++ linkage while strict/POSIX profiles keep it hidden. `_unlocked`
does not claim a lock-free call: FLOCK/FUNLOCK, arbitrary `FILE`, and
`_IO_ferror_unlocked` remain outside this externally serialized leaf. It never
creates a pathname `FILE *` and excludes `stdio.stream-io`, path/descriptor-
reopen/tmpfile/LFS behavior, byte/block I/O beyond the marker setup,
feof/clearerr, buffering/position, other unlocked APIs, multiple streams,
line/formatted/wide/memory/cookie/popen I/O, ordinary-exit flushing, general
stdio, parity, promotion, and public x86 support.

The separate `stdio-permanent-fileno-header-abi` and
`libc-stdio-permanent-fileno` gates record a private
`static-c-stdio-permanent-fileno` artifact without an export or capability.
Its pinned-musl/static differential calls `fileno` only on permanent `stdin`,
`stdout`, and `stderr`, proving their fixed `0`/`1`/`2` descriptor adapters.
It creates no `FILE *`, performs no stream I/O or descriptor mutation, and
does not select arbitrary-file, pathname, or descriptor-reopen behavior.
Pinned musl's lock and negative-descriptor `EBADF` behavior remain outside this
externally serialized leaf; the separate GNU/BSD `fileno_unlocked` sibling owns
the weak alias. The POSIX.1-2008 C11/C++17 proof ratchets `int (FILE *)` and
unmangled C++ linkage; matching strict witnesses retain its POSIX-only header
visibility. It excludes
`stdio.stream-io`, path/tmpfile/LFS behavior, byte/block/line/formatted/wide
I/O, buffering/positions/status/lock/unlocked APIs, multiple streams,
memory/cookie/popen I/O, ordinary-exit flushing, general stdio, parity,
promotion, and public x86 support.

The separate `stdio-permanent-fileno-unlocked-header-abi` and
`libc-stdio-permanent-fileno-unlocked` gates record one private
`static-c-stdio-permanent-fileno-unlocked` artifact. It adds only musl's weak,
same-address GNU/BSD `fileno_unlocked` alias of strong `fileno`, without
promoting a capability. Its pinned-musl/static fixture compares the two
function-pointer addresses and their fixed `0`/`1`/`2` results on permanent
`stdin`, `stdout`, and `stderr`; it creates no `FILE *`, does no stream I/O,
and mutates no descriptor. The C11/C++17 header matrix proves GNU/BSD
declaration visibility and unmangled C++ linkage while strict/POSIX profiles
remain negative. The conventional `_unlocked` spelling does not claim a
lock-free operation: musl's FLOCK/FUNLOCK and negative-descriptor `EBADF`
paths remain outside this externally serialized leaf. It excludes
`stdio.stream-io`, FILE/path or descriptor-reopen/tmpfile/LFS behavior, all
other unlocked APIs other than separately selected `feof_unlocked` and
`ferror_unlocked`,
byte/block/line/formatted/wide I/O, buffering/position or
status, multiple streams, memory/cookie/popen I/O, ordinary-exit flushing,
general stdio, parity, promotion, and public x86 support.

The separate `libc-stdio-format-scan` gate
(`./scripts/dev-x86_64.sh libc-stdio-format-scan`) records one private
`static-c-stdio-format-scan` artifact in the still-planned
`libc.text-math-locale-stdio` family. Its project-header C fixture first runs
against pinned musl and then a true `-nostdlib -static` candidate. It selects
only allocation-free C-locale byte-buffer
`snprintf`/`vsnprintf`/`sprintf`/`vsprintf` and NUL-string
`sscanf`/`vsscanf`: literals/`%%`; integer flags, widths, precisions, and
`hh`/`h`/`l`/`ll`/`j`/`z`/`t` length forms; byte/string and count-store
conversions; and input suppression, widths, selected integer bases and prefix
admission, `%c`, `%s`, `%n`, whitespace before literal `%%`, matching failure,
and EOF. The fixture proves alternate-form zero/precision rules, C99
would-have-written/truncation/NUL/one-byte/zero-capacity behavior,
`EOVERFLOW` for a count beyond `int`, and native register-save/overflow-area
`va_list` forwarding. A candidate-only section
ratchets deterministic `EINVAL` rejection for selected unsupported grammar.
It excludes `FILE` streams, `printf`/`fprintf`/`scanf`/`fscanf`, decimal/long-double,
wide, scanset, grouping/positional, and pointer-valued `%p` conversion,
allocation, locale objects, all integer scanner overflow apart from the
separate bounded source-overflow profiles below, general stdio, parity,
promotion, and public x86 support.

The distinct `libc-stdio-integer-scan` gate
(`./scripts/dev-x86_64.sh libc-stdio-integer-scan`) records one private
`static-c-stdio-integer-scan` artifact without adding an export or capability.
Its project-header fixture runs six fixed narrow NUL-byte strings through
pinned musl 1.2.6 and one true `-nostdlib -static` candidate, limiting itself
to `%d`/`%i`/`%u`/`%x` scans (with `%llu` only for the exact ULLONG_MAX
boundary). It records musl `vfscanf`/`intscan` source overflow: a 20-digit
decimal or 17-digit hexadecimal run beyond ULLONG_MAX consumes the complete
run, writes ERANGE, saturates at ULLONG_MAX, clears a leading minus, and then
uses the existing ordinary target store; the direct `vsscanf` path is covered
as well. This is pinned-musl source-overflow evidence, not a portable ISO C
target-overflow claim. The sibling `libc-stdio-octal-hex-scan` gate owns the
separate `%o`/`%X` overflow profile; arbitrary input, float/wide/scanset/
positional/FILE input, byte formatting, allocation, locale objects, a general
scanner or stdio boundary, parity, promotion, and public x86 support remain
outside this decimal/hex artifact.

The distinct `libc-stdio-octal-hex-scan` gate
(`./scripts/dev-x86_64.sh libc-stdio-octal-hex-scan`) records one private
`static-c-stdio-octal-hex-scan` artifact without adding an export or
capability. Its project-header fixture runs six fixed narrow NUL-byte strings
through pinned musl 1.2.6 and one true `-nostdlib -static` candidate, limiting
itself to `%o`/`%X` scans (with `%llo`/`%llX` only for exact ULLONG_MAX
boundaries). Its independent C11/C++17 header gate checks only the existing
`sscanf`/`vsscanf` signatures and unmangled C++ C spellings. It records the
power-of-two `vfscanf`/`intscan` source-overflow
path: a 22-digit octal or 17-digit uppercase-hex run beyond ULLONG_MAX consumes
its complete digit run, writes ERANGE, saturates to ULLONG_MAX, clears a leading
minus, and then makes musl's ordinary x86 target store; literal suffixes and
`%22o`/`%17X` width witnesses seal exact consumption, while direct and
`vsscanf` paths are both covered. This is pinned-musl source-overflow evidence,
not a portable ISO C target-overflow claim. Decimal/float/wide/scanset/
positional/FILE input, byte formatting, arbitrary input, allocation, locale
objects, a general scanner or stdio boundary, parity, promotion, and public x86
support remain outside it.

The distinct `libc-stdio-fixed-percent-scan` gate
(`./scripts/dev-x86_64.sh libc-stdio-fixed-percent-scan`) records one private
`static-c-stdio-fixed-percent-scan` artifact without adding an export or
capability. Its independent C11/C++17 header gate proves only the existing
`sscanf`/`vsscanf` signatures and unmangled C++ C spellings. The fixed
project-header fixture compares pinned musl 1.2.6 with a true
`-nostdlib -static` candidate for only vfscanf's top-level `%%` parser state: selected
C-locale input whitespace is skipped, exactly one percent is consumed without
a destination or assignment, a following literal continues normally, and
zero-assignment matching failure remains distinct from whitespace-only or
empty-input EOF while errno stays stale. Direct `vsscanf` forwarding proves
the compiler-owned va_list is untouched. This is pinned-musl parser-state
evidence, not a general scanf-literal claim. `%n`/`%hhn` count-store,
character/string/scanset/pointer/integer/floating/wide forms, general format
whitespace, FILE input, byte formatting, locale objects, a general scanner or
stdio boundary, parity, promotion, and public x86 support remain outside it.

The distinct `libc-stdio-fixed-format-whitespace-scan` gate
(`./scripts/dev-x86_64.sh libc-stdio-fixed-format-whitespace-scan`) records
one private `static-c-stdio-fixed-format-whitespace-scan` artifact without
adding an export or capability. Its independent C11/C++17 header gate proves
only the existing `sscanf`/`vsscanf` signatures and unmangled C++ C spellings.
The fixed project-header fixture compares pinned musl 1.2.6 with a true
`-nostdlib -static` candidate for only vfscanf's top-level C-locale
format-whitespace parser state: it coalesces a format-space run, consumes zero
or more input-space bytes without a destination, assignment, or va_list
advance, and preserves stale errno. The direct and `vsscanf` witnesses cover
all selected whitespace, zero input whitespace before a literal,
all-whitespace empty-input zero success, later literal EOF, and matching
failure. This is pinned-musl parser-state evidence, not a general
scanf-format-whitespace claim. Literal-percent `%%` is owned by the sibling
fixed-percent profile; `%n`/`%hhn`, character/string/scanset/pointer/integer/
floating/wide forms, conversions, FILE input, byte formatting, locale objects,
a general scanner or stdio boundary, parity, promotion, and public x86 support
remain outside it.

The distinct `libc-stdio-fixed-literal-scan` gate
(`./scripts/dev-x86_64.sh libc-stdio-fixed-literal-scan`) records one private
`static-c-stdio-fixed-literal-scan` artifact without adding an export or
capability. Its independent C11/C++17 header gate proves only the existing
`sscanf`/`vsscanf` signatures and unmangled C++ C spellings. The fixed
project-header fixture compares pinned musl 1.2.6 with a true
`-nostdlib -static` candidate for only vfscanf's top-level non-percent,
non-format-whitespace raw-literal state: one raw byte matches one input byte
without a destination, assignment, or va_list advance and preserves stale
errno. Direct and `vsscanf` witnesses cover a complete literal, mismatch after
a matched prefix, later-literal and initial EOF, and first-byte matching
failure. This is pinned-musl parser-state evidence, not a general
scanf-literal claim. Literal-percent `%%` and C-locale format whitespace are
owned by sibling fixed profiles; `%n`/`%hhn`, character/string/scanset/pointer/
integer/floating/wide forms, conversions, FILE input, byte formatting, locale
objects, a general scanner or stdio boundary, parity, promotion, and public x86
support remain outside it.

The distinct `libc-stdio-fixed-empty-format-scan` gate
(`./scripts/dev-x86_64.sh libc-stdio-fixed-empty-format-scan`) records one
private `static-c-stdio-fixed-empty-format-scan` artifact without adding an
export or capability. Its independent C11/C++17 header gate proves only the
existing `sscanf`/`vsscanf` signatures and unmangled C++ C spellings. The
fixed project-header fixture compares pinned musl 1.2.6 with a true
`-nostdlib -static` candidate for only `vfscanf` format-NUL termination:
after musl's private NUL-string setup, an empty format skips its parser loop
and returns zero assignments for empty or nonempty input. Direct and
`vsscanf` witnesses retain stale errno and a fixture-only trailing `va_list`
sentinel. This is pinned-musl format-termination evidence, not a general
scanf-empty-format claim. Raw literal matching, literal-percent `%%`, and
C-locale format whitespace are owned by sibling fixed profiles; `%n`/`%hhn`,
character/string/scanset/pointer/integer/floating/wide forms, conversions,
external FILE input, byte formatting, locale objects, a general scanner or
stdio boundary, parity, promotion, and public x86 support remain outside it.

The distinct `libc-stdio-fixed-suppressed-character-scan` gate
(`./scripts/dev-x86_64.sh libc-stdio-fixed-suppressed-character-scan`) records
one private `static-c-stdio-fixed-suppressed-character-scan` artifact without
adding an export or capability. Its independent C11/C++17 header gate proves
only the existing `sscanf`/`vsscanf` signatures and unmangled C++ C spellings.
The fixed project-header fixture compares pinned musl 1.2.6 with a true
`-nostdlib -static` candidate for only the literal non-wide `%*3c` state:
musl assignment suppression supplies no destination, performs no `va_list`
advance or assignment, and consumes exactly three raw bytes including leading
or interior C-locale whitespace. Direct and `vsscanf` witnesses retain a
fixture-only trailing sentinel and stale errno while distinguishing a
nonempty-short matching failure from initial EOF and retaining one raw high
byte. A following literal merely witnesses consumption; raw literal matching
remains owned by the sibling fixed-literal profile. This is pinned-musl
assignment-suppression evidence, not a general scanf-suppression claim.
Unsuppressed `%c`, all other widths or suppressed forms, literal-percent `%%`,
C-locale format whitespace, `%n`/`%hhn`, string/scanset/pointer/integer/
floating/wide forms, external FILE input, byte formatting, locale objects, a
general scanner or stdio boundary, parity, promotion, and public x86 support
remain outside it.

The distinct `libc-stdio-fixed-suppressed-string-scan` gate
(`./scripts/dev-x86_64.sh libc-stdio-fixed-suppressed-string-scan`) records
one private `static-c-stdio-fixed-suppressed-string-scan` artifact without
adding an export or capability. Its independent C11/C++17 header gate proves
only the existing `sscanf`/`vsscanf` signatures and unmangled C++ C spellings.
The fixed project-header fixture compares pinned musl 1.2.6 with a true
`-nostdlib -static` candidate for only the literal non-wide `%*3s` state:
musl assignment suppression supplies no destination, performs no `va_list`
advance, terminator write, or assignment, skips C-locale input whitespace, and
consumes at most three non-whitespace token bytes. Direct and `vsscanf`
witnesses retain a fixture-only trailing sentinel and stale errno while proving
short-token success, exact-width consumption before a following literal,
whitespace-only and initial EOF, and one raw high-byte token. A following
literal merely witnesses consumption; raw literal matching remains owned by
the sibling fixed-literal profile. This is pinned-musl assignment-suppression
evidence, not a general scanf-suppression claim. Unsuppressed `%s` destination
storage, `%c`, all other widths or suppressed forms, literal-percent `%%`,
C-locale format whitespace, `%n`/`%hhn`, scanset/pointer/integer/floating/
wide forms, external FILE input, byte formatting, locale objects, a general
scanner or stdio boundary, parity, promotion, and public x86 support remain
outside it.

The distinct `libc-stdio-fixed-suppressed-scanset-scan` gate
(`./scripts/dev-x86_64.sh libc-stdio-fixed-suppressed-scanset-scan`) records
one private `static-c-stdio-fixed-suppressed-scanset-scan` artifact without
adding an export or capability. Its independent C11/C++17 header gate proves
only the existing `sscanf`/`vsscanf` signatures and unmangled C++ C spellings.
The fixed project-header fixture compares pinned musl 1.2.6 with a true
`-nostdlib -static` candidate for only the literal non-wide `%*3[abc]` state:
musl assignment suppression supplies no destination, performs no `va_list`
advance, terminator write, or assignment, does not skip C-locale input
whitespace, and consumes at most three raw a/b/c member bytes. Direct and
`vsscanf` witnesses retain a fixture-only trailing sentinel and stale errno
while proving short-member success, exact-width consumption before a following
literal, leading-whitespace and first-non-member matching failure, initial EOF,
and one high byte retained for a following raw literal. A following literal
merely witnesses member consumption; raw literal matching remains owned by the
sibling fixed-literal profile. This is pinned-musl assignment-suppression
evidence, not a general scanf-suppression or scanset claim. Unsuppressed
`%3[abc]` storage, all other widths or suppressed forms,
unbounded/leading-zero/range/inverse/allocating/wide scanset grammar,
literal-percent `%%`, C-locale format whitespace, `%n`/`%hhn`,
character/string/pointer/integer/floating/wide forms, external FILE input,
byte formatting, locale objects, a general scanner or stdio boundary, parity,
promotion, and public x86 support remain outside it.

The distinct libc-stdio-fixed-suppressed-count-scan gate
(./scripts/dev-x86_64.sh libc-stdio-fixed-suppressed-count-scan) records one
private static-c-stdio-fixed-suppressed-count-scan artifact without adding an
export or capability. Its independent C11/C++17 header gate proves only the
existing sscanf/vsscanf signatures and unmangled C++ C spellings. The fixed
project-header fixture compares pinned musl 1.2.6 with a true
-nostdlib -static candidate for only literal non-wide %*n: the star field has
no destination, while musl's count state reads no source byte, does not
advance the fixture-only trailing va_list sentinel, performs no count store,
and makes no assignment. Direct and vsscanf witnesses retain stale errno while
proving empty-input zero-assignment success, a later-literal zero-assignment
mismatch, and no source consumption seen through following raw literals. Those
literals merely witness the selected count-state boundary; raw literal
matching remains owned by the sibling fixed-literal profile. This is
pinned-musl evidence, not a portable ISO C %*n, general scanf-suppression, or
count-conversion claim. Unsuppressed %n/%hhn storage, other count lengths or
widths, character/string/scanset/pointer/integer/floating/wide forms,
literal-percent, format whitespace, external FILE input, byte formatting,
locale objects, a general scanner or stdio boundary, parity, promotion, and
public x86 support remain outside it.

The separate `libc-stdio-float-hex-output` gate
(`./scripts/dev-x86_64.sh libc-stdio-float-hex-output`) records one private
`static-c-stdio-float-hex-output` artifact without adding an export or
capability. Its project-header C fixture runs against pinned musl and a true
`-nostdlib -static` candidate, selecting only C-locale promoted binary64
`%a`/`%A` output with musl's no-op `l` modifier. It proves raw-bit default and
explicit precision spelling, all four selected x86 fenv directions
(ties-to-even in nearest mode), signed zero/subnormal/infinity/NaN, width,
zero/left padding, C99 truncation, `%n`, bounded `EOVERFLOW`, and direct plus
`v*` XMM register-save/overflow-area traversal with sequential mixed GP/SSE
arguments. Candidate-only `%f`, `%La`, and positional `%3$a` reject with
`EINVAL`. Formatter floating-exception side effects, decimal/long-double
output, FILE streams, wide/allocating forms, locale objects, general stdio,
parity, promotion, and public x86 support remain excluded.

The sibling `libc-stdio-errno-output` gate
(`./scripts/dev-x86_64.sh libc-stdio-errno-output`) records only bare
GNU/musl `%m` output through that existing byte-buffer formatter. Its
project-header C fixture first runs against pinned musl 1.2.6, then a true
`-nostdlib -static` candidate, proving no variadic argument is consumed, the
current selected initial-exec errno slot supplies the immutable fixed-C-locale
message, and ordinary selected string width/precision, truncation, `%n`, and
`v*` forwarding preserve errno. The leaf does not call public `strerror`, add
an export, or select general diagnostics, locale translation, streams, or a
broader output grammar; `%lm` and positional `%1$m` remain candidate-only
`EINVAL` rejections. It does not establish general stdio, family completion,
promotion, or public x86 support.

The separate `stdio-permanent-line-io-header-abi` and
`libc-stdio-permanent-line-io` gates record the private
`static-c-stdio-permanent-line-io` artifact. It admits `fgets`, `fputs`, and
`puts` only for the three process-lifetime standard streams; it deliberately
rejects the fixed pathname/tmpfile slot. The pinned-musl
project-header/static differential proves newline inclusion, NUL termination,
the positive one-byte `fgets` no-consume boundary, and EOF-before-a-byte;
then proves that `fputs` omits the terminating NUL and keeps both ordinary and
newline-containing stdout strings buffered until explicit `fflush`, while
`puts` appends and publishes its newline and stderr `fputs` is immediate. The
dedicated strict C11/C++17 header proof ratchets the exact declarations and
unmangled names. It does not select `stdio.stream-io`, path/descriptor-reopen/
tmpfile or LP64/LFS work, positions/buffer configuration/locks/unlocked APIs,
multiple streams, allocation/registry, `getdelim`/`getline`/legacy-word I/O,
formatted/wide/memory/cookie/`fopencookie`/`popen` streams, ordinary-exit
flushing, general stdio, parity, promotion, or public x86 support.

The separate `libc-stdio-path-stream` gate records one fixed private static
path-stream slot inside still-planned `libc.text-math-locale-stdio`: exactly
one externally serialized regular-file `fopen("r")`/`fopen("w+")` lifecycle
with selected byte/block I/O, explicit output flush, pre-I/O caller-buffered
`_IOFBF`, logical `fseek`/`fseeko`/`ftell`/`ftello`, opaque 16-byte
`fgetpos`/`fsetpos`, `rewind`, `fclose`, and slot reuse. The project-header
fixture executes first against pinned musl 1.2.6 and then a closed static
candidate, proving buffered-write positions, the active slot's participation
in all-owned-output `fflush(NULL)`, failed-seek errno without a new `ferror`,
read-ahead-adjusted `SEEK_CUR`, offset-prefix `fpos_t` restoration with opaque
tail preservation, EOF/rewind, and close/reopen behavior. Candidate-only checks
ratchet the one-slot, mode, and buffer-reconfiguration limits. It excludes
`fdopen`, `freopen`, append/exclusive/close-on-exec/general mode parsing,
multiple live streams, allocation/registries, input `fflush`, `_IONBF`/`_IOLBF`/
post-I/O buffer reconfiguration, and general stdio; it does not establish x86
support, parity, promotion, or public support.

The separate `fopen64-header-abi` and `libc-fopen64-alias` gates record the
selected-private `stdio.fopen64-alias` capability. On x86 Linux LP64, pinned
musl 1.2.6 exposes `fopen64` only when `_LARGEFILE64_SOURCE` is defined, as
the source-level `#define fopen64 fopen`; the C11/C++17 profile matrix retains
its hiding in strict, GNU, `_FILE_OFFSET_BITS=64`, and `_LARGEFILE_SOURCE`
profiles. The static fixture verifies the existing selected `fopen` route
through that macro while archive and final-ELF checks reject a distinct x86
`fopen64` symbol. Run `./scripts/dev-x86_64.sh fopen64-header-abi` and
`./scripts/dev-x86_64.sh libc-fopen64-alias` for the two proofs. This does not
complete `stdio.path-stream`, general stdio, family completion, promotion, or
public x86 support.

The separate `libc-stdio-tmpfile` gate records one bounded private static C
`tmpfile` route over that same fixed slot. It accepts only an inactive slot,
requests a mode-`0600` exclusive regular-file candidate below `/tmp`, lets the
process umask mask that mode, immediately unlinks it, and uses the descriptor
as the selected `w+` stream. It retains musl 1.2.6 `src/stdio/tmpfile.c`'s
`MAXTRIES=100` attempt bound, but deliberately replaces
`src/temp/__randname.c`'s clock/TID state with a direct 96-bit Linux
`getrandom` hexadecimal suffix; no userspace PRNG is introduced. If unlinking
fails it fails closed rather than returning a linked file. The project-header
C fixture runs first through pinned musl and then through a true
`-nostdlib -static` candidate, while a dedicated C++17 probe independently
proves the same header alias. Together they prove that
`_LARGEFILE64_SOURCE` gives `tmpfile64` only as a preprocessing alias with no
distinct ELF symbol, zero-umask mode-0600, normal restrictive-umask masking,
nlink-zero regular-descriptor state, binary read/write/seek behavior,
close/slot reuse, and the candidate-only busy-slot `EMFILE` limit. It does not
select multiple streams, a general temporary-file policy or pathname exposure,
allocation/registry, `tmpnam`/`tempnam`/`mkstemp`/`mkdtemp`/`mktemp`,
`fopencookie`, `popen`, formatted/wide I/O, ordinary-exit flushing, general
stdio, capability or family completion, promotion, or public x86 support.

The separate `libc-text-math-locale-stdio-composition` gate is one private
cross-surface static artifact, not another implementation wrapper or a family
completion claim. Its one project-header C fixture runs against pinned musl
and a closed static candidate while composing only the math/complex,
float-parse, locale/multibyte, and permanent-standard-stream boundaries.
It composes C.UTF-8 `mbrtowc`, C-locale `strtod`, `__fpclassify`, initial-exec
errno, and pipe-observed `fputc`/`fflush(stdout)`: a valid UTF-8 conversion
preserves stale errno, an invalid lead establishes EILSEQ, and successful
parsing plus explicit stream output retain that datum. It rejects dynamic TLS,
scalar libm, allocation, and ambient runtime dependencies. It does not
exercise the format/path/wide-stream, locale-object, iconv, wide-character, or
independently selected `_l` parser contracts, even though shared selected roots
can materialize sibling symbols in the final link. It does not establish general
text/math/locale/stdio behavior, parity, promotion, or public x86 support.

`libc-directory-streams` is the separate private static C runtime artifact
that follows that compile-only header evidence. One project-header fixture runs
first through pinned musl 1.2.6 and then through a true `-nostdlib -static`
candidate, covering only `opendir`, `fdopendir`, `closedir`, `dirfd`,
`readdir`, `readdir_r`, `rewinddir`, `seekdir`, `telldir`, C-locale
`alphasort`, GNU `versionsort`, `getdents`, and `posix_getdents`. It ratchets the x86
`openat=257`, `fstat=5`, `fcntl=72`, `mmap=9`, `munmap=11`, `close=3`,
`getdents64=217`, and `lseek=8` paths plus close-on-exec descriptor transfer,
255-byte names, cursor/EOF behavior, raw record framing, `ENOTDIR`, and
nonzero-flag `EOPNOTSUPP`. Its `DIR` state owns one private anonymous mapping,
not a C allocator. GNU `versionsort` delegates musl's scalar digit/leading-zero
order to the selected public `strverscmp` byte-string leaf. `scandir`,
directory walking, broader locale collation, cancellation, full C runtime/POSIX
parity, family promotion, and public x86 support remain excluded.

`libc-scandir` is a separate, strictly opt-in mixed-runtime allocation-client
artifact over that unchanged directory boundary and the separately selected
allocator wrapper. Its `x86-scandir` feature is cfg-isolated inside the
directory owner, does not modify default static roots or exports, and selects
no capability/family completion. The project-header fixture first runs through
pinned musl 1.2.6 and then through a selected crabc archive whose link map
rejects every musl directory, sort, and allocator object. It proves copied
caller-owned sorted records, zero results, failure nonpublication, and
deterministic rollback for the first vector allocation, first copied record,
and later vector growth. The internal x86 thunks call the selected
`malloc`/`realloc`/`free` C ABI names rather than allocator backend internals.
Callbacks must return normally: C++ exceptions and C `longjmp` cannot cross the
Rust boundary. It does not select `scandirat`, directory walking, allocator
lifecycle/interposition, failures inside pinned-musl startup/opendir or every
backend-corruption path, libc.so, CRT, loader, sysroot, promotion, or public
x86 support.

`libc-filesystem-traversal`
(`./scripts/dev-x86_64.sh libc-filesystem-traversal`) is the separate opt-in,
allocation-free static C artifact for `ftw` and `nftw`. Its
`x86-filesystem-traversal` feature adds exactly those two exports without
changing the default static archive; it walks from the established directory
boundary rather than selecting `scandir` or a C allocator. The project-header
fixture differentials ordinary traversal against pinned musl 1.2.6 and proves
the frozen `FTW_CHDIR` profile only on the candidate, because musl 1.2.6
ignores that flag. It covers physical/depth/mount traversal, descriptor-limit
behavior, callback return, symlink cases, and callback CWD repair and
restoration. Callbacks must return normally: C++ exceptions and C `longjmp`
cannot cross the Rust boundary. Cancellation policy, general filesystem
policy, libc.so, CRT, loader, sysroot, family promotion, and public x86
support remain outside this artifact.

`libc-filesystem-directory`
(`./scripts/dev-x86_64.sh libc-filesystem-directory`) is the private aggregate
over `libc-directory-streams`, `libc-scandir`, and
`libc-filesystem-traversal`. It reruns their independent header, ordinary-musl,
frozen-`FTW_CHDIR`, directory-stream, and allocation-client evidence, then
proves that the combined `x86-scandir,x86-filesystem-traversal` archive owns
the frozen `filesystem.directory` roster: `alphasort`, `ftw`, `nftw`,
`readdir_r`, `scandir`, `telldir`, and `versionsort`. This makes that frozen
capability `selected-private` while preserving the default archive.
`libc.posix-runtime` remains planned and nonpublic; the aggregate does not
claim family completion, promotion, or general x86 runtime support.

`libc-lchmod-unsupported` is a private native `verified_slice`, not a
promotion. Its project-header C fixture first runs a raw-created dangling
symlink through pinned musl 1.2.6 and then through the exact `crabc-libc`
archive under `-nostdlib -static`. It selects only GNU/BSD-visible `lchmod`:
the candidate returns `-1` with `EOPNOTSUPP`/`ENOTSUP` 95 without pathname
resolution or a Linux syscall; its candidate-only null-path check demonstrates
that fixed pre-resolution boundary. It excludes `fchmodat`, path/permission policy,
directory or filesystem-extension behavior, allocation, cancellation, family
completion, promotion, and public x86 support.

`mkfifo-header-abi` is an eight-profile C11/C++17 project-header/pinned-musl
matrix for unconditional `mkfifo(const char *, mode_t)`, x86 LP64 `mode_t`,
`S_IFMT`/`S_IFIFO` and selected permission constants, and unmangled C++
linkage. Its paired `libc-mkfifo` private `static-c-mkfifo` artifact runs one
project-header C fixture first through pinned musl 1.2.6 and then through a
`-nostdlib -static` candidate. It selects only `mkfifo`: musl's `mode |
S_IFIFO` reaches direct Linux x86-64 `mknodat=259` at `AT_FDCWD=-100` with
dev 0. A child-local shell `umask 000` makes FIFO type/requested mode
observable, while stale errno on success, duplicate `EEXIST`, and null-path
`EFAULT` remain checked. It does not select `filesystem.special-nodes`,
`mkfifoat`, `mknod`, `mknodat`, device-node/C-umask/pathname/CWD policy,
allocation, locale/terminal/environment/process state, family promotion, or
public x86 support.

`mkdirat-header-abi` is a distinct eight-profile C11/C++17 project-header/
pinned-musl matrix for unconditional `mkdirat(int, const char *, mode_t)`, x86
LP64 `int`/`mode_t`, directory-mode constants, `SYS_mkdirat=258`, and unmangled
C++ linkage. Its paired `libc-mkdirat` private `static-c-mkdirat` artifact runs
a project-header C fixture first through pinned musl 1.2.6 and then through a
`-nostdlib -static` candidate. It selects only musl's direct
caller-supplied-dirfd Linux x86-64 `mkdirat=258` body. Raw setup opens one
fixture-owned directory and compares 0750/0000 selected modes with one raw
0710 directory while preserving stale errno on success; it also checks
duplicate `EEXIST`, invalid-dirfd `EBADF`, null-path `EFAULT`, and missing-parent
`ENOENT` under a child-local shell `umask 000`. It neither chooses `AT_FDCWD`
nor selects `mkdir`, `mkfifo`, `mkfifoat`, `mknod`, `mknodat`, other pathname
operations, C umask/CWD/pathname/permission policy, directory streams,
allocation, locale/terminal/environment/process state, family promotion, or
public x86 support.

`mkfifoat-header-abi` is a distinct eight-profile C11/C++17 project-header/
pinned-musl matrix for unconditional `mkfifoat(int, const char *, mode_t)`, x86
LP64 `int`/`mode_t`, FIFO mode constants, and unmangled C++ linkage. Its paired
`libc-mkfifoat` private `static-c-mkfifoat` artifact runs a project-header C
fixture first through pinned musl 1.2.6 and then through a `-nostdlib -static`
candidate. It selects only `mkfifoat`: musl's `mode | S_IFIFO` passes the
caller-supplied directory fd to direct Linux x86-64 `mknodat=259` with dev 0.
Raw setup owns one fixture directory; the test observes descriptor-relative
FIFO type/mode, stale errno on success, duplicate `EEXIST`, bad-dirfd `EBADF`,
and null-path `EFAULT` under a child-local shell `umask 000`. It neither chooses
`AT_FDCWD` nor selects `mkfifo`, `mknod`, `mknodat`, device nodes, C umask/CWD/
pathname policy, `filesystem.special-nodes`, allocation, locale/terminal/
environment/process state, family promotion, or public x86 support.

`readlinkat-header-abi` is an eight-profile C11/C++17 project-header/
pinned-musl matrix for unconditional `readlinkat(int, const char *, char *,
size_t)`, including the x86 LP64 scalar types and unmangled C++ linkage. Its
paired private `libc-readlinkat` static artifact selects only musl's direct
Linux x86-64 `readlinkat=267` body. A raw-created symbolic link and regular
sibling prove full/truncated non-NUL caller output, stale `errno` success,
`ENOENT`/`EINVAL`/`EBADF`/`EFAULT`, and the zero-capacity private-dummy rule:
the selected C call returns zero without changing caller storage while the raw
zero-capacity request reports `EINVAL`. It excludes ordinary `readlink`, other
*at entries, pathname/CWD policy, directory streams, allocation, cancellation,
a Rust facade, family completion, promotion, and public x86 support.

`linkat-header-abi` is a separate eight-profile C11/C++17 project-header/
pinned-musl matrix for unconditional `linkat(int, const char *, int, const
char *, int)`, four-byte x86 LP64 `int` spelling, pointer arguments, and
unmangled C++ linkage. Its paired private `libc-linkat` static artifact selects
only musl 1.2.6's direct Linux x86-64 `linkat=265` body. The fixture creates a
regular source under one raw-opened directory descriptor and verifies the
candidate makes a descriptor-relative same-inode hard link in another against
a raw request; a raw-created source symlink proves forwarded
`AT_SYMLINK_FOLLOW`. It also proves stale `errno` success, duplicate `EEXIST`,
bad old/new dirfds `EBADF`, null old/new path `EFAULT`, missing-source `ENOENT`,
and invalid flags `EINVAL`. It excludes ordinary `link`, every other *at entry,
pathname/CWD/namespace policy, directory streams, allocation, cancellation, a
Rust facade, filesystem capability completion, family promotion, and public x86
support.

`renameat2-header-abi` is the focused eight-profile C11/C++17 project-header/
pinned-musl `<stdio.h>` matrix for the GNU-only
`renameat2(int, const char *, int, const char *, unsigned)` declaration and
`RENAME_NOREPLACE=1`, `RENAME_EXCHANGE=2`, and `RENAME_WHITEOUT=4` macros. GNU
C and C++ are visible; default, strict, POSIX, X/Open, BSD C and strict C++
are hidden. Its paired private `libc-renameat2` static artifact preserves musl
1.2.6's exact two-branch route: zero flags issue Linux x86-64 `renameat=264`,
and nonzero flags issue `renameat2=316`. The raw-owned fixture proves
descriptor-relative replacement and stale `errno`, `RENAME_NOREPLACE`
`EEXIST`, `RENAME_EXCHANGE` inode swapping, invalid exchange/whiteout
`EINVAL`, missing `ENOENT`, null-path `EFAULT`, and a raw `renameat`
comparator. It does not select ordinary `rename`, public `renameat`, other *at
entries, pathname/CWD/namespace policy, allocation, cancellation, a Rust
facade, filesystem capability completion, promotion, or public x86 support.

`lchown-header-abi` is a separate eight-profile C11/C++17 project-header/
pinned-musl matrix for unconditional `lchown(const char *, uid_t, gid_t)`,
four-byte unsigned x86 LP64 `uid_t`/`gid_t` spelling, and unmangled C++
linkage. Its paired private `libc-lchown` static artifact selects only musl
1.2.6's direct Linux x86-64 `lchown=94` branch. The raw-owned fixture creates
and observes one dangling symlink, then passes all-ones no-change owner/group
words: candidate stale `errno` success and a raw request pin final-component
no-follow behavior without requiring `CAP_CHOWN`, plus missing/empty `ENOENT`
and null `EFAULT`. It excludes `chown`, `fchown`, `fchownat`, musl's non-x86
fallback, credential/ownership policy, another pathname entry, pathname/CWD/
namespace policy, directory streams, allocation, cancellation, a Rust facade,
filesystem capability completion, family promotion, and public x86 support.

`hasmntopt-header-abi` is a separate eight-profile C11/C++17 project-header/
pinned-musl matrix for unconditional
`hasmntopt(const struct mntent *, const char *)`, the x86 LP64 40-byte,
8-byte-aligned `struct mntent` record, its 0/8/16/24/32/36 field offsets, and
unmangled C++ linkage. The current project header reaches `stdio.h` for
`FILE`, while pinned musl uses `__NEED_FILE` directly; the gate constrains only
the selected lookup declaration and record ABI. Its paired private
`libc-hasmntopt` static artifact runs a caller-owned option-byte fixture first
through musl 1.2.6 and then through one selected archive member under true
`-nostdlib -static`. It pins comma and equals boundaries, exact returned
pointers, prefix/absent negatives, musl's empty-first-element behavior, and no
mutation. The final candidate has no syscall, call, TLS, errno, helper-string,
FILE/stdio, allocation, or mntent stream/parser closure. It excludes
`setmntent`, `endmntent`, `getmntent`, `getmntent_r`, `addmntent`, `/etc/mtab`
lookup, mount databases, general string APIs, locale objects/environment/
catalogs/general locale, pathname policy, a Rust facade, promotion, and public
x86 support.

`libc-extended-attributes` is the separate private static C runtime artifact
paired with that header gate. Its project-header fixture first runs through
pinned musl 1.2.6 and then through the exact `crabc-libc` archive under
`-nostdlib -static`, selecting exactly `setxattr`, `lsetxattr`, `fsetxattr`,
`getxattr`, `lgetxattr`, `fgetxattr`, `listxattr`, `llistxattr`, `flistxattr`,
`removexattr`, `lremovexattr`, and `fremovexattr`. It compares binary and
zero-length values, size queries, initialized-prefix preservation,
NUL-separated lists, `CREATE`/`REPLACE`, and direct `ERANGE`/`EEXIST`/
`ENODATA`/`EINVAL` behavior, including a paired uniformly-unavailable
`EOPNOTSUPP`/`ENOSYS` filesystem-policy branch. It exercises no-follow calls
on a regular file without selecting symlink-storage policy. The runner also
ratchets the exact archive export set, initial-TLS `errno`, direct x86 syscall
numbers 188 through 199, and a candidate with no interpreter, `DT_NEEDED`,
unresolved symbols, dynamic TLS, or unowned runtime dependency. ACL/namespace
policy, `*xattrat`, cancellation, xattr family completion, promotion, full
x86-64 parity, and public x86 support remain excluded.
The separate `timeval-transitive-header-abi` command resolves 35 compile-only
rows for five fixed headers (`sys/time.h`, `utmpx.h`, `utmp.h`, `lastlog.h`,
and `sys/timex.h`) across seven isolated C11/C++17 profiles, proving complete
`struct timeval` visibility and named x86 LP64 embedded-record layouts only.
It does not require an identical private include graph or dependent feature
surface.
It excludes direct `sys/time.h` callable declaration/linkage, other
`sys/time.h` feature or macro parity, dependent-header callable linkage,
runtime behavior, all-header closure, family promotion, and public x86
support. The separate `sys-time-direct-header-abi` command resolves seven
compile-only profiles for the direct `sys/time.h` surface: selected
unconditional and GNU/BSD/GNU-only declarations, x86 LP64
`timeval`/`itimerval`/`timezone` layouts, interval-timer values,
timer/conversion macros, and unmangled C++ declaration references. It proves
the spelling requested by those declarations, not actual callable artifact
linkage or runtime behavior. The separate `access-header-abi` command resolves
eight compile-only profiles for direct `fcntl.h`/`unistd.h`: selected
`access`/`faccessat` declarations, access and `AT_*` values, GNU-only
`eaccess`/`euidaccess` visibility across default-C and isolated C11/C++17
profiles, and unmangled C++ declaration references. It proves only the names
requested by declarations, not artifact linkage or runtime behavior. The live
`candidate-header-closure` command resolves all 1,337 rows formed by the 183
pinned-musl public headers plus eight project-only headers across seven
isolated profiles (`c11-gnu`, `cxx17-gnu`, `c11-strict`, `c11-posix-2008`,
`c11-xopen-700`, `c11-bsd`, and `cxx17-strict`). Each row compiles the
project-header-first candidate and, where applicable, the pinned-musl
reference using only raw-GCC builtin and declared Linux-UAPI roots. The report
records exactly two explicit `reference-not-applicable` rows—
`aio.h:c11-strict` and `aio.h:cxx17-strict`—because pinned musl leaves
`struct sigevent` incomplete in those macro-free profiles; the candidate
still must compile and does. This is a complete isolated empty-TU consumer
matrix, not feature-visibility, declaration/layout, callable-linkage,
archive, runtime, installed-header, family-promotion, or public-x86 evidence.
The wider candidate visibility for those `aio.h` rows remains a tracked parity
question rather than being silently treated as equivalent. The static-export
list is only an input to the default archive linkage audit: unlisted public
callables remain owned by planned `libc.c-abi-compat`, while noncallable header
ABI remains owned by `libc.headers-layouts`.

`header-callable-provider-linkage-audit` separately uses the checked inventory
to ordinarily extract the 1,054 current default-static and 47 verified
feature-provider callable members from isolated exact Cargo profiles. It checks
replacement-symbol extractability and weak same-address aliases, while the
dedicated environment and resolver runners retain replacement-provider
selection and behavior. Its 411-name unprovided complement remains explicit:
this is selected-provider archive evidence, not full callable closure, runtime
behavior, family promotion, or public x86 support.

`header-abi-matrix` adds a separate checked Clang-derived 1,337-row report for
function source declaration forms and emitted linkage spellings plus named
typedefs, record shapes, enum values, variables, and macro replacement forms.
Its current 1,086 comparable red source-form rows, one
`aio.h:c11-strict` oracle-not-applicable row, and 56 project-only rows are
evidence to review—not parity waivers or ABI classifications. It excludes byte
layouts, anonymous declarations, inline behavior, archive linkage, runtime,
family promotion, and public x86 support.

`header-declaration-macro-visibility-matrix` derives a checked identity report
from that same refreshed compiler collection, rather than collecting another
header cross-product. It compares only named `(kind, name)` declaration and
macro visibility across all 1,337 rows: 1,072 current identity-mismatch rows,
208 matched rows, while the one `aio.h:c11-strict` oracle-not-applicable row
and 56 project-only rows retain checked candidate fact summaries and digests.
Its 22,208 same-identity source-form
differences across 766 rows—including 14 form-only rows—remain separately
accounted and are not an ABI-equality claim. This is generic feature-visibility
evidence only; declaration-form equality, layouts, linkage, runtime, family
promotion, and public x86 support remain outside it.

The private `installed-header-tree-closure` artifact separately materializes
the 191 candidate headers into a temporary `usr/include` tree, then resolves
the same 1,337 empty-TU rows across `c11-gnu`, `cxx17-gnu`, `c11-strict`,
`c11-posix-2008`, `c11-xopen-700`, `c11-bsd`, and `cxx17-strict`. Candidate
compilation is rooted at that temporary installed tree; include traces reject
both repository `include/` source-tree leakage and every host include path,
allowing only the materialized tree, raw-GCC builtin headers, and the fixed
Linux 5.10 UAPI root. The two strict `aio.h` pinned-musl
`reference-not-applicable` rows remain explicit and do not waive candidate
success. This is an installed-header-tree closure artifact distinct from the
source-tree closure, not full declaration, layout, feature-visibility, or
linkage parity; an archive or runtime artifact; CRT, loader, driver, or
owned-sysroot evidence; promotion; or public x86 support.

`header-abi-project` places the project headers first and compile-checks only
the staged x86 `fenv`, `float`, and fundamental-type declarations, in both SSE
and x87 evaluation modes. It deliberately has no link step: the declarations
remain a source-only ABI slice. The relevant declarations are also
prerequisites of the separate `libc-bootstrap-primitives` artifact gate, but
this compile-only command does not select the header family, `crabc-libc`, or
general x86 C-header support.

`math-complex-header-abi` runs project-header-first and pinned-musl C11/C++
consumers in default SSE and `-mfpmath=387` modes. It proves the named x87
`long double`/complex layouts and constants, `float_t`/`double_t` selection,
`math_errhandling` and fast-FMA macro policy, GNU `HUGE`, C accessor macros,
`tgmath` dispatch with single evaluation, relational-predicate single
evaluation, classification/sign declarations, C/C++ project-header provenance,
exact typed references for the selected 22-entry x87 long-double block, and
unmangled C++ linkage for every named runtime symbol. Its C executables
intentionally link pinned musl's math runtime, so it is header semantics
only—not general math, `crabc-libc`, or public x86 support.

`math-complex-complete-header-abi` is the declaration/linkage ratchet for the
complete private 66-symbol `math.complex` capability. Its project-first and
pinned-musl C++17 probes take every typed address in default SSE and
`-mfpmath=387` modes, require unmangled C references, and ratchet the SysV
8-byte/16-byte binary32/binary64 complex forms plus 16-byte binary80 and
32-byte long-complex storage. It is header evidence only; the separate static
differential owns result, exception, and source-oracle behavior.

`math-elementary-long-double-header-abi` is the declaration/linkage ratchet
for the exact 35-symbol private `math.elementary-long-double` capability. Its
project-first and pinned-musl C++17 probes take every typed address in default
SSE and `-mfpmath=387` modes, require unmangled C references, and ratchet the
SysV 16-byte align-16 binary80 storage plus GNU `sincosl` output-pointer
signature. It is header evidence only; the separate static differential owns
runtime behavior and does not make general `libm` or public x86 support.

`math-special-header-abi` is the complete declaration/linkage ratchet for the
separately selected `math.special` capability. A project-first and pinned-musl
C++17 probe takes an exactly typed address for all ninety ledger symbols plus
`signgam` in default SSE and `-mfpmath=387` modes. It fixes the SysV 16-byte,
align-16 binary80 layout and LP64 integer returns and requires every reference
to retain unmangled C linkage. Musl intentionally does not declare the hidden
`__lgammal_r` implementation name, so only that ledger-named ABI receives an
explicit `extern "C"` declaration in the probe. This compile-only gate does
not itself select runtime behavior or broader elementary/complex math.

`sys-reg-header-abi` places the project headers first and compile-checks the
27 Linux/x86-64 ptrace register-index macros in `<sys/reg.h>`. It is another
declaration-only header ratchet, not a ptrace runtime or `crabc-libc` claim.

`machine-context-header-abi` separately compares seven isolated C11/C++17
profiles through raw-GCC project-first and pinned-musl roots for the selected
`sys/auxv.h`, `sys/ptrace.h`, `sys/reg.h`, `sys/user.h`, `sys/procfs.h`, and
`sys/ucontext.h` declarations and x86 LP64 layouts. It checks x86-only
HWCAP/register namespace separation and unmangled C++ references, but does not
select aux-vector, ptrace, or context-switch runtime behavior, archive linkage,
header-family completion, or public x86 support.

`types-header-abi` compiles the C and C++ project-header-first
`<bits/alltypes.h>`/`<sys/types.h>` declarations and opaque pthread layouts,
then compiles the same assertions against pinned musl. It covers only the
named `nlink_t`, `blksize_t`, `pthread_t`, and layout declarations; it does
not select a pthread implementation or `crabc-libc`.

`stat-header-abi` compiles project and pinned-musl C/C++ `<sys/stat.h>`
declarations, including the x86-64 144-byte `struct stat` layout and selected
mode/timestamp contracts. It is source-only header evidence; it does not
provide filesystem behavior or select `crabc-libc`.

`ctype-header-abi` compiles project-first and pinned-musl C/C++ `<ctype.h>`
declarations for the fixed-C-locale boundary. The fourteen ordinary
classification/case-conversion declarations are unconditional; the exact
C-only `isascii` macro and `toascii` declaration require POSIX/XOPEN/GNU/BSD
feature selection. Strict C verifies those extension names stay hidden, while
the C++ companion verifies the `isascii` macro stays hidden and checks the
GNU-visible declarations directly.
This is compile-only header evidence; it does not select locale behavior,
`crabc-libc`, or a general C text ABI.

`integer-arithmetic-header-abi` compiles project-first and pinned-musl C/C++
`<stdlib.h>` declarations for `abs`, `labs`, `llabs`, `div`, `ldiv`, and
`lldiv`. All six declarations are unconditional; the probes additionally
ratchet the x86 LP64 `div_t`, `ldiv_t`, and `lldiv_t` field layouts and return
types. This arithmetic-only gate is distinct from the separately staged
integer-parsing declaration and archive artifact; it does not select random
state, `crabc-libc`, or a general C runtime ABI.

`integer-parse-header-abi` compiles project-first and pinned-musl C/C++
`<stdlib.h>` and `<inttypes.h>` declarations for `atoi`, `atol`, `atoll`,
`strtol`, `strtoul`, `strtoll`, `strtoull`, `strtoimax`, and `strtoumax`.
All nine declarations are unconditional; the probes ratchet their exact
pointer/result types, x86 LP64 `intmax_t`/`uintmax_t` aliases, and unmangled
C++ linkage. This is compile-only declaration evidence; the separately staged
static artifact owns the runtime byte-scan, `errno`, range, and end-pointer
behavior. It does not select `crabc-libc` generally or a general C runtime ABI.

`float-parse-header-abi` compiles project-first and pinned-musl GNU-profile
C11/C++17 declarations for the twenty public names in
`numeric.parse-float-locale` across `<stdlib.h>`, `<wchar.h>`, `<inttypes.h>`,
and `<locale.h>`. It ratchets binary32/binary64/x87 results, 16-byte align-16
x86 `long double`, four-byte `wchar_t`, LP64 `intmax_t`, `locale_t`, and
unmangled C++ linkage. The three weak internal `__strto*_l` spellings have no
public declaration. This remains compile-only evidence and does not establish
general header-family or runtime support.

`getsubopt-header-abi` separately proves the installed `<stdlib.h>` boundary
for the already-selected `getsubopt` spelling: strict C/C++ hides it, while
POSIX.1-2008, X/Open 700, GNU, and BSD profiles expose the exact
`int (char **, char *const *, char **)` declaration and unmangled C++ symbol.
The project pass uses raw `-nostdinc`/`-nostdinc++` compilation with a traced
project-plus-compiler-builtin include closure. This is a declaration-only
state-free parser boundary, not a broad parser, locale, environment, or
installed-header-family completion.

`l64a-header-abi` separately proves the shared installed `<stdlib.h>` boundary
for the private radix-64 artifacts: strict/POSIX C/C++ profiles independently
hide `a64l` and `l64a`, while X/Open 700, GNU, and BSD profiles expose exact
unmangled `long(const char *)` and `char *(long)` C++ linkage. The raw
project-header pass traces only project `<stdlib.h>`, `<features.h>`, and
`<bits/alltypes.h>` roots. This is declaration evidence, not general numeric
conversion or `crabc-libc` support.

`intmax-arithmetic-header-abi` compiles project-first and pinned-musl C/C++
`<inttypes.h>` declarations for `imaxabs` and `imaxdiv`. Both declarations are
unconditional; the probes additionally ratchet the x86 LP64 `imaxdiv_t` field
layout, return type, and unmangled C++ linkage. This is compile-only header
evidence for the arithmetic forms only; it is distinct from the separately
staged `strtoimax`/`strtoumax` declaration and archive evidence, and does not
select `crabc-libc` or a general C runtime ABI.

`personality-header-abi` separately compiles project-first and pinned-musl
C/C++ `<sys/personality.h>` declarations for the unconditional Linux spelling
`int personality(unsigned long)`. Strict, POSIX, X/Open, and GNU selections
ratchet the eight-byte x86 unsigned-long word, `PER_LINUX=0`/`PER_MASK=0xff`,
syscall macro 135, and unmangled C++ linkage. This is declaration-only
evidence for the separately selected process-personality artifact; it does not
select personality policy or executable transitions, prctl/capability/namespace
controls, credential or identity/session families, scheduler state, or a
general C-process ABI.

`setfsuid-header-abi` compiles project-first and pinned-musl C/C++
`<sys/fsuid.h>` declarations for the unconditional Linux extension
`int setfsuid(uid_t)`. Strict, POSIX, X/Open, and GNU selections ratchet the
four-byte unsigned x86 `uid_t`, syscall macro 122, and unmangled C++ linkage.
This is declaration-only evidence for the separately selected filesystem-UID
artifact; it does not select `setfsgid`, credential mutation policy, account
data, process-wide synchronization, or a general C-process ABI.

`setfsgid-header-abi` separately compiles project-first and pinned-musl C/C++
`<sys/fsuid.h>` declarations for the unconditional Linux extension
`int setfsgid(gid_t)`. Strict, POSIX, X/Open, and GNU selections ratchet the
four-byte unsigned x86 `gid_t`, syscall macro 123, and unmangled C++ linkage.
This is declaration-only evidence for the separately selected filesystem-GID
artifact; it does not select `setfsuid`, credential mutation policy, account
data, process-wide synchronization, or a general C-process ABI.

`credential-observation-header-abi` compiles project-first and pinned-musl
C/C++ `<unistd.h>` declarations for unconditional `getgroups` and GNU-only
`getresuid`/`getresgid`. Strict, POSIX, and BSD selections must hide both
`getres*` declarations; the GNU C++ probe additionally checks unmangled C
linkage. This is compile-only header evidence; it does not select account
database, credential-mutation, or a general C-process ABI.

`login-name-header-abi` compiles project-first and pinned-musl C/C++
`<unistd.h>` declarations for unconditional `getlogin` and `getlogin_r`.
Strict, POSIX, GNU, and BSD selections prove their exact `char *`/`int`
signatures, x86 LP64 `size_t`, and unmangled C++ linkage. This is compile-only
header evidence for the bounded environment-backed login-name artifact, not
passwd, terminal/session identity, a general C-process ABI, or public x86
support.

`child-reaping-header-abi` compiles project-first and pinned-musl C/C++
`<sys/wait.h>` declarations. Strict C/C++ checks `wait` and `waitpid`; a
POSIX-selected pass adds `waitid`, child `siginfo_t` layout, wait-id/options,
and unmangled C++ linkage. The project header's broader `waitid` visibility is
a recorded current divergence, not a general x86 header-completion claim. This
is compile-only evidence for the bounded child-reaping artifact, not process
control or a general C ABI.

`immediate-termination-header-abi` compiles project-first and pinned-musl
C11/C++ `<stdlib.h>` declarations for `_Exit(int)`. It proves the
unconditional declaration and unmangled C++ linkage while selecting no
ordinary-exit, quick-exit hook, CRT, or lifecycle-state contract. This is
compile-only evidence for the bounded immediate-termination artifact, not a
general C runtime ABI.

`posix-exit-header-abi` compiles project-first and pinned-musl C11/C++
`<unistd.h>` declarations for `_exit(int)`. It proves the unconditional
declaration and unmangled C++ linkage while selecting no C11 implementation,
ordinary-exit, CRT, or lifecycle-state contract. This is compile-only evidence
for the bounded POSIX forwarding artifact, not a general C runtime ABI.

`sched-yield-header-abi` compiles project-first and pinned-musl strict,
POSIX, XOPEN, and GNU C11/C++17 `<sched.h>` declarations for
`int sched_yield(void)`. It proves the unconditional no-argument signed-int
declaration and unmangled C++ linkage only; it is not scheduler-policy,
affinity, thread-lifecycle, or general-header-completion evidence.

`sched-getcpu-header-abi` separately compiles project-first and pinned-musl
GNU C11/C++17 `<sched.h>` declarations for `int sched_getcpu(void)`, with
strict, POSIX, and XOPEN profiles required to hide it. It proves only the
GNU declaration and unmangled C++ linkage, not CPU affinity/topology,
scheduler policy, time support, or general-header completion.

`sched-cpucount-header-abi` separately compiles project-first and pinned-musl
GNU C11/C++17 `<sched.h>` declarations/macros for
`int __sched_cpucount(size_t, const cpu_set_t *)`, `CPU_COUNT_S`, and
`CPU_COUNT`. It ratchets the 128-byte, align-8 GNU `cpu_set_t` layout and
unmangled C++ helper reference; strict, POSIX, and XOPEN profiles must hide all
three GNU spellings. This is declaration/macro evidence only, not affinity,
CPU topology, CPU-mask construction/allocation/comparison, scheduler policy,
time support, or general-header completion.

`sched-priority-bounds-header-abi` separately compiles project-first and
pinned-musl strict/POSIX/XOPEN/GNU C11/C++17 `<sched.h>` declarations for the
unconditional `int sched_get_priority_max(int)` and
`int sched_get_priority_min(int)` signatures, including unmangled C++
references. It is declaration/linkage evidence for only that read-only pair,
not scheduler policy, parameters, affinity, time support, or general-header
completion.

`callback-algorithms-header-abi` compiles project-first and pinned-musl C/C++
`<stdlib.h>` declarations for `bsearch`, `qsort`, and GNU/BSD `qsort_r`.
`bsearch` and `qsort` are unconditional; strict, POSIX, and XOPEN selections
must hide `qsort_r`. The private `__qsort_r` spelling remains unavailable in
both C and C++, while the positive C++ references ratchet unmangled C linkage.
This is compile-only evidence for the bounded callback-algorithms artifact,
not general C sorting/searching or public x86 runtime support.

`ffs-header-abi` compiles project-first and pinned-musl C/C++ `<strings.h>`
declarations for `ffs`, `ffsl`, and `ffsll`. It verifies their XOPEN/GNU/BSD
feature gate, strict/POSIX hiding, exact signatures, and unmangled C++ symbol
references. This is compile-only header evidence; it does not select C text,
general bit operations, or `crabc-libc`.

`memccpy-header-abi` compiles project-first and pinned-musl C/C++ `<string.h>`
declarations for `memccpy(void *restrict, const void *restrict, int, size_t)`.
It proves X/Open/GNU/BSD visibility, strict/POSIX hiding, the exact pointer
signature, and unmangled C++ C linkage. This is header-only evidence, not a
general memory or C-string capability.

`aio-error-header-abi` compiles project-first and pinned-musl GNU-profile
C/C++ `<aio.h>` observations for `aio_error(const struct aiocb *)`. It proves
the exact function-pointer type, 168-byte align-8 `struct aiocb`, volatile
`__err` at offset 112, `_LARGEFILE64_SOURCE` alias, and unmangled C++ C
linkage. It is header evidence only: pinned musl's macro-free `<aio.h>` leaves
its embedded `struct sigevent` incomplete, and no AIO lifecycle/runtime claim
is selected.

`byte-strings-header-abi` compiles project-first and pinned-musl C/C++
`<string.h>`/`<strings.h>` declarations for the closed byte-string set: `index`, `rindex`,
`strchr`, GNU-gated `strchrnul`, `strcmp`, GNU `strverscmp`, `strcspn`,
`strlen`, `strncmp`, `strnlen`, `strpbrk`, `strrchr`, `strspn`, `strstr`, and
GNU/BSD-gated `bcopy`/`bzero`. A strict POSIX C pass expects GNU
`strverscmp`/`strchrnul` and BSD `bcopy`/`bzero` to remain hidden, matching
musl; C++ remains GNU-selected by its driver. This is compile-only header
evidence; it does not select C string behavior or `crabc-libc`.

`memory-search-header-abi` compiles project-first and pinned-musl C/C++
`<string.h>` declarations for the closed memory-search set: unconditional
`memchr`, POSIX/GNU-gated `memmem`, and GNU-gated `memrchr`. Strict C checks
keep the feature-gated declarations hidden, while the C++ companion is checked
positively because its driver implicitly enables GNU declarations. This is
compile-only header evidence; it does not select C memory-search behavior or
`crabc-libc`.

`memccpy-header-abi` compiles project-first and pinned-musl C/C++ `<string.h>`
declarations for `void *memccpy(void *restrict, const void *restrict, int,
size_t)`. It verifies XOPEN/GNU/BSD visibility, strict/POSIX C hiding, exact
signature, and unmangled C++ linkage. This is compile-only header evidence; it
does not select C memory behavior or `crabc-libc`.

`mempcpy-header-abi` compiles project-first and pinned-musl C/C++ `<string.h>`
declarations for `void *mempcpy(void *restrict, const void *, size_t)`. It
verifies GNU-only visibility, default/strict/POSIX/XOPEN/BSD C hiding, exact signature,
and unmangled C++ linkage. This is compile-only header evidence; it does not
select C memory behavior or `crabc-libc`.

`strsep-header-abi` compiles project-first and pinned-musl C/C++ `<string.h>`
declarations for `char *strsep(char **, const char *)`. It verifies GNU/BSD
visibility, default/strict/POSIX/XOPEN C hiding, exact signature, and
unmangled C++ linkage. This is compile-only header evidence; it does not
select C string behavior or `crabc-libc`.

`strtok-header-abi` compiles project-first and pinned-musl C/C++ `<string.h>`
declarations for unconditional `char *strtok(char *, const char *)`. It
ratchets the exact function-pointer ABI under default, strict, POSIX, X/Open,
GNU, and BSD selectors, project-header provenance, and unmangled C++ linkage.
This is compile-only header evidence; it does not select C string/tokenizer
behavior or `crabc-libc`.

`string-copy-header-abi` compiles project-first and pinned-musl C/C++
`<string.h>` declarations for the closed C-string-copy set: unconditional
`strcpy`/`strncpy`/`strcat`/`strncat`, POSIX/XOPEN/GNU/BSD-gated
`stpcpy`/`stpncpy`, and GNU/BSD-gated `strlcpy`/`strlcat`. Strict C checks
keep the feature-gated declarations hidden, while the C++ companion is checked
positively because its driver implicitly enables GNU declarations. This is
compile-only header evidence; it does not select C string-copy behavior or
`crabc-libc`.

`error-strings-header-abi` compiles project-first and pinned-musl C/C++
`<string.h>` declarations for unconditional `strerror` and the
POSIX/XOPEN/GNU/BSD-selected `int strerror_r` and
`char *strerror_l(int, locale_t)` forms. Strict C and C++ checks keep both
feature-gated declarations hidden, while positive C++ objects retain unmangled
references to all public functions. Musl's private `__xpg_strerror_r` and
`__strerror_l` aliases are intentionally absent from the header and remain
runtime/ELF evidence. This is compile-only evidence; it does not select
diagnostics, termination, locale state, or `crabc-libc`.

`string-duplication-header-abi` compiles project-first and pinned-musl C/C++
`<string.h>` declarations for POSIX `strdup(const char *)` and
`strndup(const char *, size_t)`. Strict C keeps both hidden, while POSIX/GNU C
and GNU-selected C++ retain their exact unmangled signatures. This is
compile-only header evidence; it does not select C allocation or string
behavior, or `crabc-libc`.

`random-entropy-header-abi` compiles project-first and pinned-musl C/C++
`<sys/random.h>` and `<unistd.h>` declarations for `getrandom`, its GRND
constants, and GNU/BSD-gated `getentropy`. The strict C pass verifies that
`getentropy` remains hidden without a feature selector; C++ is checked
positively because its driver implicitly enables GNU declarations. This is
compile-only header evidence; it does not select C random behavior or
`crabc-libc`.

`time-header-abi` compiles project and pinned-musl C/C++ `<time.h>`
declarations, including LP64 time types, `timespec`, `itimerspec`, `tm`, GNU
aliases, clock values, `clock_nanosleep`, and selected timer declarations. It
is source-only header evidence; it does not provide C time behavior or select
`crabc-libc`.

`timerfd-header-abi` is the paired eight-profile C11/C++17 matrix over project
and pinned-musl `<sys/timerfd.h>`. It proves the exact three timerfd
declarations and flag values, preserves strict C/C++'s forward-declared
`itimerspec` pointer boundary, proves the POSIX-profile 32-byte align-8 record
and its interval/value offsets, and retains unmangled C++ linkage across 16
tree/profile rows. It is timerfd-artifact header evidence, not installed-header,
time/signal family, runtime, promotion, or public-support completion.

`signalfd-header-abi` is the paired eight-profile C11/C++17 matrix over project
and pinned-musl `<sys/signalfd.h>`. It proves the unconditional `signalfd`
declaration, `SFD_NONBLOCK`/`SFD_CLOEXEC`, 128-byte align-8 `sigset_t`, the
128-byte align-8 `signalfd_siginfo` record and key offsets, and unmangled C++
linkage across 16 tree/profile rows. It is signalfd-artifact header evidence,
not installed-header, signal/runtime family, promotion, or public-support
completion.

`poll-header-abi` compiles project and pinned-musl C/C++ `<poll.h>`
declarations, including `nfds_t`, `pollfd`, and the x86 extension values. It
is source-only header evidence; it does not provide polling behavior or select
`crabc-libc`.

`select-header-abi` compiles project and pinned-musl strict/GNU C/C++
`<sys/select.h>` declarations, including `fd_set`, `FD_*` macros,
`timeval`/`timespec`, `sigset_t`, `select`/`pselect`, and their C linkage. It
is header-only evidence; it does not provide descriptor-readiness or
signal-wait behavior or select `crabc-libc`.

`fcntl-header-abi` compiles project and pinned-musl C/C++ `<fcntl.h>`
declarations, including x86 open/fcntl flags, `flock`, GNU owner/file-handle
records, selected extensions, large-file aliases including `lockf64`, and
the unconditional base `posix_fallocate` declaration together with its
`_LARGEFILE64_SOURCE`-only alias spelling. It is source-only header evidence;
it does not provide descriptor behavior or select `crabc-libc`.

`descriptor-advice-header-abi` compiles isolated project and pinned-musl C/C++
`<fcntl.h>` profiles for unconditional `posix_fadvise` and
`POSIX_FADV_NORMAL` through `POSIX_FADV_NOREUSE`, GNU-only
`readahead(int, off_t, size_t)`, and the LF64-only `posix_fadvise64` macro
alias. Strict/no-feature and LF64-only profiles prove `readahead` remains
hidden; C++ object checks prove unmangled base/GNU linkage, while the runner's
`-H` traces keep the feature/header owners explicit. It is compile-only
declaration evidence, not cache-effect, descriptor behavior, or public x86
support.

`filesystem-capacity-header-abi` compiles seven base and two
`_LARGEFILE64_SOURCE` project/pinned-musl C/C++ profiles for
`<sys/statfs.h>` and `<sys/statvfs.h>`. It proves the four declarations, x86
LP64 `fsid_t`/`statfs`/`statvfs` layouts and mount flags, C++ C-linkage
spelling, and LF64-only function/type macro aliases. It is compile-only
declaration/layout/linkage evidence, not archive linkage, runtime behavior,
filesystem support, or public x86 support.

`vector-io-header-abi` compiles fourteen project/pinned-musl C/C++ profiles
for `<sys/uio.h>`. It proves only the x86 LP64 `iovec` layout and
`UIO_MAXIOV`, unconditional `readv`/`writev`, GNU/BSD `preadv`/`pwritev`,
GNU-only v2/RWF/process-vm declarations and hiding, GNU/BSD LF64 aliases, and
unmangled C++ spelling. It is compile-only declaration/layout/linkage
evidence, not archive linkage, vector-I/O runtime behavior, or public x86
support.

`flock-header-abi` compiles project and pinned-musl C/C++ `<sys/file.h>`
declarations, including the direct `flock` signature, x86 operation bits, and
legacy `L_*` values with unmangled C++ linkage. It is source-only header
evidence; it does not select locking behavior or `crabc-libc`.

`sendfile-header-abi` compiles project and pinned-musl C/C++
`<sys/sendfile.h>` declarations, including signed x86 LP64 `off_t`,
`SYS_sendfile=40`, the direct signature, large-file alias spelling, and
unmangled C++ linkage. It is source-only header evidence; it does not select
descriptor transfer behavior or `crabc-libc`.

`tee-header-abi` compiles project and pinned-musl C/C++ GNU `<fcntl.h>`
declarations for `ssize_t tee(int, int, size_t, unsigned)`, with C++ linkage.
It also proves default, strict, POSIX, XOPEN, and BSD C selector profiles hide
that GNU-only spelling. It is source-only declaration evidence; it does not
select pipe-buffer transfer behavior or `crabc-libc`.

`splice-header-abi` compiles project and pinned-musl C/C++ GNU `<fcntl.h>`
declarations for `ssize_t splice(int, off_t *, int, off_t *, size_t,
unsigned)`, signed x86 `off_t`, and unmangled C++ linkage. Strict, POSIX,
XOPEN, and BSD C selector profiles hide that GNU-only spelling; the C++ driver
follows musl's extension-visible mode. It is source-only declaration evidence;
it does not select descriptor, pipe, or transfer behavior or `crabc-libc`.

`sync-file-range-header-abi` compiles project and pinned-musl C/C++ GNU
`<fcntl.h>` declarations for `int sync_file_range(int, off_t, off_t,
unsigned)`, with signed x86 `off_t` and C++ linkage. It also proves default,
strict, POSIX, XOPEN, and BSD C selector profiles hide that GNU-only spelling.
It is source-only declaration evidence; it does not select cache/writeback or
durability policy, descriptor ownership, `sync`/`syncfs`, or `crabc-libc`.

`copy-file-range-header-abi` compiles project and pinned-musl C/C++ GNU
`<unistd.h>` declarations for `ssize_t copy_file_range(int, off_t *, int,
off_t *, size_t, unsigned)`, signed x86 `off_t`, and unmangled C++ linkage.
Strict, POSIX, XOPEN, and BSD C selector profiles hide that GNU-only spelling;
the C++ driver follows musl's extension-visible mode. It is source-only
declaration evidence; it does not select descriptor-copy behavior, fallback,
or `crabc-libc`.

`unistd-header-abi` compiles project and pinned-musl C/C++ `<unistd.h>`
declarations, including the staged x86 LP64 POSIX/GNU selectors, process and
system helper declarations, GNU hostname/domain-name signatures, lock
constants, and large-file aliases. It is source-only and does not select C
process, filesystem, descriptor, namespace, or UTS-identity behavior.

`getpagesize-header-abi` is a separate project-first/pinned-musl C11/C++17
`<unistd.h>` declaration gate for only `int getpagesize(void)`. It proves
GNU/BSD visibility, the exact no-argument signed-int signature, and unmangled
C++ linkage while proving default, strict, POSIX, and XOPEN hiding. It is
header-only evidence; it does not select general page-size discovery,
`sysconf`/path configuration behavior, archive linkage, C runtime, or public
x86 support.

`ualarm-header-abi` is a separate project-first/pinned-musl C11/C++17
`<unistd.h>` declaration matrix for only `unsigned int ualarm(unsigned int,
unsigned int)`. It proves GNU/BSD/XOPEN<700 visibility with unmangled C++
linkage while default, strict, POSIX, and XOPEN=700 correctly hide the opt-in
declaration. It is header-only evidence; it does not select `ITIMER_REAL`
state, signals, archive linkage, C runtime, or public x86 support.

`usleep-header-abi` is a separate project-first/pinned-musl C11/C++17
`<unistd.h>` declaration matrix for only `int usleep(unsigned int)`. It proves
GNU, BSD, and XOPEN=600 visibility with unmangled C++ linkage while default,
strict, POSIX, and XOPEN=700 correctly hide the opt-in declaration. It is
header-only evidence; it does not select sleep policy, timers, signals, archive
linkage, C runtime, or public x86 support.

`system-header-abi` compiles project and pinned-musl C/C++ `<sys/utsname.h>`
and `<sys/sysinfo.h>` declarations, including the GNU 65-byte `nodename` and
`domainname` fields in the 390-byte public `utsname` record and the public
368-byte sysinfo compatibility record plus all four unconditional
`get_nprocs*`/`get_*phys_pages` function signatures. It is source-only and
distinct from bounded Rust or static-C system-information slices.

`syscall-header-abi` places project `<sys/syscall.h>` first and compares its
complete 384-pair `__NR_*`/`SYS_*` macro surface with pinned musl 1.2.6. It is
compile-only and provides no syscall behavior or C runtime artifact.

`signal-header-abi` compile-checks staged GNU and POSIX x86 `<signal.h>`
signal-frame layouts, including general-register, floating-state, context, and
alternate-stack records, against pinned musl. It is source-only and does not
select C signal behavior or `crabc-libc`.

`termios-header-abi` compile-checks staged GNU x86 C and C++ `<termios.h>`
layouts, declarations, C linkage, selected baud vocabulary, and the
alltypes-owned `winsize` contract against pinned musl. It is header-only
evidence, not a general C terminal/runtime claim.

`mman-header-abi` compile-checks staged C and C++ `<sys/mman.h>` declarations
and selected Linux/x86 mapping values, including `MAP_32BIT`, against pinned
musl. It is source-only and does not select mapping behavior or `crabc-libc`.

`memory-sync-header-abi` separately compares project-first and pinned-musl C
and C++ `<sys/mman.h>` profiles for unconditional `msync` and its three
`MS_*` values, including unmangled C++ linkage. It is compile-only evidence;
it does not select runtime behavior, musl's cancellation-point semantics,
complete `sys/mman.h`, family completion, promotion, or public x86 support.

`memory-locking-header-abi` separately compares project-first and pinned-musl
strict/POSIX/GNU C/C++ `<sys/mman.h>` profiles for exactly `mlock`, `munlock`,
and GNU `mlock2`/`MLOCK_ONFAULT`, including GNU hiding and unmangled C++
linkage. It is compile-only evidence, not archive linkage, locking behavior,
complete `sys/mman.h`, family completion, or public x86 support.

`memfd-create-header-abi` separately compares project-first and pinned-musl
eight-profile C/C++ `<sys/mman.h>` GNU visibility for exactly
`memfd_create` and `MFD_CLOEXEC`/`MFD_ALLOW_SEALING`/`MFD_HUGETLB`: visible
only under GNU feature selection, hidden otherwise, and unmangled from C++.
It is compile-only evidence, not archive linkage, descriptor or filesystem
behavior, family completion, promotion, or public x86 support.

`resource-header-abi` compile-checks strict and GNU/LFS C and C++
`<sys/resource.h>` records, selectors, priorities, declarations, and aliases
against pinned musl: an unsigned-long-long `rlim_t`, 16-byte `rlimit`, and
272-byte `rusage` with its caller-resident 128-byte tail. It is source-only
header evidence and does not select process-resource behavior or `crabc-libc`.

`socket-header-abi` compile-checks project-first and pinned-musl GNU C/C++
`<sys/socket.h>` and `<netinet/in.h>` base transport declarations, then runs a
tiny C probe through each header set for the installed IPv6 address-
classification macros. It also proves the immutable `in6addr_any` and
`in6addr_loopback` declarations, musl's union-backed 16-byte align-4 `struct
in6_addr` layout, and unmangled C++ data-symbol references. It covers only
generic and IPv4/IPv6 socket-address
records, `socklen_t`, selected address-family/type, creation, shutdown, and
basic send/receive constants, the `socket`/`socketpair`,
bind/listen/accept/`accept4`/connect, send/receive, name-query, and shutdown
signatures, and the named IPv6 macro classifications. It is source-only header
evidence: it does not select socket options, vector or ancillary-message APIs,
address-conversion or socket behavior, `crabc-libc`, or public x86 support.

`nameser-header-abi` compile-checks project-first and pinned-musl C and C++
`<resolv.h>` consumers for exactly
`dn_skipname(const unsigned char *, const unsigned char *)`,
`dn_expand(const unsigned char *, const unsigned char *, const unsigned char *, char *, int)`, and
`ns_get16(const unsigned char *)`, `ns_get32(const unsigned char *)`, and
`ns_put16(unsigned, unsigned char *)`, plus the eight-byte align-4
`struct _ns_flagdata { int mask; int shift; }` and `const struct _ns_flagdata *`
array-decay declaration. It ratchets `NS_CMPRSFLGS=0xc0`, `NS_MAXLABEL=63`,
`NS_MAXCDNAME=255`, and `NS_MAXDNAME=1025`, then checks the C++ object retains
five unmangled C function symbols and one unmangled `_ns_flagdata` data
reference. It is declaration-only evidence for caller-owned DNS wire-name span
walking and expansion, immutable nameserver flag-accessor data, caller-owned
16-bit and 32-bit wire reads, and one caller-owned 16-bit wire write; it does not
establish archive linkage, resolver state, `/etc/resolv.conf` parsing, DNS
packet I/O, sockets, netdb, installed-header completion, family promotion, or
public x86 support.

`quota-header-abi` is the seven-profile project-first/pinned-musl C/C++
compile-only `<sys/quota.h>` gate for the full pinned-musl quota header:
unconditional `dbtob`/`btodb`/`fs_to_dq_blocks`/`dqoff` macro replacements,
quota constants and masks, legacy `dq_*` aliases, `dqblk`/`dqinfo` LP64
layouts, and the C/C++ `quotactl` declaration. It neither links nor executes a
quota probe or `quotactl`, and does not select quotactl archive/runtime
behavior, quota policy/accounting, filesystem/kernel state,
`system.kernel-admin`, installed-header completion, family completion,
promotion, or public x86 support.

`inet-address-header-abi` compile-checks project-first and pinned-musl
default/GNU/strict C and C++ `<arpa/inet.h>` profiles. It ratchets the exact
`inet_pton`, `inet_ntop`, `inet_aton`, `inet_addr`, `inet_ntoa`,
`inet_makeaddr`, and `inet_lnaof`
declarations, the x86 `in_addr_t`/`in_port_t`/`struct in_addr` layouts, `INET_ADDRSTRLEN` and
`INET6_ADDRSTRLEN`, and unmangled C++ C spellings. It is declaration/layout
evidence only: it does not establish archive linkage, numeric-address runtime
behavior, DNS/resolver state, netdb, installed-header completion, family
promotion, or public x86 support.

`libc-inet-address` is the separate private static C numeric-address artifact
under still-planned `libc.resolver`. Its project-header C body executes first
through pinned musl 1.2.6 and then through a true `-nostdlib -static`
candidate. It selects only `inet_pton`, `inet_ntop`, hidden global
`__inet_aton`, the same-address weak `inet_aton` alias, and `inet_addr`; the
fixture pins strict IPv4/IPv6 grammar, historical base-zero and abbreviated
`inet_aton` forms, network bytes, `INADDR_NONE` ambiguity, partial parse and
output writes, mapped-v4/longest-zero-run text, AF-family errors, and the
different short-buffer behavior for AF_INET and AF_INET6 `inet_ntop`. It does
not select DNS/resolver state, netdb, interface lookup, the separate
`inet_ntoa` scratch-buffer and classful IPv4 arithmetic candidates, allocation, stdio, libc.so, CRT, loader, sysroot, resolver-network
behavior, family promotion, or public x86 support.

`libc-inet-ntoa` is a distinct private static C `inet_ntoa` scratch-buffer
artifact under still-planned `libc.resolver`. Its project-header C body runs
through pinned musl 1.2.6 and then through an archive-free
`-nostdlib -static` candidate whose final link receives only the one extracted
`inet_ntoa` object, never `libc.a`; a separate archive ratchet proves that
object is published. It preserves musl's one shared static 16-byte dotted-IPv4
buffer: calls return the same pointer and the next call overwrites its text.
Musl uses `snprintf`; this bounded leaf manually writes four decimal octets
because the longest result is fifteen bytes plus NUL, so it does not select
stdio. It neither reads nor writes `h_errno` or `errno`, and has no h_errno
storage, TLS, numeric netdb, resolver configuration, DNS, `/etc/hosts`,
`/etc/resolv.conf`, conventional network database, interface, socket,
allocation, syscall, libc.so, CRT, loader, sysroot, resolver completion,
family promotion, or public x86 support.

`libc-inet-classful` is a distinct private static C classful IPv4 arithmetic
artifact under still-planned `libc.resolver`. Its project-header C body runs
through pinned musl 1.2.6 and then through an archive-free `-nostdlib -static`
candidate whose final link receives only the one extracted object containing
`inet_makeaddr` and `inet_lnaof`, never `libc.a`; a separate archive ratchet
proves both exports. Pinned musl's `inet_legacy.c` puts those two local
raw-word functions beside `inet_network` and `inet_netof`; the source audit
confirms the unselected `inet_network` still carries its `inet_addr`
dependency. The regression covers musl's `n < 256`, `n < 65536`, and remaining
prefix shifts plus the raw `s_addr` <128/<192/otherwise local-address masks.
It does not select byte-order helpers, `inet_ntoa` scratch storage, h_errno or
errno, TLS, allocation, stdio, syscalls, resolver configuration, DNS,
`/etc/hosts`, `/etc/resolv.conf`, netdb, interfaces, sockets, libc.so, CRT,
loader, sysroot, resolver completion, family promotion, or public x86 support.

`libc-hstrerror` is a separate private static C message leaf under
still-planned `libc.resolver`. Its project-header C body first executes through
pinned musl 1.2.6 and then through a true `-nostdlib -static` candidate. It
selects only `hstrerror`'s four conventional h_errno messages and the unknown
fallback, with immutable stable pointers. In the selected C/POSIX/C.UTF-8
profiles musl's `LCTRANS_CUR` hook is identity-only. It neither reads nor
writes `h_errno` or `errno`, nor selects h_errno storage, TLS, locale catalogs,
allocation, stdio, syscalls, `/etc/hosts`, `/etc/resolv.conf`, resolver
configuration, DNS, network-database/NSS, interface, socket, libc.so, CRT,
loader, sysroot, resolver completion, family promotion, or public x86 support.

`h-errno-header-abi` (`./scripts/dev-x86_64.sh h-errno-header-abi`) is the
seven-profile project-first/pinned-musl C and C++ `<netdb.h>` gate for the
feature-gated `h_errno` accessor macro and `__h_errno_location` declaration.
It records the GNU/BSD visibility split, the `int *` result type, and
unmangled C++ linkage; it does not link an archive or select resolver behavior.
`libc-h-errno` (`./scripts/dev-x86_64.sh libc-h-errno`) is the separate private
static ABI artifact under still-planned `libc.resolver`. It selects only the
four-byte link-visible `h_errno` fallback object and its accessor, with the
authenticated main thread using that object and selected pthread workers using
one direct initial-TLS slot. The pinned-musl comparison and freestanding
`-nostdlib -static` fixture retain this boundary and reject dynamic TLS,
resolver configuration, DNS, socket/network database behavior, and foreign
threads. Musl's `h_errno.lo` normally reaches worker state through its full
musl TCB; this selected port intentionally substitutes the direct static-TLS
slot and therefore claims only the tested selected-worker semantics. The
artifact does not complete `process.globals`, resolver behavior, family
promotion, or public x86 support.

`libc-endservent` (`./scripts/dev-x86_64.sh libc-endservent`) is a separate
private static C ABI leaf under still-planned `libc.c-abi-compat`, not a
service-database or resolver-network capability. The paired
`endservent-header-abi` matrix compares pinned-musl and project `<netdb.h>` C
and C++ consumers under strict, POSIX, X/Open, and GNU profiles, proving the
unconditional `void endservent(void)` declaration, exact no-argument function
pointer type, and unmangled C++ linkage. Its project-header body first executes
through pinned musl 1.2.6, then through an archive-free true
`-nostdlib -static` candidate linked from exactly one extracted `endservent`
object, never `libc.a`; the aggregate archive export ratchet is separate.
Pinned musl maps the selected direct return to `src/network/serv.c::endservent`.
The direct/function-pointer differential and disassembly admit no service
cursor, `/etc/services`, `setservent`, `getservent`, service lookup, resolver
state/configuration, DNS, h_errno, errno, TLS, allocation, syscall, socket,
NSS, libc.so, CRT, loader, sysroot, family completion, promotion, or public
x86 support.

`libc-dn-skipname` (`./scripts/dev-x86_64.sh libc-dn-skipname`) is a distinct
private static C ABI artifact inside still-planned `libc.resolver`, not
resolver-network behavior or a promotion. Its project-header C fixture runs
first through pinned musl 1.2.6 and then through an archive-free true
`-nostdlib -static` candidate linked from exactly one extracted `dn_skipname`
object, never `libc.a`; the aggregate archive ratchet separately proves the
export. Musl maps its dependency-free 83-byte `dn_skipname.lo` object to
`src/network/dn_skipname.c`. The fixed differential covers root and ordinary
labels, a compressed-pointer octet consuming exactly two bytes without pointer
following, truncated pointer/label failure, and musl's intentional treatment
of octets 64 through 191 as label lengths. It has no resolver state,
`h_errno`/`errno`/TLS, `/etc/hosts` or `/etc/resolv.conf` access, DNS packet
I/O, socket, netdb/database, parser sibling, address-codec, interface,
Ethernet, allocation, syscall, libc.so, CRT, loader, sysroot, family
promotion, or public x86 support.

`libc-dn-expand` (`./scripts/dev-x86_64.sh libc-dn-expand`) is a distinct
private static caller-owned DNS wire-name expansion C ABI artifact inside
still-planned `libc.resolver`, not resolver-network behavior or a promotion.
Its project-header C fixture runs first through pinned musl 1.2.6 and then
through an archive-free true `-nostdlib -static` candidate linked from exactly
one extracted `dn_expand` object, never `libc.a`; the aggregate archive ratchet
separately proves the hidden global `__dn_expand` and weak default `dn_expand`
same-address alias pair. Pinned musl maps the dependency-free 292-byte
`dn_expand.lo` object to `src/network/dn_expand.c`. The fixed differential
covers root and label text, compressed, noncanonical top-bit, and high-offset
pointers, initial encoded-span return length, truncated/out-of-range/loop failure, early
source-at-end/nonpositive-space failure, the 254-byte output cap, and partial
dotted output. It has no resolver state, `h_errno`/`errno`/TLS,
`/etc/hosts` or `/etc/resolv.conf` access, DNS packet I/O, socket,
netdb/database, parser sibling, `dn_skipname`, nameser read/write helper,
address-codec, interface, Ethernet, allocation, syscall, libc.so, CRT,
loader, sysroot, family promotion, or public x86 support.

`libc-ns-flagdata` (`./scripts/dev-x86_64.sh libc-ns-flagdata`) is a distinct
private static immutable nameserver flag-accessor data C ABI artifact inside
still-planned `libc.resolver`, not resolver-network behavior or a promotion.
Its project-header C fixture runs first through pinned musl 1.2.6 and then
through an archive-free true `-nostdlib -static` candidate linked from exactly
one extracted `_ns_flagdata` object, never `libc.a`; the aggregate export
ratchet separately proves publication. Pinned musl puts the global default
read-only 128-byte sixteen-record table in the no-relocation
`.rodata._ns_flagdata` section of `src/network/ns_parse.c`, beside parser code
which remains unselected. The differential proves the eight-byte align-4
two-`int` C record layout, all sixteen `(mask, shift)` pairs, six all-zero
reserved records, and `ns_msg_getflag` QR/opcode/AA/TC/RD/RA/Z/AD/CD/rcode
extraction. It excludes parser code, resolver state, `h_errno`/`errno`/TLS,
`/etc/hosts` and `/etc/resolv.conf`, DNS packet I/O, sockets, netdb/database,
nameser helpers, address codecs, interfaces, Ethernet, allocation, syscalls,
libc.so, CRT, loader, sysroot, resolver-family completion, and public x86
support.

`libc-ns-get16` (`./scripts/dev-x86_64.sh libc-ns-get16`) is a distinct
private static caller-owned nameserver 16-bit wire-read C ABI artifact inside
still-planned `libc.resolver`, not resolver-network behavior or a promotion.
Its project-header C fixture runs first through pinned musl 1.2.6 and then
through an archive-free true `-nostdlib -static` candidate linked from exactly
one extracted `ns_get16` object, never `libc.a`; the aggregate archive ratchet
separately proves the export. Pinned musl puts the 11-byte call-free
`ns_get16` section in `src/network/ns_parse.c` beside parser siblings, which
remain unselected. The fixed differential covers aligned and unaligned
network-order two-byte reads plus `NS_GET16`'s cursor advance. It has no
resolver state, `h_errno`/`errno`/TLS, `/etc/hosts` or `/etc/resolv.conf`
access, DNS packet I/O, socket, netdb/database, parser sibling, address codec,
integer byte-order helper, interface, Ethernet, allocation, syscall, libc.so,
CRT, loader, sysroot, family promotion, or public x86 support.

`libc-ns-get32` (`./scripts/dev-x86_64.sh libc-ns-get32`) is a distinct
private static caller-owned nameserver 32-bit wire-read C ABI artifact inside
still-planned `libc.resolver`, not resolver-network behavior or a promotion.
Its project-header C fixture runs first through pinned musl 1.2.6 and then
through an archive-free true `-nostdlib -static` candidate linked from exactly
one extracted `ns_get32` object, never `libc.a`; the aggregate archive ratchet
separately proves the export. Pinned musl puts the seven-byte call-free
`ns_get32` section in `src/network/ns_parse.c` beside parser siblings, which
remain unselected. The fixed differential covers aligned and unaligned
network-order four-byte reads, LP64 `unsigned long` zero extension, and
`NS_GET32`'s cursor advance. It has no resolver state, `h_errno`/`errno`/TLS,
`/etc/hosts` or `/etc/resolv.conf` access, DNS packet I/O, socket,
netdb/database, parser sibling, address codec, integer byte-order helper,
interface, Ethernet, allocation, syscall, libc.so, CRT, loader, sysroot,
family promotion, or public x86 support.

`libc-ns-put16` (`./scripts/dev-x86_64.sh libc-ns-put16`) is a distinct
private static caller-owned nameserver 16-bit wire-write C ABI artifact inside
still-planned `libc.resolver`, not resolver-network behavior or a promotion.
Its project-header C fixture runs first through pinned musl 1.2.6 and then
through an archive-free true `-nostdlib -static` candidate linked from exactly
one extracted `ns_put16` object, never `libc.a`; the aggregate archive ratchet
separately proves the export. Pinned musl puts the 10-byte call-free
`ns_put16` section in `src/network/ns_parse.c` beside parser siblings, which
remain unselected. The fixed differential covers unaligned network-order
two-byte writes, truncation to an `unsigned` value's low 16 bits, unchanged
neighboring bytes, and `NS_PUT16`'s cursor advance. It has no resolver state,
`h_errno`/`errno`/TLS, `/etc/hosts` or `/etc/resolv.conf` access, DNS packet
I/O, socket, netdb/database, parser sibling, address codec, integer byte-order
helper, interface, Ethernet, allocation, syscall, libc.so, CRT, loader,
sysroot, family promotion, or public x86 support.

`libc-numeric-netdb` is a separate private static C `netdb.h` result-record
artifact under still-planned `libc.resolver`. Its project-header C body first
executes through pinned musl 1.2.6 and then through a true
`-nostdlib -static` candidate. It selects exactly numeric `getaddrinfo`,
`freeaddrinfo`, numeric-fallback `getnameinfo`, and `gai_strerror`: IPv4,
IPv6, mapped-v4, and null-node passive/loopback records; numeric services;
opaque result-list lifetime; numeric host/service rendering; and selected EAI
errors/text. The fixture ratchets the x86 LP64 `struct addrinfo` and socket
layouts, function declarations, and public AI/NI/EAI constants. Result nodes
use one private anonymous page and are released only through `freeaddrinfo`;
this is not a general allocator. It does not read `/etc/hosts` or
`/etc/resolv.conf`, inspect interfaces, consult service databases, send DNS,
keep resolver state/cache, perform reverse lookup, add NSS/plugins/DoH/DoT/
mDNS, or promote `libc.resolver`, x86 support, or any public platform claim.

`libc-interface-discovery` is a separate private static C interface-name and
address-snapshot artifact under still-planned `libc.posix-runtime`. Its
project-header body runs through pinned musl 1.2.6 and a true
`-nostdlib -static` candidate in a Docker network-none namespace. It selects
only `if_nametoindex`, `if_indextoname`, `if_nameindex`, `if_freenameindex`,
`getifaddrs`, and `freeifaddrs`, including loopback ioctl round trips,
terminated name-list ownership, and independent AF_PACKET/IPv4/IPv6 loopback
snapshots. The x86 `interface_discovery.rs` boundary owns only private mmap
result storage and raw ioctl/rtnetlink exchange; it excludes numeric netdb,
resolver configuration, DNS, conventional network databases, public `ifreq`,
interface mutation, generic allocation, dynamic runtime artifacts, promotion,
and public x86 support.

`socket-messages-header-abi` compile-checks project-first and pinned-musl
POSIX/GNU/BSD C/C++ `<sys/socket.h>` message/options declarations. It covers
only `setsockopt`, `getsockopt`, `sendmsg`, `recvmsg`, `sendmmsg`, `recvmmsg`,
and `sockatmark`; x86 `iovec`, padded public `msghdr`/`cmsghdr`, GNU
`mmsghdr`, CMSG alignment/traversal boundaries, feature hiding, and unmangled
C++ linkage. This is source-only declaration/layout/linkage evidence: it does
not select archive linkage, socket runtime behavior, installed-header or
family completion, or public x86 support.

`sysv-semaphore-header-abi` compile-checks project-first and pinned-musl C and
C++ `sys/ipc.h`/`sys/sem.h` declarations, selected LP64 SysV IPC layouts and
command values, variadic `semctl` C linkage, and GNU-only `semtimedop`
visibility across eight feature profiles. It records the installed
`_SEM_SEMUN_UNDEFINED` boundary: applications define `union semun`; this is
header evidence only and does not select SysV IPC behavior, `crabc-libc`, or
public x86 support.

`sysv-message-shared-memory-header-abi` compile-checks project-first and
pinned-musl C and C++ `sys/ipc.h`/`sys/msg.h`/`sys/shm.h` declarations,
feature-visible member spellings, selected x86 LP64 records and constants,
and unmangled C linkage across eight feature profiles. It covers only the
selected header surface for `ftok`, message queues, and shared memory; it does
not select archive linkage, runtime behavior, header-family completion, full
x86-64 parity, or public x86 support.

`mm-abi-reference` compile-checks pinned-musl x86 `mmap`/`mremap`/`mprotect`/
`munmap` numbers and the closed mapping/remapping constants used by the native
Rust facade. It does not compile project C headers or select a C ABI artifact.

`mlock-reference` executes a pinned-musl x86 probe for `mlock`/`munlock`/
`mlock2`, `MLOCK_ONFAULT`, constrained-memlock outcomes, and invalid range/flag
behavior. It establishes only the per-range typed Rust locking boundary, not
global locking policy or C mapping support.

`msync-reference` executes a pinned-musl x86 probe for `msync`, its accepted
`MS_*` flag combinations, and zero-length no-op behavior. It establishes only
the typed Rust mapping-synchronization boundary, not C mapping support or wider
VM policy.

`madvise-reference` executes a pinned-musl x86 probe for the `madvise` syscall,
its closed normal/random/sequential/will-need/DONTNEED advice vocabulary,
private-anonymous Linux page discard, and musl-compatible POSIX `DONTNEED`
no-op behavior. It establishes only the typed Rust advisory boundary, not C
mapping support or wider VM policy.

`mincore-reference` executes a pinned-musl x86 probe for `mincore`, its
4096-byte page unit, one-byte-per-page output, and partial-range rounding. It
establishes only the typed Rust residency boundary, not C mapping support or a
general VM facade.

`fs-advice-reference` executes a pinned-musl x86 probe for `fadvise64` and
`readahead`, their syscall values, all six `POSIX_FADV_*` policies,
descriptor-position preservation, and direct invalid range/descriptor behavior.
It establishes only the typed Rust `fs::{fadvise, readahead}` boundary, not C
filesystem support or broader path-based behavior.

`ftruncate-reference` executes a pinned-musl x86 descriptor-length lifecycle.
It pins `ftruncate=77` and its signed 64-bit Linux `loff_t` argument, then
uses a fresh memfd to prove extension with a zero-filled new range and later
shrink. The typed Rust `u64` facade refuses a length above `i64::MAX` with
`EINVAL` before it borrows the descriptor or reaches the syscall. Together
with `file-position-reference`, it proves the admitted typed
`io.file-position` family; it does not select C `unistd`/header behavior,
pathname truncation, allocation, durability policy, or broader filesystem
support.

`timestamp-reference` executes the consolidated pinned-musl/raw x86
timestamp-mutation evidence plus focused Rust regressions. It pins
`utimensat=280`, the `rdi`/`rsi`/`rdx`/`r10` syscall4 ABI, and the signed
16-byte align-8 `timespec` pair used by
`fs::{Timespec, Timestamps, UTIME_NOW, UTIME_OMIT, futimens}`. It covers the
descriptor/null-path form, bounded directory-relative and current-directory
forms, final-symlink no-follow mutation, and the legacy whole-second form.
Explicit/current/omit behavior, path selection, direct validation, and the
legacy conversion boundary remain direct Rust behavior. By itself this command
does not select general `filesystem.path-core`, public C timestamp APIs or
errno TLS, or broader filesystem metadata policy; `path-core-reference`
composes it with the other selected path-core evidence.

`posix-fallocate-reference` executes pinned-musl/raw x86 evidence plus the
focused Rust regression for `fs::posix_fallocate`. It pins
`fallocate=285`, signed 64-bit `off_t`, fixed mode zero, unlinked regular-file
extension to 8192 bytes with a retained prefix and zero-filled new range, and
preserved file position. Pinned musl's C spelling
returns `EINVAL`/`EBADF` directly without changing `errno`, whereas the raw
syscall returns `-1` and sets `errno`; the Rust facade returns `Errno` and
preflights unsigned offset, length, and range representation before borrowing
the descriptor. It admits neither general Linux fallocate modes, pathname
allocation, C ABI/errno-TLS behavior, filesystem fallback or policy, nor
durability.

`fallocate-reference` is the separate general typed-Rust gate. It pins x86
`fallocate=285` with signed 64-bit `off_t` and only the closed modes
`ALLOCATE=0`, `KEEP_SIZE=0x01`, `PUNCH_HOLE=0x02`, and `ZERO_RANGE=0x10`.
Pinned-musl/raw evidence covers extension, keep-size, stable descriptor
position, invalid combinations and unknown bits, zero-length/negative ranges,
read-only and closed descriptors, and pipe errors. On a fixture filesystem
that supports them, it also proves zero-range and punch-hole effects; otherwise
both C paths must return `EOPNOTSUPP` without changing size or position. Safe
Rust preflights flags and unsigned range overflow before borrowing the
descriptor. The ordinary C `fallocate` spelling and raw syscall use `-1` plus
`errno`; this does not admit C ABI or errno TLS behavior. Future flags,
pathname allocation, filesystem fallback/policy, durability, and public x86
support remain excluded.

`file-position-reference` executes the remaining pinned-musl x86
`lseek`/`fsync`/`fdatasync` lifecycle. It pins syscalls `8`/`74`/`75`,
signed 64-bit `off_t`, and `SEEK_SET`/`SEEK_CUR`/`SEEK_END`; a fresh memfd
proves typed start/current/end positions, sparse data/hole positions,
position-preserving sync calls, and direct oversized-offset `SEEK_SET:EINVAL` and
`SEEK_DATA`/`SEEK_HOLE:ENXIO`, pipe `ESPIPE`, and invalid-descriptor
`EBADF` errors. It completes only the typed Rust file-position family, not a
C filesystem API, pathname behavior, or host-filesystem durability claim.

`sync-reference` executes pinned-musl/raw x86 evidence plus its focused Rust
regression for `fs::sync`. It pins syscall `162`: after a disposable dirty
regular-file fixture, musl's void wrapper returns normally and the raw syscall
returns zero. This establishes only Linux's system-wide kernel/filesystem
writeback completion request and its unit-success contract, not writeback
timing, storage-cache or power-loss durability, the descriptor-associated
`syncfs(2)` operation, C filesystem APIs, pathname opening, or broader
filesystem behavior.

`syncfs-reference` executes pinned-musl/raw x86 evidence plus its focused Rust
regression for `fs::syncfs`. It pins syscall `306` and the one-word `rdi`
descriptor argument. Pinned musl and the raw syscall both accept a regular
file and a pipefs descriptor; the regular-file request leaves the current
position unchanged, and a duplicated then closed descriptor yields `EBADF`.
This establishes only a kernel/filesystem writeback completion request, not
storage-cache or power-loss durability, the separate process/system-wide
`sync(2)` operation, C filesystem APIs, pathname opening, or broader
filesystem behavior.

`sync-file-range-reference` executes pinned-musl/raw x86
`sync_file_range` evidence plus its focused Rust regression. It pins syscall
`277`, the `rdi`/`rsi`/`rdx`/`r10` scalar argument placement, signed
64-bit `loff_t`, and the closed `WAIT_BEFORE`/`WRITE`/`WAIT_AFTER` values
`1`/`2`/`4`. A regular-file zero-length request through EOF may succeed or
report direct `EOPNOTSUPP`, while preserving the current position in either
case; raw and musl agree on unknown-flag `EINVAL`, pipe `ESPIPE`, and invalid
descriptor `EBADF`. The typed Rust boundary rejects unknown flags and unsigned
ranges that cannot fit Linux's signed ABI; its raw core seam separately proves
invalid flags reach the x86 fourth syscall argument. The closed-descriptor
check intentionally uses that raw seam because a safe `BorrowedFd` cannot
outlive an open descriptor. This establishes a writeback request only, not
metadata or storage-cache durability, a C filesystem API, pathname opening, or
broader filesystem behavior.

`memfd-reference` executes the direct typed x86 `memfd_create`/seal lifecycle.
It pins `memfd_create=319`, raw `fcntl=72`, `MFD_CLOEXEC`,
`MFD_ALLOW_SEALING`, and `MFD_HUGETLB` values `1`/`2`/`4`,
`F_ADD_SEALS=1033`/`F_GET_SEALS=1034`, and Linux-5.10
`F_SEAL_SEAL`/`SHRINK`/`GROW`/`WRITE`/`FUTURE_WRITE` values
`1`/`2`/`4`/`8`/`16`. It checks named fresh-descriptor ownership and `CLOEXEC`,
the 249-byte accepted and 250-byte-kernel-rejected label boundary, sealing
state, `F_SEAL_WRITE`'s live-writable-mapping `EBUSY` guard followed by write
rejection, grow/shrink effects, and the `F_SEAL_FUTURE_WRITE` boundary:
preexisting writable shared mappings stay usable, while direct writes and new
writable shared mappings get `EPERM`; it also checks final-seal `EPERM` and
pipe/closed-descriptor errors. The Rust regression separately proves its
256-byte fixed-stack name rejection before a syscall.

This completes only typed Rust `filesystem.memory-file`,
`filesystem.seal-observation`, and `filesystem.seal-mutation`. It does not
select a C `fcntl`/header ABI, `memfd_secret`, broad filesystem behavior, or
huge-page size/reservation policy. `MFD_HUGETLB` selects only the kernel's
default huge-page size and leaves resource outcomes direct. `F_SEAL_EXEC` is
retained and forwarded for newer kernels, but its Linux-6.3 executable-policy
behavior is unproved on the Linux-5.10 baseline.

`rand-reference` runs a pinned-musl native x86 reference executable for
`getrandom` syscall/flag values and initialized-length behavior. It does not
link or select a crabc artifact.

`time-abi-reference` pins the musl x86 `timespec` shape,
realtime/monotonic/monotonic-raw/process-CPU clock IDs, and
`clock_gettime`/`clock_getres` syscall values used by the bounded native Rust
time facade. The separate `advanced-time-reference` gate records the wider
clock and POSIX-timer ABI. Neither command compiles a project C header or
selects a C ABI artifact.

`time-observation-reference` executes pinned-musl x86 realtime, C
`time(NULL)` whole-second, and process-CPU observations used by typed `time`,
`timespec_get`, `realtime_millis`, and `process_cpu_time` helpers. It does not
compile a project C header or select a C ABI artifact.

`relative-sleep-reference` executes a pinned-musl x86 `nanosleep` probe for
zero-duration completion, invalid-request `EINVAL`, and signal-interrupted
positive remainder behavior. It establishes only the typed Rust relative-sleep
boundary, not a C sleep ABI.

`clock-nanosleep-reference` executes the direct typed Rust x86
`clock_nanosleep(2)` slice. It pins the 16-byte, align-8 `timespec`, syscall
230, relative zero completion and child-contained `EINTR` with a positive
remainder, plus `TIMER_ABSTIME` past-deadline completion and a live interrupted
deadline with a null remainder pointer. Pinned musl returns a direct positive
error from its C function, whereas the raw syscall uses `-1` plus `errno`; the
typed Rust facade instead uses its direct syscall error boundary. It completes
only `time.clock-sleep`: C sleep APIs, clock mutation, POSIX timers, and
broader time policy remain excluded.
It is distinct from the separately selected private C static-archive
`libc-nanosleep` and `libc-clock-nanosleep` artifacts below.

`getitimer-reference` executes the direct typed x86 read-only interval-timer
query. It pins signed 16-byte, align-8 `timeval` and 32-byte, align-8
`itimerval` records (nested offsets zero/eight and interval/value offsets
zero/16), `getitimer=36`, all three `ITIMER_*` selectors, canonical results
from musl and the direct syscall, and invalid-selector `EINVAL`. A result is
a transient snapshot, so it does not compare separately read values that can
decrement. It admits only `time::getitimer`; C time APIs and timer/signal
delivery policy remain excluded.

`setitimer-reference` executes the x86 `time.process-interval-control` slice.
It pins syscall 38 over the established 16-byte `timeval` and 32-byte
`itimerval` records, all three `ITIMER_*` selectors, uses short-lived children
for every timer mutation, and verifies musl/raw old-setting exchange,
replacement, disarm, and malformed-microsecond `EINVAL` behavior. The typed
Rust facade admits validated microsecond settings and the Rust-only
`alarm`/`ualarm` aliases, which operate on `ITIMER_REAL`: `alarm` rounds a
prior fractional remainder up to seconds, while `ualarm` returns bounded whole
microseconds. The pinned-musl C `ualarm` comparison is valid only for
subsecond inputs because musl does not normalize inputs of one second or more;
the Rust facade intentionally accepts `u32` microseconds through `Duration`.
These aliases add no C ABI. C time APIs, timer/signal delivery policy, and
broader timer control remain excluded.

`timerfd-reference` executes pinned-musl and raw x86 proofs for the direct
typed `time::{timerfd_create, timerfd_settime, timerfd_gettime}` slice. It pins
the 32-byte, align-8 `itimerspec` layout (interval/value offsets zero and 16),
syscalls 283/286/287, all five named Linux timer clocks (with the alarm-clock
capability result preserved), known and future-bit kernel validation,
close-on-exec/nonblocking creation, relative/absolute settings,
`CANCEL_ON_SET` acceptance, periodic-setting inspection, exact eight-byte
expiration reads, disarming, and invalid
cases. It does not select broader timer policy, C time APIs, or a general x86
facade.

`pselect-reference` executes pinned-musl and raw x86 descriptor-bit-vector
proofs for the direct typed `event::{select, pselect}` slice. It pins
`FD_SETSIZE=1024`, the 128-byte `fd_set` with eight-byte words,
`pselect6=270`, empty/readable pipe behavior, caller-timeout preservation,
invalid `nfds` handling, raw mask-pointer/size argument-six placement, and
raw/pinned-musl temporary signal-mask restoration. C select APIs and a general x86
facade remain excluded.

`poll-reference` executes a pinned-musl x86 pipe fixture through `poll(2)` to
pin empty, readable, and hangup states used by the bounded typed Rust poll
facade. It does not compile a project C header or select a C ABI artifact.

`ppoll-reference` executes a pinned-musl x86 pipe and signal fixture through
`ppoll(2)` and `pause(2)`, pinning readiness, temporary signal-mask
restoration, and `EINTR` completion. It is evidence for only the typed Rust
readiness slice, not C polling support or `crabc-libc` selection.

`epoll-reference` executes pinned-musl and raw x86 lifecycle proofs for the
direct typed `event::epoll` slice. It pins the packed 12-byte, align-1
`epoll_event` layout (event bits at offset zero and the 64-bit data union at
offset four), the `epoll_create1`/`epoll_ctl`/`epoll_pwait` syscall numbers,
close-on-exec and legacy creation, future-bit forwarding for Linux validation,
create/add/modify/delete readiness behavior, borrowed eight-byte masks, and
temporary mask installation/restoration. C polling support and a general x86
facade remain excluded.

`process-identity-reference` executes pinned-musl scalar and
real/effective/saved UID/GID observations. It is an oracle for the bounded
typed Rust read-only identity facade, not C process API support.

`getgroups-reference` executes a pinned-musl x86 supplementary-group
query/fill lifecycle. It pins unsigned 32-bit, align-4 `gid_t`,
`getgroups=115`, null zero-count queries, musl/direct fill equivalence, and
the conditional undersized-buffer `EINVAL` result. It admits only typed Rust
`process::{getgroups_count, getgroups}`: the count is a sizing observation,
not a reservation, so callers retry after an `EINVAL` count-to-fill race. It
does not select C `getgroups`/`setgroups`, credential mutation or
synchronization, or a broader process API.

`process-session-reference` executes pinned-musl `getpgid`, `getpgrp`, and
`getsid` observations. It is an oracle for the typed read-only process
group/session slice, not process control support.

`setrlimit-reference` executes a child-contained pinned-musl x86
calling-process resource-limit exchange. It pins `prlimit64=302`, the
16-byte `rlimit64` record, raw set plus musl read, musl restore plus raw read,
and inverted-limit `EINVAL` for the typed Rust `process::setrlimit` API. It
does not select target-process mutation or C process support.

`umask-reference` executes a child-contained pinned-musl process-mask
exchange. It pins x86 `umask=95`, unsigned 32-bit `mode_t`, and raw/musl
old-mask exchange plus restoration for the typed Rust `process::umask` API.
It admits neither pathname creation nor C process support.

`pidfd-open-reference` executes pinned-musl `pidfd_open(2)` calls, pinning
descriptor ownership, `PIDFD_NONBLOCK`, and direct kernel error behavior. It
is evidence for only the typed Rust pidfd-creation slice, not process control
or C process support.

`fcntl-getlk-reference` executes a pinned-musl x86 `F_GETLK` probe, pinning
the `struct flock` record shape, unlocked queries, and a forked conflicting-lock
observation. It establishes only the typed read-only Rust lock-query boundary,
not lock mutation, general `fcntl`, or C process support.

`fcntl-status-reference` executes pinned-musl and raw x86
`fcntl(F_GETFL/F_SETFL)` calls. It pins `fcntl=72`, commands `3`/`4`, x86
status values, shared open-file-description mutation through `dup`, immutable
access/creation/per-descriptor bits, exact restoration, and direct `EBADF`.
It establishes only typed Rust `fs::{OFlags, fcntl_getfl, fcntl_setfl}` status
flags—not pathname opening, generic C `fcntl`, or errno-TLS support.

`flock-reference` executes pinned-musl/raw x86 evidence plus its focused Rust
regression for `fs::{FlockOperation, flock}`. It pins syscall `73` and
`LOCK_SH`/`LOCK_EX`/`LOCK_NB`/`LOCK_UN` values `1`/`2`/`4`/`8`.
It proves only advisory whole-file locks associated with an open file
description: duplicates share and can release that state, while an independently
opened child descriptor sees nonblocking exclusive contention before succeeding
after release. Invalid operations and closed descriptors report direct
`EINVAL`/`EBADF`. It does not select `flock`/`fcntl` record-lock
interaction or `fcntl` record-lock mutation, C APIs or errno TLS, pathname
opening, durability, or network/distributed-filesystem semantics.

`sendfile-reference` executes pinned-musl/raw x86 evidence plus its focused
Rust regression for `fs::sendfile`. It pins syscall `40` and signed
64-bit `off_t`: an explicit input offset advances without moving the input
descriptor's shared position, while a null offset advances that position.
The regular-file fixture proves short and EOF-zero results, output bytes and
position, and direct `EINVAL`/`EBADF` errors. It does not select a C API
or errno TLS, pathname opening, socket/network or splice behavior, durability,
or kernel descriptor ownership transfer. Passing a reference or `BorrowedFd`
retains Rust descriptor ownership; an owning `AsFd` passed by value follows
ordinary Rust move/drop semantics.

`copy-file-range-reference` executes pinned-musl/raw x86 evidence plus its
focused Rust regression for `fs::copy_file_range`. It pins syscall `326` and
signed 64-bit `off_t`: explicit input and output offsets are staged and commit
only after a successful copy without moving either shared descriptor position,
while a null offset advances that descriptor's shared position. The
regular-file fixture proves short and EOF-zero results at fixed zero flags; the
raw and pinned-musl explicit-offset forms agree. Its C fixture records raw/
musl negative-offset `EOVERFLOW`, nonzero-flag `EINVAL`, and closed-descriptor
`EBADF`; the typed Rust boundary instead rejects unrepresentable unsigned
offset/ranges with `Errno::INVAL` before either `AsFd` conversion. It does not
select C APIs or errno TLS, pathname operations, copy flags, sendfile/splice
fallbacks, filesystem-copy policy, or durability.

`scheduler-priority-bounds-reference` executes a pinned-musl x86 probe for the
`SCHED_OTHER`/`SCHED_FIFO`/`SCHED_RR` priority minima and maxima, raw syscall
values, and invalid-policy behavior. It establishes only the typed Rust
read-only scheduler-priority bounds query, not scheduling mutation or C process
support.

`rr-interval-reference` executes the direct typed x86 read-only
`sched_rr_get_interval(2)` query. It pins the x86 16-byte, align-8 `timespec`,
syscall 148, PID-zero and explicit-`gettid` selection for both the calling
task and a distinct live worker task, canonical duration validation, and
direct `ESRCH` propagation. Its pinned-musl C oracle uses the worker only as
harness machinery; the interval query does not select a C API, pthread facade,
scheduler policy, other scheduler parameters, errno TLS, or CPU affinity.

`sched-affinity-reference` executes the direct typed x86 read-only
CPU-affinity observation slice. It pins the fixed 128-byte mask and syscall
204, PID-zero and explicit `gettid` selection for the calling task and a
distinct live non-leader task, raw initialized-prefix/untouched-tail behavior,
and pinned musl's zero-success/zero-tail C-wrapper normalization. The typed
Rust facade owns a zeroed mask and exposes no C return value. Its pinned-musl
pthread worker is oracle harness machinery only; this observation gate excludes
scheduler policy, C or pthread facades, errno TLS, and broader record-owning
support.

`sched-affinity-set-reference` executes the direct typed x86
`sched_setaffinity(2)` slice. It pins the 128-byte mask and syscall 203. The
probe reapplies the initial task's observed mask without broadening it, then
selects a retained live non-leader worker task by explicit `gettid` and narrows
that worker to one observed CPU before it exits. The typed facade accepts a
caller-provided bounded `CpuSet`; Linux may intersect it with available and
cgroup-permitted CPUs. Both musl and the raw syscall succeed; an empty mask
yields `EINVAL`, a missing task ID yields `ESRCH`, and the postcondition cannot
include a CPU outside the requested mask. Its pinned-musl pthread worker is
oracle harness machinery only. Other scheduler policy, C or pthread facades,
errno TLS, and broader record-owning support remain excluded.

`priority-reference` executes a pinned-musl x86 probe for
`PRIO_PROCESS`/`PRIO_PGRP`/`PRIO_USER`, `getpriority` syscall 140, the
non-negative `[1, 40]` raw success encoding, and missing-process `ESRCH`.
It establishes only the typed Rust read-only `getpriority` boundary; it does
not by itself select priority mutation or C process support.

`setpriority-reference` executes a child-contained pinned-musl x86
scheduling-priority exchange. It pins `setpriority=141`, the existing closed
`PRIO_*`/nice-value vocabulary, raw set plus musl read, musl no-op set plus raw
read, invalid-selector `EINVAL`, and missing process/group/user target `ESRCH`
for the typed Rust
`process::{setpriority_process, setpriority_process_group, setpriority_user}`
operations. It does not select scheduler-policy mutation or C process support.

`rlimit-reference` executes a pinned-musl x86 read-only resource-limit
lifecycle. It pins the 16-byte, align-8 `rlimit`/`rlimit64` record
(current/maximum offsets zero and eight), `prlimit64=302`,
`RLIM_INFINITY=UINT64_MAX`, the complete selectors zero through 15, repeated
and explicit-self reads, and invalid-selector/missing-target errors. It is
evidence for typed calling-process `process::getrlimit` only. Its
explicit-self and missing-target observations alone do not select targeted
queries, mutation beyond `setrlimit`, C process APIs, or a general x86 facade.

`rlimit-targeted-reference` executes a pinned-musl/raw x86 read-only targeted
resource-limit query. A forked live child retains a distinct safe
`RLIMIT_NOFILE` soft limit while musl `prlimit` and raw `prlimit64=302` both
return its full 16-byte, align-8 `rlimit64` record. The native Rust regression
makes the matching typed optional-PID query and preserves missing-PID `ESRCH`.
It admits only the bounded read-only `process::getrlimit_for` slice; target
mutation, C process APIs, errno TLS, and broader record-owning support remain
excluded.

`rusage-reference` executes a pinned-musl x86 read-only resource-usage
lifecycle. It pins the 16-byte, align-8 `timeval`, the 144-byte, align-8
kernel-initialized `rusage` prefix (selected offsets zero, 16, 32, and 136),
the public 272-byte musl record's reserved tail at offset 144,
`getrusage=98`, selectors `0`/`-1`/`1`, direct selector observations with
stable children-prefix equivalence, canonical values, and invalid-selector
behavior. It admits typed read-only `process::getrusage` only: its Rust value
copies the initialized kernel prefix and omits musl's uninitialized reserved
tail. It does not select C `struct rusage` storage, raw record exposure,
broader process-accounting policy, or a general x86 facade.

`times-reference` executes a pinned-musl x86 read-only process-accounting
lifecycle. It pins signed 64-bit `clock_t`, the 32-byte, align-8 `tms` record
(field offsets zero, eight, 16, and 24), `times=100`, nonnegative process
ticks, a normal nondecreasing observation sequence, and direct syscall
observations. The independent elapsed tick return remains signed because it
may wrap. It admits typed read-only `process::times` only; it does not select
C `times`/`struct tms` support, tick-rate conversion, or a general x86 facade.

`fstat-reference` records the pinned-musl x86 144-byte `fstat` record and
regular-file behavior for the bounded descriptor `fs::fstat` slice. It does
not by itself complete the broader filesystem path-core capability; the
aggregate `path-core-reference` uses it as one component.

`statfs-reference` completes the typed Rust `filesystem.capacity-metadata`
slice: pinned-musl/raw x86 `statfs` and `fstatfs` capacity observations,
private Linux filesystem-statistics records, and musl's `statfs`-to-`statvfs`
mapping, including its first-filesystem-id-word rule. It is Rust-only; public
C structs and ABI,
allocator and errno TLS, pathname mutation, and broader filesystem metadata
remain excluded.

`statat-reference` records the private x86 144-byte stat record through
`newfstatat(2)`, both relative to a borrowed directory descriptor and through
`CWD`, with only `AT_SYMLINK_NOFOLLOW`. It does not expose `AT_EMPTY_PATH`,
general stat/path APIs, or filesystem mutation. It is the narrow
`st_dev`/`st_ino` identity foundation for the separately admitted logical
current-directory name.

`path-lifecycle-reference` is the staged private pathname-lifecycle and
metadata batch. Its pinned-musl/raw x86 oracle and focused Rust regressions
cover the 144-byte `stat` record, descriptor-relative `openat`/`newfstatat`
metadata, regular-file creation and `truncate`, `mkdirat`, typed special-node
creation with an unprivileged FIFO fixture, `unlinkat`/`rmdir`, `fchmod`/
`fchmodat`, and safe same-owner/group
`fchown`/`fchownat` no-op ownership observations. It proves exact inode/type
records, final-symlink follow/no-follow metadata selection, fixed flag
validation, and the fixture’s representative `ENOENT`/`EINVAL` outcomes. The
closed x86 syscall
numbers are `openat=257`, `mkdirat=258`, `mknodat=259`, `fchownat=260`,
`newfstatat=262`, `unlinkat=263`, `fchmodat=268`, `fchmod=91`,
`fchown=93`, and `truncate=76`. The typed API admits special-node kinds, while
this unprivileged oracle exercises only FIFO creation and leaves direct kernel
privilege/filesystem policy visible. This is staged private Rust evidence only;
it does not make x86 runtime support public, select a C ABI or `errno` TLS, or
by itself complete the aggregate `filesystem.path-core` capability.

`namespace-reference` is the separate staged namespace portion of this batch:
hard and symbolic links, caller-buffer `readlinkat`, and descriptor-relative
`renameat2` lifecycle operations. It proves exact link target bytes and inode
identity, final-link selection, short-buffer behavior, fixed rename/link flag
validation, and the fixture’s representative missing-path and
invalid-operation outcomes. This is private staged evidence and does not make
x86 runtime support public or select a C ABI/`errno` TLS. `AT_EMPTY_PATH`
outside the separately evidenced statx-specific form, canonicalization, CWD
mutation, C `DIR` APIs and bulk directory helpers, C temporary-file/directory
APIs, xattr namespace/ACL and symlink-storage policy, and broader filesystem
policy remain future work. The separately evidenced `xattr-reference`,
`directory-reference`, `temporary-object-reference`, and `statx-reference`
gates cover only their direct Rust boundaries.
The aggregate
`path-core-reference` separately adds the selected owned `readlink`/
`readlinkat` convenience boundary.

`socket-transport-reference` is the staged direct socket/address transport
batch. Its pinned-musl/raw x86 probe and focused Rust regressions prove native
Linux LP64 `iovec`/`msghdr`/`mmsghdr`, IPv4/IPv6 socket-address, and
socket-storage layouts; Unix-pair traffic; IPv4/IPv6 UDP and IPv4 TCP loopback lifecycle;
typed local/peer endpoint values; `accept4` close-on-exec/nonblocking flags;
shutdown; the named `SOL_SOCKET` option set; fixed `SIOCATMARK`; and ordinary
vectored and batched messages. It is Rust-only evidence: C socket/errno APIs,
resolver/netdb state, network-device ioctls, ancillary-control buffers,
Unix-domain address values, and general x86 runtime support remain excluded.

`interface-device-reference` is the separate x86 interface/device vertical
slice. Its pinned-musl/raw probe locks the Linux LP64 40-byte `ifreq` ioctl
record, `SIOCGIFINDEX`/`SIOCGIFNAME`, and the fixed 12-byte `sockaddr_nl`,
16-byte netlink/link, 8-byte address, and aligned attribute records used for
`RTM_GETLINK` and `RTM_GETADDR`, plus the 16-byte `iovec`/56-byte `msghdr`
`recvmsg(MSG_TRUNC)` receive seam. The direct Rust regression uses only stable
loopback/self-consistency checks: it proves the index/name round trip,
allocation-free link enumeration, owned deduplicated names, and an owned
two-phase link/IPv4-and-IPv6-address snapshot. The same lane runs malformed
netlink-parser regressions and rejects a datagram above its fixed 8192-byte
receive buffer with `OVERFLOW`, never as a partial snapshot. The command also
builds the no-std static probes for the allocation-free and alloc-gated seams.
This remains a Rust-only native API: generic ioctl, C
`ifreq`/`ifaddrs`/`if_nameindex`, interface mutation, resolver/netdb state, C
errno/TLS, and public x86 support remain excluded. The private
`facade.record-owning` foundation is verified by its closed aggregate runner:
its 24 slices are the exact union of all 44 closed capabilities, without
promoting any C-runtime boundary or public x86 support.

`resolver-transport-reference` proves the private no-std
`crabc-core::resolver` exchange seam only. Its isolated local UDP/TCP fixtures
prove that short, wrong-ID, question-mismatched, record-framing-malformed, and
oversized UDP datagrams are ignored; `recvmsg(MSG_TRUNC)` prevents a fixed
caller buffer from parsing a partial datagram. A truncated UDP response retries
the exact query through partial length-prefixed TCP I/O, a silent first server
advances to the next configured server, and total failure remains within the
caller's timeout budget. This transport command does not itself exercise or
evidence the separately staged alloc-backed `crabc-rs::resolver` or
`crabc-rs::netdb` facade, parse `/etc/hosts` or `/etc/resolv.conf`, consult C
resolver state, or contact external DNS.

`resolver-facade-reference` admits the alloc-backed
`crabc-rs::resolver` policy plus its `netdb::HostDatabase` dependency. Its local fixtures
cover strict owned hosts parsing and host-before-DNS precedence, numeric/mapped
and passive lookup policy, A/AAAA lookup, search/`ndots`, CNAME, PTR, bounded
timeout mapping, and direct system snapshot smoke. The no-std probe keeps the
same resolver/hosts boundary linkable without a C resolver ABI. This excludes
C resolver/netdb state or ABI, NSS, plugins, `/etc/networks`, external DNS,
and public x86 support.

`netdb-reference` completes the separate owned `crabc-rs::netdb` x86 slice.
It proves strict caller-byte and direct-system `/etc/hosts`, `/etc/services`,
and `/etc/protocols` snapshots, typed host/service/protocol lookup,
source-order enumeration, owned records after input disposal, and malformed
whole-snapshot rejection; its no-std probe covers hosts, services, and
protocols together. It does not add `/etc/networks`, NSS/plugins, C
netdb/resolver static storage or ABI, external DNS, or public x86 support.

`users-databases-reference` completes the separate private
`crabc-rs::users` x86 slice. It proves immutable caller-byte and direct-system
`/etc/passwd` plus `/etc/group` snapshots, strict UTF-8 fields with interior
NUL rejection, typed user/group IDs and member names, source-order
enumeration, duplicate-record first-match lookup, post-input ownership, and
malformed whole-snapshot rejection. The no-std
`users_databases_direct_probe` preserves the alloc-backed direct Rust boundary;
paired raw/pinned-musl C evidence pins `openat=257`, `read=0`, `close=3`,
`O_RDONLY=0`, and `O_CLOEXEC=0x00080000` for deterministic conventional-file
fixtures. Each system file is capped at one mebibyte and is loaded separately,
not as an atomic cross-file account transaction. This selects no C
`getpw*`/`getgr*` state, cursor, header, or ABI; no errno TLS, shadow,
process-global enumeration, utmp/utmpx, mntent, user-shell/login helpers, account or group mutation,
`initgroups`, NSS/providers, or public x86 support.

`mount-reference` completes the separate private `crabc-rs::mount` x86
direct-error slice. `mount::{mount, unmount, MountFlags, UnmountFlags}`
requires non-null source, target, and filesystem-type byte paths, rejects
interior NUL bytes before either syscall, and accepts data only as an optional
borrowed `&CStr`. It pins the five-register x86 `mount=165` calling convention
(`rdi`/`rsi`/`rdx` path pointers, `r10` flags, and `r8` data) and
`umount2=166` (`rdi` target and `rsi` flags). The focused Rust regression,
no-std `mount_direct_probe`, and raw/pinned-musl C fixture use a per-process
unique missing target and direct errors only; they never grant mount authority
or perform a successful mount/unmount operation. Each C raw/musl pair must
agree on `EPERM` when permission checking precedes resolution or `ENOENT` when
the checked-absent target is reached, rather than hiding that kernel ordering.

This is not a mount policy or namespace-management surface. It selects no
null source/type form, arbitrary data pointer, successful namespace mutation,
bind/remount/propagation or detach policy, `pivot_root`, `unshare`, `setns`,
or filesystem-descriptor mount APIs (`fsopen`, `fsconfig`, `fsmount`,
`move_mount`, `open_tree`, `fspick`); no C mount/umount API/header/ABI or errno
TLS; and no public x86 support.

`access-reference` completes the record-free direct
`fs::{access, accessat}` permission-observation slice. It pins x86
`access=21`, legacy `faccessat=269`, and flags-bearing `faccessat2=439`; Rust
uses the legacy `faccessat(AT_FDCWD, path, mode)` seam for `access`. Its closed
`Access` modes and distinct `AccessAtFlags` prevent access-specific
`AT_EACCESS`/`AT_SYMLINK_NOFOLLOW` policy from widening the private `statat`
flag type. Raw and pinned-musl calls agree on ordinary and descriptor-relative
checks, missing-path `ENOENT`, dangling-final-symlink follow versus nofollow,
and invalid mode/flag `EINVAL`. A child-contained differing-real/effective-ID
fixture proves the effective-credential form. The fixed-stack Rust path input
rejects interior NULs and 256-byte inputs before the kernel in its no-alloc
configuration. This direct permission command does not admit pathname
mutation, C APIs/errno TLS, or the separately evidenced
`filesystem.path-core` family.

`getcwd-reference` completes x86 `filesystem.cwd` and the contained
`filesystem.path-metadata` logical-name slice. Direct syscall 79 and pinned
musl agree on the exact initialized NUL-terminated caller-buffer prefix and
undersized-buffer `ERANGE` behavior. The pinned-musl C wrapper instead returns
`EINVAL` for its zero-size input; the direct Rust facade retains the raw-kernel
`ERANGE` rather than emulating that wrapper policy. The alloc-gated
`process::getcwd_alloc` clears and reuses a caller vector, retries only
`ERANGE`, and returns a `CString`; a native child regression puts its CWD
beyond the initial small buffer.

The same gate proves raw and pinned-musl `newfstatat=262` agreement on the
x86 144-byte `stat` identity fields. Pinned musl's C
`get_current_dir_name` reads environment `PWD`; Rust instead takes an explicit
caller-owned `Option<&CStr>` and never reads the environment. A nonempty
absolute snapshot that has the same `st_dev`/`st_ino` pair as `.` preserves its
exact logical spelling, including non-UTF-8 bytes. Mismatched, relative, empty,
or absent snapshots fall back to physical `getcwd`, and a too-small validated
buffer returns `RANGE`; alloc-gated logical/physical results are also covered.
`getcwd-reference` itself does not select `chdir` or `fchdir`; those are
separately evidenced by `cwd-canonicalize-reference`. C APIs, errno TLS, and
general stat/path APIs remain explicitly deferred.

`readlinkat-reference` executes the private x86 caller-buffer raw
`readlinkat(2)` boundary. It records the initialized target prefix without
adding a NUL byte, and accepts a short output buffer with its truncated prefix.
The raw syscall rejects a zero-length buffer with `EINVAL`; pinned musl's C
wrapper instead returns an empty successful result, which the direct Rust
facade deliberately does not emulate. Without `alloc`, `&str` and byte-slice
paths use fixed 256-byte stack conversion storage; a borrowed `&CStr` remains
caller-owned. This raw command does not by itself select
`filesystem.path-core`.

`path-core-reference` is the private x86 aggregate for the selected
`filesystem.path-core` capability. It composes fstat/statat, pathname
lifecycle, namespace, timestamp, and raw-readlink musl/kernel probes with
focused Rust regressions. Its alloc-gated `readlink` and `readlinkat` return a
byte-preserving `CString`, reuse a supplied vector where possible, and retry
when Linux returns a length equal to the buffer capacity because that result is
ambiguous between an exact fit and truncation. The regression uses an exactly
capacity-sized non-UTF-8 target, and the no-std static probe links both owned
entry points with a private allocator. The separately evidenced
`filesystem.canonicalize`/`filesystem.cwd-mutation` and
`filesystem.extended-metadata` statx-specific `AT_EMPTY_PATH` slices,
`filesystem.directory`, `filesystem.xattr`, and
`filesystem.temporary-objects` slices, C ABI/errno TLS, and public x86 support
remain outside this path-core slice.

`xattr-reference` is the separate private x86 `filesystem.xattr` vertical
slice. Its focused no-alloc Rust regression, no-std static probe, and
pinned-musl/raw C fixture cover all path, no-follow-path, and descriptor
set/get/list/remove forms. Values remain raw bytes, including embedded NULs;
zero-sized value/list calls are size queries; successful caller buffers expose
only their initialized prefixes; undersized buffers return `RANGE`; and lists
stay Linux NUL-separated bytes with no sorting or allocation policy. The C
fixture requires `XATTR_CREATE=1`, `XATTR_REPLACE=2`, and x86 syscall numbers
188 through 199, while leaving unknown flag validation, `EEXIST`, `ENODATA`,
and `EINVAL` visible. A filesystem which uniformly reports `EOPNOTSUPP` or
`ENOSYS` for the initial paired musl/raw operation takes a recorded
unavailable-policy branch. User xattrs on symlinks are not selected: the
no-follow syscall form is exercised on a regular file rather than assuming a
filesystem's symlink-xattr policy. This Rust facade evidence does not select
the separately evidenced `filesystem.extended-metadata` slice, additional
xattr namespace/ACL policy, C directory/temporary APIs, or public x86 support;
the separate static C artifact above owns its bounded `sys/xattr.h` and
errno-TLS boundary, including the selected descriptor forms.

`directory-reference` is the separate private x86 directory-record vertical
slice. Its no-alloc Rust regressions and static probes cover `RawDir`'s
aligned caller-owned `getdents64` buffer, validated borrowed byte names,
255-byte names, and direct undersized-buffer `EINVAL`; `Dir` owns a
close-on-exec descriptor, transfers existing ownership without reopening, and
turns its first error into exhaustion. Its opaque `d_off` cookies discard
buffered records on direct `lseek`, while deferred rewind restarts iteration.
The pinned-musl/raw fixture pins `getdents64=217`, `lseek=8`, and
`openat=257`, plus the private `linux_dirent64` offsets (`ino` 0, `off` 8,
`reclen` 16, `type` 18, name 19). `opendir`/`fdopendir`/`dirfd`/`readdir`/
`telldir`/`seekdir`/`rewinddir` are pinned-musl oracle calls only. This does
not select C `DIR`/`dirent` APIs, `readdir_r`, `scandir`, sorting or walking
helpers, public `telldir`, C temporary-file/directory APIs, canonicalization,
the separately evidenced `filesystem.extended-metadata` statx-only
`AT_EMPTY_PATH` form, CWD mutation, C ABI/errno TLS, or public x86 support.

`temporary-object-reference` is the separate private x86 temporary-object
vertical slice. Its no-default-feature and alloc Rust regressions and three
no-std static probes cover `NamedTempFile`, `TempFile`, and the temporary
directory forms. Named files use an explicit retained parent descriptor,
exclusive mode `0600` creation, a 96-bit lowercase-hex `getrandom` basename,
close-on-exec, descriptor-relative cleanup after a CWD change, and explicit
ownership transfer that deliberately leaves the name linked. Anonymous files
use `O_TMPFILE | O_RDWR | O_CLOEXEC`, remain regular files with link count zero,
and return `EOPNOTSUPP` unchanged on an unsupported filesystem rather than
falling back to a named entry. Temporary directories use atomic `mkdirat` mode
`0700`, preserve arbitrary non-NUL prefix/path bytes, and offer either
caller-buffered or alloc-owned output. The direct Rust and paired
pinned-musl/raw C evidence pin `getrandom=318`, `openat=257`, `mkdirat=258`,
`unlinkat=263`, `fcntl=72`, `O_TMPFILE=0x00410000`, and the related
close-on-exec/create/remove flags. It
does not select C `mkstemp`/`mkdtemp`/`tmpfile`/`tmpnam`/`tempnam`/`mktemp`
APIs, a default temporary-directory policy or global registry, CWD mutation,
canonicalization, the separately evidenced `filesystem.extended-metadata`
statx-only `AT_EMPTY_PATH` form, file-handle APIs, C ABI/errno TLS, or public
x86 support.

`statx-reference` is the separate private x86 extended-metadata vertical
slice. Its focused Rust regression, no-std static probe, and pinned-musl/raw C
fixture lock `SYS_statx=332`, the private Linux 5.10 256-byte align-8 output through
`stx_dio_offset_align` at byte 156, and ordinary path, borrowed-descriptor,
and final-symlink metadata observations. The returned `stx_mask` remains
authoritative for optional fields; the reserved request bit is rejected before
the syscall, and unknown requested bits are masked to the layout this facade
understands. Only this statx flag vocabulary admits `AT_EMPTY_PATH`: it does
not turn that flag into a general x86 `*at` facility. The raw Rust boundary is
stateless and preserves `ENOSYS`; unlike pinned musl's C wrapper, it does not
fall back to `fstatat`. When the raw C syscall reports `ENOSYS`, the fixture
records its explicit `raw=ENOSYS-musl-fallback` branch instead of claiming
raw/musl equality. It does not select general `AT_EMPTY_PATH`, the separately
evidenced canonicalization/CWD-mutation slice, file-handle APIs, C `struct
statx`/`sys/stat.h`/errno TLS, or public x86 support.

`cwd-canonicalize-reference` is the private x86 filesystem-context vertical
slice. Its fixed `PATH_MAX=4096` workspace canonicalizer produces an absolute,
byte-preserving physical pathname without a C `realpath` call: it uses direct
`openat=257`, `readlinkat=267`, and `getcwd=79` descriptor/path operations to
normalize `.` and `..`, resolve relative and absolute symbolic links, preserve
non-UTF-8 bytes, bound expansion and output capacity, and stop after forty
symbolic links. The alloc spelling returns an owned NUL-terminated path while
the no-alloc spelling initializes only the caller's output prefix. The same
gate proves direct `chdir=80` and `fchdir=81`; these mutate process-global CWD
state, so the Rust regression is child-contained and restoration is performed
through an owned directory descriptor. The paired pinned-musl/raw C fixture is
an oracle for physical pathname and CWD behavior only. This does not select
`chroot` or `process.root-change`, per-thread CWD isolation, C
`realpath`/`chdir`/`fchdir` APIs, errno TLS, a C filesystem ABI, or public x86
support.

`root-change-reference` is the separate private x86 `process.root-change`
vertical slice. `process::chroot<P: PathArg>` uses direct Linux x86
`chroot=161`, accepts safe byte paths, and returns direct `Errno` failures. A
successful call changes future absolute pathname resolution for the process but
leaves CWD unchanged; it provides neither restoration nor a route to the old
root. This is not a containment or sandbox boundary. The focused Rust
child-contained regression and pinned-musl/raw C oracle make successful calls
only in disposable child processes, with `CAP_SYS_CHROOT`; the existing `no_std`
`process_chroot_direct_probe` also proves the direct boundary. It selects no C
ABI or errno TLS, `pivot_root`, mount namespaces, or public x86 support.

`ipc-reference` is the separate private x86 POSIX named-message-queue vertical
slice. Its focused Rust regressions, no-std static probe, and pinned-musl/raw C
fixture lock the fixed-arity `mq_open=240`, `mq_unlink=241`,
`mq_timedsend=242`, `mq_timedreceive=243`, and `mq_getsetattr=245` syscalls;
an `i32` `mqd_t`; the 64-byte align-8 `mq_attr`; and the 16-byte align-8
absolute-deadline `timespec`. The direct Rust boundary validates POSIX
`/name` spelling before passing Linux's raw no-leading-slash name, keeps queue
descriptor ownership explicit through close/drop and unlink-after-open, and
covers typed attributes, `CLOEXEC`, nonblocking/full/empty behavior, priority
ordering through 32767, and absolute `CLOCK_REALTIME` timeouts. It does not
itself select `mq_notify`, SysV IPC, semaphores, AIO, general C mqueue
headers/APIs/errno TLS, a C ABI, or public x86 support. The separately sealed
`static-c-mq-setattr` archive artifact below does not promote this Rust-facing
slice.

`shm-reference` is the separate private x86 POSIX named-shared-memory vertical
slice. Its focused Rust regression and paired pinned-musl/raw C fixture lock
`openat=257`, `unlinkat=263`, and normal four-argument `openat` placement of
the mode word in `r10`; POSIX leading-slash normalization and invalid-name
preflight; `NAME_MAX=255`; and fixed 265-byte `/dev/shm/<name>\0` construction.
`shm::open` owns a descriptor, always adds `O_CLOEXEC`, preserves caller status
flags and direct kernel/mount errors, and leaves an unlinked object usable
through a live descriptor. Its default final-symlink resolution follows the
link; a caller-supplied `O_NOFOLLOW` exposes the direct `ELOOP` result. The
Rust boundary deliberately matches existing
AArch64/Rustix direct behavior by forcing only `O_CLOEXEC`; pinned musl's C
`shm_open` wrapper also adds `O_NOFOLLOW` and `O_NONBLOCK`, so the fixture
records an intentional flag-policy difference rather than claiming raw/musl
flag equivalence. It does not select C shared-memory APIs/ABI, TLS `errno`,
cancellation mechanics, SysV shared memory or semaphores, mapping/sizing
abstractions, mount policy/fallback, global registries, wider IPC, or public
x86 support.

`inotify-reference` is the separate private x86 bounded inotify vertical
slice. Its focused Rust regressions, no-std static probe, and pinned-musl/raw C
fixture lock `inotify_init1=294`, `inotify_add_watch=254`, and
`inotify_rm_watch=255`; the 16-byte align-4 `struct inotify_event` header
(`wd`/`mask`/`cookie`/`len` at offsets 0/4/8/12, `name` at 16); and
`IN_NONBLOCK=0x00000800` plus `IN_CLOEXEC=0x00080000`. The Rust boundary owns
the descriptor, scopes watch identifiers to it, reads only into caller storage,
preserves byte names and unknown observed mask bits, validates variable-length
records, and exposes direct `EAGAIN`, `EINVAL`, `ENOENT`, `ENAMETOOLONG`, and
`EBADF` outcomes. The Rust facade does not select a Rust C wrapper or errno
TLS, legacy `inotify_init`, fanotify, recursive/background watcher policy,
global registries, namespaces/capability mutation, wider system facilities, or
public x86 support. The separate private `static-c-event-descriptors` artifact
owns bounded C `sys/inotify.h` headers/APIs/ABI and legacy-init evidence without
broadening this Rust slice or public support.

`calendar-time-reference` is the separate private x86 civil-time vertical
slice. Its focused UTC-calendar, timezone-rule, and local-calendar Rust
regressions, three no-std static probes, and pinned-musl/raw C fixture lock
`gettimeofday=96`; its private 16-byte align-8 `timeval` output
(`tv_sec`/`tv_usec` at offsets 0/8); and microsecond-to-`UnixTime`
normalization. `CalendarTime` provides strict UTC proleptic-Gregorian
conversion rather than a C `struct tm` representation. `TimeZone` owns rules
parsed only from caller-supplied POSIX-TZ bytes or TZif v1/v2/v3 data, including
the v2/v3 trailing POSIX rule; `LocalCalendar` converts a known instant in one
direction through those rules, so no DST-fold/gap local-to-instant choice is
invented. The C oracle confines its `TZ`/`tzset` setup to its own short-lived
process. Native Rust neither reads nor mutates `TZ`, libc timezone globals, or
system zoneinfo. This does not select C time headers/APIs/ABI, `time_t`,
`timeval`, or `tm` layout, errno TLS, clock query/set or process/thread clock
operations, POSIX timers, zoneinfo discovery/loading policy, inverse
`mktime`-style conversion, or public x86 support.

`advanced-time-reference` is the separate private x86 advanced-clock and
owned-POSIX-timer vertical slice. Its focused Rust regression, four no-std
static probes, and paired pinned-musl/raw C fixture lock the closed named
clock values; `clock_settime=227`, `clock_gettime=228`, and
`clock_getres=229`; and the Linux process-clock encoding validated by
`clock_getcpuclockid`. A descriptor-backed dynamic clock retains only a
borrowed descriptor for its query, while an unencodable or unresolved process
clock remains `SRCH` rather than becoming an arbitrary signed clock ID.

The same fixture locks the private 16-byte align-8 `timespec`, 32-byte
align-8 `itimerspec`, and 64-byte align-8 `sigevent` records; POSIX timer
syscalls 222 through 226; and `timer_settime`'s fourth `old_value` pointer in
`r10`. `PosixTimer` owns the kernel's private `i32` identifier, returns typed
duration pairs, supports `SIGEV_NONE`, signal, and thread-directed signal
notifications, and deletes on request or best-effort drop. The child-contained
oracle exercises no-side-effect timer initial, one-shot, periodic, disarm, and
delete lifecycles; unarmed signal forms prove their record shapes without a
handler or delivery. Clock-setting evidence invokes only `CLOCK_MONOTONIC` and
never mutates realtime. `TimerSetFlags` forwards non-`TIMER_ABSTIME` bits
unchanged; the Linux 5.10 POSIX-timer path ignores those bits rather than
returning an invented validation error. Its `SIGEV_NONE` disarm can retain a
nonzero last-expiry value while reporting a zero interval, which the typed
query preserves rather than normalizing into a fabricated all-zero setting.

This remains private Rust-only evidence. It selects neither C
`time.h`/`timer_t`/`sigevent` ABI nor `errno` TLS, `SIGEV_THREAD` callback
creation, signal-handler or timer-scheduling policy, global timer registries,
or public x86 support.

`child-ownership-reference` is the separate private x86 prepared-child
ownership vertical slice. `PreparedExec` owns copied, NUL-terminated path,
argument, and environment storage before the private `clone=56` child path;
the child uses only `FdAction` close/`dup2` operations and selected
`SpawnOptions` process-group, session, and signal-mask setup before
`execve=59`. A close-on-exec error pipe is reserved outside every requested
descriptor target, so parent-visible child setup or exec errors are reported
and reaped before `spawn` returns. A successful `Child` is a unique consuming
wait owner: `wait4=61` returns one `WaitStatus`, and even a `NOHANG` result of
`None` consumes the owner rather than creating a retry/supervision API.

The paired raw/pinned-musl C oracle pins four-byte `int`/`pid_t`, child syscall
numbers `clone=56`, `wait4=61`, and `waitid=247`, and the 128-byte align-8
`siginfo_t` child-report layout through `si_status` at offset 24. Its contained
lifecycle proves an unchanged `WNOHANG` status, `WNOWAIT` observation, exit
42, one exact reap, and post-reap `ECHILD`; focused Rust regressions also cover
descriptor actions, exec-failure reaping, error-pipe descriptor collisions, and
the consuming `NOHANG` state transition.

This remains private Rust-only evidence. The separately selected static C
child-reaping artifact does not broaden it into a generic child-ownership or
supervision API. This Rust slice selects neither generic
`fork`/`vfork`/`exec`/`wait`/`waitpid`/`waitid`, `posix_spawn`, C process or
signal headers/APIs/ABI, errno TLS, pthread/atfork/cancellation mechanics,
arbitrary spawn attributes, current-process exec, child supervision, nor public
x86 support.

`thread-kill-reference` is the separate private x86 exact same-process
thread-directed signal-delivery vertical slice. `signal::kill_thread` accepts a
typed positive `Pid` and application-visible `Signal`, fixes `tgid` to the
calling process, and uses direct Linux `tgkill=234` to deliver to one named
thread. The focused Rust regression confines its handler disposition and target
thread to a disposable process; it also proves direct `ESRCH` for an impossible
or nonmember thread ID and `EINVAL` for an explicitly unsafe invalid signal.
The no-std `thread_kill_direct_probe` proves the typed direct Rust boundary. The
paired raw/pinned-musl C fixture pins the exact raw syscall ABI and supplies
contained signal-delivery behavior evidence: raw `tgkill` proves a live
worker's pending signal, handler TID, and delivery, while musl's adjacent
`pthread_kill` behavior uses `tkill`. It does not select a musl `tgkill` API.

This remains private Rust-only evidence. It selects neither generic
process/group signaling, signal masks, queued signals, `signalfd`, a
signal-disposition framework, C `kill`/`tgkill`/`pthread_kill` headers or ABI,
errno TLS, pthread cancellation, nor public x86 support.

`mapping-reference` is the separate private x86 `memory.mapping` vertical
slice. It admits only unsafe `mm::{mmap, mmap_anonymous, mprotect, munmap}`:
the direct Linux syscalls are `mmap=9`, `mprotect=10`, and `munmap=11`.
`ProtFlags` and `MprotectFlags` are closed to `PROT_READ`, `PROT_WRITE`, and
`PROT_EXEC` (with empty `PROT_NONE`), while `MapFlags` requires exactly
`MAP_SHARED` or `MAP_PRIVATE`; the anonymous form adds `MAP_ANONYMOUS` itself.
`MAP_FIXED`, `MAP_32BIT`, and wider mapping/protection modes reject before the
kernel seam.

The focused Rust regression proves anonymous-private RW write, RO readback,
RW restoration, and unique unmap; a shared file mapping over a borrowed memfd
has immediate `pread` visibility. It also covers zero-length `mmap`, fixed and
`MAP_32BIT` flag rejection, and unaligned `mprotect` errors. The no-std
`mapping_direct_probe` covers the anonymous lifecycle. Paired raw and
pinned-musl C arms run the anonymous protection/readback/unmap sequence in
disposable children and pin the syscall values, LP64 widths, page size, and
selected `PROT_*`/`MAP_*` values. Only raw `SYS_mprotect` asserts the unaligned
`EINVAL` result: musl 1.2.6 rounds that wrapper input before its syscall, so
the fixture does not claim error equivalence.

This remains private Rust-only evidence. Callers retain mapping lifetime,
pointer provenance, backing-file, and reference-validity obligations; no
reference may survive `munmap` or an incompatible `mprotect`. The slice does
not select `mremap`, range locks/sync/advice/residency, the separate
`memory.vm` program-break/process-wide-lock/legacy-remap boundary, fixed or
wider mapping modes, C `sys/mman.h`/errno TLS, or public x86 support.

`memory-vm-reference` is the separate private x86 `memory.vm` vertical slice.
It admits unsafe `process::kernel_brk` for a null query and exact replay only,
`mm::MlockAllFlags`, `mm::{mlockall, munlockall}`, and unsafe
`mm::remap_file_pages`. The direct ABI is `brk=12`, `mlockall=151`,
`munlockall=152`, and `remap_file_pages=216`; its closed lock flags are
`MCL_CURRENT=1`, `MCL_FUTURE=2`, and `MCL_ONFAULT=4`. Linux returns a current
break pointer from `brk` even when an adjustment cannot be made, so this is
not libc `brk`/`sbrk` bookkeeping or an allocator boundary.
The raw C arm proves the null-query/same-address-replay contract. Pinned musl
1.2.6's `sbrk(0)` query agrees with that current pointer, but its
`brk(current)` wrapper deliberately returns `ENOMEM`; the raw break remains
unchanged. That recorded wrapper distinction is not selected Rust behavior.

`mlockall` changes process-wide policy. The focused Rust regression and the
paired raw/pinned-musl C arms therefore execute in disposable children and
attempt `munlockall` after a successful lock; direct `EPERM`, `ENOMEM`, and
`EAGAIN` remain accepted where capabilities or `RLIMIT_MEMLOCK` prevent the
request. The unsafe legacy remap seam fixes its compatibility protection and
flag words to zero. Its selected one-page anonymous mapping produces direct
`EINVAL` in raw and musl arms, without selecting a file-backed remapping
contract.

This remains private Rust-only evidence. It selects no allocator, heap, or
program-break adjustment policy; no `mremap` or fixed maps; no range locks,
sync, advice, or residency facilities; no file-backed legacy-remap policy; no
C VM header/API/ABI or errno TLS; and no public x86 support.

`pty-basic-reference` is the separate private x86 `terminal.pty-basic`
vertical slice. `pty::{openpt, grantpt, unlockpt}` admit only the owned Linux
PTY allocation steps; `PtyPair::open` validates and unlocks the devpts slave,
then owns both master and slave descriptors. Its peer open always includes
`O_NOCTTY`; controlling-terminal and session transitions remain unselected.
Borrowed master/slave access and `into_parts` retain ordinary descriptor
ownership.

`ptsname_into` derives the ASCII `/dev/pts/<number>` path plus a trailing NUL
from `TIOCGPTN` in caller-owned `MaybeUninit` storage; an insufficient buffer
returns `RANGE` without partial-name success. Allocation-enabled `ptsname`
owns equivalent bytes instead of selecting C's static `ptsname` buffer. The
focused Rust test, no-std `pty_basic_direct_probe`, and paired raw/pinned-musl
C fixture pin `openat=257`, `ioctl=16`, the selected `O_*` words, and
`TIOCGPTN`/`TIOCSPTLCK`/`TIOCGPTPEER`; they exercise pair allocation, byte
transfer, PTY-number/name agreement, and the forced `O_NOCTTY` peer-open
request rather than asserting session state. Raw ioctl/unlock/name paths
return non-PTY `ENOTTY`; pinned musl's C `grantpt` is a no-op success because
devpts grants during allocation, while the private Rust `grantpt` deliberately
validates `TIOCGPTN` and returns `NOTTY`.

`terminal-reference` completes the seven terminal capabilities that build on
this safe pair/name base. `PtyPair::set_controlling_terminal` and
`PtyPair::establish_session_and_controlling_terminal` are the only explicit
unsafe terminal transitions; callers must own the isolated, single-threaded
process/session/terminal authority, and a failed post-`setsid` ioctl leaves
the new session in place. The x86 `termios_x86_64.rs` conversion keeps the
36-byte/align-4 kernel record private rather than casting musl's
60-byte/`NCCS=32` C record. It exposes named typed attribute, queue/flow/break,
exclusive, foreground/session, window-size, isatty, and validated tty-name
operations. Its C oracle runs raw and pinned-musl arms through the same PTY
state, including the Rustix-shaped raw-mode transformation and a distinct B0
input selector, and confines the session transition to a child.

This Rust vertical remains private evidence. It selects no general C
PTY/termios header/API/ABI or errno TLS, generic ioctl, public direct
`ioctl_tiocgptpeer`, `openpty`/`forkpty`/`login_tty`/`vhangup`, generalized
process supervision, or public x86 support. The separate static
`libc-termios-control` artifact forwards the public C record only across its
closed named C boundary; it does not promote the Rust vertical or a general C
terminal capability. The aggregate `facade.record-owning` family is a private
foundation verified by its closed runner, not a general C-terminal or public
x86 support claim.

`system-reference` records the pinned-musl `uname` and `sysinfo` behavior used
by bounded typed system name/status/load observations. It does not select
`crabc-libc` or establish C system-information behavior.

`thread-reference` records pinned-musl `gettid`, `sched_getcpu`, and
`sched_yield` behavior for the bounded typed thread slice. It does not
establish pthread, affinity, or scheduling-policy support.

`thread-credentials-reference` records x86 `setresuid=117` and
`setresgid=119`, their unsigned 32-bit identity words, and musl/raw all-ones
no-change behavior. The typed Rust boundary maps only `None` to that all-ones
word and rejects an explicit typed all-ones ID with `EINVAL`. It intentionally
exposes the direct calling-task kernel operation, not musl's process-wide
synchronized credential transition; it does not establish a general C
credential API or broader process/thread support. The separate static
`libc-credentials` artifact owns only its named C setter surface.

`fs-credentials-reference` records x86 `setfsuid=122` and `setfsgid=123`,
their unsigned 32-bit identity words, all-ones query behavior, and prior-ID
returns. Its short-lived child compares pinned-musl and raw query/current-
effective-ID requests. The typed unsafe `process::{set_fs_uid, set_fs_gid}`
boundary reserves all-ones for `None`, rejects explicit typed all-ones IDs with
`EINVAL`, and does not claim that a requested change can report permission
denial, synchronize credentials process-wide, or establish C credential APIs.

[`parity.toml`](parity.toml) is the closed machine-readable x86 completion
ledger. Its validator and focused tests account for the AArch64-equivalent
capability/gate families separately from these foundation measurements.

After the suite passes, `core` finds the single freshly built `crabc-core`
test executable in its ephemeral native target directory and disassembles it.
The gate rejects any `fxrstor`/`fxrstor64` instruction: fenv mutations may
change only x87 control/status and MXCSR, never restore a saved XMM register
file without a Rust register-clobber contract.

`libc-syscall` compiles only `libc/src/c_abi/x86_64/syscall.rs` with a temporary
native probe. It checks raw `openat`, `setsockopt`, and `mmap` calls so the
fourth through sixth x86 syscall registers are behavior-tested without
selecting `crabc-libc` or a public C ABI.

`libc-errno-tls` compiles only `libc/src/c_abi/x86_64/errno.rs` and links a
native C fixture through the installed project `errno.h`. It proves a local
initial-TLS datum with `R_X86_64_TPOFF*`, no `__tls_get_addr` path, zero
initialization, and independent main/pthread `errno` slots. This standalone
probe remains direct relocation evidence; separately recorded static archive
artifact boundaries select the shared archive, while only their errno-observing
leaves link this owner. It is not a musl differential or a general C ABI
claim.

`libc-allocator-runtime` is a distinct opt-in mixed-runtime artifact, not one
of the dependency-free selected-static leaves. It builds the exact shared
`libc/src/allocator_mimalloc.rs` wrapper and `libmimalloc-sys` 0.1.49 backend
used by the active AArch64 runtime, then extracts only the wrapper object, the
x86 initial-TLS errno owner, and the bundled mimalloc v3.3.2 object. The same
project-header probe first runs against pinned musl and then through that
crabc wrapper. The candidate is statically linked, and its link map must reject
musl's `malloc`, `calloc`, `realloc`, `free`, `aligned_alloc`, and
`posix_memalign`, `memalign`, `reallocarray`, and `valloc` objects, so every
observed allocation call belongs to crabc. The exact ten-export wrapper object
contains its private witness plus all nine `memory.allocator-basic` C symbols;
this mixed-runtime predecessor does not itself select that capability. The
separate real-runtime gate below records the selected-private x86 evidence.
The transaction covers distinct aligned zero-size allocation, natural
alignment through large requests, grow/shrink/failure-preserving reallocation,
zeroed and overflow-checked counted allocation, stale-errno `free`, accepted
non-multiple aligned sizes, invalid-alignment errno, POSIX output preservation,
and reallocation to zero. The extension adds checked `reallocarray` growth and
overflow preservation of its live input, historical zero-alignment `memalign`,
and a 4096-byte-aligned `valloc` result.

Pinned musl still supplies the candidate's static startup, pthread-key,
mapping, time, environment, and diagnostic primitives because their x86 crabc
composition is not owned here. The bundled backend object also retains its
private `mi_*` globals. The artifact therefore proves real x86 libc allocator
wrapper integration but not a standalone runtime, dynamic interposition,
general thread/fork/exit lifecycle, an owned CRT/sysroot, the separately paused
fixed mimalloc v3.5.0 Rust port, allocator-family closure, promotion, or public
x86 support.

`libc-allocator-basic-runtime-v1` is the private capability-selection gate for
those same nine APIs. It runs through real crabc `crt1.o`/`crti.o`/`crtn.o`,
static startup, Initial TLS v1, pthread creation/join, public joined-worker-only
`fork` with ordered `pthread_atfork` hooks, wait, and ordinary `atexit`/`exit`.
The common pinned-musl/project-header fixture retains the zero-product `calloc`
regression, error/output-preservation and alignment rules, post-join allocation
ownership, parent/child liveness, and an allocation from the exit callback. The
already selected `malloc_usable_size` owner observes only live allocations and
remains a distinct capability. The candidate permits the exact eleven-member
backend-support tail, rejects musl allocator/observer/runtime owners and glibc,
and proves crabc ownership of `fputs`, `sleep`, and `__stack_chk_fail`. It does
not prove deterministic backend failure, arbitrary live-thread fork recovery,
interposition, a dynamic allocator/runtime, product closure, promotion, or
public x86 support.

`libc-allocator-string-duplication` is the separately opt-in mixed-runtime
allocation-client artifact over that exact wrapper, not a new allocator
surface. Its one crate-owned object exports only strong `strdup`/`strndup` and
a private witness, then calls the prior weak `malloc` ABI; it is paired with
the wrapper, errno owner, and unchanged bundled mimalloc v3.3.2 object. The
link map rejects musl's two duplication and all nine allocator implementation
objects. The project-header musl/crabc executions prove high-byte returned
copy ownership, bounded and zero-limit `strndup`, stale errno across `free`,
and full/bounded protected-page source edges. Pinned musl still supplies the
candidate's static startup and process prerequisites. This artifact does not
itself select `memory.allocator-basic` or `text.byte-strings-stateful`, nor
allocator lifecycle or interposition/failure injection, general C string/locale
behavior, an owned CRT/sysroot, promotion, or public x86 support.

`libc-allocator-observability` completes the distinct one-symbol AArch64
`memory.allocator-observability` contract without widening the earlier weak
allocator-wrapper object. The shared
`libc/src/allocator_observability_mimalloc.rs` owner exports strong
`malloc_usable_size`: null yields zero and every live pointer is observed by a
direct `mi_usable_size` call over the unchanged active backend. The project
`malloc.h` gate admits exactly that observer and rejects unselected
`mallinfo`, `mallinfo2`, `malloc_info`, `malloc_stats`, and `mallopt` surfaces.

The pinned-musl reference, active AArch64 crabc test, and x86 candidate share
one C fixture covering zero-size, small/large, calloc, aligned, reallocated,
two post-join remote-thread, and contained inherited-child pointers. Repeated
observations must be stable and successful observation preserves stale errno.
The candidate links real crabc `crt1.o`/`crti.o`/`crtn.o`; crabc owns static
startup and Initial TLS v1, errno, allocation, pthread create/join/TSD/mutex,
mapping, clock, `waitpid`, and child `_exit`; its current static-startup path
also publishes the already-selected bounded environment, program-name, and
auxiliary-vector leaves. The fixture's raw single-threaded x86 fork is
containment plumbing only, not a selected public fork/atfork API.

The unchanged bundled mimalloc v3.3.2 object now requires exactly these
eleven pinned-musl support members: `__lock.lo`, `abort.lo`, `abort_lock.lo`,
`block.lo`, `libc.lo`, `prctl.lo`, `realpath.lo`, `strchrnul.lo`, `strdup.lo`,
`syscall.lo`, and `syscall_ret.lo`. The final link-map ratchet separately
requires crabc ownership of `fputs`, `sleep`, and `__stack_chk_fail`. Current
crabc startup supplies `__environ`/`getenv`; the candidate-local clone of pinned `libc.lo` weakens only its duplicate
`__progname`/`__progname_full` definitions while preserving its required
`__libc`/`__hwcap` data. The final link-map ratchet rejects every musl
allocator/observer, startup/TLS, pthread, mapping, clock, and wait owner,
along with glibc, dynamic TLS, an interpreter, dynamic dependencies, and
unresolved symbols. This selects only `memory.allocator-observability` within
this observer gate; the separate real-runtime allocator-basic slice owns its
nine APIs. General fork/atfork, full libc/pthread/runtime closure, the fixed
mimalloc v3.5.0 Rust port, promotion, and public x86 support remain unselected.

`crypt-header-abi` and `libc-crypt` together complete one private opt-in
`crypto.crypt`/`crypto.crypt-helpers` slice. The C/C++ header gate fixes the
260-byte `struct crypt_data` layout, unmangled `crypt`/`crypt_r` declarations,
and strict/POSIX hiding versus X/Open/GNU/BSD `<unistd.h>` visibility. The
static candidate exercises the actual strong `crypt`, weak `crypt_r`, and all
five private `__crypt_*` spellings. It delegates only canonical bounded `$5$`
and `$6$` SHA-crypt work to the already approved RustCrypto `sha-crypt` and
`base64ct` dependencies; no digest, rounds, transposition, or MCF serializer
is implemented locally. The candidate admits pinned-musl
`malloc`/`aligned_alloc`/`free` solely for dependency-owned temporary storage,
and explicitly rejects composition with `x86-allocator-runtime` until that
provider boundary is evidenced. Legacy DES/BSDI/MD5/bcrypt crypt semantics,
default static exports, allocator lifecycle, libc.so, CRT, loader, sysroot,
family promotion, and public x86 support remain unselected. The separate
selected-private `legacy.misc` slice supplies opt-in, inert link-compatible
`encrypt`/`setkey` names only: no DES, cipher, PRNG, crypto service,
default-export widening, or promotion follows from that ABI boundary.

`libc-alloca` is deliberately not another allocator wrapper or lifecycle
claim. It byte-matches project `alloca.h` to pinned musl 1.2.6, including the
`#define alloca __builtin_alloca` macro and `bits/alltypes.h` size_t request,
then verifies C/C++ macro use has no callable alloca reference. One
positive-size dynamic/nested-frame C fixture executes through pinned musl and
an archive-free `-nostdlib -static` candidate containing only the fixture and
an exit syscall shim. The candidate proves compiler-emitted aligned stack
storage and rejects callable alloca, allocator/runtime symbols, PT_TLS,
interpreter/DT_NEEDED, PLT, unresolved, dynamic-TLS, and backend paths. It
selects neither `memory.allocator-basic` nor
`memory.allocator-observability`; alloca zero-size, stack exhaustion/guards,
VLA/unwind/escaping-pointer behavior, heap allocation/lifecycle/interposition,
CRT/sysroot, promotion, and public x86 support remain excluded.

`libc-stack-chk-fail` is a separate private selected-static compiler-support
artifact, not a stack-protector runtime. It maps only musl 1.2.6
`src/env/__stack_chk_fail.c::__stack_chk_fail` and its x86 `a_crash()` `hlt`
body, retaining the strong default-visible primary plus the hidden weak
same-address `__stack_chk_fail_local` alias. Pinned musl's primary entry and
two true `-nostdlib -static` candidates (one for each spelling) terminate with
status 139 (`128 + SIGSEGV`); the archive and final-ELF checks reject guard
storage, `__init_ssp`, ambient failure handlers, TLS, dynamic linkage, loader,
pthread, lifecycle, public C declarations, promotion, and public x86 support.

`libc-stat-compat` and `libc-credentials` are two private static
`crabc-libc` semantic-vertical gates over one dependency-free `libc.a`. The
stat fixture resolves only `stat`, `lstat`, `fstat`, `fstatat`, their
historical aliases, and `__errno_location`, then proves the LP64 `struct stat`
record, regular-file/symlink and relative/`AT_FDCWD` behavior, aliases, and
`ENOENT`/`EBADF`/`EINVAL` translation against pinned musl. The separate
credential fixture resolves only `setgroups`, `setuid`, `setgid`,
`setresuid`, `setresgid`, and the four explicitly profile-limited aliases. It
proves direct all-ones no-change and rejected-input `EINVAL` behavior, while
expecting the candidate aliases to return `-1`/`EOPNOTSUPP` without mutation
where musl succeeds through its process-wide credential rendezvous.

The other static archive artifacts are non-capability boundaries; they remain
distinct from the `filesystem.stat-compat` and `process.credentials` semantic
leaves.

`libc-bootstrap-primitives` is a separately recorded static
`verified_artifact` gate over the same archive, not a semantic-capability
vertical. Its project-header C body first executes against pinned musl and
then in a `-nostdlib -static` candidate. It selects only the fixed
musl-derived `memcpy`/`memmove`/`memset`/`memcmp`/`bcmp`, x87/MXCSR fenv, and
normal/signal-mask continuation surfaces; the fixture-local initial-TLS
setup exists only because the body observes `errno`. It proves guard-page
edges for copy, move, fill, and comparison; zero-length comparison; fenv state
transitions; and normal plus signal-mask non-local continuation. Each static
candidate also closes the crate-owned `c.*.rcgu.o` C-export surface separately
from compiler-builtins archive members and rejects every dynamic TLS model in
the fully linked artifact.

`libc-signal-control` is a separately recorded static
`verified_artifact` gate over that archive, not a `process.signal` capability
vertical. Its project-header C body first executes through pinned musl and
then through a `-nostdlib -static` candidate. It selects only `sigaction`,
`signal`, `sigemptyset`/`sigfillset`/`sigaddset`/`sigdelset`/`sigismember`,
the calling-thread `sigprocmask`/`sigpending` boundary, and `SIGRTMAX`. It
proves the 128-byte public `sigset_t`, 152-byte public `struct sigaction`,
the kernel's distinct one-word signal mask, reserved 32–34 behavior, musl's
partial old-action/mask/pending output writes, `sigpending(NULL)`'s `EFAULT`,
block/pending/unblock state, and successful handler return. The archive gate
also ties `sigaction_impl`'s relocation to the exact hidden syscall-15
restorer. The fixture's raw `tgkill(getpid,gettid,SIGUSR*)` is private delivery
evidence only: it selects no C `kill`, `raise`, or `tgkill` wrapper. It also excludes waits and
cancellation points, queues, alternate stacks, pthread signal policy, legacy
helpers, generic signal management, and public x86 support.

`libc-signal-execution` is a separately recorded
`static-c-process-signal-execution` `verified_artifact` within planned
`libc.posix-runtime`, not a `process.signal` capability or C-runtime
completion. Its project-header C body runs first through pinned musl and then
through a `-nostdlib -static` candidate. It composes the existing simple
action/set/mask/sigsuspend boundary with exactly `kill`, `killpg`, `raise`,
`sigqueue`, `sigtimedwait`, `sigwaitinfo`, and `sigwait`. The gate checks
musl's one-word application-signal block/restore transaction, queued
128-byte align-8 `siginfo_t` sender/value layout, stale `errno`, EINTR retry,
and the musl `sigwait` `-1`/`errno` failure convention. A raw clone/pipe/wait/
exit child is fixture-only deterministic containment for the interrupted wait;
the archive exposes no lifecycle API. The runner ratchets exact archive
exports and rejects dynamic TLS, C++ runtime, allocator, pthread/clone,
auxv/sysconf, and unselected signal paths. It does not select `tgkill`,
alternate stacks outside their separate artifact, signalfd, legacy signal APIs,
pthread signal/cancellation policy, generic process lifecycle, libc.so, CRT,
loader, sysroot, signal/header family completion, or public x86 support.

`libc-signal-altstack` is a separate static `verified_artifact` within planned
`libc.posix-runtime`. Its project-header C body runs through pinned musl and a
true `-nostdlib -static` candidate. It selects `sigaltstack`'s 24-byte x86
`stack_t` query/install/disable, stale-`errno`, null query, fixed-minimum
prechecks, and a single `SA_ONSTACK` handler entry/return through the existing
hidden restorer. It preserves musl's too-small-before-`SS_ONSTACK` ordering but
intentionally keeps the existing fixed x86 `MINSIGSTKSZ=2048` preflight rather
than musl's startup-auxv dynamic minimum. It does not select alternate-stack
allocation/ownership, generic delivery, waits/queues/signalfd, pthread signal
policy/cancellation, libc.so, CRT, loader, sysroot, family completion, or
public x86 support.

`libc-timerfd` is a separate `static-c-timerfd` `verified_artifact` within
planned `libc.posix-runtime`. Its project-header C body runs first through
pinned musl 1.2.6 and then through a true `-nostdlib -static` candidate. It
selects exactly `timerfd_create`, `timerfd_settime`, and `timerfd_gettime`,
with direct Linux `283`/`286`/`287` paths and a 32-byte align-8 `itimerspec`.
It proves creation flags, direct invalid/null/closed-descriptor errors,
stale-errno success, one-shot eight-byte expiration reads, periodic query and
disarm, plus realtime `TFD_TIMER_ABSTIME`/`TFD_TIMER_CANCEL_ON_SET` acceptance.
The runner rejects POSIX process-timer, signal, callback/registry, generic
event-loop, pthread, allocator, and dynamic-runtime paths. This is not C
time/signal/event family completion, AArch64 parity, promotion, or public x86
support.

`libc-signalfd` is a separate `static-c-signalfd` `verified_artifact` within
planned `libc.posix-runtime`. Its project-header C body runs first through
pinned musl 1.2.6 and then through a true `-nostdlib -static` candidate. It
selects exactly `signalfd`, maps directly to Linux `signalfd4=289`, supplies
the fixed eight-byte kernel signal-set size, and leaves the public 128-byte
`sigset_t` pointer borrowed. It proves invalid creation flags and null-mask
`EFAULT`, nonblocking/close-on-exec creation, stale errno, empty-read `EAGAIN`,
queued `SIGUSR1`/`SIGUSR2` records, and Linux's ignored flags on descriptor
update. The runner rejects timer/readiness, pthread, allocator, and dynamic
runtime paths. This is not signal-mask/disposition policy, generic process
signaling, a generic event loop, C signal/event family completion, AArch64
parity, promotion, or public x86 support.

`libc-sigpause` is a separate `static-c-sigpause` `verified_artifact` within
planned `libc.posix-runtime`. Its project-header C body runs first through
pinned musl 1.2.6 and then through a true `-nostdlib -static` candidate. It
selects exactly `sigpause`: query the calling mask into a private eight-byte
kernel word, reject invalid/reserved input with `EINVAL`, remove only the
requested valid application signal, and call `rt_sigsuspend=130`. A
runner-owned FIFO queues blocked `SIGUSR1` before the call and proves
`sigpause(0)`, valid `-1`/`EINTR` handler delivery, and entry
`SIGUSR1`/`SIGUSR2` mask restoration. It is not a public signal mask/action
API, generic delivery or process control, queues/signalfd, timers/readiness,
pthread cancellation, signal-family completion, AArch64 parity, promotion, or
public x86 support.

`libc-sigisemptyset` is a separate `static-c-sigisemptyset`
`verified_artifact` within planned `libc.posix-runtime`. Its project-header C
body first runs through pinned musl 1.2.6 and then through a true
`-nostdlib -static` candidate. It selects exactly the GNU
`sigisemptyset` predicate: x86 musl's `_NSIG=65` makes its `SST_SIZE` one, so
the predicate reads only the first eight-byte public `sigset_t` word, returns
one iff that word is zero, ignores the fifteen-word tail, writes no caller
storage, preserves stale `errno`, and makes no syscall. The shared signal-header
gate proves the GNU pointer declaration and strict-POSIX hiding. It does not
itself select the separately bounded `sigandset`/`sigorset` leaf,
handlers/actions, mask or process signaling, waits, queues, descriptors,
timers, pthread policy, signal-family completion, AArch64 parity, promotion,
or public x86 support.

`libc-sigandset-sigorset` is a separate `static-c-sigandset-sigorset`
`verified_artifact` within planned `libc.posix-runtime`. Its project-header C
body first runs through pinned musl 1.2.6 and then through a true
`-nostdlib -static` candidate. It selects exactly the GNU `sigandset` and
`sigorset` helpers: x86 musl's `_NSIG=65` makes both `SST_SIZE` one, so each
reads the left and right first eight-byte public `sigset_t` words before
writing only the destination first word with AND or OR, returns zero, preserves
stale `errno`, and leaves every tail word untouched. The common C signal-header
gate and a paired C++17 probe prove GNU-only signatures, strict-POSIX hiding,
and unmangled C linkage. Ordinary results, both destination alias directions,
and tail sentinels run through pinned musl and the freestanding candidate. It
does not select `sigisemptyset`, handlers/actions, mask or process signaling,
waits, queues, descriptors, timers, pthread policy, signal-family completion,
AArch64 parity, promotion, or public x86 support.

`libc-sigpending` is a separate `static-c-sigpending` `verified_artifact`
within planned `libc.posix-runtime`. Its project-header C body runs first
through pinned musl 1.2.6 and then through a true `-nostdlib -static`
candidate. It selects exactly the POSIX `sigpending` observation: Linux
`rt_sigpending=127` receives the caller pointer and one eight-byte kernel
signal-set size, writes only the first public word, and leaves the fifteen-word
tail caller-resident. Fixture-only raw block/`tgkill` setup queues one `SIGUSR1`
to prove the returned bit; the body also proves tail sentinels, stale `errno`,
and null/non-null `EFAULT`. The shared C signal gate and paired C++17 proof
keep the POSIX declaration and unmangled linkage. It does not select
handlers/actions, signal masks, process signaling, waits, queues, descriptors,
timers, pthread policy, signal-family completion, AArch64 parity, promotion,
or public x86 support.

`libc-sigrtmax` is a separate `static-c-sigrtmax` `verified_artifact` within
planned `libc.posix-runtime`. Its one-symbol C body first runs through pinned
musl 1.2.6 and then through a true `-nostdlib -static` candidate. It maps only
musl's `src/signal/sigrtmax.c`: x86 `_NSIG=65` makes
`__libc_current_sigrtmax()` and the public `SIGRTMAX` macro return 64. The
fixture proves direct/macro results, a repeated equality, stale `errno`, and
no call or syscall; the common C signal-header gate and a C++17 POSIX/GNU
matrix retain the POSIX-family C signature and unmangled
references. It leaves the separately selected realtime-minimum bridge out of
its candidate and does not select delivery, actions, masks, process signaling,
waits, queues, descriptors, timers, pthread policy, signal-family completion,
AArch64 parity, promotion, or public x86 support.

`libc-sigrtmin` is a separate `static-c-sigrtmin` `verified_artifact` within
planned `libc.posix-runtime`. Its one-symbol C body first runs through pinned
musl 1.2.6 and then through a true `-nostdlib -static` candidate. It maps only
musl's `src/signal/sigrtmin.c`: direct `__libc_current_sigrtmin()` returns 35.
The fixture proves direct/public-`SIGRTMIN` value results, a repeated equality,
stale `errno`, and no call or syscall; the common C signal-header gate and a
C++17 POSIX/GNU matrix retain the POSIX-family C signature and unmangled direct
references. The project header's existing fixed `SIGRTMIN` spelling remains a
bounded value check, not a general header rewrite. It leaves the separately
selected realtime-maximum bridge out of its candidate and does not select
delivery, actions, masks, process signaling, waits, queues, descriptors,
timers, pthread policy, signal-family completion, AArch64 parity, promotion,
or public x86 support.

`libc-process-signal` is the closed aggregate for the selected-private frozen
`process.signal` slice within still-planned `libc.posix-runtime`. Its exact
34-name roster is `__libc_current_sigrtmax`, `__libc_current_sigrtmin`,
`__sysv_signal`, `bsd_signal`, `kill`, `killpg`, `psiginfo`, `psignal`,
`raise`, `sigaction`, `sigaddset`, `sigaltstack`, `sigandset`, `sigdelset`,
`sigemptyset`, `sigfillset`, `sighold`, `sigignore`, `siginterrupt`,
`sigisemptyset`, `sigismember`, `sigorset`, `sigpause`, `sigpending`,
`sigprocmask`, `sigqueue`, `sigrelse`, `sigset`, `signal`, `signalfd`,
`sigsuspend`, `sigtimedwait`, `sigwait`, and `sigwaitinfo`. The aggregate
reruns the 16 direct component gates before checking the composed archive:
the default selected-static surface stays frozen, and only the opt-in
`x86-signal-legacy-aliases`, `x86-signal-sysv-helpers`, and
`x86-signal-reporting` feature closure adds exactly `__sysv_signal`,
`bsd_signal`, `psiginfo`, `psignal`, `sighold`, `sigignore`, `sigrelse`, and
`sigset`.

`psignal-header-abi` and `libc-psignal` provide the reporting pair's C/C++
profile and pinned-musl/static evidence: strict headers hide both names while
POSIX, X/Open, GNU, and BSD profiles expose them; `psiginfo` forwards only
`si_signo`; and complete `stderr` output preserves incoming errno. Callers
must externally serialize all selected `stderr` use. The bounded permanent
stream has no general FILE lock, locale/orientation state, partial-short-write
equivalence, or async-signal-safety claim. This aggregate does not complete
signal management, process lifecycle, pthread/cancellation policy, libc.so,
CRT, loader, sysroot, its family, promotion, or public x86 support.

`libc-sched-getscheduler` is a separate `static-c-sched-getscheduler`
`verified_artifact` within planned `libc.posix-runtime`. Its one-symbol C body
first runs through pinned musl 1.2.6 and then through a true
`-nostdlib -static` candidate. It maps only musl's `src/sched/sched_getscheduler.c`,
which deliberately returns `-1` with `ENOSYS` for every
`sched_getscheduler(pid_t)` input rather than exposing Linux's thread-scoped
raw x86 syscall 145 under the POSIX process-facing name. The common C body
proves raw current-task success and raw invalid `-EINVAL`, then proves the C
ABI ENOSYS result for current, invalid, and missing pid-shaped inputs. The
strict/POSIX/X/Open/GNU C/C++ matrix retains the exact unmangled declaration.
It does not select scheduler mutation or parameters, priority bounds,
`sched_yield`, affinity, pthread scheduling attributes, lifecycle,
scheduler-family completion, AArch64 parity, promotion, or public x86 support.
`libc-alarm` is a separate `static-c-alarm` `verified_artifact` within planned
`libc.posix-runtime`. Its one-symbol project-header C body first runs through
pinned musl 1.2.6 and then through a true `-nostdlib -static` candidate. It
maps only musl's `src/unistd/alarm.c` and the x86 LP64 direct branch in
`src/signal/setitimer.c`: with eight-byte `time_t` and `long`, `alarm` replaces
`ITIMER_REAL` with a zero-interval whole-second record, discards the raw
`setitimer=38` C return after its ordinary errno side effect, and returns the
old `tv_sec + !!tv_usec`. Its
fixture-private raw syscall seeds and inspects a far-future record to prove
the `604800.999999` to `604801` ceiling, one-shot replacement, disarm return,
and stale `errno`; the existing project-first/pinned-musl C11/C++17 unistd
matrix proves unconditional `unsigned int alarm(unsigned int)` and unmangled
C++ linkage. It exposes neither public `setitimer` nor `ualarm` and does not
select handlers/actions, signal masks, waits, delivery policy, POSIX timers,
timer descriptors, pthread policy, signal/timer-family completion, AArch64
parity, promotion, or public x86 support.

`ualarm-header-abi` and `libc-ualarm` are a separate private opt-in
`x86-ualarm` `static-c-ualarm` `verified_artifact` within planned
`libc.posix-runtime`. The former proves the exact
`unsigned int ualarm(unsigned int, unsigned int)` GNU/BSD/XOPEN<700 C/C++
declaration partition; the latter runs one project-header C body through
pinned musl 1.2.6 and then through a true `-nostdlib -static` archive built
with `--features x86-ualarm`. It maps only musl's `src/unistd/ualarm.c` and
the x86 LP64 direct branch of `src/signal/setitimer.c`: zero-second
`ITIMER_REAL` fields carry the requested microseconds, valid calls return the
old remaining interval with C unsigned wrapping, and the
one-million-microsecond field is `EINVAL` without changing the prior timer.
The Rust leaf's zero-initialized old record deliberately returns `UINT_MAX` on
that error rather than using musl's indeterminate failure return. Only the
feature archive adds `ualarm`; the unfeatured static archive and
`static_c_abi_exports.txt` remain unchanged. This artifact carries no
capability or family promotion and does not select timer/signal policy,
`alarm`/`getitimer`/`setitimer`, libc.so, CRT, loader, sysroot, or public x86
support.

`libc-usleep` is a separate `static-c-usleep` `verified_artifact` within
planned `libc.posix-runtime`. Its one-symbol project-header C body first runs
through pinned musl 1.2.6 and then through a true `-nostdlib -static`
candidate. It maps only `src/unistd/usleep.c`: unsigned microseconds become a
local LP64 `timespec` through quotient/remainder normalization and then pass to
the separately selected `nanosleep(&tv, &tv)` seam. The C/C++ feature matrix
proves GNU/BSD/XOPEN<700 declaration visibility, and the shared fixture proves
zero/short stale-errno completion plus fixture-only raw-SIGALRM `EINTR` across
1000000, 1000001, and `UINT_MAX`. It does not select `sleep`, `alarm`,
`ualarm`, timer control, handlers/actions, masks, process signaling, waits,
queues, descriptors, pthread policy, family completion, promotion, or public
x86 support.

`libc-sigaddset-sigdelset-sigfillset` is a separate
`static-c-sigset-mutation` `verified_artifact` within planned
`libc.posix-runtime`. Its project-header C body runs first through pinned musl
1.2.6 and then through a true `-nostdlib -static` candidate. It selects exactly
the POSIX `sigaddset`, `sigdelset`, and `sigfillset` helpers: x86 musl's
`_NSIG=65` makes `SST_SIZE=1`, so fill stores
`0xfffffffc7fffffff` and add/delete modify only the first eight-byte public
`sigset_t` word. The fixture proves low/realtime mutation, two untouched tail
sentinels, stale `errno`, and `-1`/`EINVAL` before dereference for 0,
reserved 32--34, and 65. The common C GNU/POSIX signal-header gate and a
paired C++17 POSIX/GNU feature matrix retain the exact signatures and
unmangled linkage. It does not select handlers/actions, masks or process
signaling, waits, queues, descriptors, timers, pthread policy, signal-family
completion, AArch64 parity, promotion, or public x86 support.

`libc-static-tls-v1` is a separately recorded private static
`verified_artifact` inside still-planned `libc.pthread-tls`. Its freestanding
candidate start shim passes the untouched Linux entry stack to the hidden
libc `__crabc_x86_static_tls_bootstrap` hook before selected C code can access
TLS. The hook validates the final executable's `AT_PHDR` program-header view
through `PT_PHDR` when present or a strict static `ET_EXEC` no-`PT_PHDR`
ELF-header fallback, then validates the optional single `PT_TLS` image,
materializes its main-thread x86 Variant-II image, and retains the immutable
template for the selected worker seam. The
fixture links initialized, TBSS, and 4096-byte-aligned TLS definitions from
two C translation units plus libc `errno`; after it mutates the main image,
two sequential workers prove that each receives the original linked state.
The gate requires direct TPOFF forms, one real initialized/TBSS `PT_TLS`, raw
`arch_prctl(ARCH_SET_FS)` and mapping paths, and no dynamic TLS resolver or
ambient runtime. It separately corrupts the fallback ELF version and `PT_TLS`
`p_filesz`, requiring the entry shim's bootstrap-failure status 127 for each
malformed image. It does not select DTV/module state, a loader handoff, dynamic
TLS, a general pthread runtime, CRT/sysroot integration, or public x86
support. This isolated archive fixture is distinct from the composed
`libc-crt-static-tls` startup proof below.

`libc-crt-static-tls` is a separately recorded private static
`verified_artifact` under the same still-planned `libc.pthread-tls` family. It
links the real Rust `rcrt1.o`/`crti.o`/`crtn.o` objects with the selected libc
archive-owned bounded `__libc_start_main`. The no-archive link must fail at
both the hidden, non-preemptible `__crabc_x86_static_tls_bootstrap` and startup
boundaries. The candidate has one real initialized/TBSS/4096-byte-aligned
`PT_TLS` image from two C translation units; after checked relocation and
RELRO the real CRT invokes libc before preinit, init, main, 32 fixed
no-allocation C `atexit`/`__cxa_atexit` registrations in LIFO order, and
fini. Its no-op `__cxa_finalize` retains ordinary handlers for that exit walk.
One selected normal pthread worker sees fresh initial TLS and errno. The gate
rejects an interpreter, `DT_NEEDED`, PLT, unresolved symbols, and dynamic TLS
forms, then corrupts final `PT_TLS.p_filesz` and requires status 127. Pinned
musl is the selected C TLS/pthread/ordinary-exit oracle; because its ordinary
startup does not dispatch the fixture's preinit array, the reference fixture
explicitly adapts that lifecycle. This does not select a general CRT/startup
or libc entry ABI, stdio/C++/DSO or concurrent-exit lifecycle, pthread/TLS
parity, loader TLS, sysroot, or public x86 support.

The same static-startup archive owner retains pinned musl 1.2.6
`src/env/__libc_start_main.c`'s private `weak_alias(dummy1, __init_ssp)`
fallback. The AArch64 static manifest records weak `__init_ssp` in
`__libc_start_main.lo`; the staged archive and ordinary static-PIE candidate
retain that default-visible weak binding, and a caller-owned strong private
definition wins after real CRT startup extracts the owner. This is only a
static archive-binding boundary: the fallback ignores its entropy pointer and
the selected startup never invokes it, so it does not initialize a canary,
consume `AT_RANDOM`, select stack-protector startup, loader state, or a
general process startup policy.

The same static-startup/ordinary-exit owner also retains pinned musl 1.2.6
`src/exit/exit.c`'s private `weak_alias(dummy, __stdio_exit)` fallback. The
AArch64 static manifest records it as weak in `exit.lo` and the separate strong
stream-finalization body in `__stdio_exit.lo`; the staged archive and
static-PIE candidate retain the weak binding, while a caller-owned private
strong spelling wins after real CRT startup extracts the owner. That override
traps on any later dispatch while the full PIMBCAF lifecycle completes, proving
selected ordinary exit never invokes it. This is archive-binding evidence only:
no stream flush, `FILE` inspection, stdio lock/finalization, allocator, loader,
or general process-exit policy is selected.

`libc-crt1-static-tls` is the parallel private static `verified_artifact`
under the same still-planned `libc.pthread-tls` family. It links real Rust
`crt1.o`/`crti.o`/`crtn.o` through an ordinary final static `ET_EXEC` link,
instead of rcrt1's self-relocating static-PIE route. The direct entry calls
the shared TLS-first startup, so hidden
`__crabc_x86_static_tls_bootstrap(original_entry_stack)` succeeds before the
archive-owned bounded `__libc_start_main` lifecycle. The runner proves an
archive-free link fails at both boundaries; one real initialized/TBSS/4096-byte
aligned `PT_TLS` image through preinit, init, main, fixed 32-registration
no-allocation LIFO `atexit`/`__cxa_atexit` exit, and fini; no-op
`__cxa_finalize`; one fresh selected worker; and malformed
`PT_TLS.p_filesz` status-127 rejection. It is not general CRT/startup or libc
entry ABI, pthread/TLS parity, dynamic or loader TLS, a dynamic loader,
sysroot, or public x86 support.

`owned-static-sysroot` is the first private installed-artifact composition
inside both still-planned `sysroot.static-tls` and
`sysroot.owned-artifact`. `scripts/build_x86_64_owned_sysroot.py` atomically
installs the regular-file project header tree, all five Rust-produced CRT
objects, a deterministic `libc.a` rebuilt from only `c.*.rcgu.o` members, and
the bounded Rust-only `libcrabc-builtins.a`. Two clean builds must be
byte-identical, including normalized producer and exclusion records. The
consumer compiles with `-nostdinc`, audits every dependency path, then links
through the sealed `bin/crabc-cc` driver from an exact installed/object
allowlist. Its `-static`/`-static-pie` plans select `crt1.o`/`ET_EXEC` and
`rcrt1.o`/`ET_DYN`, respectively; receipt-bearing links admit caller-owned
objects only and publish disjoint JSON/map/trace records. It executes the
existing `PIMBCAF` initialized/TBSS/4096-byte-aligned Static Initial TLS v1,
pthread, and ordinary-exit lifecycle while forcing `__udivti3` from the
installed helper archive; removing that archive must fail at the helper.
Forged dependency and linker traces separately reject ambient headers, CRT,
musl libc, libgcc/compiler runtime, and loader paths. Both final images have
one `PT_TLS`, GNU RELRO, a non-executable stack, no interpreter or dynamic
dependency, no unresolved symbol, and retain malformed-`PT_TLS.p_filesz`
status-127 rejection. Two normalized private packages are byte-identical, and
one safely extracted manifest-bound regular-file payload repeats both smokes. The installed
tree deliberately omits shared libc, loader, dynamic link modes, and complete
libc/helper closure. This remains a bounded static-product seed, not full
static coverage or either family’s completion; both families therefore remain
planned and x86-64 remains non-public. The exact boundary is documented in
[`owned-static-sysroot.md`](owned-static-sysroot.md).

`libc-pthread-create-join-tls` is a separately recorded static
`verified_artifact` under the same still-planned `libc.pthread-tls` family. Its
project-header C body first runs against pinned musl and then in a
`-nostdlib -static` candidate. It selects a null-attribute `pthread_create`
with one `pthread_join` for either a normal return or the selected-worker
`pthread_exit` path: each concurrently live worker receives a distinct full
Static Initial TLS v1 final-image copy, so its errno and fixture TLS state are
fresh while the creator's live TLS remains unchanged. A pointer result crosses
the join boundary. The gate proves the hidden musl-shaped clone=56 register
shuffle, selected exit=60 path, the clear-child-tid shared futex=202 wait, and
post-exit TLS plus control/stack munmap=11 reclamation. A fixed private
64-worker registry validates the explicit-exit caller's `%fs:0`, kernel
`gettid`, and still-live clear-child-tid word, serializes publication with join
withdrawal, and is exhausted/reused by a candidate-only capacity route. It does
not select attributes or detached-at-create behavior, pthread-exit
cleanup/TSD/main-thread behavior, any self/equal behavior beyond the separately
recorded identity artifact,
cancellation, synchronization objects, dynamic TLS/DTV, loader or CRT TLS,
broader C11 threads, or public x86 support.

The same `pthread_create` archive owner also retains musl 1.2.6
`src/thread/pthread_create.c`'s private `weak_alias(dummy_0,
__membarrier_init)` fallback. The pinned AArch64 static manifest records that
binding as weak in `pthread_create.lo` and records the optional strong body in
`membarrier.lo`; the staged archive and normal candidate retain the weak
definition, while a caller-owned private strong spelling wins after
`pthread_create` extracts its owner. This is archive-binding evidence only:
selected worker creation never calls it, so no `membarrier`
syscall/registration, public API, dynamic TLS, loader state, or process-startup
policy is selected.

`libc-pthread-identity` is a separately recorded private static
`verified_artifact` under the same still-planned `libc.pthread-tls` family. Its
project-header C body first runs against pinned musl and then through a
`-nostdlib -static` candidate. It selects only opaque x86 Variant-II `%fs:0`
identity: weak same-address `pthread_self`/`thrd_current` and
`pthread_equal`/`thrd_equal` pairs, with macro and un-macroed function equality
returning exactly one for equal identities and zero for distinct identities.
The main thread, two concurrently live normal workers, and one selected
explicit-exit worker prove that `pthread_create` returns the child's TP and
that one join resolves it through the private registry before mapping
reclamation. It does not select a dereferenceable TCB, broader C11
lifecycle/locks or TSD, detachment beyond the separately recorded artifact,
cancellation, dynamic or loader TLS, CRT, sysroot, general pthread behavior,
or public x86 support.

`libc-c11-lifecycle` is a separately recorded private static
`verified_artifact` under the same still-planned `libc.pthread-tls` family. Its
project-header C body first runs against pinned musl and then through a
`-nostdlib -static` candidate. It selects only typed
`thrd_create`/`thrd_join`/`thrd_exit`: the `int (*)(void *)` callback stays in
its dedicated C11 worker arm instead of being cast to a pointer-returning
pthread routine, each child handle is its opaque `%fs:0` TP, and normal plus
explicit results retain every signed `int`, including `INT_MIN` and `INT_MAX`.
The fixture checks identity before a successful join releases the worker's TLS
and control mappings, then proves independent child errno, a null result slot,
two simultaneously live workers, and 64-slot exhaustion/reuse. Pinned musl
covers only standard normal and `thrd_exit` paths. Candidate-only null-start
and unsupported C11-to-`pthread_exit` / pthread-to-`thrd_exit` routes fail
closed after safe reclamation without exposing an incompatible result. It does
not select detachment or sleep beyond the separately recorded artifacts,
`thrd_yield`, once, mutexes/conditions, TSS, cancellation, dynamic/loader TLS, broader
pthread/C11 behavior, CRT, sysroot, or public x86 support.

`libc-pthread-detach` is a seventh separately recorded private static
`verified_artifact` under the same still-planned `libc.pthread-tls` family. Its
project-header C body first runs ordinary external pthread/C11 detach routes
against pinned musl and then through a `-nostdlib -static` candidate. It
selects only prompt state-only `pthread_detach`/`thrd_detach` ownership of the
already selected workers: a successful detach neither waits nor releases an
active stack/TLS mapping. A later selected create/join boundary may reclaim a
detached worker only after `CLONE_CHILD_CLEARTID` clears the child TID, then
withdraws its private registry entry. The comparable routes run before and
after the fixture's callback-completion signal, not after kernel exit.
Self-detach, null/repeated/racing ownership attempts, join-after-detach, and
64-slot delayed reuse are candidate-only diagnostics rather than musl parity
or portable post-detach-handle behavior. This does not select detached-at-create
attributes, general pthread/C11 or detached-thread behavior, cancellation,
TSS, synchronization, dynamic/loader TLS, CRT, sysroot, or public x86 support.

`libc-thrd-sleep` is a ninth separately recorded private static
`verified_artifact` under the same still-planned `libc.pthread-tls` family. Its
project-header C body first runs through pinned musl and then through a
`-nostdlib -static` candidate. It selects only the direct non-cancellation C11
`thrd_sleep` adapter over `clock_nanosleep(CLOCK_REALTIME, 0, ...)`: completion
returns zero, `EINTR` returns `-1`, and invalid-nanosecond or null-duration
failures return `-2`, without changing `errno`. The fixture proves those
routes plus a deterministic SIGALRM interruption with a positive remaining
interval. It does not select `thrd_yield`, cancellation cleanup, C11
lifecycle/synchronization/TSS, dynamic/loader TLS, CRT, sysroot, or public x86
support.

`libc-thrd-yield` is a twentieth separately recorded private static
`verified_artifact` under the same still-planned `libc.pthread-tls` family.
Its project-header C body first runs against pinned musl and then through a
`-nostdlib -static` candidate. It selects only C11 `thrd_yield`'s
no-argument Linux `sched_yield=24` syscall. Normal invocation and a
fixture-local seccomp-forced raw `EPERM` both discard their raw result and
preserve C `errno`, matching musl's void entry; the artifact makes no
scheduler handoff, fairness, or peer-progress guarantee. It excludes the
separately recorded POSIX `sched_yield` status-returning C API, scheduler
policy/parameters, affinity and pthread scheduling attributes, C11
lifecycle/synchronization/TSS/cancellation,
dynamic/loader TLS, CRT, sysroot, full pthread/C11 or x86-64 parity,
promotion, and public x86 support.

`libc-pthread-cpuclock` is a twenty-first separately recorded private static
`verified_artifact` under the same still-planned `libc.pthread-tls` family.
Its project-header C body first runs against pinned musl and then through a
`-nostdlib -static` candidate. It selects only `pthread_getcpuclockid` for the
bootstrapped process-main task's own `pthread_self()` handle. Rather than
dereference a full musl pthread TCB, the candidate validates its existing
`%fs:0` plus Linux-TID main-task identity, reads direct `gettid=186`, and
reproduces the exact 32-bit Linux per-thread CPU-clock encoding. The fixture
proves that exact ID, acceptance by the separately selected `clock_gettime`,
normalized observation, and preserved errno. Candidate-only null/non-self
calls return `ESRCH` without changing the output sentinel or errno. It excludes
worker, foreign, completed, or general handles; `clock_getcpuclockid` and
general C clocks; scheduler or affinity attributes; lifecycle, cancellation,
synchronization, TSS, a TCB/thread list, dynamic/loader TLS, CRT, sysroot,
full pthread/TLS or x86-64 parity, promotion, and public x86 support.

`libc-pthread-name` is a twenty-second separately recorded private static
`verified_artifact` under the same still-planned `libc.pthread-tls` family.
Its project-header C body first runs against pinned musl and then through a
`-nostdlib -static` candidate. It selects only GNU
`pthread_setname_np`/`pthread_getname_np` for the bootstrapped process-main
task's own `pthread_self()` handle. The candidate validates its `%fs:0`
initial-main identity before observing either buffer, then uses direct
`prctl=157` with `PR_SET_NAME=15` or `PR_GET_NAME=16` for Linux's 16-byte task
comm. The fixture proves self set/get, raw getter observation, ERANGE at the
length boundary, and preserved errno. Candidate-only non-self calls return
`ESRCH` without input/output observation. Worker or foreign naming, a full
pthread TCB/thread list, musl's procfs route, cancellation, a general prctl C
API, scheduler/affinity attributes, lifecycle/synchronization/TSS,
dynamic/loader TLS, CRT, sysroot, full pthread/TLS or x86-64 parity,
promotion, and public x86 support remain excluded.

`libc-pthread-barrierattr-pshared` remains a separately recorded private static
record leaf under the still-planned `libc.pthread-tls` family. Its project-header
C body first runs against pinned musl and then through a `-nostdlib -static`
candidate. It selects only `pthread_barrierattr_setpshared`/
`pthread_barrierattr_getpshared` over the public four-byte word: valid
private/shared values replace that whole word with `0`/`INT_MIN`, invalid
values preserve it, and a nonzero raw word queries as shared. The fixture
deliberately supplies caller-owned raw record storage and does not call a
lifecycle function or the separately selected barrier block. Its record-only
evidence therefore does not establish barrier initialization, waiting,
destruction, or process-shared operation. Threads, TLS, synchronization,
cancellation, CRT, loader, sysroot, family completion, promotion, and public
x86 support remain excluded.

`libc-pthread-barrier` is the adjacent private static barrier artifact under
the same still-planned family. Its pinned-musl/project-header fixture and true
`-nostdlib -static` candidate cover the complete seven-name barrier surface:
attribute lifecycle/pshared records, count validation, two reusable private
selected-worker rounds with one serial result each, and one shared-futex
cross-fork round followed by quiescent destroy. It ports musl's private stack
instance and shared vmlock paths over the exact 32-byte, align-eight public
record. Fixture-local mapping, fork, wait, clock, and exit plumbing does not
select a C process runtime. Arbitrary destroy races, broad pthread
synchronization/lifecycle, cancellation, dynamic/loader TLS, CRT/sysroot
integration, family completion, promotion, x86-64 parity, and public x86
support remain excluded.

`libc-pthread-spin-destroy` is a separately recorded private static
`verified_artifact` under the same still-planned `libc.pthread-tls`
family. Its dedicated C/C++ header matrix verifies the unconditional
four-byte `pthread_spinlock_t` and exact unmangled
`pthread_spin_destroy(pthread_spinlock_t *)` spelling under pinned musl and
project headers. Its shared C fixture then runs against pinned musl and one
extracted crabc object in a `-nostdlib -static` candidate: direct and typed
function-pointer calls return zero and leave a caller-owned sentinel unchanged.
The pinned object is source-closed and has no peer call or state operation;
the sentinel is non-observation evidence, not a valid initialization or
lifecycle claim. `pthread_spin_init`, lock/trylock/unlock, arbitrary spin
state, synchronization, atomics, threads, cancellation, a general pthread
runtime, family completion, promotion, x86-64 parity, and public x86 support
remain excluded.

`libc-pthread-mutex-normal` is a tenth separately recorded private static
`verified_artifact` under the same still-planned `libc.pthread-tls` family.
Its project-header C body first runs against pinned musl and then through a
`-nostdlib -static` candidate. It selects only an all-zero or
`pthread_mutex_init(..., NULL)` process-private `PTHREAD_MUTEX_NORMAL` object
and `pthread_mutex_init`/`destroy`/`lock`/`trylock`/`unlock`. The exact lock
word moves from `0` to `EBUSY` and, under contention, to `EBUSY|INT_MIN`; its
private `FUTEX_WAIT_PRIVATE`/`FUTEX_WAKE_PRIVATE` handoff is exercised across
six bounded two-worker rounds. The fixture proves held-lock `EBUSY`, mutual
exclusion, and caller-`errno` preservation. Non-null attributes or a nonzero
type word return `ENOTSUP` rather than being interpreted as another mutex
type. It does not select mutex attributes, recursive/error-checking/robust/PI/
process-shared/timed mutexes, C11 mutex or condition behavior beyond the
separately selected plain adapter, general condition variables, cancellation,
dynamic/loader TLS, CRT/sysroot integration, general pthread synchronization,
full pthread/TLS or x86-64 parity, or public x86 support.

`libc-pthread-rwlock` is a fifteenth separately recorded private static
`verified_artifact` under that same still-planned `libc.pthread-tls` family.
Its project-header C body first runs against pinned musl and then through a
`-nostdlib -static` candidate. It selects the complete installed
`pthread_rwlock_*` and `pthread_rwlockattr_*` family over the 56-byte,
eight-byte-aligned rwlock and eight-byte, four-byte-aligned attribute records:
init/destroy, reader and writer lock/try/timed-lock, unlock, and attribute
init/destroy/get/set process sharing. The seven lock-operation public names
are weak same-address aliases of hidden `__pthread_rwlock_*` definitions. The
fixture proves static and private or process-shared initialization, concurrent
readers, reader/writer exclusion, expired and future absolute `CLOCK_REALTIME`
timeout status including musl's initial-try ordering, wake-before-deadline handoff,
caller-`errno` preservation, and cross-process shared-futex reader and writer
wakeups. Fixture-local raw time, mapping, fork, wait, and exit plumbing does
not select a C process runtime, CRT, loader, or public x86 support. It does
not select cancellation, priority or fairness guarantees, general pthread
synchronization or runtime ownership, dynamic/loader TLS, CRT/sysroot
integration, full pthread/TLS or x86-64 parity, promotion, or public x86
support.

`libc-pthread-cond-private` is an eleventh separately recorded private static
`verified_artifact` under that same still-planned `libc.pthread-tls` family.
Its project-header C body first runs against pinned musl and then through a
`-nostdlib -static` candidate. It selects only a 48-byte, eight-byte-aligned
all-zero or `pthread_cond_init(..., NULL)` process-private `pthread_cond_t`,
paired only with the selected all-zero or NULL-initialized
`PTHREAD_MUTEX_NORMAL` object. The candidate preserves musl's private stack
waiter/list/barrier/requeue protocol with `FUTEX_WAIT_PRIVATE`,
`FUTEX_WAKE_PRIVATE`, and `FUTEX_REQUEUE_PRIVATE`. The fixture proves static
and NULL initialization, one deterministic signal, a two-waiter broadcast,
four bounded 64-handoff ping-pong rounds, caller-`errno` preservation, and
quiescent destruction. Candidate-only evidence requires every non-NULL
condition attribute to return `ENOTSUP`; it is a fail-closed selected-boundary
diagnostic, not a musl-parity claim. It does not select condition attributes,
process-shared or timed waits, cancellation, C11 condition behavior beyond the
selected plain adapter, general condition behavior, non-selected mutex kinds,
destruction with live waiters,
dynamic/loader TLS, CRT/sysroot integration, general pthread synchronization,
full pthread/TLS or x86-64 parity, promotion, or public x86 support.

`libc-c11-plain-sync` is a twelfth separately recorded private static
`verified_artifact` under that same still-planned `libc.pthread-tls` family.
Its project-header C body first runs against pinned musl and then through a
`-nostdlib -static` candidate. It selects only the installed header's distinct
40-byte, eight-byte-aligned `mtx_t` and 48-byte, eight-byte-aligned `cnd_t`
records: `mtx_plain` initialization, mutex init/destroy/lock/trylock/unlock,
and condition init/destroy/wait/signal/broadcast. The adapter routes directly
through the selected private normal-mutex and condition waiter/barrier/requeue
engines without an interposable pthread C call; a held trylock maps to
`thrd_busy`. Recursive and timed kinds are candidate-only `thrd_error`
rejections before their records are interpreted, not musl-differential
behavior. It does not select timed calls, static C11 initialization,
cancellation, TSS, once, process-shared synchronization, C11-family
completion, full pthread/TLS or x86-64 parity, promotion, or public x86
support.

`libc-pthread-c11-once` is a thirteenth separately recorded private static
`verified_artifact` under that same still-planned `libc.pthread-tls` family.
Its project-header C body first runs against pinned musl and then through a
`-nostdlib -static` candidate. It selects only normal-return `pthread_once`
and C11 `call_once` for the installed four-byte, zero-initialized
`pthread_once_t` and `once_flag` records. The shared private state machine
moves `0 -> 1`; while two selected contenders start, it records contention as
state `3` and uses `FUTEX_WAIT_PRIVATE`; it then release-publishes `2` and
uses `FUTEX_WAKE_PRIVATE` only if waiters were recorded. The fixture proves static
and local zero initialization, exactly one initializer, relaxed-payload
visibility after completion without a separate release/acquire edge, and
caller-`errno` preservation. C11 calls the
private shared machine without an interposable pthread C call. It does not
select cancellation reset, initializer `pthread_exit`/`thrd_exit`, recursive
same-control entry, fork/atfork, TSS, dynamic/loader TLS, musl's weak
`pthread_once` ELF binding, general pthread/C11 synchronization, full
pthread/TLS or x86-64 parity, promotion, or public x86
support.

`libc-pthread-c11-tsd` is a fourteenth separately recorded private static
`verified_artifact` under that same still-planned `libc.pthread-tls` family.
Its project-header C body first runs against pinned musl and then through a
`-nostdlib -static` candidate. It selects only
`pthread_key_create`/`pthread_key_delete`/`pthread_getspecific`/
`pthread_setspecific` and `tss_create`/`tss_delete`/`tss_get`/`tss_set` over
a private 128-key table, a permanent process-main value table, and one table
in each selected worker control. A null destructor reserves a key; deletion
clears only those selected values and calls no old destructor. A normal
pthread/C11 return, `pthread_exit`, or `thrd_exit` clears every non-null value
before callback, drops the metadata lock for that callback, permits a rearm
through at most four ascending-key passes, and finishes before join-result
publication or `SYS_exit`. The fixture proves main/worker isolation,
128-key exhaustion and deleted-slot reuse, clear-before-callback fourth-pass
rearming, all four selected exit routes, and caller-`errno` preservation.
Invalid/deleted keys and non-selected callers deliberately fail closed rather
than using musl's unchecked internal fast paths; selected-main admission
requires the bootstrapped `%fs:0` plus Linux TID pair, so an inherited FS base
alone is insufficient. It excludes main-thread process-exit destructors,
foreign threads beyond that admission boundary, cancellation/cleanup,
concurrent key-deletion/destructor interaction, fork/atfork, detached-thread
lifecycle beyond the existing selected-worker exit seam, dynamic/loader
TLS/DTV, allocator ordering, a general TCB/all-thread list,
weak/same-address TSD aliases, exact ELF parity, general pthread/C11 behavior,
full pthread/TLS or x86-64 parity, promotion, and public x86 support.

`libc-pthread-cancel-deferred` is a sixteenth separately recorded private
static `verified_artifact` under that same still-planned `libc.pthread-tls`
family. Its project-header C body first runs against pinned musl and then
through a `-nostdlib -static` candidate. It selects one default joinable,
pointer-returning worker route only: the worker retains deferred type, disables
cancellation, and publishes that state; its creator records `pthread_cancel`;
explicit `pthread_testcancel` returns while DISABLE and `PTHREAD_CANCEL_MASKED`
are non-delivering; re-enabling leaves that request pending; and the worker's
next explicit `pthread_testcancel` is the sole selected delivery point. The
exit disables cancellation before it drains LIFO cleanup handlers, then runs
the selected TSD destructor phase before publishing `PTHREAD_CANCELED`; the
fixture preserves the creator's errno. The separate project-header/pinned-musl
C/C++ declaration matrix checks the cancellation constants, sentinel type,
24-byte `struct __ptcb`, cleanup macro/helper ABI, all six selected signatures,
and unmangled C++ spellings; it is compile-only and supplies no behavior
evidence. This does not select asynchronous cancellation delivery,
cancellation signals; implicit, blocking-syscall, or synchronization-wait
cancellation points; C11, detached, main, or foreign-thread cancellation; a
general pthread cancellation runtime; full pthread/TLS or x86-64 parity;
promotion; or public x86 support.

`libc-pthread-tls-aggregate` is a seventeenth private static composition
artifact under the still-planned `libc.pthread-tls` family. Its project-header
two-worker body first runs against pinned musl and then through the same
`-nostdlib -static` archive. It composes only the already selected Static
Initial TLS v1, create/join, normal mutex/condition, rwlock, once, and
pthread-key/TSD paths: distinct workers hold shared reads, publish through a
private condition, receive a parent broadcast, and execute clear-before-
callback destructors before their distinct join results. The parent proves
writer exclusion while both reads are live and writer acquisition after join.
It neither exercises nor extends the separate deferred-cancellation route, and
adds no attributes, timed/process-shared synchronization, C11 adapter,
detached/foreign-thread, dynamic/loader TLS, CRT/sysroot, pthread/TLS-parity,
promotion, or public-x86 claim.

`libc-pthread-atfork` is an eighteenth private static `verified_artifact`
under that same still-planned family. Its project-header C fixture first runs
against pinned musl, then against the dependency-free `-nostdlib -static`
candidate. It selects one fixed-capacity, single-threaded 32-record
`pthread_atfork`/`fork` route only: reverse prepare, forward parent/child hooks
after raw Linux `fork=57`, and the parent route before errno publication on
deterministic `EPERM` failure through a fixture-local seccomp filter. The child
then registers and dispatches one bounded ordinary-exit callback after its
child hooks. A selected-worker reservation or live mapping instead returns
`EAGAIN` before callbacks; successful join reopens admission for another
complete fork/child-exit lifecycle. It excludes recursive callbacks and
callback-driven worker creation; foreign/concurrent threads,
registration/fork callers, and selected-worker lifecycle callers; signal masks/safety;
allocator, TSD, cancellation, synchronization, or loader reset; dynamic TLS;
CRT/sysroot integration; general fork, atfork, process-exit, or pthread
behavior; full pthread/TLS or x86-64 parity; promotion; and public x86 support.

The same static archive-binding check retains pinned musl 1.2.6
`src/process/fork.c`'s private `weak_alias(dummy, __ldso_atfork)` and
`weak_alias(dummy, __aio_atfork)` fallbacks. The AArch64 static manifest
records both weak spellings in `fork.lo`, while `aio.lo` owns the separate
strong `__aio_atfork` body. The staged archive and ordinary freestanding
candidate retain the weak binding; a caller-owned strong private
`__aio_atfork` definition wins after `fork` extracts the archive member and
traps on any later dispatch while the bounded fork proof completes. This is
neither a loader-hook nor AIO implementation: the fallbacks are inert, the
bounded `fork` route does not dispatch through either, and no loader lock/reset,
mapping, finalization, AIO queue/lock, request-cancellation, file-descriptor
coordination, public AIO, or general atfork capability is selected.

`libc-pthread-affinity` is a nineteenth private static `verified_artifact`
under that same still-planned family. Its project-header C fixture first runs
against pinned musl, then against the dependency-free `-nostdlib -static`
candidate. It selects only GNU `pthread_getaffinity_np` and
`pthread_setaffinity_np` over musl's tagged 128-byte, 1024-bit `cpu_set_t`.
The bootstrapped process-main task is admitted only through its own
`pthread_self()` handle, and one executing selected worker only through its
opaque-TP registry mapping while its parent-written `CLONE_PARENT_SETTID` word
is positive. The direct get route retains the initialized Linux
`sched_getaffinity=204` prefix and clears the caller tail exactly as musl does;
the set route uses `sched_setaffinity=203`. The fixture proves main/worker get
and set, tail clearing, undersized/empty `EINVAL`, preserved `errno`, and
post-join `ESRCH`. It excludes affinity attributes, `sched_*` C APIs, `CPU_*`
helpers, `pthread_getattr_np`, non-self-main and foreign/general handles,
target completion or concurrent join/detach/reaping, scheduler policy,
dynamic/loader TLS, full pthread/TLS or x86-64 parity, promotion, and public
x86 support.


`libc-termios-control` is a separately recorded static
`verified_artifact` gate over that archive, not a terminal capability. Its
project-header C body first executes through pinned musl and then through a
`-nostdlib -static` candidate. It selects only fixed baud/raw helpers, named
attribute/queue/flow/break requests, and fixed window-size records. The public
60-byte x86 C `termios` pointer is passed directly to Linux, which reads or
writes only its shared 36-byte prefix; the fixture proves preserved public
tails and a protected-page input boundary. Per-wrapper emitted-code gates pin
the action/request words and third ioctl argument for named calls. It excludes
generic ioctl, `tcdrain`/cancellation, C terminal/session/PTY policy, dynamic
runtime, and public x86 support.

`libc-ctermid` is a separately recorded static `verified_artifact` gate over
that archive, not a terminal or filesystem capability. Its C/C++ header gate
proves the feature-gated `<stdio.h>` declaration and `L_ctermid == 20`, their
strict hiding, and `<unistd.h>`'s unconditional C-linkage declaration against
pinned musl. One project-header C body then
executes through pinned musl and a `-nostdlib -static` candidate. It selects
only the fixed `/dev/tty` spelling: null returns a borrowed immutable literal;
a caller-owned `L_ctermid` buffer receives the nine NUL-terminated bytes and
keeps its remaining tail. The candidate has no syscall, TLS/errno, allocation,
terminal I/O, or string-helper path. It excludes terminal policy,
PTY/session/termios/tty discovery, getpass, generic filesystem behavior,
temporary-file families, filesystem handles, dynamic runtime, family
completion, promotion, and public x86 support.

`libc-grantpt` is a separately recorded static `static-c-grantpt`
`verified_artifact` gate over that archive, not a PTY or terminal capability.
Its X/Open/GNU/BSD C/C++ `<stdlib.h>` declaration gate proves exact
`int grantpt(int)` linkage and strict/POSIX hiding before one project-header C
body executes through pinned musl and a `-nostdlib -static` candidate. It
selects only musl's historical zero-return compatibility wrapper: direct and
function-pointer calls with `-1`, `INT32_MIN`, `0`, and `INT32_MAX` succeed;
the pinned-musl route preserves stale errno. The candidate does not inspect the
descriptor or use TLS/errno, allocation, helper calls, or a syscall. It
excludes PTY allocation/grant/unlock/naming, descriptor authority, terminal
discovery or session policy, `posix_openpt`, `unlockpt`, `ptsname`/`ptsname_r`,
openpty/forkpty/login_tty/vhangup, generic ioctl, dynamic runtime, family
completion, promotion, and public x86 support.

`libc-unlockpt` is a separately recorded static `static-c-unlockpt`
`verified_artifact` gate over that archive, not a PTY or terminal capability.
Its X/Open/GNU/BSD C/C++ `<stdlib.h>` declaration gate proves exact
`int unlockpt(int)` linkage and strict/POSIX hiding before one project-header C
body executes through pinned musl and a `-nostdlib -static` candidate. It
selects only musl's fixed private-zero `TIOCSPTLCK=0x40045431` bridge: `-1`
reports `EBADF`, a raw-opened non-PTY reports `ENOTTY`, and one fresh raw-opened
devpts master succeeds with stale errno preserved before fixture-only peer
observation. The candidate includes only the existing errno translation and
fixed request; it rejects generic ioctl and all unselected terminal/PTY
helpers. It excludes PTY allocation/grant/naming, descriptor ownership,
terminal discovery or session/process policy, `posix_openpt`, `grantpt`,
`ptsname`/`ptsname_r`, openpty/forkpty/login_tty/vhangup, dynamic runtime,
family completion, promotion, and public x86 support.

`libc-gethostid` is a separate static `verified_artifact` inside
still-planned `libc.c-abi-compat`, not a `system.kernel-admin` capability. Its
focused X/Open/GNU/BSD `<unistd.h>` C/C++ gate proves `long gethostid(void)`,
strict/POSIX hiding, and unmangled linkage against pinned musl and project
headers. One project-header C body then executes through pinned musl and a
`-nostdlib -static` candidate. It proves musl's exact zero `long` result and
rejects TLS/errno, dynamic linkage, unresolved symbols, runtime dependencies,
external calls, and syscalls in the selected implementation. It neither reads
host configuration nor selects hostname/domain-name state, host-identity or
secure-execution policy, libc.so, CRT, loader, sysroot, family completion,
promotion, or public x86 support.

`issetugid-header-abi` and `libc-issetugid` record a separate private
`static-c-issetugid` artifact inside still-planned `libc.c-abi-compat`, not a
credential or secure-execution-policy capability. The GNU/BSD-only
`<unistd.h>` C/C++ matrix proves `int issetugid(void)`, strict/POSIX/X/Open
hiding, and unmangled linkage against pinned musl and project headers. One
project-header C body executes through ordinary pinned musl and three
`-nostdlib -static` candidates. It proves musl `src/misc/issetugid.c`'s cached
`libc.secure` observation: ordinary direct and function-pointer calls return
zero, while bounded fixture-only final-AT_SECURE and UID/EUID-mismatch vectors
return one with errno preserved. The candidate audits the exact archive
surface, initial TLS bootstrap before static startup, no dynamic TLS/runtime
closure, and no credential, environment, `secure_getenv`, raw-auxv, or syscall
path in `issetugid`. It excludes credential mutation or policy, descriptor
hygiene, loader policy, process lifecycle, general pthread/TLS behavior,
process.globals, family completion, promotion, and public x86 support.

`legacy-misc-header-abi` and `libc-legacy-misc` evidence the exact frozen
eight-symbol `legacy.misc` capability as a selected-private slice inside
still-planned `libc.c-abi-compat`. The unfeatured selected-static archive
remains frozen: the existing system-information and `issetugid` owners retain
`get_avphys_pages`, `get_nprocs`, `get_nprocs_conf`, `get_phys_pages`, and
`issetugid`, while the dependency-free opt-in `x86-legacy-misc` owner adds
only `fmtmsg`, `setkey`, and `encrypt`. The raw pinned-musl/project C/C++
matrix proves strict/POSIX base declarations, X/Open `setkey`/`encrypt`, and
GNU/BSD `issetugid` visibility with unmangled C linkage. The static aggregate
proves bounded musl-derived `MSGVERB`/stderr/console/error `fmtmsg` behavior,
the exact three-symbol feature delta, and static ELF closure. `setkey` and
`encrypt` are deliberately inert link-compatible ABI names only: they neither
dereference nor mutate caller storage and select no DES, cipher, PRNG, crypto
service, default export, legacy runtime, family promotion, or public x86
support.

`gettid-header-abi` and `libc-gettid` record a separate private
`static-c-gettid` artifact inside still-planned `libc.c-abi-compat`, not a
process or scheduler capability. The GNU-only `<unistd.h>` C/C++ matrix proves
the exact `pid_t gettid(void)` spelling, strict/POSIX/X/Open/BSD hiding, and
unmangled linkage against pinned musl and project headers. The shared C body
then runs through pinned musl and a canonical-archive
`-nostdlib -static -Wl,--gc-sections` candidate, comparing direct and
function-pointer returns with a fixture-local raw `gettid=186` result. Rust
codegen-unit placement is not the artifact boundary, so the runner requires
one archive owner and validates the final reachable executable instead of
extracting a compiler-chosen object. Musl's source reads its current TCB's
tid; the candidate makes the intentional no-TCB direct-syscall adaptation and
rejects errno/TLS, helper calls, dynamic linkage, runtime dependencies, and
aggregate process/scheduler/pthread behavior. It does not select
process.globals, libc.so, CRT, loader, sysroot, family completion, promotion,
or public x86 support.

`posix-close-header-abi` and `libc-posix-close` record a separate private
`static-c-posix-close` artifact inside still-planned `libc.c-abi-compat`, not
a descriptor or filesystem capability. The pinned-musl/project `<unistd.h>`
C/C++ matrix proves unconditional `int posix_close(int, int)` visibility under
strict, POSIX, X/Open, and GNU profiles, its exact two-int type, and unmangled
C++ linkage. The shared C body then executes through pinned musl and one true
`-nostdlib -static` candidate. Musl's source ignores flags and delegates to
close; the isolated candidate proves direct and function-pointer closure of
fixture-owned descriptors, stale-errno preservation, and `EBADF`, while
retaining only direct `close=3` plus its no-retry `EINTR` success mapping. The
closed candidate rejects `close` and generic descriptor-I/O extraction. It
does not select descriptor lifetime/ownership policy, cancellation/AIO
coordination, filesystem policy, libc.so, CRT, loader, sysroot, family
completion, promotion, or public x86 support.

`endhostent-header-abi` and `libc-endhostent` record a separate private
`static-c-endhostent` artifact inside still-planned `libc.c-abi-compat`, not a
netdb or resolver capability. The pinned-musl/project `<netdb.h>` C/C++ matrix
proves unconditional `void endhostent(void)` and `void endnetent(void)`
declarations under strict, POSIX, X/Open, and GNU profiles, their exact
no-argument types, and unmangled C++ linkage through the header's C-linkage
guards. The shared C body then executes through pinned musl and one true
dependency-free `-nostdlib -static` candidate. Musl 1.2.6
`src/network/ent.c` supplies an empty `endhostent` body and
`weak_alias(endhostent, endnetent)`; the fixture proves direct and
function-pointer no-op calls plus the strong/weak same-address alias identity.
The candidate rejects host/network enumeration and resolver extraction. It
does not select legacy database state, `/etc/hosts` or `/etc/networks`, NSS,
resolver behavior, generic netdb APIs, libc.so, CRT, loader, sysroot, family
completion, promotion, or public x86 support.

`libc-isatty` is a separately recorded static `static-c-isatty`
`verified_artifact` gate over that archive, not a terminal capability. Its
strict/POSIX/X/Open/GNU/BSD C/C++ `unistd.h` declaration gate and one
project-header C body first execute through pinned musl and then through a
`-nostdlib -static` candidate. It selects only `isatty(int)`: pinned musl's
direct `ioctl=16`/`TIOCGWINSZ=0x5413` private winsize scratch followed by the
exact `syscall(...) + 1` conversion. The fixture proves tty success with
stale-errno preservation, invalid-fd `EBADF`, and `/dev/null` `ENOTTY`; its
raw devpts setup only supplies the known tty descriptor. It neither opens nor
names a terminal and excludes terminal discovery, termios mutation/control,
PTY/session policy, `ttyname`, `getpass`, generic ioctl, dynamic runtime,
family completion, promotion, and public x86 support.

`libc-ttyname-r` is a separately recorded static `static-c-ttyname-r`
`verified_artifact` gate over that archive, not a terminal/path capability.
Its strict/POSIX/X/Open/GNU/BSD C/C++ `unistd.h` declaration gate and one
project-header C body first execute through pinned musl and then through a
`-nostdlib -static` candidate. It selects only caller-buffered
`int ttyname_r(int, char *, size_t)`: the already selected `isatty` check,
musl's fixed private `/proc/self/fd/<fd>` spelling, its zero-capacity readlink
dummy-byte compatibility result, one fitting NUL write, and private
named-target/original-descriptor device-inode equality. The fixture proves a
devpts name matching the raw procfd link, stale-errno-preserving success,
one-byte/zero-capacity `ERANGE` without errno replacement, null-buffer
`EFAULT`, invalid-fd `EBADF`, and `/dev/null` `ENOTTY`. Its direct closure
audits `readlink=89`, `fstat=5`, `newfstatat=262`, and the selected `isatty`
ioctl without public `readlink`/`stat`/`fstat`/`ttyname`, PTY/session, termios,
or generic ioctl helpers. It does not select generic filesystem/path
completion, terminal/session policy, static `ttyname` storage, dynamic runtime,
family completion, promotion, or public x86 support.

`libc-tcgetpgrp` is a separately recorded static `static-c-tcgetpgrp`
`verified_artifact` gate over that archive, not terminal/session capability.
Its strict/POSIX/X/Open/GNU/BSD C/C++ `unistd.h` declaration gate and one
project-header C body first execute through pinned musl and then through a
`-nostdlib -static` candidate. It selects only `pid_t tcgetpgrp(int)`: pinned
musl's direct `ioctl=16`/`TIOCGPGRP=0x540f` private int scratch. The fixture
proves a child-established foreground pid with stale-errno preservation,
invalid-fd `EBADF`, and `/dev/null` `ENOTTY`; the child-only raw devpts
`fork`/`setsid`/`TIOCSCTTY` transition is kernel-precondition plumbing, not an
archive session/process-control API. It excludes terminal discovery, termios
mutation/control, PTY/session policy, `tcsetpgrp`, `tcgetsid`, `ttyname`,
`getpass`, generic ioctl, dynamic runtime, family completion, promotion, and
public x86 support.

`libc-tcsetpgrp` is a separately recorded static `static-c-tcsetpgrp`
`verified_artifact` gate over that archive, not a terminal/session capability.
Its strict/POSIX/X/Open/GNU/BSD C/C++ `unistd.h` declaration gate and one
project-header C body first execute through pinned musl and then through a
`-nostdlib -static` candidate. It selects only `int tcsetpgrp(int, pid_t)`:
pinned musl's direct `ioctl=16`/`TIOCSPGRP=0x5410` private `int` copy. The
fixture proves assignment of a distinct in-session child group with
stale-errno preservation, invalid-fd `EBADF`, and `/dev/null` `ENOTTY`; its
child-only raw devpts `fork`/`setsid`/`TIOCSCTTY`/`setpgid` transition and raw
`TIOCGPGRP` postcondition are kernel-precondition plumbing, not archive
session/process-control APIs. It neither creates a session nor chooses a
group, changes process membership, or establishes a controlling terminal. It
excludes terminal discovery, termios mutation/control, PTY/session policy,
`tcgetpgrp`, `tcgetsid`, `ttyname`, `getpass`, generic ioctl, dynamic runtime,
family completion, promotion, and public x86 support.

`libc-getpass` is a separately recorded static `verified_artifact` gate over
that archive, not a terminal or password capability. Its GNU/BSD C/C++ header
gate and one project-header C body first execute through pinned musl and then
through a `-nostdlib -static` candidate. It selects only historical C
`getpass`: opening `/dev/tty` with `O_RDWR|O_NOCTTY|O_CLOEXEC`, direct absent
controlling-terminal `ENXIO`, temporary canonical no-echo/no-signal
`TCSAFLUSH` input, the private fixed `TCSBRK` drain request, optional prompt
and newline output, one shared 128-byte static result buffer with 127-byte
truncation, and exact terminal restoration. Raw devpts/session operations are
fixture plumbing only. It excludes C PTY/session helpers, generic ioctl,
account data, a Rust secret API, cancellation, secret-memory erasure, terminal
policy, dynamic runtime, family completion, promotion, and public x86 support.

`libc-mktemp` is a separately recorded `static-c-mktemp` `verified_artifact`
gate over that archive, not `filesystem.extensions` completion. Its GNU/BSD
C/C++ header gate and project-header C fixture first run through pinned musl
and then through a `-nostdlib -static` candidate. It selects only historical
`mktemp(char *)`: mutable trailing `XXXXXX` validation, musl's realtime/TID
six-byte `A`-`P`/`a`-`p` mapping, direct `newfstatat` availability lookup,
`ENOENT` for a presently absent result, and invalid/non-missing-error first-byte
clearing. It does not create, reserve, open, or return authority for the
pathname and is inherently racy. It excludes `tmpnam`/`tempnam`, all
`mkstemp`/`mkdtemp` forms, `tmpfile`, entropy/crypto policy, generic temporary
or filesystem policy, descriptor/directory and file-handle authority, a Rust
temporary API, dynamic runtime, family completion, promotion, and public x86
support.

`libc-process-context` is a separately recorded static
`verified_artifact` gate over that archive, not the `process.control`
capability. Its project-header C body first executes through pinned musl and
then through a `-nostdlib -static` candidate. It selects only scalar
`getpid`/`getppid`/`get*id` observations, reversible `umask`, and named
process-group/session wrappers. It compares scalar and invalid-request errno
results with raw Linux, then confines `setpgrp`/`setpgid`/`setsid` state
transitions to raw-forked children. Per-wrapper emitted-code gates pin the
selected syscall words. It excludes C fork/exec/posix_spawn, gettid, generic
process control and signal delivery, pthread coordination, dynamic runtime,
and public x86 support; the separately selected child-reaping artifact owns
the closed `wait`/`waitpid`/`waitid` surface.

`libc-environment` is the private selected `static-c-environment` slice for
exactly `process.environment-mutation` (`clearenv`, `setenv`, and `unsetenv`).
Its `environ` aliases, `getenv`, and `putenv` support the tested C ABI and
environment ownership model only; they do not select `process.globals`. The
`x86-environment-runtime` feature selects `environment_runtime.rs`; ordinary
selected-static builds retain the legacy dependency-free bounded
`environment.rs` leaf. The three direct native gates retain the frozen
`<stdlib.h>` declaration/C++-linkage matrix, GNU `<unistd.h>` `environ` object
matrix, and pinned-musl runtime comparison.

Under `env -i CRABC_X86_INITIAL=entry`, the real crabc `crt1`/`crti`/`crtn`
candidate publishes initial `envp` before an ordinary `.init_array`
constructor; that constructor observes the aliases and lookup, mutates one
key with `setenv`, and `main` observes the result. The runtime follows musl's
`oldenv`/`__env_rm_add` ownership split: copied `setenv` strings are tracked,
caller `putenv` storage stays borrowed, and a direct vector is copied only for
an append. It proves first-match lookup, direct-vector replacement/removal,
over-128-entry growth, and reclamation. Fixture-only linker allocation wrappers
also prove that replacement copied-string malloc, direct-vector append malloc,
and owned-vector append realloc `ENOMEM` leave the published environment
unchanged. Post-publication ownership-registry allocation failure remains
outside this claim.

The candidate composes the existing x86 allocator wrapper and bundled backend
with an exact eleven-member candidate-local pinned-musl backend-support tail,
while rejecting musl environment or allocator entries. Returned `getenv`
pointers, direct `environ` writes, caller storage, signal reentry, and
fork/exec transitions remain caller-coordinated. This slice does not select
`secure_getenv`, secure-execution policy, a general threaded environment
lifecycle, `memory.allocator-basic`, dynamic runtime, CRT completion, loader,
sysroot, family completion, promotion, or public x86 support.

`libc-secure-environment` is a separately recorded
`static-c-secure-environment` `verified_artifact`, not a secure-execution or
process-environment capability. Its project-header C body first executes
through pinned musl and then through a `-nostdlib -static` candidate. The
shared static startup validates and first publishes the raw initial auxv to
the separate `static-c-auxv-observation` artifact; this leaf then caches musl's
last matching `AT_SECURE`/UID/EUID/GID/EGID decision before callbacks and
exports GNU `secure_getenv` only. Secure mode returns null without inspecting
the requested name; normal mode returns the selected borrowed `getenv` value.
Synthetic final-`AT_SECURE` and UID/EUID-mismatch vectors prove both secure
paths, including an invalid-name call. It does not alter raw `getauxval`,
sanitize descriptors, mutate credentials or environment state, create or
execute processes, install signals, select loader policy, complete a CRT or
runtime family, promote x86, or claim public support.

`libc-login-name` is a separately recorded `static-c-login-name`
`verified_artifact` gate over that archive, not a login/session identity
capability. Its project-header C body first executes through pinned musl and
then through a `-nostdlib -static` candidate. It selects only `getlogin` and
`getlogin_r`: the first `LOGNAME` entry returns a borrowed pointer, preserving
caller-owned `putenv` aliasing and later mutation. An absent name returns
`ENXIO`; too-small storage returns `ERANGE` without writing; an exact-fit or
larger caller buffer receives the value and NUL, including for an empty name.
Both calls preserve stale `errno`. It owns no allocation, storage, lock,
passwd/utmp parsing, terminal/session lookup, credential policy, or secure
execution. Direct `environ` assignment and caller-owned storage/mutation
remain caller-coordinated. It does not select process creation, exec/spawn
inheritance, supervision, dynamic runtime, CRT objects, or public x86 support.

`libc-child-reaping` is a separately recorded
`static-c-child-reaping` `verified_artifact` gate over that archive, not a
process-control or child-supervision capability. Its project-header C body
first executes through pinned musl and then through a `-nostdlib -static`
candidate. It selects exactly `wait`, `waitpid`, and `waitid`: `wait4=61`
backs the first two forms and `waitid=247` writes the public child report.
Fixture-local raw clone/pipe/exit plumbing creates race-free blocked, exited,
and reaped states without exporting C fork or exec. The fixture proves
`WNOHANG`'s unchanged `waitpid` status and no-event `waitid` observation,
`WNOWAIT` report-then-exact-reap behavior, consuming `waitid`, post-reap
`ECHILD`, and invalid-selector `EINVAL`. Musl routes this family through
cancellation-point machinery; this direct static leaf intentionally retains
the archive's non-cancellation model. It excludes C fork/vfork/clone/exec/
`posix_spawn`, generic child supervision, signal delivery or signal waits,
pthread/atfork lifecycle, dynamic runtime, and public x86 support.

`libc-immediate-termination` is a separately recorded
`static-c-immediate-termination` `verified_artifact` gate over that archive,
not a process-lifecycle capability. Its project-header C body first executes
through pinned musl and then through a `-nostdlib -static` candidate. It
selects exactly C11 `_Exit`: fixture-local raw clone/wait control observes
child exit status 37, while the leaf emits `exit_group=231` and preserves
musl's defensive `exit=60` loop only if whole-process termination returns.
It has no errno, initial-TLS, callback, lock, allocator, or mutable lifecycle
state. It excludes POSIX `_exit`, ordinary `exit`/`abort`/`atexit`,
`at_quick_exit`/`quick_exit` hooks, stdio flushing/fini/destructors, fork
coordination, pthread lifecycle, dynamic runtime, and public x86 support.

`libc-posix-exit` is a separately recorded `static-c-posix-exit`
`verified_artifact` gate over that archive, not a process-lifecycle capability.
Its project-header C body first executes through pinned musl and then through a
`-nostdlib -static` candidate. It selects exactly POSIX `_exit`: musl's
complete `src/unistd/_exit.c` source makes one no-return forward to the
separately selected C11 `_Exit` sibling. Fixture-local raw clone/wait observes
child status 41; emitted `_exit` only calls `_Exit`, and only that sibling
contains `exit_group=231` plus musl's defensive `exit=60` loop. `_exit` has no
raw syscall, errno, initial-TLS, callback, lock, allocator, or mutable
lifecycle state. It excludes ordinary `exit`/`abort`/`atexit`,
`at_quick_exit`/`quick_exit` hooks, stdio flushing/fini/destructors, fork
coordination, pthread lifecycle, dynamic runtime, and public x86 support.

`libc-posix-spawnattr-init` is a separately recorded
`static-c-posix-spawnattr-init` `verified_artifact` inside still-planned
`libc.posix-runtime`, not a spawn or process-control capability. Its focused
pinned-musl/project C/C++ `<spawn.h>` matrix proves the unconditional
`int posix_spawnattr_init(posix_spawnattr_t *)` signature, unmangled linkage,
and the x86 336-byte/eight-byte-aligned record layout with its member offsets.
The same project-header C fixture first executes musl 1.2.6
`src/process/posix_spawnattr_init.c`, then a true `-nostdlib -static` candidate
made from exactly one Rust object. Direct and function-pointer calls fully zero
byte-filled caller records, retain adjacent guards, and preserve stale `errno`
on the ordinary musl route. The candidate uses a fixed 42-word direct-store
loop with no undefined helper, call, syscall, errno/TLS, allocator, dynamic
runtime, CRT, loader, or sysroot dependency. It does not select
`posix_spawn`/`posix_spawnp`, other attribute APIs, file actions,
fork/vfork/clone, exec, child lifecycle, signal delivery, scheduler policy,
family completion, promotion, or public x86 support; the generic AArch64
export remains unchanged.

`libc-posix-spawnattr-getpgroup` is a separately recorded
`static-c-posix-spawnattr-getpgroup` `verified_artifact` inside still-planned
`libc.posix-runtime`, not a process-spawn or process-control capability. Its
pinned-musl/project C/C++ `<spawn.h>` matrix proves the unconditional
`int posix_spawnattr_getpgroup(const posix_spawnattr_t *, pid_t *)` ABI,
unmangled C++ linkage, signed four-byte `pid_t` storage, and the x86
offset-four `__pgrp` record member. The shared fixture first executes musl
1.2.6 `src/process/posix_spawnattr_getpgroup.c`, then a true
`-nostdlib -static` candidate extracted from exactly one Rust object. Direct
and function-pointer calls copy positive and negative process groups from
byte-filled 336-byte caller records, retain every input byte and adjacent
input/output guard, and leave stale `errno` unchanged on the ordinary musl
route. The candidate is one fixed offset-four load and output-word store with
no undefined helper, call, syscall, errno/TLS, allocator, dynamic runtime,
CRT, loader, or sysroot path. It does not select `posix_spawn`/`posix_spawnp`,
other attribute APIs, file actions, fork/vfork/clone, exec, child lifecycle,
signals, scheduler policy, family completion, promotion, or public x86
support; the generic AArch64 export remains unchanged.

`libc-posix-spawnattr-getschedpolicy` is a separately recorded
`static-c-posix-spawnattr-getschedpolicy` `verified_artifact` inside
still-planned `libc.posix-runtime`, not a process-spawn, process-control, or
scheduler capability. Its pinned-musl/project C/C++ `<spawn.h>` matrix proves
the unconditional `int posix_spawnattr_getschedpolicy(const posix_spawnattr_t
*, int *)` ABI, unmangled C++ linkage, and complete x86 336-byte/eight-byte-
aligned attribute type. The shared fixture first executes musl 1.2.6
`src/process/posix_spawnattr_sched.c::posix_spawnattr_getschedpolicy`, whose
complete body is `return ENOSYS;`, then a true `-nostdlib -static` candidate
extracted from exactly one Rust object. Direct and function-pointer calls over
nonnull, null-attribute, null-output, and both-null pointer shapes all return
the positive error number `ENOSYS=38`, retain byte-filled caller record and
guarded output storage, and preserve stale `errno` on the ordinary musl route.
The candidate materializes only that immediate result: no pointer dereference,
helper call, syscall, errno/TLS, allocator, dynamic runtime, CRT, loader, or
sysroot path. It does not select `posix_spawn`/`posix_spawnp`, other attribute
APIs, file actions, fork/vfork/clone, exec, child lifecycle, signals,
scheduler policy/parameter behavior, family completion, promotion, or public
x86 support; the generic AArch64 export remains unchanged.

`libc-bsearch` is a separate capability-free `static-c-bsearch`
`verified_artifact` inside still-planned `libc.c-abi-compat`. Its strict,
POSIX, X/Open, GNU, and BSD C/C++ `<stdlib.h>` matrix proves the unconditional
five-argument `bsearch` declaration and unmangled C++ linkage. One
project-header C fixture then executes through pinned musl and a
`-nostdlib -static` candidate. It pins musl's direct/function-pointer
callback ABI, first/last/miss behavior, duplicate midpoint pointer, wide
record stride, and zero-count callback suppression. The candidate contains
only `bsearch` from this boundary and rejects qsort/qsort_r/__qsort_r,
search-container helpers, TLS/errno, allocation, locale, syscall, and runtime
state. It neither changes qsort/qsort_r behavior nor selects general
sorting/searching, callback ownership, libc.so, CRT, loader, sysroot, family
completion, promotion, or public x86 support.

`libc-linear-search` is a separate capability-free `static-c-linear-search`
`verified_artifact` inside still-planned `libc.c-abi-compat`. Its strict,
POSIX, X/Open, GNU, and BSD C/C++ `<search.h>` matrix proves the unconditional
five-argument `lfind` and `lsearch` declarations and unmangled C++ linkage.
One project-header C fixture then executes through pinned musl and a
`-nostdlib -static` candidate. It pins direct/function-pointer callback ABI,
lfind's first matching duplicate and miss without count mutation, lsearch's
existing hit, a non-int-stride miss copy/count increment, and zero-count
callback suppression. The candidate contains only `lfind`/`lsearch` from this
boundary and rejects bsearch/qsort/qsort_r, search-container and byte-copy
helpers, TLS/errno, allocation, locale, syscall, and runtime state. It
selects neither general sorting/searching nor callback ownership, libc.so,
CRT, loader, sysroot, family completion, promotion, or public x86 support.

`libc-intrusive-queue` is a separate capability-free
`static-c-intrusive-queue` `verified_artifact` inside still-planned
`libc.c-abi-compat`. Its strict, POSIX, X/Open, GNU, and BSD C/C++ `<search.h>`
matrix proves unconditional `insque`/`remque` declarations and unmangled C++
linkage. One project-header C fixture runs through pinned musl and a
`-nostdlib -static` candidate, proving null-predecessor reset without stale
neighbor writes, splice before an existing successor, payload preservation,
middle-node unlink repair, and `remque` retaining its removed node links. The
candidate contains only this paired two-link mutation boundary and rejects
linear/binary/sort/tree/hash helpers, TLS/errno, allocation, callbacks,
locale, locks, syscalls, and runtime state. It selects no general searching,
tree/list/container lifecycle, `search.tree-intrusive` capability, libc.so,
CRT, loader, sysroot, family completion, promotion, or public x86 support.

`libc-qsort` is a separate capability-free `static-c-qsort`
`verified_artifact` inside still-planned `libc.c-abi-compat`. Its strict,
POSIX, X/Open, GNU, and BSD C/C++ `<stdlib.h>` matrix proves the unconditional
four-argument `qsort` declaration and unmangled C++ linkage. One
project-header C fixture then executes through pinned musl and a
`-nostdlib -static` candidate. It pins direct/function-pointer comparator
calls, duplicate-key sorting, record permutation, a 308-byte smoothsort
cycling-buffer stride, and zero-count callback suppression. The candidate
contains qsort plus its private worker but rejects bsearch,
__qsort_r/qsort_r, search-container helpers, TLS/errno, allocation, locale,
syscall, and runtime state. It preserves qsort_r behavior separately and
selects neither general sorting/searching nor callback ownership, libc.so,
CRT, loader, sysroot, family completion, promotion, or public x86 support.

`libc-callback-algorithms` is a separately recorded
`static-c-callback-algorithms` `verified_artifact` gate over that archive, not
a general sorting/searching capability. Its project-header C body first
executes the public `bsearch`, `qsort`, and `qsort_r` cases through pinned musl
and then through a `-nostdlib -static` candidate; the candidate also directly
exercises private `__qsort_r`. It closes exactly `bsearch`, `__qsort_r`, and
`qsort` as strong exports plus weak, same-address `qsort_r`. The fixed musl
smoothsort core retains its O(1) cycling buffer; qsort's separate adapter calls
the private worker, and GNU/BSD `qsort_r` retains its final-context
callback ABI. The fixture proves bsearch hit/miss/zero-element behavior,
ordinary and wide-record sorting with byte preservation, context identity,
the private helper, and a caller's strong `qsort_r` override. This stateless,
allocation-free leaf has no syscall, errno, TLS, allocator, or mutable state.
It is private native x86 evidence only: it excludes generic C sorting/search,
callback registries, C longjmp/C++ exception transport, dynamic runtime, and
public x86 support.

The same callback proof now additionally selects only the ABI-only
`numeric.qsort-helper` capability: strong, uninstalled `__qsort_r` context ABI
over the private smoothsort worker and its weak same-address `qsort_r` alias.
The direct candidate proves helper sorting and a strong caller override, while
the public qsort/qsort_r surface remains
under `numeric.scalar-legacy-callback`. This does not promote the planned
`libc.c-abi-compat` family or select general sorting, runtime ownership, or
public x86 support.

`libc-search-tree-intrusive` is a private selected
`search.tree-intrusive` slice inside still-planned `libc.c-abi-compat`. Its
six-profile pinned-musl/project C/C++ header matrix and static runtime
differential prove strong `tdelete`, `tdestroy`, `tfind`, `tsearch`, and
`twalk`, hidden global `__tsearch_balance`, GNU-only `tdestroy`/`struct qelem`,
AVL rotations/traversal/deletion, optional key callbacks, allocation-failure
rollback, and private mmap/munmap node ownership without a C allocator export.
It leaves libc.so, CRT, loader, sysroot, family promotion, and public x86
support unselected.

`libc-search-hash-table` is a private selected `search.hash-table` slice
inside still-planned `libc.c-abi-compat`. Its six-profile pinned-musl/project
C/C++ header matrix and static runtime differential prove strong `hcreate`,
`hdestroy`, and `hsearch` plus weak GNU `hcreate_r`, `hdestroy_r`, and
`hsearch_r`, with GNU-only `hsearch_data`/`_r` visibility under BSD. The common
fixture proves zero-capacity construction, unsigned-byte hashing, duplicate
first-entry retention, global/caller-record independence, grow-and-rehash
rollback/retry, repeated-create overwrite/leak, and idempotent destruction.
Musl's private calloc/free table ownership is deliberately represented by
private mmap/munmap table and entry-array mappings; RLIMIT_AS and mincore prove
the selected failure and release transitions without adding a C allocator
export. It does not select callback trees, iteration, general allocation or
containers, process/environment mutation, libc.so, CRT, loader, sysroot,
family promotion, or public x86 support.

`libc-gettext-catalog` is the separate private `catalog.gettext` slice inside
still-planned `libc.c-abi-compat`. Its default/strict/POSIX/XOPEN/BSD/GNU
pinned-musl/project C/C++ matrix ratchets all nine `<libintl.h>` and three
`<nl_types.h>` declarations, including unmangled catalog linkage. The common
static-musl/freestanding candidate body proves no-catalog identity/plural
fallbacks, errno preservation, default/current/overlong domain behavior,
binding query/rebind rules, UTF-8-only codesets, and direct missing-catalog
`ENOENT`. The candidate then proves its explicit fixed profile: one 256-byte
domain buffer, four permanent bindings, `catgets` caller-default, and no-op
`catclose`. It deliberately does not parse/load `.mo` or message-catalog
files, consult NLSPATH/LANG or locale maps, evaluate plural rules, use mmap or
an allocator, or claim general gettext/catalog translation, family promotion,
or public x86 support.

`libc-clock-gettime` is a separately recorded
`static-c-clock-gettime` `verified_artifact` gate over that archive, not a C
time or runtime capability. Its project-header C body first executes through
pinned musl and then through a `-nostdlib -static` candidate. It selects only
the normal `clock_gettime` zero-or-`-1`/`errno` convention for realtime,
monotonic, and process-CPU observations: normalized output, nondecreasing
monotonic/process-CPU records, invalid-clock errors, and stale errno
preservation on success. Valid calls require a writable output record because
musl may use vDSO code before a null pointer reaches its syscall fallback. The
candidate emits
`clock_gettime=228` through rdi/rsi and writes the selected initial-TLS errno
slot only on error. Musl may use a vDSO resolver before its syscall fallback;
this direct leaf intentionally owns no vDSO resolver or dynamic runtime state.
It excludes `clock_getres`/`clock_settime`, `time`, calendar/timer state,
pthread cancellation, dynamic runtime, and public x86 support.

`libc-clock-adjtime` is a separately recorded
`static-c-clock-adjtime-error-abi` `verified_artifact` gate over that archive,
not clock-adjustment support. Its `<sys/timex.h>` C/C++ profiles prove the
unconditional exact external-C declaration and x86 `struct timex` layout.
The project-header C body first executes through pinned musl and then through
a `-nostdlib -static` candidate, but only with rejected `clockid_t -1` and
`CLOCK_MONOTONIC` requests. It proves the direct `clock_adjtime=305` rdi/rsi
error convention, initial-TLS errno publication, and Linux's `EINVAL`,
capability-first `EPERM`, or direct `EOPNOTSUPP` result without issuing a valid
`CLOCK_REALTIME` adjustment. The wrapper deliberately installs no authority
guard: a valid caller can reach Linux outside this evidence. It excludes
successful clock authority/discipline/state semantics, valid-record behavior,
clock observation, calendar/time-zone policy, POSIX timers, cancellation,
dynamic runtime, family completion, promotion, and public x86 support.

`libc-clock-settime` is a separately recorded
`static-c-clock-settime-error-abi` `verified_artifact` gate over that archive,
not clock-setting support. Its header gate proves that `<time.h>` hides the
POSIX declaration under strict C11/C++17 and exposes the exact C and C++
external-C signature under POSIX, X/Open, and GNU profiles. Its project-header
C body first executes through pinned musl and then through a `-nostdlib -static`
candidate, but only with rejected `clockid_t -1` and
`CLOCK_MONOTONIC` requests. It therefore proves the direct `clock_settime=227`
error convention, initial-TLS errno publication, and Linux's `EINVAL` or
capability-first `EPERM` result without issuing a valid `CLOCK_REALTIME`
update. The wrapper deliberately installs no authority guard: a valid caller
can reach Linux outside this evidence. It excludes successful clock authority
or state semantics, clock observation, calendar/time-zone policy, POSIX timers,
cancellation, dynamic runtime, family completion, promotion, and public x86
support.

`libc-timer-getoverrun` is a separately recorded
`static-c-timer-getoverrun-error-abi` `verified_artifact` gate over that
archive, not POSIX-timer support. Its `<time.h>` header gate hides the POSIX
declaration under strict C11/C++17 and proves the exact opaque external-C
signature under POSIX, X/Open, and GNU profiles. The project-header C body
first executes through pinned musl 1.2.6 and then through a `-nostdlib -static`
candidate, but only with nonnegative opaque `timer_t` values `0` and `INT_MAX`.
It therefore proves the direct `timer_getoverrun=225` rdi error convention and
initial-TLS errno publication for Linux `EINVAL`, without creating, arming,
querying, deleting, or observing a valid POSIX timer. Musl's negative tagged
pthread-timer representation requires private `pthread_impl` state and is
explicitly excluded; the leaf never decodes or dereferences a timer handle. It
does not select timer ownership, overrun values, valid timer state, signal
delivery, calendar/time-zone policy, cancellation, dynamic runtime, family
completion, promotion, or public x86 support.

`libc-timer-delete` is a separately recorded
`static-c-timer-delete-raw-error-abi` `verified_artifact` gate over that
archive, not POSIX-timer support. Its `<time.h>` header gate hides the POSIX
declaration under strict C11/C++17 and proves the exact opaque external-C
signature under POSIX, X/Open, and GNU profiles. In a fresh process that
creates no POSIX timers, the project-header C body first executes through
pinned musl 1.2.6 and then through a `-nostdlib -static` candidate, but only
with nonnegative opaque `timer_t` values `0` and `INT_MAX`. It therefore proves
the direct raw-result `timer_delete=226` rdi convention: Linux returns
`-EINVAL` and the caller errno sentinel remains unchanged. Musl's negative
tagged pthread-timer representation requires private `pthread_impl`, atomic
timer-ID marking, and `SIGTIMER`; it is explicitly excluded and the leaf never
decodes or dereferences a timer handle. It does not establish valid timer-deletion
semantics, timer ownership/state, signal delivery, calendar/time-zone policy,
cancellation, dynamic runtime, family completion, promotion, or public x86
support.

`libc-timer-gettime` is a separately recorded
`static-c-timer-gettime-error-abi` `verified_artifact` gate over that archive,
not POSIX-timer support. Its `<time.h>` header gate hides the POSIX declaration
under strict C11/C++17 and proves the exact opaque external-C declaration,
timespec/itimerspec layout, and unmangled C++ linkage under POSIX, X/Open, and
GNU profiles. In a fresh process that creates no POSIX timers, the
project-header C body first executes through pinned musl 1.2.6 and then through
a `-nostdlib -static` candidate, but only with nonnegative opaque `timer_t`
values `0` and `INT_MAX` and initialized writable output records. It proves
only the direct `timer_gettime=224` rdi/rsi error convention: Linux returns
`-1`/`EINVAL` and leaves each record unchanged. Musl's negative tagged
pthread-timer representation requires private `pthread_impl` state and is
explicitly excluded; the leaf never decodes or dereferences a timer handle. It
does not establish valid timer query values, timer ownership/state, lifecycle,
clock/calendar/time-zone policy, signal delivery, cancellation, dynamic runtime,
family completion, promotion, or public x86 support.

`libc-timer-settime` is a separately recorded
`static-c-timer-settime-error-abi` `verified_artifact` gate over that archive,
not POSIX-timer support. Its `<time.h>` header gate hides the POSIX declaration
under strict C11/C++17 and proves the exact opaque external-C declaration,
flags argument, timespec/itimerspec layout, and unmangled C++ linkage under
POSIX, X/Open, and GNU profiles. In a fresh process that creates no POSIX
timers, the project-header C body first executes through pinned musl 1.2.6 and
then through a `-nostdlib -static` candidate, but only with nonnegative opaque
`timer_t` values `0` and `INT_MAX`, flags zero, a valid nonzero request record,
and initialized old-value storage. It proves only the direct
`timer_settime=223` rdi/rsi/rdx/r10 error convention: Linux returns
`-1`/`EINVAL` and leaves both records unchanged. Musl's negative tagged
pthread-timer representation requires private `pthread_impl` state and is
explicitly excluded; the leaf never decodes or dereferences a timer handle. It
does not establish valid timer-control values, timer ownership/state/lifecycle,
signal delivery, clock/calendar/time-zone policy, cancellation, dynamic runtime,
family completion, promotion, or public x86 support.

`libc-time-observation` is a separately recorded
`static-c-time-observation` `verified_artifact` gate over that archive, not a
C time-runtime capability. Its project-header C body first executes through
pinned musl and then through a `-nostdlib -static` candidate. It selects only
`clock`, `time`, C11 `timespec_get`, `clock_getres`, and `gettimeofday`:
normalized realtime/CPU records, integer-second/window consistency, `TIME_UTC`
and unsupported-base behavior, invalid-clock errors, and stale errno
preservation. The candidate emits direct
`clock_gettime=228`, `clock_getres=229`, and `gettimeofday=96` rdi/rsi paths;
it deliberately ignores obsolete timezone output and owns no vDSO resolver or
dynamic runtime state. It excludes calendar/timezone state, clock mutation,
POSIX timers, cancellation, dynamic runtime, and public x86 support.

`libc-difftime` is a separately recorded `static-c-difftime-binary64`
`verified_artifact` gate over that archive, not C time-family completion. Its
project-header C body first executes through pinned musl and then through a
`-nostdlib -static` candidate; a C++ header object keeps the same unmangled
declaration. It selects only scalar `difftime`: ordinary positive, negative,
and zero results, INT64_MAX/INT64_MIN endpoint values, and the 2047
subtract-before-binary64-conversion case. Cross-endpoint signed overflow has no
C-source contract and remains unselected. The candidate has no syscall,
errno/TLS, clock observation, timezone/calendar policy, formatting, timer, or
floating-environment policy; it excludes dynamic runtime and public x86
support.

`libc-timegm` is a separately recorded `static-c-timegm-utc`
`verified_artifact` gate over that archive, not C calendar or time-family
completion. Its GNU/BSD project-header C body first executes through pinned
musl and then through a `-nostdlib -static` candidate. It selects only the
caller-owned fixed-UTC `timegm` normalization: epoch, negative-month, leap
carry, valid pre-epoch `-1` with stale errno preserved, and `EOVERFLOW` with
the complete input record unchanged. A success writes `tm_isdst=0`,
`tm_gmtoff=0`, and immutable `UTC`; the candidate makes no syscall and reads
no `TZ`, environment, timezone global, or zoneinfo. It excludes
`gmtime`/`mktime`, local conversion, calendar formatting/parsing, clock
observation/mutation, POSIX timers, cancellation, dynamic runtime, and public
x86 support.

`libc-gmtime-r` is a separately recorded `static-c-gmtime-r-utc`
`verified_artifact` gate over that archive, not C calendar or time-family
completion. Its POSIX project-header C body first executes through pinned musl
and then through a `-nostdlib -static` candidate. It selects only the
caller-buffered UTC `gmtime_r` conversion: epoch, pre-epoch, and leap-day
records with stale errno preserved, plus null/`EOVERFLOW` with the complete
caller output record unchanged. A success returns the caller's output pointer and
writes `tm_isdst=0`, `tm_gmtoff=0`, and immutable `UTC`; the candidate makes
no syscall and reads no `TZ`, environment, timezone global, or zoneinfo. It
excludes non-reentrant storage, local/inverse conversion, calendar
formatting/parsing, clock observation/mutation, POSIX timers, cancellation,
dynamic runtime, and public x86 support.

`libc-system-configuration` is a separately recorded
`static-c-system-configuration` `verified_artifact` gate over that archive,
not a general system-information, filesystem, or runtime capability. Its
project-header C body first executes through pinned musl and then through a
`-nostdlib -static` candidate. It selects only the `_SC_CLK_TCK` and
`_SC_PAGE_SIZE`/`_SC_PAGESIZE` `sysconf` queries, musl's bounded
`confstr` copy/truncation behavior, all twenty-one table-based
`pathconf`/`fpathconf` selectors, the fixed x86 Linux `getpagesize`, and the
`RLIMIT_NOFILE`-clamped `getdtablesize` query. Valid path-configuration
selectors deliberately neither read a pathname nor consume a file descriptor,
including valid indeterminate `-1` values that preserve stale `errno`;
invalid selectors return `EINVAL`. The candidate emits only
`prlimit64=302` for `getdtablesize` and rejects accidental path-configuration
syscalls. The corresponding AArch64 implementation now uses this same table,
with `tests/path_configuration_exports.rs` dynamically comparing it to pinned
musl without filesystem access. This is agreement for this selected cluster,
not evidence that the two platforms are otherwise behaviorally identical. It
excludes the rest of musl's
`sysconf` table, `statfs`/`statvfs`, filesystem policy, `/proc`, startup-owned
auxv/`getauxval`, dynamic runtime, and public x86 support.

`libc-getpagesize` is a separate private `static-c-getpagesize`
`verified_artifact`, derived from the existing
`system_configuration.rs` owner rather than a new configuration subsystem.
Pinned musl 1.2.6 `src/legacy/getpagesize.c` returns `PAGE_SIZE`; its x86_64
limits source fixes that result at 4096. After the GNU/BSD-only C/C++ header
gate, the fixture runs the same C body against pinned musl and then links one
true `-nostdlib -static -Wl,--gc-sections` candidate. Direct and
function-pointer calls both return 4096. Although the source object also owns
the selected system-configuration entries, final-link collection retains only
`getpagesize` and rejects `sysconf`, `confstr`, `pathconf`,
`fpathconf`, `getdtablesize`, errno/TLS, auxv, filesystem, allocator, PLT,
and call/syscall paths. This does not alter or promote
`static-c-system-configuration`; it is not general page-size discovery,
`sysconf`/path configuration, C-runtime, CRT, or public x86 support.

`libc-mapping-core` is a separately recorded `static-c-mman-mapping-core`
`verified_artifact` gate over that archive, not a general C mapping or runtime
capability. Its project-header C body first executes through pinned musl and
then through a `-nostdlib -static` candidate, while the paired C/C++
`sys/mman.h` gate checks the named declarations. It selects exactly `mmap`,
`munmap`, `mprotect`, `madvise`, `posix_madvise`, and `mincore`: musl's
4096-byte mapping-offset and `PTRDIFF_MAX` rejections, anonymous non-fixed
`EPERM` to `ENOMEM` fallback, page-rounded `mprotect`, ordinary advice/errno,
POSIX `DONTNEED` no-op/direct-positive-error behavior, and full/partial
residency vectors. The archive's explicit local no-op `__vm_wait` site records
that it has no musl loader/allocator process-wide VM synchronization contract.
It excludes its separate direct no-cancellation `msync` sibling, full musl
`msync` cancellation semantics, `mremap`, `mlock*`, remap/shared-memory and
memfd paths, mapping policy, allocator, libc.so, CRT, loader, sysroot, and
public x86 support. This is one artifact within planned `libc.posix-runtime`,
not full `<sys/mman.h>`, family, C-runtime, or platform completion.

`libc-memory-sync` is a separately recorded private planned
`static-c-memory-sync` evidence artifact over that archive, not a general C
mapping or runtime capability. Its project-header C body first executes
through pinned musl and then through a `-nostdlib -static` candidate, after the
eight-profile C/C++ declaration gate. It selects only caller-owned direct
no-cancellation `msync`: x86 `msync=26`, all three public `MS_*` bits,
stale-`errno` success, and Linux 5.10's flag-first and
alignment-before-zero-length validation order over a disposable private
anonymous mapping. Pinned musl uses `syscall_cp`; this candidate deliberately
has no cancellation state machine, so it does not establish musl cancellation
semantics or full C ABI parity. It also does not prove file-backed shared-map
writeback or invalidation, persistence, durability, VM-wide synchronization,
`mremap`, mapping policy, allocator, libc.so, CRT, loader, sysroot, promotion,
or public x86 support. This is one planned evidence artifact within
`libc.posix-runtime`, not full `<sys/mman.h>`, family, C-runtime, or platform
completion.

`libc-memory-locking` is a separately recorded
`static-c-memory-locking` `verified_artifact` gate over that archive, not a
general C mapping or runtime capability. Its project-header C body first
executes through pinned musl and then through a `-nostdlib -static` candidate,
while the paired six-profile C/C++ `sys/mman.h` gate checks declarations. It
selects exactly `mlock`, `munlock`, and GNU `mlock2(MLOCK_ONFAULT)`: musl's
`flags=0` delegation to `mlock`, direct x86 `mlock=149`, `munlock=150`, and
`mlock2=325`, stale-errno success, first-fault locking, invalid-flag `EINVAL`,
and overflow-range `EINVAL`. Linux's `EPERM`/`EAGAIN`/`ENOMEM` memlock result
is accepted where locking is not available. It excludes cancellation,
`mlockall`/`munlockall`, the separate direct `msync` sibling, `mremap`, mapping
policy, allocator, libc.so, CRT, loader, sysroot, and public x86 support. This
is one artifact within planned `libc.posix-runtime`, not full `<sys/mman.h>`,
family, C-runtime, or platform completion.

`libc-memfd-create` is a separately recorded private planned
`static-c-memfd-create` evidence artifact over that archive, not a descriptor,
filesystem, or C-runtime capability. Its GNU project-header C body first
executes through pinned musl and then through a `-nostdlib -static` candidate,
after the eight-profile GNU-only C/C++ declaration gate. It selects only
direct x86 `memfd_create=319`, the selected initial-TLS `errno` boundary,
ordinary and 249-byte labels, creation-flag forwarding, stale `errno` on
success, and Linux's 250-byte/all-ones-flag-word `EINVAL` and bad-pointer
`EFAULT` results; fixture-local raw close cleanup does not select a C close API. It
does not establish seals or C `fcntl`, `memfd_secret`, huge-page resource or
page-size policy, descriptor lifecycle, broad filesystem behavior, libc.so,
CRT, loader, sysroot, family/platform parity, promotion, or public x86
support. This is one planned evidence artifact within `libc.posix-runtime`,
not full `<sys/mman.h>`, family, C-runtime, or platform completion.

`libc-header-layouts-baseline` is a separately recorded
`static-c-header-layouts-baseline` artifact within planned
`libc.headers-layouts`, not header or C-runtime completion. It runs the
existing types/stat/time/poll/select/fcntl/unistd/system/signal/termios/mman/
resource/socket C/C++ header gates, then links one C fixture and one
freestanding C++17 companion through the existing static archive after the
same pair succeeds with pinned musl. The C++ entry has C linkage and is called
from C; the runner proves its selected archive references are unmangled and
rejects standard C++ headers, constructors, exceptions, RTTI, C++ runtime
helpers, and dynamic TLS. It consumes only the already selected errno, stat,
clock, mapping, resource, readiness, socket/close, signal-mask, termios,
uname/sysinfo, and page-size leaves. It adds no C export or project header,
and does not claim every installed header, complete C++ support, a general C
ABI, libc.so, CRT, loader, sysroot, or public x86 support.

`libc-nanosleep` is a separately recorded `static-c-nanosleep`
`verified_artifact` gate over that archive, not a C time or runtime capability.
Its project-header C body first executes through pinned musl and then through
a `-nostdlib -static` candidate. It selects only `nanosleep`'s normal
zero-or-`-1`/`errno` convention: zero completion preserves stale errno,
invalid and null requests produce `EINVAL`/`EFAULT`, and a delivered signal
produces `EINTR` with a positive remaining interval. The candidate emits
`nanosleep=35` through rdi/rsi and writes the selected initial-TLS errno slot
on error. Musl's `nanosleep` delegates through its relative realtime
`clock_nanosleep` route to `__syscall_cp` cancellation machinery; this direct
leaf intentionally omits pthread cancellation until the x86 pthread/TLS
runtime exists. The separate `static-c-sleep` artifact may delegate to this
boundary, but this fixture rejects it from its final candidate; `usleep`, C
clock/timer state, signal policy, dynamic runtime, and public x86 support
remain excluded here.

`sleep-header-abi` and `libc-sleep` are a separate private `static-c-sleep`
`verified_artifact`, not C time or runtime completion. The all-profile
project/pinned-musl C11/C++17 `<unistd.h>` gate fixes only the unconditional
`unsigned int sleep(unsigned int)` declaration and C++ linkage. Its common
project-header C body first executes through pinned musl and then through a
`-nostdlib -static` candidate. It proves musl 1.2.6 `src/unistd/sleep.c`'s
one-call wrapper over the selected `nanosleep` boundary: `sleep(0)` preserves
stale `errno`, while fixture-local `SIGALRM` makes `sleep(2)` return a nonzero
truncated whole-second remainder with `EINTR`. The archive/object and final
ELF checks require one `sleep` export, one `nanosleep` relocation, and no
direct syscall or errno/TLS access in the wrapper. The raw timer and selected
signal setup are test plumbing only: this does not select `usleep`, pthread
cancellation, wake timing, signal/mask policy, clock or timer control,
dynamic runtime, family completion, promotion, or public x86 support.

`libc-usleep` is a separately recorded `static-c-usleep` `verified_artifact`
over that archive, not a C sleep or timer capability. Its project-header C
body first executes through pinned musl and then through a `-nostdlib -static`
candidate. It retains musl's whole source closure in `src/unistd/usleep.c`:
`unsigned int` microseconds normalize to one local LP64 `timespec`, and the
same record passes as both arguments to the selected `nanosleep(&tv, &tv)`
seam. Completion preserves stale errno; fixture-only raw-SIGALRM interruption
produces `-1`/`EINTR` at 1000000, 1000001, and `UINT_MAX`. It excludes
`sleep`, `alarm`, `ualarm`, timer state, signal policy, pthread policy, dynamic
runtime, and public x86 support.

`libc-clock-nanosleep` is a separately recorded
`static-c-clock-nanosleep` `verified_artifact` gate over that archive, not a C
time or runtime capability. Its project-header C body first executes through
pinned musl and then through a `-nostdlib -static` candidate. It selects only
`clock_nanosleep`'s zero-or-positive-errno convention: zero and absolute-past
completion, invalid request/clock errors, relative `EINTR` with a positive
remaining interval, and absolute `EINTR` with a null remaining pointer. The
candidate emits `clock_nanosleep=230` through rdi/rsi/rdx/r10 and never reads
or writes errno; it retains musl's local `CLOCK_THREAD_CPUTIME_ID` `EINVAL`
rule because raw Linux returns `EOPNOTSUPP`; fixture-local initial TLS exists
only for the selected signal helper. Musl routes relative `CLOCK_REALTIME`
requests through `nanosleep` and uses `__syscall_cp` as a cancellation point;
the direct leaf intentionally uses syscall 230 for every remaining clock and
omits pthread cancellation without calling or depending on the separately
selected `nanosleep` leaf. It excludes `sleep`/`usleep`, C clock/timer state,
signal policy, pthread/TLS lifecycle, `libc.so`, CRT, loader, sysroot, and
public x86 support.

`libc-descriptor-entry` is a separately recorded
`static-c-descriptor-entry` `verified_artifact` gate over that archive, not a
descriptor/filesystem capability. Its project-header C body first executes
through pinned musl and then through a `-nostdlib -static` candidate. It
selects only `open`, `openat`, and `creat`: optional C mode consumption only
for `O_CREAT` or the complete `O_TMPFILE` mask, forced `O_LARGEFILE`,
`open=2`, `openat=257` with the fourth syscall word in `r10`, and musl's
private ignored-result `F_SETFD`/`FD_CLOEXEC` post-step after a successful
`open(O_CLOEXEC)`. Fixture-local raw `fcntl` calls only create/observe the
temporary descriptor state; they do not exercise the separately selected
public C `fcntl` status-control entry. The artifact
proves no-mode and required-mode calls, relative lookup, create/truncate
behavior, descriptor flags, and direct errno results. It excludes pathname
policy, a filesystem capability, cancellation, dynamic runtime, and public
x86 support.

`libc-access` is a separately recorded `static-c-filesystem-access`
`verified_artifact` gate over that archive, not a filesystem capability. Its
project-header C body first executes through pinned musl and then through a
`-nostdlib -static` candidate. It selects exactly `access`, `faccessat`,
`euidaccess`, and weak same-address `eaccess`: `access=21` performs the
real-ID check, zero flags use `faccessat=269`, and nonzero flags use
`faccessat2=439` through `r10`. A runner-provisioned root-owned mode-0400
record plus fixture-local raw child prove real/effective credential separation,
descriptor-relative and final-symlink behavior, direct errno results, stale
errno on success, and a strong caller override of the weak alias. It excludes
path/permission policy, `fchmodat`, general C credential/process
behavior, cancellation, dynamic runtime, and public x86 support.

`libc-fcntl-status-control` is a separately recorded
`static-c-fcntl-status-control` `verified_artifact` gate over that archive,
not a descriptor/filesystem capability or generic C `fcntl` implementation.
Its project-header C body first executes through pinned musl for only
`F_GETFD`, `F_SETFD`, `F_GETFL`, and `F_SETFL`, then through a
`-nostdlib -static` candidate. Its assembly dispatcher preserves the variadic
C ABI: two-word getter calls receive an explicit Linux `rdx=0`, while only
the two setters use the scalar third word. The fixture's raw setup/teardown
keeps the candidate independent of the C open/dup/close artifacts; it proves
descriptor-local `FD_CLOEXEC`, shared open-file-description status flags over
a raw duplicate, the musl `F_SETFL` `O_LARGEFILE` rule, stale errno on all
four successful calls, and direct `EBADF` errors. The shared dispatcher routes
the separately selected `F_GETLK`/`F_SETLK` pointer forms to their sibling;
every remaining public C command, including `F_GETOWN`, `F_DUPFD*`, OFD locks,
ownership, leases, and seals, deliberately returns `-1`/`EINVAL` before a
vararg is observed or a syscall runs. The broader header declarations and the
separate direct Rust `F_GETLK`/status/seal slices do not widen this C artifact.
It excludes `lockf`/`flock`, cancellation, generic descriptor or filesystem
policy, general runtime, and public x86 support.

`libc-fcntl-record-locks` is a separately recorded
`static-c-fcntl-record-locks` `verified_artifact` gate over the same archive,
not a descriptor/filesystem capability or generic C `fcntl` implementation.
Its project-header C body runs through pinned musl and then a
`-nostdlib -static` candidate for only pointer-bearing nonblocking
`F_GETLK`/`F_SETLK` calls. The shared dispatcher preserves the caller's
`struct flock *` in `rdx`; the fixture proves the public x86 record layout,
unlocked query, child-observed parent lock/PID and conflict, release, stale
errno on success, and direct `EBADF`/`EINVAL` failures. It does not select
`F_SETLKW` cancellation, OFD locks, `lockf`, `flock`, generic `fcntl`, lock
ownership/signalling policy, descriptor/pathname policy, general runtime, or
public x86 support.

`libc-flock` is a separately recorded `static-c-flock` `verified_artifact`
gate over the same archive, not a general locking or descriptor capability.
Its project-header C/C++ `<sys/file.h>` gate runs before a pinned-musl and
`-nostdlib -static` candidate fixture for only direct nonblocking `flock`.
It proves the x86 operation bits, duplicate open-file-description release
state, a separately opened child conflict and later exclusive reacquisition,
stale errno on success, and direct `EWOULDBLOCK`/`EAGAIN`, `EBADF`, and
`EINVAL` errors. It does not select `fcntl` record-lock interaction, `lockf`,
generic descriptor/pathname policy, network/distributed-filesystem semantics,
general runtime, or public x86 support.

`libc-sendfile` is a separately recorded `static-c-sendfile`
`verified_artifact` gate over the same archive, not a general descriptor
transfer capability. Its project-header C/C++ `<sys/sendfile.h>` gate runs
before a pinned-musl and `-nostdlib -static` candidate fixture for direct
regular-file transfer. It proves `sendfile=40` x86 ABI forwarding, explicit
offset advance without input-position mutation, null-offset short transfer and
EOF zero, stale errno on success, and `EINVAL`/`EBADF` errors. It does not
select pathname, socket/pipe, splice, copy-file-range, vector-I/O, durability,
cancellation, general runtime, or public x86 support.

`libc-tee` is a separately recorded `static-c-tee` `verified_artifact` gate
over the same archive, not a general pipe or descriptor capability. Its
project-header C/C++ GNU `<fcntl.h>` gate runs before a pinned-musl and
`-nostdlib -static` candidate fixture for direct pipe-buffer duplication. It
proves `tee=276` x86 ABI forwarding, source bytes remain readable after an
equal destination-pipe copy, zero-length stale errno on success, and direct
`EBADF`. It does not select pipe creation/ownership, generic descriptor
policy, `splice`/`vmsplice`, cancellation, general runtime, or public x86
support.

`libc-splice` is a separately recorded `static-c-splice` `verified_artifact`
gate over the same archive, not a descriptor, pipe, or transfer capability.
Its project-header C/C++ GNU `<fcntl.h>` gate runs before a pinned-musl and
`-nostdlib -static` candidate fixture for one regular-file-to-pipe
explicit-input-offset request. It proves `splice=275` x86 ABI forwarding,
raw/wrapper result and pointed-offset agreement, copied pipe bytes, retained
file position, stale `errno` on success, and direct invalid-flags `EINVAL` plus
bad-input `EBADF`. It does not select pathname or descriptor/pipe ownership,
blocking, fallback, general pipe/filesystem transfer policy,
`tee`/`vmsplice`/`sendfile`/`copy_file_range`, durability, cancellation,
general runtime, or public x86 support.

`libc-sync-file-range` is a separately recorded
`static-c-sync-file-range` `verified_artifact` gate over the same archive, not
a descriptor/filesystem capability. Its project-header C/C++ GNU `<fcntl.h>`
gate runs before a pinned-musl and `-nostdlib -static` candidate fixture for
one direct regular-file range request. It proves `sync_file_range=277` x86 ABI
forwarding, exact raw result/`errno` agreement, retained shared descriptor
position, stale `errno` on success, and direct invalid-flags `EINVAL` and
bad-descriptor `EBADF`. It does not select pathname or descriptor ownership,
cache/writeback policy or durability, `sync`/`syncfs`, `fallocate`,
cancellation, general runtime, or public x86 support.

`libc-copy-file-range` is a separately recorded
`static-c-copy-file-range` `verified_artifact` gate over the same archive, not
a descriptor/filesystem capability. Its project-header C/C++ GNU `<unistd.h>`
gate runs before a pinned-musl and `-nostdlib -static` candidate fixture for
one same-filesystem regular-file explicit-offset request. It proves
`copy_file_range=326` x86 ABI forwarding, raw/wrapper result and pointed-offset
agreement, copied bytes, retained shared descriptor positions, stale `errno`
on success, and direct invalid-flags `EINVAL` plus bad-input `EBADF`. It does
not select pathname or descriptor ownership, copy fallback or cross-filesystem
policy, `sendfile`/`splice`, durability, cancellation, general runtime, or
public x86 support.

`libc-posix-fallocate` is a separately recorded
`static-c-posix-fallocate` `verified_artifact` gate over the same archive, not
a general allocation or descriptor capability. Its strict/no-feature and
large-file-only C/C++ `<fcntl.h>` profiles run before a pinned-musl and
`-nostdlib -static` candidate fixture for direct mode-zero range allocation.
It proves `fallocate=285` forwarding with signed LP64 offsets, an unlinked
range [4096, 8192) with retained prefix, zero-fill, and stable file
position, and the POSIX direct positive `EINVAL`/`EBADF` returns without
changing `errno`. It does not select general `fallocate` flags, pathname or
filesystem policy, durability, cancellation, general runtime, or public x86
support.

`libc-descriptor-advice` is a separately recorded
`static-c-descriptor-advice` `verified_artifact` gate over the same archive,
not a descriptor/filesystem capability. Its strict/no-feature, GNU-only, and
large-file-only C/C++ `<fcntl.h>` profiles run before a pinned-musl and
`-nostdlib -static` candidate fixture. It proves only unconditional
`posix_fadvise` and all six `POSIX_FADV_*` values, GNU-only `readahead`, and
the LF64-only `posix_fadvise64` macro alias to the unmangled base. The fixture
proves direct `fadvise64=221` positive `EINVAL`/`EBADF` returns without errno
publication, `readahead=187` `-1`/published-errno behavior, zero-length
advice, and stable file position/size over an unlinked regular file. It makes
no cache-residency or cache-effect claim. It does not select cache policy or
effects, allocation, pathname or filesystem policy, durability, cancellation,
general runtime, or public x86 support.

`libc-filesystem-capacity` is a separately recorded
`static-c-filesystem-capacity` `verified_artifact` gate over the same archive,
not a filesystem capacity capability. Its dedicated `sys/statfs.h`/
`sys/statvfs.h` C/C++ matrix runs before pinned-musl and `-nostdlib -static`
fixture execution for exactly `statfs`, `fstatfs`, `statvfs`, and `fstatvfs`.
It proves `statfs=137`/`fstatfs=138`, zeroed public statfs records, and musl
`src/stat/statvfs.c`'s successful zero-and-map statvfs conversion, including
fragment-size fallback, `f_favail=f_ffree`, first-fsid-word mapping, stale
errno success, and direct ENOENT/EBADF results. It does not select capacity or
quota meaning, filesystem accounting/policy, pathname behavior, durability,
cancellation, general runtime, or public x86 support.

`libc-vector-io` is a separately recorded `static-c-vector-io`
`verified_artifact` gate over the same archive, not a vector-I/O capability.
Its fourteen-profile `<sys/uio.h>` C/C++ matrix runs before pinned-musl and
`-nostdlib -static` fixture execution for exactly `readv`, `writev`, `preadv`,
and `pwritev`. It proves x86 vector ABI/register paths, segment order,
unchanged positioned offsets, kernel invalid-count/signed-offset errors, and a
sparse offset above 4 GiB independently observed with raw `lseek`. It retains
musl's selected `pwritev` `-1 -> -2` and append-protection boundary, while
deliberately deferring cancellation. It does not select v2/process-vm runtime,
scalar descriptor I/O, stdio, general runtime, or public x86 support.

`libc-ioctl` is a separately recorded `static-c-generic-ioctl`
`verified_artifact` gate over the same archive, not generic device support.
After the direct `sys/ioctl.h` C/C++ matrix and a pinned-musl execution, its
freestanding candidate proves `ioctl=16` forwarding for `FIONREAD` pointer
output, `FIONBIO` pointer input, and the two legal no-vararg calls
`FIOCLEX`/`FIONCLEX`. The assembly boundary supplies `rdx=0` only for those
two request words; every other admitted call requires an explicit third
pointer or integer word, while other two-word forms remain outside the
artifact contract. It proves ABI forwarding and errno behavior, not arbitrary
request/device semantics, terminal/session policy, socket options,
cancellation, general runtime, or public x86 support.

`libc-descriptor-io` is a separately recorded static
`verified_artifact` gate over that archive, not a descriptor/filesystem
capability. Its project-header C body first executes through pinned musl and
then through a `-nostdlib -static` candidate. It selects only `close`,
read/write/pread/pwrite, signed lseek/ftruncate, fsync/fdatasync requests,
duplication, and pipe creation. Fixture-local raw `memfd_create`/`fcntl` calls
only create anonymous regular files and observe flags. The fixture proves
transfer and shared-position behavior, zero-fill/shrink position preservation,
the exact musl `pwrite` `-1`/O_APPEND boundary, duplication replacement and
close-on-exec behavior, and pipe flags. It excludes C open/path, generic fcntl-command, or vector
I/O, pthread cancellation/AIO integration, filesystem durability, general
runtime, and public x86 support.

`libc-descriptor-lifecycle` is a separately recorded private static
`verified_artifact` gate over that archive, not a descriptor/filesystem
capability. One project-header C body runs through pinned musl and then a
`-nostdlib -static` candidate, composing selected `open`/`openat`/`creat`,
public status-control `fcntl`, descriptor I/O, `fstat`/`fstatat`, duplication,
and close behavior in one PID-isolated relative-directory lifecycle. Raw
syscalls only create and remove that directory. It does not establish general
C runtime, cancellation, CRT, loader, sysroot, family completion, AArch64
parity, or public x86 support.

`libc-descriptor-pipeline` is a separately recorded private static
`verified_artifact` gate over the same archive, not a descriptor-readiness or
filesystem capability. Its project-header C body first executes through
pinned musl and then a `-nostdlib -static` candidate. It composes only already
selected `pipe2`, public status/descriptor-flag `fcntl`, `poll`,
`readv`/`writev`, `dup`, and `close` leaves through one nonblocking CLOEXEC
pipe lifecycle: empty/readable/hangup transitions, vector ordering, duplicate
read ownership after closing the original descriptor, selected flag mutation,
and initial-TLS errno preservation. It adds no API and excludes generic
descriptor/path policy, cancellation, AIO, CRT/TLS lifecycle, loader, sysroot,
family completion, AArch64 parity, and public x86 support.

`libc-timestamp-updates` is a separately recorded private static
`verified_artifact` over that archive, not a filesystem or C-runtime
capability. One project-header C body runs through pinned musl and then a real
archive-owned `rcrt1`/`crti`/`crtn` static PIE. It selects exactly
`utimensat`, `futimens`, strong `__futimesat` with weak same-address
`futimesat`, `futimes`, `lutimes`, `utimes`, and `utime`, including
`UTIME_NOW`, `UTIME_OMIT`, no-follow, timeval, and whole-second behavior. It
does not establish filesystem policy, dynamic libc, loader, CRT/sysroot,
family completion, AArch64 parity, or public x86 support.

`libc-process-resources` is a separately recorded static
`verified_artifact` gate over that archive, not a process-resource capability.
Its project-header C body first executes through pinned musl and then through
a `-nostdlib -static` candidate. It selects only `getrlimit`/`setrlimit`, GNU
`prlimit` and its source alias, `getrusage`, `getpriority`/`setpriority`, and
`nice`. The fixture proves all selected limit selectors, a child-contained
old-and-new `prlimit` transaction, a live-child target query, the 144-byte
initialized `rusage` prefix with its preserved public tail, raw priority
encoding, and the capability-conditional `nice` `EACCES` to `EPERM` mapping.
It excludes `times`, scheduler policy, cgroups, C process lifecycle,
pthread coordination, general runtime, and public x86 support.

`libc-sched-yield` is a separately recorded private `static-c-sched-yield`
artifact, not a scheduler capability. Its project-header C fixture first runs
against pinned musl and then through a `-nostdlib -static` candidate. It selects
only musl's status-returning `sched_yield(void)` bridge: normal success leaves
stale `errno` unchanged, while fixture-local seccomp forces raw `EPERM` and
proves `-1` with `errno=EPERM`. It excludes scheduler handoff, fairness,
policy/parameters, affinity, C11/pthread and process lifecycle, general
runtime, family completion, promotion, and public x86 support.

`libc-sched-getcpu` is a distinct private `static-c-sched-getcpu` GNU
current-CPU observation artifact, not a scheduler or time capability. Its
project-header fixture first runs against pinned musl and then through a true
`-nostdlib -static` candidate. Musl's x86 source may use a private vDSO
resolver/cache before its direct fallback; this artifact implements and proves
only direct `getcpu=309`, so a candidate-only seccomp-forced `EPERM` validates
the raw `-1`/errno conversion rather than comparing musl's vDSO route. Normal
nonnegative observations preserve stale errno. It excludes CPU/NUMA/cache
output, topology/migration policy, affinity, scheduler policy/parameters/
priority/yield, thread state, clocks/timers/calendar/timezone/environment,
general runtime, family completion, promotion, and public x86 support.

`libc-sched-cpucount` is a distinct private `static-c-sched-cpucount` GNU
caller-buffer bit-count artifact, not scheduler, affinity, or time support.
Its project-header C fixture runs first through pinned musl 1.2.6 and then
through a true `-nostdlib -static` candidate. It maps exactly to musl's
`src/sched/sched_cpucount.c::__sched_cpucount` bytewise eight-bit loop over a
valid caller-owned range, proving zero, partial, and full 128-byte masks plus
the `CPU_COUNT_S`/`CPU_COUNT` macro forwarding. It has no syscall, errno/TLS,
allocation, CPU state observation or mutation, scheduler policy/parameter/
priority/yield, clock/timer/calendar/timezone, or ambient runtime path.
Invalid caller storage, count conversion above `INT_MAX`, the rest of the
`CPU_*` macro family, family completion, promotion, and public x86 support
remain excluded.

`libc-sched-priority-bounds` is a separate private
`static-c-sched-priority-bounds` artifact, not scheduler or time support. Its
project-header C fixture first runs through pinned musl 1.2.6 and then a true
`-nostdlib -static` candidate. It maps exactly to musl's
`src/sched/sched_get_priority_max.c` pair of direct scalar queries, proving
`SCHED_OTHER`, `SCHED_FIFO`, `SCHED_RR` bounds and invalid-policy
`-1`/`EINVAL` conversion with stale errno retained on success. It excludes
policy selection/mutation, current-policy/parameter queries, affinity,
scheduler progress/fairness, threads, clocks/timers/calendar/timezone,
environment, family completion, promotion, and public x86 support.

`libc-readiness-waits` is the fixture for a separately recorded
`static-c-readiness-signal-waits` `verified_artifact` gate over that archive,
not a descriptor-readiness or
signal-wait capability. Its project-header C body first executes through
pinned musl and then through a `-nostdlib -static` candidate. It selects only
`poll`, GNU `ppoll`, `select`, `pselect`, `pause`, and `sigsuspend`.
The fixture proves empty/readable/hangup pipe readiness; musl-style private
timeout copies that leave public `ppoll`/`select`/`pselect` timeout records
unchanged; and pending-signal temporary-mask restoration for `ppoll`,
`pselect`, and `sigsuspend`. Musl routes these waits through cancellation-point
machinery; this direct static leaf intentionally omits that pthread
cancellation behavior. A race-free in-process trigger for `pause` is outside
the closed artifact, so `pause` is retained and proved only by its emitted
direct Linux syscall path. It does not exercise epoll/eventfd; the separate
`libc-event-descriptors` artifact owns those selected archive exports. It
excludes C open/path, generic fcntl-command, or vector I/O, AIO, generic
signal delivery/waits, pthread mask policy, timers,
process lifecycle, general runtime, and public x86 support.

`libc-system-observation` is the fixture for a separately recorded
`static-c-system-observation` `verified_artifact` gate over that archive, not
a general system-information capability. Its project-header C body first
executes through pinned musl and then through a `-nostdlib -static` candidate.
It selects only `uname` and `sysinfo`. The fixture proves null-pointer
`EFAULT` results, the 390-byte public `utsname` record, and the 368-byte
public `sysinfo` record. Linux performs its 112-byte `sysinfo` kernel write,
including the first four public `__reserved` bytes at offsets 108 through 111;
the caller-resident tail at offsets 112 through 367 retains its sentinel. It
excludes the separately recorded hostname/domain identity and processor/page
artifacts, system-file parsing, process identity, generic system information,
dynamic runtime, and public x86 support.

`libc-system-information` is the fixture for a separately recorded
`static-c-system-information` `verified_artifact` gate over that archive, not
a general system-information capability. Its project-header C body first runs
through pinned musl and then through a `-nostdlib -static` candidate. It
selects only `get_nprocs_conf`, `get_nprocs`, `get_phys_pages`, and
`get_avphys_pages`: the musl-shaped 128-byte raw affinity mask, CPU-zero
fallback after a child-local forced affinity error, and successful
`sysinfo`-derived physical/free-plus-buffer page calculations. It deliberately
does not select `getloadavg`, affinity control, topology/scheduler policy,
`/proc` parsing, general `sysconf`, dynamic runtime, or public x86 support.

`libc-getloadavg` is the fixture for a separate private `static-c-getloadavg`
`verified_artifact` gate over that archive, not a general system-information
capability. Its GNU/BSD-only project-header C/C++ declaration matrix and one
project-header C body first execute through pinned musl and then through a
`-nostdlib -static` candidate. It selects only historical `getloadavg`:
nonpositive count/no-output/stale-`errno` behavior, a positive three-entry
clamp, and caller-owned binary64 output against an adjacent raw `sysinfo`
snapshot. The musl source's failed `sysinfo` local-record read has no usable
output contract; the safe candidate reports that errno with `-1` and no
output. It excludes public `sysinfo`/`uname`, processor/page helpers, `/proc`,
topology or scheduler policy, general `sysconf`, dynamic runtime, and public
x86 support.

`libc-uts-identity` is a separately recorded
`static-c-uts-identity` `verified_artifact` gate over that archive, not a
namespace or system-information capability. Its project-header C body first
executes through pinned musl and then through a `-nostdlib -static` candidate.
It selects only `gethostname`, `sethostname`, `getdomainname`, and
`setdomainname` atop the separately selected `uname` record seam. It maps
pinned musl 1.2.6 `src/unistd/gethostname.c`, `src/linux/sethostname.c`,
`src/misc/getdomainname.c`, and `src/misc/setdomainname.c` respectively.
Each arm uses a fresh UTS namespace before either setter runs; only this canonical
Docker command gains `CAP_SYS_ADMIN`, so the fixture never changes the
container or host identity. It proves musl's bounded 65-byte hostname
copy/forced-NUL rule, the complete-fitting NUL-terminated domain-name copy,
and direct setter `EFAULT`/`EINVAL` results. It excludes namespace management,
gethostid/sethostid, system-file parsing, sysconf, process identity, general
runtime, and public x86 support.

`libc-network-byte-order` is a separately recorded private
`static-c-network-byte-order` `verified_artifact` inside still-planned
`libc.posix-runtime`, not resolver or Ethernet work. Its project-header C body
first runs through pinned musl 1.2.6 and then through a
`-nostdlib -static` candidate, selecting exactly `htonl`, `htons`, `ntohl`,
and `ntohs`. On little-endian x86 it proves the 32-bit `01 02 03 04` and
16-bit `01 02` wire-byte results, inverse round trips, and zero/all-one fixed
points while rejecting TLS, errno, allocation, syscall, and ambient runtime
paths. It does not select `inet_*` address conversion or scratch storage,
resolver configuration, DNS, netdb/database, Ethernet/interface behavior,
socket transport, general networking, family promotion, or public x86
support.

`libc-in6addr-any` is a separately recorded private `static-c-in6addr-any`
`verified_artifact` inside still-planned `libc.posix-runtime`, not resolver,
DNS, netdb, interface, Ethernet, or socket-runtime work. Its project-header C
fixture first runs through pinned musl 1.2.6 and then through an archive-free
`-nostdlib -static` candidate that receives exactly one extracted crabc object,
never `libc.a`. It proves the stable, global default read-only 16-byte
all-zero `in6addr_any` object from musl `src/network/in6addr_any.c`; the
independent final-octet-one `src/network/in6addr_loopback.c` object remains
separately selected and excluded from this candidate. The paired C/C++
socket-header gate proves the union-backed align-4 `struct in6_addr` and
unmangled C++ data references. It selects no
address conversion, errno, TLS, allocation, syscall, `/etc/hosts`,
`/etc/resolv.conf`, resolver/DNS/netdb, interface, Ethernet, socket transport,
family promotion, or public x86 support.

`libc-in6addr-loopback` is a separately recorded private
`static-c-in6addr-loopback` `verified_artifact` inside still-planned
`libc.posix-runtime`, not resolver, DNS, netdb, interface, Ethernet, or
socket-runtime work. Its project-header C fixture first runs through pinned
musl 1.2.6 and then through an archive-free `-nostdlib -static` candidate that
receives exactly one extracted crabc object, never `libc.a`. It proves the
stable, global default read-only 16-byte `in6addr_loopback` object from musl
`src/network/in6addr_loopback.c`: fifteen zero bytes followed by one. The
independent all-zero `src/network/in6addr_any.c` object is separately selected
but excluded from this candidate. The paired C/C++ socket-header gate proves
the union-backed align-4 `struct in6_addr` and unmangled C++ data references.
It selects no address conversion, errno, TLS, allocation, syscall,
`/etc/hosts`, `/etc/resolv.conf`, resolver/DNS/netdb, interface, Ethernet,
socket transport, family promotion, or public x86 support.

`libc-socket-transport` is a separately recorded
`static-c-socket-transport` `verified_artifact` gate over that archive, not a
general socket capability. Its project-header C body first executes through
pinned musl and then through a `-nostdlib -static` candidate. It selects only
`socket`/`socketpair`, `bind`/`listen`/`accept`/`accept4`/`connect`,
`send`/`recv`/`sendto`/`recvfrom`, `shutdown`, `getsockname`, and
`getpeername` on local-only Unix or loopback endpoints. The direct Linux 5.10
paths atomically observe `SOCK_CLOEXEC|SOCK_NONBLOCK` on `socket`,
`socketpair`, and `accept4`, deliberately have no pre-5.10 fallback, and no
pthread-cancellation machinery; the canonical generic container grants the
command no additional capabilities. It excludes socket options, vector or
ancillary-message APIs, resolver/netdb state, interface ioctls, general socket
policy, dynamic runtime, and public x86 support.

`libc-socket-messages` is a separately recorded private
`static-c-socket-messages` `verified_artifact` gate inside still-planned
`libc.posix-runtime`, not a general socket capability. Its POSIX/GNU/BSD
project-header/pinned-musl C/C++ matrix runs before one `-nostdlib -static`
fixture checks exactly `setsockopt`, `getsockopt`, `sendmsg`, `recvmsg`,
`sendmmsg`, `recvmmsg`, and `sockatmark`. The archive adapts musl's padded
public message records, bounds outgoing ancillary copying to 1056 bytes,
loops padded `sendmsg` rather than issuing raw `SYS_sendmmsg=307`, and uses
direct `recvmmsg` and `SIOCATMARK`. Cancellation is explicitly deferred. It
does not select resolver/netdb, generic socket/options/ancillary/ioctl
behavior, dynamic runtime, family/platform parity, or public x86 support.

`libc-sysv-semaphore` is a separately recorded
`static-c-sysv-semaphore` `verified_artifact` gate over that archive, not a
complete SysV IPC capability. The project-header fixture first executes
through pinned musl and then through a `-nostdlib -static` candidate. It
selects only `semget`, `semop`, `semtimedop`, and variadic `semctl`, including
the caller-supplied `union semun` machine-word ABI, selected scalar/pointer commands,
and the five no-vararg commands with an explicit zero union word. It proves
the `semget` oversized-count `EINVAL` precheck, operation/timeout forwarding,
raw errors, stale errno on success, and `IPC_RMID` cleanup. It excludes SysV
message queues and shared memory from this semaphore artifact itself; the
separate `libc-sysv-message-shared-memory` artifact selects their bounded
adjacent C routes. Named/timed POSIX semaphores, `SEM_UNDO` and cross-process
lifecycle policy, cancellation, dynamic runtime, family completion, full
x86-64 parity, and public x86 support remain excluded.

`posix-semaphore-header-abi` is the paired C/C++ project-header/pinned-musl
`semaphore.h` declaration/layout gate. It keeps musl's full declaration
surface visible—including named and timed forms—while proving the x86 32-byte
align-4 volatile-word `sem_t`, its `timespec` dependency, and C++ linkage.
`libc-posix-semaphore` records the separate private
`static-c-posix-semaphore` artifact: the same C body first executes through
pinned musl, then through a `-nostdlib -static` archive candidate. It selects
only unnamed `sem_init`, `sem_destroy`, `sem_getvalue`, `sem_trywait`,
`sem_wait`, and `sem_post`; it proves their errno/stale-errno boundaries,
the `SEM_VALUE_MAX` overflow check, and a caller-owned `MAP_SHARED` pshared
parent/child futex handoff. `sem_timedwait`, named semaphores, cancellation
cleanup, signal-action restart policy, destruction races, general POSIX IPC,
and public x86 support remain outside this artifact.

`mq-setattr-header-abi` is a project-first/pinned-musl C/C++ `mqueue.h`
declaration/layout gate for only `mq_setattr`: signed four-byte `mqd_t`, the
64-byte align-8 LP64 `mq_attr` record, `mq_getsetattr=245`, and unmangled C++
linkage. Its paired `libc-mq-setattr` command records the private
`static-c-mq-setattr` artifact. The same one-symbol C fixture first executes
through pinned musl and then through a `-nostdlib -static` archive candidate;
it selects only `mq_setattr(mqd_t, const struct mq_attr *, struct mq_attr *)`,
the `O_NONBLOCK` replacement, optional prior-attribute result, stale `errno`
on success, and direct `EINVAL`/`EBADF` outcomes. It does not select queue
open/close/unlink, transfer, notification, timed operations, general IPC, a
Rust facade contract, cancellation, dynamic runtime, family completion, or
public x86 support.

`libc-sysv-message-shared-memory` is a separately recorded private
`static-c-sysv-message-shared-memory` `verified_artifact` gate over that
archive, not complete SysV IPC. Its project-header C body first executes
through pinned musl and then through a `-nostdlib -static` candidate. It
selects only `ftok`, `msgget`, `msgsnd`, `msgrcv`, `msgctl`, `shmget`, `shmat`,
`shmdt`, and `shmctl`. The fixture proves an `IPC_PRIVATE` nonblocking local
message-queue lifecycle, a local shared-memory attach/status/detach/remove
lifecycle, raw errors and stale errno on success, the x86 `r10`/`r8` syscall
argument paths, musl's `shmget` rewrite above `PTRDIFF_MAX`, and the exact
`shmat` `(void *)-1` error sentinel. `msgsnd` and `msgrcv` deliberately omit
musl's cancellation machinery because that runtime lifecycle remains
unselected. It excludes general POSIX IPC beyond the separately selected
one-symbol `mq_setattr` artifact, semaphores, broader SysV operations and
namespace/permission policy, cancellation, dynamic runtime, header/runtime
family completion, promotion, full x86-64 parity, and public x86 support.

`libc-event-descriptors` is a separately recorded private
`static-c-event-descriptors` `verified_artifact` gate over that archive, not
an event-descriptor or header-family completion claim. Its project-header C
body first executes through pinned musl and then through a `-nostdlib -static`
candidate. It selects only `epoll_create`, `epoll_create1`, `epoll_ctl`,
`epoll_wait`, `epoll_pwait`, `eventfd`, `eventfd_read`, `eventfd_write`,
`inotify_init`, `inotify_init1`, `inotify_add_watch`, and
`inotify_rm_watch`. It proves the packed x86 12-byte epoll event record,
`epoll_ctl`'s `r10` argument, and `epoll_pwait`'s `r10`/`r8`/`r9` arguments
with BPF-verified temporary-mask pointer and eight-byte kernel sigset size,
plus bounded eventfd and inotify lifecycles. The direct leaf deliberately
omits pthread cancellation and pre-Linux-5.10 `ENOSYS` fallbacks. It excludes
`epoll_pwait2`, fanotify, AIO, watcher policy, dynamic runtime, header/runtime
family completion, promotion, full x86-64 parity, and public x86 support. The
separately selected timerfd and signalfd archive leaves remain outside this
event-descriptor candidate.

`pathname-lifecycle-header-abi` is a separate eight-profile C11/C++17
project-header/pinned-musl matrix for the selected `fcntl.h`, `stdio.h`,
`sys/stat.h`, `sys/types.h`, and `unistd.h` C surface: exact LP64
`size_t`/`ssize_t`/`off_t`/`mode_t` spellings, mode and `O_PATH` constants,
and unmangled C++ references. Its paired `libc-pathname-lifecycle` private
`static-c-pathname-lifecycle` `verified_artifact` runs the same project-header
C body through pinned musl and then through a `-nostdlib -static` candidate.
It selects exactly `chdir`, `getcwd`, `mkdir`, `unlink`, `rmdir`, `remove`,
`rename`, `link`, `symlink`, `readlink`, `chmod`, `fchmod`, and `truncate`.
The fixture proves caller-buffer absolute `getcwd`, zero-capacity `readlink`,
`remove`'s raw-`EISDIR` rmdir retry, direct errors, link/rename/mode/truncate
lifecycle, and musl's live-`O_PATH` `fchmod` `/proc/self/fd` fallback. The
allocation-free candidate intentionally returns `EINVAL` instead of musl's
null-buffer `getcwd` allocation extension. It excludes allocation, pathname
canonicalization, directory streams, xattr/ACL, mount/namespace policy,
cancellation, dynamic runtime, header/runtime family completion, promotion,
full x86-64 parity, and public x86 support.

`libc-memccpy` is a separately recorded `static-c-memccpy`
`verified_artifact` inside still-planned `libc.posix-runtime`, not a general
memory or C-string capability. Its project-header fixture runs through pinned
musl 1.2.6, then through a true archive-free `-nostdlib -static` candidate
linked from exactly one extracted `memccpy` object, never `libc.a`.
It preserves musl `src/string/memccpy.c`'s equally misaligned byte prefix and
`ONES`/`HIGHS` marker-word check, low-eight-bit marker conversion, exact-range
return-after-marker/null behavior, and bounded page-edge input. It excludes
overlap support, `memcpy`/`memmove`/`memset`/`mempcpy`, errno/TLS, allocation,
syscalls, stdio, resolver/DNS/netdb, sockets, family completion, promotion,
and public x86 support.

`libc-aio-error` is a separately recorded `static-c-aio-error`
`verified_artifact` inside still-planned `libc.posix-runtime`, not AIO runtime
support. Its project-header fixture runs through pinned musl 1.2.6 and then a
true archive-free `-nostdlib -static` candidate linked from exactly one
extracted `aio_error` object, never `libc.a`. It preserves musl
`src/aio/aio.c`'s compiler-only barrier, volatile `__err` observation at the
x86 168-byte `aiocb`'s offset 112, and `0x7fffffff` sign-bit mask. AIO
submission, `aio_return`, waits, cancellation, completion, I/O, state,
errno/TLS, resolver/DNS/netdb, sockets, promotion, and public support remain
excluded.

`libc-byte-strings` is a separately recorded
`static-c-byte-strings` `verified_artifact` gate over that archive, not a
promotion of the Rust-subsumed text capabilities. Its project-header C body
first executes through pinned musl and then through a `-nostdlib -static`
candidate. It selects only `index`/`rindex`, `strchr`/`strchrnul`, `strcmp`,
GNU `strverscmp`, `strcspn`, `strlen`, `strncmp`, `strnlen`, `strpbrk`,
`strrchr`, `strspn`, and `strstr`. Musl's public `index` and `rindex` entries
are forwarding wrappers mapped to `strchr` and `strrchr`; its private
`__strchrnul` and `__memrchr` helpers remain internal, while GNU `strverscmp`
retains musl's scalar digit/leading-zero comparison state machine and scalar
fallback behavior as intentional implementation boundaries. The artifact
excludes stateful string, locale, allocation, vectorized, dynamic-runtime,
and public-x86-support claims.

`libc-legacy-memory` is a separately recorded `static-c-legacy-memory`
`verified_artifact`, not a `memory.bytes-basic` or allocator claim. Its
project-header C fixture first executes through pinned musl and then through a
true `-nostdlib -static` candidate made from exactly the one `bcopy`/`bzero`
adapter object and the established bulk-memory object. Musl's two wrappers map
`bcopy(source, destination, length)` to overlap-safe
`memmove(destination, source, length)` and `bzero(destination, length)` to
`memset(destination, 0, length)`. The candidate ratchets exact adapter exports
and only its direct `memmove`/`memset` dependencies, then proves zero-length
and overlapping copy plus bounded caller-buffer clearing. It has no allocator,
errno/TLS, locale, syscall, dynamic-runtime, CRT, loader, or sysroot path; it
does not select general bulk memory, `mempcpy`, `explicit_bzero`, allocator
lifecycle/interposition, family completion, promotion, or public x86 support.

`libc-memccpy` is a separately recorded `static-c-memccpy`
`verified_artifact`, not a `memory.bytes-basic` or allocator claim. Its
dedicated C/C++ header gate checks XOPEN/GNU/BSD visibility, strict/POSIX
hiding, and C linkage against pinned musl. Its project-header C fixture first
executes through pinned musl and then through a true `-nostdlib -static`
candidate made from exactly one object exporting only `memccpy`. The matrix
checks no-match/null returns, first-target one-past returns, source/destination
residues 0..7, length boundaries through 64, and signed/wide `int c`
narrowing. It has no allocator, errno/TLS, locale, syscall, dynamic-runtime,
CRT, loader, or sysroot path; it does not select general bulk memory,
`memory.bytes-basic`, `mempcpy`, `explicit_bzero`, allocator
lifecycle/interposition, family completion, promotion, or public x86 support.

`libc-mempcpy` is a separately recorded `static-c-mempcpy`
`verified_artifact`, not a `memory.bytes-basic` or allocator claim. Its
dedicated C/C++ header gate checks GNU-only visibility, default/strict/POSIX/XOPEN/BSD
C hiding, and C linkage against pinned musl. Its project-header C fixture first
executes through pinned musl and then through a true `-nostdlib -static`
candidate made from exactly one adapter object exporting only `mempcpy` and the
already selected bulk-memory object. It proves the direct `memcpy` relocation,
destination-plus-length returns, and exact copied/untouched bytes over
source/destination residues 0..7 and length boundaries through 64 including
zero. It has no allocator, errno/TLS, locale, syscall, dynamic-runtime, CRT,
loader, or sysroot path; it does not select general bulk memory,
`memory.bytes-basic`, `memccpy`, `explicit_bzero`, allocator
lifecycle/interposition, family completion, promotion, or public x86 support.

`libc-strsep` is a separately recorded `static-c-strsep`
`verified_artifact`, not a `memory.bytes-basic`, general-string, or allocator
claim. Its dedicated C/C++ header gate checks GNU/BSD visibility,
default/strict/POSIX/XOPEN C hiding, and C linkage against pinned musl. Its
project-header C fixture first executes through pinned musl and then through a
true `-nostdlib -static` candidate made from exactly one object exporting only
`strsep`. It proves first-delimiter in-place NUL replacement and caller
`char **` advancement for leading/consecutive/trailing delimiters, delimiter
sets, empty/no-match terminal state, high-bit bytes, and null stored state. It
has no allocator, errno/TLS, locale, syscall, dynamic-runtime, CRT, loader, or
sysroot path; it does not select general string/tokenization, `strtok`/
`strtok_r`, memory-search, `mempcpy`, getsubopt, allocator
lifecycle/interposition, family completion, promotion, or public x86 support.

`libc-strtok` is a separately recorded `static-c-strtok`
`verified_artifact`, not a `memory.bytes-basic`, general-string, reentrant, or
thread-safe-text claim. Its dedicated C/C++ header gate proves the
unconditional `<string.h>` ABI and C++ linkage across strict through BSD
profiles. Its project-header C fixture first executes through pinned musl and
then through a true `-nostdlib -static` candidate made from exactly one object
exporting only `strtok`. It proves leading delimiter skipping, one-byte in-place
NUL splitting, exhaustion, empty strings and delimiters, high-bit bytes,
replacement input, and the single shared non-TLS continuation when sequences
interleave. That cursor deliberately matches musl's historical `strtok` state,
not a reentrant or thread-safe tokenizer; concurrent unsynchronized calls are
outside its C contract. It has no allocator, errno/TLS, locale, syscall,
dynamic-runtime, CRT, loader, or sysroot path; it does not select `strtok_r`,
general string/tokenization, allocator lifecycle/interposition, family
completion, promotion, or public x86 support. The generic AArch64 export is
unchanged.

`libc-random-entropy` is a separately recorded
`static-c-random-entropy` `verified_artifact` gate over that archive, not a
promotion of the Rust random-source or random-state capabilities. Its
project-header C body first executes through pinned musl and then through a
`-nostdlib -static` candidate. It selects only `getrandom` and `getentropy`.
Musl's `getrandom` wrapper is a pthread cancellation point through
`syscall_cp`, while its bounded `getentropy` loop disables cancellation and
rejects lengths above 256 bytes; the direct leaf deliberately omits pthread
cancellation because that boundary remains deferred. The selected wrappers
translate direct Linux status through the initial-TLS errno slot. The fixture
proves initialized-prefix/length behavior, zero-length handling, direct
pointer/flag errors, and the 256-byte `EIO` boundary. It excludes C random-state
helpers, general pthread/TLS lifecycle, dynamic runtime, allocator, loader,
sysroot, and public x86 support.

`libc-memory-search` is a separately recorded
`static-c-memory-search` `verified_artifact` gate over that archive, not a
general C string capability. Its project-header C body first executes through
pinned musl and then through a `-nostdlib -static` candidate. It selects only
`memchr`, POSIX/GNU `memmem`, and GNU `memrchr`; musl's private `__memrchr`
helper remains internal and unexported. The leaf is stateless,
allocation-free, and has no errno/TLS or syscall boundary. It excludes general
string/locale/stateful text support, libc.so, dynamic runtime, allocator,
loader, sysroot, and public x86 support.

`libc-string-copy` is a separately recorded
`static-c-string-copy` `verified_artifact` gate over that archive, not a
general C string capability. Its project-header C body first executes through
pinned musl and then through a `-nostdlib -static` candidate. It selects only
`stpcpy`, `stpncpy`, `strcpy`, `strncpy`, `strcat`, `strncat`, `strlcpy`, and
`strlcat`; musl's private `__stpcpy`/`__stpncpy` helpers remain internal and
unexported. The scalar fallback is stateless and allocation-free, with no
errno/TLS or syscall boundary. It excludes bounded byte transfer,
duplication/allocation, token/locale state, libc.so, dynamic runtime,
allocator, loader, sysroot, and public x86 support.

`libc-error-strings` is a separately recorded `static-c-error-strings`
`verified_artifact` inside still-planned `libc.c-abi-compat`, not completion
of the broader `error.reporting-termination` capability. Its identical
project-header fixture runs through pinned musl 1.2.6 and a true
`-nostdlib -static` candidate, comparing a digest over every nonnegative x86
errno table index `0..=134`. Direct checks prove musl's immutable
`No error information` catch-all, caller-buffer ERANGE/truncation/NUL and
untouched-tail behavior, and weak same-address `__xpg_strerror_r`. The leaf
has no errno/TLS, allocator, mutable unknown buffer, or dynamic dependency.
It deliberately excludes negative-input musl undefined behavior, locale
objects/catalogs, `strsignal`, perror/err/warn diagnostics, `abort`, exit
hooks, variadic `syscall`, libc.so, CRT, loader, sysroot, promotion, and public
x86 support. The separate `libc-locale-error-strings` artifact owns the fixed
profile `strerror_l` spellings; this original error-reporting leaf neither
invokes nor establishes them.

`libc-allocator-string-duplication` is separately recorded as the
mixed-runtime `static-c-allocator-string-duplication` artifact rather than a
dependency-free string leaf. Its project-header body first runs through pinned
musl and then through the opt-in crabc client/wrapper/errno/backend archive.
It selects exactly `strdup` and `strndup`: a returned allocation is owned by
the existing `free` boundary; its bounded variant reads no byte beyond its
explicit limit. The runner rejects musl duplicate/allocator owners and proves
high-byte ownership, zero-limit and truncated output, stale errno, and
protected-page full/bounded inputs. It excludes allocator lifecycle, general
string or locale state, dynamic interposition/failure injection, full runtime
closure, promotion, and public x86 support.

`libc-strsignal` is the private selected `error.strsignal` slice within the
still-planned `libc.c-abi-compat` family. Its pinned-musl/project `<string.h>`
C/C++ matrix and static project-header differential select only strong
`strsignal`: immutable fixed C/POSIX/C.UTF-8 descriptions for Linux x86
signals `1..=64`, including the musl x86 `SIGHUP..SIGSYS` map and exact
`RT32` through `RT64` spellings. The common fixture verifies the shared
`Unknown signal` storage and hashes `-4..=68` through a sealed
`-nostdlib -static` candidate. It selects no locale/catalog translation,
`strerror`/`strerror_l`, `psignal`, perror/err/warn, signal
delivery/disposition, termination, errno/TLS, allocation, syscall, general
diagnostics, promotion, or public x86 support.

`libc-ctype` is a separately recorded `static-c-ctype`
`verified_artifact` gate over that archive, not a general locale or C text
capability. Its project-header C body first executes through pinned musl and
then through a `-nostdlib -static` candidate. It selects only `isalnum`,
`isalpha`, `isblank`, `iscntrl`, `isdigit`, `isgraph`, `islower`, `isprint`,
`ispunct`, `isspace`, `isupper`, `isxdigit`, `tolower`, `toupper`, `isascii`,
and `toascii`. The fixed ASCII C locale leaf is stateless and allocation-free,
with no errno/TLS or syscall boundary; its fixture covers `EOF` and every
`unsigned char` value. It excludes locale selection and `_l` ctype, wide or
multibyte text, collation, dynamic runtime, allocator, loader, sysroot, and
public x86 support.

`libc-integer-arithmetic` is a separately recorded
`static-c-integer-arithmetic` `verified_artifact` gate over that archive, not
a general numeric or C runtime capability. Its project-header C body first
executes through pinned musl and then through a `-nostdlib -static` candidate.
It selects only `abs`, `labs`, `llabs`, `div`, `ldiv`, and `lldiv`: scalar
absolute values and typed quotient/remainder aggregates. The leaf is
stateless and allocation-free, with no errno/TLS or syscall boundary; native
signed division retains C's undefined-domain processor fault for a zero
divisor or unrepresentable signed result, which the fixture deliberately does
not invoke. It is distinct from the separately selected integer parser; it
excludes random state, `imaxabs`/`imaxdiv`, callback sorting/searching,
floating-point math, dynamic runtime, allocator, loader, sysroot, and public
x86 support.

`libc-integer-parse` is a separately recorded
`static-c-integer-parse` `verified_artifact` gate over that archive, not a
general numeric or C runtime capability. Its project-header C body first
executes through pinned musl and then through a `-nostdlib -static` candidate.
It resolves exactly `atoi`, `atol`, `atoll`, `strtol`, `strtoul`, `strtoll`,
`strtoull`, `strtoimax`, and `strtoumax`. The fixed-C-locale byte scan covers
ASCII whitespace and signs, bases `0` and `2..36`, `0`/`0x` prefixes, exact
end-pointer movement, musl's invalid-base/no-conversion `EINVAL` result,
stale `errno` on success, and signed/unsigned `ERANGE` boundaries. The three
decimal convenience entries cover defined inputs only and do not write
`errno`. It excludes floating, wide, locale-specific, and internal conversion
forms; stdio; allocation; dynamic runtime; allocator; loader; sysroot; and
public x86 support.

`libc-float-parse` records both the low-level `static-c-float-parse` artifact
and the completed private `numeric.parse-float-locale` verified slice, without
completing `libc.text-math-locale-stdio`. Its project-header fixture first runs
through pinned musl and then through a `-nostdlib -static` candidate. All
twenty-three ledger symbols are invoked through function pointers: the four
narrow conversions; public and weak-internal ignored-locale `_l` wrappers;
wide floating and integer conversions; `ecvt`, `fcvt`, `gcvt`; and
`getsubopt`. The checked-in x86 translation retains the narrow string
pseudo-`FILE`, x87 binary80 operation order, and musl's 60-byte wide refill
adapter. Its private refill invokes only that adapter and does not expose
`FILE` or import general stdio. The allocation-free Rust companion removes the
older AArch64 staging implementation's wide-input length cap and performs
exact binary64 decimal rounding without selecting `sprintf`.

The differential corpus covers narrow decimal/hex grammar, end pointers,
`errno`, flags and all four x87/MXCSR rounding directions; raw 10-byte
binary80 results; ignored locale handles; refill-spanning wide strings,
Unicode whitespace, non-ASCII termination, arbitrary-length wide integers and
overflow; exact legacy decimal strings; and in-place suboption mutation. The
grammar remains fixed across C, POSIX, and C.UTF-8. Arbitrary locale maps or
locale-dependent radix, real stdio, allocation, general text/locale or
scalar/complex math, libc.so, CRT, loader, sysroot, family completion,
promotion, and public x86 support remain outside the slice.

`libc-getsubopt` is a separate `static-c-getsubopt` artifact over the same
already-selected export, not a second capability selection. Its installed
header matrix compares pinned musl and project `<stdlib.h>` C/C++ feature
visibility, then one project-header C body runs through pinned musl and a true
`-nostdlib -static` candidate. It covers only caller-owned in-place comma
splitting, ordered NUL-or-`=` key matching, value/cursor mutation, unknown and
empty tokens, empty-key behavior, and independently interleaved caller
cursors. The candidate has no TLS, errno, locale, environment, allocator,
stdio, syscall, byte-string runtime dependency, or parser state. General
parser/environment/locale behavior, family completion, promotion, and public
x86 support remain excluded.

`libc-l64a` is a separate private `static-c-l64a` artifact inside
still-planned `libc.c-abi-compat`, not a general numeric-conversion claim. It
maps only `l64a` from pinned musl 1.2.6 `src/misc/a64l.c`: one extracted,
one-symbol `-nostdlib -static` object proves the low-32-bit cast, at most six
low-to-high `./0-9A-Za-z` digits, initial NUL result, same process-global
seven-byte address, and overwrite on a later call. The shared source's `a64l`
decoder is deliberately absent from that encoder candidate. The candidate owns
no errno, TLS, locale, allocator, syscall, or runtime edge; concurrent callers
must synchronize and copy results before later calls. General numeric
conversion, family completion, promotion, and public x86 support remain
excluded.

`libc-intmax-arithmetic` is a separately recorded
`static-c-intmax-arithmetic` `verified_artifact` gate over that archive, not a
general numeric or C runtime capability. Its project-header C body first
executes through pinned musl and then through a `-nostdlib -static` candidate.
It selects only `imaxabs` and `imaxdiv`: the LP64 `intmax_t` absolute-value
and quotient/remainder aggregate forms. The leaf is stateless and
allocation-free, with no errno/TLS or syscall boundary; native signed division
retains C's undefined-domain processor fault for a zero divisor or
unrepresentable signed result, which the fixture deliberately does not invoke.
It is distinct from the separately selected `strtoimax`/`strtoumax` parser;
it excludes callback sorting/searching, floating-point math, dynamic runtime,
allocator, loader, sysroot, and public x86 support.

`libc-credential-observation` is a separately recorded
`static-c-credential-observation` `verified_artifact` gate over that archive,
not a general C-process or account-database capability. Its project-header C
body first executes through pinned musl and then through a `-nostdlib -static`
candidate. It selects only `getgroups`, GNU `getresuid`, and GNU `getresgid`.
The group fixture retains a bounded retry policy for the count-to-fill
`EINVAL` race without forcing a concurrent credential transition; its
raw/candidate partial-null pointer matrix proves real/effective/saved output
order and direct `EFAULT` behavior even when all observed IDs are equal. It
excludes account lookup, mutation, credential synchronization, child/process
control, dynamic runtime, allocator, loader, sysroot, and public x86 support.

`libc-ffs` is a separately recorded `static-c-ffs`
`verified_artifact` gate over that archive, not a general bit-operation or C
runtime capability. Its project-header C body first executes through pinned
musl and then through a `-nostdlib -static` candidate. It selects only `ffs`,
`ffsl`, and `ffsll`, each returning one plus the least-significant set-bit
index or zero. The scalar leaf is stateless and allocation-free, with no
errno/TLS or syscall boundary; its fixture proves zero, low and high set bits,
and two's-complement negative values through the exact width-specific APIs.
It excludes `fls`, general bit operations, C string manipulation, parsing,
atomics, dynamic runtime, allocator, loader, sysroot, and public x86 support.

Earlier errno-observing candidates use fixture-local startup that reserves the
initial-TLS errno datum and installs the x86 Variant-II `%fs:0` self pointer;
the byte-string, immediate-termination, POSIX-exit, and callback-algorithms candidates
deliberately do neither because their selected functions do not observe errno.
That older fixture setup does not describe `libc-static-tls-v1`,
`libc-pthread-create-join-tls`, `libc-pthread-identity`, `libc-c11-lifecycle`,
`libc-pthread-detach`, `libc-pthread-cpuclock`, `libc-pthread-name`, `libc-pthread-mutex-normal`,
`libc-pthread-rwlock`, `libc-pthread-cond-private`, `libc-c11-plain-sync`, or
`libc-pthread-c11-once`, or `libc-pthread-c11-tsd`: their start shims
delegate the untouched entry stack to the hidden libc Static Initial TLS v1
owner instead of writing an FS base themselves. `libc-thrd-sleep` deliberately
retains the fixture-local errno/TLS setup because it proves that its adapter
preserves `errno`; that start shim is test-only and not a CRT or TLS ownership
claim. `libc-thrd-yield` likewise retains fixture-local errno/TLS setup solely
to prove that its void raw-syscall leaf does not publish either a normal or
forced-error result through `errno`; its start shim is also test-only and not
a CRT or TLS ownership claim. All candidates have no
interpreter, `DT_NEEDED`, unresolved symbols, dynamic TLS resolver, allocator,
or ambient C runtime. Apart from the bounded child mapping established by
`libc-pthread-create-join-tls` and its separately recorded detach sibling,
their fixture setup is not a CRT, general TLS lifecycle, pthread runtime,
dynamic-loader, sysroot, `libc.so`, or
public-x86-support claim.

`libc-thread-pointer` compiles only the private
`libc/src/c_abi/x86_64/thread_pointer.rs` leaf. It maps pinned musl 1.2.6
`arch/x86_64/pthread_arch.h::__get_tp()`'s direct `%fs:0` read, then compares
an opaque candidate value with an inline pinned-musl fixture in the main and a
real worker thread. It never dereferences the word or asserts it is nonzero.
It does not perform `__pthread_self()`/`TP_OFFSET` arithmetic, derive `errno`,
initialize or allocate TLS, write an FS base, expose `pthread_t`, or establish
pthread creation/join, clone TLS, static/dynamic/loader TLS, `__tls_get_addr`,
`pthread_self`, `__errno_location`, a public C ABI, `crabc-libc`, CRT, ldso,
or sysroot support.

`libc-foundation` compiles one source-only x86 primitive-composition object:
a uniquely named fixed-six-word bridge forwards through the proved raw register
boundary and publishes Linux errors through the same initial-TLS `errno` slot,
while the fixed-musl memory and fenv leaves coexist in that object. It does not
export C's variadic `syscall(long, ...)`, whose public contract remains deferred
to the selected full libc. The runner executes one focused fixture separately
against pinned musl and the candidate with the project `errno.h`,
`sys/syscall.h`, `string.h`, and `fenv.h` first. It is deliberately not
`crabc-libc`, a broad C/POSIX behavior claim, pthread or signal support, an
ldso/CRT/sysroot artifact, or public x86 support.

`libc-fenv` compiles only `libc/src/c_abi/x86_64/fenv.rs`, then runs one C
fixture against pinned musl and the isolated x86 object with the project
`<fenv.h>` first. It proves the 32-byte x87/MXCSR `fenv_t` storage, exception
flag transitions, all four rounding modes, `feholdexcept`/`feupdateenv`, and
the default-environment path. This standalone source-only runner is direct
leaf evidence; the same implementation is selected only through
`libc-bootstrap-primitives`, not as a general x86 C ABI claim.

`libc-math-complex` is the separately recorded
`static-c-math-complex-foundation` artifact. Its freestanding project-header C
fixture runs first through pinned musl and then through one `-nostdlib -static`
candidate archive. It selects exactly binary32/binary64/x87
`__fpclassify*`/`__signbit*` plus the `creal*`/`cimag*`/`conj*` ABI entries,
proving zero/subnormal/normal/infinity/NaN and signed-zero classification plus
float/double/long-double complex access and conjugation. The adjacent complete
capability owns the broader complex exports; this foundation gate rejects
ambient `libm` and scalar providers it does not own rather than attributing
that surface to this artifact. It is only a classification/sign and x87
long-double/complex foundation, not itself scalar/complex math completion,
`libc.so`, CRT/TLS lifecycle, loader, sysroot, or public x86 support.

`libc-math-complex-complete` is the complete private
`static-c-math-complex-complete` capability slice. It composes the nine
foundation `creal*`/`cimag*`/`conj*` entries with 57 checked pinned-musl 1.2.6
entries for magnitude, phase, projection, powers, roots, logarithms,
exponentials, and circular/hyperbolic/inverse complex functions. The generator
pins the normalized source-tree digest and GCC 15.2.0 PIC translation, retains
source notices, and localizes musl scalar plus LLVM compiler-rt
complex-multiply support so it cannot become a public elementary dependency.

The runner invokes the complete C++ header gate, ratchets all 66 capability
exports and provider locality, and links a freestanding `-nostdlib -static
--gc-sections` candidate. It compares 5,712 exact 64-byte records with pinned
musl across all rounding modes, including result components, exception flags,
binary32/binary64 payloads, and only the defined ten bytes of each binary80
component. Every public long-complex boundary retains the SysV 16-byte binary80
and 32-byte complex ABI. Musl's `ccoshl`, `cexpl`, `csinhl`, `csqrtl`, and
`ctanhl` preserve their source-oracle internal binary64 wrappers without
narrowing any public boundary. This selects only `math.complex`; it does not
itself select the separate elementary or fenv-sensitive math capability,
numeric parsing, or general libc/libm. Family completion, promotion, full
parity, and public support remain unselected or false.

`libc-elementary-sqrt-fenv` is the separate non-promoting
`static-c-elementary-sqrt-fenv` artifact inside still-planned
`libc.text-math-locale-stdio`. Its project-header C fixture runs first through
pinned musl and then through one garbage-collected `-nostdlib -static`
candidate archive. It calls parenthesized `sqrt`, `sqrtf`, and `sqrtl`
function addresses under independently reset nearest, downward, upward, and
toward-zero modes. Exact binary32/binary64/binary80 results, `FE_INEXACT`,
signed zero, infinity, NaN, and negative-domain `FE_INVALID` prove the split
MXCSR/x87 environment, while ELF/disassembly gates require `sqrtsd`, `sqrtss`,
`fldt`, and `fsqrt` without ambient libm or retained TLS. This selects no
other elementary function, math errno policy, general scalar/complex math,
`libc.so`, CRT/TLS lifecycle, loader, sysroot, family completion, promotion,
full x86-64 parity, or public x86 support.

`libc-fenv-rounding` is the separate non-promoting
`static-c-fenv-sensitive-rounding` artifact inside still-planned
`libc.text-math-locale-stdio`. Its project-header C fixture runs first through
pinned musl and then through a garbage-collected `-nostdlib -static` candidate.
It takes parenthesized `rint*` and `nearbyint*` addresses for binary32,
binary64, and x87 binary80. All four independently reset modes, exact integral
and signed-zero results, FE_INEXACT raising versus suppression, and retention
of preexisting FE_INEXACT plus FE_DIVBYZERO prove the split MXCSR/x87
environment. The implementation maps AArch64's `math_lrint.rs` and
`math_compat.rs` semantics but keeps the binary80 ABI and fenv operation order
target-private. ELF/disassembly gates reject dynamic/TLS dependencies,
ambient libm, and unselected `sqrt*`, `cproj*`, `exp10*`/`pow10*`, and `fdim*`.
It alone does not complete `math.elementary-fenv-sensitive`; the separately
selected aggregate composes this rounding proof with the `fdim*` and
`exp10*`/`pow10*` components. The containing family, general math, promotion,
full x86-64 parity, and public x86 support remain unselected.
`libc-math-minmax` is the separate non-promoting `static-c-math-minmax`
artifact for binary64/binary32 `fmax`/`fmin` and `fmaxf`/`fminf`. Its
project-header C fixture and default-SSE/`-mfpmath=387` C++ signature probes
run first through pinned musl and then through one garbage-collected
`-nostdlib -static` candidate. They prove ordinary and infinite values,
Annex-F +0/-0 selection for opposing signs, raw quiet/signaling-NaN
left-to-right operand selection without `FE_INVALID`, all four MXCSR modes,
and preservation of preexisting `FE_DIVBYZERO`. The target leaf uses raw
integer IEEE classification before `ucomisd`/`ucomiss`, and final-link proof
requires strong crabc-owned definitions rather than compiler-builtins weak
fallbacks. This artifact does not select or extract `fmaxl`/`fminl`, `fdim*`,
bit-sign functions, fenv rounding, special/complex or binary80/x87 math;
family completion, promotion, full x86-64 parity, and public x86 support
remain unselected.
`libc-math-bit-sign` is the separate non-promoting `static-c-math-bit-sign`
artifact for binary64/binary32 `fabs`/`fabsf` and `copysign`/`copysignf`. Its
project-header C fixture and default-SSE/`-mfpmath=387` C++ signature probes
run first through pinned musl and then through one garbage-collected
`-nostdlib -static` candidate. They prove ordinary and infinite values,
signed zero, raw quiet/signaling-NaN payload/sign preservation without
`FE_INVALID`, all four MXCSR modes, and preservation of preexisting
`FE_DIVBYZERO`. The target leaf uses only SSE logical sign masks, and the
final-link proof requires strong crabc-owned definitions rather than
compiler-builtins weak fallbacks. This artifact does not select or extract
`fabsl`/`copysignl`, `fdim*`, fmax/fmin, fenv rounding, special/complex or
binary80/x87 math; family completion, promotion, full x86-64 parity, and
public x86 support remain unselected.
`libc-math-trunc` is the separate non-promoting `static-c-math-trunc`
artifact for binary64/binary32 `trunc`/`truncf`. Its project-header C fixture
and default-SSE/`-mfpmath=387` C++ signature probes run first through pinned
musl and then through one garbage-collected `-nostdlib -static` candidate.
They prove ordinary/integral values, signed zero, infinity, raw
quiet/signaling-NaN payloads, ordinary and raw-subnormal fractional values,
the musl `FE_INEXACT`/no-`FE_INVALID` path, all four MXCSR modes, and
preservation of preexisting `FE_DIVBYZERO`. The target leaf uses raw
exponent/fraction masks plus volatile SSE force evaluation; final-link proof
requires strong crabc-owned definitions rather than compiler-builtins weak
fallbacks. This artifact does not select or extract `truncl`, `round*`,
`rint*`/`nearbyint*`, bit-sign, `fdim*`, fmax/fmin, special/complex, or
binary80/x87 math; family completion, promotion, full x86-64 parity, and
public x86 support remain unselected.
`libc-math-fmod` is the separate non-promoting `static-c-math-fmod` artifact
for binary64/binary32 `fmod`/`fmodf`. Its project-header C fixture and
default-SSE/`-mfpmath=387` C++ signature probes run first through pinned musl
and then through one garbage-collected `-nostdlib -static` candidate. The
direct musl 1.2.6 `fmod.c`/`fmodf.c` mapping normalizes raw IEEE significands,
uses the source subtraction loop, and rescales x-signed normal or subnormal
remainders. It also proves quiet/signaling-NaN and zero-divisor/infinite-x
domain behavior through musl's `(x*y)/(x*y)` `FE_INVALID` path, all four MXCSR
modes, and preexisting `FE_DIVBYZERO`. Final-link proof requires strong
crabc-owned definitions rather than compiler-builtins weak fallbacks and
rejects `fmodl`, remainder/remquo/modf, rounding/truncation, special/complex,
and binary80/x87 math. Family completion, promotion, full x86-64 parity, and
public x86 support remain unselected.
`libc-math-cbrt` is the separate non-promoting `static-c-math-cbrt` artifact
for binary64/binary32 `cbrt`/`cbrtf`. Its project-header C fixture and
default-SSE/`-mfpmath=387` C++ signature probes run first through pinned musl
and then through one garbage-collected `-nostdlib -static` candidate. The
checked GCC 15.2.0 assembly translation of musl 1.2.6 `cbrt.c`/`cbrtf.c`
preserves the source's binary64 rough estimate and Newton order, including
`cbrtf`'s MXCSR-directed final binary64-to-binary32 conversion. The complete
record differential compares raw binary64/binary32 payloads, exception flags,
and requested versus observed rounding directions for signed zero, normal and
subnormal bounds, ordinary powers, maximum finite values, infinities, and
quiet/signaling NaNs in all four modes. Final-link proof requires strong
crabc-owned definitions and `divsd`/`mulsd`/`cvtsd2ss`, while rejecting weak
compiler-builtins fallback, `cbrtl`, fma, fmod/remainder/modf,
rounding/truncation, bit-sign/minmax/fdim, special/complex, and binary80/x87
math. Family completion, promotion, full x86-64 parity, and public x86 support
remain unselected.
`libc-math-exp2` is the separate non-promoting `static-c-math-exp2` artifact
for binary64/binary32 `exp2`/`exp2f`. Its project-header C fixture and
default-SSE/`-mfpmath=387` C++ signature probes run first through pinned musl
and then through one garbage-collected `-nostdlib -static` candidate. The
checked GCC 15.2.0 translation of musl 1.2.6 `exp2.c`/`exp2f.c` incorporates
private binary64/binary32 tables and local overflow/underflow range helpers;
it neither pulls `math.special` nor calls ambient libm. The 232-record raw
differential covers signed zero, tiny/subnormal and overflow/underflow bounds,
ordinary reduction points, finite extremes, infinities, quiet/signaling NaNs,
raw results, flags, and requested versus observed MXCSR direction in all four
modes. Final-link proof requires strong crabc-owned definitions and scalar
`addsd`/`addss`/`subsd`/`mulsd`/`mulss` conversion paths, while rejecting weak
compiler-builtins fallback, `exp2l`, adjacent exp/log/pow functions, fenv
API/policy, special/complex/binary80 math, dynamic linkage, TLS, and ambient
libm. Family completion, promotion, full x86-64 parity, and public x86 support
remain unselected.
`libc-math-expm1` is the separate non-promoting `static-c-math-expm1` artifact
for binary64/binary32 `expm1`/`expm1f`. Its project-header C fixture and
default-SSE/`-mfpmath=387` C++ signature probes run first through pinned musl
and then through one garbage-collected `-nostdlib -static` candidate. The
checked GCC 15.2.0 assembly translation of musl 1.2.6 `expm1.c`/`expm1f.c` is
the direct no-call source closure: it retains binary64/binary32 reduction,
polynomial reconstruction, raw-subnormal `FORCE_EVAL`, and overflow scaling
without tables, ambient libm, or selected `math.special` state. The 248-record
raw differential compares signed zeros, tiny/subnormal and normal bounds,
reduction/overflow thresholds, finite extremes, infinities, quiet/signaling
NaNs, result payloads, flags, and requested versus observed MXCSR direction in
all four modes. Final-link proof requires strong crabc-owned definitions and
scalar `addsd`/`addss`/`subsd`/`subss`/`mulsd`/`mulss`/`divsd`/`divss`/
`cvtsd2ss`, while rejecting weak compiler-builtins fallback, `expm1l`,
adjacent exp/log/pow functions, fenv API/policy, special/complex/binary80
math, dynamic linkage, TLS, and ambient libm. Family completion, promotion,
full x86-64 parity, and public x86 support remain unselected.
`libc-math-log10` is the separate non-promoting `static-c-math-log10` artifact
for binary64/binary32 `log10`/`log10f`. Its project-header C fixture and
default-SSE/`-mfpmath=387` C++ signature probes run first through pinned musl
and then through one garbage-collected `-nostdlib -static` candidate. The
checked GCC 15.2.0 translation of musl 1.2.6 `log10.c`/`log10f.c` is a direct
no-call source closure: it preserves raw classification, subnormal scaling,
reduction, polynomial reconstruction, and zero/negative domain arithmetic
without tables, ambient libm, or selected `math.special` state. The 224-record
raw differential covers signed-zero divide-by-zero, negative-domain invalid,
tiny/subnormal and normal boundaries, reduction points, finite extremes,
infinities, quiet/signaling NaNs, result payloads, flags, and requested versus
observed MXCSR direction in all four modes. Final-link proof requires strong
crabc-owned definitions and scalar `addsd`/`addss`/`subsd`/`subss`/`mulsd`/
`mulss`/`divsd`/`divss`, while rejecting weak compiler-builtins fallback,
`log10l`, adjacent log/exp/pow functions, fenv API/policy,
special/complex/binary80 math, dynamic linkage, TLS, and ambient libm. Family
completion, promotion, full x86-64 parity, and public x86 support remain
unselected.
`libc-math-ceil` is the separate non-promoting `static-c-math-ceil` artifact
for binary64/binary32 `ceil`/`ceilf`. Its project-header C fixture and
default-SSE/`-mfpmath=387` C++ signature probes run first through pinned musl
and then through one garbage-collected `-nostdlib -static` candidate. The
checked GCC 15.2.0 assembly translation of musl 1.2.6 `ceil.c`/`ceilf.c`
preserves binary64's raw IEEE classification and `toint` add/subtract order,
alongside binary32's raw fraction-mask and volatile `FORCE_EVAL` path. The
216-record raw differential compares signed zero, normal/subnormal and
integral-neighbor boundaries, large finite values, infinities,
quiet/signaling NaNs, exception flags, and requested versus observed MXCSR
direction in all four modes. Final-link proof requires strong crabc-owned
definitions and `addsd`/`subsd`/`addss`, while rejecting weak
compiler-builtins fallback, `ceill`, floor, fma, fmod, cbrt, static
rounding/fenv policy, special/complex/binary80 math, dynamic linkage, TLS,
and ambient-libm surface. Family completion, promotion, full x86-64 parity,
and public x86 support remain unselected.
`libc-math-floor` is the separate non-promoting `static-c-math-floor` artifact
for binary64/binary32 `floor`/`floorf`. Its project-header C fixture and
default-SSE/`-mfpmath=387` C++ signature probes run first through pinned musl
and then through one garbage-collected `-nostdlib -static` candidate. The
checked GCC 15.2.0 assembly translation of musl 1.2.6 `floor.c`/`floorf.c`
preserves binary64's raw IEEE classification and `toint` add/subtract order,
alongside binary32's raw fraction-mask and volatile `FORCE_EVAL` path. The
216-record raw differential compares signed zero, normal/subnormal and
integral-neighbor boundaries, large finite values, infinities,
quiet/signaling NaNs, exception flags, and requested versus observed MXCSR
direction in all four modes. Final-link proof requires strong crabc-owned
definitions and `addsd`/`subsd`/`addss`, while rejecting weak
compiler-builtins fallback, `floorl`, ceiling, fma, fmod, cbrt, static
rounding/fenv policy, special/complex/binary80 math, dynamic linkage, TLS,
and ambient-libm surface. Family completion, promotion, full x86-64 parity,
and public x86 support remain unselected.
`libc-math-round` is the separate non-promoting `static-c-math-round` artifact
for binary64/binary32 `round`/`roundf`. Its project-header C fixture and
default-SSE/`-mfpmath=387` C++ signature probes run first through pinned musl
and then through one garbage-collected `-nostdlib -static` candidate. The
checked GCC 15.2.0 assembly translation of musl 1.2.6 `round.c`/`roundf.c`
preserves sign normalization, `toint` add/subtract order, and the half-away
correction. The 216-record raw differential compares signed zero,
normal/subnormal and integral-neighbor boundaries, exact halfway values,
large finite values, infinities, quiet/signaling NaNs, exception flags, and
requested versus observed MXCSR direction in all four modes. Final-link proof
requires strong crabc-owned definitions and `addsd`/`subsd`/`addss`/`subss`,
while rejecting weak compiler-builtins fallback, `roundl`, fenv API/policy,
`rint`/`nearbyint`, truncation, directed ceiling/floor, fma, fmod, cbrt,
special/complex/binary80 math, dynamic linkage, TLS, and ambient-libm surface.
Family completion, promotion, full x86-64 parity, and public x86 support
remain unselected.
`libc-math-log2` is the separate non-promoting `static-c-math-log2` artifact
for binary64/binary32 `log2`/`log2f`. Its project-header C fixture and
default-SSE/`-mfpmath=387` C++ signature probes run first through pinned musl
and then through one garbage-collected `-nostdlib -static` candidate. The
checked GCC 15.2.0 assembly translation of musl 1.2.6 `log2.c`/`log2f.c`
preserves close-to-one reconstruction, subnormal normalization, table
reduction, exact-power behavior, and zero/domain expressions through its
exact local two-table/four-error-helper closure. The 216-record raw
differential compares signed zero, normal/subnormal and power-of-two-neighbor
boundaries, table-range values, large finite values, infinities,
quiet/signaling NaNs, exception flags, and requested versus observed MXCSR
direction in all four modes. Final-link proof requires strong crabc-owned
definitions, local table/error helpers, and scalar `divsd`/`mulsd`/`addsd`/
`subsd`/`divss`/`mulss`/`subss`, while rejecting weak compiler-builtins
fallback, `log2l`, other log/exp families, fenv API/policy,
special/complex/binary80 math, dynamic linkage, TLS, and ambient-libm surface.
Family completion, promotion, full x86-64 parity, and public x86 support
remain unselected.
`libc-fdim` is a separate non-promoting `static-c-fdim` artifact for the
binary64/binary32 positive-difference pair. Its project-header C fixture and
default-SSE/`-mfpmath=387` C++ signature probes run first through pinned musl
and then through one garbage-collected `-nostdlib -static` candidate. They
prove the exact `fdim`/`fdimf` C linkage; ordinary positive and +0 results;
left-to-right raw quiet/signaling-NaN payload return without `FE_INVALID`; all
four MXCSR rounding modes and `FE_INEXACT` for a half-ULP subtraction; and
overflow with `FE_OVERFLOW|FE_INEXACT`. The target leaf uses musl-shaped
integer NaN classification before SSE comparison, and the ELF gate requires a
strong crabc-owned definition rather than the compiler-builtins weak fallback.
That artifact by itself remains only the binary32/binary64 pair. The separate
private `libc-math-elementary-fenv-sensitive` aggregate composes it with the
existing `rint*`/`nearbyint*`, `exp10`/`pow10`, and `exp10f`/`pow10f` gates
plus the opt-in binary80 `fdiml`/`exp10l`/`pow10l` closure. Its all-fifteen
typed-call candidate and pinned-musl differentials select exactly
`math.elementary-fenv-sensitive`; category/family completion, promotion, full
x86-64 parity, and public x86 support remain unselected.


`libc-math-x87-extended` is the separate
`static-c-math-x87-extended` artifact. It carries pinned musl 1.2.6's
target-specific x86 implementations of `acosl`, `asinl`, `atanl`, `atan2l`,
`ceill`, `exp2l`, `expl`, `expm1l`, `fabsl`, `floorl`, `fmodl`, `log10l`,
`log1pl`, `log2l`, `logl`, `lrintl`, `llrintl`, `rintl`, `remainderl`,
`remquol`, `sqrtl`, and `truncl` across a target-private `global_asm!` leaf
and the already selected single-owner `rintl`/`sqrtl` sibling leaves. No entry
narrows through binary64: long-double operands remain in their SysV
16-byte stack slots and results remain binary80 in `st0`. The project-header
fixture takes each function address, runs the identical body against pinned
musl and the freestanding static candidate, and compares 1,260 records over
all four rounding modes: the defined ten binary80 bytes, exception flags,
integer conversions, and signed `remquol` quotient bits. The final ELF rejects
TLS, ambient `libm`, and unowned runtime dependencies and structurally requires
the selected x87 instruction families. This remains a non-capability artifact:
it does not itself select the completed `math.elementary-long-double` or
special-function capability,
promote `libc.text-math-locale-stdio`, or establish general libc/libm, CRT,
loader, sysroot, full x86-64 parity, or public x86 support.

`libc-math-special` is the complete private `static-c-math-special` capability
slice. Ten of its exact ninety symbols are supplied by the prior classifier/
sign and x87 conversion/remainder leaves; the other eighty come from a checked
source-faithful assembly translation of pinned musl 1.2.6. The generator
verifies the normalized complete source-tree digest and GCC 15.2.0 input,
prefixes translation-unit locals, and renames every required elementary
support provider under local `crabc_x86_math_special_*` names, so sine/cosine,
exp/log/pow/sqrt, rounding, and argument-reduction dependencies do not leak as
public exports or select another capability. The shared archive's separately
selected public `rint`/`rintf` and `sqrt`/`sqrtf` siblings remain visible but
are not attributed to this slice. `__signgam` and weak same-address
`signgam` are included only for non-reentrant `lgamma*` state.

The runner first invokes `math-special-header-abi`, builds the selected static
archive, ratchets all ninety capability exports plus the sign state and the
private-provider locality, and links a freestanding `-nostdlib -static
--gc-sections` candidate. It rejects unresolved, dynamic, TLS, ambient libm,
numeric-parser, allocation, and unowned dependencies. Function-pointer calls
compare 5,544 exact 32-byte records with pinned musl across all four rounding
modes: exception flags, binary32/binary64 results, the defined ten binary80
bytes, integer/pointer outputs, decomposition components, quotient bits,
gamma signs/state, stepping/scaling boundaries, and ordinary/special error,
gamma, and Bessel cases. Every long-double boundary remains SysV x87 binary80
without binary64 narrowing. The completed slice selects only `math.special`;
it does not itself select the separate elementary/fenv-sensitive or complex
math capabilities. The surrounding family, general math, promotion, full
parity, and public x86 support remain planned or false.

`libc-math-elementary-long-double` is the complete private
`static-c-math-elementary-long-double` capability slice. It composes the
seventeen already-evidenced x87 binary80 entries with eighteen checked
source-faithful pinned-musl 1.2.6 providers: inverse/hyperbolic/circular
functions, `cbrtl`, sign/extrema/norm, `fmal`, `powl`, rounding, and GNU
`sincosl`. The generator verifies the normalized source-tree digest and GCC
15.2.0 input, preserves source-specific notices, and keeps its
`__cosl`/`__sinl`/`__tanl` argument-reduction closure and binary64
`floor`/`scalbn` support local.

The runner invokes the C++ header gate, ratchets all 35 selected exports and
private-provider locality, and links a freestanding `-nostdlib -static
--gc-sections` candidate. It rejects unresolved, dynamic, TLS, ambient libm,
numeric parser, allocation, complex, and unowned dependencies, then compares
2,764 exact 40-byte records with pinned musl across all four rounding modes.
The records retain only the ten defined binary80 bytes plus x87/MXCSR flags and
cover signed zeros, finite boundaries, infinities, NaNs, powers, hyperbolics,
`fmal`, and both `sincosl` results. Every public long-double boundary retains
the SysV binary80 ABI. This selects only `math.elementary-long-double`; it
does not itself select the separate fenv-sensitive scalar math capability,
numeric parsing, or complex/general math. Family completion, promotion, full
parity, and public x86 support remain unselected or false.

`locale-multibyte-header-abi` and `libc-locale-multibyte` are one separate,
non-promoting named-locale/text artifact. The strict C11/C++17 header matrix
checks selected `<locale.h>`, `<stdlib.h>`, and `<wchar.h>` declarations,
x86 `mbstate_t`/`lconv` layout, and C++ C linkage. Its static C fixture first
runs against pinned musl and then against the selected archive. It admits only
direct named `C`, `POSIX`, and `C.UTF-8` categories: musl's built-in UTF-8 map
affects `LC_CTYPE` alone, so the exact returned mixed `LC_ALL` serialization
is `C.UTF-8;C;C;C;C;C`. It covers C byte code units, ordinary UTF-8
conversion paths, and one caller-owned positive-capacity UTF-8 resume. A
candidate-only check rejects non-returned POSIX-component,
non-CTYPE-UTF-8-component, and uniform six-component `LC_ALL` forms without
changing state; noninitial `mbsrtowcs` resume with zero output capacity is
deliberately not selected. Locale objects,
environment lookup, collation, iconv, wide streams/stdio, general locale/text
completion, `libc.so`, CRT, loader, sysroot, promotion, and public x86 support
remain outside this artifact.

`locale-profile-header-abi` and `libc-locale-profile` are the separate
selected-private `locale.core` fixed-profile vertical. Unlike the adjacent
multibyte artifact, it invokes exactly `setlocale` and `localeconv`: a strict
C11/C++17 project-versus-pinned-musl header proof fixes the six category
values, the 96-byte `struct lconv` layout, the two function signatures, and
unmangled C++ references. The shared C fixture then runs first against pinned
musl 1.2.6 and then a true `-nostdlib -static --gc-sections` candidate. It
observes initial C state, direct `C`/`POSIX`/`C.UTF-8` selection, every
category query, the exact CTYPE-only global serialization
`C.UTF-8;C;C;C;C;C`, and musl's stable immutable POSIX `lconv` record: `.`
for `decimal_point`, empty remaining text fields, and fourteen `CHAR_MAX`
monetary char fields. Candidate-only checks reject `setlocale(category, "")`,
arbitrary map names, and unreturned mixed forms without changing state. The
final ELF must have no unresolved or dynamic dependency, PT_TLS, multibyte or
wide conversion, locale object, allocator, environment, gettext, numeric,
time, stdio, or ambient-runtime boundary. This marks only the fixed
`setlocale`/`localeconv` seam as selected-private `locale.core`; it does not
claim every legacy locale spelling, general locale/encoding data, family
completion, promotion, or public x86 support.

`libc-regex` is a separately recorded `static-c-bounded-regex` artifact, not
completion of the `pattern.regex` capability. Its project-header C fixture
first runs through pinned musl 1.2.6 and then through a true freestanding
static candidate. The installed ABI matches musl's 64-byte `regex_t`, signed
64-bit `regoff_t`, 16-byte `regmatch_t`, flags, result codes, declarations,
and C++ linkage. Runtime evidence selects only C-locale byte concatenation,
anchors, dot, byte lists/ranges, `*`, and ERE `+`/`?`, with ASCII
`REG_ICASE`, `REG_NEWLINE`, `REG_NOSUB`, execution flags, leftmost-longest
whole-match reporting, exact `regerror` messages, and fixed 128-atom/4096-byte
bounds. A private fixed-size anonymous mapping owns compiled state without a
public C allocator. Unsupported groups, alternation, counted repetition,
backreferences, named classes, collating/equivalence elements, and non-ASCII
pattern bytes are rejected instead of approximated. `wordexp`, glob/fnmatch C
ABIs, locale-aware or multibyte regex, a Rust regex ecosystem, libc.so, CRT,
loader, sysroot, family completion, promotion, and public x86 support remain
unselected.

`libc-process-globals-getopt` is a separate private
`static-c-process-globals-getopt` artifact inside still-planned
`libc.c-abi-compat`. The same project-header C fixture first runs through a
non-PIE pinned-musl 1.2.6 static executable, then through a true
`-nostdlib -static` x86 candidate. The candidate's evidence-only entry first
installs the existing Static Initial TLS v1 image and then enters the bounded
static `__libc_start_main`, which publishes the validated empty-or-`argv[0]`
full name and last-slash short name before its init callback and `main`. The
runner proves musl's weak same-address `optreset`/`__optreset`,
`program_invocation_name`/`__progname_full`,
`program_invocation_short_name`/`__progname`, and
`__posix_getopt`/`getopt` identities in the pinned reference, selected archive,
and final candidate, including observable writes through the data aliases.
It also covers short clusters and arguments, all three restart routes,
UTF-8 option code points under `C.UTF-8`, quiet unknown/missing results, and
GNU long required/optional/flag/ambiguous/permuted/long-only behavior. The
x86 leaf reuses the established AArch64 musl-derived parser body with only
target-local errno, multibyte, string, and permanent-stream adapters. It owns
no environment object or mutation API, direct auxv observation beyond the
separate `static-c-auxv-observation` artifact, secure state, loader startup,
allocator, general locale/stdio, `libc.so`, CRT family, sysroot, C ABI closure,
family promotion, or public x86 support.

`libc-auxv-observation` is the adjacent private
`static-c-auxv-observation` artifact inside still-planned `libc.c-abi-compat`.
The project `<sys/auxv.h>` C body first executes through pinned musl 1.2.6 and
then a true `-nostdlib -static` candidate. Its existing static-TLS handoff and
bounded `__libc_start_main` validate envp plus no more than 4096 `AT_NULL`-
terminated auxiliary-vector pairs, then release-publish the kernel-owned
vector before constructors and `main`. The archive exposes strong
`__getauxval` with weak same-address `getauxval`; evidence covers
`AT_PAGESZ`, `AT_PHENT`, `AT_PHNUM`, zero-valued `AT_SECURE` with stale errno,
and absent `AT_NULL`/`ENOENT`. It excludes raw auxv address exposure,
secure-execution policy/`secure_getenv`, environment ownership, auxv-derived
system configuration, loader/dynamic startup, `libc.so`, CRT completion,
family promotion, and public x86 support.

`iconv-header-abi` and `libc-locale-wide-iconv` add a separate, non-promoting
static composition artifact. The C11/C++17 gate checks the pointer-sized
`iconv_t` typedef, `iconv_open`/`iconv`/`iconv_close` signatures, project
header provenance, and unmangled C++ spellings. The runtime fixture first
runs under pinned musl and then a true `-nostdlib -static` candidate. It
composes the existing named `C`/`POSIX`/`C.UTF-8` multibyte seam with only
allocation-free ASCII, UTF-8, UTF-16LE/BE, UTF-32LE/BE, and native 32-bit
`WCHAR_T` descriptor conversions. It observes musl's exact fuzzy
name-normalization boundary, fixed-endian UTF-16 and UTF-32 byte order,
malformed-scalar pointer/count progress, ASCII `'*'` substitution,
EILSEQ/EINVAL/E2BIG, stale errno, reset, and close. Generic BOM/stateful
UTF-16, UCS-2, arbitrary legacy codepages,
locale objects, collation, wide streams/stdio, Unicode normalization,
allocation, general text/locale/iconv completion, `libc.so`, CRT, loader,
sysroot, promotion, and public x86 support remain outside this artifact.

`wide-character-header-abi` and `libc-wide-character` record a separate
private `static-c-wide-character-core` artifact. The `_XOPEN_SOURCE=700`
C11/C++17 matrix proves signed 32-bit `wchar_t`, unsigned 32-bit `wint_t`,
LP64 `wctype_t`, pointer-shaped `wctrans_t`, all 46 selected declarations,
and unmangled C linkage from project and pinned-musl headers. The shared
runtime fixture then runs under pinned musl and a true `-nostdlib -static`
candidate. It covers allocation-free wide string/memory operations,
caller-owned `wcstok` state, code-point collation/transformation in the named
`C`, `POSIX`, and `C.UTF-8` locales, Unicode case comparison, and terminal
column width. A byte-for-byte fingerprint over U+0000 through U+110000 closes
all selected classification, simple-case, descriptor, and width behavior
against musl 1.2.6. The checked-in compressed alpha, punctuation, case-map,
nonspacing, and wide tables are a mechanical MIT-licensed transcription of
the pinned musl release, not a runtime locale or legacy-encoding database.
This core excludes `wcsdup`, locale objects and every `_l` entry, Unicode
normalization, wide stdio/streams, formatting/scanning, time conversion, allocation,
general text/locale completion, `libc.so`, CRT, loader, sysroot, promotion,
and public x86 support remain outside this core artifact. Wide numeric parsing
belongs to the separately selected numeric-parse slice and is not exercised by
this artifact. The built-in locale-object/localized-wide artifact below is
independently judged.

`wcswcs-header-abi` and `libc-wcswcs` record the distinct private
`static-c-wcswcs` alias leaf. The strict/POSIX/X/Open/GNU/BSD C11/C++17
matrix proves the unconditional exact `wchar_t *wcswcs(const wchar_t *, const
wchar_t *)` declaration and unmangled C linkage. Its same project-header
fixture first executes with pinned musl and then through a true
`-nostdlib -static` candidate, proving empty-needle identity, first-suffix
selection, null misses, signed full-width units, and no input mutation. The
one-export scalar closure follows musl's `wcswcs.c -> wcsstr.c` alias without
extracting `wcsstr`, the broad wide-character object, locale/Unicode policy,
multibyte conversion, or a general wide text/search surface. It remains
selected-private and does not promote the family or public x86 support.

`locale-object-wide-header-abi` and `libc-locale-object-wide` record the
separate private `static-c-locale-object-localized-wide` artifact. The
`_XOPEN_SOURCE=700` C11/C++17 matrix proves the pointer-shaped `locale_t`,
`LC_GLOBAL_LOCALE`, category masks, `nl_item` values, all 28 selected
locale-object/langinfo/wide `_l` declarations, and unmangled C linkage. The
shared runtime fixture then runs under pinned musl and a true
`-nostdlib -static` candidate. Immutable allocation-free `C`/`POSIX` and
`C.UTF-8` tokens retain only a CTYPE encoding distinction; fixed C/POSIX
langinfo data and the selected wide Unicode tables need no locale database.
The existing Static Initial TLS v1 image makes `uselocale` independent for the
selected main and bounded pthread workers, and a new worker begins in
global-following mode. The fixture proves lifecycle transitions, CODESET,
time/numeric/messages items, per-thread multibyte selection, parent/worker
isolation, localized code-point collation, and an exhaustive
U+0000-through-U+110000 localized classification/case fingerprint. Arbitrary
locale names, environment lookup, locale maps/refcounts, allocation, gettext,
legacy encodings, bounded multibyte extensions, narrow `_l` strings/ctype,
locale-specific numeric parsing, wide stdio/format/time conversion, general
locale/text completion, `libc.so`, CRT, loader, sysroot, promotion, and public
x86 support remain unselected.

`locale-narrow-header-abi` and `libc-locale-narrow` record the separate
private `static-c-locale-narrow-collation` artifact. Its `_XOPEN_SOURCE=700`
C11/C++17 matrix proves pointer-shaped `locale_t`, exact declarations for all
14 narrow ctype/case `_l` entries plus ordinary/localized case comparison and
byte collation/transformation, and unmangled C linkage through `ctype.h`,
`locale.h`, `string.h`, and `strings.h`. The shared pinned-musl/static fixture
passes `C`, `POSIX`, and `C.UTF-8` tokens through every localized entry,
fingerprints EOF plus all 256 byte values, checks ASCII/high-byte full and
bounded comparisons, and locks musl's exact all-or-no-write `strxfrm`
capacity boundary. It composes with the existing calling-thread Static
Initial TLS v1 `uselocale` state and proves the selected token is unchanged;
the leaf adds no TLS or locale data. The project AArch64 contract owns the
same 22 symbols, but its current transformation helper writes a short
NUL-terminated prefix, so the x86 evidence explicitly follows pinned musl's
no-short-write rule. Arbitrary locale names/maps, general locale or legacy
encoding databases, Unicode narrow classification, normalization,
allocation/refcounts, gettext, localized numeric parsing, wide
stdio/format/time conversion, general text/locale completion, `libc.so`, CRT,
loader, sysroot, promotion, and public x86 support remain unselected.

`libc-locale-ctype-locators` records the separate private
`static-c-locale-ctype-locators` ABI artifact. It deliberately leaves the
three musl glibc-compatibility locators out of installed `<ctype.h>`: a C
consumer that needs `__ctype_b_loc`, `__ctype_tolower_loc`, or
`__ctype_toupper_loc` declares it locally. The shared pinned-musl/static
fixture proves each stable pointer-to-pointer shape, its immutable 384-entry
table biased by 128, little-endian storage of musl's network-order class
words, and the complete `-128..255` signed/unsigned-byte table domain. It
compares a raw eight-byte fingerprint from a true `-nostdlib -static`
candidate that has no PT_TLS, errno, locale-object, allocator, or ambient
runtime dependency. The data remain fixed for `C`, `POSIX`, and `C.UTF-8`;
this ABI-only slice neither selects `locale.core` nor adds a locale database,
locale/environment selection, Unicode narrow classification, localized
text/numeric/time formatting, wide I/O, a dynamic runtime, family completion,
promotion, or public x86 support.

`libc-locale-error-strings` records the separate private
`static-c-locale-error-strings` ABI artifact. It adds only strong
`__strerror_l` plus musl's weak same-address public `strerror_l` alias over the
already selected immutable error-message table. The shared project-header
C/C++ matrix verifies the feature-gated `<string.h>` declaration and unmangled
C++ reference; its pinned-musl/static fixture then passes only live `C`,
`POSIX`, and `C.UTF-8` locale objects through all nonnegative errno indices
`0..=134` while testing C, UTF-8, and global-following selected-thread modes.
It proves alias address/binding, pointer equality with `strerror`, preserved
`errno`, and a matching full digest. `LC_GLOBAL_LOCALE` is only a `uselocale`
sentinel, not an explicit `strerror_l` argument. The bridge reads no locale
token or catalog and adds no locale data; it is an ABI sub-slice toward, but
not a selection of, `locale.core`. General locale/legacy-encoding databases,
arbitrary names or environment selection, gettext, `strfmon`, numeric parsing,
wide text/stdio/time conversion, iconv, diagnostics, dynamic runtime, family
completion, promotion, and public x86 support remain excluded.

`libc-memory` compiles only `libc/src/c_abi/x86_64/memory.rs`, then runs one C
fixture against pinned musl and the isolated x86 object with project
`<string.h>` first. It proves the fixed `memcpy`, `memmove`, and `memset`
algorithms across alignments, lengths, overlap direction, guard-page edges,
return values, and `memmove`'s direction-flag restoration. This standalone
source-only runner is direct leaf evidence; the separately selected
`libc-bootstrap-primitives` artifact also proves its `memcmp`/`bcmp` surface,
not a general x86 C ABI claim.

`libc-setjmp` compiles only `libc/src/c_abi/x86_64/setjmp.rs`, then runs the
same C continuation fixture once against pinned musl and once against that
isolated object with the project `<setjmp.h>` first. It proves the 200-byte
x86 machine/signal-mask record, direct aliases, callee-saved register and
stack restoration, zero-to-one return conversion, and `sigsetjmp` mask
restore behavior. This standalone source-only runner is direct leaf evidence;
the same implementation is selected only through `libc-bootstrap-primitives`,
not as a general x86 C ABI claim.

`libc-atomic` compiles only `libc/src/c_abi/x86_64/atomic.rs` and executes a
native behavior/disassembly probe for locked i32 `cmpxchg`, `xchg`, and `xadd`
helpers. It is a source-only prerequisite: it does not select `crabc-libc` or
establish pthread, TLS, or C ABI parity.

`libc-clone-raw` compiles only a uniquely named private lexical port of musl
1.2.6's `src/thread/x86_64/clone.s`. The paired pinned-musl/candidate fixture
proves the restricted `SIGCHLD` process clone, supplied child stack, callback,
and exit tail; it rejects public `clone`/`__clone`, runtime, and dynamic-TLS
dependencies. It does not establish public C clone, pthread, or TLS support.

`libc-signal-foundation` compiles only the private musl-shaped public-to-kernel
signal-action record conversion and hidden syscall-15 restorer. It checks the
152-byte public x86 layout against the 32-byte kernel action without installing
or delivering a signal. Its source-only runner is not public C
`sigaction`/`signal` behavior; the separately selected `libc-signal-control`
artifact owns that deliberately narrow public surface.

`facade` runs exactly the no-default-feature `crabc-rs` lib tests plus the
`fenv`, `futex`, `x86_64_foundation`, `x86_64_epoll`, `x86_64_eventfd`,
`x86_64_fcntl_getlk`, `x86_64_fcntl_flags`, `x86_64_fs`, `x86_64_fs_capacity`, `x86_64_fs_advice`,
`x86_64_raw_directory`, `x86_64_directory`, `x86_64_directory_position`,
`x86_64_temporary_objects`, `x86_64_statx`, `x86_64_canonicalize`, and
`x86_64_cwd_mutation`,
`x86_64_flock`,
`x86_64_sendfile`,
`x86_64_copy_file_range`,
`x86_64_posix_fallocate`,
`x86_64_fallocate`,
`x86_64_file_position`, `x86_64_sync`, `x86_64_syncfs`, `x86_64_sync_file_range`, `x86_64_ftruncate`,
`x86_64_fs_credentials`,
`x86_64_getgroups`, `x86_64_getitimer`, `x86_64_setitimer`, `x86_64_io`,
`x86_64_memfd`, `x86_64_mm`, `x86_64_param`, `x86_64_pipe`,
`x86_64_poll`, `x86_64_pselect`, `x86_64_priority`, `x86_64_setpriority`,
`x86_64_process_identity`, `x86_64_process_session`, `x86_64_pidfd_open`,
`x86_64_rand`, `x86_64_rlimit`, `x86_64_rlimit_targeted`,
`x86_64_setrlimit`, `x86_64_umask`,
`x86_64_rusage`, `x86_64_scheduler_priority_bounds`, `x86_64_sleep`,
`x86_64_clock_nanosleep`, `x86_64_statat`, `x86_64_access`, `x86_64_getcwd`,
`x86_64_readlink`, `x86_64_sched_rr_interval`, `x86_64_sched_affinity`,
`x86_64_sched_setaffinity`, `x86_64_system`, `x86_64_thread`,
`x86_64_thread_credentials`, `x86_64_time`, `x86_64_timerfd`, and
`x86_64_times`, and `x86_64_advanced_time` tests. The
child-contained `x86_64_chroot` regression runs separately in a
`CAP_SYS_CHROOT` container. The
I/O regression proves vector segment and short-read behavior, 64-bit
positioned/vector offsets, `preadv2`/`pwritev2` flags and current-offset
sentinel, plus descriptor duplication and `fcntl` flags. The eventfd regression
proves `NONBLOCK`/`CLOEXEC`, counter accumulation and reset, semaphore reads,
and Linux's reserved all-ones counter error through direct kernel seams. The
status-flags regression proves that `F_GETFL`/`F_SETFL` state is shared across
duplicates, preserves access/creation/per-descriptor bits, restores exactly,
and returns `EBADF` for a closed descriptor. The
flock regression proves only the closed advisory whole-file operation
vocabulary, duplicate open-file-description sharing/release, compatible
independent shared locks, and a nonblocking child contention/release lifecycle
with direct invalid-operation and closed-descriptor errors. It does not assert
`flock`/`fcntl` record-lock interaction, durability, or network filesystem
behavior. The
sendfile regression proves only direct descriptor inputs exercised through
borrowed handles, explicit versus shared input-position modes, short and
EOF-zero transfers, output bytes, and the signed-offset/closed-descriptor
error boundaries. It makes no socket, network, splice, pathname, C API, or
durability claim. The syscall does not transfer kernel descriptor ownership;
the public `AsFd` argument semantics remain ordinary Rust value semantics. The
copy-file-range regression proves only direct descriptor inputs exercised
through borrowed handles, independently optional explicit offsets whose updates
are staged until kernel success, null-offset shared-position advancement, short
and EOF-zero transfers, and the unsigned-range/error boundaries. It makes no
C API, errno-TLS, pathname, copy-flag, sendfile/splice-fallback,
filesystem-copy-policy, or durability claim. The syscall borrows raw descriptor
values; the public `AsFd` arguments retain ordinary Rust value semantics. The
posix-fallocate regression proves direct mode-zero range allocation through a
borrowed descriptor with unchanged shared position, `i64::MAX` range
preflight before `AsFd` conversion, and Linux's zero-length `EINVAL`. It
exposes neither general allocation flags nor C/errno-TLS behavior, pathname
allocation, filesystem fallback/policy, or durability. The
separate `fallocate` regression owns the closed general mode vocabulary and
its direct range effects; it does not broaden the public x86 support boundary.
global-sync regression proves only the unit-returning system-wide `sync(2)`
request after dirtying a disposable regular file; it deliberately makes no
timing, per-file, crash, or storage-media durability assertion. The
separate `libc-sync` static C ABI fixture adds only musl's feature-selected
`void sync(void)` spelling to that existing raw/pinned-musl boundary. It is not
`syncfs`, `sync_file_range`, `fsync`, `fdatasync`, descriptor/pathname support,
or a filesystem capability. The
syncfs regression proves regular-file and pipefs acceptance through a live
borrowed descriptor, regular-file position stability, and raw-core `EBADF`
after closure without manufacturing an invalid safe descriptor borrow. It is
a descriptor-associated filesystem writeback completion request only, not a storage-cache
durability or process/system-wide `sync(2)` claim. The
range-sync regression proves the closed flag vocabulary and signed-range
boundary, a zero-length-through-EOF writeback request with stable position,
and raw-core invalid-flag/closed-descriptor errors without manufacturing an
invalid safe descriptor borrow. The
futex regression proves borrowed-`AtomicU32` mismatch, relative-timeout,
no-waiter wake-count, race-safe wait/wake exchange behavior, and the native
`FUTEX_WAIT | FUTEX_CLOCK_REALTIME` `ENOSYS` boundary through the six-word
syscall seam; PI, requeue, bitset, fd, and waitv forms remain deferred. Futex
has no musl C wrapper, so this direct-kernel slice uses the existing x86 core
ABI test and pinned Rustix behavior fixture as its evidence.
The parameter regression proves stable scalar aux-vector observations while
retaining the x86 exclusion of the pointer-valued `AT_EXECFN` API. The pipe
regression proves Linux/x86-64's distinct `O_DIRECT` packet-mode bit, packet-tail
discard, and descriptor `CLOEXEC`. The mapping regression proves closed
anonymous/file mapping, bounded remap growth/shrink/fixed replacement,
protection, unmapping, per-range `mlock`/`mlock2(MLOCK_ONFAULT)`/`munlock` with
constrained-memlock outcomes, `msync`, closed Linux/POSIX advisory behavior, and
page-residency output/rounding, including a sparse 4 GiB file offset; it permits
`PROT_NONE`, rejects `MAP_32BIT` and wider map/protection policy, and leaves
`MREMAP_DONTUNMAP` deferred. The readiness regression proves typed
borrowed-record empty/readable/hangup pipe behavior, temporary `ppoll`
signal-mask restoration, signal-only `pause` completion, requested-flag
retention, and timeout-range rejection. The direct readiness regression proves
the x86 12-byte epoll event record, close-on-exec creation, legacy-size
validation, future-bit forwarding for Linux validation, empty and pipe
readiness, caller token preservation, modification, deletion,
initialized-prefix handling, and temporary masked-wait installation/restoration
through raw and pinned-musl probes. It also proves the 1024-bit `fd_set`, direct
select/pselect empty/readable and invalid-`nfds` behavior, raw `pselect6`
argument-six mask-pointer/size placement, and raw/pinned-musl pselect mask
restoration. This completes the bounded `io.readiness` capability, not C
polling support. The timerfd regression completes direct typed
`time::{timerfd_create, timerfd_settime, timerfd_gettime}`: the x86 32-byte
timer record, all five named clock values with alarm-clock capability results,
known and future flag forwarding, relative/absolute settings, `CANCEL_ON_SET`
acceptance, periodic-setting inspection, epoll readiness, exact expiration reads, disarming, and
invalid record/flag/descriptor handling. The filesystem
regression proves a
typed descriptor `fstat` record, typed `statfs`/`fstatfs` capacity metadata
with its derived `statvfs` views, the staged descriptor-relative pathname
lifecycle and namespace batch, direct `access`/`accessat`
  real/effective-credential observations, caller-buffer and alloc-gated `getcwd`
  plus raw caller-buffered and owned allocation-backed `readlinkat` output, the
  separately admitted bounded physical canonicalizer and explicit
  process-global CWD mutation boundary, plus
`fadvise64`/`readahead` behavior and direct bounded anonymous memory-file
creation plus seal observation/mutation, and the staged native socket/address
transport family. The
process regressions prove typed PID/identity/session observations, typed
calling-process and bounded live-target resource-limit query plus
child-contained mutation and process-global umask exchange with restore
safety, typed read-only process accounting, typed supplementary-group query/fill, direct read-only
interval-timer query plus admitted typed interval-timer control and aliases,
owned nonblocking pidfds, read-only `getpriority` plus child-contained typed
scheduling-priority mutation, typed read-only resource-usage observations,
conflicting-lock `F_GETLK`
records, scheduler-priority bounds, and direct typed round-robin interval
observations, plus the child-contained `process::chroot` transition's direct
errors, future absolute-path mutation, and unchanged CWD; the system and
thread regressions prove the named bounded kernel observations. It verifies the
explicitly admitted Rust subset only; it does not make readiness policy beyond
the named select/pselect and epoll operations, timerfd policy beyond the named
typed descriptor operations,
signalfd, target resource-limit mutation, C `struct rusage` or `struct tms` support, broader
  unselected filesystem behavior, C
  directory/temporary facilities and xattr namespace/ACL policy,
global locking policy, wider mapping policy, network interface/device,
resolver, netdb, and other
kernel-record-owning facade families, or a general x86-64 facade selectable or
supported.

The random regression proves raw Linux `getrandom` flag values and initialized
prefix handling, musl's bounded 256-byte `getentropy` behavior, and owned
deterministic state without C random globals. It does not broaden the facade
or make the C random API selectable.

The direct time regressions prove x86 `timespec` shape, bounded realtime,
monotonic, monotonic-raw, and process-CPU clock observations, normalized
results, truncated realtime-millisecond observations, nondecreasing CPU time,
and typed relative `nanosleep` completion/interruption with an explicit
remainder through the validated vDSO/direct-syscall seam. The direct
`clock_nanosleep` regression additionally proves relative and absolute
mode-specific pointer contracts, including absolute interruption with no
invented remainder, and direct error handling. The direct `getitimer`
regression proves closed selectors and canonical transient query results. The
`time.process-interval-control` regression proves child-contained `setitimer`
exchange/disarm behavior over validated microsecond settings for all selectors,
plus Rust-only `alarm`/`ualarm` aliases on `ITIMER_REAL`; C `ualarm` comparison
is limited to subsecond inputs because musl does not normalize inputs of one
second or more.

The separate `x86_64_advanced_time` regression and
`advanced-time-reference` gate add only the recorded advanced-clock and owned
POSIX-timer boundary: extended named clock IDs, process-clock validation,
borrowed descriptor-clock rejection, direct non-realtime clock-set validation,
and private POSIX-timer ownership. Civil time, timezone, C sleep/time ABI,
`SIGEV_THREAD` callbacks, broad timer/signal policy, and public x86 support
remain outside this direct facade subset.

`ldso-relocation` compiles and runs only the unintegrated
`ldso/src/x86_64_relocation.rs` source tests under the pinned native image. It
proves checked symbol-free `R_X86_64_RELATIVE` RELA and ELF64 RELR handling,
including no-mutation rejection of malformed, overlapping-table, and duplicate
targets. It does not select `crabc-ldso`, an ELF interpreter, or dynamic loader
entry point.

`ldso-image` compiles and runs only the unintegrated checked x86 ELF image
parser. It validates file-facing ELF/program-header and RELA/RELR metadata
before a future mapper or relocation engine can consume it; it neither maps an
image nor selects `crabc-ldso`.

`ldso-owned-crt-handoff-wire` is a separate private post-relocation CRT
acceptance artifact within the still-planned `ldso.dynamic-runtime` family.
`Scrt1.o` retains pinned musl's null-finalizer path for a foreign loader; only
after its direct entry handoff can it read the weak GOT-resolved
`__crabc_x86_64_owned_crt_handoff` record. The versioned record supplies a
dependency-constructor callback and a process finalizer, and the freestanding
fixture proves the bounded `PDiIMFfL` order plus malformed-record status-127
rejection. The separate publication artifact below is the only current x86
interpreter route; this acceptance artifact alone remains neither a loader
execution path nor dynamic CRT, libc, sysroot, or public x86 support.

`ldso-owned-crt-handoff` is a third private post-relocation sibling of the
initial graph. It maps the same fixed no-TLS main -> mid -> leaf shape, but
publishes exactly one immutable v1 weak-GOT record to a Rust-produced `Scrt1.o`
main after relocation. Its fixture-local no-libc lifecycle proves
`PDdIMFL` under `env -i`, while pinned musl proves the absent-record `A` path;
malformed records and an early finalizer fail closed. It uses neither `%rdx`
nor an ambient loader/libc contract, and does not select a generic loader,
DSO finalization, dynamic CRT/sysroot, or public x86 support.

`ldso-fixed-graph-introspection` is a cfg-isolated private no-TLS sibling of
that same main -> mid -> leaf loader transaction. After graph relocation,
RELRO sealing, and dependency constructors, it release-publishes the actual
three loader object records plus copied image names. One weak undefined main
`R_X86_64_GLOB_DAT` import reaches an exact immutable 40-byte v1 record whose
three callback-free operations copy a bounded image snapshot,
`dladdr`-shaped nearest-symbol metadata, and useful
`RTLD_DI_LINKMAP`-shaped per-image base/dynamic/name information. No borrowed
loader name, `link_map *`, ordinary handle, callback reentrancy, graph mutation,
or unload route crosses this wire. The candidate ET_DYN path runs under
`env -i`, carries no ambient runtime dependency or PT_TLS, and returns status
127 for a malformed record; pinned musl separately proves the corresponding
fixed-graph `dl_iterate_phdr`, `dladdr`, and
`dlopen`/`dlinfo`/`dlclose` observations. This remains a private copied-state
foundation, not public dlfcn, process RuntimeV1 publication, a general loader,
dynamic CRT/sysroot, family promotion, or public x86 support.

`ldso-fixed-graph-dlfcn` is a separate cfg-isolated no-TLS sibling that
consumes those actual post-relocation graph objects through a private
`RuntimeV1`-ordered ABI. Its exact 64-byte v1 record supplies open, symbol,
close, address, snapshot, and per-handle information callbacks. Main has a
permanent loader token; repeated mid/leaf opens acquire the same stable token
with bounded atomic reference state, and the last close makes that explicit
token stale without affecting permanent startup mapping ownership. Symbol
lookup searches only main order or the handle's fixed dependency suffix and
returns checked defined global/weak non-TLS dynamic-symbol addresses. Text,
diagnostics, and metadata are always copied. The runner verifies the exact
weak main `R_X86_64_GLOB_DAT`, dependency-free 64-byte-record ET_DYN
interpreter, fixed DT_NEEDED topology, clean environment, and absence of
PT_TLS, ambient libc/loader dependencies, and public `dl*` exports. A
link-provider negative preserves the record as a strong main import, and a
separate mid DSO preserves a weak import; the candidate rejects both with
status 127, as it does malformed record data.
Pinned musl separately proves matching fixed-startup-graph
`dlopen`/`dlsym`/`dlclose`, `dladdr`, `dlinfo`, and `dl_iterate_phdr`
observations. This artifact cannot load/search an object, promote scope,
finalize/unmap, publish process `RuntimeV1`, or select public dlfcn, candidate
libc, a general loader, dynamic CRT/sysroot, family promotion, or public x86
support.

`ldso-public-dlfcn` is the staged public-C bridge over that same immutable
loader record. The canonical x86 `libc.a` export contract now includes
`dlopen`, `dlsym`, `dlclose`, `dlerror`, `dladdr`, `dlinfo`, and
`dl_iterate_phdr`; the dynamic fixture uses an isolated PIC build of the exact
leaf so an unrelated static-errno codegen unit cannot introduce PT_TLS. The
candidate PIE still has only the fixed mid -> leaf DT_NEEDED graph and one weak
record GLOB_DAT. A 32-live-thread fixed table keyed by Linux TID owns one-shot
errors and `dladdr` names, while `dlinfo` exposes stable immutable link-map
views and iteration invokes callbacks outside the bridge lock. For a live
retained handle within the 32-slot bound, the pinned-musl `-7` differential
proves that the unsupported request preserves its output pointer, publishes
exact `Unsupported request -7`, and remains pending through a valid
`RTLD_DI_LINKMAP` query. The native differential also proves that
`dlclose(NULL)` returns one and publishes exact `Invalid library handle 0`;
non-null invalid closes remain loader-owned. For a live retained non-`RTLD_NEXT`
handle, the pinned-musl empty-name `dlsym` branch returns null and publishes
exact `Symbol not found: `; the candidate substitutes it only after its bounded
loader returns `loader symbol name is invalid`. Non-empty missing names, null
symbol pointers, and invalid handles retain their existing loader paths. For a
writable `Dl_info`, the pinned-musl `dladdr(NULL)` branch returns zero without
changing it or publishing `dlerror`; the bridge preserves that no-image
observation for a null address. For a non-null address outside every
retained fixed-image `PT_LOAD`, musl's `addr2dso` likewise finds no image and
returns zero before touching `Dl_info` or `dlerror`; the bridge admits only its
exact `loader address not found` result to preserve that observation. Other
non-null failure and unavailable-record paths retain their output-clearing
fail-closed handling. Only in this non-runtime
public bridge, `dlopen(NULL, RTLD_NOLOAD)` returns musl's permanent main handle
and leaves `dlerror` clear before mode processing; the bounded runtime-mapping
sibling continues to reject that bare NULL/NOLOAD initial-object request.
Pinned musl's `ldso/dynlink.c:dl_iterate_phdr` invokes a callback before taking
its reader lock for the next image. After the bridge's already-existing
unknown-object failure, both executions let the first callback consume the
nonempty same-thread `dlerror` once, return `74` through iteration, and leave
the next `dlerror` null. This is only a diagnostic-state reentrancy proof:
callback-driven mapping, graph mutation, and general loader reentrancy remain
unselected.
Pinned musl and project C/C++
headers prove the public LP64 ABI and ordinary behavior; raw clone workers
prove diagnostic isolation without TLS, and absent/malformed records prove
there is no ambient loader fallback. RTLD_NEXT, global promotion,
filesystem search/mapping, graph mutation, finalization, and unload remain
excluded. This artifact deliberately selects neither dlfcn capability,
`ldso.dynamic-runtime`, nor public x86 support.

`ldso-dladdr-symbol-bounds` is a separate fixed-graph `dladdr` differential
over that already-existing bridge, not an additional loader admission path.
Its real leaf has one four-byte default-visible dynamic object immediately
followed by local mapped padding. Pinned musl and the no-ambient candidate
agree that the exact object and an interior byte return its symbol, while the
one-past address still identifies the leaf but returns null `dli_sname` and
`dli_saddr`. The runner preserves the exact weak 64-byte record/GLOB_DAT
boundary, verifies the unchanged seven-symbol static archive and no PT_TLS,
and proves absent or malformed records fail closed. It adds no name search,
handle rule, graph mapping, unload/finalization behavior, dlfcn capability,
or public x86 support.

`ldso-bounded-dlopen` advances one real loader-mapping prerequisite without
widening that public claim. The cfg-isolated interpreter keeps the same
64-byte RuntimeV1-shaped record and initial main/mid/leaf graph, then
serializes exactly one slash-free basename lookup through the main image's
validated absolute RUNPATH. The candidate maps a no-TLS RELA-only ET_DYN whose
dependencies are already retained, applies final protections and RELRO, then
runs at most one validated executable legacy `DT_INIT` entry followed by its
bounded constructor array, each exactly once, and validates at most one
executable legacy `DT_FINI` target without dispatching it. Pinned musl leaves
that legacy fini hook inert on ordinary final close; `DT_FINI_ARRAY` stays
reject-only. The legacy tags are limited to the appended DSO: main/mid/leaf
`DT_INIT`/`DT_FINI` stay reject-only, and malformed runtime targets fail before
publication. Native raw-clone callers prove concurrent opens share one loader
token and one legacy/init-array sequence; a separate no-`RTLD_NODELETE`
close/reopen differential proves inert legacy fini behavior. Copied dladdr, dlinfo, and
dl_iterate_phdr observations prove the added mapping. PT_TLS, slash paths,
recursive/unretained dependencies, and second-object capacity fail closed.
The same fourth-slot DSO may carry one paired nonempty aligned 1–16-entry
load-contained `DT_PREINIT_ARRAY`/`DT_PREINIT_ARRAYSZ` metadata array. Pinned
musl ignores that DSO array during `dlopen`; the candidate checks only the tag
pair before publication and deliberately never retains, reads, or dispatches
its entries. A pair outside the DSO's load ranges fails before publication, and
initial main/mid/leaf preinit tags stay reject-only in this sibling.
Pinned musl 1.2.6 additionally proves that `RTLD_NOLOAD` returns an extra
reference only after that runtime object is present. The candidate admits that
query only for its one appended basename: it returns the same token without
path lookup, mapping, constructor execution, or snapshot change; unpresent
names, `NULL`, and named initial-graph objects fail closed. The candidate's
copied `dlpi_adds` remains unchanged for that reference, whereas pinned musl's
observation changes; musl remains the oracle here for presence/reference
semantics. `RTLD_NODELETE` is accepted only with LAZY/NOW for that same
fourth object, including a no-load reference. Its process-lifetime mapping
already supplies residency, so explicit handles still become stale on close
and no generic unload lifecycle is selected. General search/mutation, TLS growth, RTLD_NEXT, global promotion,
`DT_FINI_ARRAY`, finalization/unload, both dlfcn
capability selections, and public x86 support remain excluded.

`ldso-dynamic-admission` is the consumed aggregate admission gate for eight
real-ELF private interpreter/bridge transactions. It runs each fixture afresh, so its
positive inventory is limited to the no-TLS RELATIVE/GLOB_DAT/JUMP_SLOT plus
bounded leaf RELR graph, the GNU-Dynamic DTPMOD/DTPOFF graph, and the
owned-CRT weak-GLOB_DAT record graph, the callback-free fixed-graph
introspection record, the retained-object handle/symbol dlfcn-runtime record,
its public-C bridge, its finite-symbol `dladdr` boundary, and the one-slot runtime mapper. Their in-place malformed inputs retain the fail-closed
PT_TLS, COPY, malformed RELA/RELR, TEXTREL/static-TLS, TPOFF,
malformed/early-handoff, malformed-introspection-record, malformed-dlfcn-record,
and strong-dlfcn-import negatives. It is not a generated report or a general
loader/public-dlfcn/runtime-map-or-promote/mutable-graph/finalize-or-unload/
dynamic-CRT/sysroot/public-support claim.

`ldso-initial-graph` is one separately built private ET_DYN interpreter
artifact within still-planned `ldso.dynamic-runtime`, not the `crabc-ldso`
target. Its native runner first verifies the pinned musl 1.2.6 oracle, then
proves one fixed main PIE -> `mid.so` -> `leaf.so` graph with one absolute
fixture RUNPATH lookup, x86-64 RELATIVE/GLOB_DAT/JUMP_SLOT ELF64 RELA
relocation plus the leaf's one bounded packed `DT_RELR` direct-and-bitmap
stream with independent 512-record/512-target caps. The pre-Rust interpreter
bootstrap remains `DT_RELA`-only. It proves
leaf-before-mid dependency `DT_INIT_ARRAY` dispatch and final interpreter-and-
graph `PT_GNU_RELRO` sealing including child faults on main and leaf
`.data.rel.ro` writes. Mutated fixtures fail closed for an out-of-file
`PT_LOAD` range, `PT_TLS`, unsupported RELA, out-of-range relocation target/
table, incomplete or malformed `DT_RELR`, bitmap-without-direct-address,
nonwritable or duplicate RELR targets, over-cap RELR streams (including
zero-bit bitmap runs), `DT_TEXTREL`/static-TLS flags, and main-image `DT_INIT`.
Main-image constructor dispatch is explicitly rejected and remains future CRT
handoff work. This is not general `DT_NEEDED` or RUNPATH policy,
general or interpreter `DT_RELR`, TLS, symbol versions, `dl*`, a dynamic
CRT/sysroot, or public x86 support.

`ldso-target-root` is the companion private admission proof. It keeps the
source-root graph artifact unchanged, then rebuilds that fixed graph through
the feature-gated x86 `crabc-ldso` cdylib target and executes it as the actual
ET_DYN `PT_INTERP` candidate. The runner still rejects every DT_NEEDED and
PT_TLS runtime edge and reruns the complete fixed graph's pinned-musl and
negative-input matrix. It does not select a general x86 loader, installed
runtime, libc, dynamic CRT/sysroot, promotion, or public x86 support.

`loader-libc-general-tls-runtime-v1` is a separate private wire over the
bounded general main -> left/right -> shared initial-TLS graph. Its dedicated
cfg root reserves both the retained general-TLS state and a local/hidden
72-byte loader descriptor before `ARCH_SET_FS`; pre-FS failure releases both.
After successful installation it commits retained state without a fallible
successor, fills the descriptor, release-publishes `READY` last, and only then
allows the preflighted dependency constructor to attach the libc observer. The
observer validates ready/magic/version/ABI-size/mode/owner/generation and DTV
bounds before `ARCH_GET_FS`, `%fs`, or DTV access. Native direct evidence
checks that the record is writable, absent from `.dynsym`, outside rounded
RELRO, and reached only by its exact weak undefined main-image GOT import;
strong-main and weak-DSO import variants reject before FS installation. The
`loader-libc-general-tls-runtime-v1-target-root` companion runs the positive
path through the feature-gated Cargo root. Pinned musl remains only the
ordinary diamond's initial TLS layout/value oracle. Neither command creates a
CRT carrier, installed dynamic product, pthread/new-thread operation, DTV
growth, runtime mapping/unload, general lifecycle, promotion, or public x86
support.

`dynamic-main-thread-runtime-v1` adds one narrower private bridge above that
wire: a special Rust-produced `Scrt1.o` calls the main-resident RuntimeV1
observer immediately before a fixture-local dynamic `__libc_start_main`. The
loader accepts only Scrt1's exact weak null owned-CRT `R_X86_64_GLOB_DAT`
import; strong-main and weak-DSO variants reject before `ARCH_SET_FS`, and a
DSO definition cannot interpose. The real main and private dynamic libc prove
dynamic TLS/errno and `PIMFL` callback order. Its
`dynamic-main-thread-runtime-v1-target-root` companion executes the Cargo
feature root. This is not an owned-CRT carrier, loader finalizer/dependency
lifecycle handoff, dynamic product, worker/DTV-growth, `dlopen`, sysroot,
promotion, or public x86 support.

`ldso-initial-tls` is a separate private Variant-II GNU-Dynamic TLS artifact
inside the same still-planned `ldso.dynamic-runtime` family, not a widened
`crabc-ldso` target. Its fixed TLS-free main PIE -> `mid.so` -> `leaf.so`
graph materializes only the two DSO `PT_TLS` images, preserves initialized
values, zeroes TBSS, preserves a 4096-byte TLS alignment, assigns IDs only to
the TLS-bearing modules, and resolves `R_X86_64_DTPMOD64`/
`R_X86_64_DTPOFF64` plus `__tls_get_addr` after all relocation and before
constructors. The candidate has no external runtime dependency and runs with
an empty environment; the naked pinned-musl reference main carries only
musl's static resolver object, not a libc dependency. Mutations reject bad
`PT_TLS` size/alignment/phase/file backing/duplication, bad DTPMOD/DTPOFF,
`R_X86_64_TPOFF64`, and `DF_STATIC_TLS`. It does not select initial-exec or
TLSDESC, DTV growth, `dl*`, pthread/TCB parity, a general loader, dynamic
CRT/sysroot, full x86-64 parity, or public x86 support.

`ldso-initial-exec-tls` is a cfg-isolated private sibling of that exact
initial-TLS graph. It retains the two GNU-Dynamic DSO TLS images and their
DTPMOD/DTPOFF/`__tls_get_addr` evidence, while admitting only the leaf's one
named `tls_model(initial-exec)` value through `DF_STATIC_TLS` plus one
leaf-local `R_X86_64_TPOFF64` relocation. The native runner compares the same
clean-environment topology with pinned musl 1.2.6, proves the initialized and
mutated TPOFF value, and rejects a substituted dynamic-TLS TPOFF, nonzero
TPOFF addend, absent leaf flag, or a static-TLS GNU-Dynamic mid. It is not a
general static-TLS namespace, broader initial-exec/TLSDESC support, pthread or
TCB parity, dynamic CRT/sysroot, full x86-64 parity, or public x86 support.

The separately launched `./crt/run-x86_64.sh static-pie` gate proves the
private Rust-produced `rcrt1.o`/`crti.o`/`crtn.o` no-TLS static-PIE foundation.
Its fixture has a test-local successful TLS-bootstrap stub so it can retain
generic lifecycle and RELA/RELR relocation evidence without claiming TLS
materialization. It rejects malformed non-relative RELA data closed. This is
not a libc, pthread, dynamic-TLS, dynamic-loader, sysroot, or public
x86-support claim.

`./scripts/dev-x86_64.sh consumer-static-pie-lto` is the first private native
consumer artifact recorded under the still-planned `consumer.rust-std-lto`
family. It compiles the same no-std `crabc-rs` application plus four dependency
crates as a native O3 control and as linker-plugin LLVM bitcode for full LLD
`--lto-O3`. Both links use an ordered closed list: deterministic Rust-produced
`rcrt1.o`/`crti.o`/`crtn.o`, those Rust inputs, the exact pinned target
`libcore` rlib, a twice-reproduced object containing only the already-selected
x86 bulk-memory leaf, and the deterministic one-member
`libcrabc-builtins.a`. The gate records hashes for every input, requires
`__udivti3` trace attribution to that archive, rejects foreign runtime markers,
and inspects both outputs for x86-64 static ET_DYN closure and direct syscall
code before executing each twice with identical raw output. The O3 image keeps
the helper symbol while full LTO internalizes it. Its ignored JSON evidence is
written to `compat/reports/x86_64/consumer-static-pie-lto/latest.json`.

This first executable established the closed compiler/link/runtime boundary.
It is not stock Rust `std`, an owned sysroot, libc or loader integration, a
source build, completion or promotion of `consumer.rust-std-lto`, or public
x86 support.

`./scripts/dev-x86_64.sh consumer-native-facade-lto` is the next private
artifact in that still-planned family. It carries the named workload shape of
the AArch64 `lto-native-facade` fixture across x86 `crabc-rs`: stable getpid,
`/dev/null` open/write, pipe read/write, eventfd read/write, `F_GETFD`, and
owned descriptor close routes must all succeed before the fixed output is
emitted. The x86 fixture is separately hashed and explicitly does not claim to
be the same source because its current static CRT needs private lifecycle and
pinned-core panic owners. A runtime-derived helper call also requires the
one-member `libcrabc-builtins.a` to satisfy `__udivti3`.

The gate compiles the application and dependency crates as linker-plugin
bitcode, performs full LLD `--lto-O3` with the same ordered closed inputs as
the earlier consumer, audits the final static ET_DYN image, and executes the
whole workload twice. Every selected input is hashed; ambient CRT, libc,
loader, compiler runtime, interpreter, DT_NEEDED entry, and unresolved symbol
are rejected. Ignored evidence is written to
`compat/reports/x86_64/consumer-native-facade-lto/latest.json`. This closes a
real native-facade-shaped no-std prerequisite only. Stock Rust `std`, an
installed owned sysroot, dynamic libc/loader integration, the complete
AArch64 gate, source build, family promotion, and public x86 support remain
unproved.

`./scripts/dev-x86_64.sh libc-crt-static-tls` is the separate composed proof:
real Rust CRT objects require the hidden libc bootstrap archive boundary, then
run a high-alignment initialized/TBSS `PT_TLS` image through archive-owned
preinit/init/main/ordinary-exit/fini and one selected worker. It proves the
fixed 32-entry LIFO ordinary-exit block and rejects malformed final
`PT_TLS.p_filesz` with status 127. This remains neither general CRT or libc
startup, loader TLS, sysroot, nor public x86 support.

Apart from the narrowly named `libc-stat-compat`, `libc-credentials`,
`libc-bootstrap-primitives`, `libc-signal-control`, `libc-signal-execution`,
`libc-signal-altstack`, `libc-timerfd`, `libc-signalfd`, `libc-sigpause`,
`libc-sigisemptyset`, `libc-sigandset-sigorset`, `libc-sigpending`, and
`libc-sigrtmax`, `libc-sigrtmin`, `libc-sched-getscheduler`,
`libc-sigaddset-sigdelset-sigfillset`,
`libc-sigrtmax`, `libc-sigrtmin`, `libc-alarm`, `libc-ualarm`, `libc-usleep`,
`libc-sigaddset-sigdelset-sigfillset`,
`libc-static-tls-v1`, `libc-crt-static-tls`,
`libc-pthread-create-join-tls`, `libc-pthread-identity`, `libc-c11-lifecycle`,
`libc-pthread-detach`, `libc-thrd-sleep`, `libc-thrd-yield`, `libc-pthread-cpuclock`, `libc-pthread-name`, `libc-pthread-barrierattr-pshared`, `libc-pthread-barrier`, `libc-pthread-spin-destroy`, `libc-pthread-mutex-normal`,
`libc-pthread-rwlock`, `libc-pthread-cond-private`, `libc-c11-plain-sync`, `libc-pthread-c11-once`,
`libc-pthread-c11-tsd`,
`libc-termios-control`,
`libc-ctermid`,
`libc-grantpt`,
`libc-unlockpt`,
`libc-gethostid`,
`libc-endhostent`,
`libc-sethostent`,
`libc-gettid`,
`libc-posix-close`,
`libc-isatty`,
`libc-ttyname-r`,
`libc-tcgetpgrp`,
`libc-tcsetpgrp`,
`libc-bsearch`,
`libc-linear-search`,
`libc-intrusive-queue`,
`libc-qsort`,
`libc-getpass`,
`libc-mktemp`,
`libc-process-context`, `libc-environment`, `libc-secure-environment`, `libc-login-name`, `libc-child-reaping`, and
`libc-immediate-termination`, `libc-posix-exit`, `libc-posix-spawnattr-init`, `libc-callback-algorithms`,
`libc-search-hash-table`,
`libc-gettext-catalog`,
`libc-clock-gettime`,
`libc-clock-adjtime`,
`libc-clock-settime`,
`libc-timer-getoverrun`,
`libc-timer-delete`,
`libc-timer-gettime`,
`libc-timer-settime`,
`libc-time-observation`,
`libc-difftime`,
`libc-timegm`,
`libc-gmtime-r`,
`libc-system-configuration`,
`libc-getpagesize`,
`libc-mapping-core`,
`libc-memory-sync`,
`libc-memory-locking`,
`libc-memfd-create`,
`libc-header-layouts-baseline`,
`libc-nanosleep`,
`libc-usleep`,
`libc-sleep`,
`libc-clock-nanosleep`,
`libc-descriptor-entry`,
`libc-access`,
`libc-fcntl-status-control`,
`libc-fcntl-record-locks`,
`libc-flock`,
`libc-sendfile`,
`libc-tee`,
`libc-splice`,
`libc-sync-file-range`,
`libc-copy-file-range`,
`libc-posix-fallocate`,
`libc-filesystem-capacity`,
`libc-vector-io`,
`libc-ioctl`,
`libc-sysv-semaphore`,
`libc-mq-setattr`,
`libc-sysv-message-shared-memory`,
`libc-event-descriptors`,
`libc-pathname-lifecycle`,
`libc-mkfifo`,
`libc-mkdirat`,
`libc-mkfifoat`,
`libc-readlinkat`,
`libc-linkat`,
`libc-renameat2`,
`libc-lchown`,
`libc-hasmntopt`,
`libc-descriptor-io`,
`libc-descriptor-lifecycle`,
`libc-descriptor-pipeline`,
`libc-timestamp-updates`,
`libc-process-resources`, `libc-readiness-waits`, and
`libc-system-observation`, `libc-system-information`, `libc-uts-identity`, `libc-socket-transport`,
`libc-socket-messages`,
`libc-byte-strings`, `libc-legacy-memory`, `libc-memccpy`, `libc-mempcpy`, `libc-strsep`, `libc-strtok`, `libc-random-entropy`, `libc-memory-search`,
`libc-string-copy`, `libc-allocator-string-duplication`, `libc-scandir`,
`libc-filesystem-traversal`, `libc-filesystem-directory`, `libc-error-strings`,
`libc-locale-error-strings`, `libc-ctype`, `libc-integer-arithmetic`,
`libc-integer-parse`, `libc-float-parse`, `libc-getsubopt`, `libc-l64a`, `libc-a64l`, `libc-intmax-arithmetic`, `libc-credential-observation`,
`libc-ffs`, `libc-math-complex`, `libc-math-complex-complete`, `libc-elementary-sqrt-fenv`, and
`libc-fenv-rounding` static archive harnesses, and the separately scoped
`static-pie` CRT gate, and the bounded `owned-static-sysroot` installed
artifact gate, the lane owns no
allocator evidence beyond the separately scoped wrapper, string-duplication,
and observability artifacts, and exposes no generic Cargo, shell, general
`crabc-libc` artifact, dynamic-loader artifact, general CRT, or complete
sysroot command. Those remain separate future completion work under
`x86-64.md`; passing any command must not be reported as x86_64 runtime parity.
