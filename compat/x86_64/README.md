# Native x86_64 foundation evidence

This closed, native Linux/x86_64 lane is foundation evidence named by
[`x86-64.md`](../../x86-64.md). It runs the fixed `crabc-core` lib suite and
the separately admitted direct `crabc-rs` subset for the
`x86_64-unknown-linux-musl` target, including only the proved `fs::flock`
whole-file advisory locking, `fs::sendfile` descriptor transfer,
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
lifetime. It leaves `mq_notify`, C mqueue APIs/ABI and `errno` TLS, and public
x86 runtime support unselected.
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
runtime support unselected.
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
./scripts/dev-x86_64.sh header-abi-project
./scripts/dev-x86_64.sh math-complex-header-abi
./scripts/dev-x86_64.sh sys-reg-header-abi
./scripts/dev-x86_64.sh types-header-abi
./scripts/dev-x86_64.sh stat-header-abi
./scripts/dev-x86_64.sh ctype-header-abi
./scripts/dev-x86_64.sh integer-arithmetic-header-abi
./scripts/dev-x86_64.sh integer-parse-header-abi
./scripts/dev-x86_64.sh intmax-arithmetic-header-abi
./scripts/dev-x86_64.sh credential-observation-header-abi
./scripts/dev-x86_64.sh child-reaping-header-abi
./scripts/dev-x86_64.sh immediate-termination-header-abi
./scripts/dev-x86_64.sh callback-algorithms-header-abi
./scripts/dev-x86_64.sh ffs-header-abi
./scripts/dev-x86_64.sh byte-strings-header-abi
./scripts/dev-x86_64.sh memory-search-header-abi
./scripts/dev-x86_64.sh string-copy-header-abi
./scripts/dev-x86_64.sh random-entropy-header-abi
./scripts/dev-x86_64.sh time-header-abi
./scripts/dev-x86_64.sh poll-header-abi
./scripts/dev-x86_64.sh select-header-abi
./scripts/dev-x86_64.sh fcntl-header-abi
./scripts/dev-x86_64.sh unistd-header-abi
./scripts/dev-x86_64.sh system-header-abi
./scripts/dev-x86_64.sh syscall-header-abi
./scripts/dev-x86_64.sh signal-header-abi
./scripts/dev-x86_64.sh mman-header-abi
./scripts/dev-x86_64.sh resource-header-abi
./scripts/dev-x86_64.sh socket-header-abi
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
./scripts/dev-x86_64.sh libc-pthread-create-join-tls
./scripts/dev-x86_64.sh termios-header-abi
./scripts/dev-x86_64.sh libc-termios-control
./scripts/dev-x86_64.sh libc-process-context
./scripts/dev-x86_64.sh libc-child-reaping
./scripts/dev-x86_64.sh libc-immediate-termination
./scripts/dev-x86_64.sh libc-callback-algorithms
./scripts/dev-x86_64.sh libc-clock-gettime
./scripts/dev-x86_64.sh libc-system-configuration
./scripts/dev-x86_64.sh libc-mapping-core
./scripts/dev-x86_64.sh libc-header-layouts-baseline
./scripts/dev-x86_64.sh libc-nanosleep
./scripts/dev-x86_64.sh libc-clock-nanosleep
./scripts/dev-x86_64.sh libc-descriptor-entry
./scripts/dev-x86_64.sh libc-fcntl-status-control
./scripts/dev-x86_64.sh libc-descriptor-io
./scripts/dev-x86_64.sh libc-process-resources
./scripts/dev-x86_64.sh libc-readiness-waits
./scripts/dev-x86_64.sh libc-system-observation
./scripts/dev-x86_64.sh libc-uts-identity
./scripts/dev-x86_64.sh libc-socket-transport
./scripts/dev-x86_64.sh libc-byte-strings
./scripts/dev-x86_64.sh libc-random-entropy
./scripts/dev-x86_64.sh libc-memory-search
./scripts/dev-x86_64.sh libc-string-copy
./scripts/dev-x86_64.sh libc-ctype
./scripts/dev-x86_64.sh libc-integer-arithmetic
./scripts/dev-x86_64.sh libc-integer-parse
./scripts/dev-x86_64.sh libc-intmax-arithmetic
./scripts/dev-x86_64.sh libc-credential-observation
./scripts/dev-x86_64.sh libc-ffs
./scripts/dev-x86_64.sh libc-thread-pointer
./scripts/dev-x86_64.sh libc-foundation
./scripts/dev-x86_64.sh libc-fenv
./scripts/dev-x86_64.sh libc-math-complex
./scripts/dev-x86_64.sh libc-memory
./scripts/dev-x86_64.sh libc-setjmp
./scripts/dev-x86_64.sh libc-atomic
./scripts/dev-x86_64.sh libc-clone-raw
./scripts/dev-x86_64.sh libc-signal-foundation
./scripts/dev-x86_64.sh ldso-relocation
./scripts/dev-x86_64.sh ldso-image
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

`headers-layouts.toml` is the checked-in contract for the thirty selected
native header gates. It names each dispatcher command, direct C/C++ probe and
runner, and only the project headers explicitly included by those probes. It
does not claim a transitive include closure, complete installed headers,
archive linkage, runtime completion, or public x86 support; the ledger
validator rejects a missing, renamed, or reclassified gate.

`public-header-surface` adds the separate all-public-header inventory needed
before that bounded gate set can grow into a completion contract. It derives
the 183 pinned-musl public header paths, compares them to the checked-in
`public_headers.txt` inventory, requires every reference path to exist in the
project include tree, and compiles each empty C11+GNU consumer with project
headers first and then with pinned musl alone. The current native image records
180 jointly consumable headers, three shared missing-Linux-UAPI inputs
(`sys/kd.h`, `sys/soundcard.h`, and `sys/vt.h`), and eight candidate-only
headers. The report is generated under `compat/reports/`; it is a
consumability/accounting artifact, not declaration, layout, linkage, runtime,
installed-header completion, or public x86 support evidence.

`headers-layouts-foundation.toml` is the planned v2 contract that turns those
separate inventories into a reviewable closure plan without claiming that the
plan has run. It partitions all 183 pinned paths plus eight project-only
extensions, retains the three `sys/*` wrappers as explicit Linux 5.10 UAPI
dependencies rather than ignored gaps, and expands every class across C11 and
C++17 GNU plus strict/POSIX/XOPEN/BSD feature profiles. The one current
partial result is the 180 non-UAPI C11+GNU empty consumers; C++ applicability,
feature visibility, isolated candidate transitive closure, declaration/layout
comparison, and callable linkage are still individual required matrix work.
The static-export list is only an input to that linkage audit: unlisted public
callables remain owned by planned `libc.c-abi-compat`, while noncallable header
ABI remains owned by `libc.headers-layouts`. The v2 contract keeps this family
planned and makes no installed-header, runtime, or public-support claim.

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
and unmangled C++ linkage. Its C executables intentionally link pinned musl's
math runtime, so it is header semantics only—not general math, `crabc-libc`,
or public x86 support.

`sys-reg-header-abi` places the project headers first and compile-checks the
27 Linux/x86-64 ptrace register-index macros in `<sys/reg.h>`. It is another
declaration-only header ratchet, not a ptrace runtime or `crabc-libc` claim.

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
classification/case-conversion declarations are unconditional; `isascii` and
`toascii` require POSIX/XOPEN/GNU/BSD feature selection. Strict C verifies
those two extension declarations stay hidden, while the C++ companion is
checked positively because its driver implicitly enables GNU declarations.
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

`intmax-arithmetic-header-abi` compiles project-first and pinned-musl C/C++
`<inttypes.h>` declarations for `imaxabs` and `imaxdiv`. Both declarations are
unconditional; the probes additionally ratchet the x86 LP64 `imaxdiv_t` field
layout, return type, and unmangled C++ linkage. This is compile-only header
evidence for the arithmetic forms only; it is distinct from the separately
staged `strtoimax`/`strtoumax` declaration and archive evidence, and does not
select `crabc-libc` or a general C runtime ABI.

`credential-observation-header-abi` compiles project-first and pinned-musl
C/C++ `<unistd.h>` declarations for unconditional `getgroups` and GNU-only
`getresuid`/`getresgid`. Strict, POSIX, and BSD selections must hide both
`getres*` declarations; the GNU C++ probe additionally checks unmangled C
linkage. This is compile-only header evidence; it does not select account
database, credential-mutation, or a general C-process ABI.

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

`byte-strings-header-abi` compiles project-first and pinned-musl C/C++
`<string.h>` declarations for the closed byte-string set: `index`, `rindex`,
`strchr`, GNU-gated `strchrnul`, `strcmp`, `strcspn`, `strlen`, `strncmp`,
`strnlen`, `strpbrk`, `strrchr`, `strspn`, and `strstr`. A strict POSIX C pass
expects `strchrnul` to remain hidden, matching musl; C++ remains GNU-selected
by its driver. This is compile-only
header evidence; it does not select C string behavior or `crabc-libc`.

`memory-search-header-abi` compiles project-first and pinned-musl C/C++
`<string.h>` declarations for the closed memory-search set: unconditional
`memchr`, POSIX/GNU-gated `memmem`, and GNU-gated `memrchr`. Strict C checks
keep the feature-gated declarations hidden, while the C++ companion is checked
positively because its driver implicitly enables GNU declarations. This is
compile-only header evidence; it does not select C memory-search behavior or
`crabc-libc`.

`string-copy-header-abi` compiles project-first and pinned-musl C/C++
`<string.h>` declarations for the closed C-string-copy set: unconditional
`strcpy`/`strncpy`/`strcat`/`strncat`, POSIX/XOPEN/GNU/BSD-gated
`stpcpy`/`stpncpy`, and GNU/BSD-gated `strlcpy`/`strlcat`. Strict C checks
keep the feature-gated declarations hidden, while the C++ companion is checked
positively because its driver implicitly enables GNU declarations. This is
compile-only header evidence; it does not select C string-copy behavior or
`crabc-libc`.

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
records, selected extensions, and large-file aliases including `lockf64`. It
is source-only header evidence; it does not provide descriptor behavior or
select `crabc-libc`.

`unistd-header-abi` compiles project and pinned-musl C/C++ `<unistd.h>`
declarations, including the staged x86 LP64 POSIX/GNU selectors, process and
system helper declarations, GNU hostname/domain-name signatures, lock
constants, and large-file aliases. It is source-only and does not select C
process, filesystem, descriptor, namespace, or UTS-identity behavior.

`system-header-abi` compiles project and pinned-musl C/C++ `<sys/utsname.h>`
and `<sys/sysinfo.h>` declarations, including the GNU 65-byte `nodename` and
`domainname` fields in the 390-byte public `utsname` record and the public
368-byte sysinfo compatibility record. It is source-only and distinct from the
bounded Rust kernel-prefix system-information slice.

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

`resource-header-abi` compile-checks strict and GNU/LFS C and C++
`<sys/resource.h>` records, selectors, priorities, declarations, and aliases
against pinned musl: an unsigned-long-long `rlim_t`, 16-byte `rlimit`, and
272-byte `rusage` with its caller-resident 128-byte tail. It is source-only
header evidence and does not select process-resource behavior or `crabc-libc`.

`socket-header-abi` compile-checks project-first and pinned-musl GNU C/C++
`<sys/socket.h>` and `<netinet/in.h>` base transport declarations, then runs a
tiny C probe through each header set for the installed IPv6 address-
classification macros. It covers only generic and IPv4/IPv6 socket-address
records, `socklen_t`, selected address-family/type, creation, shutdown, and
basic send/receive constants, the `socket`/`socketpair`,
bind/listen/accept/`accept4`/connect, send/receive, name-query, and shutdown
signatures, and the named IPv6 macro classifications. It is source-only header
evidence: it does not select socket options, vector or ancillary-message APIs,
address-conversion or socket behavior, `crabc-libc`, or public x86 support.

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
APIs, xattr file-handle and symlink-storage policy, and broader filesystem
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
filesystem's symlink-xattr policy. This does not select the separately
evidenced `filesystem.extended-metadata` slice, xattr file-handle APIs, C
directory/temporary APIs, C `sys/xattr.h` or errno TLS, or public x86 support.

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
select `mq_notify`, SysV IPC, semaphores, AIO, C mqueue headers/APIs/errno TLS,
a C ABI, or public x86 support.

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
`EBADF` outcomes. It does not select C `sys/inotify.h` headers/APIs/ABI or
errno TLS, legacy `inotify_init`, fanotify, recursive/background watcher
policy, global registries, namespaces/capability mutation, wider system
facilities, or public x86 support.

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
alternate stacks, signalfd, legacy signal APIs, pthread signal/cancellation
policy, generic process lifecycle, libc.so, CRT, loader, sysroot, signal/header
family completion, or public x86 support.

`libc-pthread-create-join-tls` is a separately recorded static
`verified_artifact` under the still-planned `libc.pthread-tls` family. Its
project-header C body first runs against pinned musl and then in a
`-nostdlib -static` candidate. It selects a null-attribute `pthread_create`
with one `pthread_join` for either a normal return or the selected-worker
`pthread_exit` path: each concurrently live worker has a distinct zeroed
initial-TLS `errno` slot, a pointer result crosses the join boundary, and the
creator's `errno` remains unchanged. The gate proves the hidden musl-shaped
clone=56 register shuffle, selected exit=60 path, the clear-child-tid shared
futex=202 wait, and post-exit munmap=11 reclamation. A fixed private 64-worker
registry validates the explicit-exit caller's `%fs:0`, kernel `gettid`, and
still-live clear-child-tid word, serializes publication with join withdrawal,
and is exhausted/reused by a candidate-only capacity route. It does not select
attributes, detach, pthread-exit cleanup/TSD/main-thread behavior, self/equal,
cancellation, synchronization objects, dynamic TLS/DTV, loader or CRT TLS,
C11 threads, or public x86 support.

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

`libc-callback-algorithms` is a separately recorded
`static-c-callback-algorithms` `verified_artifact` gate over that archive, not
a general sorting/searching capability. Its project-header C body first
executes the public `bsearch`, `qsort`, and `qsort_r` cases through pinned musl
and then through a `-nostdlib -static` candidate; the candidate also directly
exercises private `__qsort_r`. It closes exactly `bsearch`, `__qsort_r`, and
`qsort` as strong exports plus weak, same-address `qsort_r`. The fixed musl
smoothsort core retains its O(1) cycling buffer; `qsort` adapts its
two-argument callback, and GNU/BSD `qsort_r` retains its final-context
callback ABI. The fixture proves bsearch hit/miss/zero-element behavior,
ordinary and wide-record sorting with byte preservation, context identity,
the private helper, and a caller's strong `qsort_r` override. This stateless,
allocation-free leaf has no syscall, errno, TLS, allocator, or mutable state.
It is private native x86 evidence only: it excludes generic C sorting/search,
callback registries, C longjmp/C++ exception transport, dynamic runtime, and
public x86 support.

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
It excludes `msync` cancellation, `mremap`, `mlock*`, remap/shared-memory and
memfd paths, mapping policy, allocator, libc.so, CRT, loader, sysroot, and
public x86 support. This is one artifact within planned `libc.posix-runtime`,
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
runtime exists. It excludes `sleep`/`usleep`, C clock/timer state, signal
policy, dynamic runtime, and public x86 support.

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
four successful calls, and direct `EBADF` errors. Every other public C
command, including `F_GETLK`, `F_GETOWN`, `F_DUPFD*`, record/OFD locks,
ownership, leases, and seals, deliberately returns `-1`/`EINVAL` before a
vararg is observed or a syscall runs. The broader header declarations and the
separate direct Rust `F_GETLK`/status/seal slices do not widen this C
artifact. It excludes `lockf`/`flock`, cancellation, generic descriptor or
filesystem policy, general runtime, and public x86 support.

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
direct Linux syscall path. It excludes epoll/eventfd, C open/path, generic
fcntl-command, or vector I/O, AIO, generic signal delivery/waits, pthread mask policy, timers,
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
excludes the separately recorded hostname/domain identity artifact,
system-file parsing, process identity, generic system information, dynamic
runtime, and public x86 support.

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

`libc-byte-strings` is a separately recorded
`static-c-byte-strings` `verified_artifact` gate over that archive, not a
promotion of the Rust-subsumed text capabilities. Its project-header C body
first executes through pinned musl and then through a `-nostdlib -static`
candidate. It selects only `index`/`rindex`, `strchr`/`strchrnul`, `strcmp`,
`strcspn`, `strlen`, `strncmp`, `strnlen`, `strpbrk`, `strrchr`, `strspn`, and
`strstr`. Musl's public `index` and `rindex` entries are forwarding wrappers
mapped to `strchr` and `strrchr`; its private `__strchrnul` and `__memrchr`
helpers remain internal, while scalar fallback behavior is retained as an
intentional implementation boundary. The artifact excludes stateful string,
locale, allocation, vectorized, dynamic-runtime, and public-x86-support
claims.

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
the byte-string, immediate-termination, and callback-algorithms candidates
deliberately do neither because their selected functions do not observe errno.
All candidates have no interpreter,
`DT_NEEDED`, unresolved symbols, dynamic TLS resolver, allocator, or ambient C
runtime. Apart from the bounded child mapping established by
`libc-pthread-create-join-tls`, their fixture setup is not a CRT, general TLS
lifecycle, pthread runtime, dynamic-loader, sysroot, `libc.so`, or public-x86-
support claim.

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
float/double/long-double complex access and conjugation. The gate rejects
ambient `libm`, unselected `cabs*`/`carg*`/`cproj*`, powers, and
transcendentals. It is only a classification/sign and x87 long-double/complex
foundation, not scalar/complex math completion, `libc.so`, CRT/TLS lifecycle,
loader, sysroot, or public x86 support.

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
  directory/temporary facilities and xattr file-handle APIs,
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

The separately launched `./crt/run-x86_64.sh static-pie` gate proves the
private Rust-produced `rcrt1.o`/`crti.o`/`crtn.o` static-PIE foundation. Its
no-`PT_TLS` form retains generic lifecycle behavior; its high-alignment
initialized/TBSS local-exec form proves one main-executable x86 Variant-II
image below a `%fs:0` self pointer before preinit/init/main/fini. It validates
the program-header/image boundary and fails malformed TLS metadata closed.
This is not a libc, pthread, dynamic-TLS, dynamic-loader, sysroot, or public
x86-support claim.

Apart from the narrowly named `libc-stat-compat`, `libc-credentials`,
`libc-bootstrap-primitives`, `libc-signal-control`, `libc-signal-execution`, and
`libc-pthread-create-join-tls`, `libc-termios-control`,
`libc-process-context`, `libc-child-reaping`, and
`libc-immediate-termination`, `libc-callback-algorithms`,
`libc-clock-gettime`,
`libc-system-configuration`,
`libc-mapping-core`,
`libc-header-layouts-baseline`,
`libc-nanosleep`,
`libc-clock-nanosleep`,
`libc-descriptor-entry`,
`libc-fcntl-status-control`,
`libc-descriptor-io`,
`libc-process-resources`, `libc-readiness-waits`, and
`libc-system-observation`, `libc-uts-identity`, `libc-socket-transport`,
`libc-byte-strings`, `libc-random-entropy`, `libc-memory-search`,
`libc-string-copy`, `libc-ctype`, `libc-integer-arithmetic`,
`libc-integer-parse`, `libc-intmax-arithmetic`, `libc-credential-observation`,
`libc-ffs`, and `libc-math-complex` static archive harnesses, and the separately scoped
`static-pie` CRT gate,
the lane owns no
allocator evidence and exposes no generic Cargo, shell, general `crabc-libc`
artifact, dynamic-loader artifact, general CRT, or sysroot command. Those remain
separate future completion work under `x86-64.md`; passing any command must
not be reported as x86_64 runtime parity.
