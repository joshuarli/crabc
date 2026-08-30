# `crabc-rs` design

`crabc-rs` is the idiomatic Linux/AArch64 OS/runtime facade over the shared
`crabc-core` implementation. It is not a generated C-wrapper crate. Its
current platform is Linux/AArch64 little-endian with Linux 5.10 as the kernel
baseline; no second `crabc` architecture is planned.

## Boundary

```text
Rust application
       │
   crabc-rs
       │ direct typed Linux operations
   crabc-core
       │
Linux kernel
```

Syscall-like native APIs must not round-trip through the public C ABI or TLS
`errno`. The only permitted runtime-state exception is the append-only,
versioned private `RuntimeV1` bridge owned by libc/ldso; it is used where
loader, thread/TLS, or opt-in stdio state cannot be represented as a direct
kernel operation.

## API rules

- Prefer typed descriptors, paths, flags, errors, resource ownership, and
  explicit buffer initialization over C pointers, sentinels, globals, or
  `errno`.
- A safe API must make invalid ownership/lifetime states unrepresentable. A
  public unsafe API documents exact pointer provenance, alignment, aliasing,
  lifetime, and process-state obligations.
- Process-global mutation (environment, cwd/root, credentials, signals,
  loader state) must expose its coordination boundary rather than hide it.
- `std` integration is welcome; `no_std` remains a supported base. The crate
  does not grow an async runtime, portability framework, process supervisor,
  security-policy layer, or C-varargs imitation.
- Use Rustix only as a pinned API/behavior/source oracle. It is never a
  production dependency.

## Capability accounting

[`compat/crabc-rs/coverage.toml`](../../compat/crabc-rs/coverage.toml) owns
the exact classification of every measured C capability and native seam. A
group is either verified with evidence, deferred with a concrete contract, or
documented as ABI-only, Rust-subsumed, internal runtime, or the allocator scope
exception. Do not turn a documented C group into a native API merely to raise
a wrapper count.

The exact classification and scope limits for deferred groups are in
[`compat/crabc-rs/coverage.toml`](../../compat/crabc-rs/coverage.toml); the
relevant acceptance contract is selected through [`STATUS.md`](../../STATUS.md).
Completed delivery rationale is preserved in the
[historical `crabc-rs` record](../history/crabc-rs-delivery-plan.md).

## Bounded netdb snapshots

`crabc_rs::netdb` provides immutable owned snapshots for `/etc/hosts`,
`/etc/services`, and `/etc/protocols`. `HostDatabase`, `ServiceDatabase`, and
`ProtocolDatabase` accept caller bytes or load their conventional system file
through direct Linux file operations; strict UTF-8 records can be enumerated
in source order and lookups return owned clones. Blank/comment lines are
ignored, malformed non-empty records reject the complete snapshot, system
loads are capped at one mebibyte, and direct I/O errors remain typed. This is
deliberately not `/etc/networks`, NSS/provider discovery, resolver policy, or
the C static-buffer netdb ABI.

The private native x86 evidence lane selects all three owned snapshot types
after separate resolver and netdb evidence. This does not change the public
platform-support boundary.

The same private x86 lane separately selects `filesystem.path-core` through
its direct `fs_x86_64` boundary. The admitted subset composes typed
descriptor-relative metadata and pathname lifecycle operations, links/rename,
bounded timestamp mutation, and raw plus alloc-gated owned `readlink` values.
Owned target reads preserve arbitrary non-NUL bytes and retry whenever Linux
returns a length equal to the supplied capacity, because that result does not
distinguish a complete exact fit from truncation. This does not add the
separately selected `filesystem.canonicalize`/`filesystem.cwd-mutation` or
`filesystem.extended-metadata` statx-specific boundaries, C-style directory or
temporary-file abstractions, the separately selected xattr, directory-record,
and temporary-object boundaries, a C filesystem ABI, or public x86 support.

The same private x86 lane separately selects `filesystem.xattr` through
`fs_x86_64` direct syscall forms. `getxattr`/`lgetxattr`/`fgetxattr` and the
matching setters, listers, and removers accept only caller-owned byte buffers,
paths, and descriptors: values preserve arbitrary bytes, zero-length get/list
buffers query the required length, and successful reads expose only initialized
prefixes. `XattrFlags` retains unknown bits for Linux to validate. The evidence
does not impose symlink-xattr storage policy—its no-follow form is exercised on
a regular file—and it does not select the separately evidenced
`filesystem.extended-metadata` boundary or newer `*xattrat` forms. The separate
private static C artifact owns the bounded `sys/xattr.h`/errno state; neither
slice establishes public x86 support.

The same private x86 lane separately selects the allocation-free
`filesystem.directory` trio through `raw_dir.rs` and `fs_x86_64.rs`.
`RawDir` borrows a caller-owned `MaybeUninit<u8>` buffer, validates Linux
`getdents64` records, and returns byte-preserving borrowed names; `Dir` owns a
close-on-exec directory descriptor over that same record iterator. Its seek
and rewind operations use opaque Linux `d_off` cookies and discard buffered
records. This is neither a C `DIR`/`dirent` wrapper nor an enumeration policy:
`readdir_r`, `scandir`, sorting/walking helpers, public `telldir`, C
temporary-file/directory APIs, CWD mutation, C ABI/errno state, and public x86
support remain out of scope.

The same private x86 lane separately selects
`filesystem.temporary-objects` through `fs_x86_64.rs`. `NamedTempFile`
creates a mode-`0600`, close-on-exec entry from an explicit directory authority,
retains a duplicate parent descriptor for cleanup, and uses a 96-bit
`getrandom` hexadecimal basename; moving its file descriptor out deliberately
persists the entry. `TempFile` instead opens `O_TMPFILE | O_RDWR | O_CLOEXEC`
without a directory entry and returns `EOPNOTSUPP` unchanged rather than
falling back to a named file. The temporary-directory forms use atomic
mode-`0700` `mkdirat` creation and return byte-preserving caller-buffered or
alloc-owned paths. This does not select C `mkstemp`/`mkdtemp`/`tmpfile`/`tmpnam`/
`tempnam`/`mktemp` APIs, a default temporary-directory policy or global
registry, CWD mutation, canonicalization, the separately selected statx-only
`AT_EMPTY_PATH` form, file-handle APIs, C ABI/errno state, or public x86
support.

The same private x86 lane separately selects
`filesystem.extended-metadata` through `fs_x86_64.rs` and the shared private
`crabc_core::fs::statx_raw` wire seam. `fs::statx` copies a typed value from an
aligned 256-byte Linux 5.10 record and keeps the returned field mask authoritative.
Its dedicated flag vocabulary admits `AT_EMPTY_PATH` only for `statx`; it does
not widen other `*at` APIs. The reserved request bit rejects before entry and
future requested bits are masked to the known record layout. This is a direct,
stateless syscall boundary: an `ENOSYS` result remains an `ENOSYS` result,
rather than reproducing musl's `fstatat` compatibility fallback. C
`struct statx`/`sys/stat.h` ABI, general `AT_EMPTY_PATH`, the separately
selected canonicalization/CWD-mutation boundary, file-handle APIs, errno state,
and public x86 support remain out of scope.

The same private x86 lane separately selects `filesystem.canonicalize` and
`filesystem.cwd-mutation` through `fs_x86_64.rs` and `process_x86_64.rs`.
`fs::canonicalize_into` builds a physical absolute pathname in a fixed
`PATH_MAX=4096` workspace, while alloc-gated `fs::canonicalize` returns the
same byte-preserving path as an owned `CString`. Both use direct
`openat`/`readlinkat`/`getcwd` operations, normalize `.` and `..`, resolve
relative and absolute symbolic links, reject interior NULs, and bound traversal
at forty symbolic links. `process::chdir` and `process::fchdir` directly expose
process-global CWD mutation rather than presenting it as thread-local state;
callers must coordinate concurrent pathname work and may restore with an owned
directory descriptor. The selected boundary does not add `chroot` or
`process.root-change`, C `realpath`/`chdir`/`fchdir` APIs, errno state, a C
filesystem ABI, or public x86 support.

The same private x86 lane separately selects `process.root-change` through
`process_x86_64.rs`. `process::chroot<P: PathArg>` accepts safe byte paths,
uses direct Linux x86 syscall `chroot=161`, and returns direct `Errno` failures.
A successful call changes future absolute pathname resolution process-wide but
leaves CWD unchanged; it provides neither restoration nor a route to the old
root. This is not a containment or sandbox boundary. The
`./scripts/dev-x86_64.sh root-change-reference` gate keeps successful focused
Rust and pinned-musl/raw C oracle transitions in disposable child processes
with `CAP_SYS_CHROOT`; it also builds the existing `no_std`
`process_chroot_direct_probe`. This selects no C ABI or errno TLS,
`pivot_root`, mount namespaces, or public x86 support.

The same private x86 lane separately selects `process.thread-kill` through
`signal.rs`. `signal::kill_thread(tid, signal)` accepts typed positive `Pid`
and application-visible `Signal` values, fixes `tgid` to the calling process,
and directly invokes Linux x86 `tgkill=234` for one named thread. It preserves
direct `ESRCH` for an impossible/nonmember target and `EINVAL` for an invalid
signal. The `./scripts/dev-x86_64.sh thread-kill-reference` gate combines a
disposable-process Rust handler regression, the no-std
`thread_kill_direct_probe`, and a pinned-musl/raw C signal-delivery oracle. The
raw half is the exact syscall ABI proof and verifies a live worker's pending
signal, handler TID, and delivery. Musl's adjacent `pthread_kill` behavior
uses `tkill`, so it does not imply a selected musl `tgkill` API. This selects
no generic process/group signaling, signal masks, queues, `signalfd`,
signal-management framework, C ABI or errno TLS, pthread cancellation, or
public x86 support.

The same private x86 lane separately selects `memory.mapping` through
`mm_x86_64.rs`: unsafe `mm::{mmap, mmap_anonymous, mprotect, munmap}` invoke
the direct `mmap=9`, `mprotect=10`, and `munmap=11` seams. `ProtFlags` and
`MprotectFlags` are closed to `READ`, `WRITE`, and `EXEC` (empty is
`PROT_NONE`), while `MapFlags` requires exactly shared or private and the
anonymous spelling supplies `MAP_ANONYMOUS`. Fixed-address and wider map bits,
including `MAP_FIXED` and `MAP_32BIT`, reject before entry. Callers retain
pointer provenance, mapping lifetime, file-backing, and reference-validity
obligations: no reference may survive `munmap` or an incompatible
`mprotect`.

`./scripts/dev-x86_64.sh mapping-reference` combines a focused Rust regression
and no-std `mapping_direct_probe` with paired raw/pinned-musl child evidence.
It covers the anonymous RW → RO → RW lifecycle and unique unmap, a shared
file mapping over a borrowed memfd, zero-length and closed-flag rejection, and
the direct unaligned `mprotect` error. The C fixture pins the selected LP64
values and lifecycle in both arms; unaligned `mprotect` is `EINVAL` only in
the raw syscall arm, because musl 1.2.6 rounds its wrapper input before making
the syscall. That wrapper policy is oracle evidence, not selected Rust
behavior. This selects no `mremap`, mapping locks/sync/advice/residency,
the separate `memory.vm` program-break/process-wide-lock/legacy-remap
boundary, fixed or wider mapping modes, C `sys/mman.h` ABI or errno TLS, or
public x86 support.

The private x86 lane separately selects `memory.vm` through
`process_x86_64.rs` and `mm_x86_64.rs`. It admits unsafe
`process::kernel_brk` for null-query and exact-replay evidence only, closed
`mm::MlockAllFlags`, `mm::{mlockall, munlockall}`, and unsafe
`mm::remap_file_pages`. The direct x86 seams are `brk=12`, `mlockall=151`,
`munlockall=152`, and `remap_file_pages=216`. `brk` returns the current break
pointer even when Linux cannot adjust it; this narrow boundary is therefore
not libc `brk`/`sbrk` bookkeeping or allocator management.
The raw C arm proves null-query and same-address replay. Pinned musl 1.2.6
uses `sbrk(0)` to observe that same current pointer, but its `brk(current)`
wrapper deliberately returns `ENOMEM`; the raw break remains unchanged. This
is an oracle wrapper distinction, not selected Rust behavior.

`MlockAllFlags` admits only `MCL_CURRENT=1`, `MCL_FUTURE=2`, and
`MCL_ONFAULT=4`. `mlockall` changes policy for the calling process, so the
`memory-vm-reference` focused Rust regression and paired raw/pinned-musl C
arms run it in disposable children and attempt `munlockall` cleanup. A valid
request can retain direct `EPERM`, `ENOMEM`, or `EAGAIN` when capability or
`RLIMIT_MEMLOCK` limits apply. The unsafe legacy remap seam fixes the C
compatibility protection and flags words to zero; selected evidence is only a
one-page anonymous mapping with direct `EINVAL` in raw and musl arms, not
file-backed remapping behavior.

This is private Rust-only evidence. It selects no allocator, heap, or
program-break adjustment policy; no `mremap` or fixed maps; no range locks,
sync, advice, or residency facilities; no file-backed legacy-remap policy; no
C VM API/header/ABI or errno TLS; and no public x86 support.

## Caller-owned resolver snapshots

`resolver::ResolverConfig` owns a bounded snapshot of conventional resolver
configuration. `from_bytes` accepts caller-supplied `/etc/resolv.conf` and
`/etc/hosts` bytes for isolated fixtures, while `from_system` reads those two
files directly through crabc's Linux file operations; neither constructor
consults process-global resolver state or NSS/provider modules. The parser
keeps up to three nameservers, six search suffixes, and bounded
`ndots`/timeout/attempts options. Invalid recognized records reject the
complete snapshot.

`Resolver::lookup` checks the owned `HostDatabase` before DNS, then orders
relative candidates by configured search suffixes and the `ndots` threshold;
an absolute name is queried as-is. DNS A and AAAA answers are owned typed
addresses, and a bounded CNAME chain is followed with loop protection while
retaining the terminal canonical name. Network exchange reuses the direct
configured-order UDP transport, TCP truncation fallback, retry count, and
nameserver failover already covered by resolver-transport tests. The slice does
not add DNSSEC, DoH/DoT, mDNS, IDNA, resolver formatting/parsing APIs, or a
global cache/configuration registry.

## Named temporary files

`fs::NamedTempFile` is the bounded named-file contract for the safe `mkstemp`
family. `create_temp_file` opens the requested parent directory, while
`create_temp_file_at` requires a real directory descriptor; both retain a
close-on-exec duplicate of that directory so cleanup does not depend on the
process CWD. Creation uses a 96-bit `getrandom` hexadecimal basename and
atomic `O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC` mode `0600`, retrying only
`EEXIST` collisions.

The value owns the file and parent descriptors, unlinks on drop, exposes only
the generated basename, and offers explicit `remove` or `into_owned_fd`
persistence semantics. `mktemp`/`tempnam`/`tmpnam` remain racy or ambient C
pathname facilities; `name_to_handle_at` and `open_by_handle_at` remain
authority-bearing file-handle operations. None is represented by a generic
filesystem framework.

`fs::TempFile` is the separate anonymous-file contract. It opens a regular
file with Linux `O_TMPFILE | O_RDWR | O_CLOEXEC` relative to an explicit
directory, owns only the descriptor, and never creates a directory entry.
`EOPNOTSUPP` is returned unchanged when the filesystem lacks `O_TMPFILE`
support; no named-file fallback is attempted.

## Bounded glob expansion

`pattern::glob` and `pattern::glob_at` expand a relative byte pattern below an
explicit root pathname or borrowed directory descriptor. They traverse
directories through direct `fs::openat` and `RawDir` operations, match each
component with the existing allocation-free `fnmatch` engine, and return
owned `GlobPath` values whose bytes remain arbitrary Unix pathname bytes.
Results are sorted lexicographically by raw bytes; no matches return an empty
vector, missing intermediate candidates are non-matches, and root or
directory-read errors remain typed. Absolute, empty, NUL-containing, and
`..`-escaping patterns are rejected, and wildcard traversal excludes `.` and
`..` records; intermediate symlinks retain Linux `openat` following
semantics, so this is not a filesystem-confinement boundary. This is not a C
`glob_t` wrapper and never chooses a hidden CWD search root.

## Local account snapshots

`users::{UserDatabase, GroupDatabase, Database}` owns immutable conventional
`/etc/passwd` and `/etc/group` snapshots. Each record owns strict UTF-8 text,
numeric IDs, and group-member names; enumeration keeps source order and
lookups return the first matching local record. `from_system` performs bounded
direct descriptor I/O, so it neither calls the C passwd/group APIs nor exposes
their static storage or global cursors. This is local-file data only: it does
not create NSS/provider support, a mutable account registry, shadow parsing,
utmp/utmpx, mntent, user-shell cursors, or login policy.

The private native x86 lane separately selects only this `users.databases`
boundary through `users.rs`. Its `users-databases-reference` gate combines the
alloc-gated Rust regression, the no-std `users_databases_direct_probe`, and a
child-contained pinned-musl/raw conventional-file oracle. It proves owned
strict UTF-8 records with interior-NUL and malformed whole-snapshot rejection,
source-order duplicate preservation and first-match lookup, plus separately
bounded one-mebibyte direct `/etc/passwd` and `/etc/group` loads through x86
`openat=257`, `read=0`, and `close=3`. The two conventional files are not an
atomic multi-file transaction. This selects no C `getpw*`/`getgr*` API, static
result/cursor or process-global enumeration state, header/ABI, or errno TLS; shadow, utmp/utmpx, mntent,
user-shell/login helpers, account/group mutation or `initgroups`, NSS/provider
framework, and public x86 support remain excluded.

## Checked mount error boundary

`mount::{mount, unmount, MountFlags, UnmountFlags}` is the Rust-facing Linux
mount request boundary. It requires non-null source, target, and filesystem-
type paths as checked Unix byte strings and accepts mount data only as an
optional borrowed `&CStr`; it does not expose the kernel's null source/type
forms or arbitrary data pointers. The underlying direct calls use Linux
`mount(2)` and `umount2(2)`, so a successful call changes the calling process's
mount namespace. That effect is not a sandbox or namespace-management promise.

The private native x86 lane separately selects only a non-mutating
`mount.basic` error slice through `mount_x86_64.rs`. Its `mount-reference` gate
combines a focused Rust regression, the no-std `mount_direct_probe`, and a
paired raw/pinned-musl C fixture. It pins `mount=165` with source, target,
filesystem type, flags, and optional data in `rdi`/`rsi`/`rdx`/`r10`/`r8`, and
`umount2=166` with target/flags in `rdi`/`rsi`. All evidence uses unique
missing targets and direct errors only, with interior-NUL preflight; it neither
grants mount authority nor performs a successful mount-namespace mutation.
The paired raw/musl C calls must agree on `EPERM` when permission checking
precedes resolution or `ENOENT` when the checked-absent target is reached, so
the contract does not pretend that one errno wins in every capability context.

This evidence selects no null source/type form, arbitrary data pointer,
successful mount/unmount operation, `pivot_root`, `unshare`, `setns`, namespace
management, bind/remount/propagation or detach policy, or filesystem-descriptor
mount APIs (`fsopen`, `fsconfig`, `fsmount`, `move_mount`, `open_tree`,
`fspick`). It also selects no C mount/umount header, ABI, or errno TLS and no
public x86 support.

## Bounded inotify observation

`system::inotify` owns a Linux inotify descriptor, typed watch identifiers,
and a caller-buffered iterator of validated, byte-preserving event records.
It is a direct `inotify_init1`/`inotify_add_watch`/`inotify_rm_watch` seam:
the Rust facade has no C wrapper or ABI, TLS `errno`, legacy `inotify_init`,
background reader, global watch registry, or policy engine. The parser rejects
malformed variable-length records; queue overflow and unknown kernel mask bits
stay observable. This does not imply namespaces, capability mutation, ptrace,
`process_vm`, fanotify, recursive watching, or an administration framework.

The private Linux/x86-64 evidence lane separately selects only this bounded
`system::inotify` boundary after direct `inotify_init1=294`,
`inotify_add_watch=254`, and `inotify_rm_watch=255` ABI proof; the 16-byte
align-4 event header and caller-buffer record framing; pinned-musl/raw oracle;
focused Rust regression; and no-std probe evidence. It leaves the wider system
family planned and selects no Rust C wrapper, TLS `errno`, legacy init,
fanotify, recursive or background watcher policy, global registry,
namespace/capability mutation, or public x86 support. The separate private
`static-c-event-descriptors` artifact owns bounded C `sys/inotify.h` and
legacy-init evidence without broadening this Rust facade or public support.

## POSIX message queues

`crabc_rs::ipc::MessageQueue` owns a Linux POSIX named-message-queue
descriptor. `ipc::open`, `ipc::create`, and `ipc::unlink` use the fixed-arity
Linux kernel syscalls directly, so the C `mq_open` varargs convention never
crosses the native boundary. Queue attributes, `O_NONBLOCK`, bounded typed
priorities, caller-borrowed send/receive buffers, and absolute
`CLOCK_REALTIME` deadlines are explicit; close is available as a consuming
operation and is also guaranteed by descriptor drop. Notification, SysV IPC,
named semaphores, AIO, and aggregate IPC policy are deliberately excluded.

The private Linux/x86-64 evidence lane separately selects only this direct
`ipc` named-message-queue boundary after its native ABI, pinned-musl/raw
oracle, focused Rust, and no-std-probe evidence. It selects no C mqueue
API/header, C ABI, TLS `errno`, or public x86 support.

## POSIX shared memory

`crabc_rs::shm::{open, unlink}` is a deliberately narrow named-object
boundary. Leading slashes are ignored; the remaining POSIX name must be
nonempty, cannot be `.` or `..`, and cannot contain `/`. At most `NAME_MAX`
(255) name bytes are copied into a fixed 265-byte
`/dev/shm/<name>\0` construction. `open` uses ordinary direct filesystem
descriptor operations, always adds `O_CLOEXEC`, and returns an `OwnedFd`;
`unlink` removes only the namespace entry, so an already-open descriptor
remains valid. Because it does not inject `O_NOFOLLOW`, default final-symlink
resolution follows the link; a caller-supplied `O_NOFOLLOW` gets the direct
`ELOOP` result. This does not introduce a mapping or sizing abstraction,
mount-discovery/fallback policy, a global registry, SysV shared memory,
semaphores, C ABI/`errno`/cancellation mechanics, or IPC policy framework.

The private Linux/x86-64 evidence lane separately selects only this
`ipc.posix-shm` boundary after direct `openat=257`/`unlinkat=263` ABI proof,
focused Rust regression, and a paired pinned-musl/raw C fixture. In the normal
four-argument `openat` form, x86-64 passes the mode word in `r10`. The Rust
facade deliberately matches existing AArch64/Rustix direct behavior by forcing
only `O_CLOEXEC`; musl's C `shm_open` wrapper additionally forces
`O_NOFOLLOW` and `O_NONBLOCK`. That is an intentional recorded wrapper-policy
difference, including final-symlink behavior, not a claim of raw/musl flag
equivalence. The slice remains staged
private evidence and does not establish public x86 support.

## Civil time and explicit timezone rules

`time::wall_clock` returns a normalized `UnixTime` observation. The UTC
calendar seam is deliberately value-oriented: `CalendarTime`, `time::gmtime`,
`time::timegm`, and `time::difftime` perform strict proleptic-Gregorian
conversion over a known instant instead of exposing C `time_t` or `struct tm`
storage. Invalid calendar states and out-of-range conversions return typed
errors rather than silently normalizing an impossible date.

The Gregorian kernels are a semantic Rust translation of pinned musl 1.2.6,
not an unrecorded compatibility copy. [`crabc-rs/UPSTREAM.md`](../../crabc-rs/UPSTREAM.md)
retains the exact source/function map, release/archive identity, MIT notice,
and intentional differences: wider checked intermediates and strict,
non-mutating Rust values rather than C `struct tm` normalization and TLS
`errno` protocol.

The alloc-gated `timezone::TimeZone` is an immutable owned rule set constructed
from explicit POSIX-TZ bytes or TZif v1/v2/v3 bytes. It does not consult or
mutate `TZ`, libc timezone globals, or a system-zoneinfo path. The alloc-gated
`time::LocalCalendar` projects a known `UnixTime` through a supplied `TimeZone`,
retaining the resulting offset, daylight-saving flag, and abbreviation. The
direction is intentional: the facade does not offer inverse
local-calendar-to-instant conversion, because a DST fold or gap would require
hidden ambiguity policy.

The private Linux/x86-64 evidence lane separately selects this
`time.civil-calendar` boundary after direct `gettimeofday=96` ABI proof for a
private 16-byte `timeval` output record, pinned-musl UTC/POSIX-TZ oracle
anchors, focused UTC/timezone/local-calendar regressions, and no-std static
probes. The C oracle contains any temporary `TZ`/`tzset` setup in its own
short-lived process; native Rust retains rule input as an explicit value. This
calendar boundary itself does not select C time headers/APIs/ABI, `errno` TLS,
`time_t`/`tm`/`timeval` layout, zoneinfo discovery/loading policy, inverse
`mktime`-style conversion, or public x86 support. Advanced x86 clock and timer
evidence is recorded separately below.

## Advanced clocks and owned POSIX timers

The time facade keeps clock selectors and timer lifetime typed. `ClockId`
accepts only the named Linux clock vocabulary; `DynamicClockId` either holds a
known selector, a borrowed descriptor-backed clock, or a validated
`ProcessClockId`. `clock_getcpuclockid` constructs that process value only
after Linux accepts its encoded CPU clock, so a safe caller cannot manufacture
an arbitrary signed `clockid_t`. `clock_settime` validates its Rust
`Timespec` before forwarding the direct kernel mutability and permission
result.

`PosixTimer` owns a private kernel timer identifier. Its `TimerSpec` contains
only checked Rust durations, `TimerSetFlags` preserves non-`ABSTIME` bits for
the direct Linux behavior (the 5.10 POSIX-timer path ignores them), and
explicit deletion or `Drop` retires the timer. The
notification vocabulary admits no-side-effect, signal, and thread-directed
signal modes, but intentionally has no `SIGEV_THREAD` callback mode: callback
lifetime and process-runtime policy do not fit this direct OS boundary. It
does not publish a C `timer_t`, `sigevent`, `itimerspec`, callback pointer, or
global timer registry. Linux can retain a nonzero last-expiry value after a
`SIGEV_NONE` disarm even though its reported interval is zero; `gettime`
preserves that direct kernel observation rather than manufacturing a zero
setting.

The private Linux/x86-64 evidence lane separately selects
`time.clock-query`, `time.clock-process-id`, `time.clock-set`, and
`time.posix-timers` after raw/pinned-musl ABI proof for the private
`timespec`, `itimerspec`, and `sigevent` records; the clock/timer syscalls; the
x86 `r10` fourth argument of `timer_settime`; focused Rust lifecycle
regressions; and no-std static probes. The oracle never mutates realtime and
keeps signal notification forms unarmed. This adds no C time ABI, `errno` TLS,
`SIGEV_THREAD` callback runtime, signal-handler/scheduling policy, or public
x86 support.

## Owned PTY/session pairs

`pty::PtyPair::open` owns both sides of a Linux pseudoterminal. It opens
`/dev/ptmx`, validates and unlocks the devpts allocation with `TIOCGPTN` and
`TIOCSPTLCK`, then obtains the slave with `TIOCGPTPEER`; the peer open always
uses `O_NOCTTY` so pair construction does not alter process session state.
`pty::ptsname_into` writes an ASCII `/dev/pts/<number>` path plus NUL into
caller-owned `MaybeUninit` storage, while alloc-enabled `pty::ptsname` returns
an owned `CString` and reuses the supplied vector.

The staged private Linux/x86-64 lane keeps that safe `pty_x86_64.rs` base and
then completes a target-specific terminal vertical. `PtyPair::open` still
requires `RDWR` and forces `O_NOCTTY`, while the only state transition is the
explicit unsafe `set_controlling_terminal` or
`establish_session_and_controlling_terminal` handoff. The latter calls
`setsid` followed by `TIOCSCTTY`; callers must isolate and serialize the
process-global session, process-group, and terminal authority, and failure
after `setsid` leaves the new session in effect.

`termios_x86_64.rs` keeps Linux's 36-byte/align-4 `TCGETS` record private:
four u32 flags, one line byte, and 19 special-code bytes. This deliberately
differs from pinned musl x86-64's 60-byte/`NCCS=32` public record. The named
Rust APIs cover attributes, standard baud selectors, special codes,
queue/flow/break, exclusive mode, foreground group/session, window size,
terminal detection, and procfs-plus-inode-validated tty names without a C ABI
cast or generic ioctl surface. The independent `static-c-termios-control`
artifact forwards a public C `struct termios` pointer only across its closed
static C boundary, so Linux consumes its shared 36-byte prefix; it does not
alter this Rust facade or select a general C terminal API.
`terminal-reference` runs no-default and alloc
tests, a no-std probe, and paired raw/pinned-musl C arms over that contract;
its session transition is child-contained. It does not publish a generic ioctl
or public `ioctl_tiocgptpeer`, select C terminal APIs/errno TLS, provide a
process supervisor, or establish public x86 support.

The process-state transition is intentionally explicit and unsafe:
`PtyPair::set_controlling_terminal` requires an existing Linux session leader,
and `PtyPair::establish_session_and_controlling_terminal` performs `setsid`
followed by `TIOCSCTTY`. Callers must isolate and serialize this process-global
operation; failure after `setsid` leaves the new session in effect. This slice
does not provide a process supervisor or prepared-exec wrapper. `forkpty`,
`login_tty`, and `vhangup` remain C-only historical helpers, and `isastream`
has no Linux PTY meaning.

## Prepared child ownership

`process::PreparedExec::spawn` transfers one native child owner into
`process::Child`. The owner is deliberately neither `Clone` nor `Copy`, and
`Child::wait` consumes it, so a PID cannot be duplicated into multiple safe
wait attempts. The existing prepared error-pipe, descriptor-action, fork,
exec, and wait behavior remains bounded to explicit caller inputs; nonblocking
polling, `Command`/`PATH` search, `posix_spawn` attributes, and process-lifetime
policy are separate contracts.

The private Linux/x86-64 evidence lane separately admits that same alloc-gated
ownership boundary in `crabc-rs/src/process_x86_64.rs`: parent-owned C-string
and pointer preparation, `FdAction::{close, dup2}`, bounded `SpawnOptions`, a
`CLOEXEC` error pipe relocated away from requested `dup2` targets, and one
consuming `Child::wait`. Its internal fork-equivalent clone exists only inside
`PreparedExec::spawn`; it does not expose generic x86 `fork`, direct `exec`,
`waitpid`, `waitid`, polling/retry waits, C process APIs or `errno` TLS. The
native raw/pinned-musl child lifecycle evidence is a private parity slice, not
public x86 platform support.

## Loader introspection snapshots

`dl::LoadedImageSnapshot::capture` and `dl::Library::information` use the
append-only introspection fields of `RuntimeV1`. `libldso.so` owns the object
graph and holds its recursive loader lock only while copying a bounded set of
fixed records and names into caller-provided storage. The bridge invokes no
Rust or application callback while locked and never returns a `link_map *`, a
loader-owned name pointer, or a borrowed record.

`LoadedImage` and `LibraryInformation` therefore own their text and record
storage, while image, program-header, TLS, and dynamic-section addresses are
opaque copied process values. They do not extend mapping lifetimes or grant
permission to dereference an image after later loader activity. Older
`RuntimeV1` tables remain valid for the pre-introspection callbacks through
the legacy prefix-size check; callers gate the new fields on the complete
extension size.

## Scope-resolved C-only families

The remaining C POSIX regex, process-control, process-wide credential and
environment mutation, signal-alias, pthread/C11, global calendar/clock, and
kernel-administration families are not deferred native facade work. Their
useful typed seams are already individual capabilities; the rest would either
duplicate C ABI storage and lifetime contracts or create an excluded process,
thread, time-policy, or security-policy framework. Their C compatibility and
any explicit profile limits remain in `libc`; the exact non-native rationale
is recorded in `compat/crabc-rs/coverage.toml`.

## Dependencies and optimization

Normal dependencies must be small, mature, focused, pure Rust where practical,
and compatible with the `no_std`/LTO boundary. Before adding one, document its
primitive, why `core`/`alloc` is insufficient, normal transitive graph,
proc-macros/build scripts/native code, allocation/global state, `no_std`
status, and LTO effect; obtain user approval unless already explicitly given.

No cryptography is hand-written. The C `crypt(3)` compatibility slice uses
RustCrypto `sha-crypt`; its limits and dependency review live in
[`compat/crabc-rs/crypt-profile.md`](../../compat/crabc-rs/crypt-profile.md).

The native-facade LTO proof establishes a bounded direct native getpid/write route in O3 and fat-LTO lanes.
It does not prove whole-program LTO or optimization inside dynamically loaded
`libc.so`; see [`compat/lto/README.md`](../../compat/lto/README.md).

## Evidence standard

For each selected capability: define the ownership and error contract; add a
focused observable test; compile the narrow no-std/direct-boundary proof where
relevant; run musl/POSIX or a source oracle as appropriate; then update the
ledger and documentation. A new test or source marker alone is not a verified
claim.
