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

The active deferred groups and their scope limits are in
[`TODO.md`](../../TODO.md). Completed delivery rationale is preserved in the
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

## Bounded inotify observation

`system::inotify` owns a Linux inotify descriptor, typed watch identifiers,
and a caller-buffered iterator of validated, byte-preserving event records.
It is a direct `inotify_init1`/`inotify_add_watch`/`inotify_rm_watch` seam:
there is no public C call, TLS `errno`, background reader, global watch
registry, or policy engine. The parser rejects malformed variable-length
records; queue overflow and unknown kernel mask bits stay observable. This
does not imply namespaces, capability mutation, ptrace, `process_vm`, fanotify,
or an administration framework.

## POSIX message queues

`crabc_rs::ipc::MessageQueue` owns a Linux POSIX named-message-queue
descriptor. `ipc::open`, `ipc::create`, and `ipc::unlink` use the fixed-arity
AArch64 kernel syscalls directly, so the C `mq_open` varargs convention never
crosses the native boundary. Queue attributes, `O_NONBLOCK`, bounded typed
priorities, caller-borrowed send/receive buffers, and absolute
`CLOCK_REALTIME` deadlines are explicit; close is available as a consuming
operation and is also guaranteed by descriptor drop. Notification, SysV IPC,
named semaphores, AIO, and aggregate IPC policy are deliberately excluded.

## Owned PTY/session pairs

`pty::PtyPair::open` owns both sides of a Linux pseudoterminal. It opens
`/dev/ptmx`, validates and unlocks the devpts allocation with `TIOCGPTN` and
`TIOCSPTLCK`, then obtains the slave with `TIOCGPTPEER`; the peer open always
uses `O_NOCTTY` so pair construction does not alter process session state.
`pty::ptsname_into` writes an ASCII `/dev/pts/<number>` path plus NUL into
caller-owned `MaybeUninit` storage, while alloc-enabled `pty::ptsname` returns
an owned `CString` and reuses the supplied vector.

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
