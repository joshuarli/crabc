# Installed descriptor-control contract

The installed Linux/x86-64 runtime provides the useful POSIX/Linux descriptor
control mechanisms in `fcntl`. This is a C variadic ABI boundary over kernel
open-file-description and process state, not a descriptor policy framework.
Linux 5.10 is the baseline. The frozen private whitelist in
`descriptor_control.rs` remains unchanged; owned builds select
`owned_descriptor_control.rs` through `static_c_abi.rs`.

## Source and command map

The source oracle is musl 1.2.6 release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, archive SHA-256
`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
`src/fcntl/fcntl.c::fcntl` maps to the owned assembly dispatcher and its four
Rust helpers; POSIX record calls reuse `record_locks.rs::fcntl_record_lock`.
The source is covered by musl's MIT license in its `COPYRIGHT`. Numeric ABI
vocabulary is the pinned x86 `bits/fcntl.h`/`fcntl.h` installed header contract.
No production dependency or native implementation is added.

| C third argument | Commands |
| --- | --- |
| Absent; explicit zero sent to Linux | `F_GETFD`, `F_GETFL`, `F_GETOWN`, `F_GETSIG`, `F_GETLEASE`, `F_GETPIPE_SZ`, `F_GET_SEALS` |
| Promoted `int` | `F_DUPFD`, `F_SETFD`, `F_SETFL`, `F_SETOWN`, `F_SETSIG`, `F_SETLEASE`, `F_DUPFD_CLOEXEC`, `F_SETPIPE_SZ`, `F_ADD_SEALS` |
| `unsigned long` | `F_NOTIFY` |
| `struct flock *` | `F_GETLK`, `F_SETLK`, `F_SETLKW`, `F_OFD_GETLK`, `F_OFD_SETLK`, `F_OFD_SETLKW`, `F_CANCELLK` |
| `struct f_owner_ex *` | `F_GETOWN_EX`, `F_SETOWN_EX` |
| Two `uid_t` words | `F_GETOWNER_UIDS` |
| `uint64_t *` | `F_GET_RW_HINT`, `F_SET_RW_HINT`, `F_GET_FILE_RW_HINT`, `F_SET_FILE_RW_HINT` |

The public assembly entry preserves SysV AMD64's fd/command in rdi/rsi and only
consumes rdx for commands with a third C argument. Legal two-argument calls do
not enter a fixed-three-argument Rust function. Unknown commands use a zero
syscall word to obtain Linux's descriptor/command error precedence without
reading an absent vararg. This does not define an ABI for future commands with
new argument contracts.

Rust does not dereference or retain pointer arguments; Linux copies the
command-specific record. Callers keep pointed-to objects live for the entire
syscall, including OFD blocking waits. Inaccessible addresses remain kernel
errors. Scalar arguments use their command's promoted type; pointer values
retain all 64 address bits. `F_SETFL` includes musl's `O_LARGEFILE` adjustment.

`F_GETOWN` uses `F_GETOWN_EX` and translates a process-group owner to negative
`pid_t` **without** treating that result as an errno encoding. Other syscall
errors use the owned thread's errno. Linux 5.10 guarantees `F_GETOWN_EX` and
atomic `F_DUPFD_CLOEXEC`, so the historical owner fallback, duplication retry
fallback, and redundant post-duplication close-on-exec workaround are omitted.
There is no non-atomic duplication emulation.

Exactly `F_SETLKW` uses the source cancellation-point syscall path. OFD's
blocking extension uses an ordinary raw syscall, as musl does; deferred
cancellation stays pending until a later cancellation point. OFD and POSIX
locks retain their kernel distinction between open-file-description and
process ownership. Filesystem-dependent leases/hints and obsolete commands
return actual kernel results; the runtime does not synthesize success or a
fallback when a filesystem or current kernel rejects them.

## Evidence

Run `./scripts/dev-x86_64.sh owned-fcntl`. One PIC project-header object is
linked unchanged to pinned musl, installed static ET_EXEC/static PIE and
dynamic PIE/non-PIE. Dynamic entries run through kernel and direct loader
entry. The runner optionally accepts an existing dynamic product and is
registered as `fcntl` in the three-product qualification matrix. Per-entry
output, the shared object/hash, header trace and product metadata remain in
`.work/x86_64/tmp/owned-fcntl.*`.

The probe covers:

- Legal no-vararg queries with a deliberately poisoned third register;
  integer, full-width pointer and unsigned-long command routes.
- Duplication minimums, per-descriptor CLOEXEC and shared status flags;
  pipe sizing and errors; process/PGRP ownership and negative return values;
  explicit notification signal selection and actual asynchronous pipe delivery.
- Owner/UID records, lease query/acquisition/release, dnotify deregistration,
  inode/file read-write hints, memfd seals and their observable write/size
  restrictions, and raw-kernel error equivalence on unsupported commands.
- OFD/POSIX conflicts, reported owner IDs, duplicated OFD lifetime and blocking
  acquisition; blocked POSIX cancellation versus OFD deferred cancellation.
  A retained read-only proc directory descriptor supplies exact fd/command
  syscall observations inside private dynamic roots.

All files belong to each run's scratch tree or anonymous memfds/pipes. Signals,
leases and descriptor owners are process-local test state; no host scheduler,
limits, lease policy, filesystem configuration or unrelated tasks are changed.
Child lock holders are explicitly released/reaped and have a bounded alarm;
the runner bounds each execution with a process-group timeout.

This is component evidence. The frozen private status/record-lock tests remain
separate; complete family accounting and final same-revision installed-product
qualification remain requirements of the owning plans. No AArch64 execution or
public x86 promotion is implied.
