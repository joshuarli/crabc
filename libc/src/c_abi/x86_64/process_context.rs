//! Static Linux/x86-64 selected C process-context boundary.
//!
//! This leaf owns one intentionally bounded native C surface: scalar identity
//! observation (`getpid`, `getppid`, `getuid`, `getgid`, `geteuid`, and
//! `getegid`), process-group/session observation and control (`getpgrp`,
//! `getpgid`, `getsid`, `setpgrp`, `setpgid`, and `setsid`), plus the
//! process-global `umask` exchange. It composes only the raw Linux syscall
//! register boundary and the selected initial-TLS C `errno` writer. It is not
//! C fork/exec, a process supervisor, a general C/POSIX runtime, libc.so,
//! CRT, pthread/TLS lifecycle, loader, sysroot, allocator, or public x86
//! support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/unistd/getpid.c`, `src/unistd/getppid.c`, `src/unistd/getuid.c`,
//!   `src/unistd/getgid.c`, `src/unistd/geteuid.c`, and
//!   `src/unistd/getegid.c` map to the six direct scalar wrappers below.
//! - `src/unistd/getpgid.c`, `src/unistd/getsid.c`,
//!   `src/unistd/getpgrp.c`, `src/unistd/setpgid.c`,
//!   `src/unistd/setpgrp.c`, and `src/unistd/setsid.c` map to the
//!   process-group/session wrappers.
//! - `src/stat/umask.c` maps to [`umask`]'s direct `SYS_UMASK=95` exchange.
//!   Musl routes that raw result through its generic `syscall` return helper,
//!   but Linux's `umask(2)` always returns the prior mask, so this selected
//!   normal path neither needs nor reaches an errno/TLS translation seam.
//!
//! Musl's `__syscall` leaves remain raw scalar returns, while its `syscall`
//! leaves publish Linux's `-4095..=-1` errors through C `errno`. The latter
//! mapping is owned here by the selected `c_status` boundary rather than by a
//! general variadic `syscall(long, ...)` export. The only intentional scope
//! difference is that this artifact's fixture supplies raw `fork`/`wait4`/
//! `exit` only to contain group/session mutations; those C APIs are not
//! selected or exported.

use core::ffi::{c_int, c_uint};

use super::{c_status, raw_syscall};

/// Return the calling process identifier.
///
/// This scalar observation has no pointer or memory-validity requirement. It
/// is the raw Linux `getpid` result at the syscall point and does not establish
/// any process-lifecycle, fork, or pthread contract.
#[no_mangle]
pub extern "C" fn getpid() -> c_int {
    // SAFETY: `SYS_GETPID` is the zero-argument Linux/x86-64 identity query.
    unsafe { raw_syscall::syscall0(raw_syscall::SYS_GETPID) as c_int }
}

/// Return the calling process's parent process identifier.
///
/// This is a scalar observation only; a concurrent parent lifecycle can
/// change the observed relationship independently of this wrapper.
#[no_mangle]
pub extern "C" fn getppid() -> c_int {
    // SAFETY: `SYS_GETPPID` is the zero-argument Linux/x86-64 parent query.
    unsafe { raw_syscall::syscall0(raw_syscall::SYS_GETPPID) as c_int }
}

/// Return the calling task's real user identifier.
///
/// This does not select credential mutation or process-wide credential
/// synchronization.
#[no_mangle]
pub extern "C" fn getuid() -> c_uint {
    // SAFETY: `SYS_GETUID` is the zero-argument Linux/x86-64 scalar query.
    unsafe { raw_syscall::syscall0(raw_syscall::SYS_GETUID) as c_uint }
}

/// Return the calling task's real group identifier.
///
/// This does not select credential mutation or process-wide credential
/// synchronization.
#[no_mangle]
pub extern "C" fn getgid() -> c_uint {
    // SAFETY: `SYS_GETGID` is the zero-argument Linux/x86-64 scalar query.
    unsafe { raw_syscall::syscall0(raw_syscall::SYS_GETGID) as c_uint }
}

/// Return the calling task's effective user identifier.
///
/// This does not select credential mutation or process-wide credential
/// synchronization.
#[no_mangle]
pub extern "C" fn geteuid() -> c_uint {
    // SAFETY: `SYS_GETEUID` is the zero-argument Linux/x86-64 scalar query.
    unsafe { raw_syscall::syscall0(raw_syscall::SYS_GETEUID) as c_uint }
}

/// Return the calling task's effective group identifier.
///
/// This does not select credential mutation or process-wide credential
/// synchronization.
#[no_mangle]
pub extern "C" fn getegid() -> c_uint {
    // SAFETY: `SYS_GETEGID` is the zero-argument Linux/x86-64 scalar query.
    unsafe { raw_syscall::syscall0(raw_syscall::SYS_GETEGID) as c_uint }
}

/// Replace the process file-creation mask and return its prior value.
///
/// The mutation is process-global. Callers that share a process must arrange
/// their own synchronization and restoration; this static artifact does not
/// provide a scoped mask guard, path-creation APIs, or pthread coordination.
#[no_mangle]
pub extern "C" fn umask(mask: c_uint) -> c_uint {
    // SAFETY: Linux `SYS_UMASK` takes one scalar mode word and always returns
    // the prior mask. Musl's generic `syscall` macro has an error translator,
    // but the kernel supplies no error encoding for this operation.
    unsafe { raw_syscall::syscall1(raw_syscall::SYS_UMASK, i64::from(mask)) as c_uint }
}

/// Create a new session for the calling process and return its identifier.
///
/// This changes calling-process session and process-group state. Callers must
/// ensure that the Linux `setsid(2)` transition is appropriate for every
/// affected descriptor and task; no controlling-terminal handoff, fork/exec,
/// or pthread process-state coordination is provided here.
#[no_mangle]
pub extern "C" fn setsid() -> c_int {
    // SAFETY: `SYS_SETSID` is the zero-argument Linux session transition.
    let result = unsafe { raw_syscall::syscall0(raw_syscall::SYS_SETSID) };
    c_status(result)
}

/// Set a process's process-group identifier through Linux `setpgid(2)`.
///
/// `process_id` and `group_id` are passed unchanged as signed x86 `pid_t`
/// values. The caller must arrange process-parent/child ordering and any
/// concurrent process-group policy; this leaf does not implement lifecycle,
/// job-control, signal, or pthread coordination.
#[no_mangle]
pub extern "C" fn setpgid(process_id: c_int, group_id: c_int) -> c_int {
    // SAFETY: both C arguments are scalar Linux `pid_t` words in the first
    // two x86 syscall registers.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_SETPGID,
            i64::from(process_id),
            i64::from(group_id),
        )
    };
    c_status(result)
}

/// Return the process-group identifier for `process_id`.
///
/// The scalar signed x86 `pid_t` value is passed directly to Linux. On a
/// Linux error, this returns `-1` and writes the calling initial-TLS `errno`.
#[no_mangle]
pub extern "C" fn getpgid(process_id: c_int) -> c_int {
    // SAFETY: `process_id` is the one scalar Linux `getpgid(2)` argument.
    let result = unsafe {
        raw_syscall::syscall1(raw_syscall::SYS_GETPGID, i64::from(process_id))
    };
    c_status(result)
}

/// Return the session identifier for `process_id`.
///
/// The scalar signed x86 `pid_t` value is passed directly to Linux. On a
/// Linux error, this returns `-1` and writes the calling initial-TLS `errno`.
#[no_mangle]
pub extern "C" fn getsid(process_id: c_int) -> c_int {
    // SAFETY: `process_id` is the one scalar Linux `getsid(2)` argument.
    let result = unsafe {
        raw_syscall::syscall1(raw_syscall::SYS_GETSID, i64::from(process_id))
    };
    c_status(result)
}

/// Return the calling process's process-group identifier.
///
/// Like musl's source leaf, this is the direct `getpgid(0)` scalar result; it
/// does not select a general variadic `syscall` export or an error policy for
/// an operation Linux defines as successful for the current process.
#[no_mangle]
pub extern "C" fn getpgrp() -> c_int {
    // SAFETY: `SYS_GETPGID` receives the scalar current-process selector 0.
    unsafe { raw_syscall::syscall1(raw_syscall::SYS_GETPGID, 0) as c_int }
}

/// Set the calling process's group identifier to its process identifier.
///
/// This is the legacy `setpgid(0, 0)` alias. Its process-state obligations
/// are exactly those of [`setpgid`].
#[no_mangle]
pub extern "C" fn setpgrp() -> c_int {
    setpgid(0, 0)
}
