//! Static Linux/x86-64 C credential-setter boundary.
//!
//! This selected leaf owns the nine C setters classified by
//! `process.credentials`: `setgroups`, `setuid`, `setgid`, `setresuid`,
//! `setresgid`, `seteuid`, `setegid`, `setreuid`, and `setregid`. It follows
//! the active compatibility profile exactly:
//!
//! - `setresuid` and `setresgid` expose their direct calling-task Linux
//!   operations.
//! - `setgroups`, `setuid`, and `setgid` pass their raw Linux operations
//!   through the selected C `errno` boundary.
//! - `seteuid`, `setegid`, `setreuid`, and `setregid` return
//!   `-1`/`EOPNOTSUPP` without changing any identity. A process-wide musl
//!   transition needs the all-thread credential rendezvous that this static
//!   artifact does not own.
//!
//! The leaf has no allocator, pthread, process registry, dynamic TLS, or
//! ambient C-runtime dependency. Its native fixture uses only all-ones
//! no-change `setres*` requests and rejected `setuid`/`setgid`/`setgroups`
//! inputs, so it never changes the evidence process's credentials.

use core::ffi::{c_int, c_uint};

use super::{c_status, errno, raw_syscall};

const EOPNOTSUPP: c_int = 95;

#[inline]
fn profile_unsupported() -> c_int {
    // SAFETY: this is the selected C ABI's calling-thread error publication
    // path. The static initial-TLS errno slot is owned by the parent root.
    unsafe { errno::set_errno(EOPNOTSUPP) };
    -1
}

/// Replace the calling task's supplementary-group list through Linux.
///
/// # Safety
///
/// If `count` is nonzero and Linux examines the list, `groups` must point to
/// `count` readable x86 `gid_t` words for the syscall's duration. Credential
/// mutation is process-sensitive: callers must arrange their own authority,
/// thread coordination, and recovery policy. This static leaf does not turn a
/// successful kernel transition into a process-wide pthread guarantee.
#[no_mangle]
pub unsafe extern "C" fn setgroups(count: usize, groups: *const c_uint) -> c_int {
    // SAFETY: the C caller upholds Linux's pointer and credential-transition
    // requirements for `setgroups(2)`.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_SETGROUPS,
            count as i64,
            groups as usize as i64,
        )
    };
    c_status(result)
}

/// Change the calling task's Linux real/effective/saved user identity.
///
/// # Safety
///
/// The caller must provide a Linux `uid_t` word and coordinate any credential
/// transition with all affected program threads. This direct static boundary
/// makes no process-wide pthread synchronization claim.
#[no_mangle]
pub unsafe extern "C" fn setuid(user_id: c_uint) -> c_int {
    // SAFETY: the scalar C argument is passed directly to Linux `setuid(2)`.
    let result = unsafe { raw_syscall::syscall1(raw_syscall::SYS_SETUID, i64::from(user_id)) };
    c_status(result)
}

/// Change the calling task's Linux real/effective/saved group identity.
///
/// # Safety
///
/// The caller must provide a Linux `gid_t` word and coordinate any credential
/// transition with all affected program threads. This direct static boundary
/// makes no process-wide pthread synchronization claim.
#[no_mangle]
pub unsafe extern "C" fn setgid(group_id: c_uint) -> c_int {
    // SAFETY: the scalar C argument is passed directly to Linux `setgid(2)`.
    let result = unsafe { raw_syscall::syscall1(raw_syscall::SYS_SETGID, i64::from(group_id)) };
    c_status(result)
}

/// Set selected calling-task user-ID slots through Linux `setresuid(2)`.
///
/// # Safety
///
/// Each argument is one raw Linux `uid_t` word; all-ones means "unchanged".
/// The caller must coordinate any actual identity transition with every
/// affected thread. This artifact does not provide musl's process-wide
/// credential rendezvous.
#[no_mangle]
pub unsafe extern "C" fn setresuid(
    real_user_id: c_uint,
    effective_user_id: c_uint,
    saved_user_id: c_uint,
) -> c_int {
    // SAFETY: the scalar C arguments are passed unchanged to Linux's three
    // x86 syscall registers for `setresuid(2)`.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_SETRESUID,
            i64::from(real_user_id),
            i64::from(effective_user_id),
            i64::from(saved_user_id),
        )
    };
    c_status(result)
}

/// Set selected calling-task group-ID slots through Linux `setresgid(2)`.
///
/// # Safety
///
/// Each argument is one raw Linux `gid_t` word; all-ones means "unchanged".
/// The caller must coordinate any actual identity transition with every
/// affected thread. This artifact does not provide musl's process-wide
/// credential rendezvous.
#[no_mangle]
pub unsafe extern "C" fn setresgid(
    real_group_id: c_uint,
    effective_group_id: c_uint,
    saved_group_id: c_uint,
) -> c_int {
    // SAFETY: the scalar C arguments are passed unchanged to Linux's three
    // x86 syscall registers for `setresgid(2)`.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_SETRESGID,
            i64::from(real_group_id),
            i64::from(effective_group_id),
            i64::from(saved_group_id),
        )
    };
    c_status(result)
}

/// Report the deliberate C-profile limitation for effective user-ID changes.
///
/// # Safety
///
/// This function accepts one raw C `uid_t` word. It never dereferences memory
/// or changes credentials; it always reports `EOPNOTSUPP` in the caller's
/// initial-TLS `errno` slot.
#[no_mangle]
pub unsafe extern "C" fn seteuid(_effective_user_id: c_uint) -> c_int {
    profile_unsupported()
}

/// Report the deliberate C-profile limitation for effective group-ID changes.
///
/// # Safety
///
/// This function accepts one raw C `gid_t` word. It never dereferences memory
/// or changes credentials; it always reports `EOPNOTSUPP` in the caller's
/// initial-TLS `errno` slot.
#[no_mangle]
pub unsafe extern "C" fn setegid(_effective_group_id: c_uint) -> c_int {
    profile_unsupported()
}

/// Report the deliberate C-profile limitation for real/effective user changes.
///
/// # Safety
///
/// This function accepts two raw C `uid_t` words. It never dereferences memory
/// or changes credentials; it always reports `EOPNOTSUPP` in the caller's
/// initial-TLS `errno` slot.
#[no_mangle]
pub unsafe extern "C" fn setreuid(_real_user_id: c_uint, _effective_user_id: c_uint) -> c_int {
    profile_unsupported()
}

/// Report the deliberate C-profile limitation for real/effective group changes.
///
/// # Safety
///
/// This function accepts two raw C `gid_t` words. It never dereferences memory
/// or changes credentials; it always reports `EOPNOTSUPP` in the caller's
/// initial-TLS `errno` slot.
#[no_mangle]
pub unsafe extern "C" fn setregid(_real_group_id: c_uint, _effective_group_id: c_uint) -> c_int {
    profile_unsupported()
}
