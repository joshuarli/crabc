//! Static Linux/x86-64 C credential-observation boundary.
//!
//! This selected leaf completes the read-only companion to the admitted
//! scalar identity and credential-setter leaves: `getgroups`, GNU
//! `getresuid`, and GNU `getresgid`. It owns no account-file lookup, identity
//! mutation, process-wide credential rendezvous, allocator, callback,
//! cancellation, or mutable runtime state. `getgroups` deliberately preserves
//! Linux's query-then-fill race: callers retry an `EINVAL` fill after a group
//! list change rather than receiving an invented stable snapshot.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/unistd/getgroups.c` maps to [`getgroups`].
//! - `src/misc/getresuid.c` maps to [`getresuid`].
//! - `src/misc/getresgid.c` maps to [`getresgid`].
//!
//! Each pinned source is one `syscall(...)` wrapper. The selected static C
//! boundary owns the corresponding raw-result to initial-TLS `errno`
//! translation through [`c_status`], without exporting a general variadic
//! `syscall(long, ...)` ABI.

use core::ffi::{c_int, c_uint};

use super::{c_status, raw_syscall};

/// Query or fill the calling process's supplementary-group list.
///
/// A zero `count` with a null `groups` pointer queries the current length. If
/// `count` is positive and Linux examines `groups`, the caller must provide
/// `count` writable x86 `gid_t` words for the syscall duration. The count can
/// change before a subsequent fill, which reports `-1`/`EINVAL`; this direct
/// leaf deliberately leaves retry policy with the caller.
#[no_mangle]
pub unsafe extern "C" fn getgroups(count: c_int, groups: *mut c_uint) -> c_int {
    // SAFETY: the caller provides the conditional Linux output-buffer
    // contract. `count` remains a signed x86 `int` word for kernel validation.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_GETGROUPS,
            i64::from(count),
            groups as usize as i64,
        )
    };
    c_status(result)
}

/// Write the calling task's real, effective, and saved user IDs.
///
/// Each pointer must designate one writable x86 `uid_t` word for Linux to
/// write during this call. The kernel can expose direct `EFAULT` for an
/// invalid output pointer; this leaf does not synthesize partial-output or
/// credential-snapshot policy.
#[no_mangle]
pub unsafe extern "C" fn getresuid(
    real_user_id: *mut c_uint,
    effective_user_id: *mut c_uint,
    saved_user_id: *mut c_uint,
) -> c_int {
    // SAFETY: the caller upholds each kernel output-pointer contract.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_GETRESUID,
            real_user_id as usize as i64,
            effective_user_id as usize as i64,
            saved_user_id as usize as i64,
        )
    };
    c_status(result)
}

/// Write the calling task's real, effective, and saved group IDs.
///
/// Each pointer must designate one writable x86 `gid_t` word for Linux to
/// write during this call. The kernel can expose direct `EFAULT` for an
/// invalid output pointer; this leaf does not synthesize partial-output or
/// credential-snapshot policy.
#[no_mangle]
pub unsafe extern "C" fn getresgid(
    real_group_id: *mut c_uint,
    effective_group_id: *mut c_uint,
    saved_group_id: *mut c_uint,
) -> c_int {
    // SAFETY: the caller upholds each kernel output-pointer contract.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_GETRESGID,
            real_group_id as usize as i64,
            effective_group_id as usize as i64,
            saved_group_id as usize as i64,
        )
    };
    c_status(result)
}
