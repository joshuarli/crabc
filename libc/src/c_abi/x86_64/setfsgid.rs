//! Bounded Linux/x86-64 static filesystem-credential setfsgid boundary.
//!
//! This one-symbol leaf is the exact direct wrapper from pinned musl 1.2.6:
//! `src/linux/setfsgid.c::setfsgid` calls `syscall(SYS_setfsgid, gid)`.
//! Linux's unusual result contract returns the *previous* filesystem GID even
//! when a requested change is refused. Consequently a normal successful raw
//! return does not reveal whether the requested credential became current,
//! and it leaves a caller's existing `errno` value unchanged.
//!
//! The selected C ABI preserves musl's raw-result conversion for the reserved
//! Linux error range, while retaining every ordinary previous-GID result as a
//! signed C `int`. It owns no query helper, user filesystem credential,
//! account database, credential rendezvous, process/session control, scheduler
//! policy, or runtime lifecycle.

use core::ffi::{c_int, c_uint};

use super::{c_status, raw_syscall};

/// Request the calling task's filesystem GID through Linux.
///
/// The `gid` word is an unsigned 32-bit Linux `gid_t`. Linux returns the
/// previous filesystem GID rather than a zero success status; callers that
/// need to know whether a requested transition took effect must use a
/// separately selected observation strategy. This narrow direct wrapper does
/// not coordinate a credential transition with other threads.
#[no_mangle]
pub unsafe extern "C" fn setfsgid(group_id: c_uint) -> c_int {
    // SAFETY: the C scalar is the one Linux `setfsgid(2)` argument in rdi.
    // `c_status` preserves ordinary prior-GID results and publishes only a
    // reserved raw Linux error through the selected initial-TLS errno slot.
    let result = unsafe {
        raw_syscall::syscall1(raw_syscall::SYS_SETFSGID, i64::from(group_id))
    };
    c_status(result)
}
