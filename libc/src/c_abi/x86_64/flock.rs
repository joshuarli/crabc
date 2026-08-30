//! Selected static Linux/x86-64 C `flock(2)` boundary.
//!
//! This leaf owns only the direct two-word `flock` C entry point. It forwards
//! the caller's descriptor and operation bits to Linux `flock=73` and applies
//! the selected initial-TLS C `errno` translation. It does not select fcntl
//! record locks, `lockf`, pathname opening, descriptor lifecycle, durability,
//! network-filesystem policy, libc.so, CRT, loader, sysroot, or public x86
//! support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/linux/flock.c` maps to [`flock`] and its direct Linux `flock=73`
//!   request.
//!
//! Linux validates the descriptor and `LOCK_*` operation bits, including the
//! nonblocking conflict result. This bounded leaf retains the raw operation
//! contract and has no cancellation-point or userspace locking machinery.

use core::ffi::c_int;

use super::{c_status, raw_syscall};

/// Apply one advisory whole-file lock operation to an open file description.
///
/// # Safety
///
/// `descriptor` must be an open file descriptor or the caller deliberately
/// requests Linux's `EBADF` behavior. `operation` must contain the Linux
/// `LOCK_SH`, `LOCK_EX`, `LOCK_NB`, or `LOCK_UN` bits and their permitted
/// combinations, unless the caller deliberately requests Linux's `EINVAL`
/// behavior. The caller owns all descriptor lifetime and sharing semantics;
/// this direct leaf has no pathname or cancellation contract.
#[no_mangle]
pub unsafe extern "C" fn flock(descriptor: c_int, operation: c_int) -> c_int {
    // SAFETY: the caller owns the raw descriptor and operation-bit contract;
    // Linux x86-64 takes them in rdi/rsi for direct flock=73.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_FLOCK,
            i64::from(descriptor),
            i64::from(operation),
        )
    };
    c_status(result)
}
