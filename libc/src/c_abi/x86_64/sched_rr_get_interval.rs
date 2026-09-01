//! Bounded Linux/x86-64 sched_rr_get_interval C ABI boundary.
//!
//! This opt-in owner maps pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` (musl MIT) at
//! `src/sched/sched_rr_get_interval.c::sched_rr_get_interval`. Musl retains a
//! 32-bit time64 compatibility branch, but Linux/x86-64 has no
//! `SYS_sched_rr_get_interval_time64`, so its selected branch is exactly
//! `syscall(SYS_sched_rr_get_interval, pid, ts)`.
//!
//! Linux 5.10 x86-64 syscall 148 writes the caller-owned 16-byte `timespec`
//! result. This wrapper contributes no scheduler policy mutation, parameter
//! query, affinity, allocation, global state, fallback, or validation policy.

use core::ffi::{c_int, c_void};

use super::{c_status, raw_syscall};

/// Read the round-robin interval for one Linux task.
///
/// # Safety
///
/// For a successful request, `interval` must designate writable, properly
/// aligned Linux/x86-64 `struct timespec` storage for the duration of the
/// syscall, with no conflicting access while the kernel writes it. The raw
/// pointer and `pid` are otherwise forwarded unchanged, including kernel
/// error cases such as a null output pointer or a missing task.
#[no_mangle]
pub unsafe extern "C" fn sched_rr_get_interval(pid: c_int, interval: *mut c_void) -> c_int {
    // SAFETY: Linux/x86-64 syscall 148 consumes the signed C pid in rdi and
    // the caller-supplied output address in rsi. `c_status` owns only raw
    // Linux error-to-initial-TLS-errno conversion.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_SCHED_RR_GET_INTERVAL,
            i64::from(pid),
            interval as i64,
        )
    };
    c_status(result)
}
