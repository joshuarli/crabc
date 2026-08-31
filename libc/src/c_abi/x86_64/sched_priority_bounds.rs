//! Selected static Linux/x86-64 scheduler-priority bounds C ABI.
//!
//! Pinned musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`
//! maps `src/sched/sched_get_priority_max.c::sched_get_priority_max` and
//! `src/sched/sched_get_priority_max.c::sched_get_priority_min` to the two
//! direct `syscall(SYS_sched_get_priority_*)` wrappers below. Linux 5.10
//! x86-64 takes one signed `int` policy in the first argument register and
//! returns one signed `int`: syscall 146 supplies the maximum and 147 the
//! minimum. A raw Linux error becomes C `-1` with the positive errno recorded
//! in the selected initial-TLS errno slot.
//!
//! This private, non-promoting artifact selects only the read-only scalar
//! bounds for the fixture's `SCHED_OTHER`, `SCHED_FIFO`, `SCHED_RR`, and
//! invalid-policy cases. It does not select scheduler policy selection or
//! mutation, current-policy or parameter queries, affinity, scheduler
//! progress/fairness, threads, clocks/timers, calendar or timezone behavior,
//! environment state, allocation, loader/CRT/sysroot work, family completion,
//! promotion, or public x86 support.

use core::ffi::c_int;

use super::{c_status, raw_syscall};

/// Return the Linux scheduler priority maximum for `policy`.
///
/// Success preserves the caller's errno. A checked Linux raw error is mapped
/// through `c_status` to `-1` and the selected initial-TLS errno slot.
#[no_mangle]
pub extern "C" fn sched_get_priority_max(policy: c_int) -> c_int {
    // SAFETY: Linux/x86-64 syscall 146 consumes one scalar policy value and
    // returns one raw scalar result. `c_status` owns C errno publication.
    let result = unsafe {
        raw_syscall::syscall1(raw_syscall::SYS_SCHED_GET_PRIORITY_MAX, policy as i64)
    };
    c_status(result)
}

/// Return the Linux scheduler priority minimum for `policy`.
///
/// Success preserves the caller's errno. A checked Linux raw error is mapped
/// through `c_status` to `-1` and the selected initial-TLS errno slot.
#[no_mangle]
pub extern "C" fn sched_get_priority_min(policy: c_int) -> c_int {
    // SAFETY: Linux/x86-64 syscall 147 consumes one scalar policy value and
    // returns one raw scalar result. `c_status` owns C errno publication.
    let result = unsafe {
        raw_syscall::syscall1(raw_syscall::SYS_SCHED_GET_PRIORITY_MIN, policy as i64)
    };
    c_status(result)
}
