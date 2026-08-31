//! Selected static Linux/x86-64 C `sched_get_priority_min` boundary.
//!
//! This private leaf maps exactly to pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/sched/sched_get_priority_max.c::sched_get_priority_min` is the direct
//! `syscall(SYS_sched_get_priority_min, policy)` wrapper below. That source
//! also defines `sched_get_priority_max`, which is a separate private artifact
//! and is not linked by this leaf's static fixture.
//!
//! Linux 5.10 x86-64 `sched_get_priority_min=147` receives the signed C `int`
//! policy in `rdi`. A raw Linux `-4095..=-1` result becomes C `-1` after
//! publication through the selected initial-TLS `errno` slot; successful
//! priority values preserve stale `errno`. The fixture observes only
//! `SCHED_OTHER`, `SCHED_FIFO`, `SCHED_RR`, and a rejected invalid policy. It
//! is not scheduler policy selection or mutation, a priority-maximum query,
//! parameter/affinity API, scheduler handoff/fairness guarantee, C11/pthread
//! lifecycle, process lifecycle, libc.so, CRT, loader, sysroot, family
//! completion, promotion, or public x86 support.

use core::ffi::c_int;

use super::{c_status, raw_syscall};

/// Return Linux's minimum schedulable priority for one policy selector.
///
/// The integer selector is forwarded directly, as in musl. A successful
/// result is a nonnegative priority and leaves the caller's C `errno`
/// untouched; a raw Linux error becomes `-1` and the corresponding positive
/// error code in the selected initial-TLS slot. This function has no policy
/// selection, mutation, or scheduling-progress guarantee.
#[no_mangle]
pub extern "C" fn sched_get_priority_min(policy: c_int) -> c_int {
    // SAFETY: Linux/x86-64 syscall 147 takes one signed integer policy word
    // in `rdi`; c_status owns the ordinary C status/errno conversion.
    let result = unsafe {
        raw_syscall::syscall1(raw_syscall::SYS_SCHED_GET_PRIORITY_MIN, policy as i64)
    };
    c_status(result)
}
