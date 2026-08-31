//! Bounded Linux/x86-64 static POSIX `sched_yield` leaf.
//!
//! This private static ABI leaf is source-mapped to pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/sched/sched_yield.c::sched_yield` is the complete status-returning
//! `syscall(SYS_sched_yield)` wrapper below. Unlike the already selected C11
//! `thrd_yield` sibling, this POSIX entry converts a Linux raw error into
//! C's `-1` plus the calling initial-TLS `errno` value.
//!
//! Linux 5.10 x86-64 `sched_yield=24` has no arguments. This leaf does not
//! select scheduler policy or parameter APIs, affinity, a scheduler handoff,
//! fairness, peer progress, C11 lifecycle or synchronization, general thread
//! state, process lifecycle, dynamic or loader TLS, CRT, sysroot, x86-64
//! parity, promotion, or public x86 support.

use core::ffi::c_int;

use super::{c_status, raw_syscall};

/// Yield the calling task's remaining CPU time through POSIX `sched_yield`.
///
/// Linux exposes no arguments and a status result. Successful yields preserve
/// the incoming C `errno`; a Linux raw `-4095..=-1` result becomes `-1` and
/// publishes its positive error number through the selected initial-TLS slot.
/// This has no scheduler-policy, fairness, or process-lifecycle guarantee.
#[no_mangle]
pub extern "C" fn sched_yield() -> c_int {
    // SAFETY: Linux/x86-64 `sched_yield=24` consumes no arguments and returns
    // one raw status word. `c_status` owns the selected C errno conversion.
    let result = unsafe { raw_syscall::syscall0(raw_syscall::SYS_SCHED_YIELD) };
    c_status(result)
}
