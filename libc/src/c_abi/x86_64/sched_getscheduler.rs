//! Bounded Linux/x86-64 static POSIX scheduler-policy observation boundary.
//!
//! This private static ABI leaf is the exact behavior of pinned musl 1.2.6
//! release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's
//! MIT license. Its complete source mapping is
//! `src/sched/sched_getscheduler.c::sched_getscheduler`:
//! `return __syscall_ret(-ENOSYS);`.
//!
//! Linux 5.10 x86-64 does provide raw syscall `sched_getscheduler=145`, but
//! it identifies a thread rather than a POSIX process. Musl deliberately
//! refuses to expose that thread operation through the process-facing
//! `sched_getscheduler(pid_t)` API. Preserve that compatibility boundary for
//! every input: return `-1` and set the calling initial-TLS `errno` to
//! `ENOSYS=38`, without issuing syscall 145.
//!
//! This one-symbol leaf selects neither scheduler mutation, parameter
//! observation, affinity, thread/process lifecycle, priority bounds,
//! `sched_yield`, pthread scheduling attributes, a scheduler policy guarantee,
//! dynamic or loader TLS, CRT, sysroot, promotion, nor public x86 support.

use core::ffi::c_int;

use super::c_status;

const ENOSYS: i64 = 38;

/// Return musl's process/thread-mismatch compatibility failure.
#[no_mangle]
pub extern "C" fn sched_getscheduler(_pid: c_int) -> c_int {
    c_status(-ENOSYS)
}
