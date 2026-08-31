//! Bounded Linux/x86-64 static POSIX scheduler-parameter compatibility-failure boundary.
//!
//! This private static ABI leaf is the exact behavior of pinned musl 1.2.6
//! release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's
//! MIT license. Its complete source mapping is
//! `src/sched/sched_setparam.c::sched_setparam`:
//! `return __syscall_ret(-ENOSYS);`.
//!
//! Linux 5.10 x86-64 provides raw syscall `sched_setparam=142`, but it changes
//! a thread's scheduler parameter. Musl does not expose that thread-scoped
//! operation through the POSIX process-facing spelling. Preserve musl's
//! compatibility boundary for every pid-shaped input and every pointer,
//! including null: return `-1`, set the calling initial-TLS `errno` to
//! `ENOSYS=38`, and leave the caller's `sched_param` storage untouched without
//! issuing syscall 142.
//!
//! This one-symbol leaf selects neither scheduler mutation nor policy,
//! parameter records, priority bounds, `sched_yield`, affinity, pthread
//! scheduling attributes, thread/process lifecycle, dynamic or loader TLS,
//! CRT, sysroot, promotion, nor public x86 support.

use core::ffi::{c_int, c_void};

use super::c_status;

const ENOSYS: i64 = 38;

/// Return musl's process/thread-mismatch compatibility failure without
/// dereferencing the otherwise-required read-only scheduler record.
#[no_mangle]
pub extern "C" fn sched_setparam(_pid: c_int, _param: *const c_void) -> c_int {
    c_status(-ENOSYS)
}
