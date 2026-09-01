//! Bounded Linux/x86-64 static POSIX scheduler-policy compatibility-failure boundary.
//!
//! This private static ABI leaf is the exact behavior of pinned musl 1.2.6
//! release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's
//! MIT license. Its complete source mapping is
//! `src/sched/sched_setscheduler.c::sched_setscheduler`:
//! `return __syscall_ret(-ENOSYS);`.
//!
//! Linux 5.10 x86-64 provides raw syscall `sched_setscheduler=144`, but it
//! changes a thread's scheduler policy and parameter. Musl does not expose
//! that thread-scoped operation through the POSIX process-facing spelling.
//! Preserve musl's compatibility boundary for every pid-shaped input, policy,
//! and pointer, including null: return `-1`, set the calling initial-TLS
//! `errno` to `ENOSYS=38`, and leave caller-owned `sched_param` storage
//! untouched without issuing syscall 144.
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
pub extern "C" fn sched_setscheduler(
    _pid: c_int,
    _policy: c_int,
    _param: *const c_void,
) -> c_int {
    c_status(-ENOSYS)
}
