//! Bounded Linux/x86-64 static GNU scheduler-affinity mutation boundary.
//!
//! This private static ABI leaf is source-mapped to pinned musl 1.2.6 release
//! commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/sched/affinity.c::sched_setaffinity` is the complete direct
//! `syscall(SYS_sched_setaffinity, tid, size, set)` wrapper below. Musl's
//! `syscall` macro reaches `__syscall_ret`, so successful status zero leaves
//! C `errno` unchanged and a raw Linux error becomes `-1` through initial-TLS
//! `errno`.
//!
//! Linux 5.10 x86-64 syscall `sched_setaffinity=203` replaces one task's
//! affinity mask with the caller-owned readable byte extent. The leaf forwards
//! the signed task selector, byte count, and pointer unchanged; it owns no
//! CPU-mask construction, affinity observation, scheduler policy or parameter
//! behavior, pthread handle/lifecycle state, or mutation coordination.
//!
//! This leaf selects only GNU `sched_setaffinity(pid_t, size_t, const
//! cpu_set_t *)`. It selects neither `sched_getaffinity`, CPU allocation/count/
//! macro helpers, pthread affinity or lifecycle, dynamic or loader TLS, CRT,
//! sysroot, promotion, scheduler-family completion, nor public x86 support.

use core::ffi::{c_int, c_void};

use super::{c_status, raw_syscall};

/// Replace one Linux task's CPU-affinity mask through the GNU C ABI.
///
/// # Safety
///
/// `mask` and `cpusetsize` are forwarded to Linux without a Rust-side
/// dereference. For a successful call, `mask` must designate readable storage
/// for exactly `cpusetsize` bytes for the duration of the syscall. A null,
/// unreadable, or otherwise invalid pointer is likewise forwarded, so Linux
/// reports its normal error (the C ABI fixture covers `EFAULT` for null storage).
/// The caller owns task lifetime, permissions, CPU-mask validity, and any
/// synchronization required around this kernel mutation; this one-symbol leaf
/// neither observes the resulting mask nor coordinates pthread or process
/// scheduling state.
#[no_mangle]
pub unsafe extern "C" fn sched_setaffinity(
    task_id: c_int,
    cpusetsize: usize,
    mask: *const c_void,
) -> c_int {
    // SAFETY: raw syscall forwarding does not dereference `mask`; Linux/x86-64
    // receives pid, byte count, and mask in rdi/rsi/rdx and reports bad storage.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_SCHED_SETAFFINITY,
            i64::from(task_id),
            cpusetsize as i64,
            mask as usize as i64,
        )
    };
    c_status(result)
}
