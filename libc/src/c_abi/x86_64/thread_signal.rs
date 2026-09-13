//! Native Linux/x86-64 `tgkill` C ABI extension.
//!
//! The frozen crabc C ABI at commit
//! `3e100d45c5a0798c2d3862d5e2eef584c610ccf9` exported
//! `int tgkill(int, int, int)`.  Native musl 1.2.6 deliberately has no public
//! `tgkill` export, so this is an explicit crabc extension with the frozen C
//! signature, not a claim that musl provides an ABI counterpart.  The focused
//! evidence compares the same installed-header application object with a
//! separate musl `syscall(SYS_tgkill, ...)` adapter for Linux errno behavior.
//!
//! Linux validates the scalar thread-group id, task id, signal number, and
//! permission at syscall `tgkill=234`.  Invalid identifiers and signals are
//! ordinary C error results: [`c_status`] publishes the kernel errno and
//! returns `-1`.  There are no caller-owned pointer arguments.  A caller must
//! only request a signal operation it is permitted to perform and must retain
//! whatever process/thread lifetime it relies on; this leaf establishes no
//! pthread, signal-disposition, or target-lifecycle policy.

use core::ffi::c_int;

use super::{c_status, raw_syscall};

/// Deliver `signal` to caller-selected task `thread_id` in thread group
/// `thread_group` through Linux `tgkill(2)`.
///
/// This preserves the frozen crabc C extension's independent `tgid` argument;
/// it does not substitute the current process id as the Rust facade's
/// same-process thread helper does.
#[no_mangle]
pub extern "C" fn tgkill(thread_group: c_int, thread_id: c_int, signal: c_int) -> c_int {
    // SAFETY: Linux/x86-64 `tgkill=234` receives exactly these three scalar
    // C `int` words in rdi/rsi/rdx. The kernel owns id, signal, and permission
    // validation; c_status performs the sole C errno/result translation.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_TGKILL,
            i64::from(thread_group),
            i64::from(thread_id),
            i64::from(signal),
        )
    };
    c_status(result)
}
