//! Owned pthread scheduling: musl 1.2.6 (MIT), commit
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417, src/thread/
//! pthread_getschedparam.c, pthread_setschedparam.c, pthread_setschedprio.c.
//! The lifecycle owner pins mappings and excludes TID retirement with its
//! kill lock. Block internal signals too: asynchronous cancellation must not
//! abandon that lease. Raw syscall results preserve the requester's errno.
use core::ffi::{c_int, c_void};
use super::{pthread_create_join, pthread_signal::AllSignals, raw_syscall};
const ESRCH: c_int = 3;

unsafe fn with_target(thread: *mut c_void, action: impl FnOnce(c_int) -> c_int) -> c_int {
    let mask = match unsafe { AllSignals::block() } {
        Ok(mask) => mask,
        Err(error) => return error,
    };
    // Signal delivery accepts retired targets; scheduling instead reports
    // ESRCH. Distinguish callback omission from a successful live syscall.
    let mut result = ESRCH;
    unsafe { pthread_create_join::with_selected_pthread_signal_target(thread, |_, tid, _| {
        result = action(tid);
        0
    }); }
    drop(mask);
    result
}

/// Read a live thread's scheduler and priority, preserving errno.
/// # Safety
/// `thread` must be a still-valid process-local pthread handle; `policy` and
/// `param` must be writable, nonoverlapping int and sched_param objects.
#[no_mangle]
pub unsafe extern "C" fn pthread_getschedparam(thread: *mut c_void, policy: *mut c_int, param: *mut c_void) -> c_int {
    unsafe { with_target(thread, |tid| {
        let result = -raw_syscall::syscall2(143, tid as i64, param as i64) as c_int;
        if result == 0 {
            // Musl stores even a raw get-scheduler failure in policy after a
            // successful getparam; it does not translate it into return/errno.
            policy.write(raw_syscall::syscall1(145, tid as i64) as c_int);
        }
        result
    }) }
}

/// Set a live thread's scheduler and priority, preserving errno.
/// # Safety
/// `thread` must be a still-valid process-local pthread handle and `param`
/// must point to a readable sched_param object.
#[no_mangle]
pub unsafe extern "C" fn pthread_setschedparam(thread: *mut c_void, policy: c_int, param: *const c_void) -> c_int {
    unsafe { with_target(thread, |tid| {
        -raw_syscall::syscall3(144, tid as i64, policy as i64, param as i64) as c_int
    }) }
}

/// Set a live thread's priority within its current policy, preserving errno.
/// # Safety
/// `thread` must be a still-valid process-local pthread handle.
#[no_mangle]
pub unsafe extern "C" fn pthread_setschedprio(thread: *mut c_void, priority: c_int) -> c_int {
    unsafe { with_target(thread, |tid| {
        -raw_syscall::syscall2(142, tid as i64, (&priority as *const c_int) as i64) as c_int
    }) }
}
