//! Bounded Linux/x86-64 static pthread task-name leaf.
//!
//! This private static ABI leaf is source-mapped to pinned musl 1.2.6 release
//! commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/thread/pthread_setname_np.c::pthread_setname_np` bounds a name to
//!   Linux's 16-byte task-comm slot and uses `prctl(PR_SET_NAME)` for self.
//! - `src/thread/pthread_getname_np.c::pthread_getname_np` requires a
//!   16-byte output buffer and uses `prctl(PR_GET_NAME)` for self.
//!
//! Musl reaches a different live target by dereferencing its full `struct
//! pthread` TCB for a Linux TID, then performing cancellable procfs I/O.
//! Static Initial TLS v1 deliberately owns no dereferenceable TCB, thread
//! list, or `/proc`/cancellation path. This leaf therefore admits only the
//! bootstrapped process-main task through that task's own `pthread_self()`
//! handle. It verifies the existing `%fs:0` plus initial-task identity before
//! examining either C name buffer, then issues direct Linux `prctl=157` with
//! `PR_SET_NAME=15` or `PR_GET_NAME=16`.
//!
//! The leaf selects only GNU `pthread_setname_np` and `pthread_getname_np` for
//! that self handle. Null, worker, foreign, completed, and non-self handles
//! fail closed with candidate-only `ESRCH` before the name input or output is
//! observed. It does not select worker names, musl's procfs task-name path,
//! cancellation, a general `prctl` C API, a pthread TCB/thread list,
//! scheduling/affinity attributes, lifecycle, synchronization, TSS, dynamic
//! or loader TLS, CRT, sysroot, general pthread/TLS behavior, or public x86
//! support. Pthread errors are positive return values: neither entry writes C
//! `errno`.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread task-name leaf requires little-endian Linux/x86-64");

use core::ffi::{c_char, c_int, c_void};

use super::{pthread_identity, raw_syscall, static_tls};

const ESRCH: c_int = 3;
const ERANGE: c_int = 34;
const LINUX_ERRNO_MAX: i64 = 4_095;
const TASK_COMM_LEN: usize = 16;
const PR_SET_NAME: i64 = 15;
const PR_GET_NAME: i64 = 16;

/// Whether an opaque C handle is the one selected bootstrapped main task.
#[inline]
fn is_selected_main_self(thread: *mut c_void) -> bool {
    let current_thread_pointer = pthread_identity::current_thread_pointer();
    !thread.is_null()
        && thread == current_thread_pointer.cast()
        && static_tls::is_initial_thread_pointer(current_thread_pointer)
}

/// Translate the raw self-name `prctl` result to the pthread status domain.
///
/// `PR_SET_NAME` and `PR_GET_NAME` return zero on success. Linux errors stay
/// positive pthread statuses; an impossible raw result fails closed as ESRCH
/// rather than publishing C errno or exposing a malformed kernel value.
#[inline]
fn pthread_status(result: i64) -> c_int {
    if result == 0 {
        0
    } else if result < 0 && result >= -LINUX_ERRNO_MAX {
        result.wrapping_neg() as c_int
    } else {
        ESRCH
    }
}

/// Check musl's bounded `strnlen(name, 16)` self-name precondition.
///
/// # Safety
///
/// `name` must be readable through its first NUL byte or through all sixteen
/// bytes of Linux's task-comm window. This is the same caller-owned C string
/// validity requirement that musl's bounded `strnlen` observes.
#[inline]
unsafe fn name_fits_task_comm(name: *const c_char) -> bool {
    for offset in 0..TASK_COMM_LEN {
        // SAFETY: the caller upholds the bounded readable C-string contract.
        if unsafe { name.add(offset).read() } == 0 {
            return true;
        }
    }
    false
}

/// Set the calling bootstrapped-main pthread's Linux task name.
///
/// # Safety
///
/// `name` must point to a readable NUL-terminated C string or sixteen readable
/// bytes. `thread` must be this task's current bootstrapped-main
/// `pthread_self()` value. Any other handle is outside the selected musl
/// differential and returns `ESRCH` before `name` is read.
#[no_mangle]
pub unsafe extern "C" fn pthread_setname_np(thread: *mut c_void, name: *const c_char) -> c_int {
    if !is_selected_main_self(thread) {
        return ESRCH;
    }
    // SAFETY: the C caller owns the bounded source-string contract above.
    if !unsafe { name_fits_task_comm(name) } {
        return ERANGE;
    }
    // SAFETY: Linux/x86-64 prctl=157 receives option/pointer/zero words in
    // rdi/rsi/rdx/r10/r8. The selected C string remains readable for the call.
    pthread_status(unsafe {
        raw_syscall::syscall5(
            raw_syscall::SYS_PRCTL,
            PR_SET_NAME,
            name as usize as i64,
            0,
            0,
            0,
        )
    })
}

/// Read the calling bootstrapped-main pthread's Linux task name.
///
/// # Safety
///
/// When `len >= 16`, `name` must point to at least sixteen writable bytes for
/// Linux's complete task-comm result. `thread` must be this task's current
/// bootstrapped-main `pthread_self()` value. Any other handle is outside the
/// selected musl differential and returns `ESRCH` before `len` or `name` is
/// observed.
#[no_mangle]
pub unsafe extern "C" fn pthread_getname_np(
    thread: *mut c_void,
    name: *mut c_char,
    len: usize,
) -> c_int {
    if !is_selected_main_self(thread) {
        return ESRCH;
    }
    if len < TASK_COMM_LEN {
        return ERANGE;
    }
    // SAFETY: Linux/x86-64 prctl=157 receives option/pointer/zero words in
    // rdi/rsi/rdx/r10/r8. The C caller retains the 16-byte writable output.
    pthread_status(unsafe {
        raw_syscall::syscall5(
            raw_syscall::SYS_PRCTL,
            PR_GET_NAME,
            name as usize as i64,
            0,
            0,
            0,
        )
    })
}
