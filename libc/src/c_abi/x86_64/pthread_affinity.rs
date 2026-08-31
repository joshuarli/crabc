//! Bounded Linux/x86-64 static pthread-affinity leaf.
//!
//! This private static ABI leaf is source-mapped to pinned musl 1.2.6 release
//! commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/sched/affinity.c::pthread_getaffinity_np` supplies the direct
//!   selected-thread `sched_getaffinity` syscall, positive pthread-status
//!   translation, and zero-fill of any bytes beyond Linux's returned mask.
//! - `src/sched/affinity.c::pthread_setaffinity_np` supplies the direct
//!   selected-thread `sched_setaffinity` syscall and its positive
//!   pthread-status translation.
//!
//! Musl obtains a target TID from its complete `struct pthread`. Static Initial
//! TLS v1 deliberately has no such public TCB. This leaf instead admits only
//! (a) the bootstrapped process-main task through that task's own
//! `pthread_self()` handle and (b) a live handle still published by the
//! selected static worker registry. The registry copies Linux's
//! `CLONE_PARENT_SETTID` value while its private control record remains live;
//! no public handle is dereferenced. The lookup releases the registry lock
//! before the kernel call, so callers must keep a selected target executing
//! and must not race this narrow operation with target completion,
//! `pthread_join`, `pthread_detach`, or another selected lifecycle boundary
//! that can clear its TID, withdraw its mapping, or permit TID reuse. A
//! finished, withdrawn, foreign, null, or non-self main handle fails closed
//! with `ESRCH`.
//!
//! The leaf selects only GNU `pthread_getaffinity_np` and
//! `pthread_setaffinity_np`. It does not select `sched_getaffinity`,
//! `sched_setaffinity`, affinity attributes, `pthread_attr_*affinity_np`,
//! `pthread_getattr_np`, per-thread scheduling APIs, `CPU_*` mask helper
//! macros, general TCB/thread-list ownership, foreign threads, dynamic/loader
//! TLS, or general pthread/TLS behavior. Each public C entry preserves the
//! caller's `errno`, as pthread APIs report a positive error number directly.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread-affinity leaf requires little-endian Linux/x86-64");

use core::ffi::{c_int, c_void};

use super::{pthread_create_join, pthread_identity, raw_syscall, static_tls};

const ESRCH: c_int = 3;
const EINVAL: c_int = 22;
const LINUX_ERRNO_MAX: i64 = 4_095;

#[inline]
fn is_linux_error(result: i64) -> bool {
    result < 0 && result >= -LINUX_ERRNO_MAX
}

/// Translate one raw Linux result to the direct pthread status convention.
///
/// Linux can only return a negative errno in the bounded range below. Keeping
/// an impossible negative result as `EINVAL` prevents a malformed raw value
/// from escaping the public pthread error domain.
#[inline]
fn pthread_status(result: i64) -> c_int {
    if result >= 0 {
        0
    } else if is_linux_error(result) {
        result.wrapping_neg() as c_int
    } else {
        EINVAL
    }
}

/// Read the bootstrapped main task's Linux TID without modifying C `errno`.
#[inline]
fn current_linux_thread_id() -> Option<c_int> {
    // SAFETY: Linux/x86-64 `gettid` takes no arguments. This leaf reads only
    // the task ID needed to target the self-addressed initial-thread handle.
    let result = unsafe { raw_syscall::syscall0(raw_syscall::SYS_GETTID) };
    if is_linux_error(result) || result <= 0 || result > i64::from(c_int::MAX) {
        return None;
    }
    Some(result as c_int)
}

/// Resolve one admitted opaque pthread handle to its currently live Linux TID.
///
/// A selected worker lookup never dereferences the caller's opaque value. The
/// sibling registry validates it while the private mapping is live and copies
/// only its parent-written child-TID word. See the module contract for the
/// excluded concurrent completion/join/detach/reclamation race.
fn selected_thread_id(thread: *mut c_void) -> Result<c_int, c_int> {
    if thread.is_null() {
        return Err(ESRCH);
    }

    let current_thread_pointer = pthread_identity::current_thread_pointer();
    if thread == current_thread_pointer.cast()
        && static_tls::is_initial_thread_pointer(current_thread_pointer)
    {
        return current_linux_thread_id().ok_or(ESRCH);
    }

    pthread_create_join::selected_worker_linux_thread_id(thread).ok_or(ESRCH)
}

/// Invoke Linux `sched_getaffinity` and reproduce musl's successful tail clear.
///
/// # Safety
///
/// `mask` must designate writable memory for `cpusetsize` bytes for the raw
/// Linux syscall. On a successful syscall the initialized kernel prefix is
/// retained and this helper clears the remaining caller-owned bytes.
unsafe fn get_affinity(thread_id: c_int, cpusetsize: usize, mask: *mut c_void) -> i64 {
    // SAFETY: the public C caller owns the raw Linux buffer validity contract.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_SCHED_GETAFFINITY,
            i64::from(thread_id),
            cpusetsize as i64,
            mask as usize as i64,
        )
    };
    if result >= 0 && (result as usize) < cpusetsize {
        // SAFETY: a successful kernel result initialized the first `result`
        // bytes of this valid caller buffer. The remaining `cpusetsize -
        // result` bytes are still writable caller-owned memory.
        unsafe {
            core::ptr::write_bytes(
                mask.cast::<u8>().add(result as usize),
                0,
                cpusetsize - result as usize,
            );
        }
    }
    result
}

/// Read one admitted selected thread's Linux CPU-affinity mask.
///
/// # Safety
///
/// `mask` must be valid writable storage for `cpusetsize` bytes for the
/// duration of the call. `thread` must be the caller's bootstrapped-main
/// `pthread_self()` value or a currently live selected static-worker handle;
/// it must remain executing and must not race selected completion, join,
/// detach, or reaping ownership.
#[no_mangle]
pub unsafe extern "C" fn pthread_getaffinity_np(
    thread: *mut c_void,
    cpusetsize: usize,
    mask: *mut c_void,
) -> c_int {
    let thread_id = match selected_thread_id(thread) {
        Ok(thread_id) => thread_id,
        Err(error) => return error,
    };
    // SAFETY: the C ABI caller retains the documented raw buffer contract.
    pthread_status(unsafe { get_affinity(thread_id, cpusetsize, mask) })
}

/// Replace one admitted selected thread's Linux CPU-affinity mask.
///
/// # Safety
///
/// `mask` must be valid readable storage for `cpusetsize` bytes for the
/// duration of the call. `thread` must be the caller's bootstrapped-main
/// `pthread_self()` value or a currently live selected static-worker handle;
/// it must remain executing and must not race selected completion, join,
/// detach, or reaping ownership.
#[no_mangle]
pub unsafe extern "C" fn pthread_setaffinity_np(
    thread: *mut c_void,
    cpusetsize: usize,
    mask: *const c_void,
) -> c_int {
    let thread_id = match selected_thread_id(thread) {
        Ok(thread_id) => thread_id,
        Err(error) => return error,
    };
    // SAFETY: the C ABI caller retains the documented raw buffer contract.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_SCHED_SETAFFINITY,
            i64::from(thread_id),
            cpusetsize as i64,
            mask as usize as i64,
        )
    };
    pthread_status(result)
}
