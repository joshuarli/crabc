//! Bounded Linux/x86-64 static pthread CPU-clock leaf.
//!
//! This private static ABI leaf is source-mapped to pinned musl 1.2.6 release
//! commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/thread/pthread_getcpuclockid.c::pthread_getcpuclockid` reads the
//! target's Linux TID from musl's full `struct pthread` and encodes its
//! per-thread CPU clock as `(~tid << 3) | 6`.
//!
//! Static Initial TLS v1 deliberately owns just the x86 Variant-II `%fs:0`
//! self word, not musl's dereferenceable TCB. This leaf therefore admits only
//! the bootstrapped process-main task through that task's own
//! `pthread_self()` handle. It verifies that opaque self identity with the
//! existing Static Initial TLS v1 task-ID discriminator, reads the calling
//! task's Linux TID through direct `gettid=186`, and performs musl's exact
//! 32-bit clock-ID encoding. The difference is intentional and local: no C
//! handle is dereferenced and no worker, foreign, completed, or general
//! pthread handle is admitted. A null or non-self handle fails closed with
//! `ESRCH` before observing the output slot; that diagnostic is candidate-only
//! because musl's full-TCB implementation requires a valid handle.
//!
//! The leaf selects only `pthread_getcpuclockid` for the calling bootstrapped
//! process-main thread. It does not select `clock_getcpuclockid`, general C
//! clock APIs, worker CPU clocks, a TCB/thread list, lifecycle ownership,
//! affinity or scheduling attributes, cancellation, synchronization, TSS,
//! dynamic/loader TLS, CRT, sysroot, general pthread/TLS behavior, or public x86 support.
//! Pthread errors are positive return values: this entry does not write C `errno`.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread CPU-clock leaf requires little-endian Linux/x86-64");

use core::ffi::{c_int, c_void};

use super::{pthread_identity, raw_syscall, static_tls};

const ESRCH: c_int = 3;
const LINUX_ERRNO_MAX: i64 = 4_095;

/// Convert one valid Linux thread ID to Linux's per-thread CPU-clock ID.
///
/// The unsigned computation intentionally retains musl's 32-bit `int`
/// machine representation without relying on signed-overflow behavior.
#[inline]
fn thread_cpu_clock_id(thread_id: c_int) -> c_int {
    ((!(thread_id as u32)).wrapping_shl(3) | 6) as c_int
}

/// Translate an anomalous raw `gettid` result to the pthread status domain.
///
/// Linux normally returns one positive task ID. A seccomp-injected raw Linux
/// failure remains its positive errno, while impossible nonpositive or
/// out-of-range values fail closed as `ESRCH` without touching C `errno`.
#[inline]
fn gettid_status(result: i64) -> Result<c_int, c_int> {
    if result > 0 && result <= i64::from(c_int::MAX) {
        return Ok(result as c_int);
    }
    if result < 0 && result >= -LINUX_ERRNO_MAX {
        return Err(result.wrapping_neg() as c_int);
    }
    Err(ESRCH)
}

/// Return the Linux CPU-clock ID for the calling bootstrapped-main pthread.
///
/// # Safety
///
/// `clock_id` must point to writable x86-64 `clockid_t` (`int`) storage for
/// the duration of the call. `thread` must be the calling bootstrapped
/// process-main task's current `pthread_self()` value. Passing any other
/// handle is outside the selected musl differential; this bounded candidate
/// returns `ESRCH` without reading the handle or writing `clock_id`.
#[no_mangle]
pub unsafe extern "C" fn pthread_getcpuclockid(
    thread: *mut c_void,
    clock_id: *mut c_int,
) -> c_int {
    let current_thread_pointer = pthread_identity::current_thread_pointer();
    if thread.is_null()
        || thread != current_thread_pointer.cast()
        || !static_tls::is_initial_thread_pointer(current_thread_pointer)
    {
        return ESRCH;
    }

    // SAFETY: Linux/x86-64 `gettid=186` takes no arguments. The preceding
    // static-TLS discriminator proved this is the selected initial task.
    let thread_id = match gettid_status(unsafe {
        raw_syscall::syscall0(raw_syscall::SYS_GETTID)
    }) {
        Ok(thread_id) => thread_id,
        Err(status) => return status,
    };
    // SAFETY: the caller upholds the writable `clockid_t` output contract.
    unsafe { clock_id.write(thread_cpu_clock_id(thread_id)) };
    0
}
