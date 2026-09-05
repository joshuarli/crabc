//! Bounded Linux/x86-64 static pthread CPU-clock leaf.
//!
//! This private static ABI leaf is source-mapped to pinned musl 1.2.6 release
//! commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/thread/pthread_getcpuclockid.c::pthread_getcpuclockid` reads the
//! target's Linux TID from musl's full `struct pthread` and encodes its
//! per-thread CPU clock as `(~tid << 3) | 6`.
//!
//! Static Initial TLS v1 deliberately owns just the x86 Variant-II `%fs:0`
//! self word, not musl's dereferenceable TCB. This leaf therefore admits the
//! bootstrapped process-main task through that task's own `pthread_self()`
//! handle, a held live process-main target queried by a selected worker, and
//! a live handle published by the selected worker registry. The current-main
//! route preserves the existing `%fs:0` plus Linux-TID discriminator and
//! reads direct `gettid=186`; the initial-target route copies the Static
//! Initial TLS owner's recorded TID. The worker registry instead copies its
//! positive `CLONE_PARENT_SETTID` child-TID while its private control record
//! is still linked. No route dereferences public `pthread_t`.
//!
//! Registry lookup releases its lock before this leaf returns the encoded
//! clock ID. A caller querying a worker must therefore keep that selected
//! target executing and must not race target completion, `pthread_join`,
//! `pthread_detach`, or a later selected lifecycle/reaping boundary that can
//! clear its TID, withdraw its mapping, or permit TID reuse. The initial
//! target is the same scalar snapshot: a worker querying a saved main handle
//! must keep main executing. Null and foreign handles fail closed with `ESRCH`
//! before observing the output slot, as do finished or withdrawn
//! selected-worker handles. The retained initial-main token has no
//! exited-main invalidation; its only supported condition is the held-live
//! target contract. Those diagnostics are candidate-only because musl's
//! full-TCB implementation requires a valid handle.
//!
//! The leaf selects only `pthread_getcpuclockid` for the bootstrapped main
//! thread, a held process-main target, and a live selected worker. It does not
//! select `clock_getcpuclockid`, general C clock APIs, a public TCB/thread
//! list, lifecycle ownership,
//! affinity or scheduling attributes, cancellation, synchronization, TSS,
//! dynamic/loader TLS, CRT, sysroot, general pthread/TLS behavior, or public x86 support.
//! Pthread errors are positive return values: this entry does not write C `errno`.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread CPU-clock leaf requires little-endian Linux/x86-64");

use core::ffi::{c_int, c_void};

use super::{pthread_create_join, pthread_identity, raw_syscall, static_tls};

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

/// Resolve one admitted opaque pthread handle to its currently live Linux TID.
///
/// A selected worker lookup never dereferences the caller's opaque value. The
/// sibling registry validates it while its private control mapping is live and
/// copies only its parent-written child-TID word. The public operation excludes
/// the concurrent completion/join/detach/reclamation race documented above.
#[inline]
fn selected_thread_id(thread: *mut c_void) -> Result<c_int, c_int> {
    if thread.is_null() {
        return Err(ESRCH);
    }

    let current_thread_pointer = pthread_identity::current_thread_pointer();
    if thread == current_thread_pointer.cast()
        && static_tls::is_initial_thread_pointer(current_thread_pointer)
    {
        // SAFETY: Linux/x86-64 `gettid=186` takes no arguments. The static-TLS
        // discriminator proved this is the selected bootstrapped initial task.
        return gettid_status(unsafe { raw_syscall::syscall0(raw_syscall::SYS_GETTID) });
    }

    if let Some(thread_id) = static_tls::selected_initial_thread_id(thread.cast()) {
        return Ok(thread_id);
    }

    pthread_create_join::selected_worker_linux_thread_id(thread).ok_or(ESRCH)
}

/// Return the Linux CPU-clock ID for one admitted selected pthread.
///
/// # Safety
///
/// `clock_id` must point to writable x86-64 `clockid_t` (`int`) storage for
/// the duration of the call. `thread` must be the caller's bootstrapped-main
/// `pthread_self()` value, a held live process-main handle, or a currently
/// live selected worker handle. A saved initial target and every worker target
/// must remain executing and must not race selected completion, join, detach,
/// or reaping ownership. Passing an unadmitted handle is outside the selected
/// musl differential; this bounded candidate returns `ESRCH` without reading
/// the handle or writing `clock_id`.
#[no_mangle]
pub unsafe extern "C" fn pthread_getcpuclockid(
    thread: *mut c_void,
    clock_id: *mut c_int,
) -> c_int {
    let thread_id = match selected_thread_id(thread) {
        Ok(thread_id) => thread_id,
        Err(status) => return status,
    };
    // SAFETY: the caller upholds the writable `clockid_t` output contract.
    unsafe { clock_id.write(thread_cpu_clock_id(thread_id)) };
    0
}
