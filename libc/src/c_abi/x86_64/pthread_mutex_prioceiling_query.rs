//! Bounded Linux/x86-64 static `pthread_mutex_getprioceiling` artifact.
//!
//! This private static ABI leaf is a source-specific semantic port of pinned
//! musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
//! under musl's MIT license recorded in `COPYRIGHT`:
//!
//! - `src/thread/pthread_mutex_getprioceiling.c::pthread_mutex_getprioceiling`
//!   returns `EINVAL` without reading either argument.
//!
//! The admitted surface is deliberately only this unavailable
//! priority-protect query. It retains the public C signature but owns no
//! mutex record, priority ceiling, scheduler state, errno/TLS state, syscall,
//! allocation, synchronization, cancellation, or thread lifecycle behavior.
//! In particular, this frozen leaf does not select
//! `pthread_mutex_setprioceiling`, mutex initialization/locking/destruction,
//! or a priority-protect mutex state machine. The cfg-owned runtime provides
//! the same direct `EINVAL` setter separately. The direct status result is not
//! a mutex capability claim, general pthread support, or public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread mutex priority-ceiling query leaf requires little-endian Linux/x86-64");

use core::ffi::{c_int, c_void};

const EINVAL: c_int = 22;

/// Return musl's direct unsupported status for a priority-protect query.
///
/// # Safety
///
/// This is a raw C ABI entry. The selected musl path intentionally does not
/// dereference either pointer, so it does not establish ownership, validity,
/// or initialization rules for a mutex or result slot. Callers must not infer
/// priority-protect mutex support from this direct `EINVAL` result.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_getprioceiling(
    _mutex: *const c_void,
    _ceiling: *mut c_int,
) -> c_int {
    EINVAL
}
