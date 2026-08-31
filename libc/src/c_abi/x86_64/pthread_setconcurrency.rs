//! Bounded Linux/x86-64 static `pthread_setconcurrency` artifact.
//!
//! This private static ABI leaf is a source-specific semantic port of pinned
//! musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
//! under musl's MIT license recorded in `COPYRIGHT`:
//!
//! - `src/thread/pthread_setconcurrency.c::pthread_setconcurrency` returns
//!   `EINVAL` for a negative request, `EAGAIN` for a positive request, and
//!   zero only for the no-op zero request.
//!
//! The selected source reads no thread record and changes no concurrency,
//! scheduler, or process state. It neither calls nor needs
//! `pthread_getconcurrency`; that neighboring constant query remains
//! deliberately unselected. This entry has no errno/TLS, syscall, allocator,
//! synchronization, cancellation, thread-lifecycle, or runtime dependency.
//! It is a private selected static artifact, not a pthread runtime, scheduler
//! contract, family completion, or public x86 support claim.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread setconcurrency leaf requires little-endian Linux/x86-64");

use core::ffi::c_int;

const EAGAIN: c_int = 11;
const EINVAL: c_int = 22;

/// Return musl's stateless availability result for a concurrency request.
///
/// The selected entry does not record an accepted value: zero is merely the
/// one successful no-op request, while negative and positive requests return
/// their fixed status values without publishing through `errno`.
#[no_mangle]
pub extern "C" fn pthread_setconcurrency(value: c_int) -> c_int {
    if value < 0 {
        EINVAL
    } else if value > 0 {
        EAGAIN
    } else {
        0
    }
}
