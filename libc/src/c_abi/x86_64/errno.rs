//! Linux/x86-64 C `errno` storage boundary.
//!
//! The selected static x86 metadata, credential, bootstrap-primitives, simple
//! signal-control, termios-control, selected process-context, selected
//! fcntl status-control/nonblocking record-lock, advisory flock, descriptor-I/O,
//! selected process-resources, and selected readiness/signal-
//! waits, selected system-configuration, selected system-observation, selected UTS-namespace identity, and
//! basic socket-transport, integer-parsing, and nanosleep artifact boundaries share this
//! one initial-TLS slot.
//! Its source-only probe
//! remains the direct relocation proof: `ERRNO` uses the executable's initial TLS block
//! (`R_X86_64_TPOFF*`), not a dynamic TLS resolver. The separately selected
//! bounded create/explicit-exit/join artifact can materialize only this datum
//! for its child; general pthread lifecycle, loader-installed dynamic TLS, and
//! a general x86 C runtime remain separate work.

use core::ffi::c_int;

/// Per-thread C `errno` storage for the x86 C ABI.
///
/// The initial zero value and thread-local placement are part of the C
/// contract: each thread starts with an independent zero-initialized `errno`.
#[thread_local]
static mut ERRNO: c_int = 0;

/// Return the calling thread's C `errno` storage.
///
/// C's `errno` macro dereferences this pointer. The source-only x86 evidence
/// links a static C program and proves that its main and pthread instances are
/// distinct, zero-initialized TLS slots.
#[no_mangle]
pub unsafe extern "C" fn __errno_location() -> *mut c_int {
    core::ptr::addr_of_mut!(ERRNO)
}

/// Musl's internal spelling used by the bundled mimalloc C backend.
///
/// The public ABI remains `__errno_location`; this alias prevents an opt-in
/// allocator artifact from importing a second errno owner merely because the
/// backend was compiled against musl's hidden internal declaration.
#[cfg(feature = "x86-allocator-runtime")]
#[no_mangle]
pub unsafe extern "C" fn ___errno_location() -> *mut c_int {
    core::ptr::addr_of_mut!(ERRNO)
}

/// Publish one Linux error number in the calling thread's C `errno` slot.
///
/// This stays private to the x86 C-runtime foundation: public callers reach
/// the slot only through [`__errno_location`]. Keeping the writer beside the
/// storage prevents a future target composition from reaching across a
/// module boundary to mutate target-specific TLS directly.
#[inline]
pub(crate) unsafe fn set_errno(value: c_int) {
    // SAFETY: The caller is the C ABI error-translation boundary for the
    // calling thread. `ERRNO` is one initial-TLS `c_int` slot on x86-64.
    unsafe { ERRNO = value };
}

/// Read the calling thread's C `errno` slot within the selected x86 ABI.
///
/// This remains private to local adapters that must inspect a translated or
/// selected current error, notably `nice`'s `EACCES` to `EPERM` compatibility
/// mapping and the bare `%m` fixed-C-locale formatter conversion. Public C
/// callers use [`__errno_location`] instead.
#[inline]
pub(crate) unsafe fn get_errno() -> c_int {
    // SAFETY: The selected C ABI owns the calling thread's one initial-TLS
    // errno slot. This is a plain read and does not change its value.
    unsafe { ERRNO }
}
