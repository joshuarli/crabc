//! Linux/x86-64 selected `h_errno` status-slot C ABI boundary.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license
//! recorded in `COPYRIGHT`, maps `src/network/h_errno.c` to exactly the
//! link-visible four-byte `h_errno` object and `__h_errno_location` accessor.
//! The pinned static archive owns both in `h_errno.lo`.
//!
//! Musl's installed x86 `<netdb.h>` hides the legacy object behind
//! `(*__h_errno_location())`.  This private artifact retains that shape for a
//! bootstrapped process main thread and selected pthread workers: the
//! authenticated main thread uses the link-visible legacy object, while each
//! selected worker receives one direct initial-TLS slot.  The global object is
//! therefore a compatibility fallback, not the public C spelling or an
//! inter-thread status channel.
//!
//! This is an intentional source-layout difference rather than a whole-TCB
//! translation: musl's worker accessor reaches its complete pthread/TCB
//! status storage, while this selected runtime does not model that TCB.  Its
//! direct initial-TLS worker slot proves only the observed selected-worker
//! status identity and isolation; it does not claim musl TCB field-offset or
//! foreign-thread parity.
//!
//! Static Initial TLS v1 and the selected pthread create/join boundary are
//! prerequisites.  This is not a general musl TCB or dynamic-TLS
//! implementation: a foreign-thread caller that has not entered through the
//! selected static TLS and selected pthread-worker contract is outside this
//! artifact.  It neither parses resolver configuration nor selects DNS,
//! sockets, hosts/services databases, `getaddrinfo`, `__res_state`, allocator,
//! `crabc-core`, or a resolver-runtime completion claim.

use core::ffi::c_int;

use super::{pthread_identity, static_tls};

/// Link-visible legacy resolver-status fallback for the bootstrapped main task.
///
/// C callers normally reach this through the public `<netdb.h>` accessor macro;
/// the object remains exported for old object-file compatibility.
#[no_mangle]
pub static mut h_errno: c_int = 0;

// The standalone h_errno profile has no resolver state record. Keep its
// selected worker status independent and direct-TLS, just as the source
// oracle's accessor chooses a worker-local status slot rather than the
// link-visible main fallback object.
#[cfg(not(feature = "x86-resolver-runtime"))]
#[thread_local]
static mut SELECTED_WORKER_H_ERRNO: c_int = 0;

/// Return the selected worker's resolver-status storage.
///
/// With the wider resolver feature, its public `__res_state` record owns the
/// worker slot so resolver operations retain their existing record updates.
/// The standalone artifact instead owns one otherwise independent direct-TLS
/// integer. Both routes require the selected worker lifecycle described above.
#[cfg(feature = "x86-resolver-runtime")]
#[inline]
unsafe fn selected_worker_location() -> *mut c_int {
    unsafe { super::resolver_runtime::resolver_worker_h_errno_location() }
}

#[cfg(not(feature = "x86-resolver-runtime"))]
#[inline]
unsafe fn selected_worker_location() -> *mut c_int {
    core::ptr::addr_of_mut!(SELECTED_WORKER_H_ERRNO)
}

/// Locate the calling selected thread's historical resolver-status slot.
///
/// # Safety
///
/// The caller must run after Static Initial TLS v1 has bootstrapped the main
/// task, or on a worker made by the selected pthread create/join owner. A raw
/// foreign thread lacks the direct-TLS and identity contract required here.
#[inline]
pub(super) unsafe fn location() -> *mut c_int {
    let thread_pointer = pthread_identity::current_thread_pointer();
    if static_tls::is_initial_thread_pointer(thread_pointer) {
        core::ptr::addr_of_mut!(h_errno)
    } else {
        unsafe { selected_worker_location() }
    }
}

/// Publish one status value to the calling selected thread's slot.
///
/// # Safety
///
/// The caller must satisfy [`location`]'s selected static-TLS/thread-lifecycle
/// contract. The returned storage is ordinary mutable C state and concurrent
/// callers must use the thread isolation selected by this artifact.
#[cfg(feature = "x86-resolver-runtime")]
#[inline]
pub(super) unsafe fn set(value: c_int) {
    unsafe { location().write(value) };
}

/// Read the calling selected thread's status value.
///
/// # Safety
///
/// The caller must satisfy [`location`]'s selected static-TLS/thread-lifecycle
/// contract.
#[cfg(feature = "x86-resolver-runtime")]
#[inline]
pub(super) unsafe fn current() -> c_int {
    unsafe { location().read() }
}

/// Return the calling selected thread's historical resolver-status slot.
///
/// The returned raw pointer remains valid only while the selected main task or
/// selected pthread worker remains alive. C consumers must not retain a worker
/// slot after that worker has completed and its private TLS mapping is released.
#[no_mangle]
pub extern "C" fn __h_errno_location() -> *mut c_int {
    // SAFETY: the C ABI is entered only through the artifact's documented
    // bootstrapped-main or selected-worker contract; the implementation makes
    // no reference from the resulting raw pointer.
    unsafe { location() }
}
