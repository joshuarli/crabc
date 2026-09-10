//! Fixed musl-compatible utmpx stubs for the native x86-64 owned product.
//!
//! This private C ABI leaf translates the complete six-entry boundary from
//! musl 1.2.6 `src/legacy/utmpx.c`. Musl intentionally provides no utmp/utmpx
//! database implementation: the two cursor controls are empty, and the four
//! record operations return null without reading their query or publishing an
//! error. Keep this leaf independent of the richer AArch64 database owner in
//! `utmp_databases.rs`.

use core::ffi::c_void;

/// The public header's `struct utmpx` is opaque at this source boundary. The
/// six functions only pass its pointer, so an ABI-equivalent `c_void` pointer
/// keeps this owner from inventing a record layout or database state.
type Utmpx = c_void;

/// End the inert utmpx cursor.
///
/// # Safety
/// This C ABI entry has no caller-owned pointer or state requirement.
#[no_mangle]
pub unsafe extern "C" fn endutxent() {}

/// Return the next inert utmpx record, which is always absent.
///
/// # Safety
/// This C ABI entry has no caller-owned pointer or state requirement.
#[no_mangle]
pub unsafe extern "C" fn getutxent() -> *mut Utmpx {
    core::ptr::null_mut()
}

/// Find an inert utmpx record, which is always absent.
///
/// The query is deliberately ignored, as in musl's source. It is not
/// dereferenced, and this entry does not alter errno.
///
/// # Safety
/// `query` may be null because this source does not inspect it; any non-null
/// pointer remains the caller's live object for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn getutxid(_query: *const Utmpx) -> *mut Utmpx {
    core::ptr::null_mut()
}

/// Find an inert utmpx line, which is always absent.
///
/// The query is deliberately ignored, as in musl's source. It is not
/// dereferenced, and this entry does not alter errno.
///
/// # Safety
/// `query` may be null because this source does not inspect it; any non-null
/// pointer remains the caller's live object for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn getutxline(_query: *const Utmpx) -> *mut Utmpx {
    core::ptr::null_mut()
}

/// Reject an inert utmpx record update by returning null.
///
/// The record is deliberately ignored, as in musl's source. It is not
/// dereferenced, and this entry does not alter errno.
///
/// # Safety
/// `record` may be null because this source does not inspect it; any non-null
/// pointer remains the caller's live object for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn pututxline(_record: *const Utmpx) -> *mut Utmpx {
    core::ptr::null_mut()
}

/// Reset the inert utmpx cursor.
///
/// # Safety
/// This C ABI entry has no caller-owned pointer or state requirement.
#[no_mangle]
pub unsafe extern "C" fn setutxent() {}
