//! Fixed musl-compatible utmpx stubs for the native x86-64 owned product.
//!
//! This private C ABI leaf translates the complete
//! `src/legacy/utmpx.c` boundary from musl 1.2.6: seven strong inert
//! entries, seven weak traditional utmp aliases, and the two weak name
//! aliases. Musl intentionally provides no utmp/utmpx database
//! implementation. Cursor controls and the file update operation are empty;
//! record operations return null without reading their query or publishing an
//! error; and both name entries return `-1` with `errno == ENOTSUP`.
//! Keep this leaf independent of the richer AArch64 database owner in
//! `utmp_databases.rs`.
//!
//! Source provenance: musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, MIT license; the exact
//! `src/legacy/utmpx.c` source SHA-256 is
//! `3138ac427b05fc86177bf80e5e62a3b84b5d1e14daba1e6b935edc3b9839ce56`.

use core::ffi::{c_char, c_int, c_void};

use super::errno;

/// The public header's `struct utmpx` is opaque at this source boundary. The
/// source only passes its pointer, so an ABI-equivalent `c_void` pointer keeps
/// this owner from inventing a record layout or database state.
type Utmpx = c_void;
const ENOTSUP: c_int = 95;

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

/// Append to the inert utmpx database boundary, which performs no work.
///
/// The path and record are deliberately ignored, so even invalid or
/// unreadable pointers are accepted without an errno change.
///
/// # Safety
/// The pointers may be null or invalid because this source does not inspect
/// either argument.
#[no_mangle]
pub unsafe extern "C" fn updwtmpx(_path: *const c_char, _record: *const Utmpx) {}

// Musl's weak_alias declarations are same-address ELF aliases. Forwarding
// wrappers would change pointer identity and strong caller override behavior.
core::arch::global_asm!(
    ".weak endutent",
    ".set endutent, endutxent",
    ".weak setutent",
    ".set setutent, setutxent",
    ".weak getutent",
    ".set getutent, getutxent",
    ".weak getutid",
    ".set getutid, getutxid",
    ".weak getutline",
    ".set getutline, getutxline",
    ".weak pututline",
    ".set pututline, pututxline",
    ".weak updwtmp",
    ".set updwtmp, updwtmpx",
);

/// Reject changing the inert utmpx database name.
///
/// Musl's internal `__utmpxname` is represented by this weak provider so the
/// two public names can remain same-address aliases without exporting an
/// additional internal symbol. The path is never read.
///
/// # Safety
/// `path` may be null or invalid because this source does not inspect it.
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn utmpname(_path: *const c_char) -> c_int {
    // SAFETY: this selected x86 C ABI owns the caller's initial-TLS errno
    // slot for the fixed musl ENOTSUP result.
    unsafe { errno::set_errno(ENOTSUP) };
    -1
}

// Both public names are weak aliases of musl's private __utmpxname body.
// Keep the Rust provider private to this module's implementation surface;
// only the two source-declared public names are emitted.
core::arch::global_asm!(
    ".weak utmpxname",
    ".set utmpxname, utmpname",
);
