//! Static Linux/x86-64 environment-backed login-name observation.
//!
//! This leaf owns exactly `getlogin` and `getlogin_r`. Musl deliberately
//! treats the first `LOGNAME` environment entry as the login-name source; it
//! does not derive an identity from passwd, utmp, a terminal, credentials, or
//! session state. This leaf therefore composes only the separately selected
//! bounded process-environment owner.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/unistd/getlogin.c` maps `getlogin()` to `getenv("LOGNAME")`.
//! - `src/unistd/getlogin_r.c` returns `ENXIO` when that lookup is absent,
//!   returns `ERANGE` without a write when the complete value plus NUL does
//!   not fit, and otherwise copies the complete value into caller storage.
//!
//! `getlogin` returns the environment owner's borrowed pointer. Neither that
//! pointer nor `getlogin_r`'s source remains stabilized after `getenv`
//! releases its private lock. Caller-coordinated environment writers, direct
//! `environ` assignment, and caller-owned `putenv` mutation/lifetime are
//! required exactly as for the selected environment leaf. Both functions
//! preserve incoming `errno`; `getlogin_r` returns `ENXIO` or `ERANGE`
//! directly and does not set `errno`.
//!
//! This artifact owns no storage, allocator, lock, file or database parsing,
//! terminal/session lookup, credential policy, secure-execution decision,
//! process creation, exec/spawn inheritance, or supervision. It is not a
//! general login/session identity service, dynamic libc, CRT, loader, sysroot,
//! promotion, or public x86 support.

use core::ffi::{c_char, c_int};
use core::ptr;

use super::environment;

const ENXIO: c_int = 6;
const ERANGE: c_int = 34;
const LOGNAME: &[u8; 8] = b"LOGNAME\0";

unsafe fn c_string_length(value: *const c_char) -> usize {
    let mut length = 0usize;
    loop {
        // SAFETY: the pointer came from the selected environment owner and
        // remains a valid C string under the caller-coordination contract.
        if unsafe { ptr::read(value.add(length).cast::<u8>()) } == 0 {
            return length;
        }
        length += 1;
    }
}

/// Return the first `LOGNAME` value as a borrowed environment pointer.
///
/// The pointer may be null. A non-null result remains valid only while the
/// caller prevents environment replacement, direct `environ` writes, and
/// mutation or expiry of caller-owned `putenv` storage.
///
/// # Safety
///
/// The caller must keep the environment vector and any caller-owned entry
/// storage valid and unchanged for every use of the returned pointer.
#[no_mangle]
pub unsafe extern "C" fn getlogin() -> *mut c_char {
    unsafe { environment::getenv(LOGNAME.as_ptr().cast()) }
}

/// Copy the current `LOGNAME` value into caller-owned storage.
///
/// # Safety
///
/// `name` may be null when `size` is zero or when `LOGNAME` is absent because
/// those paths return before writing. Otherwise it must designate `size`
/// writable bytes that do not overlap the borrowed environment value. The
/// caller must prevent concurrent environment mutation throughout the lookup,
/// length scan, and copy.
#[no_mangle]
pub unsafe extern "C" fn getlogin_r(name: *mut c_char, size: usize) -> c_int {
    let login = unsafe { getlogin() };
    if login.is_null() {
        return ENXIO;
    }
    let length = unsafe { c_string_length(login) };
    if length >= size {
        return ERANGE;
    }
    // SAFETY: the caller supplies a nonoverlapping writable destination large
    // enough for the measured value and its terminating NUL.
    unsafe { ptr::copy_nonoverlapping(login, name, length + 1) };
    0
}
