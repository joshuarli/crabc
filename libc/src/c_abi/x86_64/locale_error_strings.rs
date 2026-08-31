//! Fixed-profile Linux/x86-64 locale-aware error-string ABI bridge.
//!
//! This leaf owns only musl's strong `__strerror_l` spelling and its weak
//! same-address public `strerror_l` alias. The admitted `C`, `POSIX`, and
//! `C.UTF-8` locale objects all use the immutable English messages already
//! owned by `error_strings`, so the bridge deliberately does not inspect the
//! opaque locale token, mutate selected-thread locale state, allocate, access
//! message catalogs, or touch `errno`, TLS, locks, or process state. It is not
//! `strerror`, `strerror_r`, `strsignal`, `strfmon`, gettext, a general locale database,
//! libc.so, a CRT, a loader, a sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/errno/strerror.c::__strerror_l` selects the locale-translated
//!   message, and `weak_alias(__strerror_l, strerror_l)` requires equal ELF
//!   symbol values. Fixed project profiles have no messages translation, so
//!   this leaf forwards to the already translated fixed-message lookup.
//! - `src/locale/locale_map.c` and locale catalogs remain deliberately
//!   unselected: C/POSIX/C.UTF-8 share the same selected error messages.
//!
//! C callers must pass a live locale object returned by the selected
//! `newlocale` boundary. `LC_GLOBAL_LOCALE`, null, stale, and arbitrary tokens
//! are outside this `strerror_l` argument contract, matching the musl oracle.

use core::ffi::{c_char, c_int, c_void};

use super::error_strings;

// Musl's weak_alias(__strerror_l, strerror_l) requires equal ELF symbol
// values. A Rust wrapper would have a different address and would silently
// weaken the static C ABI contract.
core::arch::global_asm!(
    ".weak strerror_l",
    ".set strerror_l, __strerror_l",
);

/// Return one immutable fixed-profile error message through an explicit locale.
///
/// # Safety
///
/// `locale` must be a live C/POSIX/C.UTF-8 locale object produced by the
/// selected `newlocale` boundary. `LC_GLOBAL_LOCALE`, null, stale, and
/// arbitrary locale tokens are outside the ABI contract even though the
/// current fixed-message implementation does not dereference the token.
/// Returned storage is process-static and must not be modified or freed.
#[no_mangle]
pub unsafe extern "C" fn __strerror_l(error: c_int, _locale: *mut c_void) -> *mut c_char {
    error_strings::strerror(error)
}
