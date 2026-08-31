//! Selected static Linux/x86-64 C `wcswcs` ABI boundary.
//!
//! This leaf owns exactly musl's unconditional legacy `wcswcs` spelling: a
//! read-only wide-substring search which returns the first matching haystack
//! suffix, the original haystack for an empty needle, or null when no suffix
//! matches. It neither creates nor transforms wide strings.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/string/wcswcs.c` is the public forwarding entry to `wcsstr`.
//! - `src/string/wcsstr.c` is the direct wide-substring source closure. Its
//!   two-way acceleration is intentionally represented here by a private
//!   scalar suffix comparison: the valid NUL-terminated `wchar_t` C-string
//!   contract, first-match order, return pointer, and no-match result are
//!   preserved without extracting the existing broad wide-character object.
//!
//! The local closure is stateless and allocation-free. It has no errno, TLS,
//! locale object, multibyte conversion, Unicode classification, syscall,
//! cancellation, lock, CRT, loader, sysroot, or mutable-runtime dependency.
//! It is a selected-private ABI artifact only, not general wide text/search,
//! `wcsstr`, locale or Unicode support, a C string subsystem, family
//! completion, promotion, or public x86 support.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 C wcswcs leaf requires little-endian Linux/x86-64");

use core::{ffi::c_int, ptr::null_mut};

type Wchar = c_int;

/// Preserve the C-defined first-suffix wide-substring contract without
/// extracting the independently selected broad `wcsstr` object.
///
/// # Safety
///
/// `haystack` and `needle` must each designate a readable NUL-terminated
/// `wchar_t` sequence. They may alias because this helper writes neither.
#[inline(always)]
unsafe fn musl_wcsstr(haystack: *const Wchar, needle: *const Wchar) -> *mut Wchar {
    // SAFETY: the caller supplies the first readable needle unit.
    if unsafe { needle.read() } == 0 {
        return haystack.cast_mut();
    }

    let mut suffix = haystack;
    loop {
        // SAFETY: the caller supplies the current haystack suffix unit.
        if unsafe { suffix.read() } == 0 {
            return null_mut();
        }

        let mut haystack_cursor = suffix;
        let mut needle_cursor = needle;
        loop {
            // SAFETY: the caller supplies the current readable needle unit.
            let needle_unit = unsafe { needle_cursor.read() };
            if needle_unit == 0 {
                return suffix.cast_mut();
            }
            // SAFETY: a non-NUL needle unit can be compared against the
            // current readable haystack suffix unit under the C-string
            // contract. A haystack terminator simply fails this comparison.
            if unsafe { haystack_cursor.read() } != needle_unit {
                break;
            }
            haystack_cursor = haystack_cursor.wrapping_add(1);
            needle_cursor = needle_cursor.wrapping_add(1);
        }
        suffix = suffix.wrapping_add(1);
    }
}

/// Locate the first wide-substring occurrence using musl's `wcswcs` ABI.
///
/// # Safety
///
/// `haystack` and `needle` must each designate a readable NUL-terminated
/// `wchar_t` sequence. The returned pointer aliases `haystack` or is null;
/// this function writes neither input.
#[no_mangle]
pub unsafe extern "C" fn wcswcs(haystack: *const Wchar, needle: *const Wchar) -> *mut Wchar {
    // SAFETY: this public entry forwards its unchanged C-string obligations.
    unsafe { musl_wcsstr(haystack, needle) }
}
