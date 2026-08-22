//! Process parameters whose values require no libc-global state.

use core::ffi::CStr;

/// Linux's ABI-visible scheduler clock tick rate.
///
/// On Linux/AArch64 this `USER_HZ` value is fixed at 100. `page_size` is not
/// exposed until crabc-rs has an explicit aux-vector initialization boundary:
/// hard-coding a page size would be wrong for valid 16 KiB and 64 KiB kernels.
#[inline]
#[must_use]
pub const fn clock_ticks_per_second() -> u64 { 100 }

const EMPTY_CSTR: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"\0") };

/// Returns the calling process's Linux page size from `AT_PAGESZ`.
///
/// The value is zero when the auxiliary vector is unavailable. Linux permits
/// 4 KiB, 16 KiB, and 64 KiB AArch64 pages, so this is intentionally queried
/// rather than hard-coded.
#[inline]
#[must_use]
pub fn page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap_or(0)
}

/// Returns the Linux `AT_HWCAP` and `AT_HWCAP2` values for this process.
///
/// Missing records are represented by zero, matching Rustix's Linux raw
/// backend and the kernel's `getauxval` convention.
#[inline]
#[must_use]
pub fn linux_hwcap() -> (usize, usize) {
    (
        crabc_core::param::auxv_value(crabc_core::param::AT_HWCAP).unwrap_or(0),
        crabc_core::param::auxv_value(crabc_core::param::AT_HWCAP2).unwrap_or(0),
    )
}

/// Returns Linux's `AT_MINSIGSTKSZ` value, or zero when unavailable.
#[inline]
#[must_use]
pub fn linux_minsigstksz() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_MINSIGSTKSZ).unwrap_or(0)
}

/// Returns the executable pathname recorded in Linux's `AT_EXECFN` entry.
///
/// The pointer is owned by the process's initial stack and remains valid for
/// the process lifetime. A missing entry returns an empty C string.
#[inline]
#[must_use]
pub fn linux_execfn() -> &'static CStr {
    let pointer = crabc_core::param::auxv_value(crabc_core::param::AT_EXECFN)
        .unwrap_or(0) as *const core::ffi::c_char;
    if pointer.is_null() {
        return EMPTY_CSTR;
    }
    // SAFETY: Linux's AT_EXECFN value is a pointer to a NUL-terminated
    // executable pathname in the process's initial stack. That stack remains
    // live for the process lifetime, which is represented by `'static` here.
    unsafe { CStr::from_ptr(pointer) }
}
