//! Process parameters whose values require no libc-global state.

#[cfg(target_arch = "aarch64")]
use core::ffi::CStr;

/// Linux's ABI-visible scheduler clock tick rate.
///
/// On the staged Linux targets this `USER_HZ` value is fixed at 100. The
/// separately exposed [`page_size`] reads the process auxiliary vector rather
/// than assuming a target-wide page size.
#[inline]
#[must_use]
pub const fn clock_ticks_per_second() -> u64 {
    100
}

#[cfg(target_arch = "aarch64")]
const EMPTY_CSTR: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"\0") };

/// Returns the calling process's Linux page size from `AT_PAGESZ`.
///
/// The value is zero when the auxiliary vector is unavailable. It is queried
/// rather than hard-coded because page size is a target kernel property.
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
///
/// This accessor is not admitted in the staged x86 facade: an auxv word read
/// from `/proc/self/auxv` alone does not prove pointer provenance, mapping, or
/// NUL bounds. A future x86 startup-state owner must establish that contract
/// before exposing a safe executable-path reference.
#[cfg(target_arch = "aarch64")]
#[inline]
#[must_use]
pub fn linux_execfn() -> &'static CStr {
    let pointer = crabc_core::param::auxv_value(crabc_core::param::AT_EXECFN).unwrap_or(0)
        as *const core::ffi::c_char;
    if pointer.is_null() {
        return EMPTY_CSTR;
    }
    // SAFETY: Linux's AT_EXECFN value is a pointer to a NUL-terminated
    // executable pathname in the process's initial stack. That stack remains
    // live for the process lifetime, which is represented by `'static` here.
    unsafe { CStr::from_ptr(pointer) }
}
