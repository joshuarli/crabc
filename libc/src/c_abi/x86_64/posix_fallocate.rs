//! Selected static Linux/x86-64 C `posix_fallocate(3)` boundary.
//!
//! This leaf owns only mode-zero descriptor range allocation. It forwards the
//! descriptor, literal zero mode, and signed `off_t` offset/length to Linux
//! `fallocate=285` in rdi/rsi/rdx/r10. Unlike ordinary C syscall wrappers,
//! POSIX `posix_fallocate` returns a positive error number directly and must
//! not write `errno`, including on success. It does not select Linux fallocate
//! flags, pathname allocation, fallback policy, durability, libc.so, CRT,
//! loader, sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/fcntl/posix_fallocate.c` maps to [`posix_fallocate`] and its direct
//!   `SYS_fallocate` request with literal mode zero.
//!
//! This bounded leaf intentionally uses the direct syscall rather than a
//! cancellation-point or filesystem fallback route; those wider runtime
//! contracts remain unselected.

use core::ffi::{c_int, c_long};

use super::raw_syscall;

const LINUX_ERRNO_MAX: i64 = 4_095;

/// Translate Linux's reserved raw-error range to POSIX's direct error return.
///
/// This deliberately does not publish through the selected C `errno` slot:
/// the POSIX function reports the positive error number to its caller.
#[inline]
fn posix_status(result: i64) -> c_int {
    if result < 0 && result >= -LINUX_ERRNO_MAX {
        result.wrapping_neg() as c_int
    } else {
        result as c_int
    }
}

/// Ensure a descriptor has storage allocated over one signed file range.
///
/// # Safety
///
/// `descriptor` must be an open descriptor for a file type accepted by Linux
/// `fallocate(2)`, or the caller deliberately requests its direct error
/// result. `offset` and `length` are passed as signed LP64 `off_t` values; the
/// caller owns descriptor lifetime, filesystem choice, allocation policy, and
/// any concurrent file-position or content effects. This leaf fixes Linux's
/// mode to zero and provides no pathname, flag, fallback, or durability
/// policy.
#[no_mangle]
pub unsafe extern "C" fn posix_fallocate(
    descriptor: c_int,
    offset: c_long,
    length: c_long,
) -> c_int {
    // SAFETY: the caller owns the descriptor and signed-range contract;
    // syscall4 places literal mode zero, offset, and length in rsi/rdx/r10.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_FALLOCATE,
            i64::from(descriptor),
            0,
            i64::from(offset),
            i64::from(length),
        )
    };
    posix_status(result)
}
