//! Selected static Linux/x86-64 C descriptor-advice boundaries.
//!
//! This leaf owns only `posix_fadvise(3)` and GNU `readahead(2)` over an
//! already-open descriptor. `posix_fadvise` forwards its descriptor, signed
//! `off_t` range, and advice word to Linux `fadvise64=221` in
//! rdi/rsi/rdx/r10, then returns a positive POSIX error number without writing
//! `errno`. `readahead` forwards its descriptor, signed `off_t` offset, and
//! `size_t` count to Linux `readahead=187` in rdi/rsi/rdx, using ordinary C
//! `ssize_t`/`errno` translation. Neither operation changes the descriptor's
//! file position. This leaf does not select allocation, caching policy,
//! pathname behavior, durability, cancellation, libc.so, CRT, loader,
//! sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/fcntl/posix_fadvise.c` maps to [`posix_fadvise`] and its direct
//!   positive-error `SYS_fadvise64` request.
//! - `src/linux/readahead.c` maps to [`readahead`] and its ordinary direct
//!   `SYS_readahead` syscall-result conversion.
//!
//! The two APIs share descriptor-advice scope but retain their deliberately
//! different POSIX and GNU error-reporting contracts.

use core::ffi::{c_int, c_long};

use super::{c_ssize_status, raw_syscall};

const LINUX_ERRNO_MAX: i64 = 4_095;

/// Translate Linux's raw error range to POSIX's direct error return.
///
/// `posix_fadvise` reports errors directly and therefore never publishes to
/// the selected C `errno` slot, including on success.
#[inline]
fn posix_status(result: i64) -> c_int {
    if result < 0 && result >= -LINUX_ERRNO_MAX {
        result.wrapping_neg() as c_int
    } else {
        result as c_int
    }
}

/// Give Linux one POSIX access-pattern advisory over an open descriptor.
///
/// # Safety
///
/// `descriptor` must be open for a file type accepted by Linux
/// `fadvise64(2)`, or the caller deliberately requests its direct error
/// result. `offset` and `length` are passed unchanged as signed LP64 `off_t`
/// words; `advice` is passed unchanged for Linux validation. The caller owns
/// descriptor lifetime and all caching-policy consequences.
#[no_mangle]
pub unsafe extern "C" fn posix_fadvise(
    descriptor: c_int,
    offset: c_long,
    length: c_long,
    advice: c_int,
) -> c_int {
    // SAFETY: the caller owns the descriptor, signed-range, and advice-word
    // contracts; syscall4 places the fourth Linux argument in r10.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_FADVISE64,
            i64::from(descriptor),
            i64::from(offset),
            i64::from(length),
            i64::from(advice),
        )
    };
    posix_status(result)
}

/// Request Linux readahead for one descriptor range.
///
/// # Safety
///
/// `descriptor` must be open for a file type accepted by Linux
/// `readahead(2)`, or the caller deliberately requests its ordinary C error
/// result. `offset` is passed unchanged as signed LP64 `off_t`, and `count`
/// is passed unchanged as `size_t`; the caller owns descriptor lifetime and
/// the advisory caching consequences.
#[no_mangle]
pub unsafe extern "C" fn readahead(
    descriptor: c_int,
    offset: c_long,
    count: usize,
) -> isize {
    // SAFETY: the caller owns the descriptor and scalar range contracts;
    // Linux x86-64 receives readahead=187 in rdi/rsi/rdx.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_READAHEAD,
            i64::from(descriptor),
            i64::from(offset),
            count as i64,
        )
    };
    c_ssize_status(result)
}
