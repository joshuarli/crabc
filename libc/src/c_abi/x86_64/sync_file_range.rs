//! Selected static Linux/x86-64 GNU C `sync_file_range(2)` boundary.
//!
//! This leaf owns only one direct descriptor-range writeback request. It
//! forwards the descriptor, signed LP64 `off_t` offset/length, and unsigned
//! flags to Linux `sync_file_range=277` in `rdi/rsi/rdx/r10`, translating the
//! raw status through the selected initial-TLS C `errno` boundary. It does
//! not select pathname opening, file ownership, cache or writeback policy,
//! media-cache durability, `sync`/`syncfs`, cancellation, libc.so, CRT,
//! loader, sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/linux/sync_file_range.c` maps to [`sync_file_range`] and its direct
//!   Linux `sync_file_range=277` request.
//!
//! This bounded leaf intentionally uses musl's direct syscall path rather
//! than inventing a cancellation-point, storage-policy, or fallback contract.

use core::ffi::{c_int, c_long};

use super::{c_status, raw_syscall};

/// Request Linux writeback synchronization for one descriptor byte range.
///
/// # Safety
///
/// `descriptor` must be open for a file type accepted by Linux
/// `sync_file_range(2)`, and `offset`/`length` are signed LP64 `off_t` values.
/// `flags` must contain only Linux-supported `SYNC_FILE_RANGE_*` bits unless
/// the caller deliberately requests Linux's direct error result. The caller
/// owns descriptor lifetime, filesystem selection, concurrent data changes,
/// and every cache/durability policy; this leaf has no pathname, fallback, or
/// cancellation contract.
#[no_mangle]
pub unsafe extern "C" fn sync_file_range(
    descriptor: c_int,
    offset: c_long,
    length: c_long,
    flags: u32,
) -> c_int {
    // SAFETY: the caller owns the descriptor, signed-range, and flag contract;
    // syscall4 moves the C ABI fourth argument from rcx to Linux's r10.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_SYNC_FILE_RANGE,
            i64::from(descriptor),
            i64::from(offset),
            i64::from(length),
            i64::from(flags),
        )
    };
    c_status(result)
}
