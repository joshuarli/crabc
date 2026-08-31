//! Selected static Linux/x86-64 GNU C `splice(2)` boundary.
//!
//! This leaf owns only one direct descriptor-range transfer request. It
//! forwards input/output descriptors, optional caller-owned signed LP64
//! `off_t` pointers, length, and flags to Linux `splice=275` in
//! `rdi/rsi/rdx/r10/r8/r9`, translating the raw byte-count result through the
//! selected initial-TLS C `errno` boundary. It does not select pathname
//! opening, descriptor or pipe ownership, transfer fallback or general pipe
//! policy, `tee`/`vmsplice`/`sendfile`/`copy_file_range`, durability,
//! cancellation, libc.so, CRT, loader, sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/linux/splice.c` maps to [`splice`] and its direct Linux
//!   `splice=275` request.
//!
//! This bounded leaf intentionally uses musl's direct syscall path rather
//! than inventing a cancellation-point, fallback, or descriptor/pipe-policy
//! contract.

use core::ffi::{c_int, c_long};

use super::{c_ssize_status, raw_syscall};

/// Transfer up to `length` bytes between two Linux descriptors.
///
/// # Safety
///
/// `input_offset` and `output_offset` must be null or point to aligned,
/// writable signed LP64 `off_t` (`c_long`) values for the duration of the
/// call. The caller owns both descriptor lifetimes, endpoint types, blocking
/// state, transfer semantics, and every fallback, pipe, filesystem, and
/// durability policy. `flags` is forwarded without policy or preflight, so
/// the caller deliberately accepts Linux's direct result.
#[no_mangle]
pub unsafe extern "C" fn splice(
    input_descriptor: c_int,
    input_offset: *mut c_long,
    output_descriptor: c_int,
    output_offset: *mut c_long,
    length: usize,
    flags: u32,
) -> isize {
    // SAFETY: the caller owns optional offset pointers, descriptor lifetimes,
    // endpoint types, range, and flag contracts; syscall6 moves C arguments
    // four through six from rcx/r8/r9 to Linux r10/r8/r9.
    let result = unsafe {
        raw_syscall::syscall6(
            raw_syscall::SYS_SPLICE,
            i64::from(input_descriptor),
            input_offset as usize as i64,
            i64::from(output_descriptor),
            output_offset as usize as i64,
            length as i64,
            i64::from(flags),
        )
    };
    c_ssize_status(result)
}
