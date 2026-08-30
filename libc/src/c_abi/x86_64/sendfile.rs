//! Selected static Linux/x86-64 C `sendfile(2)` boundary.
//!
//! This leaf owns only the direct four-word `sendfile` C entry point. It
//! forwards the output/input descriptors, optional signed `off_t` pointer,
//! and byte count to Linux `sendfile=40` in rdi/rsi/rdx/r10, translating the
//! raw byte-count result through the selected initial-TLS C `errno` boundary. It does not
//! select pathname opening, socket or splice behavior, descriptor ownership,
//! libc.so, CRT, loader, sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/linux/sendfile.c` maps to [`sendfile`] and its direct Linux
//!   `sendfile=40` request.
//!
//! This bounded leaf intentionally uses the direct syscall rather than musl's
//! cancellation-point machinery; the x86 pthread/cancellation lifecycle is
//! not selected by this artifact.

use core::ffi::{c_int, c_long};

use super::{c_ssize_status, raw_syscall};

/// Transfer up to `count` bytes from an input descriptor to an output
/// descriptor through Linux's direct `sendfile(2)` operation.
///
/// # Safety
///
/// `offset` must be null or point to an aligned, writable `off_t` (`c_long`)
/// for the duration of the call. The descriptors must satisfy Linux's
/// `sendfile(2)` input/output requirements, and `count` must be the intended
/// byte count. Linux validates descriptor and offset errors; this direct leaf
/// does not provide pathname, socket, splice, or cancellation semantics.
#[no_mangle]
pub unsafe extern "C" fn sendfile(
    output_descriptor: c_int,
    input_descriptor: c_int,
    offset: *mut c_long,
    count: usize,
) -> isize {
    // SAFETY: the caller supplies the optional offset pointer and descriptor
    // validity contracts; syscall4 places its fourth argument in r10.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_SENDFILE,
            i64::from(output_descriptor),
            i64::from(input_descriptor),
            offset as usize as i64,
            count as i64,
        )
    };
    c_ssize_status(result)
}
