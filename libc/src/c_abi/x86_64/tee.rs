//! Selected static Linux/x86-64 GNU C `tee(2)` boundary.
//!
//! This leaf owns only direct pipe-buffer duplication through the four-word
//! `tee` C entry point. It forwards the source descriptor, destination
//! descriptor, byte count, and flags to Linux `tee=276` in `rdi/rsi/rdx/r10`,
//! translating the raw byte-count result through the selected initial-TLS C
//! `errno` boundary. It does not select pipe creation or ownership, generic
//! descriptor policy, `splice`/`vmsplice`/`sendfile` transfer behavior,
//! libc.so, CRT, loader, sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/linux/tee.c` maps to [`tee`] and its direct Linux `tee=276`
//!   request.
//!
//! This bounded leaf intentionally uses the direct syscall rather than musl's
//! cancellation-point machinery; x86 pthread cancellation and general
//! descriptor/process policy are not selected by this artifact.

use core::ffi::c_int;

use super::{c_ssize_status, raw_syscall};

/// Duplicate up to `length` bytes from one pipe buffer to another pipe buffer.
///
/// # Safety
///
/// `source_descriptor` and `destination_descriptor` must be pipe endpoints
/// suitable for Linux `tee(2)`, `length` must be the intended byte count, and
/// `flags` must contain only Linux-supported `SPLICE_F_*` bits, unless the
/// caller deliberately requests Linux's error behavior. The caller owns pipe
/// lifetime, blocking, and sharing semantics; this direct leaf has no pipe
/// creation, cancellation, or general descriptor policy contract.
#[no_mangle]
pub unsafe extern "C" fn tee(
    source_descriptor: c_int,
    destination_descriptor: c_int,
    length: usize,
    flags: u32,
) -> isize {
    // SAFETY: the caller owns the raw pipe-descriptor and flags contract;
    // syscall4 moves the C ABI fourth argument from rcx to Linux's r10.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_TEE,
            i64::from(source_descriptor),
            i64::from(destination_descriptor),
            length as i64,
            i64::from(flags),
        )
    };
    c_ssize_status(result)
}
