//! Selected static Linux/x86-64 C random-entropy boundary.
//!
//! This leaf owns exactly two direct, allocation-free C entropy entries:
//! `getrandom` and `getentropy`. It composes only Linux's x86-64 `getrandom`
//! syscall register ABI and the selected initial-TLS C `errno` writer. It is
//! not a PRNG or cryptographic algorithm, random state, an allocator,
//! filesystem-randomness helper, libc.so, CRT, pthread/TLS lifecycle, dynamic
//! TLS, loader, sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/linux/getrandom.c` maps to the direct three-word Linux wrapper
//!   below.
//! - `src/misc/getentropy.c` maps to the BSD-compatible 256-byte cap, repeated
//!   `getrandom(..., 0)` calls, and `EINTR` retry loop below.
//!
//! Musl makes `getrandom` a cancellation point through `syscall_cp`, and
//! `getentropy` temporarily disables cancellation through
//! `pthread_setcancelstate`. This selected static leaf deliberately emits the
//! direct Linux syscall instead: the x86 pthread/cancellation lifecycle is not
//! yet selected. The remaining musl-visible success, partial-read, `EINTR`,
//! `EIO`, and `errno` behavior is kept at this boundary. Linux 5.10 is the
//! project baseline, so there is no pre-`getrandom` fallback.

use core::ffi::{c_int, c_uint, c_void};

use super::{c_ssize_status, errno, raw_syscall};

const EINTR: c_int = 4;
const EIO: c_int = 5;
const GETENTROPY_MAX_BYTES: usize = 256;

/// Fill up to `length` caller-owned bytes from Linux's entropy source.
///
/// # Safety
///
/// If Linux examines the buffer, `buffer` must designate `length` writable
/// bytes for the syscall's duration. A null buffer is valid only with zero
/// length. The kernel validates `flags`; this direct static leaf does not
/// supply musl's pthread cancellation-point behavior.
#[no_mangle]
pub unsafe extern "C" fn getrandom(
    buffer: *mut c_void,
    length: usize,
    flags: c_uint,
) -> isize {
    // SAFETY: the caller supplies the complete Linux output-buffer contract;
    // the kernel validates the random-source flags and publishes raw errors.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_GETRANDOM,
            buffer as usize as i64,
            length as i64,
            i64::from(flags),
        )
    };
    c_ssize_status(result)
}

/// Fill exactly `length` bytes through the BSD-compatible entropy contract.
///
/// # Safety
///
/// If `length` is nonzero, `buffer` must designate that many writable bytes
/// for every retry. A null buffer is valid only with zero length. Requests
/// larger than 256 bytes fail with `-1` and `errno = EIO` before Linux observes
/// the pointer; this leaf otherwise retains musl's direct partial-fill/retry
/// behavior while deliberately omitting its pthread cancellation suppression.
#[no_mangle]
pub unsafe extern "C" fn getentropy(buffer: *mut c_void, length: usize) -> c_int {
    if length > GETENTROPY_MAX_BYTES {
        // SAFETY: this selected C ABI owns the calling initial-TLS errno slot.
        unsafe { errno::set_errno(EIO) };
        return -1;
    }

    let mut remaining = length;
    let mut cursor = buffer.cast::<u8>();
    while remaining != 0 {
        // SAFETY: `cursor` begins at the caller's writable range and advances
        // only by a successful initialized prefix from the preceding call.
        let result = unsafe { getrandom(cursor.cast(), remaining, 0) };
        if result < 0 {
            // SAFETY: `getrandom` just translated this raw Linux result into
            // the selected initial-TLS C errno slot.
            if unsafe { errno::get_errno() } == EINTR {
                continue;
            }
            return -1;
        }

        let written = result as usize;
        // Linux's nonzero-length getrandom success contract supplies a
        // positive initialized prefix. Retain musl's retry loop if a future
        // kernel nevertheless reports a zero-byte success.
        if written == 0 {
            continue;
        }
        // SAFETY: `written <= remaining` is the Linux successful byte-count
        // contract; the caller's original writable range covers this suffix.
        cursor = unsafe { cursor.add(written) };
        remaining -= written;
    }
    0
}
