//! Selected static Linux/x86-64 C `clock_gettime` boundary.
//!
//! This leaf owns only the ordinary C clock-observation result and errno
//! boundary. It translates Linux's raw `-errno` result through the selected
//! initial-TLS errno slot, returning zero on success and `-1` on failure.
//! It intentionally uses the direct Linux syscall rather than importing a
//! vDSO resolver or any dynamic runtime state.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/time/clock_gettime.c` maps to [`clock_gettime`] below. Musl may use
//! its internal vDSO route before falling back to the kernel. This bounded
//! static leaf records the intentional direct-syscall difference until a C
//! runtime owns that resolver and its process-lifetime state.
//!
//! This does not select `clock_getres`, `clock_settime`, `time`, POSIX timers,
//! calendar/time-zone state, pthread cancellation, libc.so, CRT, dynamic TLS,
//! loader, sysroot, or public x86 support.

use core::ffi::{c_int, c_void};

use super::{c_status, raw_syscall};

/// Read one Linux clock through the ordinary POSIX C result convention.
///
/// A successful query returns zero and preserves the caller's errno. Linux
/// errors return `-1` after publication in the calling initial-TLS errno slot.
///
/// # Safety
///
/// `output` must point to writable 16-byte, align-eight x86-64 `struct
/// timespec` storage for the syscall duration. A null or invalid output
/// pointer is outside this selected static-artifact contract: musl may route
/// valid clocks through vDSO code before a kernel syscall would report EFAULT.
/// The caller owns the clock identifier's meaning and the output record
/// lifetime.
#[no_mangle]
pub unsafe extern "C" fn clock_gettime(clock_id: c_int, output: *mut c_void) -> c_int {
    // SAFETY: the caller owns the raw Linux clock ID and output-pointer
    // contract. Linux/x86-64 receives these two words in rdi/rsi.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_CLOCK_GETTIME,
            i64::from(clock_id),
            output as usize as i64,
        )
    };
    c_status(result)
}
