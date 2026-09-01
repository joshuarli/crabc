//! Bounded Linux/x86-64 iopl/ioperm C ABI boundary.
//!
//! This opt-in owner maps pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` (musl MIT) directly:
//!
//! - `src/linux/iopl.c::iopl` is one `syscall(SYS_iopl, level)` request.
//! - `src/linux/ioperm.c::ioperm` is one
//!   `syscall(SYS_ioperm, from, count, turn_on)` request.
//!
//! It intentionally contributes no policy, validation, port instruction, or
//! privilege fallback. The bounded native fixture calls only invalid arguments
//! that Linux rejects with `EINVAL` or, when its authority check comes first,
//! `EPERM`; it does not test or authorize successful permission changes or
//! port I/O.

use core::ffi::{c_int, c_ulong};

use super::{c_status, raw_syscall};

/// Request a Linux I/O privilege-level change for the calling task.
///
/// # Safety
///
/// A caller requesting a valid level must be authorized to change the calling
/// task's kernel I/O privilege state and must coordinate any successful state
/// change with all code that could issue port-I/O instructions. This wrapper
/// forwards the scalar unchanged; Linux owns validation and failure behavior.
#[no_mangle]
pub unsafe extern "C" fn iopl(level: c_int) -> c_int {
    // SAFETY: Linux/x86-64 syscall 172 consumes the C `int` level in rdi.
    // `c_status` translates only a reserved raw Linux error through the
    // selected calling thread's initial-TLS errno slot.
    let result = unsafe { raw_syscall::syscall1(raw_syscall::SYS_IOPL, i64::from(level)) };
    c_status(result)
}

/// Request a Linux I/O-port permission-range change for the calling task.
///
/// # Safety
///
/// A caller requesting a valid range must be authorized to change the calling
/// task's kernel permission bitmap and must coordinate the resulting state
/// with all code that could access the affected ports. `from`, `count`, and
/// `turn_on` are forwarded as raw Linux scalar words; Linux owns their
/// validation and failure behavior.
#[no_mangle]
pub unsafe extern "C" fn ioperm(from: c_ulong, count: c_ulong, turn_on: c_int) -> c_int {
    // SAFETY: Linux/x86-64 syscall 173 consumes unsigned-long from/count in
    // rdi/rsi and the C int turn_on word in rdx. Casting preserves each
    // machine-word bit pattern and `c_status` owns only raw-error translation.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_IOPERM,
            from as i64,
            count as i64,
            i64::from(turn_on),
        )
    };
    c_status(result)
}
