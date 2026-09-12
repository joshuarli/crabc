//! Linux/x86-64 `arch_prctl` C ABI boundary for owned products.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` (musl MIT) implements
//! `src/linux/arch_prctl.c::arch_prctl` as the direct
//! `syscall(SYS_arch_prctl, code, addr)` veneer with C `int` status/`errno`
//! conversion. Musl exports that ELF compatibility spelling without declaring
//! it in its pinned `<sys/prctl.h>`; the selected Linux syscall header remains
//! the factual public-header source for `SYS_arch_prctl = 158`.
//!
//! This leaf does not own TLS setup, segment-base policy, process startup, or
//! I/O permission policy. It forwards both scalar words unchanged and leaves
//! every operation-specific validation and state transition to Linux.

use core::ffi::{c_int, c_ulong};

use super::{c_status, raw_syscall};

/// Invoke Linux/x86-64 `arch_prctl` with the supplied operation and word.
///
/// # Safety
///
/// For read operations such as `ARCH_GET_FS` and `ARCH_GET_GS`, `addr` must
/// encode a valid writable `unsigned long *` for the whole kernel operation.
/// For base-setting operations, the caller must preserve the calling thread's
/// TLS and segment-base invariants: changing FS or GS can invalidate the C
/// runtime before this function returns. Other operation codes retain their
/// Linux-defined pointer, lifetime, privilege, and process-state obligations.
/// This wrapper performs no validation or recovery.
#[no_mangle]
pub unsafe extern "C" fn arch_prctl(code: c_int, addr: c_ulong) -> c_int {
    // SAFETY: Linux/x86-64 syscall 158 consumes the C int code in rdi and the
    // unsigned-long word in rsi. The unsafe C boundary documents the complete
    // operation-specific pointee and segment-base obligations; c_status owns
    // only reserved raw-error translation through the selected errno slot.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_ARCH_PRCTL,
            i64::from(code),
            addr as i64,
        )
    };
    c_status(result)
}
