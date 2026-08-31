//! Bounded Linux/x86-64 static process-personality boundary.
//!
//! This one-symbol leaf is the exact direct wrapper from pinned musl 1.2.6:
//! `src/linux/personality.c::personality` calls `syscall(SYS_personality,
//! persona)`. Linux treats the unsigned-long value `0xffffffffUL` as a
//! non-mutating query for the current task's execution personality; ordinary
//! successful calls return that prior personality rather than a zero status.
//!
//! The selected C ABI preserves musl's raw-result conversion for the reserved
//! Linux error range while keeping successful previous-personality values as a
//! signed C `int`. It owns no personality policy, executable transition,
//! capability, namespace, privilege, process identity/session, scheduler, or
//! runtime lifecycle surface.

use core::ffi::{c_int, c_ulong};

use super::{c_status, raw_syscall};

/// Query or request the calling task's Linux execution personality.
///
/// The caller supplies the complete Linux personality word. In particular,
/// `0xffffffffUL` queries without changing the calling task, while other
/// values may change Linux-owned execution semantics. This one-syscall C ABI
/// leaf adds no policy, validation, or process-wide coordination.
#[no_mangle]
pub unsafe extern "C" fn personality(persona: c_ulong) -> c_int {
    // SAFETY: the C unsigned-long personality word is Linux syscall 135's
    // single scalar argument in rdi. `c_status` publishes only a reserved raw
    // Linux error through the selected initial-TLS errno slot.
    let result = unsafe {
        raw_syscall::syscall1(raw_syscall::SYS_PERSONALITY, persona as i64)
    };
    c_status(result)
}
