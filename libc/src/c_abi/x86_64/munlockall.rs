//! Selected static Linux/x86-64 C `munlockall` release boundary.
//!
//! This one-symbol private artifact is a source-faithful translation of pinned
//! musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
//! under musl's MIT license:
//!
//! - `src/mman/munlockall.c::munlockall` maps directly to [`munlockall`].
//!
//! Musl performs exactly `syscall(SYS_munlockall)`. Linux/x86-64 assigns that
//! zero-argument release request `munlockall=152`. This wrapper deliberately
//! imposes no lock-state tracking or policy: Linux owns the calling process's
//! whole-process lock state, while the shared C result translator preserves
//! musl's zero or `-1` plus errno convention.
//!
//! The focused static fixture runs in a disposable process and proves two
//! idempotent successful releases preserve stale errno. This module does not select `mlockall`,
//! per-range `mlock`/`munlock`/`mlock2`, mapping or allocator
//! policy, process lifecycle, pthread cancellation, signals, libc.so, CRT,
//! loader, sysroot, promotion, or public x86 support.

use core::ffi::c_int;

use super::{c_status, raw_syscall};

/// Release whole-process memory locks from the calling process.
///
/// Linux owns whether any lock state was present and the process-wide effect.
/// This direct C spelling preserves the kernel result rather than maintaining
/// a local lock-state model or selecting the complementary lock request.
#[no_mangle]
pub extern "C" fn munlockall() -> c_int {
    // SAFETY: Linux/x86-64 `munlockall=152` takes no argument registers. The
    // kernel owns the calling process's lock state; this wrapper only preserves
    // musl's direct syscall route and C errno translation.
    let result = unsafe { raw_syscall::syscall0(raw_syscall::SYS_MUNLOCKALL) };
    c_status(result)
}
