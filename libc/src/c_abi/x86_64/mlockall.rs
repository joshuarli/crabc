//! Selected static Linux/x86-64 C `mlockall` request boundary.
//!
//! This one-symbol private artifact is a source-faithful translation of pinned
//! musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
//! under musl's MIT license:
//!
//! - `src/mman/mlockall.c::mlockall` maps directly to [`mlockall`].
//!
//! Musl performs exactly `syscall(SYS_mlockall, flags)`. Linux/x86-64 assigns
//! that one-word request `mlockall=151`, with the C `int` argument in `rdi`.
//! This wrapper deliberately performs no flag validation: Linux owns the
//! `MCL_CURRENT`, `MCL_FUTURE`, optional kernel flag, capability, memlock-limit,
//! and process-wide lock-policy outcomes, while the shared C result translator
//! preserves musl's `-1` plus errno convention.
//!
//! The focused static fixture runs in a disposable process and uses a private
//! raw `munlockall=152` cleanup syscall only after a success. That cleanup is
//! fixture containment—not this module's C export; the separately recorded
//! `munlockall` artifact owns that public spelling. This module does not select
//! that separate implementation, per-range `mlock`/`munlock`/`mlock2`, mapping or allocator
//! policy, process lifecycle, pthread cancellation, signals, libc.so, CRT,
//! loader, sysroot, promotion, or public x86 support.

use core::ffi::c_int;

use super::{c_status, raw_syscall};

/// Request Linux whole-process memory locking with the caller's flag word.
///
/// The process-wide lock state and any successful unlock are the caller's
/// responsibility. This direct C spelling preserves Linux validation and
/// resource-policy results rather than imposing a local flag vocabulary.
#[no_mangle]
pub extern "C" fn mlockall(flags: c_int) -> c_int {
    // SAFETY: Linux/x86-64 `mlockall=151` takes the C `int` flag word in rdi.
    // The kernel owns complete flag validation and the calling process's lock
    // policy; this wrapper only preserves musl's direct syscall route.
    let result = unsafe {
        raw_syscall::syscall1(raw_syscall::SYS_MLOCKALL, i64::from(flags))
    };
    c_status(result)
}
