//! Selected static Linux/x86-64 C mapping-synchronization boundary.
//!
//! This leaf owns exactly C `msync`. It composes only the raw Linux syscall
//! register boundary and the selected initial-TLS C `errno` publisher. It is
//! not a complete `<sys/mman.h>` implementation, a general VM runtime,
//! mapping policy, allocator, libc.so, CRT, loader, sysroot, or public x86
//! support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/mman/msync.c` maps to [`msync`].
//!
//! That source calls `syscall_cp(SYS_msync, ...)`; the corresponding x86-64
//! cancellation assembly is `src/thread/x86_64/syscall_cp.s`. This private
//! static archive deliberately has no cancellation state machine or
//! `__syscall_cp` boundary, so it selects only the no-cancellation direct
//! Linux `msync=26` path. That deliberate boundary is not pthread
//! cancellation or full musl `msync` parity. Linux retains ownership of flag,
//! address, range, mapping-lifetime, writeback, and invalidation behavior.
//! Linux 5.10 validates unknown/conflicting flags and page alignment before
//! its rounded zero-length success path; the paired fixture keeps those error
//! ordering rules explicit without selecting any broader mapping policy.
//! Its disposable mapping is private and anonymous, so it proves syscall
//! routing and visible validation only—not file-backed shared-map writeback,
//! invalidation effects, persistence, or durability.

use core::ffi::{c_int, c_void};

use super::{c_status, raw_syscall};

/// Synchronize one caller-owned mapping range through Linux `msync(2)`.
///
/// # Safety
///
/// `address`, `length`, and `flags` must satisfy the complete Linux `msync`
/// contract. The caller owns mapping lifetime, concurrent access, file-backed
/// writeback/invalidation semantics, and every persistence policy above the
/// kernel request. This selected static leaf does not provide pthread
/// cancellation, VM-wide synchronization, or a completion/durability policy.
#[no_mangle]
pub unsafe extern "C" fn msync(address: *mut c_void, length: usize, flags: c_int) -> c_int {
    // SAFETY: the caller owns the complete Linux mapping and synchronization
    // contract; x86 syscall arguments one through three are rdi/rsi/rdx.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_MSYNC,
            address as usize as i64,
            length as i64,
            i64::from(flags),
        )
    };
    c_status(result)
}
