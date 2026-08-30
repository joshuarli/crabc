//! Selected static Linux/x86-64 C per-range memory-locking boundary.
//!
//! This leaf owns exactly C `mlock`, `munlock`, and GNU `mlock2`. It composes
//! only the raw Linux syscall-register boundary and the selected initial-TLS
//! C `errno` publisher. It is not whole-process `mlockall`/`munlockall`,
//! mapping synchronization (`msync`), `mremap`, a general virtual-memory
//! policy API, an allocator, a loader/CRT/TLS lifecycle, or public x86
//! support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/mman/mlock.c` maps to [`mlock`].
//! - `src/mman/munlock.c` maps to [`munlock`].
//! - `src/linux/mlock2.c` maps to [`mlock2`].
//!
//! Linux/x86-64 defines `SYS_mlock`, so musl's `mlock.c` takes the direct
//! two-word `mlock=149` path here. `munlock=150` is likewise direct. Musl's
//! GNU `mlock2` keeps one visible compatibility branch: zero flags delegate
//! to `mlock`, while nonzero flags enter `mlock2=325` unchanged. This is not
//! a policy validation layer: Linux owns range overflow, mapping validity,
//! memlock limits, and unsupported-flag `EINVAL` results. These direct musl
//! wrappers do not use its cancellation-point syscall path.

use core::ffi::{c_int, c_uint, c_void};

use super::{c_status, raw_syscall};

/// Lock one caller-owned virtual-memory range through Linux `mlock(2)`.
///
/// # Safety
///
/// `address` and `length` must satisfy the complete Linux range contract,
/// including mapping lifetime and concurrent mapping mutation. A successful
/// call changes the process's per-range lock state; the caller must arrange
/// the matching [`munlock`] or mapping teardown. The selected static archive
/// owns no whole-process lock policy or cancellation machinery.
#[no_mangle]
pub unsafe extern "C" fn mlock(address: *const c_void, length: usize) -> c_int {
    // SAFETY: the caller owns the complete Linux range and lock-accounting
    // contract; the raw wrapper only puts pointer and size in rdi/rsi.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_MLOCK,
            address as usize as i64,
            length as i64,
        )
    };
    c_status(result)
}

/// Unlock one caller-owned virtual-memory range through Linux `munlock(2)`.
///
/// # Safety
///
/// `address` and `length` must satisfy Linux's complete range contract. The
/// caller owns the matching lock state, mapping lifetime, aliases, and races;
/// this leaf does not provide broader VM synchronization.
#[no_mangle]
pub unsafe extern "C" fn munlock(address: *const c_void, length: usize) -> c_int {
    // SAFETY: the caller owns the complete Linux range and lock-accounting
    // contract; the raw wrapper only puts pointer and size in rdi/rsi.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_MUNLOCK,
            address as usize as i64,
            length as i64,
        )
    };
    c_status(result)
}

/// Lock one caller-owned range through GNU `mlock2(2)`.
///
/// # Safety
///
/// `address`, `length`, and `flags` must satisfy Linux's complete `mlock2`
/// contract. The selected evidence admits `MLOCK_ONFAULT=1` and Linux's
/// unsupported-flag rejection; any successful lock remains caller-owned and
/// must later be released with [`munlock`] or mapping teardown.
#[no_mangle]
pub unsafe extern "C" fn mlock2(
    address: *const c_void,
    length: usize,
    flags: c_uint,
) -> c_int {
    // Match musl src/linux/mlock2.c exactly: the zero-flags GNU spelling is
    // the selected mlock wrapper, not a separate raw mlock2 syscall.
    if flags == 0 {
        // SAFETY: `mlock2` has the same pointer/range caller obligation on
        // this branch as `mlock`.
        return unsafe { mlock(address, length) };
    }

    // SAFETY: the caller owns the complete Linux mlock2 range and flag
    // contract; Linux validates unsupported flags and mapping/range state.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_MLOCK2,
            address as usize as i64,
            length as i64,
            i64::from(flags),
        )
    };
    c_status(result)
}
