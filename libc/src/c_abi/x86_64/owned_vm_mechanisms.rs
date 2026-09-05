//! Owned Linux/x86-64 virtual-memory mechanism boundaries.
//!
//! This module is a source-specific semantic port of pinned musl 1.2.6
//! release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's
//! MIT license recorded in `COPYRIGHT`. Its source-to-entry mapping is:
//!
//! - `src/mman/mremap.c` maps to hidden [`__mremap`] plus its weak public
//!   `mremap` alias;
//! - `src/linux/brk.c` maps to [`brk`];
//! - `src/linux/sbrk.c` maps to [`sbrk`]; and
//! - `src/linux/remap_file_pages.c` maps to [`remap_file_pages`].
//!
//! The owned runtime selects this small Linux mechanism slice because its
//! application CRT and worker retirement rules own the relevant runtime
//! lifetime boundary. Worker retirement waits for `CLONE_CHILD_CLEARTID`,
//! withdraws the worker registry record, and drains selected signal and
//! cancellation leases before its private mapping can be reclaimed. The
//! existing source-ported [`super::pthread_vmlock`] record guards public
//! process-shared barrier and robust-mutex transitions that still retain a
//! caller-owned pointer. `mremap(MREMAP_FIXED)` joins that same record before
//! Linux replaces an address range. Application mappings, aliases, and every
//! application-side concurrent access remain the caller's responsibility.
//!
//! Linux 5.10 owns all successful remap topology, including
//! `MREMAP_MAYMOVE` and `MREMAP_DONTUNMAP`; this wrapper adds no fallback or
//! policy validation. Pinned musl deliberately makes `brk` and nonzero
//! `sbrk` fail with `ENOMEM`, while `sbrk(0)` asks Linux for the current break.
//! `remap_file_pages` remains its direct legacy Linux syscall boundary.

use core::ffi::{c_int, c_void};

use super::{c_pointer_status, c_status, errno, pthread_vmlock, raw_syscall};

const ENOMEM: c_int = 12;
const MREMAP_FIXED: c_int = 2;

// The source body is `__mremap`; its public spelling remains a same-address
// weak alias. Internal source calls therefore bind the hidden provider even
// if an application interposes the public name.
core::arch::global_asm!(
    ".hidden __mremap",
    ".weak mremap",
    ".set mremap, __mremap",
);

/// Remap a caller-owned Linux mapping, preserving musl's variadic ABI.
///
/// Pinned musl rejects a new length at or above `PTRDIFF_MAX` before entering
/// Linux. It reads the fifth C argument only when `MREMAP_FIXED` is set and
/// otherwise passes a null fifth syscall word. A fixed replacement first
/// waits for the selected musl-compatible VM lifetime guard.
///
/// # Safety
///
/// The caller must satisfy Linux's complete `mremap(2)` contract for the old
/// mapping, sizes, flags, and any destination address. It must provide one
/// fifth `void *` variadic argument exactly when `flags` includes
/// `MREMAP_FIXED`; no such argument may be assumed for another flag set.
/// After success, the caller must treat the old and destination ranges with
/// Linux's resulting lifetime rules (including the distinct
/// `MREMAP_DONTUNMAP` retained-old-range rule) and synchronize all aliases
/// and concurrent access.
#[no_mangle]
pub unsafe extern "C" fn __mremap(
    old_address: *mut c_void,
    old_size: usize,
    new_size: usize,
    flags: c_int,
    mut args: ...,
) -> *mut c_void {
    if new_size >= isize::MAX as usize {
        // SAFETY: this is the selected calling thread's C errno slot.
        unsafe { errno::set_errno(ENOMEM) };
        return usize::MAX as *mut c_void;
    }

    let new_address = if flags & MREMAP_FIXED != 0 {
        // SAFETY: the caller's fixed-address variadic contract above provides
        // one `void *` word, and musl waits before consuming and forwarding it.
        unsafe { pthread_vmlock::wait() };
        // SAFETY: `MREMAP_FIXED` requires the fifth C argument.
        unsafe { args.next_arg::<*mut c_void>() }
    } else {
        core::ptr::null_mut()
    };

    // SAFETY: the caller owns the complete Linux remap request. `syscall5`
    // places the optional destination in the x86-64 fifth syscall register.
    let result = unsafe {
        raw_syscall::syscall5(
            raw_syscall::SYS_MREMAP,
            old_address as usize as i64,
            old_size as i64,
            new_size as i64,
            i64::from(flags),
            new_address as usize as i64,
        )
    };
    c_pointer_status(result)
}

/// Reject an application break transition with musl's fixed `ENOMEM` result.
///
/// Pinned musl does not let this libc change the process break. The ignored
/// `end` pointer remains part of the installed C ABI signature.
#[no_mangle]
pub extern "C" fn brk(_end: *mut c_void) -> c_int {
    // SAFETY: this is the selected calling thread's C errno slot.
    unsafe { errno::set_errno(ENOMEM) };
    -1
}

/// Return the current Linux program break for zero increment only.
///
/// Pinned musl makes every nonzero increment fail with `ENOMEM`; it does not
/// request a break change from Linux. `sbrk(0)` leaves `errno` untouched and
/// returns Linux's raw current-break word.
#[no_mangle]
pub extern "C" fn sbrk(increment: isize) -> *mut c_void {
    if increment != 0 {
        // SAFETY: this is the selected calling thread's C errno slot.
        unsafe { errno::set_errno(ENOMEM) };
        return usize::MAX as *mut c_void;
    }

    // SAFETY: Linux `brk(0)` has one zero word and returns the current break.
    // Musl deliberately passes that raw word through rather than applying C
    // errno translation.
    let result = unsafe { raw_syscall::syscall1(raw_syscall::SYS_BRK, 0) };
    result as usize as *mut c_void
}

/// Forward one legacy Linux `remap_file_pages(2)` request.
///
/// # Safety
///
/// The caller must satisfy Linux's complete address, size, protection,
/// offset, flags, mapping-lifetime, and concurrent-access contract. This
/// direct compatibility entry preserves Linux's result and `errno` behavior;
/// it does not emulate the obsolete syscall when the kernel rejects it.
#[no_mangle]
pub unsafe extern "C" fn remap_file_pages(
    address: *mut c_void,
    size: usize,
    protection: c_int,
    page_offset: usize,
    flags: c_int,
) -> c_int {
    // SAFETY: the caller owns the complete legacy Linux remap request.
    let result = unsafe {
        raw_syscall::syscall5(
            raw_syscall::SYS_REMAP_FILE_PAGES,
            address as usize as i64,
            size as i64,
            i64::from(protection),
            page_offset as i64,
            i64::from(flags),
        )
    };
    c_status(result)
}
