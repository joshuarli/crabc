//! Stateless Linux mount operations.

use core::ffi::CStr;

use crate::Result;
use crate::syscall::{decode, syscall2, syscall5, SYS_MOUNT, SYS_UMOUNT2};

/// Mounts a filesystem with the Linux `mount` ABI.
#[inline]
pub fn mount(
    source: Option<&CStr>,
    target: &CStr,
    filesystem_type: Option<&CStr>,
    flags: u64,
    data: Option<&CStr>,
) -> Result<()> {
    // SAFETY: Every present C string is NUL-terminated and stays live for
    // the syscall. Linux owns interpretation of all mount-specific data.
    decode(unsafe {
        syscall5(
            SYS_MOUNT,
            source.map_or(0, |value| value.as_ptr() as usize),
            target.as_ptr() as usize,
            filesystem_type.map_or(0, |value| value.as_ptr() as usize),
            flags as usize,
            data.map_or(0, |value| value.as_ptr() as usize),
        )
    })
    .map(|_| ())
}

/// Mounts a filesystem from raw C-ABI pointers.
///
/// # Safety
///
/// Every non-null string pointer must be a readable NUL-terminated C
/// string for the call. `data` follows the filesystem-specific Linux
/// mount contract and may be null.
#[inline]
pub unsafe fn mount_raw(
    source: *const u8,
    target: *const u8,
    filesystem_type: *const u8,
    flags: u64,
    data: *const u8,
) -> Result<()> {
    // SAFETY: The caller owns all Linux mount pointer contracts.
    decode(unsafe {
        syscall5(
            SYS_MOUNT,
            source as usize,
            target as usize,
            filesystem_type as usize,
            flags as usize,
            data as usize,
        )
    })
    .map(|_| ())
}

/// Unmounts a filesystem with the Linux `umount2` ABI.
#[inline]
pub fn umount2(target: &CStr, flags: i32) -> Result<()> {
    // SAFETY: `target` supplies a stable NUL-terminated pathname.
    decode(unsafe { syscall2(SYS_UMOUNT2, target.as_ptr() as usize, flags as usize) })
        .map(|_| ())
}

/// Unmounts a filesystem from a raw C-ABI target pointer.
///
/// # Safety
///
/// `target` must be a readable NUL-terminated pathname, or may
/// deliberately be an invalid C ABI pointer for kernel validation.
#[inline]
pub unsafe fn umount2_raw(target: *const u8, flags: i32) -> Result<()> {
    // SAFETY: The caller supplies the pathname-pointer contract.
    decode(unsafe { syscall2(SYS_UMOUNT2, target as usize, flags as usize) }).map(|_| ())
}
