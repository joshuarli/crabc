//! Stateless Linux inotify operations.

use core::ffi::CStr;

use crate::{RawFd, Result};
use crate::syscall::{decode, syscall1, syscall2, syscall3, SYS_INOTIFY_ADD_WATCH, SYS_INOTIFY_INIT1, SYS_INOTIFY_RM_WATCH};

/// Creates one Linux inotify descriptor without using libc or TLS
/// `errno`.
#[inline]
pub fn init1(flags: u32) -> Result<RawFd> {
    // SAFETY: `inotify_init1` takes a scalar flag word and returns one
    // fresh descriptor on success; Linux validates the flags.
    decode(unsafe { syscall1(SYS_INOTIFY_INIT1, flags as usize) }).map(|fd| fd as RawFd)
}

/// Adds or updates an inotify watch for a live NUL-terminated pathname.
#[inline]
pub fn add_watch(fd: RawFd, path: &CStr, mask: u32) -> Result<i32> {
    // SAFETY: `path` supplies a readable NUL-terminated pathname for the
    // duration of the direct call; all remaining arguments are scalars.
    decode(unsafe {
        syscall3(
            SYS_INOTIFY_ADD_WATCH,
            fd as usize,
            path.as_ptr() as usize,
            mask as usize,
        )
    })
    .map(|watch| watch as i32)
}

/// Removes one inotify watch from an open descriptor.
#[inline]
pub fn rm_watch(fd: RawFd, watch: i32) -> Result<()> {
    // SAFETY: both arguments are immediate Linux scalar values.
    decode(unsafe { syscall2(SYS_INOTIFY_RM_WATCH, fd as usize, watch as usize) }).map(|_| ())
}
