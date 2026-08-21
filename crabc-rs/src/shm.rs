//! POSIX shared-memory names mapped to Linux `devtmpfs` objects.

use core::ffi::CStr;

use crate::fs::{self};
use crate::path::Arg;
use crate::{Errno, OwnedFd, Result};

pub use crate::fs::{Mode, OFlags};

/// Opens a POSIX shared-memory object.
///
/// The namespace mapping is intentionally the musl/Rustix Linux rule: all
/// leading slashes are ignored, the remaining name cannot be empty, `.`,
/// `..`, or contain `/`, and the kernel descriptor is always close-on-exec.
#[inline]
pub fn open<P: Arg>(name: P, flags: OFlags, mode: Mode) -> Result<OwnedFd> {
    name.into_with_c_str(|name| with_shm_path(name, |path| {
        fs::open(path, flags | OFlags::CLOEXEC, mode)
    }))
}

/// Unlinks a POSIX shared-memory object.
#[inline]
pub fn unlink<P: Arg>(name: P) -> Result<()> {
    name.into_with_c_str(|name| with_shm_path(name, |path| fs::unlink(path)))
}

#[inline]
fn with_shm_path<T, F>(name: &CStr, operation: F) -> Result<T>
where
    F: FnOnce(&CStr) -> Result<T>,
{
    let name = name.to_bytes();
    let first = name.iter().position(|byte| *byte != b'/').ok_or(Errno::INVAL)?;
    let name = &name[first..];
    if name.len() > 255 {
        return Err(Errno::NAMETOOLONG);
    }
    if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') {
        return Err(Errno::INVAL);
    }
    let mut path = [0_u8; 265];
    path[..9].copy_from_slice(b"/dev/shm/");
    path[9..9 + name.len()].copy_from_slice(name);
    // SAFETY: the fixed prefix and checked name contain no NUL; the all-zero
    // array keeps the next byte as the C string terminator.
    let path = unsafe { CStr::from_bytes_with_nul_unchecked(&path[..10 + name.len()]) };
    operation(path)
}
