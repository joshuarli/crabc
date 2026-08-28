//! POSIX shared-memory names mapped to Linux `/dev/shm` objects.

use core::ffi::CStr;

#[cfg(feature = "alloc")]
use alloc::ffi::CString;
#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "std")]
use std::ffi::{OsStr, OsString};
#[cfg(feature = "std")]
use std::os::unix::ffi::OsStrExt;
#[cfg(feature = "std")]
use std::path::{Path, PathBuf};

use crate::fs;
use crate::{Errno, OwnedFd, Result};

pub use crate::fs::{Mode, OFlags};

/// A byte-oriented POSIX shared-memory name accepted by [`open`] and
/// [`unlink`].
///
/// Unlike the general pathname boundary, this domain-specific input boundary
/// removes all leading slashes before it needs temporary C-string storage.
/// Consequently no-allocation callers can pass every valid POSIX name,
/// including `/` followed by all 255 `NAME_MAX` bytes, without being limited
/// by the unrelated generic-path stack buffer. Implementations reject an
/// interior NUL before normalization and keep any temporary mapped pathname
/// live only for the supplied callback.
pub trait NameArg {
    /// Runs `operation` with the checked private `/dev/shm/<name>` pathname.
    fn into_with_shm_name<T, F>(self, operation: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>;
}

impl NameArg for &CStr {
    #[inline]
    fn into_with_shm_name<T, F>(self, operation: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_shm_bytes(self.to_bytes(), operation)
    }
}

impl NameArg for &[u8] {
    #[inline]
    fn into_with_shm_name<T, F>(self, operation: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_shm_bytes(self, operation)
    }
}

impl<const LENGTH: usize> NameArg for &[u8; LENGTH] {
    #[inline]
    fn into_with_shm_name<T, F>(self, operation: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_shm_bytes(self, operation)
    }
}

impl NameArg for &str {
    #[inline]
    fn into_with_shm_name<T, F>(self, operation: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_shm_bytes(self.as_bytes(), operation)
    }
}

#[cfg(feature = "alloc")]
impl NameArg for CString {
    #[inline]
    fn into_with_shm_name<T, F>(self, operation: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_shm_bytes(self.as_bytes(), operation)
    }
}

#[cfg(feature = "alloc")]
impl NameArg for &CString {
    #[inline]
    fn into_with_shm_name<T, F>(self, operation: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_shm_bytes(self.as_bytes(), operation)
    }
}

#[cfg(feature = "alloc")]
impl NameArg for String {
    #[inline]
    fn into_with_shm_name<T, F>(self, operation: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_shm_bytes(self.as_bytes(), operation)
    }
}

#[cfg(feature = "alloc")]
impl NameArg for &String {
    #[inline]
    fn into_with_shm_name<T, F>(self, operation: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_shm_bytes(self.as_bytes(), operation)
    }
}

#[cfg(feature = "std")]
impl NameArg for &OsStr {
    #[inline]
    fn into_with_shm_name<T, F>(self, operation: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_shm_bytes(self.as_bytes(), operation)
    }
}

#[cfg(feature = "std")]
impl NameArg for &OsString {
    #[inline]
    fn into_with_shm_name<T, F>(self, operation: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_shm_bytes(self.as_os_str().as_bytes(), operation)
    }
}

#[cfg(feature = "std")]
impl NameArg for OsString {
    #[inline]
    fn into_with_shm_name<T, F>(self, operation: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_shm_bytes(self.as_os_str().as_bytes(), operation)
    }
}

#[cfg(feature = "std")]
impl NameArg for &Path {
    #[inline]
    fn into_with_shm_name<T, F>(self, operation: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_shm_bytes(self.as_os_str().as_bytes(), operation)
    }
}

#[cfg(feature = "std")]
impl NameArg for &PathBuf {
    #[inline]
    fn into_with_shm_name<T, F>(self, operation: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_shm_bytes(self.as_os_str().as_bytes(), operation)
    }
}

#[cfg(all(feature = "std", target_arch = "x86_64"))]
impl NameArg for PathBuf {
    #[inline]
    fn into_with_shm_name<T, F>(self, operation: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_shm_bytes(self.as_os_str().as_bytes(), operation)
    }
}

/// Opens a POSIX shared-memory object.
///
/// All leading slashes are ignored, the remaining name cannot be empty, `.`,
/// `..`, or contain `/`, and the kernel descriptor is always close-on-exec.
///
/// This native boundary follows the existing AArch64/Rustix direct policy:
/// it adds only [`OFlags::CLOEXEC`] and otherwise passes the supplied Linux
/// status flags through to `openat(2)`. Pinned musl's C `shm_open` wrapper
/// additionally adds `O_NOFOLLOW|O_NONBLOCK`; that C-wrapper policy is
/// deliberately not inherited by this owned Rust descriptor API. Therefore a
/// final symlink is followed by default, while a caller that supplies
/// [`OFlags::NOFOLLOW`] receives Linux's direct `ELOOP` result.
#[inline]
pub fn open<P: NameArg>(name: P, flags: OFlags, mode: Mode) -> Result<OwnedFd> {
    name.into_with_shm_name(|path| fs::open(path, flags | OFlags::CLOEXEC, mode))
}

/// Unlinks a POSIX shared-memory object.
#[inline]
pub fn unlink<P: NameArg>(name: P) -> Result<()> {
    name.into_with_shm_name(|path| fs::unlink(path))
}

#[inline]
fn with_shm_bytes<T, F>(name: &[u8], operation: F) -> Result<T>
where
    F: FnOnce(&CStr) -> Result<T>,
{
    if name.contains(&0) {
        return Err(Errno::INVAL);
    }
    let first = name
        .iter()
        .position(|byte| *byte != b'/')
        .ok_or(Errno::INVAL)?;
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
