//! Unix path arguments without mandatory UTF-8 or heap allocation.
//!
//! [`Arg`] is the small boundary used by filesystem operations. Inputs which
//! are already C strings are borrowed directly. Byte, string, and Unix
//! `OsStr`/`Path` inputs use a bounded stack buffer when they fit; an alloc
//! build uses an owned `CString` for longer inputs, while a no-alloc build
//! returns `ENAMETOOLONG` instead of growing an unbounded temporary.

use core::ffi::CStr;
use core::mem::MaybeUninit;
use core::{ptr, slice};

use crate::{Errno, Result};

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

/// The largest path which can be passed through the fixed stack buffer.
///
/// One byte is reserved for the terminating NUL. This deliberately bounds
/// stack use in `--no-default-features` builds; the kernel remains responsible
/// for enforcing its own path length limits in alloc-enabled builds.
pub const SMALL_PATH_BUFFER_SIZE: usize = 256;

#[inline]
const fn invalid_input() -> Errno {
    Errno::INVAL
}

#[inline]
#[cfg(not(feature = "alloc"))]
const fn name_too_long() -> Errno {
    Errno::NAMETOOLONG
}

/// A path-like value accepted by filesystem operations.
pub trait Arg {
    /// Runs `f` with this value represented as a borrowed NUL-terminated C
    /// string. The temporary, when one is needed, remains alive for `f`.
    fn into_with_c_str<T, F>(self, f: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>;
}

/// Runs `f` with an optional path argument.
#[inline]
pub fn option_into_with_c_str<T, F, P>(path: Option<P>, f: F) -> Result<T>
where
    P: Arg,
    F: FnOnce(Option<&CStr>) -> Result<T>,
{
    match path {
        Some(path) => path.into_with_c_str(|path| f(Some(path))),
        None => f(None),
    }
}

/// Converts a byte-oriented path to a temporary C string without exceeding
/// the fixed no-alloc stack bound.
#[inline]
fn with_bytes<T, F>(bytes: &[u8], f: F) -> Result<T>
where
    F: FnOnce(&CStr) -> Result<T>,
{
    if bytes.iter().any(|&byte| byte == 0) {
        return Err(invalid_input());
    }

    if bytes.len() >= SMALL_PATH_BUFFER_SIZE {
        #[cfg(feature = "alloc")]
        {
            let path = CString::new(bytes).map_err(|_| invalid_input())?;
            return f(path.as_c_str());
        }

        #[cfg(not(feature = "alloc"))]
        {
            return Err(name_too_long());
        }
    }

    let mut buffer = [MaybeUninit::<u8>::uninit(); SMALL_PATH_BUFFER_SIZE];
    // SAFETY: `bytes.len() < SMALL_PATH_BUFFER_SIZE`, so the copy and trailing
    // NUL write fit in `buffer`. The input was checked for interior NUL above.
    unsafe {
        let destination = buffer.as_mut_ptr().cast::<u8>();
        ptr::copy_nonoverlapping(bytes.as_ptr(), destination, bytes.len());
        destination.add(bytes.len()).write(0);
        let bytes_with_nul = slice::from_raw_parts(destination, bytes.len() + 1);
        let path = CStr::from_bytes_with_nul_unchecked(bytes_with_nul);
        f(path)
    }
}

impl Arg for &CStr {
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        f(self)
    }
}

impl Arg for &[u8] {
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_bytes(self, f)
    }
}

impl Arg for &str {
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_bytes(self.as_bytes(), f)
    }
}

#[cfg(feature = "alloc")]
impl Arg for CString {
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        f(self.as_c_str())
    }
}

#[cfg(feature = "alloc")]
impl Arg for &CString {
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        f(self.as_c_str())
    }
}

#[cfg(feature = "alloc")]
impl Arg for String {
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_bytes(self.as_bytes(), f)
    }
}

#[cfg(feature = "alloc")]
impl Arg for &String {
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_bytes(self.as_bytes(), f)
    }
}

#[cfg(feature = "std")]
impl Arg for &OsStr {
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_bytes(self.as_bytes(), f)
    }
}

#[cfg(feature = "std")]
impl Arg for &OsString {
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_bytes(self.as_os_str().as_bytes(), f)
    }
}

#[cfg(feature = "std")]
impl Arg for OsString {
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_bytes(self.as_os_str().as_bytes(), f)
    }
}

#[cfg(feature = "std")]
impl Arg for &Path {
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_bytes(self.as_os_str().as_bytes(), f)
    }
}

#[cfg(feature = "std")]
impl Arg for &PathBuf {
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_bytes(self.as_os_str().as_bytes(), f)
    }
}

#[cfg(feature = "std")]
impl Arg for PathBuf {
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        with_bytes(self.as_os_str().as_bytes(), f)
    }
}

#[cfg(test)]
mod tests {
    use super::Arg;
    #[cfg(not(feature = "alloc"))]
    use super::SMALL_PATH_BUFFER_SIZE;

    #[test]
    fn bytes_preserve_non_utf8_without_allocation() {
        let bytes = [b'/', 0xff, b'\0'];
        let result = (&bytes[..bytes.len() - 1]).into_with_c_str(|path| {
            Ok((path.to_bytes().len(), path.to_bytes()[1]))
        });

        assert_eq!(result.unwrap(), (2, 0xff));
    }

    #[test]
    fn interior_nul_is_invalid() {
        let result = (&b"a\0b"[..]).into_with_c_str(|_| Ok(()));

        assert_eq!(result.unwrap_err().raw(), 22);
    }

    #[cfg(feature = "std")]
    #[test]
    fn unix_os_str_preserves_non_utf8_bytes() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let os_str = OsStr::from_bytes(b"/\xff");
        let result = os_str.into_with_c_str(|path| Ok(path.to_bytes().to_vec()));

        assert_eq!(result.unwrap(), b"/\xff");
    }

    #[cfg(not(feature = "alloc"))]
    #[test]
    fn no_alloc_paths_are_bounded() {
        let bytes = [b'a'; SMALL_PATH_BUFFER_SIZE];
        let result = bytes.as_slice().into_with_c_str(|_| Ok(()));

        assert_eq!(result.unwrap_err().raw(), 36);
    }
}
