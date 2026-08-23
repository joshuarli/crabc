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

/// A borrowed byte-oriented result of Unix `basename`/`dirname` processing.
///
/// The result never allocates or requires UTF-8. Unlike the C `libgen.h`
/// functions, it does not mutate the caller's path; this makes the native
/// operation safe to use concurrently and keeps the returned part tied to the
/// source path's lifetime.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PathPart<'a> {
    bytes: &'a [u8],
}

/// Errors raised when a raw byte path cannot be represented as a NUL-free
/// pathname payload.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PathError {
    /// The path contains a byte which would terminate a C pathname.
    InteriorNul { index: usize },
}

impl<'a> PathPart<'a> {
    /// Validates and borrows a NUL-free Unix pathname payload.
    pub fn new(path: &'a [u8]) -> core::result::Result<Self, PathError> {
        if let Some(index) = path.iter().position(|&byte| byte == 0) {
            return Err(PathError::InteriorNul { index });
        }
        Ok(Self { bytes: path })
    }

    /// Borrows the payload of an already validated C string.
    #[must_use]
    pub fn from_cstr(path: &'a CStr) -> Self {
        Self {
            bytes: path.to_bytes(),
        }
    }

    /// Computes the final non-slash path component using musl's basename
    /// policy from a C string. Empty input yields `.`; an all-slash path
    /// yields `/`.
    #[must_use]
    pub fn basename(path: &'a CStr) -> Self {
        Self {
            bytes: basename_component(path.to_bytes()),
        }
    }

    /// Computes the directory prefix using musl's dirname policy. Empty
    /// input and a path without a slash yield `.`; slash-only paths yield `/`.
    #[must_use]
    pub fn dirname(path: &'a CStr) -> Self {
        Self {
            bytes: dirname_component(path.to_bytes()),
        }
    }

    /// Returns the borrowed result bytes.
    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the result as a byte string without UTF-8 conversion.
    #[must_use]
    pub const fn as_ref_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns whether the part is the current-directory spelling `.`.
    #[must_use]
    pub fn is_current(self) -> bool {
        self.bytes == b"."
    }

    /// Returns whether the part is the root spelling `/`.
    #[must_use]
    pub fn is_root(self) -> bool {
        self.bytes == b"/"
    }
}

impl AsRef<[u8]> for PathPart<'_> {
    fn as_ref(&self) -> &[u8] {
        self.bytes
    }
}

impl core::ops::Deref for PathPart<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.bytes
    }
}

#[inline]
fn basename_component(path: &[u8]) -> &[u8] {
    if path.is_empty() {
        return b".";
    }
    let mut end = path.len();
    while end > 1 && path[end - 1] == b'/' {
        end -= 1;
    }
    if end == 1 && path[0] == b'/' {
        return &path[..1];
    }
    let mut start = end;
    while start > 0 && path[start - 1] != b'/' {
        start -= 1;
    }
    &path[start..end]
}

#[inline]
fn dirname_component(path: &[u8]) -> &[u8] {
    if path.is_empty() {
        return b".";
    }
    let mut end = path.len();
    while end > 1 && path[end - 1] == b'/' {
        end -= 1;
    }
    if end == 1 && path[0] == b'/' {
        return &path[..1];
    }

    let mut slash = end;
    while slash > 0 && path[slash - 1] != b'/' {
        slash -= 1;
    }
    if slash == 0 {
        return b".";
    }
    let mut directory_end = slash;
    while directory_end > 1 && path[directory_end - 1] == b'/' {
        directory_end -= 1;
    }
    if directory_end == 0 {
        &path[..1]
    } else {
        &path[..directory_end]
    }
}

/// Computes a borrowed basename result from a NUL-terminated path.
#[must_use]
pub fn basename(path: &CStr) -> PathPart<'_> {
    PathPart::basename(path)
}

/// Validates a byte path and computes a borrowed basename without allocation
/// or mutation.
pub fn basename_bytes(path: &[u8]) -> core::result::Result<PathPart<'_>, PathError> {
    let part = PathPart::new(path)?;
    Ok(PathPart {
        bytes: basename_component(part.bytes),
    })
}

/// Computes a borrowed dirname result from a NUL-terminated path.
#[must_use]
pub fn dirname(path: &CStr) -> PathPart<'_> {
    PathPart::dirname(path)
}

/// Validates a byte path and computes a borrowed dirname without allocation
/// or mutation.
pub fn dirname_bytes(path: &[u8]) -> core::result::Result<PathPart<'_>, PathError> {
    let part = PathPart::new(path)?;
    Ok(PathPart {
        bytes: dirname_component(part.bytes),
    })
}

#[cfg(feature = "std")]
impl<'a> PathPart<'a> {
    /// Computes basename from a Unix `Path` without requiring UTF-8.
    #[must_use]
    pub fn basename_path(path: &'a Path) -> core::result::Result<Self, PathError> {
        let part = Self::new(path.as_os_str().as_bytes())?;
        Ok(Self {
            bytes: basename_component(part.bytes),
        })
    }

    /// Computes dirname from a Unix `Path` without requiring UTF-8.
    #[must_use]
    pub fn dirname_path(path: &'a Path) -> core::result::Result<Self, PathError> {
        let part = Self::new(path.as_os_str().as_bytes())?;
        Ok(Self {
            bytes: dirname_component(part.bytes),
        })
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
        let result = (&bytes[..bytes.len() - 1])
            .into_with_c_str(|path| Ok((path.to_bytes().len(), path.to_bytes()[1])));

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

#[cfg(test)]
mod path_part_tests {
    use super::{basename_bytes, dirname_bytes, PathPart};

    #[test]
    fn basename_and_dirname_follow_musl_path_matrix() {
        let cases = [
            (b"".as_slice(), b".".as_slice(), b".".as_slice()),
            (b"a".as_slice(), b"a".as_slice(), b".".as_slice()),
            (b"a/".as_slice(), b"a".as_slice(), b".".as_slice()),
            (b"/".as_slice(), b"/".as_slice(), b"/".as_slice()),
            (b"////".as_slice(), b"/".as_slice(), b"/".as_slice()),
            (b"/a".as_slice(), b"a".as_slice(), b"/".as_slice()),
            (b"/a/".as_slice(), b"a".as_slice(), b"/".as_slice()),
            (b"/a/b".as_slice(), b"b".as_slice(), b"/a".as_slice()),
            (b"//a//b".as_slice(), b"b".as_slice(), b"//a".as_slice()),
        ];
        for (path, expected_basename, expected_dirname) in cases {
            assert_eq!(basename_bytes(path).unwrap().as_bytes(), expected_basename);
            assert_eq!(dirname_bytes(path).unwrap().as_bytes(), expected_dirname);
        }
        assert!(basename_bytes(b"/").unwrap().is_root());
        assert!(dirname_bytes(b"a").unwrap().is_current());
        assert!(basename_bytes(b"a\0/b").is_err());
    }
}
