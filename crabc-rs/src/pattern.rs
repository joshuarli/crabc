//! Native, allocation-free filename pattern matching.
//!
//! This facade accepts `CStr` values so its no-interior-NUL contract is
//! explicit while still supporting non-UTF-8 Unix names. It calls the pure
//! `crabc-core` matcher directly: no public C `fnmatch`, C sentinel, or C
//! `errno` participates in the operation.

use bitflags::bitflags;
use core::ffi::CStr;

#[cfg(feature = "alloc")]
use alloc::ffi::CString;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use core::mem::MaybeUninit;

#[cfg(feature = "alloc")]
use crate::{fs, path::Arg, AsFd, Errno, Result};

bitflags! {
    /// POSIX and musl filename-pattern matching options.
    #[repr(transparent)]
    #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
    pub struct FnmatchFlags: u32 {
        /// `*` and `?` do not match `/`.
        const PATHNAME = crabc_core::pattern::FNM_PATHNAME;
        /// Treat backslash as an ordinary pattern byte.
        const NOESCAPE = crabc_core::pattern::FNM_NOESCAPE;
        /// Wildcards do not match a leading `.` in a component.
        const PERIOD = crabc_core::pattern::FNM_PERIOD;
        /// Permit a match ending immediately before a `/`.
        const LEADING_DIR = crabc_core::pattern::FNM_LEADING_DIR;
        /// Fold ASCII letter case during matching.
        const CASEFOLD = crabc_core::pattern::FNM_CASEFOLD;
    }
}

/// Matches a C-string pattern against a C-string candidate.
///
/// The return value is a Rust-owned boolean: `true` means the complete
/// candidate matched and `false` means `FNM_NOMATCH`. `CStr` makes the
/// no-interior-NUL requirement visible in the type and preserves arbitrary
/// non-UTF-8 bytes.
#[must_use]
#[inline]
pub fn fnmatch(pattern: &CStr, candidate: &CStr, flags: FnmatchFlags) -> bool {
    crabc_core::pattern::fnmatch(pattern.to_bytes(), candidate.to_bytes(), flags.bits())
}

/// An owned byte-preserving pathname returned by [`glob`] or [`glob_at`].
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GlobPath {
    bytes: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl GlobPath {
    /// Borrows the pathname bytes without requiring UTF-8.
    #[must_use]
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Transfers ownership of the pathname bytes to the caller.
    #[must_use]
    #[inline]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(feature = "alloc")]
impl AsRef<[u8]> for GlobPath {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Expands `pattern` below an explicit starting directory pathname.
///
/// The pattern is a relative, nonempty slash-separated byte pattern. Its
/// `*`, `?`, bracket, escape, and leading-dot behavior comes from
/// [`fnmatch`]. Absolute patterns, empty components, `..` components, and
/// interior NUL bytes are rejected with [`crate::Errno::INVAL`]. The supplied
/// `root` is the only starting location; the pattern never silently uses the
/// process current directory as its search root.
/// A component exactly equal to `.` is retained, while `.` and `..` directory
/// records are never wildcard candidates, so patterns have no syntactic
/// parent traversal. Intermediate symlinks follow Linux `openat` semantics;
/// this API is not a filesystem-confinement boundary.
///
/// Returned paths retain the supplied root spelling followed by one `/` and
/// the matching relative path. Entries are owned and preserve arbitrary Unix
/// pathname bytes. Results are sorted by their raw bytes, not filesystem
/// enumeration order. No matches produce `Ok(Vec::new())`; a missing root or
/// directory-read error is returned unchanged. A missing or non-directory
/// intermediate candidate is treated as a non-match, which keeps a pattern
/// such as `missing/*` at the documented no-match result.
#[cfg(feature = "alloc")]
#[inline]
pub fn glob<P: Arg>(root: P, pattern: &[u8]) -> Result<Vec<GlobPath>> {
    root.into_with_c_str(|root| {
        let directory = fs::openat(
            fs::CWD,
            root,
            fs::OFlags::RDONLY | fs::OFlags::DIRECTORY | fs::OFlags::CLOEXEC,
            fs::Mode::empty(),
        )?;
        let mut matches = glob_at(directory.as_fd(), pattern)?;
        let root_bytes = root.to_bytes();
        for path in &mut matches {
            let mut full = Vec::with_capacity(
                root_bytes
                    .len()
                    .saturating_add(1)
                    .saturating_add(path.bytes.len()),
            );
            full.extend_from_slice(root_bytes);
            if !root_bytes.ends_with(b"/") {
                full.push(b'/');
            }
            full.extend_from_slice(&path.bytes);
            path.bytes = full;
        }
        Ok(matches)
    })
}

/// Expands `pattern` below an explicit borrowed directory descriptor.
///
/// Results are relative to `dirfd`, owned, byte-preserving, and sorted by raw
/// pathname bytes. The pattern and no-match/error policy are the same as
/// [`glob`], but no pathname lookup or process-global current-directory state
/// is involved. The borrowed descriptor's directory offset is not changed.
#[cfg(feature = "alloc")]
#[inline]
pub fn glob_at<Fd: AsFd>(dirfd: Fd, pattern: &[u8]) -> Result<Vec<GlobPath>> {
    let components = split_pattern(pattern)?;
    let directory = fs::openat(
        dirfd.as_fd(),
        &b"."[..],
        fs::OFlags::RDONLY | fs::OFlags::DIRECTORY | fs::OFlags::CLOEXEC,
        fs::Mode::empty(),
    )?;
    let mut matches = Vec::new();
    let mut prefix = Vec::new();
    expand_directory(
        directory.as_fd(),
        &components,
        &mut prefix,
        &mut matches,
    )?;
    matches.sort_unstable();
    Ok(matches)
}

#[cfg(feature = "alloc")]
const GLOB_DIRECTORY_BUFFER_SIZE: usize = 8192;

#[cfg(feature = "alloc")]
fn split_pattern(pattern: &[u8]) -> Result<Vec<&[u8]>> {
    if pattern.is_empty() || pattern[0] == b'/' || pattern.iter().any(|&byte| byte == 0) {
        return Err(Errno::INVAL);
    }

    let mut components = Vec::new();
    for component in pattern.split(|&byte| byte == b'/') {
        if component.is_empty() || component == b".." {
            return Err(Errno::INVAL);
        }
        components.push(component);
    }
    Ok(components)
}

#[cfg(feature = "alloc")]
fn expand_directory(
    directory: crate::BorrowedFd<'_>,
    components: &[&[u8]],
    prefix: &mut Vec<u8>,
    matches: &mut Vec<GlobPath>,
) -> Result<()> {
    let component = CString::new(components[0]).map_err(|_| Errno::INVAL)?;
    let mut storage = alloc::vec![MaybeUninit::<u8>::uninit(); GLOB_DIRECTORY_BUFFER_SIZE];
    let mut entries = crate::RawDir::new(directory, &mut storage);

    while let Some(entry) = entries.next() {
        let entry = entry?;
        if !fnmatch(component.as_c_str(), entry.file_name(), FnmatchFlags::PERIOD) {
            continue;
        }

        if (entry.name_bytes() == b"." || entry.name_bytes() == b"..")
            && component.as_bytes() != b"."
        {
            continue;
        }
        let name = entry.name_bytes().to_vec();
        let prefix_length = prefix.len();
        if !prefix.is_empty() {
            prefix.push(b'/');
        }
        prefix.extend_from_slice(&name);

        if components.len() == 1 {
            matches.push(GlobPath { bytes: prefix.clone() });
        } else {
            match fs::openat(
                directory,
                name.as_slice(),
                fs::OFlags::RDONLY | fs::OFlags::DIRECTORY | fs::OFlags::CLOEXEC,
                fs::Mode::empty(),
            ) {
                Ok(child) => expand_directory(
                    child.as_fd(),
                    &components[1..],
                    prefix,
                    matches,
                )?,
                Err(Errno::NOENT | Errno::NOTDIR) => {}
                Err(error) => return Err(error),
            }
        }
        prefix.truncate(prefix_length);
    }

    Ok(())
}
