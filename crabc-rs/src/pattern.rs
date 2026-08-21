//! Native, allocation-free filename pattern matching.
//!
//! This facade accepts `CStr` values so its no-interior-NUL contract is
//! explicit while still supporting non-UTF-8 Unix names. It calls the pure
//! `crabc-core` matcher directly: no public C `fnmatch`, C sentinel, or C
//! `errno` participates in the operation.

use bitflags::bitflags;
use core::ffi::CStr;

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
