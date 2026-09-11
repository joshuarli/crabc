//! Owned Linux/x86-64 C filename-pattern boundary.
//!
//! This source owner translates pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` (MIT; recorded in
//! `compat/upstreams.toml`): `src/regex/fnmatch.c` maps to
//! `owned_fnmatch.rs`, and `src/regex/glob.c` maps to `owned_glob.rs`.
//! It keeps the public `fnmatch`, `glob`, and `globfree` C records distinct
//! from the Rust-only byte matcher/traversal.  The matcher consumes the
//! selected C/POSIX/C.UTF-8 multibyte and wide-classification owners; glob
//! composes the selected C allocator, directory stream, stat, environment,
//! process-identity, and conventional-passwd owners.  It is neither a second
//! allocator, an NSS/provider framework, nor a general locale database.

use core::ffi::c_char;
#[cfg(crabc_owned_pattern_private_test)]
use core::slice;

/// A quote-removed shell pattern plus its byte-aligned syntax-protection map.
///
/// The last byte and last protection cell are both NUL. Every preceding byte
/// is non-NUL, and a nonzero mask cell makes that byte a literal even if its
/// value is shell-pattern punctuation. The frontend removes zero-width empty
/// markers before constructing this view, so matching and globbing can retain
/// the source-shaped musl byte traversal without learning core atom storage.
#[derive(Clone, Copy)]
pub(super) struct ShellPattern<'pattern> {
    bytes: &'pattern [u8],
    protection: &'pattern [u8],
}

/// Rejected private pattern-view inputs. The word-expansion frontend builds
/// these slices from already validated NUL-free atoms, but construction stays
/// checked so a malformed view cannot cross into raw matcher pointers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ShellPatternError {
    LengthMismatch,
    MissingTerminator,
    InteriorNul,
    InvalidProtection,
}

/// A `ShellPattern` map rebased onto a same-length duplicate byte allocation.
///
/// `owned_glob` owns that duplicate until it has finished every recursive
/// traversal. The view intentionally stores no mutable byte reference: glob's
/// temporary separator NUL writes preserve the original index-to-mask map.
#[derive(Clone, Copy)]
pub(super) struct ShellPatternView<'pattern> {
    base: *const c_char,
    byte_len: usize,
    protection: &'pattern [u8],
}

impl<'pattern> ShellPatternView<'pattern> {
    #[inline]
    pub(super) fn protected_at(self, pointer: *const c_char) -> bool {
        // Compare addresses rather than calling `offset_from`: recursive glob
        // only supplies pointers into `base`, but address arithmetic keeps a
        // malformed private caller from introducing an unrelated-allocation
        // provenance precondition here.
        let offset = (pointer as usize).checked_sub(self.base as usize);
        offset.is_some_and(|offset| {
            offset < self.byte_len && self.protection.get(offset).copied() == Some(1)
        })
    }
}

impl<'pattern> ShellPattern<'pattern> {
    /// Validate a terminal-NUL byte/map pair supplied by the private frontend.
    pub(super) fn new(bytes: &'pattern [u8], protection: &'pattern [u8]) -> Result<Self, ShellPatternError> {
        if bytes.len() != protection.len() {
            return Err(ShellPatternError::LengthMismatch);
        }
        if bytes.is_empty() || bytes.last().copied() != Some(0) || protection.last().copied() != Some(0) {
            return Err(ShellPatternError::MissingTerminator);
        }
        if bytes[..bytes.len() - 1].contains(&0) {
            return Err(ShellPatternError::InteriorNul);
        }
        if protection.iter().any(|cell| *cell > 1) {
            return Err(ShellPatternError::InvalidProtection);
        }
        Ok(Self { bytes, protection })
    }

    #[inline]
    pub(super) fn pointer(self) -> *const c_char {
        self.bytes.as_ptr().cast()
    }

    #[inline]
    pub(super) fn byte_len(self) -> usize {
        self.bytes.len()
    }

    #[inline]
    pub(super) fn mode(self) -> owned_fnmatch::PatternMode<'pattern> {
        owned_fnmatch::PatternMode::Shell(ShellPatternView {
            base: self.pointer(),
            byte_len: self.byte_len(),
            protection: self.protection,
        })
    }

    /// Rebase only the map onto `base`, a duplicate of `self.bytes` with the
    /// same terminal-NUL byte length. `base` must remain readable and live for
    /// every matcher/glob call that receives the returned mode.
    ///
    /// # Safety
    ///
    /// `base` must designate a live, readable allocation of exactly
    /// `byte_len` bytes whose contents equal `self.bytes`, including the
    /// terminal NUL. Every pattern pointer used with the returned mode must
    /// remain in that allocation until the mode is no longer used. Glob may
    /// temporarily replace a separator byte with NUL, but it must retain the
    /// same allocation and index mapping when it restores that byte.
    pub(super) unsafe fn rebased_mode(
        self,
        base: *const c_char,
        byte_len: usize,
    ) -> owned_fnmatch::PatternMode<'pattern> {
        debug_assert_eq!(byte_len, self.byte_len());
        owned_fnmatch::PatternMode::Shell(ShellPatternView {
            base,
            byte_len,
            protection: self.protection,
        })
    }
}

/// Private pathname expansion result. `NoActivePattern` deliberately differs
/// from an empty match set: the frontend retains the original field when all
/// apparent punctuation was protected or escaped by an expansion-derived
/// backslash.
pub(super) enum ShellGlobOutcome {
    NoActivePattern,
    NoMatch,
    Matches(ShellGlob),
}

/// Private glob failure mapping. Wordexp maps `NoSpace` precisely and treats
/// an interrupted directory walk as its existing failure path; neither C
/// `glob` record fields nor interior allocation pointers cross this boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ShellGlobError {
    NoSpace,
    Aborted,
}

/// RAII owner for the existing musl-shaped glob result allocation.
pub(super) struct ShellGlob {
    result: owned_glob::Glob,
}

/// A read-only byte pathname tied to its `ShellGlob` owner.
pub(super) struct ShellGlobPath<'result> {
    bytes: &'result [u8],
}

impl ShellGlob {
    #[inline]
    pub(super) fn len(&self) -> usize {
        owned_glob::shell_result_len(&self.result)
    }

    #[inline]
    pub(super) fn path(&self, index: usize) -> Option<ShellGlobPath<'_>> {
        owned_glob::shell_result_path(&self.result, index).map(|bytes| ShellGlobPath { bytes })
    }

    #[inline]
    pub(super) fn from_result(result: owned_glob::Glob) -> Self {
        Self { result }
    }
}

impl Drop for ShellGlob {
    fn drop(&mut self) {
        // SAFETY: only `owned_glob::shell_glob` constructs this owner, with
        // one successful result vector that this Drop consumes exactly once.
        unsafe { owned_glob::free_shell_result(&mut self.result) };
    }
}

impl<'result> ShellGlobPath<'result> {
    #[inline]
    pub(super) fn as_bytes(&self) -> &'result [u8] {
        self.bytes
    }
}

/// Use the existing Sea-of-Stars matcher for bounded wordexp parameter text.
#[inline]
pub(super) fn shell_matches(pattern: ShellPattern<'_>, text: &[u8]) -> bool {
    owned_fnmatch::shell_matches(pattern, text)
}

/// Expand one already quote-removed shell pathname pattern through the
/// existing glob allocation/traversal owner.
#[inline]
pub(super) fn shell_glob(pattern: ShellPattern<'_>) -> Result<ShellGlobOutcome, ShellGlobError> {
    owned_glob::shell_glob(pattern)
}

#[cfg(crabc_owned_pattern_private_test)]
#[inline]
unsafe fn private_test_slice<'a>(pointer: *const u8, length: usize) -> Option<&'a [u8]> {
    if pointer.is_null() {
        None
    } else {
        // SAFETY: the fixture supplies one readable fixed array for this
        // exact length. The bridge stays absent from normal products.
        Some(unsafe { slice::from_raw_parts(pointer, length) })
    }
}

/// Fixture-only C bridge for real-owner private-pattern regressions.
///
/// # Safety
///
/// `bytes` and `protection` must each designate readable arrays of
/// `pattern_length` bytes, and `text` must designate `text_length` readable
/// bytes for the entire call. The pattern arrays must have the terminal-NUL
/// form accepted by `ShellPattern::new`; malformed arrays return `-1`.
/// Callers must not mutate those ranges or change the selected CTYPE locale
/// concurrently. This bridge assumes the normal wordexp envelope's
/// cancellation suppression; fixture callers must not permit cancellation or
/// unwinding across this Rust call.
#[cfg(crabc_owned_pattern_private_test)]
#[no_mangle]
pub unsafe extern "C" fn __crabc_test_shell_match(
    bytes: *const u8,
    protection: *const u8,
    pattern_length: usize,
    text: *const u8,
    text_length: usize,
) -> core::ffi::c_int {
    let Some(bytes) = (unsafe { private_test_slice(bytes, pattern_length) }) else {
        return -1;
    };
    let Some(protection) = (unsafe { private_test_slice(protection, pattern_length) }) else {
        return -1;
    };
    let Some(text) = (unsafe { private_test_slice(text, text_length) }) else {
        return -1;
    };
    match ShellPattern::new(bytes, protection) {
        Ok(pattern) => shell_matches(pattern, text) as core::ffi::c_int,
        Err(_) => -1,
    }
}

/// Fixture-only C bridge for real-owner quote-aware glob regressions.
///
/// # Safety
///
/// `bytes` and `protection` must each designate readable arrays of
/// `pattern_length` bytes for the entire call, with the terminal-NUL form
/// accepted by `ShellPattern::new`. `match_count` must be non-null, aligned,
/// and writable for one `usize`. Callers must neither mutate those ranges nor
/// change the selected CTYPE locale concurrently. Glob allocates and walks
/// directory state, so fixture callers must also keep cancellation or
/// unwinding from crossing this Rust call, as the normal wordexp envelope does.
#[cfg(crabc_owned_pattern_private_test)]
#[no_mangle]
pub unsafe extern "C" fn __crabc_test_shell_glob(
    bytes: *const u8,
    protection: *const u8,
    pattern_length: usize,
    match_count: *mut usize,
) -> core::ffi::c_int {
    if match_count.is_null() {
        return -1;
    }
    unsafe { match_count.write(0) };
    let Some(bytes) = (unsafe { private_test_slice(bytes, pattern_length) }) else {
        return -1;
    };
    let Some(protection) = (unsafe { private_test_slice(protection, pattern_length) }) else {
        return -1;
    };
    let Ok(pattern) = ShellPattern::new(bytes, protection) else {
        return -1;
    };
    match shell_glob(pattern) {
        Ok(ShellGlobOutcome::NoActivePattern) => 0,
        Ok(ShellGlobOutcome::NoMatch) => 1,
        Ok(ShellGlobOutcome::Matches(matches)) => {
            unsafe { match_count.write(matches.len()) };
            2
        }
        Err(ShellGlobError::NoSpace) => -2,
        Err(ShellGlobError::Aborted) => -3,
    }
}

/// Fixture-only read-view witness. It exercises the lifetime-limited
/// `ShellGlob::path` API and copies no `glob_t` field or interior allocation
/// pointer across the test boundary.
///
/// # Safety
///
/// `bytes` and `protection` must each designate readable arrays of
/// `pattern_length` bytes in the terminal-NUL form accepted by
/// `ShellPattern::new`; `expected` must designate `expected_length` readable
/// bytes. None of those ranges may be mutated during the call. The caller must
/// serialize CTYPE locale changes and must prevent cancellation or unwinding
/// across the glob traversal, matching the normal wordexp envelope.
#[cfg(crabc_owned_pattern_private_test)]
#[no_mangle]
pub unsafe extern "C" fn __crabc_test_shell_glob_contains(
    bytes: *const u8,
    protection: *const u8,
    pattern_length: usize,
    expected: *const u8,
    expected_length: usize,
) -> core::ffi::c_int {
    let Some(bytes) = (unsafe { private_test_slice(bytes, pattern_length) }) else {
        return -1;
    };
    let Some(protection) = (unsafe { private_test_slice(protection, pattern_length) }) else {
        return -1;
    };
    let Some(expected) = (unsafe { private_test_slice(expected, expected_length) }) else {
        return -1;
    };
    let Ok(pattern) = ShellPattern::new(bytes, protection) else {
        return -1;
    };
    match shell_glob(pattern) {
        Ok(ShellGlobOutcome::Matches(matches)) => (0..matches.len()).any(|index| {
            matches.path(index).is_some_and(|path| path.as_bytes() == expected)
        }) as core::ffi::c_int,
        Ok(ShellGlobOutcome::NoActivePattern | ShellGlobOutcome::NoMatch) => 0,
        Err(ShellGlobError::NoSpace) => -2,
        Err(ShellGlobError::Aborted) => -3,
    }
}

#[path = "owned_fnmatch.rs"]
mod owned_fnmatch;
#[path = "owned_glob.rs"]
mod owned_glob;
