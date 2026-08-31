//! Allocation-free Linux/x86-64 narrow fixed-locale text operations.
//!
//! This leaf owns the complete narrow locale-parameterized form of the
//! selected ASCII `ctype` block, byte-string case comparison, and byte
//! collation/transformation for the built-in `C`, `POSIX`, and `C.UTF-8`
//! profiles. All three profiles use ASCII narrow classification/case and
//! unsigned-byte collation, so the explicit locale-object argument does not
//! select additional data. The ordinary collation entries likewise have no
//! observable dependency on the calling thread's locale override.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/ctype/{isalnum,isalpha,isblank,iscntrl,isdigit,isgraph,islower,
//!   isprint,ispunct,isspace,isupper,isxdigit,tolower,toupper}.c` maps each
//!   localized wrapper to the corresponding fixed-ASCII base entry.
//! - `src/string/{strcasecmp,strncasecmp}.c` maps to the unsigned-byte loops
//!   and locale-parameterized forwarding entries below.
//! - `src/locale/{strcoll,strxfrm}.c` maps to unsigned-byte `strcmp` collation
//!   and the exact transformation rule: copy the source including its NUL
//!   only when capacity is greater than the source length.
//!
//! `locale_t` remains opaque. Callers may pass only a live token supplied by
//! the locale-object leaf where POSIX requires one; like musl, these wrappers
//! do not dereference it. There is no locale database, environment lookup,
//! allocation, errno, syscall, new TLS datum, normalization, legacy encoding,
//! numeric parsing, stdio, dynamic loader, or public x86 support here.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 narrow locale leaf requires little-endian Linux/x86-64");

use core::ffi::{c_char, c_int, c_void};

use super::{byte_strings, ctype, string_copy};

type Locale = *mut c_void;

macro_rules! localized_classifier {
    ($localized:ident, $base:ident) => {
        #[no_mangle]
        pub extern "C" fn $localized(character: c_int, _locale: Locale) -> c_int {
            ctype::$base(character)
        }
    };
}

localized_classifier!(isalnum_l, isalnum);
localized_classifier!(isalpha_l, isalpha);
localized_classifier!(isblank_l, isblank);
localized_classifier!(iscntrl_l, iscntrl);
localized_classifier!(isdigit_l, isdigit);
localized_classifier!(isgraph_l, isgraph);
localized_classifier!(islower_l, islower);
localized_classifier!(isprint_l, isprint);
localized_classifier!(ispunct_l, ispunct);
localized_classifier!(isspace_l, isspace);
localized_classifier!(isupper_l, isupper);
localized_classifier!(isxdigit_l, isxdigit);
localized_classifier!(tolower_l, tolower);
localized_classifier!(toupper_l, toupper);

/// Compare two C strings after fixed-ASCII case folding.
///
/// # Safety
///
/// `left` and `right` must each designate a readable NUL-terminated byte
/// sequence. Neither pointer may be null.
#[no_mangle]
pub unsafe extern "C" fn strcasecmp(left: *const c_char, right: *const c_char) -> c_int {
    let mut left = left.cast::<u8>();
    let mut right = right.cast::<u8>();
    loop {
        // SAFETY: the caller supplies both current C-string bytes.
        let left_byte = unsafe { left.read() };
        // SAFETY: the caller supplies both current C-string bytes.
        let right_byte = unsafe { right.read() };
        let left_folded = ctype::tolower(c_int::from(left_byte));
        let right_folded = ctype::tolower(c_int::from(right_byte));
        if left_byte == 0 || right_byte == 0 || left_folded != right_folded {
            return left_folded - right_folded;
        }
        // SAFETY: both bytes were non-NUL, so both following bytes exist.
        left = unsafe { left.add(1) };
        // SAFETY: both bytes were non-NUL, so both following bytes exist.
        right = unsafe { right.add(1) };
    }
}

/// Compare at most `count` C-string bytes after fixed-ASCII case folding.
///
/// # Safety
///
/// If `count` is nonzero, `left` and `right` must each be readable through
/// either their first NUL or `count` bytes. Null pointers are valid only when
/// `count` is zero.
#[no_mangle]
pub unsafe extern "C" fn strncasecmp(
    left: *const c_char,
    right: *const c_char,
    count: usize,
) -> c_int {
    if count == 0 {
        return 0;
    }
    let mut offset = 0usize;
    loop {
        // SAFETY: `offset < count` and the caller contract supply both bytes.
        let left_byte = unsafe { left.cast::<u8>().add(offset).read() };
        // SAFETY: `offset < count` and the caller contract supply both bytes.
        let right_byte = unsafe { right.cast::<u8>().add(offset).read() };
        let left_folded = ctype::tolower(c_int::from(left_byte));
        let right_folded = ctype::tolower(c_int::from(right_byte));
        if left_byte == 0 || right_byte == 0 || left_folded != right_folded {
            return left_folded - right_folded;
        }
        offset += 1;
        if offset == count {
            return 0;
        }
    }
}

/// Compare two C strings through one explicit fixed locale object.
///
/// # Safety
///
/// The string obligations are those of [`strcasecmp`]. `_locale` must be a
/// live locale token where the C contract requires one.
#[no_mangle]
pub unsafe extern "C" fn strcasecmp_l(
    left: *const c_char,
    right: *const c_char,
    _locale: Locale,
) -> c_int {
    // SAFETY: this forwarding entry preserves both C-string obligations.
    unsafe { strcasecmp(left, right) }
}

/// Compare at most `count` bytes through one explicit fixed locale object.
///
/// # Safety
///
/// The range obligations are those of [`strncasecmp`]. `_locale` must be a
/// live locale token where the C contract requires one.
#[no_mangle]
pub unsafe extern "C" fn strncasecmp_l(
    left: *const c_char,
    right: *const c_char,
    count: usize,
    _locale: Locale,
) -> c_int {
    // SAFETY: this forwarding entry preserves both bounded string obligations.
    unsafe { strncasecmp(left, right, count) }
}

/// Collate two C strings by unsigned byte value.
///
/// # Safety
///
/// `left` and `right` must each designate a readable NUL-terminated byte
/// sequence. Neither pointer may be null.
#[no_mangle]
pub unsafe extern "C" fn strcoll(left: *const c_char, right: *const c_char) -> c_int {
    // SAFETY: unsigned-byte collation has exactly `strcmp`'s obligations.
    unsafe { byte_strings::strcmp(left, right) }
}

/// Collate two C strings through one explicit fixed locale object.
///
/// # Safety
///
/// The string obligations are those of [`strcoll`]. `_locale` must be a live
/// locale token where the C contract requires one.
#[no_mangle]
pub unsafe extern "C" fn strcoll_l(
    left: *const c_char,
    right: *const c_char,
    _locale: Locale,
) -> c_int {
    // SAFETY: this forwarding entry preserves both C-string obligations.
    unsafe { strcoll(left, right) }
}

/// Form the fixed-locale byte collation key for one C string.
///
/// # Safety
///
/// `source` must designate a readable NUL-terminated byte sequence. When
/// `count` is greater than the source length, `destination` must designate
/// writable storage for the complete source and its NUL terminator. The two
/// ranges must satisfy `strcpy`'s non-overlap contract in that case.
#[no_mangle]
pub unsafe extern "C" fn strxfrm(
    destination: *mut c_char,
    source: *const c_char,
    count: usize,
) -> usize {
    // SAFETY: the source is one caller-supplied readable C string.
    let length = unsafe { byte_strings::strlen(source) };
    if count > length {
        // SAFETY: the function contract supplies a complete writable,
        // non-overlapping destination exactly in this branch.
        unsafe { string_copy::strcpy(destination, source) };
    }
    length
}

/// Form a byte collation key through one explicit fixed locale object.
///
/// # Safety
///
/// The source, destination, capacity, and overlap obligations are those of
/// [`strxfrm`]. `_locale` must be a live locale token where required by C.
#[no_mangle]
pub unsafe extern "C" fn strxfrm_l(
    destination: *mut c_char,
    source: *const c_char,
    count: usize,
    _locale: Locale,
) -> usize {
    // SAFETY: this forwarding entry preserves the transformation obligations.
    unsafe { strxfrm(destination, source, count) }
}
