//! Allocation-free Linux/x86-64 built-in locale objects and localized wide text.
//!
//! This leaf owns immutable `C`/`POSIX` and `C.UTF-8` locale-object tokens,
//! selected-main/selected-worker `uselocale` state in the existing Static
//! Initial TLS v1 image, the fixed POSIX `nl_langinfo` table, and the complete
//! locale-parameterized form of the selected allocation-free wide-character
//! core. `POSIX` normalizes to `C`; only LC_CTYPE differs for `C.UTF-8`, while
//! numeric, time, collation, monetary, and messages data retain fixed C values.
//! No locale map, environment lookup, allocation, refcount, filesystem,
//! gettext catalog, normalization, legacy encoding, stdio, numeric parser,
//! syscall, dynamic TLS, loader, or general locale database is selected.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/locale/{newlocale,duplocale,uselocale,freelocale,langinfo}.c` maps to
//!   the immutable built-in tokens, per-thread selection, and fixed C tables.
//!   Unlike musl's general allocated objects, duplicates of these two immutable
//!   built-ins reuse their token; identity and post-`freelocale` use are not a
//!   portable locale-object contract.
//! - `src/ctype/{isw*,towctrans,wctrans}.c` localized aliases,
//!   `src/string/{wcscasecmp_l,wcsncasecmp_l}.c`, and
//!   `src/locale/{wcscoll,wcsxfrm}.c` map to the forwarding entries below.
//!   Musl's selected Unicode classification and code-point collation are
//!   locale-argument independent for these built-ins.
//!
//! `locale_t` is opaque in the installed ABI. Callers may pass only a live
//! token returned here (or `LC_GLOBAL_LOCALE` where POSIX permits it). Each
//! selected thread begins in global-following mode; a `uselocale` override
//! affects that thread's multibyte CTYPE behavior and `nl_langinfo(CODESET)`.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 locale-object leaf requires little-endian Linux/x86-64");

use core::ffi::{c_char, c_int, c_void};

use super::{errno, locale_multibyte, wide_character};

type Locale = *mut c_void;
type Wchar = i32;
type Wint = u32;
type Wctype = usize;
type Wctrans = *const c_int;

// These locale internals remain exported by musl. Their public spellings are
// weak aliases at the same address, rather than independent Rust wrappers.
// `freelocale` is the reverse source form: the strong public body also has a
// weak `__freelocale` spelling at its exact address.
core::arch::global_asm!(
    ".weak __freelocale", ".set __freelocale, freelocale",
    ".weak newlocale", ".set newlocale, __newlocale",
    ".weak uselocale", ".set uselocale, __uselocale",
    ".weak duplocale", ".set duplocale, __duplocale",
    ".weak nl_langinfo_l", ".set nl_langinfo_l, __nl_langinfo_l",
    ".weak nl_langinfo", ".set nl_langinfo, __nl_langinfo",
    ".weak iswalnum_l", ".set iswalnum_l, __iswalnum_l",
    ".weak iswalpha_l", ".set iswalpha_l, __iswalpha_l",
    ".weak iswblank_l", ".set iswblank_l, __iswblank_l",
    ".weak iswcntrl_l", ".set iswcntrl_l, __iswcntrl_l",
    ".weak iswdigit_l", ".set iswdigit_l, __iswdigit_l",
    ".weak iswgraph_l", ".set iswgraph_l, __iswgraph_l",
    ".weak iswlower_l", ".set iswlower_l, __iswlower_l",
    ".weak iswprint_l", ".set iswprint_l, __iswprint_l",
    ".weak iswpunct_l", ".set iswpunct_l, __iswpunct_l",
    ".weak iswspace_l", ".set iswspace_l, __iswspace_l",
    ".weak iswupper_l", ".set iswupper_l, __iswupper_l",
    ".weak iswxdigit_l", ".set iswxdigit_l, __iswxdigit_l",
    ".weak iswctype_l", ".set iswctype_l, __iswctype_l",
    ".weak wctype_l", ".set wctype_l, __wctype_l",
    ".weak towlower_l", ".set towlower_l, __towlower_l",
    ".weak towupper_l", ".set towupper_l, __towupper_l",
    ".weak towctrans_l", ".set towctrans_l, __towctrans_l",
    ".weak wctrans_l", ".set wctrans_l, __wctrans_l",
    ".weak wcscoll_l", ".set wcscoll_l, __wcscoll_l",
    ".weak wcsxfrm_l", ".set wcsxfrm_l, __wcsxfrm_l",
);

const ENOENT: c_int = 2;
const LC_CTYPE: c_int = 0;
const LC_ALL: c_int = 6;
const LC_CTYPE_MASK: c_int = 1 << LC_CTYPE;

const THREAD_GLOBAL: u8 = 0;
const THREAD_C: u8 = 1;
const THREAD_UTF8: u8 = 2;

#[repr(C)]
struct LocaleObject {
    ctype_utf8: u8,
}

static mut C_LOCALE_OBJECT: LocaleObject = LocaleObject { ctype_utf8: 0 };
static mut UTF8_LOCALE_OBJECT: LocaleObject = LocaleObject { ctype_utf8: 1 };

// Zero denotes global-following mode so this remains TBSS. Existing
// freestanding fixtures and Static Initial TLS v1 workers already copy and
// independently zero the complete final-executable TLS image.
#[thread_local]
static mut CURRENT_LOCALE_MODE: u8 = THREAD_GLOBAL;

static EMPTY: [u8; 1] = [0];
static ASCII_NAME: [u8; 6] = *b"ASCII\0";
static UTF8_NAME: [u8; 6] = *b"UTF-8\0";
static C_NAME: [u8; 2] = *b"C\0";
static C_UTF8_NAME: [u8; 8] = *b"C.UTF-8\0";
static RADIX: [u8; 2] = *b".\0";

static TIME_STRINGS: [&[u8]; 50] = [
    b"Sun\0", b"Mon\0", b"Tue\0", b"Wed\0", b"Thu\0", b"Fri\0", b"Sat\0",
    b"Sunday\0", b"Monday\0", b"Tuesday\0", b"Wednesday\0", b"Thursday\0",
    b"Friday\0", b"Saturday\0", b"Jan\0", b"Feb\0", b"Mar\0", b"Apr\0",
    b"May\0", b"Jun\0", b"Jul\0", b"Aug\0", b"Sep\0", b"Oct\0", b"Nov\0",
    b"Dec\0", b"January\0", b"February\0", b"March\0", b"April\0", b"May\0",
    b"June\0", b"July\0", b"August\0", b"September\0", b"October\0",
    b"November\0", b"December\0", b"AM\0", b"PM\0", b"%a %b %e %T %Y\0",
    b"%m/%d/%y\0", b"%H:%M:%S\0", b"%I:%M:%S %p\0", b"\0", b"\0",
    b"%m/%d/%y\0", b"0123456789\0", b"%a %b %e %T %Y\0", b"%H:%M:%S\0",
];
static MESSAGE_STRINGS: [&[u8]; 4] = [b"^[yY]\0", b"^[nN]\0", b"yes\0", b"no\0"];

#[inline]
const fn global_locale() -> Locale {
    usize::MAX as Locale
}

#[inline]
fn c_locale() -> Locale {
    core::ptr::addr_of_mut!(C_LOCALE_OBJECT).cast()
}

/// Return the immutable `C` locale token for one libc-internal formatting
/// operation.
///
/// Musl's `syslog.c` explicitly uses `strftime_l(..., C_LOCALE)` so its wire
/// timestamp is independent of the caller's thread locale.  Keep that
/// selection private to target-owned runtime code: it neither widens the
/// public locale-object API nor hands out another user-visible token.
#[inline]
pub(super) fn fixed_c_locale() -> Locale {
    c_locale()
}

#[inline]
fn utf8_locale() -> Locale {
    core::ptr::addr_of_mut!(UTF8_LOCALE_OBJECT).cast()
}

#[inline]
fn token_for_utf8(utf8: bool) -> Locale {
    if utf8 { utf8_locale() } else { c_locale() }
}

#[inline]
unsafe fn current_mode() -> u8 {
    unsafe { CURRENT_LOCALE_MODE }
}

#[inline]
fn token_is_utf8(locale: Locale) -> bool {
    locale == utf8_locale()
}

#[inline]
unsafe fn current_token() -> Locale {
    match unsafe { current_mode() } {
        THREAD_C => c_locale(),
        THREAD_UTF8 => utf8_locale(),
        _ => global_locale(),
    }
}

#[inline]
fn locale_utf8(locale: Locale) -> bool {
    if locale == global_locale() {
        locale_multibyte::global_ctype_is_utf8()
    } else {
        token_is_utf8(locale)
    }
}

/// Return a selected per-thread CTYPE override, or `None` while following the
/// process-global named locale.
#[inline]
pub(super) fn current_ctype_override() -> Option<bool> {
    match unsafe { current_mode() } {
        THREAD_C => Some(false),
        THREAD_UTF8 => Some(true),
        _ => None,
    }
}

// musl wide stdio temporarily installs FILE's captured built-in locale, so
// conversion and application cookie callbacks observe the same locale. This
// guard owns no reference into FILE/TLS across callbacks and restores even if
// a callback changed its thread locale, matching the source save/restore.
#[cfg(feature = "x86-owned-static-runtime")]
pub(super) struct StreamLocaleGuard { saved: u8, thread: core::marker::PhantomData<*mut ()> }
#[cfg(feature = "x86-owned-static-runtime")]
impl StreamLocaleGuard {
    /// # Safety
    /// Calling thread has initialized runtime TLS. Keep this guard on that
    /// thread through the synchronous FILE operation and all its callbacks.
    pub(super) unsafe fn enter(utf8: bool) -> Self {
        unsafe {
            let saved = CURRENT_LOCALE_MODE;
            CURRENT_LOCALE_MODE = if utf8 { THREAD_UTF8 } else { THREAD_C };
            Self { saved, thread: core::marker::PhantomData }
        }
    }
}
#[cfg(feature = "x86-owned-static-runtime")]
impl Drop for StreamLocaleGuard {
    fn drop(&mut self) { unsafe { CURRENT_LOCALE_MODE = self.saved; } }
}

#[inline]
unsafe fn string_equal(value: *const c_char, expected: &[u8]) -> bool {
    if value.is_null() {
        return false;
    }
    for (index, byte) in expected.iter().enumerate() {
        if unsafe { *value.cast::<u8>().add(index) } != *byte {
            return false;
        }
    }
    true
}

#[inline]
unsafe fn requested_utf8(name: *const c_char) -> Option<bool> {
    if unsafe { string_equal(name, b"C\0") } || unsafe { string_equal(name, b"POSIX\0") } {
        Some(false)
    } else if unsafe { string_equal(name, b"C.UTF-8\0") } {
        Some(true)
    } else {
        None
    }
}

/// Create or modify one immutable built-in locale object.
#[export_name = "__newlocale"]
pub unsafe extern "C" fn newlocale(mask: c_int, name: *const c_char, base: Locale) -> Locale {
    let mut utf8 = if base.is_null() {
        false
    } else {
        token_is_utf8(base)
    };
    if mask != 0 {
        let Some(requested) = (unsafe { requested_utf8(name) }) else {
            unsafe { errno::set_errno(ENOENT) };
            return core::ptr::null_mut();
        };
        if mask & LC_CTYPE_MASK != 0 {
            utf8 = requested;
        }
    }
    token_for_utf8(utf8)
}

/// Built-in locale tokens own no allocation.
#[no_mangle]
pub unsafe extern "C" fn freelocale(_locale: Locale) {}

/// Select or query the calling selected thread's locale object.
#[export_name = "__uselocale"]
pub unsafe extern "C" fn uselocale(locale: Locale) -> Locale {
    let old = unsafe { current_token() };
    if !locale.is_null() {
        unsafe {
            CURRENT_LOCALE_MODE = if locale == global_locale() {
                THREAD_GLOBAL
            } else if token_is_utf8(locale) {
                THREAD_UTF8
            } else {
                THREAD_C
            };
        }
    }
    old
}

/// Duplicate the immutable observable state of one built-in locale object.
#[export_name = "__duplocale"]
pub unsafe extern "C" fn duplocale(locale: Locale) -> Locale {
    if locale == global_locale() {
        token_for_utf8(locale_multibyte::global_ctype_is_utf8())
    } else {
        token_for_utf8(token_is_utf8(locale))
    }
}

#[inline]
fn bytes_pointer(bytes: &'static [u8]) -> *mut c_char {
    bytes.as_ptr() as *mut c_char
}

/// Query one fixed C/POSIX locale item through an explicit locale object.
#[export_name = "__nl_langinfo_l"]
pub unsafe extern "C" fn nl_langinfo_l(item: c_int, locale: Locale) -> *mut c_char {
    const CODESET: c_int = 14;
    if item == CODESET {
        return if locale_utf8(locale) {
            bytes_pointer(&UTF8_NAME)
        } else {
            bytes_pointer(&ASCII_NAME)
        };
    }
    let category = item >> 16;
    let index = (item & 0xffff) as usize;
    if index == 0xffff && category >= 0 && category < LC_ALL {
        if category == LC_CTYPE && locale_utf8(locale) {
            return bytes_pointer(&C_UTF8_NAME);
        }
        return bytes_pointer(&C_NAME);
    }
    match category {
        1 => match index {
            0 => bytes_pointer(&RADIX),
            1 => bytes_pointer(&EMPTY),
            _ => bytes_pointer(&EMPTY),
        },
        2 if index < TIME_STRINGS.len() => bytes_pointer(TIME_STRINGS[index]),
        5 if index < MESSAGE_STRINGS.len() => bytes_pointer(MESSAGE_STRINGS[index]),
        _ => bytes_pointer(&EMPTY),
    }
}

/// Query one fixed locale item through the calling thread's selection.
#[export_name = "__nl_langinfo"]
pub unsafe extern "C" fn nl_langinfo(item: c_int) -> *mut c_char {
    unsafe { nl_langinfo_l(item, current_token()) }
}

macro_rules! localized_classifier {
    ($localized:ident, $internal:literal, $base:ident) => {
        #[export_name = $internal]
        pub extern "C" fn $localized(character: Wint, _locale: Locale) -> c_int {
            wide_character::$base(character)
        }
    };
}

localized_classifier!(iswalnum_l, "__iswalnum_l", iswalnum);
localized_classifier!(iswalpha_l, "__iswalpha_l", iswalpha);
localized_classifier!(iswblank_l, "__iswblank_l", iswblank);
localized_classifier!(iswcntrl_l, "__iswcntrl_l", iswcntrl);
localized_classifier!(iswdigit_l, "__iswdigit_l", iswdigit);
localized_classifier!(iswgraph_l, "__iswgraph_l", iswgraph);
localized_classifier!(iswlower_l, "__iswlower_l", iswlower);
localized_classifier!(iswprint_l, "__iswprint_l", iswprint);
localized_classifier!(iswpunct_l, "__iswpunct_l", iswpunct);
localized_classifier!(iswspace_l, "__iswspace_l", iswspace);
localized_classifier!(iswupper_l, "__iswupper_l", iswupper);
localized_classifier!(iswxdigit_l, "__iswxdigit_l", iswxdigit);

#[export_name = "__iswctype_l"]
pub extern "C" fn iswctype_l(character: Wint, descriptor: Wctype, _locale: Locale) -> c_int {
    wide_character::iswctype(character, descriptor)
}

#[export_name = "__wctype_l"]
pub unsafe extern "C" fn wctype_l(name: *const c_char, _locale: Locale) -> Wctype {
    unsafe { wide_character::wctype(name) }
}

#[export_name = "__towlower_l"]
pub extern "C" fn towlower_l(character: Wint, _locale: Locale) -> Wint {
    wide_character::towlower(character)
}

#[export_name = "__towupper_l"]
pub extern "C" fn towupper_l(character: Wint, _locale: Locale) -> Wint {
    wide_character::towupper(character)
}

#[export_name = "__towctrans_l"]
pub extern "C" fn towctrans_l(character: Wint, descriptor: Wctrans, _locale: Locale) -> Wint {
    wide_character::towctrans(character, descriptor)
}

#[export_name = "__wctrans_l"]
pub unsafe extern "C" fn wctrans_l(name: *const c_char, _locale: Locale) -> Wctrans {
    unsafe { wide_character::wctrans(name) }
}

#[no_mangle]
pub unsafe extern "C" fn wcscasecmp_l(left: *const Wchar, right: *const Wchar, _locale: Locale) -> c_int {
    unsafe { wide_character::wcscasecmp(left, right) }
}

#[no_mangle]
pub unsafe extern "C" fn wcsncasecmp_l(
    left: *const Wchar,
    right: *const Wchar,
    count: usize,
    _locale: Locale,
) -> c_int {
    unsafe { wide_character::wcsncasecmp(left, right, count) }
}

#[export_name = "__wcscoll_l"]
pub unsafe extern "C" fn wcscoll_l(left: *const Wchar, right: *const Wchar, _locale: Locale) -> c_int {
    unsafe { wide_character::wcscoll(left, right) }
}

#[export_name = "__wcsxfrm_l"]
pub unsafe extern "C" fn wcsxfrm_l(
    destination: *mut Wchar,
    source: *const Wchar,
    count: usize,
    _locale: Locale,
) -> usize {
    unsafe { wide_character::wcsxfrm(destination, source, count) }
}
