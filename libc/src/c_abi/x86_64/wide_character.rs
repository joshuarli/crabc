//! Allocation-free Linux/x86-64 wide-character core.
//!
//! This leaf owns 32-bit signed `wchar_t`, 32-bit unsigned `wint_t`, LP64
//! `wctype_t`, and pointer-shaped `wctrans_t` entry points for wide strings,
//! wide memory, code-point collation, Unicode classification/simple case
//! conversion, and terminal column width. It has no allocator, locale object,
//! global conversion state, stream, formatting, numeric, time, normalization,
//! or legacy-encoding boundary. The selected `C`, `POSIX`, and `C.UTF-8`
//! locales all collate wide strings by code point, matching musl 1.2.6.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/string/{wcslen,wcsnlen,wcscpy,wcsncpy,wcpcpy,wcpncpy,wcscat,
//!   wcsncat,wcscmp,wcsncmp,wcschr,wcsrchr,wcsstr,wcscspn,wcsspn,wcspbrk,
//!   wcstok,wcscasecmp,wcsncasecmp,wmemchr,wmemcmp,wmemcpy,wmemmove,
//!   wmemset}.c` maps to the same-named functions below.
//! - `src/locale/{wcscoll,wcsxfrm}.c` maps to code-point comparison/copy.
//! - `src/ctype/{isw*,towctrans,wctrans,wcwidth,wcswidth}.c` maps to the
//!   classification, simple-case, descriptor, and display-width functions.
//! - `src/ctype/{alpha,punct,casemap,nonspacing,wide}.h` maps mechanically to
//!   `wide_character_tables.rs`; no Unicode or locale database is generated
//!   or consulted at runtime.
//!
//! The existing AArch64 `libc/src/c_abi.rs` wide-string/classification block
//! is the project symbol-shape and ownership oracle. This target-private port
//! keeps that surface staged while following pinned musl's complete compressed
//! Unicode tables rather than inheriting the AArch64 block's approximate non-ASCII classification.
//! C callers retain the ordinary pointer validity,
//! NUL-termination, non-overlap (`wmemcpy` and restrict-qualified strings),
//! and capacity obligations declared by `<wchar.h>` and `<wctype.h>`.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the wide-character core requires little-endian Linux/x86-64");

use core::ffi::{c_char, c_int};

use super::wide_character_tables::{
    ALPHA, CASE_EXCEPTIONS, CASE_RULE_BASES, CASE_RULES, CASE_TAB, NONSPACING, PUNCT, WIDE,
};

type Wchar = i32;
type Wint = u32;
type Wctype = usize;
type Wctrans = *const c_int;

const WCTYPE_ALNUM: Wctype = 1;
const WCTYPE_ALPHA: Wctype = 2;
const WCTYPE_BLANK: Wctype = 3;
const WCTYPE_CNTRL: Wctype = 4;
const WCTYPE_DIGIT: Wctype = 5;
const WCTYPE_GRAPH: Wctype = 6;
const WCTYPE_LOWER: Wctype = 7;
const WCTYPE_PRINT: Wctype = 8;
const WCTYPE_PUNCT: Wctype = 9;
const WCTYPE_SPACE: Wctype = 10;
const WCTYPE_UPPER: Wctype = 11;
const WCTYPE_XDIGIT: Wctype = 12;

#[inline]
unsafe fn wide_length(mut string: *const Wchar) -> usize {
    let start = string;
    // SAFETY: callers provide a readable NUL-terminated wide string.
    while unsafe { *string } != 0 {
        string = string.wrapping_add(1);
    }
    // SAFETY: both pointers remain within the same caller-provided string.
    unsafe { string.offset_from(start) as usize }
}

#[inline]
fn compare_units(left: Wchar, right: Wchar) -> c_int {
    if left < right {
        -1
    } else if left > right {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn wcslen(string: *const Wchar) -> usize {
    // SAFETY: forwarded public wide-string contract.
    unsafe { wide_length(string) }
}

#[no_mangle]
pub unsafe extern "C" fn wcsnlen(string: *const Wchar, maximum: usize) -> usize {
    let mut length = 0usize;
    // SAFETY: the caller supplies `maximum` readable wide elements or a NUL.
    while length != maximum && unsafe { *string.add(length) } != 0 {
        length += 1;
    }
    length
}

#[no_mangle]
pub unsafe extern "C" fn wcscpy(destination: *mut Wchar, source: *const Wchar) -> *mut Wchar {
    let mut index = 0usize;
    loop {
        // SAFETY: the public restrict-qualified string contract supplies
        // readable source and sufficient non-overlapping destination space.
        let value = unsafe { *source.add(index) };
        unsafe { *destination.add(index) = value };
        if value == 0 {
            return destination;
        }
        index += 1;
    }
}

#[no_mangle]
pub unsafe extern "C" fn wcsncpy(
    destination: *mut Wchar,
    source: *const Wchar,
    count: usize,
) -> *mut Wchar {
    let mut index = 0usize;
    // SAFETY: the caller supplies readable source through NUL or `count` and
    // writable non-overlapping destination storage for `count` elements.
    while index != count && unsafe { *source.add(index) } != 0 {
        unsafe { *destination.add(index) = *source.add(index) };
        index += 1;
    }
    while index != count {
        unsafe { *destination.add(index) = 0 };
        index += 1;
    }
    destination
}

#[no_mangle]
pub unsafe extern "C" fn wcpcpy(destination: *mut Wchar, source: *const Wchar) -> *mut Wchar {
    // SAFETY: forwarded public string-copy contract.
    unsafe { wcscpy(destination, source) };
    // SAFETY: the source is a readable NUL-terminated wide string.
    destination.wrapping_add(unsafe { wide_length(source) })
}

#[no_mangle]
pub unsafe extern "C" fn wcpncpy(
    destination: *mut Wchar,
    source: *const Wchar,
    count: usize,
) -> *mut Wchar {
    // SAFETY: forwarded public bounded-copy contract.
    unsafe { wcsncpy(destination, source, count) };
    destination.wrapping_add(unsafe { wcsnlen(source, count) })
}

#[no_mangle]
pub unsafe extern "C" fn wcscat(destination: *mut Wchar, source: *const Wchar) -> *mut Wchar {
    // SAFETY: the destination is NUL-terminated and has room for source.
    let end = destination.wrapping_add(unsafe { wide_length(destination) });
    unsafe { wcscpy(end, source) };
    destination
}

#[no_mangle]
pub unsafe extern "C" fn wcsncat(
    destination: *mut Wchar,
    source: *const Wchar,
    count: usize,
) -> *mut Wchar {
    // SAFETY: the destination is readable through NUL and has sufficient
    // writable storage for the selected source prefix and final NUL.
    let mut end = destination.wrapping_add(unsafe { wide_length(destination) });
    let mut index = 0usize;
    while index != count {
        let value = unsafe { *source.add(index) };
        if value == 0 {
            break;
        }
        unsafe { *end = value };
        end = end.wrapping_add(1);
        index += 1;
    }
    unsafe { *end = 0 };
    destination
}

#[no_mangle]
pub unsafe extern "C" fn wcscmp(left: *const Wchar, right: *const Wchar) -> c_int {
    let mut index = 0usize;
    loop {
        // SAFETY: both arguments are readable NUL-terminated wide strings.
        let left_value = unsafe { *left.add(index) };
        let right_value = unsafe { *right.add(index) };
        if left_value != right_value || left_value == 0 {
            return compare_units(left_value, right_value);
        }
        index += 1;
    }
}

#[no_mangle]
pub unsafe extern "C" fn wcsncmp(
    left: *const Wchar,
    right: *const Wchar,
    count: usize,
) -> c_int {
    let mut index = 0usize;
    while index != count {
        // SAFETY: both arguments are readable through NUL or `count`.
        let left_value = unsafe { *left.add(index) };
        let right_value = unsafe { *right.add(index) };
        if left_value != right_value || left_value == 0 {
            return compare_units(left_value, right_value);
        }
        index += 1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn wcschr(string: *const Wchar, character: Wchar) -> *mut Wchar {
    let mut cursor = string;
    loop {
        // SAFETY: the caller supplies a readable NUL-terminated string.
        let value = unsafe { *cursor };
        if value == character {
            return cursor.cast_mut();
        }
        if value == 0 {
            return core::ptr::null_mut();
        }
        cursor = cursor.wrapping_add(1);
    }
}

#[no_mangle]
pub unsafe extern "C" fn wcsrchr(string: *const Wchar, character: Wchar) -> *mut Wchar {
    // SAFETY: the caller supplies a readable NUL-terminated string.
    let mut cursor = string.wrapping_add(unsafe { wide_length(string) });
    loop {
        if unsafe { *cursor } == character {
            return cursor.cast_mut();
        }
        if cursor == string {
            return core::ptr::null_mut();
        }
        cursor = cursor.wrapping_sub(1);
    }
}

#[no_mangle]
pub unsafe extern "C" fn wcsstr(haystack: *const Wchar, needle: *const Wchar) -> *mut Wchar {
    if unsafe { *needle } == 0 {
        return haystack.cast_mut();
    }
    let mut start = haystack;
    while unsafe { *start } != 0 {
        let mut left = start;
        let mut right = needle;
        while unsafe { *right } != 0 && unsafe { *left } == unsafe { *right } {
            left = left.wrapping_add(1);
            right = right.wrapping_add(1);
        }
        if unsafe { *right } == 0 {
            return start.cast_mut();
        }
        start = start.wrapping_add(1);
    }
    core::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn wcsspn(string: *const Wchar, accept: *const Wchar) -> usize {
    let mut cursor = string;
    while unsafe { *cursor } != 0 && !unsafe { wcschr(accept, *cursor) }.is_null() {
        cursor = cursor.wrapping_add(1);
    }
    unsafe { cursor.offset_from(string) as usize }
}

#[no_mangle]
pub unsafe extern "C" fn wcscspn(string: *const Wchar, reject: *const Wchar) -> usize {
    let mut cursor = string;
    while unsafe { *cursor } != 0 && unsafe { wcschr(reject, *cursor) }.is_null() {
        cursor = cursor.wrapping_add(1);
    }
    unsafe { cursor.offset_from(string) as usize }
}

#[no_mangle]
pub unsafe extern "C" fn wcspbrk(string: *const Wchar, accept: *const Wchar) -> *mut Wchar {
    let cursor = string.wrapping_add(unsafe { wcscspn(string, accept) });
    if unsafe { *cursor } == 0 {
        core::ptr::null_mut()
    } else {
        cursor.cast_mut()
    }
}

#[no_mangle]
pub unsafe extern "C" fn wcstok(
    string: *mut Wchar,
    separators: *const Wchar,
    state: *mut *mut Wchar,
) -> *mut Wchar {
    let mut cursor = if string.is_null() {
        // SAFETY: the public ABI requires a live writable state pointer.
        unsafe { *state }
    } else {
        string
    };
    if cursor.is_null() {
        return core::ptr::null_mut();
    }
    cursor = cursor.wrapping_add(unsafe { wcsspn(cursor, separators) });
    if unsafe { *cursor } == 0 {
        unsafe { *state = core::ptr::null_mut() };
        return core::ptr::null_mut();
    }
    let token = cursor;
    cursor = cursor.wrapping_add(unsafe { wcscspn(cursor, separators) });
    if unsafe { *cursor } != 0 {
        unsafe { *cursor = 0 };
        cursor = cursor.wrapping_add(1);
        unsafe { *state = cursor };
    } else {
        unsafe { *state = core::ptr::null_mut() };
    }
    token
}

#[no_mangle]
pub unsafe extern "C" fn wmemchr(
    string: *const Wchar,
    character: Wchar,
    count: usize,
) -> *mut Wchar {
    let mut index = 0usize;
    while index != count {
        if unsafe { *string.add(index) } == character {
            return string.wrapping_add(index).cast_mut();
        }
        index += 1;
    }
    core::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn wmemcmp(
    left: *const Wchar,
    right: *const Wchar,
    count: usize,
) -> c_int {
    let mut index = 0usize;
    while index != count {
        let left_value = unsafe { *left.add(index) };
        let right_value = unsafe { *right.add(index) };
        if left_value != right_value {
            return compare_units(left_value, right_value);
        }
        index += 1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn wmemcpy(
    destination: *mut Wchar,
    source: *const Wchar,
    count: usize,
) -> *mut Wchar {
    let mut index = 0usize;
    while index != count {
        unsafe { *destination.add(index) = *source.add(index) };
        index += 1;
    }
    destination
}

#[no_mangle]
pub unsafe extern "C" fn wmemmove(
    destination: *mut Wchar,
    source: *const Wchar,
    count: usize,
) -> *mut Wchar {
    if destination == source.cast_mut() {
        return destination;
    }
    let bytes = count.wrapping_mul(core::mem::size_of::<Wchar>());
    if (destination as usize).wrapping_sub(source as usize) < bytes {
        let mut index = count;
        while index != 0 {
            index -= 1;
            unsafe { *destination.add(index) = *source.add(index) };
        }
    } else {
        unsafe { wmemcpy(destination, source, count) };
    }
    destination
}

#[no_mangle]
pub unsafe extern "C" fn wmemset(
    destination: *mut Wchar,
    character: Wchar,
    count: usize,
) -> *mut Wchar {
    let mut index = 0usize;
    while index != count {
        unsafe { *destination.add(index) = character };
        index += 1;
    }
    destination
}

#[no_mangle]
pub unsafe extern "C" fn wcscoll(left: *const Wchar, right: *const Wchar) -> c_int {
    unsafe { wcscmp(left, right) }
}

#[no_mangle]
pub unsafe extern "C" fn wcsxfrm(
    destination: *mut Wchar,
    source: *const Wchar,
    count: usize,
) -> usize {
    let length = unsafe { wide_length(source) };
    if length < count {
        unsafe { wmemcpy(destination, source, length + 1) };
    } else if count != 0 {
        unsafe { wmemcpy(destination, source, count - 1) };
        unsafe { *destination.add(count - 1) = 0 };
    }
    length
}

#[inline]
fn property(table: &[u8], character: Wint) -> bool {
    let block = table[(character >> 8) as usize] as usize;
    let byte = table[block * 32 + ((character & 255) >> 3) as usize];
    ((byte >> (character & 7)) & 1) != 0
}

#[inline]
fn case_map(character: Wint, direction: u32) -> Wint {
    if character >= 0x20000 {
        return character;
    }
    let original = character;
    let block = (character >> 8) as usize;
    let low = character & 255;
    let x = (low / 3) as usize;
    let y = (low % 3) as usize;
    let mut vector = CASE_TAB[CASE_TAB[block] as usize * 86 + x] as u32;
    vector = (vector * [2048u32, 342, 57][y] >> 11) % 6;
    let mut rule = CASE_RULES[CASE_RULE_BASES[block] as usize + vector as usize];
    let mut rule_type = rule & 255;
    let mut delta = rule >> 8;
    if rule_type < 2 {
        return original.wrapping_add((delta & -((rule_type as u32 ^ direction) as i32)) as u32);
    }
    let mut count = (delta & 255) as usize;
    let mut base = (delta as u32 >> 8) as usize;
    while count != 0 {
        let midpoint = base + count / 2;
        let candidate = CASE_EXCEPTIONS[midpoint][0] as u32;
        if candidate == low {
            rule = CASE_RULES[CASE_EXCEPTIONS[midpoint][1] as usize];
            rule_type = rule & 255;
            delta = rule >> 8;
            if rule_type < 2 {
                return original.wrapping_add(
                    (delta & -((rule_type as u32 ^ direction) as i32)) as u32,
                );
            }
            return if direction != 0 {
                original.wrapping_sub(1)
            } else {
                original.wrapping_add(1)
            };
        }
        if candidate > low {
            count /= 2;
        } else {
            base += count / 2;
            count -= count / 2;
        }
    }
    original
}

#[no_mangle]
pub extern "C" fn towlower(character: Wint) -> Wint {
    case_map(character, 0)
}

#[no_mangle]
pub extern "C" fn towupper(character: Wint) -> Wint {
    case_map(character, 1)
}

#[no_mangle]
pub extern "C" fn iswalpha(character: Wint) -> c_int {
    if character < 0x20000 {
        property(&ALPHA, character) as c_int
    } else {
        (character < 0x2fffe) as c_int
    }
}

#[no_mangle]
pub extern "C" fn iswdigit(character: Wint) -> c_int {
    character.wrapping_sub(b'0' as u32).lt(&10) as c_int
}

#[no_mangle]
pub extern "C" fn iswalnum(character: Wint) -> c_int {
    (iswdigit(character) != 0 || iswalpha(character) != 0) as c_int
}

#[no_mangle]
pub extern "C" fn iswblank(character: Wint) -> c_int {
    (character == b' ' as u32 || character == b'\t' as u32) as c_int
}

#[no_mangle]
pub extern "C" fn iswcntrl(character: Wint) -> c_int {
    (character < 32
        || character.wrapping_sub(0x7f) < 33
        || character.wrapping_sub(0x2028) < 2
        || character.wrapping_sub(0xfff9) < 3) as c_int
}

#[no_mangle]
pub extern "C" fn iswprint(character: Wint) -> c_int {
    if character < 0xff {
        return (((character + 1) & 0x7f) >= 0x21) as c_int;
    }
    if character < 0x2028
        || character.wrapping_sub(0x202a) < 0xd800 - 0x202a
        || character.wrapping_sub(0xe000) < 0xfff9 - 0xe000
    {
        return 1;
    }
    if character.wrapping_sub(0xfffc) > 0x10ffff - 0xfffc
        || character & 0xfffe == 0xfffe
    {
        return 0;
    }
    1
}

#[no_mangle]
pub extern "C" fn iswspace(character: Wint) -> c_int {
    matches!(
        character,
        0x20 | 0x09 | 0x0a | 0x0d | 0x0b | 0x0c | 0x85 | 0x2000..=0x2006
            | 0x2008..=0x200a | 0x2028 | 0x2029 | 0x205f | 0x3000
    ) as c_int
}

#[no_mangle]
pub extern "C" fn iswgraph(character: Wint) -> c_int {
    (iswspace(character) == 0 && iswprint(character) != 0) as c_int
}

#[no_mangle]
pub extern "C" fn iswlower(character: Wint) -> c_int {
    (towupper(character) != character) as c_int
}

#[no_mangle]
pub extern "C" fn iswupper(character: Wint) -> c_int {
    (towlower(character) != character) as c_int
}

#[no_mangle]
pub extern "C" fn iswpunct(character: Wint) -> c_int {
    (character < 0x20000 && property(&PUNCT, character)) as c_int
}

#[no_mangle]
pub extern "C" fn iswxdigit(character: Wint) -> c_int {
    (character.wrapping_sub(b'0' as u32) < 10
        || (character | 32).wrapping_sub(b'a' as u32) < 6) as c_int
}

unsafe fn c_name_equal(mut input: *const c_char, expected: &[u8]) -> bool {
    if input.is_null() {
        return false;
    }
    for &byte in expected {
        if unsafe { *input.cast::<u8>() } != byte {
            return false;
        }
        input = input.wrapping_add(1);
    }
    unsafe { *input == 0 }
}

#[no_mangle]
pub unsafe extern "C" fn wctype(name: *const c_char) -> Wctype {
    const NAMES: [(&[u8], Wctype); 12] = [
        (b"alnum", WCTYPE_ALNUM),
        (b"alpha", WCTYPE_ALPHA),
        (b"blank", WCTYPE_BLANK),
        (b"cntrl", WCTYPE_CNTRL),
        (b"digit", WCTYPE_DIGIT),
        (b"graph", WCTYPE_GRAPH),
        (b"lower", WCTYPE_LOWER),
        (b"print", WCTYPE_PRINT),
        (b"punct", WCTYPE_PUNCT),
        (b"space", WCTYPE_SPACE),
        (b"upper", WCTYPE_UPPER),
        (b"xdigit", WCTYPE_XDIGIT),
    ];
    for (expected, descriptor) in NAMES {
        if unsafe { c_name_equal(name, expected) } {
            return descriptor;
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn iswctype(character: Wint, descriptor: Wctype) -> c_int {
    match descriptor {
        WCTYPE_ALNUM => iswalnum(character),
        WCTYPE_ALPHA => iswalpha(character),
        WCTYPE_BLANK => iswblank(character),
        WCTYPE_CNTRL => iswcntrl(character),
        WCTYPE_DIGIT => iswdigit(character),
        WCTYPE_GRAPH => iswgraph(character),
        WCTYPE_LOWER => iswlower(character),
        WCTYPE_PRINT => iswprint(character),
        WCTYPE_PUNCT => iswpunct(character),
        WCTYPE_SPACE => iswspace(character),
        WCTYPE_UPPER => iswupper(character),
        WCTYPE_XDIGIT => iswxdigit(character),
        _ => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn wctrans(name: *const c_char) -> Wctrans {
    if unsafe { c_name_equal(name, b"toupper") } {
        1usize as Wctrans
    } else if unsafe { c_name_equal(name, b"tolower") } {
        2usize as Wctrans
    } else {
        core::ptr::null()
    }
}

#[no_mangle]
pub extern "C" fn towctrans(character: Wint, descriptor: Wctrans) -> Wint {
    match descriptor as usize {
        1 => towupper(character),
        2 => towlower(character),
        _ => character,
    }
}

#[no_mangle]
pub unsafe extern "C" fn wcsncasecmp(
    left: *const Wchar,
    right: *const Wchar,
    mut count: usize,
) -> c_int {
    if count == 0 {
        return 0;
    }
    count -= 1;
    let mut index = 0usize;
    while unsafe { *left.add(index) } != 0
        && unsafe { *right.add(index) } != 0
        && count != 0
        && (unsafe { *left.add(index) } == unsafe { *right.add(index) }
            || towlower(unsafe { *left.add(index) } as Wint)
                == towlower(unsafe { *right.add(index) } as Wint))
    {
        index += 1;
        count -= 1;
    }
    towlower(unsafe { *left.add(index) } as Wint)
        .wrapping_sub(towlower(unsafe { *right.add(index) } as Wint)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn wcscasecmp(left: *const Wchar, right: *const Wchar) -> c_int {
    unsafe { wcsncasecmp(left, right, usize::MAX) }
}

#[no_mangle]
pub extern "C" fn wcwidth(character: Wchar) -> c_int {
    let character = character as Wint;
    if character < 0xff {
        return if ((character + 1) & 0x7f) >= 0x21 {
            1
        } else if character != 0 {
            -1
        } else {
            0
        };
    }
    if character & 0xfffeffff < 0xfffe {
        if property(&NONSPACING, character) {
            return 0;
        }
        if property(&WIDE, character) {
            return 2;
        }
        return 1;
    }
    if character & 0xfffe == 0xfffe {
        return -1;
    }
    if character.wrapping_sub(0x20000) < 0x20000 {
        return 2;
    }
    if character == 0xe0001
        || character.wrapping_sub(0xe0020) < 0x5f
        || character.wrapping_sub(0xe0100) < 0xef
    {
        return 0;
    }
    1
}

#[no_mangle]
pub unsafe extern "C" fn wcswidth(string: *const Wchar, mut count: usize) -> c_int {
    let mut width: c_int = 0;
    let mut cursor = string;
    while count != 0 && unsafe { *cursor } != 0 {
        let next = wcwidth(unsafe { *cursor });
        if next < 0 {
            return next;
        }
        width += next;
        cursor = cursor.wrapping_add(1);
        count -= 1;
    }
    width
}
