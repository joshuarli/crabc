//! Selected static Linux/x86-64 fixed-C-locale character classification.
//!
//! This leaf owns exactly the stateless, allocation-free ASCII C `ctype`
//! block: `isalnum`, `isalpha`, `isblank`, `iscntrl`, `isdigit`, `isgraph`,
//! `islower`, `isprint`, `ispunct`, `isspace`, `isupper`, `isxdigit`,
//! `tolower`, `toupper`, `isascii`, and `toascii`. It has no syscall, errno,
//! TLS, allocator, locale table, cancellation, or mutable global-state
//! boundary. It is not locale selection, `_l` ctype, wide or multibyte text,
//! collation, case-insensitive string comparison, stdio, libc.so, a CRT,
//! pthread/TLS lifecycle, dynamic TLS, a loader, a sysroot, or public x86
//! support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/ctype/isalnum.c`, `src/ctype/isalpha.c`,
//!   `src/ctype/isblank.c`, `src/ctype/iscntrl.c`,
//!   `src/ctype/isdigit.c`, `src/ctype/isgraph.c`,
//!   `src/ctype/islower.c`, `src/ctype/isprint.c`,
//!   `src/ctype/ispunct.c`, `src/ctype/isspace.c`,
//!   `src/ctype/isupper.c`, and `src/ctype/isxdigit.c` map to the
//!   corresponding public classification entries below.
//! - `src/ctype/tolower.c`, `src/ctype/toupper.c`,
//!   `src/ctype/isascii.c`, and `src/ctype/toascii.c` map to the corresponding
//!   conversion and ASCII-domain entries below.
//!
//! Musl's fixed C locale is ASCII for this narrow leaf. C permits a caller to
//! pass only `EOF` or an `unsigned char` value to the ordinary ctype entries;
//! this implementation keeps the same useful result for every `c_int` while
//! making the legal domain explicit in its range checks.

use core::ffi::c_int;

#[inline]
const fn ascii(c: c_int) -> bool {
    c >= 0 && c <= 0x7f
}

#[inline]
const fn in_ascii_range(c: c_int, first: u8, last: u8) -> bool {
    c >= first as c_int && c <= last as c_int
}

#[inline]
const fn alpha(c: c_int) -> bool {
    in_ascii_range(c, b'A', b'Z') || in_ascii_range(c, b'a', b'z')
}

#[inline]
const fn digit(c: c_int) -> bool {
    in_ascii_range(c, b'0', b'9')
}

#[inline]
const fn graph(c: c_int) -> bool {
    in_ascii_range(c, b'!', b'~')
}

/// Classify an ASCII letter or decimal digit.
#[no_mangle]
pub extern "C" fn isalnum(c: c_int) -> c_int {
    (alpha(c) || digit(c)) as c_int
}

/// Classify an ASCII letter.
#[no_mangle]
pub extern "C" fn isalpha(c: c_int) -> c_int {
    alpha(c) as c_int
}

/// Classify an ASCII horizontal blank (space or tab).
#[no_mangle]
pub extern "C" fn isblank(c: c_int) -> c_int {
    (c == b' ' as c_int || c == b'\t' as c_int) as c_int
}

/// Classify an ASCII control byte.
#[no_mangle]
pub extern "C" fn iscntrl(c: c_int) -> c_int {
    (ascii(c) && (c <= 0x1f || c == 0x7f)) as c_int
}

/// Classify an ASCII decimal digit.
#[no_mangle]
pub extern "C" fn isdigit(c: c_int) -> c_int {
    digit(c) as c_int
}

/// Classify an ASCII visible non-space byte.
#[no_mangle]
pub extern "C" fn isgraph(c: c_int) -> c_int {
    graph(c) as c_int
}

/// Classify an ASCII lowercase letter.
#[no_mangle]
pub extern "C" fn islower(c: c_int) -> c_int {
    in_ascii_range(c, b'a', b'z') as c_int
}

/// Classify an ASCII printable byte, including space.
#[no_mangle]
pub extern "C" fn isprint(c: c_int) -> c_int {
    in_ascii_range(c, b' ', b'~') as c_int
}

/// Classify an ASCII printable byte that is neither a letter nor a digit.
#[no_mangle]
pub extern "C" fn ispunct(c: c_int) -> c_int {
    (graph(c) && !alpha(c) && !digit(c)) as c_int
}

/// Classify an ASCII space or horizontal/vertical whitespace byte.
#[no_mangle]
pub extern "C" fn isspace(c: c_int) -> c_int {
    (c == b' ' as c_int || in_ascii_range(c, b'\t', b'\r')) as c_int
}

/// Classify an ASCII uppercase letter.
#[no_mangle]
pub extern "C" fn isupper(c: c_int) -> c_int {
    in_ascii_range(c, b'A', b'Z') as c_int
}

/// Classify an ASCII hexadecimal digit.
#[no_mangle]
pub extern "C" fn isxdigit(c: c_int) -> c_int {
    (digit(c)
        || in_ascii_range(c, b'A', b'F')
        || in_ascii_range(c, b'a', b'f')) as c_int
}

/// Convert an ASCII uppercase letter to lowercase, preserving other values.
#[no_mangle]
pub extern "C" fn tolower(c: c_int) -> c_int {
    if in_ascii_range(c, b'A', b'Z') {
        c + (b'a' - b'A') as c_int
    } else {
        c
    }
}

/// Convert an ASCII lowercase letter to uppercase, preserving other values.
#[no_mangle]
pub extern "C" fn toupper(c: c_int) -> c_int {
    if in_ascii_range(c, b'a', b'z') {
        c - (b'a' - b'A') as c_int
    } else {
        c
    }
}

/// Classify an integer in the seven-bit ASCII domain.
#[no_mangle]
pub extern "C" fn isascii(c: c_int) -> c_int {
    ascii(c) as c_int
}

/// Discard every bit outside the seven-bit ASCII domain.
#[no_mangle]
pub extern "C" fn toascii(c: c_int) -> c_int {
    c & 0x7f
}
