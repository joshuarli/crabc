// wide-character compatibility exports.
//
// The core wide-string and multibyte primitives live in lib.rs.  This file
// fills the remaining ABI surface with bounded, ordinary-memory operations,
// POSIX width classification, and unlocked aliases for the existing wide FILE
// operations.

#[no_mangle]
pub unsafe extern "C" fn vwprintf(fmt: *const wchar_t, args: VaList) -> c_int {
    vfwprintf(stdout, fmt, args)
}

#[no_mangle]
pub unsafe extern "C" fn wprintf(fmt: *const wchar_t, args: ...) -> c_int {
    vfwprintf(stdout, fmt, args)
}

// This follows musl's fgetws loop over the existing byte-conversion-aware
// fgetwc operation.  The terminating wide newline is retained, and a read
// that obtains no characters reports NULL while preserving the stream's EOF or
// error indicator.
#[no_mangle]
pub unsafe extern "C" fn fgetws(
    dst: *mut wchar_t,
    count: c_int,
    stream: *mut FILE,
) -> *mut wchar_t {
    if count <= 0 {
        return dst;
    }
    let mut written = 0usize;
    while written + 1 < count as usize {
        let c = fgetwc(stream);
        if c == WEOF {
            break;
        }
        *dst.add(written) = c as wchar_t;
        written += 1;
        if c == b'\n' as wint_t {
            break;
        }
    }
    *dst.add(written) = 0;
    if written == 0 || ferror(stream) != 0 {
        core::ptr::null_mut()
    } else {
        dst
    }
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn fgetws_unlocked(
    dst: *mut wchar_t,
    count: c_int,
    stream: *mut FILE,
) -> *mut wchar_t {
    fgetws(dst, count, stream)
}

#[no_mangle]
pub unsafe extern "C" fn wmemchr(
    src: *const wchar_t,
    value: wchar_t,
    count: usize,
) -> *mut wchar_t {
    for i in 0..count {
        if *src.add(i) == value {
            return src.add(i) as *mut wchar_t;
        }
    }
    core::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn wmemcmp(
    left: *const wchar_t,
    right: *const wchar_t,
    count: usize,
) -> c_int {
    for i in 0..count {
        let a = *left.add(i);
        let b = *right.add(i);
        if a < b { return -1; }
        if a > b { return 1; }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn wmemcpy(
    dst: *mut wchar_t,
    src: *const wchar_t,
    count: usize,
) -> *mut wchar_t {
    core::ptr::copy_nonoverlapping(src, dst, count);
    dst
}

#[no_mangle]
pub unsafe extern "C" fn wmemmove(
    dst: *mut wchar_t,
    src: *const wchar_t,
    count: usize,
) -> *mut wchar_t {
    core::ptr::copy(src, dst, count);
    dst
}

#[no_mangle]
pub unsafe extern "C" fn wmemset(
    dst: *mut wchar_t,
    value: wchar_t,
    count: usize,
) -> *mut wchar_t {
    for i in 0..count {
        *dst.add(i) = value;
    }
    dst
}

#[no_mangle]
pub unsafe extern "C" fn wcpcpy(dst: *mut wchar_t, src: *const wchar_t) -> *mut wchar_t {
    wcscpy(dst, src);
    dst.add(wcslen(src))
}

#[no_mangle]
pub unsafe extern "C" fn wcpncpy(
    dst: *mut wchar_t,
    src: *const wchar_t,
    count: usize,
) -> *mut wchar_t {
    let mut i = 0usize;
    while i < count {
        let c = *src.add(i);
        *dst.add(i) = c;
        i += 1;
        if c == 0 {
            let terminator = i - 1;
            while i < count {
                *dst.add(i) = 0;
                i += 1;
            }
            return dst.add(terminator);
        }
    }
    dst.add(count)
}

#[no_mangle]
pub unsafe extern "C" fn wcswcs(
    haystack: *const wchar_t,
    needle: *const wchar_t,
) -> *mut wchar_t {
    wcsstr(haystack, needle)
}

#[inline]
fn wide_is_nonspacing(c: u32) -> bool {
    matches!(c,
        0x0300..=0x036f |
        0x0483..=0x0489 |
        0x0591..=0x05bd | 0x05bf | 0x05c1..=0x05c2 | 0x05c4..=0x05c5 | 0x05c7 |
        0x0610..=0x061a | 0x064b..=0x065f | 0x0670 |
        0x06d6..=0x06dc | 0x06df..=0x06e4 | 0x06e7..=0x06e8 | 0x06ea..=0x06ed |
        0x0711 | 0x0730..=0x074a | 0x07a6..=0x07b0 |
        0x07eb..=0x07f3 | 0x0816..=0x0819 | 0x081b..=0x0823 | 0x0825..=0x0827 |
        0x0829..=0x082d | 0x0859..=0x085b | 0x08d3..=0x0902 |
        0x093a..=0x093c | 0x093e..=0x094f | 0x0951..=0x0957 | 0x0962..=0x0963 |
        0x0981..=0x0983 | 0x09bc | 0x09be..=0x09c4 | 0x09c7..=0x09c8 |
        0x09cb..=0x09cd | 0x09d7 | 0x09e2..=0x09e3 |
        0x0a01..=0x0a03 | 0x0a3c | 0x0a3e..=0x0a42 | 0x0a47..=0x0a48 |
        0x0a4b..=0x0a4d | 0x0a51 | 0x0a70..=0x0a71 | 0x0a75 |
        0x0a81..=0x0a83 | 0x0abc | 0x0abe..=0x0ac5 | 0x0ac7..=0x0ac9 |
        0x0acb..=0x0acd | 0x0ae2..=0x0ae3 |
        0x0b01..=0x0b03 | 0x0b3c | 0x0b3e..=0x0b44 | 0x0b47..=0x0b48 |
        0x0b4b..=0x0b4d | 0x0b56..=0x0b57 | 0x0b62..=0x0b63 |
        0x0b82 | 0x0bbe..=0x0bc2 | 0x0bc6..=0x0bc8 | 0x0bca..=0x0bcd |
        0x0bd7 | 0x0c00..=0x0c04 | 0x0c3e..=0x0c44 | 0x0c46..=0x0c48 |
        0x0c4a..=0x0c4d | 0x0c55..=0x0c56 | 0x0c62..=0x0c63 |
        0x0c81..=0x0c83 | 0x0cbc | 0x0cbe..=0x0cc4 | 0x0cc6..=0x0cc8 |
        0x0cca..=0x0ccd | 0x0cd5..=0x0cd6 | 0x0ce2..=0x0ce3 |
        0x0d00..=0x0d03 | 0x0d3b..=0x0d3c | 0x0d3e..=0x0d44 | 0x0d46..=0x0d48 |
        0x0d4a..=0x0d4d | 0x0d57 | 0x0d62..=0x0d63 |
        0x0d81..=0x0d83 | 0x0dca | 0x0dcf..=0x0dd4 | 0x0dd6 |
        0x0dd8..=0x0ddf | 0x0df2..=0x0df3 | 0x0e31 | 0x0e34..=0x0e3a |
        0x0e47..=0x0e4e | 0x0eb1 | 0x0eb4..=0x0ebc | 0x0ebe..=0x0ebf |
        0x0f18..=0x0f19 | 0x0f35 | 0x0f37 | 0x0f39 | 0x0f71..=0x0f84 |
        0x0f86..=0x0f87 | 0x0f8d..=0x0f97 | 0x0f99..=0x0fbc | 0x0fc6 |
        0x102b..=0x103e | 0x1056..=0x1059 | 0x105e..=0x1060 | 0x1062..=0x1064 |
        0x1067..=0x106d | 0x1071..=0x1074 | 0x1082 | 0x1084 | 0x1085..=0x1086 |
        0x108d | 0x108f..=0x1090 | 0x109a..=0x109d | 0x135d..=0x135f |
        0x1712..=0x1714 | 0x1732..=0x1734 | 0x1752..=0x1753 | 0x1772..=0x1773 |
        0x17b4..=0x17d3 | 0x17dd | 0x180b..=0x180f | 0x1885..=0x1886 |
        0x18a9 | 0x1920..=0x192b | 0x1930..=0x193b | 0x1a17..=0x1a1b |
        0x1a55..=0x1a5e | 0x1a60 | 0x1a62..=0x1a6f | 0x1a75..=0x1a7f |
        0x1ab0..=0x1aff | 0x1b00..=0x1b04 | 0x1b34 | 0x1b36..=0x1b44 |
        0x1b6b..=0x1b73 | 0x1b80..=0x1b82 | 0x1ba1..=0x1bad | 0x1be6..=0x1bf3 |
        0x1c24..=0x1c37 | 0x1cd0..=0x1cf9 | 0x1dc0..=0x1dff | 0x200b..=0x200f |
        0x202a..=0x202e | 0x2060..=0x2064 | 0x2066..=0x206f | 0x20d0..=0x20ff |
        0x2cef..=0x2cf1 | 0x2d7f | 0x2de0..=0x2dff | 0x302a..=0x302f |
        0x3099..=0x309a | 0xa66f | 0xa674..=0xa67d | 0xa69e..=0xa69f |
        0xa6f0..=0xa6f1 | 0xa802 | 0xa806 | 0xa80b | 0xa823..=0xa827 |
        0xa880..=0xa881 | 0xa8b4..=0xa8c5 | 0xa8e0..=0xa8f1 | 0xa8ff |
        0xa926..=0xa92f | 0xa947..=0xa953 | 0xa980..=0xa983 | 0xa9b3 |
        0xa9b6..=0xa9c0 | 0xa9e5 | 0xaa29..=0xaa36 | 0xaa43 | 0xaa4c..=0xaa4d |
        0xaa7b..=0xaa7d | 0xaab0 | 0xaab2..=0xaab4 | 0xaab7..=0xaab8 |
        0xaabe..=0xaabf | 0xaac1 | 0xaaec..=0xaaef | 0xaaf5..=0xaaf6 |
        0xabe3..=0xabea | 0xabec..=0xabed | 0xfb1e | 0xfe00..=0xfe0f |
        0xfe20..=0xfe2f | 0xff9e..=0xff9f | 0x101fd | 0x102e0 | 0x10376..=0x1037a |
        0x10a01..=0x10a0f | 0x10a38..=0x10a3f | 0x10ae5..=0x10ae6 |
        0x11000..=0x11002 | 0x11038..=0x11046 | 0x11070 | 0x11073..=0x11074 |
        0x1107f..=0x11082 | 0x110b0..=0x110ba | 0x110bd..=0x110c0 |
        0x11100..=0x11102 | 0x11127..=0x11134 | 0x11145..=0x11146 |
        0x11173 | 0x11180..=0x11182 | 0x111b3..=0x111c0 | 0x111c9..=0x111cc |
        0x1122c..=0x11237 | 0x1123e | 0x112df..=0x112ea | 0x11300..=0x11304 |
        0x1133b..=0x1133c | 0x1133e..=0x11344 | 0x11347..=0x11348 | 0x1134b..=0x1134d |
        0x11357 | 0x11362..=0x11363 | 0x11435..=0x11446 | 0x1145e |
        0x114b0..=0x114c3 | 0x114c6 | 0x114c8..=0x114c9 | 0x115af..=0x115c0 |
        0x115dc..=0x115dd | 0x11630..=0x11643 | 0x11645..=0x11646 |
        0x116ab..=0x116b7 | 0x1171d..=0x1172b | 0x1182c..=0x1183a |
        0x11930..=0x1193e | 0x11940 | 0x11942 | 0x11943 | 0x119d1..=0x119e0 |
        0x119e2 | 0x119e4..=0x119e7 | 0x11a01..=0x11a0a | 0x11a33..=0x11a39 |
        0x11a3b..=0x11a3e | 0x11a47 | 0x11a51..=0x11a5b | 0x11a8a..=0x11a99 |
        0x11c30..=0x11c3f | 0x11c41 | 0x11c92..=0x11ca7 | 0x11ca9..=0x11cb6 |
        0x11d31..=0x11d3f | 0x11d42 | 0x11d44..=0x11d45 | 0x11d47 |
        0x11d90..=0x11d91 | 0x11d95 | 0x11d97 | 0x11ef3..=0x11ef4 |
        0x13430..=0x1343f | 0x1da00..=0x1da36 | 0x1da3b..=0x1da6c |
        0x1da75 | 0x1da84 | 0x1da9b..=0x1da9f | 0x1daa1..=0x1dabf |
        0x1e000..=0x1e02f | 0x1e130..=0x1e13f | 0x1e2ec..=0x1e2ef |
        0x1e8d0..=0x1e8d9 | 0x1e944..=0x1e94a | 0xe0100..=0xe01ef)
}

#[inline]
fn wide_is_double(c: u32) -> bool {
    (0x1100..=0x115f).contains(&c) || c == 0x2329 || c == 0x232a ||
    (0x2e80..=0xa4cf).contains(&c) && c != 0x303f ||
    (0xac00..=0xd7a3).contains(&c) || (0xf900..=0xfaff).contains(&c) ||
    (0xfe10..=0xfe19).contains(&c) || (0xfe30..=0xfe6f).contains(&c) ||
    (0xff00..=0xff60).contains(&c) || (0xffe0..=0xffe6).contains(&c) ||
    (0x1f300..=0x1faff).contains(&c) || (0x20000..=0x3fffd).contains(&c)
}

#[inline]
fn wide_char_width(c: wchar_t) -> c_int {
    let c = c as u32;
    if c == 0 { return 0; }
    if c < 0x20 || (0x7f..=0x9f).contains(&c) || c > 0x10ffff ||
        (0xd800..=0xdfff).contains(&c) || (0xfdd0..=0xfdef).contains(&c) ||
        (c & 0xfffe) == 0xfffe {
        return -1;
    }
    if wide_is_nonspacing(c) { return 0; }
    if wide_is_double(c) { return 2; }
    1
}

#[no_mangle]
pub extern "C" fn wcwidth(c: wchar_t) -> c_int {
    wide_char_width(c)
}

#[no_mangle]
pub unsafe extern "C" fn wcswidth(s: *const wchar_t, count: usize) -> c_int {
    let mut width = 0i32;
    for i in 0..count {
        let c = *s.add(i);
        if c == 0 { break; }
        let next = wide_char_width(c);
        if next < 0 { return -1; }
        width = width.saturating_add(next);
    }
    width
}

// Existing wide FILE operations are already byte-conversion aware, so their
// unlocked spellings can safely delegate without introducing a second buffer.
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn fgetwc_unlocked(stream: *mut FILE) -> wint_t {
    fgetwc(stream)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn fputwc_unlocked(c: wchar_t, stream: *mut FILE) -> wint_t {
    fputwc(c, stream)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn fputws_unlocked(s: *const wchar_t, stream: *mut FILE) -> c_int {
    fputws(s, stream)
}

#[no_mangle]
pub unsafe extern "C" fn getwc(stream: *mut FILE) -> wint_t {
    fgetwc(stream)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn getwc_unlocked(stream: *mut FILE) -> wint_t {
    fgetwc(stream)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn getwchar_unlocked() -> wint_t {
    fgetwc(stdin)
}

#[no_mangle]
pub unsafe extern "C" fn putwc(c: wchar_t, stream: *mut FILE) -> wint_t {
    fputwc(c, stream)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn putwc_unlocked(c: wchar_t, stream: *mut FILE) -> wint_t {
    fputwc(c, stream)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn putwchar_unlocked(c: wchar_t) -> wint_t {
    fputwc(c, stdout)
}

#[no_mangle]
pub unsafe extern "C" fn __fgetwc_unlocked(stream: *mut FILE) -> wint_t {
    fgetwc(stream)
}

#[no_mangle]
pub unsafe extern "C" fn __fputwc_unlocked(c: wchar_t, stream: *mut FILE) -> wint_t {
    fputwc(c, stream)
}
