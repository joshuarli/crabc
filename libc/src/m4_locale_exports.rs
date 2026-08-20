// M4 locale-aware entry points and musl internal aliases.
//
// crabc currently supports the C/POSIX locale model.  These functions expose
// that concrete behavior consistently rather than adding placeholder exports:
// the `_l` interfaces use the supplied locale object where it has state, and
// otherwise delegate to the same C-locale primitive as their non-suffixed
// counterpart.  musl exports the `__*` spellings as ABI aliases, so they must
// retain exactly the corresponding public operation and calling convention.

macro_rules! ctype_internal_locale_alias {
    ($($name:ident => $implementation:ident),+ $(,)?) => {
        $(
            #[no_mangle]
            pub extern "C" fn $name(c: c_int, loc: locale_t) -> c_int {
                $implementation(c, loc)
            }
        )+
    };
}

ctype_internal_locale_alias!(
    __isalnum_l => isalnum_l,
    __isalpha_l => isalpha_l,
    __isblank_l => isblank_l,
    __iscntrl_l => iscntrl_l,
    __isdigit_l => isdigit_l,
    __isgraph_l => isgraph_l,
    __islower_l => islower_l,
    __isprint_l => isprint_l,
    __ispunct_l => ispunct_l,
    __isspace_l => isspace_l,
    __isupper_l => isupper_l,
    __isxdigit_l => isxdigit_l,
    __tolower_l => tolower_l,
    __toupper_l => toupper_l,
);

macro_rules! wide_locale_predicate {
    ($($name:ident, $internal:ident => $implementation:ident),+ $(,)?) => {
        $(
            #[no_mangle]
            #[linkage = "weak"]
            pub extern "C" fn $name(c: wint_t, _loc: locale_t) -> c_int {
                $implementation(c)
            }

            #[no_mangle]
            pub extern "C" fn $internal(c: wint_t, loc: locale_t) -> c_int {
                $name(c, loc)
            }
        )+
    };
}

wide_locale_predicate!(
    iswalnum_l, __iswalnum_l => iswalnum,
    iswalpha_l, __iswalpha_l => iswalpha,
    iswblank_l, __iswblank_l => iswblank,
    iswcntrl_l, __iswcntrl_l => iswcntrl,
    iswdigit_l, __iswdigit_l => iswdigit,
    iswgraph_l, __iswgraph_l => iswgraph,
    iswlower_l, __iswlower_l => iswlower,
    iswprint_l, __iswprint_l => iswprint,
    iswpunct_l, __iswpunct_l => iswpunct,
    iswspace_l, __iswspace_l => iswspace,
    iswupper_l, __iswupper_l => iswupper,
    iswxdigit_l, __iswxdigit_l => iswxdigit,
);

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn iswctype_l(c: wint_t, desc: wctype_t, _loc: locale_t) -> c_int {
    iswctype(c, desc)
}

#[no_mangle]
pub unsafe extern "C" fn __iswctype_l(c: wint_t, desc: wctype_t, loc: locale_t) -> c_int {
    iswctype_l(c, desc, loc)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn wctype_l(name: *const c_char, _loc: locale_t) -> wctype_t {
    wctype(name)
}

#[no_mangle]
pub unsafe extern "C" fn __wctype_l(name: *const c_char, loc: locale_t) -> wctype_t {
    wctype_l(name, loc)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn wctrans_l(name: *const c_char, _loc: locale_t) -> wctrans_t {
    wctrans(name)
}

#[no_mangle]
pub unsafe extern "C" fn __wctrans_l(name: *const c_char, loc: locale_t) -> wctrans_t {
    wctrans_l(name, loc)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn towlower_l(c: wint_t, _loc: locale_t) -> wint_t {
    towlower(c)
}

#[no_mangle]
pub unsafe extern "C" fn __towlower_l(c: wint_t, loc: locale_t) -> wint_t {
    towlower_l(c, loc)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn towupper_l(c: wint_t, _loc: locale_t) -> wint_t {
    towupper(c)
}

#[no_mangle]
pub unsafe extern "C" fn __towupper_l(c: wint_t, loc: locale_t) -> wint_t {
    towupper_l(c, loc)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn towctrans_l(c: wint_t, desc: wctrans_t, _loc: locale_t) -> wint_t {
    towctrans(c, desc)
}

#[no_mangle]
pub unsafe extern "C" fn __towctrans_l(c: wint_t, desc: wctrans_t, loc: locale_t) -> wint_t {
    towctrans_l(c, desc, loc)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn nl_langinfo_l(item: c_int, _loc: locale_t) -> *mut c_char {
    nl_langinfo(item)
}

#[no_mangle]
pub unsafe extern "C" fn __nl_langinfo(item: c_int) -> *mut c_char {
    nl_langinfo(item)
}

#[no_mangle]
pub unsafe extern "C" fn __nl_langinfo_l(item: c_int, loc: locale_t) -> *mut c_char {
    nl_langinfo_l(item, loc)
}

#[no_mangle]
pub unsafe extern "C" fn __newlocale(mask: c_int, name: *const c_char, base: locale_t) -> locale_t {
    newlocale(mask, name, base)
}

#[no_mangle]
pub unsafe extern "C" fn __duplocale(loc: locale_t) -> locale_t {
    duplocale(loc)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __freelocale(loc: locale_t) {
    freelocale(loc)
}

#[no_mangle]
pub unsafe extern "C" fn __uselocale(loc: locale_t) -> locale_t {
    uselocale(loc)
}

#[inline]
fn ascii_fold(c: u8) -> u8 {
    if c >= b'A' && c <= b'Z' { c | 0x20 } else { c }
}

#[no_mangle]
pub unsafe extern "C" fn strcasecmp(left: *const c_char, right: *const c_char) -> c_int {
    let mut i = 0usize;
    loop {
        let l = ascii_fold(*left.add(i) as u8);
        let r = ascii_fold(*right.add(i) as u8);
        if l != r { return l as c_int - r as c_int; }
        if l == 0 { return 0; }
        i += 1;
    }
}

#[no_mangle]
pub unsafe extern "C" fn strncasecmp(left: *const c_char, right: *const c_char, n: usize) -> c_int {
    let mut i = 0usize;
    while i < n {
        let l = ascii_fold(*left.add(i) as u8);
        let r = ascii_fold(*right.add(i) as u8);
        if l != r { return l as c_int - r as c_int; }
        if l == 0 { return 0; }
        i += 1;
    }
    0
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn strcasecmp_l(left: *const c_char, right: *const c_char, _loc: locale_t) -> c_int {
    strcasecmp(left, right)
}

#[no_mangle]
pub unsafe extern "C" fn __strcasecmp_l(left: *const c_char, right: *const c_char, loc: locale_t) -> c_int {
    strcasecmp_l(left, right, loc)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn strncasecmp_l(left: *const c_char, right: *const c_char, n: usize, _loc: locale_t) -> c_int {
    strncasecmp(left, right, n)
}

#[no_mangle]
pub unsafe extern "C" fn __strncasecmp_l(left: *const c_char, right: *const c_char, n: usize, loc: locale_t) -> c_int {
    strncasecmp_l(left, right, n, loc)
}

#[no_mangle]
pub unsafe extern "C" fn strcoll(left: *const c_char, right: *const c_char) -> c_int {
    strcmp(left as *const u8, right as *const u8)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn strcoll_l(left: *const c_char, right: *const c_char, _loc: locale_t) -> c_int {
    strcoll(left, right)
}

#[no_mangle]
pub unsafe extern "C" fn __strcoll_l(left: *const c_char, right: *const c_char, loc: locale_t) -> c_int {
    strcoll_l(left, right, loc)
}

unsafe fn c_locale_transform(dst: *mut c_char, src: *const c_char, n: usize) -> usize {
    let len = strlen(src);
    if !dst.is_null() && n != 0 {
        let copied = len.min(n - 1);
        core::ptr::copy_nonoverlapping(src, dst, copied);
        *dst.add(copied) = 0;
    }
    len
}

#[no_mangle]
pub unsafe extern "C" fn strxfrm(dst: *mut c_char, src: *const c_char, n: usize) -> usize {
    c_locale_transform(dst, src, n)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn strxfrm_l(dst: *mut c_char, src: *const c_char, n: usize, _loc: locale_t) -> usize {
    c_locale_transform(dst, src, n)
}

#[no_mangle]
pub unsafe extern "C" fn __strxfrm_l(dst: *mut c_char, src: *const c_char, n: usize, loc: locale_t) -> usize {
    strxfrm_l(dst, src, n, loc)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn strerror_l(errnum: c_int, _loc: locale_t) -> *mut c_char {
    strerror(errnum)
}

#[no_mangle]
pub unsafe extern "C" fn __strerror_l(errnum: c_int, loc: locale_t) -> *mut c_char {
    strerror_l(errnum, loc)
}

unsafe fn wide_casecmp(left: *const wchar_t, right: *const wchar_t, limit: Option<usize>) -> c_int {
    let mut i = 0usize;
    loop {
        if let Some(n) = limit {
            if i == n { return 0; }
        }
        let l = towlower(*left.add(i) as wint_t);
        let r = towlower(*right.add(i) as wint_t);
        if l != r { return if l < r { -1 } else { 1 }; }
        if l == 0 { return 0; }
        i += 1;
    }
}

#[no_mangle]
pub unsafe extern "C" fn wcscasecmp(left: *const wchar_t, right: *const wchar_t) -> c_int {
    wide_casecmp(left, right, None)
}

#[no_mangle]
pub unsafe extern "C" fn wcscasecmp_l(left: *const wchar_t, right: *const wchar_t, _loc: locale_t) -> c_int {
    wcscasecmp(left, right)
}

#[no_mangle]
pub unsafe extern "C" fn wcsncasecmp(left: *const wchar_t, right: *const wchar_t, n: usize) -> c_int {
    wide_casecmp(left, right, Some(n))
}

#[no_mangle]
pub unsafe extern "C" fn wcsncasecmp_l(left: *const wchar_t, right: *const wchar_t, n: usize, _loc: locale_t) -> c_int {
    wcsncasecmp(left, right, n)
}

#[no_mangle]
pub unsafe extern "C" fn wcscoll(left: *const wchar_t, right: *const wchar_t) -> c_int {
    wcscmp(left, right)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn wcscoll_l(left: *const wchar_t, right: *const wchar_t, _loc: locale_t) -> c_int {
    wcscoll(left, right)
}

// musl exposes this internal locale entry point for code compiled against its
// headers. The current locale model supports only the C/POSIX behavior, so it
// deliberately shares the same comparison implementation as `wcscoll_l`.
#[no_mangle]
pub unsafe extern "C" fn __wcscoll_l(left: *const wchar_t, right: *const wchar_t, loc: locale_t) -> c_int {
    wcscoll_l(left, right, loc)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn wcsxfrm_l(dst: *mut wchar_t, src: *const wchar_t, n: usize, _loc: locale_t) -> usize {
    wcsxfrm(dst, src, n)
}

#[no_mangle]
pub unsafe extern "C" fn __wcsxfrm_l(dst: *mut wchar_t, src: *const wchar_t, n: usize, loc: locale_t) -> usize {
    wcsxfrm_l(dst, src, n, loc)
}

#[no_mangle]
pub unsafe extern "C" fn wcsftime(
    dst: *mut wchar_t,
    maxsize: usize,
    format: *const wchar_t,
    time: *const tm,
) -> usize {
    if maxsize == 0 { return 0; }
    let format_len = wcslen(format);
    let narrow_format = malloc(format_len + 1) as *mut c_char;
    if narrow_format.is_null() { return 0; }
    for i in 0..format_len {
        let c = *format.add(i) as u32;
        if c > 0x7f {
            free(narrow_format as *mut c_void);
            return 0;
        }
        *narrow_format.add(i) = c as c_char;
    }
    *narrow_format.add(format_len) = 0;
    let narrow_result = malloc(maxsize) as *mut c_char;
    if narrow_result.is_null() {
        free(narrow_format as *mut c_void);
        return 0;
    }
    let len = strftime(narrow_result, maxsize, narrow_format, time);
    if len != 0 {
        for i in 0..=len { *dst.add(i) = *narrow_result.add(i) as u8 as wchar_t; }
    }
    free(narrow_result as *mut c_void);
    free(narrow_format as *mut c_void);
    len
}

#[no_mangle]
pub unsafe extern "C" fn __wcsftime_l(
    dst: *mut wchar_t,
    maxsize: usize,
    format: *const wchar_t,
    time: *const tm,
    _loc: locale_t,
) -> usize {
    wcsftime(dst, maxsize, format, time)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn wcsftime_l(
    dst: *mut wchar_t,
    maxsize: usize,
    format: *const wchar_t,
    time: *const tm,
    _loc: locale_t,
) -> usize {
    wcsftime(dst, maxsize, format, time)
}

#[no_mangle]
pub unsafe extern "C" fn strtod_l(s: *const c_char, end: *mut *mut c_char, _loc: locale_t) -> f64 {
    strtod(s, end)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __strtod_l(s: *const c_char, end: *mut *mut c_char, loc: locale_t) -> f64 {
    strtod_l(s, end, loc)
}

#[no_mangle]
pub unsafe extern "C" fn strtof_l(s: *const c_char, end: *mut *mut c_char, _loc: locale_t) -> f32 {
    strtof(s, end)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __strtof_l(s: *const c_char, end: *mut *mut c_char, loc: locale_t) -> f32 {
    strtof_l(s, end, loc)
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn strtold_l(s: *const c_char, end: *mut *mut c_char, _loc: locale_t) -> f64 {
    strtold(s, end)
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __strtold_l(s: *const c_char, end: *mut *mut c_char, loc: locale_t) -> f64 {
    strtold_l(s, end, loc)
}

#[cfg(not(target_arch = "x86_64"))]
#[no_mangle]
pub unsafe extern "C" fn strtold_l(s: *const c_char, end: *mut *mut c_char, _loc: locale_t) -> f128 {
    strtold(s, end)
}

#[cfg(not(target_arch = "x86_64"))]
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __strtold_l(s: *const c_char, end: *mut *mut c_char, loc: locale_t) -> f128 {
    strtold_l(s, end, loc)
}
