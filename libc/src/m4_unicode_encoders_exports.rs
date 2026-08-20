// C11 UTF-16/UTF-32 conversion entry points.
//
// These follow musl's UTF-8 state conventions.  In particular, mbrtowc uses
// states with the high bit set while decoding an incomplete UTF-8 sequence;
// the C11 UTF-16 adapter uses positive states for a pending low surrogate.

static mut M4_C16RTOMB_INTERNAL_STATE: c_uint = 0;
static mut M4_MBRTOC16_INTERNAL_STATE: c_uint = 0;
static mut M4_MBRTOC32_INTERNAL_STATE: c_uint = 0;

#[no_mangle]
pub unsafe extern "C" fn c16rtomb(
    s: *mut c_char,
    c16: u16,
    mut ps: *mut c_uint,
) -> usize {
    if ps.is_null() {
        ps = core::ptr::addr_of_mut!(M4_C16RTOMB_INTERNAL_STATE);
    }
    let state = &mut *ps;
    let c16 = c16 as u32;

    // A null destination is the state-reset query.  A pending high surrogate
    // cannot be reset implicitly: musl reports EILSEQ and clears the state.
    if s.is_null() {
        if *state != 0 {
            *state = 0;
            ERRNO = EILSEQ;
            return !0usize;
        }
        return 1;
    }

    // Save the scalar value represented by a high surrogate.  The shift makes
    // combining the following low surrogate a single addition below.
    if *state == 0 && c16.wrapping_sub(0xd800) < 0x400 {
        *state = c16.wrapping_sub(0xd7c0) << 10;
        return 0;
    }

    let wc = if *state != 0 {
        if c16.wrapping_sub(0xdc00) >= 0x400 {
            *state = 0;
            ERRNO = EILSEQ;
            return !0usize;
        }
        let wc = state.wrapping_add(c16).wrapping_sub(0xdc00);
        *state = 0;
        wc
    } else {
        c16
    };

    // c16 is either a scalar BMP value or a completed surrogate pair here.
    wcrtomb(s, wc as c_int, core::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn c32rtomb(
    s: *mut c_char,
    c32: u32,
    ps: *mut c_uint,
) -> usize {
    // wcrtomb performs the scalar-value and current-locale validation.  The
    // ABI uses 32-bit wchar_t, so this cast preserves every char32_t value.
    wcrtomb(s, c32 as c_int, ps)
}

#[no_mangle]
pub unsafe extern "C" fn mbrtoc16(
    pc16: *mut u16,
    s: *const c_char,
    n: usize,
    mut ps: *mut c_uint,
) -> usize {
    if ps.is_null() {
        ps = core::ptr::addr_of_mut!(M4_MBRTOC16_INTERNAL_STATE);
    }
    let pending = &mut *ps;

    // A null source asks for the conversion status.  Going through the empty
    // string also emits a pending low surrogate with the required -3 result.
    if s.is_null() {
        return mbrtoc16(core::ptr::null_mut(), b"\0".as_ptr() as *const c_char, 1, ps);
    }

    // mbrtowc's incomplete UTF-8 states have their high bit set.  Positive
    // nonzero values therefore unambiguously represent our pending surrogate.
    if (*pending as c_int) > 0 {
        if !pc16.is_null() {
            *pc16 = *pending as u16;
        }
        *pending = 0;
        return !2usize;
    }

    let mut wc: wchar_t = 0;
    let ret = mbrtowc(&mut wc, s, n, ps);
    if ret <= 4 {
        let mut value = wc as u32;
        if value >= 0x10000 {
            *pending = (value & 0x3ff) + 0xdc00;
            value = 0xd7c0 + (value >> 10);
        }
        if !pc16.is_null() {
            *pc16 = value as u16;
        }
    }
    ret
}

#[no_mangle]
pub unsafe extern "C" fn mbrtoc32(
    pc32: *mut u32,
    s: *const c_char,
    n: usize,
    mut ps: *mut c_uint,
) -> usize {
    if ps.is_null() {
        ps = core::ptr::addr_of_mut!(M4_MBRTOC32_INTERNAL_STATE);
    }
    if s.is_null() {
        return mbrtoc32(core::ptr::null_mut(), b"\0".as_ptr() as *const c_char, 1, ps);
    }

    let mut wc: wchar_t = 0;
    let ret = mbrtowc(&mut wc, s, n, ps);
    if ret <= 4 && !pc32.is_null() {
        *pc32 = wc as u32;
    }
    ret
}
