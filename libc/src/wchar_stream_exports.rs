// bounded wide/multibyte conversion and tokenization exports.
//
// Unlike the null-terminated `*srt*` family, these interfaces must preserve
// the input pointer at an incomplete character or output-boundary. Keeping
// that state explicit makes callers able to resume conversion with the same
// `mbstate_t` as POSIX requires.

#[no_mangle]
pub unsafe extern "C" fn mbsnrtowcs(
    dst: *mut wchar_t,
    src: *mut *const c_char,
    nmc: usize,
    len: usize,
    state: *mut c_uint,
) -> usize {
    if src.is_null() || (*src).is_null() {
        return 0;
    }
    let state = if state.is_null() {
        &raw mut MB_STATE
    } else {
        state
    };
    let mut input = *src;
    let mut remaining = nmc;
    let mut converted = 0usize;

    while remaining > 0 && (dst.is_null() || converted < len) {
        let mut wide = 0;
        let available = core::cmp::min(remaining, 4);
        let result = mbrtowc(&mut wide, input, available, state);
        if result == !0usize {
            *src = input;
            return !0usize;
        }
        if result == !1usize {
            *src = input;
            return converted;
        }
        if result == 0 {
            if !dst.is_null() {
                *dst.add(converted) = 0;
            }
            *src = core::ptr::null();
            return converted;
        }
        if !dst.is_null() {
            *dst.add(converted) = wide;
        }
        input = input.add(result);
        remaining -= result;
        converted += 1;
    }
    *src = input;
    converted
}

#[no_mangle]
pub unsafe extern "C" fn wcsnrtombs(
    dst: *mut c_char,
    src: *mut *const wchar_t,
    nwc: usize,
    len: usize,
    state: *mut c_uint,
) -> usize {
    if src.is_null() || (*src).is_null() {
        return 0;
    }
    let mut input = *src;
    let mut remaining = nwc;
    let mut written = 0usize;
    let state = if state.is_null() {
        &raw mut MB_STATE
    } else {
        state
    };

    while remaining > 0 {
        let wide = *input;
        let mut encoded = [0 as c_char; 4];
        let count = wcrtomb(encoded.as_mut_ptr(), wide, state);
        if count == !0usize {
            *src = input;
            return !0usize;
        }
        if !dst.is_null() && written.saturating_add(count) > len {
            *src = input;
            return written;
        }
        if !dst.is_null() {
            core::ptr::copy_nonoverlapping(encoded.as_ptr(), dst.add(written), count);
        }
        if wide == 0 {
            *src = core::ptr::null();
            return written;
        }
        written += count;
        input = input.add(1);
        remaining -= 1;
    }
    *src = input;
    written
}

#[no_mangle]
pub unsafe extern "C" fn wcstok(
    input: *mut wchar_t,
    delimiters: *const wchar_t,
    state: *mut *mut wchar_t,
) -> *mut wchar_t {
    if delimiters.is_null() || state.is_null() {
        return core::ptr::null_mut();
    }
    let mut cursor = if input.is_null() { *state } else { input };
    if cursor.is_null() {
        return core::ptr::null_mut();
    }

    while *cursor != 0 {
        let mut delimiter = delimiters;
        while *delimiter != 0 && *delimiter != *cursor {
            delimiter = delimiter.add(1);
        }
        if *delimiter == 0 {
            break;
        }
        cursor = cursor.add(1);
    }
    if *cursor == 0 {
        *state = core::ptr::null_mut();
        return core::ptr::null_mut();
    }

    let token = cursor;
    while *cursor != 0 {
        let mut delimiter = delimiters;
        while *delimiter != 0 && *delimiter != *cursor {
            delimiter = delimiter.add(1);
        }
        if *delimiter != 0 {
            *cursor = 0;
            *state = cursor.add(1);
            return token;
        }
        cursor = cursor.add(1);
    }
    *state = core::ptr::null_mut();
    token
}
