// wide-memory streams.  FILE internally transports encoded bytes, so this
// callback boundary incrementally decodes the UTF-8 stream into the caller's
// wchar_t allocation.  The exposed buffer is always NUL-terminated after a
// successful flush or close, while size counts wide characters, not bytes.

#[repr(C)]
struct CabiWmemstreamCookie {
    buffer_out: *mut *mut wchar_t,
    size_out: *mut usize,
    buffer: *mut wchar_t,
    length: usize,
    capacity: usize,
    state: c_uint,
}

unsafe fn cabi_wmemstream_append(cookie: *mut CabiWmemstreamCookie, value: wchar_t) -> bool {
    let required = match (*cookie).length.checked_add(2) {
        Some(value) => value,
        None => {
            ERRNO = ENOMEM;
            return false;
        }
    };
    if required > (*cookie).capacity {
        let mut capacity = if (*cookie).capacity == 0 { 16 } else { (*cookie).capacity };
        while capacity < required {
            capacity = match capacity.checked_mul(2) {
                Some(value) => value,
                None => {
                    ERRNO = ENOMEM;
                    return false;
                }
            };
        }
        let bytes = match capacity.checked_mul(core::mem::size_of::<wchar_t>()) {
            Some(value) => value,
            None => {
                ERRNO = ENOMEM;
                return false;
            }
        };
        let grown = realloc((*cookie).buffer as *mut c_void, bytes) as *mut wchar_t;
        if grown.is_null() {
            return false;
        }
        (*cookie).buffer = grown;
        (*cookie).capacity = capacity;
        *(*cookie).buffer_out = grown;
    }
    *(*cookie).buffer.add((*cookie).length) = value;
    (*cookie).length += 1;
    *(*cookie).buffer.add((*cookie).length) = 0;
    *(*cookie).size_out = (*cookie).length;
    true
}

unsafe extern "C" fn cabi_wmemstream_write(
    file: *mut FILE,
    bytes: *const u8,
    length: usize,
) -> usize {
    let cookie = (*file).cookie as *mut CabiWmemstreamCookie;
    if cookie.is_null() {
        ERRNO = EINVAL;
        (*file).flags |= F_ERR;
        (*file)._err = 1;
        (*file).wpos = core::ptr::null_mut();
        return 0;
    }
    let buffered = (*file).wpos as usize - (*file).wbase as usize;
    if buffered != 0 {
        (*file).wpos = (*file).wbase;
        if cabi_wmemstream_write(file, (*file).wbase, buffered) != buffered {
            return 0;
        }
    }
    if length == 0 {
        return 0;
    }

    let mut offset = 0usize;
    while offset < length {
        let mut wide = 0;
        let converted = mbrtowc(
            &mut wide,
            bytes.add(offset) as *const c_char,
            length - offset,
            &mut (*cookie).state,
        );
        if converted == !1usize {
            // The current byte chunk ended in a valid incomplete sequence;
            // retain mbrtowc's state for the next FILE write callback.
            return length;
        }
        if converted == !0usize || !cabi_wmemstream_append(cookie, wide) {
            (*file).flags |= F_ERR;
            (*file)._err = 1;
            (*file).wpos = core::ptr::null_mut();
            return 0;
        }
        offset += if converted == 0 { 1 } else { converted };
    }
    length
}

unsafe extern "C" fn cabi_wmemstream_close(file: *mut FILE) -> c_int {
    let cookie = (*file).cookie as *mut CabiWmemstreamCookie;
    if cookie.is_null() {
        return 0;
    }
    let result = if (*cookie).state != 0 {
        ERRNO = EILSEQ;
        -1
    } else if (*cookie).buffer.is_null() {
        let empty = calloc(1, core::mem::size_of::<wchar_t>()) as *mut wchar_t;
        if empty.is_null() {
            -1
        } else {
            (*cookie).buffer = empty;
            (*cookie).capacity = 1;
            *(*cookie).buffer_out = empty;
            *(*cookie).buffer.add((*cookie).length) = 0;
            *(*cookie).size_out = (*cookie).length;
            0
        }
    }
    else {
        *(*cookie).buffer.add((*cookie).length) = 0;
        *(*cookie).size_out = (*cookie).length;
        0
    };
    free(cookie as *mut c_void);
    (*file).cookie = core::ptr::null_mut();
    result
}

#[no_mangle]
pub unsafe extern "C" fn open_wmemstream(
    buffer_out: *mut *mut wchar_t,
    size_out: *mut usize,
) -> *mut FILE {
    if buffer_out.is_null() || size_out.is_null() {
        ERRNO = EINVAL;
        return core::ptr::null_mut();
    }
    let file = calloc(1, core::mem::size_of::<FILE>() + UNGET + BUFSIZ) as *mut FILE;
    if file.is_null() {
        return core::ptr::null_mut();
    }
    let cookie = calloc(1, core::mem::size_of::<CabiWmemstreamCookie>()) as *mut CabiWmemstreamCookie;
    if cookie.is_null() {
        free(file as *mut c_void);
        return core::ptr::null_mut();
    }
    init_file(
        file,
        -1,
        b"w\0".as_ptr() as *const c_char,
        Some(cabi_wmemstream_close),
        buf_ptr(file),
        BUFSIZ,
    );
    (*file).flags = F_NORD | F_SVB;
    (*file).lbf = -1;
    (*file).read_fn = None;
    (*file).seek_fn = None;
    (*file).write_fn = Some(cabi_wmemstream_write);
    (*file).cookie = cookie as *mut c_void;
    (*cookie).buffer_out = buffer_out;
    (*cookie).size_out = size_out;
    *buffer_out = core::ptr::null_mut();
    *size_out = 0;
    file
}
