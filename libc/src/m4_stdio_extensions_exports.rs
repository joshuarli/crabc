// M4 formatted-allocation and stdio_ext exports.
//
// These are the stateful stdio extensions whose behavior can be expressed in
// terms of this libc's FILE layout.  The unlocked entry points intentionally
// share the ordinary operations: this FILE implementation has no locking
// boundary to remove, just as musl's weak aliases do.

#[no_mangle]
pub unsafe extern "C" fn vasprintf(
    strp: *mut *mut c_char,
    fmt: *const c_char,
    mut args: VaList,
) -> c_int {
    if strp.is_null() {
        ERRNO = EINVAL;
        return -1;
    }

    // The first pass is the same va_copy/two-pass protocol used by musl.  It
    // computes the exact allocation size without writing through a null buf.
    let mut probe = args.clone();
    let needed = format_to_buf(core::ptr::null_mut(), 0, fmt, &mut probe);
    if needed < 0 {
        *strp = core::ptr::null_mut();
        return -1;
    }
    let allocation = match (needed as usize).checked_add(1) {
        Some(size) => size,
        None => {
            *strp = core::ptr::null_mut();
            ERRNO = ENOMEM;
            return -1;
        }
    };

    let output = malloc(allocation) as *mut c_char;
    if output.is_null() {
        *strp = core::ptr::null_mut();
        ERRNO = ENOMEM;
        return -1;
    }

    let written = format_to_buf(output as *mut u8, allocation, fmt, &mut args);
    if written < 0 {
        free(output as *mut c_void);
        *strp = core::ptr::null_mut();
        return -1;
    }
    *strp = output;
    written
}

#[no_mangle]
pub unsafe extern "C" fn asprintf(
    strp: *mut *mut c_char,
    fmt: *const c_char,
    args: ...,
) -> c_int {
    vasprintf(strp, fmt, args)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn fflush_unlocked(stream: *mut FILE) -> c_int {
    fflush(stream)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn fileno_unlocked(stream: *mut FILE) -> c_int {
    fileno(stream)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn fread_unlocked(
    ptr: *mut c_void,
    size: usize,
    nmemb: usize,
    stream: *mut FILE,
) -> usize {
    fread(ptr, size, nmemb, stream)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn fwrite_unlocked(
    ptr: *const c_void,
    size: usize,
    nmemb: usize,
    stream: *mut FILE,
) -> usize {
    fwrite(ptr, size, nmemb, stream)
}

#[no_mangle]
pub unsafe extern "C" fn _flushlbf() {
    fflush(core::ptr::null_mut());
}

// The lock argument is intentionally ignored.  musl's stdio extension also
// returns zero here because its FILE lock is not a user-selectable policy.
#[no_mangle]
pub unsafe extern "C" fn __fsetlocking(stream: *mut FILE, type_: c_int) -> c_int {
    let _ = (stream, type_);
    0
}

#[no_mangle]
pub unsafe extern "C" fn __fwriting(stream: *mut FILE) -> c_int {
    if ((*stream).flags & F_NORD) != 0 || !(*stream).wend.is_null() { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "C" fn __freading(stream: *mut FILE) -> c_int {
    if ((*stream).flags & F_NOWR) != 0 || !(*stream).rend.is_null() { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "C" fn __freadable(stream: *mut FILE) -> c_int {
    if ((*stream).flags & F_NORD) == 0 { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "C" fn __fwritable(stream: *mut FILE) -> c_int {
    if ((*stream).flags & F_NOWR) == 0 { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "C" fn __flbf(stream: *mut FILE) -> c_int {
    if (*stream).lbf >= 0 { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "C" fn __fbufsize(stream: *mut FILE) -> usize {
    (*stream).buf_size
}

#[no_mangle]
pub unsafe extern "C" fn __fpending(stream: *mut FILE) -> usize {
    if (*stream).wend.is_null() || (*stream).wpos.is_null() || (*stream).wbase.is_null() {
        0
    } else {
        ((*stream).wpos as usize).wrapping_sub((*stream).wbase as usize)
    }
}

#[no_mangle]
pub unsafe extern "C" fn __fpurge(stream: *mut FILE) -> c_int {
    (*stream).wpos = core::ptr::null_mut();
    (*stream).wbase = core::ptr::null_mut();
    (*stream).wend = core::ptr::null_mut();
    (*stream).rpos = core::ptr::null_mut();
    (*stream).rend = core::ptr::null_mut();
    (*stream).ungotten_count = 0;
    0
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn fpurge(stream: *mut FILE) -> c_int {
    __fpurge(stream)
}

#[no_mangle]
pub unsafe extern "C" fn __freadahead(stream: *mut FILE) -> usize {
    if (*stream).rend.is_null() || (*stream).rpos.is_null() {
        0
    } else {
        ((*stream).rend as usize).wrapping_sub((*stream).rpos as usize)
    }
}

#[no_mangle]
pub unsafe extern "C" fn __freadptr(
    stream: *mut FILE,
    sizep: *mut usize,
) -> *const c_char {
    if (*stream).rpos.is_null() || (*stream).rpos == (*stream).rend {
        return core::ptr::null();
    }
    if !sizep.is_null() {
        *sizep = __freadahead(stream);
    }
    (*stream).rpos as *const c_char
}

#[no_mangle]
pub unsafe extern "C" fn __freadptrinc(stream: *mut FILE, inc: usize) {
    if !(*stream).rpos.is_null() {
        (*stream).rpos = (*stream).rpos.add(inc);
    }
}

#[no_mangle]
pub unsafe extern "C" fn __fseterr(stream: *mut FILE) {
    (*stream).flags |= F_ERR;
    (*stream)._err = 1;
}
