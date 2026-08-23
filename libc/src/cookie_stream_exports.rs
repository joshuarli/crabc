// GNU stdio cookie streams.  This follows musl's fopencookie buffering model:
// callback I/O owns the user cookie, while FILE retains its normal readahead
// and write-buffer behavior.  In particular, absent write callbacks are a
// successful discard sink, matching musl's public contract.

type CabiCookieReadFn = Option<unsafe extern "C" fn(*mut c_void, *mut c_char, usize) -> isize>;
type CabiCookieWriteFn = Option<unsafe extern "C" fn(*mut c_void, *const c_char, usize) -> isize>;
type CabiCookieSeekFn = Option<unsafe extern "C" fn(*mut c_void, *mut i64, c_int) -> c_int>;
type CabiCookieCloseFn = Option<unsafe extern "C" fn(*mut c_void) -> c_int>;

#[repr(C)]
pub struct CabiCookieIoFunctions {
    read: CabiCookieReadFn,
    write: CabiCookieWriteFn,
    seek: CabiCookieSeekFn,
    close: CabiCookieCloseFn,
}

#[repr(C)]
struct CabiCookieStream {
    user_cookie: *mut c_void,
    io: CabiCookieIoFunctions,
}

unsafe fn cabi_cookie_fail(file: *mut FILE, is_error: bool) -> usize {
    if is_error {
        (*file).flags |= F_ERR;
        (*file)._err = 1;
    } else {
        (*file).flags |= F_EOF;
        (*file)._eof = 1;
    }
    (*file).rpos = (*file).buf;
    (*file).rend = (*file).buf;
    0
}

unsafe extern "C" fn cabi_cookie_read(file: *mut FILE, output: *mut u8, length: usize) -> usize {
    let stream = (*file).cookie as *mut CabiCookieStream;
    let read = match (*stream).io.read {
        Some(callback) => callback,
        None => return cabi_cookie_fail(file, true),
    };

    // musl reads one direct chunk, then fills FILE's readahead buffer.  Keeping
    // that shape makes fgetc/fread and seek-offset correction agree on where
    // the underlying user cookie is positioned.
    let direct_length = if length > 1 { length - 1 } else { 1 };
    let first = read((*stream).user_cookie, output as *mut c_char, direct_length);
    if first <= 0 {
        return cabi_cookie_fail(file, first < 0);
    }
    let first = first as usize;
    if first > direct_length {
        // A callback exceeding its supplied buffer violates the GNU callback
        // contract.  Do not manufacture an out-of-bounds successful result.
        ERRNO = EIO_VAL;
        return cabi_cookie_fail(file, true);
    }
    let mut delivered = first;
    let remaining = length.saturating_sub(first);

    (*file).rpos = (*file).buf;
    let readahead = read(
        (*stream).user_cookie,
        (*file).rpos as *mut c_char,
        (*file).buf_size,
    );
    if readahead <= 0 {
        if readahead < 0 {
            (*file).flags |= F_ERR;
            (*file)._err = 1;
        } else {
            (*file).flags |= F_EOF;
            (*file)._eof = 1;
        }
        (*file).rend = (*file).rpos;
        return delivered;
    }
    let readahead = readahead as usize;
    if readahead > (*file).buf_size {
        ERRNO = EIO_VAL;
        return cabi_cookie_fail(file, true);
    }
    (*file).rend = (*file).rpos.add(readahead);
    let copied = core::cmp::min(remaining, readahead);
    if copied != 0 {
        core::ptr::copy_nonoverlapping((*file).rpos, output.add(delivered), copied);
        delivered += copied;
        (*file).rpos = (*file).rpos.add(copied);
    }
    delivered
}

unsafe extern "C" fn cabi_cookie_write(file: *mut FILE, input: *const u8, length: usize) -> usize {
    let stream = (*file).cookie as *mut CabiCookieStream;
    let write = match (*stream).io.write {
        Some(callback) => callback,
        // This apparent no-op is the documented musl behavior for a cookie
        // stream whose write operation is omitted.
        None => return length,
    };
    let buffered = (*file).wpos as usize - (*file).wbase as usize;
    if buffered != 0 {
        (*file).wpos = (*file).wbase;
        if cabi_cookie_write(file, (*file).wbase, buffered) < buffered {
            return 0;
        }
    }
    let result = write((*stream).user_cookie, input as *const c_char, length);
    if result < 0 || result as usize > length {
        if result >= 0 {
            ERRNO = EIO_VAL;
        }
        (*file).wpos = core::ptr::null_mut();
        (*file).wbase = core::ptr::null_mut();
        (*file).wend = core::ptr::null_mut();
        (*file).flags |= F_ERR;
        (*file)._err = 1;
        return 0;
    }
    result as usize
}

unsafe extern "C" fn cabi_cookie_seek(file: *mut FILE, offset: i64, whence: c_int) -> i64 {
    if whence < SEEK_SET || whence > SEEK_END {
        ERRNO = EINVAL;
        return -1;
    }
    let stream = (*file).cookie as *mut CabiCookieStream;
    let seek = match (*stream).io.seek {
        Some(callback) => callback,
        None => {
            ERRNO = ENOTSUP;
            return -1;
        }
    };
    let mut result_offset = offset;
    if seek((*stream).user_cookie, &mut result_offset, whence) < 0 {
        return -1;
    }
    result_offset
}

unsafe extern "C" fn cabi_cookie_close(file: *mut FILE) -> c_int {
    let stream = (*file).cookie as *mut CabiCookieStream;
    match (*stream).io.close {
        Some(callback) => callback((*stream).user_cookie),
        None => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn fopencookie(
    user_cookie: *mut c_void,
    mode: *const c_char,
    io: CabiCookieIoFunctions,
) -> *mut FILE {
    if mode.is_null() || (*mode != b'r' as c_char && *mode != b'w' as c_char && *mode != b'a' as c_char) {
        ERRNO = EINVAL;
        return core::ptr::null_mut();
    }

    let file_size = core::mem::size_of::<FILE>() + UNGET + BUFSIZ;
    let allocation = match file_size.checked_add(core::mem::size_of::<CabiCookieStream>()) {
        Some(size) => size,
        None => {
            ERRNO = ENOMEM;
            return core::ptr::null_mut();
        }
    };
    let file = calloc(1, allocation) as *mut FILE;
    if file.is_null() {
        ERRNO = ENOMEM;
        return core::ptr::null_mut();
    }
    let stream = (file as *mut u8).add(file_size) as *mut CabiCookieStream;
    core::ptr::write(stream, CabiCookieStream { user_cookie, io });

    init_file(
        file,
        -1,
        mode,
        Some(cabi_cookie_close),
        buf_ptr(file),
        BUFSIZ,
    );
    (*file).cookie = stream as *mut c_void;
    (*file).read_fn = Some(cabi_cookie_read);
    (*file).write_fn = Some(cabi_cookie_write);
    (*file).seek_fn = Some(cabi_cookie_seek);
    (*file).lbf = -1;
    file
}
