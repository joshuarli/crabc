// kernel random-source entry points.

use super::{c_int, c_uint, c_void, syscall_result, EINTR, EIO_VAL, ERRNO};
//
// `getentropy` has the BSD 256-byte atomic request limit. It may need more
// than one kernel read, and EINTR is retried without exposing partial success.

#[inline]
unsafe fn cabi_getrandom_raw(buffer: *mut c_void, length: usize, flags: c_uint) -> i64 {
    match unsafe { crabc_core::rand::getrandom_raw(buffer.cast(), length, flags) } {
        Ok(length) => length as i64,
        Err(errno) => -(errno.raw() as i64),
    }
}

#[no_mangle]
pub unsafe extern "C" fn getrandom(
    buffer: *mut c_void,
    length: usize,
    flags: c_uint,
) -> isize {
    syscall_result(cabi_getrandom_raw(buffer, length, flags)) as isize
}

#[no_mangle]
pub unsafe extern "C" fn getentropy(buffer: *mut c_void, length: usize) -> c_int {
    if length > 256 {
        ERRNO = EIO_VAL;
        return -1;
    }

    let mut written = 0usize;
    while written < length {
        let result = getrandom((buffer as *mut u8).add(written) as *mut c_void, length - written, 0);
        if result < 0 {
            if ERRNO == EINTR {
                continue;
            }
            return -1;
        }
        written += result as usize;
    }
    0
}
