// M4 kernel random-source entry points.
//
// `getentropy` has the BSD 256-byte atomic request limit. It may need more
// than one kernel read, and EINTR is retried without exposing partial success.

#[cfg(target_arch = "x86_64")]
const M4_SYS_GETRANDOM: i64 = 318;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_GETRANDOM: i64 = 278;

#[inline]
unsafe fn m4_getrandom_raw(buffer: *mut c_void, length: usize, flags: c_uint) -> i64 {
    <Arch as Syscalls>::syscall3(
        M4_SYS_GETRANDOM,
        buffer as i64,
        length as i64,
        flags as i64,
    )
}

#[no_mangle]
pub unsafe extern "C" fn getrandom(
    buffer: *mut c_void,
    length: usize,
    flags: c_uint,
) -> isize {
    syscall_result(m4_getrandom_raw(buffer, length, flags)) as isize
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
