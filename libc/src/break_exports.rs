// program-break exports.
//
// musl's allocator is mmap-backed and deliberately does not expose a usable
// `brk` growth interface.  Keep the public legacy exports at musl's exact
// contract: `brk` and every non-zero `sbrk` request fail with ENOMEM, while
// `sbrk(0)` remains the one raw-kernel query.

use super::{aarch64, c_int, c_void, ENOMEM, ERRNO};

const CABI_SYS_BRK: i64 = 214;

#[inline]
unsafe fn cabi_break(address: *mut c_void) -> *mut c_void {
    aarch64::syscall::syscall1(CABI_SYS_BRK, address as i64) as usize as *mut c_void
}

#[no_mangle]
pub unsafe extern "C" fn brk(address: *mut c_void) -> c_int {
    let _ = address;
    ERRNO = ENOMEM;
    -1
}

#[no_mangle]
pub unsafe extern "C" fn sbrk(increment: isize) -> *mut c_void {
    if increment == 0 {
        return cabi_break(core::ptr::null_mut());
    }
    ERRNO = ENOMEM;
    usize::MAX as *mut c_void
}
