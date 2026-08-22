// M4 program-break exports.
//
// musl's allocator is mmap-backed and deliberately does not expose a usable
// `brk` growth interface.  Keep the public legacy exports at musl's exact
// contract: `brk` and every non-zero `sbrk` request fail with ENOMEM, while
// `sbrk(0)` remains the one raw-kernel query.

#[cfg(target_arch = "x86_64")]
const M4_SYS_BRK: i64 = 12;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_BRK: i64 = 214;

#[inline]
unsafe fn m4_break(address: *mut c_void) -> *mut c_void {
    <Arch as Syscalls>::syscall1(M4_SYS_BRK, address as i64) as usize as *mut c_void
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
        return m4_break(core::ptr::null_mut());
    }
    ERRNO = ENOMEM;
    usize::MAX as *mut c_void
}
