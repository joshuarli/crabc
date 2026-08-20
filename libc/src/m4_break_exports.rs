// M4 program-break exports.
//
// Linux's brk syscall returns the current program break both on a query and
// on allocation failure; libc supplies the POSIX `-1`/ENOMEM convention by
// comparing that result with the requested address. The allocator remains
// mmap-backed, so these interfaces retain their process ABI contract without
// introducing a second allocator ownership domain.

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
    if m4_break(address) == address {
        0
    } else {
        ERRNO = ENOMEM;
        -1
    }
}

#[no_mangle]
pub unsafe extern "C" fn sbrk(increment: isize) -> *mut c_void {
    let old = m4_break(core::ptr::null_mut());
    if increment == 0 {
        return old;
    }
    let requested = match (old as usize).checked_add_signed(increment) {
        Some(address) => address as *mut c_void,
        None => {
            ERRNO = ENOMEM;
            return usize::MAX as *mut c_void;
        }
    };
    if m4_break(requested) == requested {
        old
    } else {
        ERRNO = ENOMEM;
        usize::MAX as *mut c_void
    }
}
