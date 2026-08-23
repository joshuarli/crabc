// memory-management syscalls.  mmap/munmap already have weak raw wrappers
// in regression_stubs.rs; this file supplies the remaining VM operations and
// keeps their C return/errno contracts at the public boundary.
// mlock2 and remap_file_pages are direct Linux interfaces: valid calls return
// zero, while all kernel failures pass through syscall_result unchanged.













const CABI_SYS_MPROTECT: i64 = 226;
const CABI_SYS_MADVISE: i64 = 233;
const CABI_SYS_MINCORE: i64 = 232;
const CABI_SYS_MSYNC: i64 = 227;
const CABI_SYS_MREMAP: i64 = 216;
const CABI_SYS_MLOCK: i64 = 228;
const CABI_SYS_MUNLOCK: i64 = 229;
const CABI_SYS_MLOCKALL: i64 = 230;
const CABI_SYS_MUNLOCKALL: i64 = 231;
const CABI_SYS_MLOCK2: i64 = 284;
const CABI_SYS_REMAP_FILE_PAGES: i64 = 234;

const CABI_MREMAP_FIXED: c_int = 2;
// POSIX_MADV_DONTNEED is intentionally distinct from Linux MADV_DONTNEED.
// musl keeps this POSIX advisory as a no-op instead of discarding anonymous
// pages through the Linux syscall.
const CABI_POSIX_MADV_DONTNEED: c_int = 4;

#[inline]
unsafe fn cabi_mprotect(addr: *mut c_void, len: SizeT, prot: c_int) -> i64 {
    match unsafe { crabc_core::mm::mprotect_raw(addr.cast(), len, prot as u32) } {
        Ok(()) => 0,
        Err(errno) => -(errno.raw() as i64),
    }
}

#[inline]
unsafe fn cabi_madvise(addr: *mut c_void, len: SizeT, advice: c_int) -> i64 {
    aarch64_syscall::syscall3(CABI_SYS_MADVISE, addr as i64, len as i64, advice as i64)
}

#[inline]
unsafe fn cabi_mincore(addr: *mut c_void, len: SizeT, vec: *mut u8) -> i64 {
    aarch64_syscall::syscall3(CABI_SYS_MINCORE, addr as i64, len as i64, vec as i64)
}

#[inline]
unsafe fn cabi_msync(addr: *mut c_void, len: SizeT, flags: c_int) -> i64 {
    aarch64_syscall::syscall3(CABI_SYS_MSYNC, addr as i64, len as i64, flags as i64)
}

#[inline]
unsafe fn cabi_mremap(
    old_address: *mut c_void,
    old_size: SizeT,
    new_size: SizeT,
    flags: c_int,
    new_address: *mut c_void,
) -> i64 {
    aarch64_syscall::syscall5(
        CABI_SYS_MREMAP,
        old_address as i64,
        old_size as i64,
        new_size as i64,
        flags as i64,
        new_address as i64,
    )
}

#[inline]
unsafe fn cabi_mlock(addr: *const c_void, len: SizeT) -> i64 {
    aarch64_syscall::syscall2(CABI_SYS_MLOCK, addr as i64, len as i64)
}

#[inline]
unsafe fn cabi_munlock(addr: *const c_void, len: SizeT) -> i64 {
    aarch64_syscall::syscall2(CABI_SYS_MUNLOCK, addr as i64, len as i64)
}

#[inline]
unsafe fn cabi_mlockall(flags: c_int) -> i64 {
    aarch64_syscall::syscall1(CABI_SYS_MLOCKALL, flags as i64)
}

#[inline]
unsafe fn cabi_munlockall() -> i64 {
    aarch64_syscall::syscall0(CABI_SYS_MUNLOCKALL)
}

#[inline]
unsafe fn cabi_mlock2(addr: *const c_void, len: SizeT, flags: c_uint) -> i64 {
    aarch64_syscall::syscall3(CABI_SYS_MLOCK2, addr as i64, len as i64, flags as i64)
}

#[inline]
unsafe fn cabi_remap_file_pages(
    addr: *mut c_void,
    size: SizeT,
    prot: c_int,
    pgoff: SizeT,
    flags: c_int,
) -> i64 {
    aarch64_syscall::syscall5(
        CABI_SYS_REMAP_FILE_PAGES,
        addr as i64,
        size as i64,
        prot as i64,
        pgoff as i64,
        flags as i64,
    )
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn mprotect(
    addr: *mut c_void,
    len: SizeT,
    prot: c_int,
) -> c_int {
    syscall_result(cabi_mprotect(addr, len, prot)) as c_int
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn madvise(
    addr: *mut c_void,
    len: SizeT,
    advice: c_int,
) -> c_int {
    syscall_result(cabi_madvise(addr, len, advice)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn posix_madvise(
    addr: *mut c_void,
    len: SizeT,
    advice: c_int,
) -> c_int {
    if advice == CABI_POSIX_MADV_DONTNEED {
        return 0;
    }
    let result = cabi_madvise(addr, len, advice);
    if result < 0 && result >= -4095 {
        (-result) as c_int
    } else {
        result as c_int
    }
}

#[no_mangle]
pub unsafe extern "C" fn mincore(
    addr: *mut c_void,
    len: SizeT,
    vec: *mut u8,
) -> c_int {
    syscall_result(cabi_mincore(addr, len, vec)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn msync(
    addr: *mut c_void,
    len: SizeT,
    flags: c_int,
) -> c_int {
    syscall_result(cabi_msync(addr, len, flags)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn mlock(addr: *const c_void, len: SizeT) -> c_int {
    syscall_result(cabi_mlock(addr, len)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn munlock(addr: *const c_void, len: SizeT) -> c_int {
    syscall_result(cabi_munlock(addr, len)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn mlockall(flags: c_int) -> c_int {
    syscall_result(cabi_mlockall(flags)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn munlockall() -> c_int {
    syscall_result(cabi_munlockall()) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn mlock2(addr: *const c_void, len: SizeT, flags: c_uint) -> c_int {
    syscall_result(cabi_mlock2(addr, len, flags)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn remap_file_pages(
    addr: *mut c_void,
    size: SizeT,
    prot: c_int,
    pgoff: SizeT,
    flags: c_int,
) -> c_int {
    syscall_result(cabi_remap_file_pages(addr, size, prot, pgoff, flags)) as c_int
}

// mremap has an optional fifth argument used only with MREMAP_FIXED.  Keep the
// C variadic boundary so four-argument callers remain ABI-correct.
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn mremap(
    old_address: *mut c_void,
    old_size: SizeT,
    new_size: SizeT,
    flags: c_int,
    mut args: ...,
) -> *mut c_void {
    let new_address = if flags & CABI_MREMAP_FIXED != 0 {
        args.next_arg::<*mut c_void>()
    } else {
        core::ptr::null_mut()
    };
    syscall_result(cabi_mremap(old_address, old_size, new_size, flags, new_address)) as *mut c_void
}
