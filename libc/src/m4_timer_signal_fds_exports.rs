// M4 Linux timerfd and signalfd exports.
//
// These wrappers preserve the native Linux layouts at the C ABI boundary and
// only translate the kernel's negative errno convention.  `signalfd` is
// implemented through signalfd4 on every supported architecture: unlike the
// older signalfd syscall, signalfd4 accepts the flags exposed by musl's
// public API.  The kernel sigset size is deliberately the one-word
// representation used by Linux, not the larger public userspace sigset_t.

#[repr(C)]
pub struct M4Itimerspec {
    pub it_interval: timespec,
    pub it_value: timespec,
}

#[cfg(target_arch = "x86_64")]
const M4_SYS_TIMERFD_CREATE: i64 = 283;
#[cfg(target_arch = "x86_64")]
const M4_SYS_TIMERFD_SETTIME: i64 = 286;
#[cfg(target_arch = "x86_64")]
const M4_SYS_TIMERFD_GETTIME: i64 = 287;
#[cfg(target_arch = "x86_64")]
const M4_SYS_SIGNALFD4: i64 = 289;

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_TIMERFD_CREATE: i64 = 85;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_TIMERFD_SETTIME: i64 = 86;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_TIMERFD_GETTIME: i64 = 87;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_SIGNALFD4: i64 = 74;

#[inline]
#[cfg(target_arch = "aarch64")]
unsafe fn m4_timerfd_create(clockid: c_int, flags: c_int) -> i64 {
    match crabc_core::time::timerfd_create(clockid, flags as u32) {
        Ok(fd) => fd as i64,
        Err(errno) => -(errno.raw() as i64),
    }
}

#[inline]
#[cfg(not(target_arch = "aarch64"))]
unsafe fn m4_timerfd_create(clockid: c_int, flags: c_int) -> i64 {
    <Arch as Syscalls>::syscall2(
        M4_SYS_TIMERFD_CREATE,
        clockid as i64,
        flags as i64,
    )
}

#[inline]
#[cfg(target_arch = "aarch64")]
unsafe fn m4_timerfd_settime(
    fd: c_int,
    flags: c_int,
    new_value: *const M4Itimerspec,
    old_value: *mut M4Itimerspec,
) -> i64 {
    match crabc_core::time::timerfd_settime_raw(
        fd,
        flags as u32,
        new_value.cast(),
        old_value.cast(),
    ) {
        Ok(()) => 0,
        Err(errno) => -(errno.raw() as i64),
    }
}

#[inline]
#[cfg(not(target_arch = "aarch64"))]
unsafe fn m4_timerfd_settime(
    fd: c_int,
    flags: c_int,
    new_value: *const M4Itimerspec,
    old_value: *mut M4Itimerspec,
) -> i64 {
    <Arch as Syscalls>::syscall4(
        M4_SYS_TIMERFD_SETTIME,
        fd as i64,
        flags as i64,
        new_value as i64,
        old_value as i64,
    )
}

#[inline]
#[cfg(target_arch = "aarch64")]
unsafe fn m4_timerfd_gettime(fd: c_int, current_value: *mut M4Itimerspec) -> i64 {
    match crabc_core::time::timerfd_gettime_raw(fd, current_value.cast()) {
        Ok(()) => 0,
        Err(errno) => -(errno.raw() as i64),
    }
}

#[inline]
#[cfg(not(target_arch = "aarch64"))]
unsafe fn m4_timerfd_gettime(fd: c_int, current_value: *mut M4Itimerspec) -> i64 {
    <Arch as Syscalls>::syscall2(
        M4_SYS_TIMERFD_GETTIME,
        fd as i64,
        current_value as i64,
    )
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn m4_signalfd4(
    fd: c_int,
    mask: *const c_void,
    _size: usize,
    flags: c_int,
) -> i64 {
    match unsafe { crabc_core::signal::signalfd4_raw(fd, mask.cast(), flags as u32) } {
        Ok(fd) => fd as i64,
        Err(errno) => -(errno.raw() as i64),
    }
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
unsafe fn m4_signalfd4(
    fd: c_int,
    mask: *const c_void,
    size: usize,
    flags: c_int,
) -> i64 {
    <Arch as Syscalls>::syscall4(
        M4_SYS_SIGNALFD4,
        fd as i64,
        mask as i64,
        size as i64,
        flags as i64,
    )
}

#[no_mangle]
pub unsafe extern "C" fn timerfd_create(clockid: c_int, flags: c_int) -> c_int {
    syscall_result(m4_timerfd_create(clockid, flags)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn timerfd_settime(
    fd: c_int,
    flags: c_int,
    new_value: *const M4Itimerspec,
    old_value: *mut M4Itimerspec,
) -> c_int {
    syscall_result(m4_timerfd_settime(fd, flags, new_value, old_value)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn timerfd_gettime(
    fd: c_int,
    current_value: *mut M4Itimerspec,
) -> c_int {
    syscall_result(m4_timerfd_gettime(fd, current_value)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn signalfd(
    fd: c_int,
    mask: *const SigSetT,
    flags: c_int,
) -> c_int {
    syscall_result(m4_signalfd4(
        fd,
        mask as *const c_void,
        core::mem::size_of::<SigSetT>(),
        flags,
    )) as c_int
}
