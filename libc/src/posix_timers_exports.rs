// POSIX process timers backed directly by Linux's timer_* syscalls.
//
// Linux exposes timer IDs as non-negative ints, while the musl public ABI
// exposes timer_t as an opaque pointer.  Keep the kernel ID in a local int
// during timer_create and publish it as the pointer-sized opaque value only
// after the syscall succeeds.  This avoids writing a four-byte kernel ID
// into the caller's pointer-sized timer_t object.







const CABI_SYS_TIMER_CREATE: i64 = 107;
const CABI_SYS_TIMER_SETTIME: i64 = 110;
const CABI_SYS_TIMER_GETTIME: i64 = 108;
const CABI_SYS_TIMER_GETOVERRUN: i64 = 109;
const CABI_SYS_TIMER_DELETE: i64 = 111;

#[inline]
unsafe fn cabi_timer_create(
    clockid: c_int,
    event: *const c_void,
    timerid: *mut c_int,
) -> i64 {
    aarch64::syscall::syscall3(
        CABI_SYS_TIMER_CREATE,
        clockid as i64,
        event as i64,
        timerid as i64,
    )
}

#[inline]
unsafe fn cabi_timer_delete(timerid: *mut c_void) -> i64 {
    aarch64::syscall::syscall1(CABI_SYS_TIMER_DELETE, timerid as i64)
}

#[inline]
unsafe fn cabi_timer_getoverrun(timerid: *mut c_void) -> i64 {
    aarch64::syscall::syscall1(CABI_SYS_TIMER_GETOVERRUN, timerid as i64)
}

#[inline]
unsafe fn cabi_timer_gettime(timerid: *mut c_void, value: *mut CabiItimerspec) -> i64 {
    aarch64::syscall::syscall2(
        CABI_SYS_TIMER_GETTIME,
        timerid as i64,
        value as i64,
    )
}

#[inline]
unsafe fn cabi_timer_settime(
    timerid: *mut c_void,
    flags: c_int,
    value: *const CabiItimerspec,
    old_value: *mut CabiItimerspec,
) -> i64 {
    aarch64::syscall::syscall4(
        CABI_SYS_TIMER_SETTIME,
        timerid as i64,
        flags as i64,
        value as i64,
        old_value as i64,
    )
}

#[no_mangle]
pub unsafe extern "C" fn timer_create(
    clockid: c_int,
    event: *mut c_void,
    timerid: *mut *mut c_void,
) -> c_int {
    // The kernel writes a 32-bit ID.  Do not pass timerid directly: timer_t
    // is pointer-sized in the public ABI and its upper bytes belong to the
    // caller's object.  Passing NULL through still lets Linux report EFAULT.
    if timerid.is_null() {
        return syscall_result(cabi_timer_create(clockid, event, core::ptr::null_mut())) as c_int;
    }

    let mut kernel_timerid: c_int = 0;
    let result = cabi_timer_create(clockid, event, &mut kernel_timerid);
    if syscall_result(result) < 0 {
        return -1;
    }
    *timerid = kernel_timerid as isize as *mut c_void;
    0
}

#[no_mangle]
pub unsafe extern "C" fn timer_delete(timerid: *mut c_void) -> c_int {
    syscall_result(cabi_timer_delete(timerid)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn timer_getoverrun(timerid: *mut c_void) -> c_int {
    syscall_result(cabi_timer_getoverrun(timerid)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn timer_gettime(
    timerid: *mut c_void,
    value: *mut CabiItimerspec,
) -> c_int {
    syscall_result(cabi_timer_gettime(timerid, value)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn timer_settime(
    timerid: *mut c_void,
    flags: c_int,
    value: *const CabiItimerspec,
    old_value: *mut CabiItimerspec,
) -> c_int {
    syscall_result(cabi_timer_settime(timerid, flags, value, old_value)) as c_int
}
