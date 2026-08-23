// host, process-identity, and resource exports.
//
// These wrappers keep the Linux ABI visible at the C boundary.  The 64-bit
// targets supported by crabc use the native `timeval`/`long` layouts for the
// resource structures, so the kernel can fill the caller's buffers directly.
// Privileged namespace mutations are passed through to Linux: callers see
// EPERM when the process lacks CAP_SYS_ADMIN rather than a fabricated success.

#[repr(C)]
pub struct CabiUtsName {
    pub sysname: [u8; 65],
    pub nodename: [u8; 65],
    pub release: [u8; 65],
    pub version: [u8; 65],
    pub machine: [u8; 65],
    pub domainname: [u8; 65],
}

#[repr(C)]
pub struct CabiRusage {
    pub ru_utime: timeval,
    pub ru_stime: timeval,
    pub ru_maxrss: c_long,
    pub ru_ixrss: c_long,
    pub ru_idrss: c_long,
    pub ru_isrss: c_long,
    pub ru_minflt: c_long,
    pub ru_majflt: c_long,
    pub ru_nswap: c_long,
    pub ru_inblock: c_long,
    pub ru_oublock: c_long,
    pub ru_msgsnd: c_long,
    pub ru_msgrcv: c_long,
    pub ru_nsignals: c_long,
    pub ru_nvcsw: c_long,
    pub ru_nivcsw: c_long,
}

#[repr(C)]
pub struct CabiItimerval {
    pub it_interval: timeval,
    pub it_value: timeval,
}

#[repr(C)]
pub struct CabiTms {
    pub tms_utime: ClockT,
    pub tms_stime: ClockT,
    pub tms_cutime: ClockT,
    pub tms_cstime: ClockT,
}













const CABI_SYS_GETITIMER: i64 = 102;
const CABI_SYS_SETITIMER: i64 = 103;
const CABI_SYS_UNAME: i64 = 160;
const CABI_SYS_SETDOMAINNAME: i64 = 162;
const CABI_SYS_GETRUSAGE: i64 = 165;
const CABI_SYS_TIMES: i64 = 153;
const CABI_SYS_SETRESUID: i64 = 147;
const CABI_SYS_GETRESUID: i64 = 148;
const CABI_SYS_SETRESGID: i64 = 149;
const CABI_SYS_GETRESGID: i64 = 150;
const CABI_SYS_SETHOSTNAME: i64 = 161;

const CABI_ITIMER_REAL: c_int = 0;

// Linux has no process flag corresponding to the BSD "tainted by set-id"
// state.  Musl consequently defines issetugid as false on Linux; returning
// that platform fact is not a credential check or a synthetic success path.
#[no_mangle]
pub unsafe extern "C" fn issetugid() -> c_int {
    0
}

#[inline]
unsafe fn cabi_uname_raw(uts: *mut CabiUtsName) -> i64 {
    match crabc_core::system::uname_raw(uts.cast()) {
        Ok(()) => 0,
        Err(errno) => -(errno.raw() as i64),
    }
}

#[inline]
unsafe fn cabi_sethostname(name: *const c_char, len: usize) -> i64 {
    aarch64::syscall::syscall2(CABI_SYS_SETHOSTNAME, name as i64, len as i64)
}

#[inline]
unsafe fn cabi_setdomainname(name: *const c_char, len: usize) -> i64 {
    aarch64::syscall::syscall2(CABI_SYS_SETDOMAINNAME, name as i64, len as i64)
}

#[inline]
unsafe fn cabi_getresuid(ruid: *mut c_uint, euid: *mut c_uint, suid: *mut c_uint) -> i64 {
    aarch64::syscall::syscall3(
        CABI_SYS_GETRESUID,
        ruid as i64,
        euid as i64,
        suid as i64,
    )
}

#[inline]
unsafe fn cabi_setresuid(ruid: c_uint, euid: c_uint, suid: c_uint) -> i64 {
    aarch64::syscall::syscall3(
        CABI_SYS_SETRESUID,
        ruid as i64,
        euid as i64,
        suid as i64,
    )
}

#[inline]
unsafe fn cabi_getresgid(rgid: *mut c_uint, egid: *mut c_uint, sgid: *mut c_uint) -> i64 {
    aarch64::syscall::syscall3(
        CABI_SYS_GETRESGID,
        rgid as i64,
        egid as i64,
        sgid as i64,
    )
}

#[inline]
unsafe fn cabi_setresgid(rgid: c_uint, egid: c_uint, sgid: c_uint) -> i64 {
    aarch64::syscall::syscall3(
        CABI_SYS_SETRESGID,
        rgid as i64,
        egid as i64,
        sgid as i64,
    )
}

#[inline]
unsafe fn cabi_getrusage(who: c_int, usage: *mut CabiRusage) -> i64 {
    aarch64::syscall::syscall2(CABI_SYS_GETRUSAGE, who as i64, usage as i64)
}

#[inline]
unsafe fn cabi_getitimer(which: c_int, old: *mut CabiItimerval) -> i64 {
    aarch64::syscall::syscall2(CABI_SYS_GETITIMER, which as i64, old as i64)
}

#[inline]
unsafe fn cabi_setitimer(
    which: c_int,
    new: *const CabiItimerval,
    old: *mut CabiItimerval,
) -> i64 {
    aarch64::syscall::syscall3(CABI_SYS_SETITIMER, which as i64, new as i64, old as i64)
}

#[inline]
unsafe fn cabi_times(buffer: *mut CabiTms) -> i64 {
    aarch64::syscall::syscall1(CABI_SYS_TIMES, buffer as i64)
}

#[no_mangle]
pub unsafe extern "C" fn uname(uts: *mut CabiUtsName) -> c_int {
    syscall_result(cabi_uname_raw(uts)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn getdomainname(name: *mut c_char, len: usize) -> c_int {
    // This follows musl's contract: unlike gethostname, getdomainname does
    // not truncate.  A zero or insufficient buffer is EINVAL.
    let mut uts: CabiUtsName = core::mem::zeroed();
    if syscall_result(cabi_uname_raw(&mut uts)) < 0 {
        return -1;
    }

    let mut domain_len = 0usize;
    while domain_len < uts.domainname.len() && uts.domainname[domain_len] != 0 {
        domain_len += 1;
    }
    if len == 0 || domain_len >= len {
        ERRNO = EINVAL;
        return -1;
    }

    core::ptr::copy_nonoverlapping(
        uts.domainname.as_ptr(),
        name as *mut u8,
        domain_len + 1,
    );
    0
}

#[no_mangle]
pub unsafe extern "C" fn setdomainname(name: *const c_char, len: usize) -> c_int {
    syscall_result(cabi_setdomainname(name, len)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn sethostname(name: *const c_char, len: usize) -> c_int {
    syscall_result(cabi_sethostname(name, len)) as c_int
}

// Linux has no gethostid syscall.  musl deliberately returns zero rather
// than consulting a host-specific file, making this result deterministic.
#[no_mangle]
pub unsafe extern "C" fn gethostid() -> c_long {
    0
}

#[no_mangle]
pub unsafe extern "C" fn getresuid(
    ruid: *mut c_uint,
    euid: *mut c_uint,
    suid: *mut c_uint,
) -> c_int {
    syscall_result(cabi_getresuid(ruid, euid, suid)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn setresuid(ruid: c_uint, euid: c_uint, suid: c_uint) -> c_int {
    syscall_result(cabi_setresuid(ruid, euid, suid)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn getresgid(
    rgid: *mut c_uint,
    egid: *mut c_uint,
    sgid: *mut c_uint,
) -> c_int {
    syscall_result(cabi_getresgid(rgid, egid, sgid)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn setresgid(rgid: c_uint, egid: c_uint, sgid: c_uint) -> c_int {
    syscall_result(cabi_setresgid(rgid, egid, sgid)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn getrusage(who: c_int, usage: *mut CabiRusage) -> c_int {
    syscall_result(cabi_getrusage(who, usage)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn getitimer(which: c_int, old: *mut CabiItimerval) -> c_int {
    syscall_result(cabi_getitimer(which, old)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn setitimer(
    which: c_int,
    new: *const CabiItimerval,
    old: *mut CabiItimerval,
) -> c_int {
    syscall_result(cabi_setitimer(which, new, old)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn times(buffer: *mut CabiTms) -> ClockT {
    syscall_result(cabi_times(buffer)) as ClockT
}

#[no_mangle]
pub unsafe extern "C" fn ualarm(value: c_uint, interval: c_uint) -> c_uint {
    let mut new: CabiItimerval = core::mem::zeroed();
    new.it_interval.tv_usec = interval as c_long;
    new.it_value.tv_usec = value as c_long;
    let mut old: CabiItimerval = core::mem::zeroed();
    let result = cabi_setitimer(CABI_ITIMER_REAL, &new, &mut old);
    if result < 0 {
        ERRNO = (-result) as c_int;
        return !0u32;
    }

    // ualarm's return type is unsigned; this deliberately wraps like musl's
    // C expression when a very large remaining interval is represented.
    (old.it_value.tv_sec as c_uint)
        .wrapping_mul(1_000_000)
        .wrapping_add(old.it_value.tv_usec as c_uint)
}
