// M4 host, process-identity, and resource exports.
//
// These wrappers keep the Linux ABI visible at the C boundary.  The 64-bit
// targets supported by crabc use the native `timeval`/`long` layouts for the
// resource structures, so the kernel can fill the caller's buffers directly.
// Privileged namespace mutations are passed through to Linux: callers see
// EPERM when the process lacks CAP_SYS_ADMIN rather than a fabricated success.

#[repr(C)]
pub struct M4UtsName {
    pub sysname: [u8; 65],
    pub nodename: [u8; 65],
    pub release: [u8; 65],
    pub version: [u8; 65],
    pub machine: [u8; 65],
    pub domainname: [u8; 65],
}

#[repr(C)]
pub struct M4Rusage {
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
pub struct M4Itimerval {
    pub it_interval: timeval,
    pub it_value: timeval,
}

#[repr(C)]
pub struct M4Tms {
    pub tms_utime: ClockT,
    pub tms_stime: ClockT,
    pub tms_cutime: ClockT,
    pub tms_cstime: ClockT,
}

#[cfg(target_arch = "x86_64")]
const M4_SYS_GETITIMER: i64 = 36;
#[cfg(target_arch = "x86_64")]
const M4_SYS_SETITIMER: i64 = 38;
#[cfg(target_arch = "x86_64")]
const M4_SYS_UNAME: i64 = 63;
#[cfg(target_arch = "x86_64")]
const M4_SYS_GETRUSAGE: i64 = 98;
#[cfg(target_arch = "x86_64")]
const M4_SYS_TIMES: i64 = 100;
#[cfg(target_arch = "x86_64")]
const M4_SYS_SETRESUID: i64 = 117;
#[cfg(target_arch = "x86_64")]
const M4_SYS_GETRESUID: i64 = 118;
#[cfg(target_arch = "x86_64")]
const M4_SYS_SETRESGID: i64 = 119;
#[cfg(target_arch = "x86_64")]
const M4_SYS_GETRESGID: i64 = 120;
#[cfg(target_arch = "x86_64")]
const M4_SYS_SETHOSTNAME: i64 = 170;
#[cfg(target_arch = "x86_64")]
const M4_SYS_SETDOMAINNAME: i64 = 171;

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_GETITIMER: i64 = 102;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_SETITIMER: i64 = 103;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_UNAME: i64 = 160;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_SETDOMAINNAME: i64 = 162;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_GETRUSAGE: i64 = 165;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_TIMES: i64 = 153;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_SETRESUID: i64 = 147;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_GETRESUID: i64 = 148;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_SETRESGID: i64 = 149;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_GETRESGID: i64 = 150;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_SETHOSTNAME: i64 = 161;

const M4_ITIMER_REAL: c_int = 0;

// Linux has no process flag corresponding to the BSD "tainted by set-id"
// state.  Musl consequently defines issetugid as false on Linux; returning
// that platform fact is not a credential check or a synthetic success path.
#[no_mangle]
pub unsafe extern "C" fn issetugid() -> c_int {
    0
}

#[inline]
unsafe fn m4_uname_raw(uts: *mut M4UtsName) -> i64 {
    match crabc_core::system::uname_raw(uts.cast()) {
        Ok(()) => 0,
        Err(errno) => -(errno.raw() as i64),
    }
}

#[inline]
unsafe fn m4_sethostname(name: *const c_char, len: usize) -> i64 {
    <Arch as Syscalls>::syscall2(M4_SYS_SETHOSTNAME, name as i64, len as i64)
}

#[inline]
unsafe fn m4_setdomainname(name: *const c_char, len: usize) -> i64 {
    <Arch as Syscalls>::syscall2(M4_SYS_SETDOMAINNAME, name as i64, len as i64)
}

#[inline]
unsafe fn m4_getresuid(ruid: *mut c_uint, euid: *mut c_uint, suid: *mut c_uint) -> i64 {
    <Arch as Syscalls>::syscall3(
        M4_SYS_GETRESUID,
        ruid as i64,
        euid as i64,
        suid as i64,
    )
}

#[inline]
unsafe fn m4_setresuid(ruid: c_uint, euid: c_uint, suid: c_uint) -> i64 {
    <Arch as Syscalls>::syscall3(
        M4_SYS_SETRESUID,
        ruid as i64,
        euid as i64,
        suid as i64,
    )
}

#[inline]
unsafe fn m4_getresgid(rgid: *mut c_uint, egid: *mut c_uint, sgid: *mut c_uint) -> i64 {
    <Arch as Syscalls>::syscall3(
        M4_SYS_GETRESGID,
        rgid as i64,
        egid as i64,
        sgid as i64,
    )
}

#[inline]
unsafe fn m4_setresgid(rgid: c_uint, egid: c_uint, sgid: c_uint) -> i64 {
    <Arch as Syscalls>::syscall3(
        M4_SYS_SETRESGID,
        rgid as i64,
        egid as i64,
        sgid as i64,
    )
}

#[inline]
unsafe fn m4_getrusage(who: c_int, usage: *mut M4Rusage) -> i64 {
    <Arch as Syscalls>::syscall2(M4_SYS_GETRUSAGE, who as i64, usage as i64)
}

#[inline]
unsafe fn m4_getitimer(which: c_int, old: *mut M4Itimerval) -> i64 {
    <Arch as Syscalls>::syscall2(M4_SYS_GETITIMER, which as i64, old as i64)
}

#[inline]
unsafe fn m4_setitimer(
    which: c_int,
    new: *const M4Itimerval,
    old: *mut M4Itimerval,
) -> i64 {
    <Arch as Syscalls>::syscall3(M4_SYS_SETITIMER, which as i64, new as i64, old as i64)
}

#[inline]
unsafe fn m4_times(buffer: *mut M4Tms) -> i64 {
    <Arch as Syscalls>::syscall1(M4_SYS_TIMES, buffer as i64)
}

#[no_mangle]
pub unsafe extern "C" fn uname(uts: *mut M4UtsName) -> c_int {
    syscall_result(m4_uname_raw(uts)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn getdomainname(name: *mut c_char, len: usize) -> c_int {
    // This follows musl's contract: unlike gethostname, getdomainname does
    // not truncate.  A zero or insufficient buffer is EINVAL.
    let mut uts: M4UtsName = core::mem::zeroed();
    if syscall_result(m4_uname_raw(&mut uts)) < 0 {
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
    syscall_result(m4_setdomainname(name, len)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn sethostname(name: *const c_char, len: usize) -> c_int {
    syscall_result(m4_sethostname(name, len)) as c_int
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
    syscall_result(m4_getresuid(ruid, euid, suid)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn setresuid(ruid: c_uint, euid: c_uint, suid: c_uint) -> c_int {
    syscall_result(m4_setresuid(ruid, euid, suid)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn getresgid(
    rgid: *mut c_uint,
    egid: *mut c_uint,
    sgid: *mut c_uint,
) -> c_int {
    syscall_result(m4_getresgid(rgid, egid, sgid)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn setresgid(rgid: c_uint, egid: c_uint, sgid: c_uint) -> c_int {
    syscall_result(m4_setresgid(rgid, egid, sgid)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn getrusage(who: c_int, usage: *mut M4Rusage) -> c_int {
    syscall_result(m4_getrusage(who, usage)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn getitimer(which: c_int, old: *mut M4Itimerval) -> c_int {
    syscall_result(m4_getitimer(which, old)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn setitimer(
    which: c_int,
    new: *const M4Itimerval,
    old: *mut M4Itimerval,
) -> c_int {
    syscall_result(m4_setitimer(which, new, old)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn times(buffer: *mut M4Tms) -> ClockT {
    syscall_result(m4_times(buffer)) as ClockT
}

#[no_mangle]
pub unsafe extern "C" fn ualarm(value: c_uint, interval: c_uint) -> c_uint {
    let mut new: M4Itimerval = core::mem::zeroed();
    new.it_interval.tv_usec = interval as c_long;
    new.it_value.tv_usec = value as c_long;
    let mut old: M4Itimerval = core::mem::zeroed();
    let result = m4_setitimer(M4_ITIMER_REAL, &new, &mut old);
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
