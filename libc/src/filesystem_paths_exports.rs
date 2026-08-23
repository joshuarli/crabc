// filesystem path and descriptor operations with directly testable
// unprivileged behavior.  Path calls cross the C ABI through syscall_result;
// the timeval-based timestamp calls translate to the existing utimensat
// helper so their microsecond contract is preserved.


const CABI_SYS_FACCESSAT2: i64 = 439;


const CABI_SYS_FCHDIR: i64 = 50;


const CABI_SYS_MKNODAT: i64 = 33;


const CABI_SYS_FLOCK: i64 = 32;

const CABI_S_IFIFO: c_uint = 0o010000;

const CABI_F_ULOCK: c_int = 0;
const CABI_F_LOCK: c_int = 1;
const CABI_F_TLOCK: c_int = 2;
const CABI_F_TEST: c_int = 3;
const CABI_AT_EACCESS: c_int = 0x200;

const CABI_F_WRLCK: i16 = 1;
const CABI_F_UNLCK: i16 = 2;

#[repr(C)]
struct CabiFlock {
    l_type: i16,
    l_whence: i16,
    l_start: c_long,
    l_len: c_long,
    l_pid: c_int,
}

#[inline]
unsafe fn cabi_faccessat(
    dirfd: c_int,
    path: *const c_char,
    mode: c_int,
    flags: c_int,
) -> i64 {
    if flags == 0 {
        // SYS_faccessat has no flags argument; the fourth register is ignored
        // by Linux and is kept zero for the architecture's syscall ABI.
        aarch64::syscall::syscall4(
            SYS_FACCESSAT,
            dirfd as i64,
            path as i64,
            mode as i64,
            0,
        )
    } else {
        aarch64::syscall::syscall4(
            CABI_SYS_FACCESSAT2,
            dirfd as i64,
            path as i64,
            mode as i64,
            flags as i64,
        )
    }
}

#[inline]
unsafe fn cabi_fchdir(fd: c_int) -> i64 {
    aarch64::syscall::syscall1(CABI_SYS_FCHDIR, fd as i64)
}

#[inline]
unsafe fn cabi_mknodat(
    dirfd: c_int,
    path: *const c_char,
    mode: c_uint,
    dev: c_ulong,
) -> i64 {
    aarch64::syscall::syscall4(
        CABI_SYS_MKNODAT,
        dirfd as i64,
        path as i64,
        mode as i64,
        dev as i64,
    )
}

#[inline]
unsafe fn cabi_flock(fd: c_int, operation: c_int) -> i64 {
    match crabc_core::fs::flock(fd, operation as u32) {
        Ok(()) => 0,
        Err(errno) => -(errno.raw() as i64),
    }
}

#[inline]
unsafe fn cabi_lockf(fd: c_int, command: c_int, len: c_long) -> i64 {
    if command != CABI_F_ULOCK
        && command != CABI_F_LOCK
        && command != CABI_F_TLOCK
        && command != CABI_F_TEST
    {
        ERRNO = EINVAL;
        return -1;
    }
    if len == c_long::MIN {
        ERRNO = EINVAL;
        return -1;
    }

    let current = sys_lseek(fd as i64, 0, SEEK_CUR as i64);
    if current < 0 {
        return syscall_result(current);
    }
    let (start, length) = if len < 0 {
        (current.wrapping_add(len), len.wrapping_neg())
    } else {
        (current, len)
    };
    let lock_type = if command == CABI_F_ULOCK {
        CABI_F_UNLCK
    } else {
        CABI_F_WRLCK
    };
    let mut lock = CabiFlock {
        l_type: lock_type,
        l_whence: SEEK_SET as i16,
        l_start: start,
        l_len: length,
        l_pid: 0,
    };
    let fcntl_command = match command {
        CABI_F_LOCK => F_SETLKW,
        CABI_F_TLOCK | CABI_F_ULOCK => F_SETLK,
        CABI_F_TEST => F_GETLK,
        _ => F_SETLK,
    };
    let result = sys_fcntl(fd, fcntl_command, &mut lock as *mut CabiFlock as i64);
    if result < 0 {
        return syscall_result(result);
    }
    if command == CABI_F_TEST && lock.l_type != CABI_F_UNLCK {
        ERRNO = EACCES_VAL;
        return -1;
    }
    0
}

#[inline]
unsafe fn cabi_timespecs(
    times: *const timeval,
    converted: &mut [timespec; 2],
) -> Result<*const timespec, c_int> {
    if times.is_null() {
        return Ok(core::ptr::null());
    }
    for i in 0..2 {
        let tv_usec = (*times.add(i)).tv_usec;
        if tv_usec < 0 || tv_usec >= 1_000_000 {
            return Err(EINVAL);
        }
        converted[i].tv_sec = (*times.add(i)).tv_sec;
        converted[i].tv_nsec = tv_usec * 1_000;
    }
    Ok(converted.as_ptr())
}

#[no_mangle]
pub unsafe extern "C" fn faccessat(
    dirfd: c_int,
    path: *const c_char,
    mode: c_int,
    flags: c_int,
) -> c_int {
    syscall_result(cabi_faccessat(dirfd, path, mode, flags)) as c_int
}

// Linux's faccessat2 performs this query against the effective credentials
// when AT_EACCESS is set.  That is precisely the historical euidaccess
// contract, while access(2) continues to use real credentials.
#[no_mangle]
pub unsafe extern "C" fn euidaccess(path: *const c_char, mode: c_int) -> c_int {
    syscall_result(cabi_faccessat(AT_FDCWD, path, mode, CABI_AT_EACCESS)) as c_int
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn eaccess(path: *const c_char, mode: c_int) -> c_int {
    euidaccess(path, mode)
}

// Linux has no operation to change a symlink's mode.  Musl deliberately
// exposes lchmod but reports the platform's ENOTSUP result instead of
// following the link and changing its target.
#[no_mangle]
pub unsafe extern "C" fn lchmod(_path: *const c_char, _mode: mode_t) -> c_int {
    ERRNO = ENOTSUP;
    -1
}

#[no_mangle]
pub unsafe extern "C" fn fchdir(fd: c_int) -> c_int {
    syscall_result(cabi_fchdir(fd)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn mkfifo(path: *const c_char, mode: c_uint) -> c_int {
    syscall_result(cabi_mknodat(
        AT_FDCWD,
        path,
        mode | CABI_S_IFIFO,
        0,
    )) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn mkfifoat(
    dirfd: c_int,
    path: *const c_char,
    mode: mode_t,
) -> c_int {
    syscall_result(cabi_mknodat(dirfd, path, mode | CABI_S_IFIFO, 0)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn mknod(
    path: *const c_char,
    mode: mode_t,
    dev: c_ulong,
) -> c_int {
    syscall_result(cabi_mknodat(AT_FDCWD, path, mode, dev)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn mknodat(
    dirfd: c_int,
    path: *const c_char,
    mode: mode_t,
    dev: c_ulong,
) -> c_int {
    syscall_result(cabi_mknodat(dirfd, path, mode, dev)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn flock(fd: c_int, operation: c_int) -> c_int {
    syscall_result(cabi_flock(fd, operation)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn lockf(fd: c_int, command: c_int, len: c_long) -> c_int {
    cabi_lockf(fd, command, len) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn futimes(
    fd: c_int,
    times: *const timeval,
) -> c_int {
    let mut converted: [timespec; 2] = core::mem::zeroed();
    let times = match cabi_timespecs(times, &mut converted) {
        Ok(times) => times,
        Err(error) => {
            ERRNO = error;
            return -1;
        }
    };
    syscall_result(sys_utimensat(fd, core::ptr::null(), times as *const u8, 0)) as c_int
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn futimesat(
    dirfd: c_int,
    path: *const c_char,
    times: *const timeval,
) -> c_int {
    let mut converted: [timespec; 2] = core::mem::zeroed();
    let times = match cabi_timespecs(times, &mut converted) {
        Ok(times) => times,
        Err(error) => {
            ERRNO = error;
            return -1;
        }
    };
    syscall_result(sys_utimensat(dirfd, path, times as *const u8, 0)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn utimes(
    path: *const c_char,
    times: *const timeval,
) -> c_int {
    let mut converted: [timespec; 2] = core::mem::zeroed();
    let times = match cabi_timespecs(times, &mut converted) {
        Ok(times) => times,
        Err(error) => {
            ERRNO = error;
            return -1;
        }
    };
    syscall_result(sys_utimensat(AT_FDCWD, path, times as *const u8, 0)) as c_int
}
