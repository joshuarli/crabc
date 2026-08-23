// filesystem-stat and legacy timestamp exports.
//
// These interfaces are kept deliberately close to Linux's ABI.  statfs(2)
// fills the caller's 64-bit structure directly, while the legacy timestamp
// interfaces translate to utimensat(2) so they retain the kernel's path,
// symlink, permission, and errno behavior.

#[repr(C)]
pub struct CabiStatfs {
    pub f_type: c_ulong,
    pub f_bsize: c_ulong,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_fsid: [c_int; 2],
    pub f_namelen: c_ulong,
    pub f_frsize: c_ulong,
    pub f_flags: c_ulong,
    pub f_spare: [c_ulong; 4],
}

#[repr(C)]
pub struct CabiUtimbuf {
    pub actime: TimeT,
    pub modtime: TimeT,
}

#[repr(C)]
pub struct CabiTimeb {
    pub time: TimeT,
    pub millitm: u16,
    pub timezone: i16,
    pub dstflag: i16,
}

#[inline]
unsafe fn cabi_statfs(path: *const c_char, buf: *mut CabiStatfs) -> i64 {
    aarch64_syscall::syscall2(SYS_STATFS, path as i64, buf as i64)
}

#[inline]
unsafe fn cabi_fstatfs(fd: c_int, buf: *mut CabiStatfs) -> i64 {
    aarch64_syscall::syscall2(SYS_FSTATFS, fd as i64, buf as i64)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn statfs(path: *const c_char, buf: *mut CabiStatfs) -> c_int {
    syscall_result(cabi_statfs(path, buf)) as c_int
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn fstatfs(fd: c_int, buf: *mut CabiStatfs) -> c_int {
    syscall_result(cabi_fstatfs(fd, buf)) as c_int
}

#[inline]
unsafe fn cabi_legacy_timeval_pair(
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
        converted[i] = timespec {
            tv_sec: (*times.add(i)).tv_sec,
            tv_nsec: tv_usec * 1_000,
        };
    }
    Ok(converted.as_ptr())
}

#[no_mangle]
pub unsafe extern "C" fn utime(path: *const c_char, times: *const CabiUtimbuf) -> c_int {
    let mut converted: [timespec; 2] = core::mem::zeroed();
    let times_ptr = if times.is_null() {
        core::ptr::null()
    } else {
        converted[0] = timespec {
            tv_sec: (*times).actime,
            tv_nsec: 0,
        };
        converted[1] = timespec {
            tv_sec: (*times).modtime,
            tv_nsec: 0,
        };
        converted.as_ptr()
    };

    syscall_result(sys_utimensat(
        AT_FDCWD,
        path,
        times_ptr as *const u8,
        0,
    )) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn lutimes(
    path: *const c_char,
    times: *const timeval,
) -> c_int {
    let mut converted: [timespec; 2] = core::mem::zeroed();
    let times_ptr = match cabi_legacy_timeval_pair(times, &mut converted) {
        Ok(value) => value,
        Err(error) => {
            ERRNO = error;
            return -1;
        }
    };

    syscall_result(sys_utimensat(
        AT_FDCWD,
        path,
        times_ptr as *const u8,
        AT_SYMLINK_NOFOLLOW,
    )) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn ftime(buf: *mut CabiTimeb) -> c_int {
    let mut now: timespec = core::mem::zeroed();
    let result = sys_clock_gettime(CLOCK_REALTIME, &mut now);
    if syscall_result(result) < 0 {
        return -1;
    }

    (*buf).time = now.tv_sec;
    (*buf).millitm = (now.tv_nsec / 1_000_000) as u16;
    // `timezone` is measured in seconds west of UTC by the historical C ABI;
    // crabc's timezone state is UTC until its timezone subsystem is expanded.
    (*buf).timezone = (timezone / 60) as i16;
    (*buf).dstflag = daylight as i16;
    0
}
