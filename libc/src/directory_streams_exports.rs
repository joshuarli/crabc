// directory-stream exports.
//
// Linux getdents64 records use the LP64 layout of struct dirent: an inode,
// an opaque directory offset, a record length, a type byte, and a NUL-
// terminated name.  Keeping the kernel records in a musl-sized 2048-byte
// buffer lets readdir return the same stable-until-next-call view as musl,
// while the bounds checks below prevent malformed kernel data from crossing
// the C ABI boundary.

const CABI_DIR_BUF_SIZE: usize = 2048;
const CABI_LINUX_DIRENT64_HEADER: usize = 19;
const CABI_DIR_NAME_MAX: usize = 255;
const CABI_EIO: c_int = 5;
const CABI_ENOENT: c_int = 2;
const CABI_EBADF: c_int = 9;
const CABI_ENOTDIR: c_int = 20;
const CABI_EOPNOTSUPP: c_int = 95;
const CABI_DIRENT_INT_MAX: usize = 0x7fff_ffff;
const CABI_O_PATH: c_int = 0x200000;
const CABI_O_DIRECTORY: c_int = 0x4000;

#[cfg(target_arch = "x86_64")]
const CABI_SYS_GETDENTS64: i64 = 217;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_GETDENTS64: i64 = 61;

// getdents64's header and musl's public dirent are both 8-byte aligned on
// the LP64 targets supported by this crate.  The explicit representation is
// used only for field access after the record-length and name checks below.
#[repr(C)]
pub struct CabiDirent {
    d_ino: u64,
    d_off: i64,
    d_reclen: u16,
    d_type: u8,
    d_name: [c_char; 256],
}

#[repr(C)]
pub struct CabiDirStream {
    tell: c_long,
    fd: c_int,
    buf_pos: usize,
    buf_end: usize,
    buf: [u8; CABI_DIR_BUF_SIZE],
}

#[inline]
unsafe fn cabi_dir_errno(result: i64) -> c_int {
    if result < 0 && result >= -4095 {
        (-result) as c_int
    } else {
        result as c_int
    }
}

#[inline]
unsafe fn cabi_getdents(fd: c_int, buf: *mut u8, len: usize) -> i64 {
    match unsafe { crabc_core::fs::getdents64_raw(fd, buf, len) } {
        Ok(length) => length as i64,
        Err(errno) => -(errno.raw() as i64),
    }
}

#[inline]
unsafe fn cabi_dir_record<'a>(dir: &'a mut CabiDirStream) -> Option<(*mut CabiDirent, usize)> {
    if dir.buf_pos >= dir.buf_end {
        let len = cabi_getdents(dir.fd, dir.buf.as_mut_ptr(), CABI_DIR_BUF_SIZE);
        if len == 0 {
            return None;
        }
        if len < 0 {
            // musl treats a deleted directory (ENOENT) as end-of-stream.
            if len != -(CABI_ENOENT as i64) {
                ERRNO = cabi_dir_errno(len);
            }
            return None;
        }
        let len = len as usize;
        if len > CABI_DIR_BUF_SIZE {
            ERRNO = CABI_EIO;
            return None;
        }
        dir.buf_pos = 0;
        dir.buf_end = len;
    }

    let base = dir.buf.as_mut_ptr().add(dir.buf_pos);
    let remaining = dir.buf_end - dir.buf_pos;
    if remaining < CABI_LINUX_DIRENT64_HEADER {
        dir.buf_pos = dir.buf_end;
        ERRNO = CABI_EIO;
        return None;
    }

    let reclen = core::ptr::read_unaligned(base.add(16) as *const u16) as usize;
    if reclen < CABI_LINUX_DIRENT64_HEADER || reclen > remaining {
        dir.buf_pos = dir.buf_end;
        ERRNO = CABI_EIO;
        return None;
    }

    // d_name begins at byte 19.  Reject a record without a terminator or a
    // name larger than the public 256-byte array before returning it.
    let name = base.add(CABI_LINUX_DIRENT64_HEADER);
    let name_limit = reclen - CABI_LINUX_DIRENT64_HEADER;
    let mut name_len = 0usize;
    while name_len < name_limit && *name.add(name_len) != 0 {
        name_len += 1;
    }
    if name_len == name_limit || name_len > CABI_DIR_NAME_MAX {
        dir.buf_pos = dir.buf_end;
        ERRNO = CABI_EIO;
        return None;
    }

    dir.buf_pos += reclen;
    dir.tell = core::ptr::read_unaligned(base.add(8) as *const i64) as c_long;
    Some((base as *mut CabiDirent, reclen))
}

#[inline]
unsafe fn cabi_alloc_dir(fd: c_int) -> *mut CabiDirStream {
    let mut st: Stat = core::mem::zeroed();
    if fstat(fd, &mut st) != 0 {
        return core::ptr::null_mut();
    }
    let flags = sys_fcntl(fd, F_GETFL, 0);
    if flags < 0 {
        ERRNO = cabi_dir_errno(flags);
        return core::ptr::null_mut();
    }
    if (flags as c_int & CABI_O_PATH) != 0 {
        ERRNO = CABI_EBADF;
        return core::ptr::null_mut();
    }
    if st.st_mode & S_IFMT != S_IFDIR {
        ERRNO = CABI_ENOTDIR;
        return core::ptr::null_mut();
    }

    let dir = calloc(1, core::mem::size_of::<CabiDirStream>()) as *mut CabiDirStream;
    if dir.is_null() {
        return core::ptr::null_mut();
    }
    // fdopendir makes the descriptor close-on-exec, but deliberately leaves
    // it open if setup fails.  Ignore this best-effort flag update as musl
    // does; the stream remains usable when the descriptor already has the
    // requested state or the fcntl operation is unsupported.
    let _ = sys_fcntl(fd, F_SETFD, FD_CLOEXEC as i64);
    (*dir).fd = fd;
    dir
}

#[no_mangle]
pub unsafe extern "C" fn opendir(path: *const c_char) -> *mut CabiDirStream {
    let fd = sys_openat(
        AT_FDCWD,
        path as *const u8,
        O_RDONLY | CABI_O_DIRECTORY | O_CLOEXEC,
        0,
    );
    if fd < 0 {
        ERRNO = cabi_dir_errno(fd);
        return core::ptr::null_mut();
    }
    let dir = cabi_alloc_dir(fd as c_int);
    if dir.is_null() {
        let saved = ERRNO;
        let _ = sys_close(fd);
        ERRNO = saved;
    }
    dir
}

#[no_mangle]
pub unsafe extern "C" fn fdopendir(fd: c_int) -> *mut CabiDirStream {
    cabi_alloc_dir(fd)
}

#[no_mangle]
pub unsafe extern "C" fn closedir(dir: *mut CabiDirStream) -> c_int {
    if dir.is_null() {
        ERRNO = CABI_EBADF;
        return -1;
    }
    let fd = (*dir).fd;
    let result = sys_close(fd as i64);
    free(dir as *mut c_void);
    syscall_result(result) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn dirfd(dir: *mut CabiDirStream) -> c_int {
    if dir.is_null() {
        ERRNO = CABI_EBADF;
        return -1;
    }
    (*dir).fd
}

#[no_mangle]
pub unsafe extern "C" fn readdir(dir: *mut CabiDirStream) -> *mut CabiDirent {
    if dir.is_null() {
        ERRNO = CABI_EBADF;
        return core::ptr::null_mut();
    }
    match cabi_dir_record(&mut *dir) {
        Some((record, _)) => record,
        None => core::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn readdir_r(
    dir: *mut CabiDirStream,
    buf: *mut CabiDirent,
    result: *mut *mut CabiDirent,
) -> c_int {
    if dir.is_null() || buf.is_null() || result.is_null() {
        return CABI_EBADF;
    }
    let saved_errno = ERRNO;
    ERRNO = 0;
    let record = readdir(dir);
    let read_errno = ERRNO;
    if read_errno != 0 {
        return read_errno;
    }
    ERRNO = saved_errno;
    if record.is_null() {
        *result = core::ptr::null_mut();
        return 0;
    }

    let reclen = (*record).d_reclen as usize;
    core::ptr::copy_nonoverlapping(record as *const u8, buf as *mut u8, reclen);
    *result = buf;
    0
}

#[no_mangle]
pub unsafe extern "C" fn rewinddir(dir: *mut CabiDirStream) {
    if dir.is_null() {
        ERRNO = CABI_EBADF;
        return;
    }
    let result = sys_lseek((*dir).fd as i64, 0, SEEK_SET as i64);
    if result < 0 {
        ERRNO = cabi_dir_errno(result);
    }
    (*dir).buf_pos = 0;
    (*dir).buf_end = 0;
    (*dir).tell = 0;
}

#[no_mangle]
pub unsafe extern "C" fn seekdir(dir: *mut CabiDirStream, offset: c_long) {
    if dir.is_null() {
        ERRNO = CABI_EBADF;
        return;
    }
    let result = sys_lseek((*dir).fd as i64, offset as i64, SEEK_SET as i64);
    if result < 0 {
        ERRNO = cabi_dir_errno(result);
        (*dir).tell = -1;
    } else {
        (*dir).tell = result as c_long;
    }
    (*dir).buf_pos = 0;
    (*dir).buf_end = 0;
}

#[no_mangle]
pub unsafe extern "C" fn telldir(dir: *mut CabiDirStream) -> c_long {
    if dir.is_null() {
        ERRNO = CABI_EBADF;
        return -1;
    }
    (*dir).tell
}

// These comparison callbacks are part of the directory-stream API because
// scandir callers pass them directly to qsort.  The public C struct has the
// same layout as CabiDirent on our LP64 targets; only d_name is observed.
#[no_mangle]
pub unsafe extern "C" fn alphasort(
    left: *const *const CabiDirent,
    right: *const *const CabiDirent,
) -> c_int {
    strcoll((**left).d_name.as_ptr(), (**right).d_name.as_ptr())
}

#[no_mangle]
pub unsafe extern "C" fn versionsort(
    left: *const *const CabiDirent,
    right: *const *const CabiDirent,
) -> c_int {
    strverscmp((**left).d_name.as_ptr(), (**right).d_name.as_ptr())
}

#[no_mangle]
pub unsafe extern "C" fn getdents(
    fd: c_int,
    buf: *mut CabiDirent,
    len: SizeT,
) -> c_int {
    let len = if len > CABI_DIRENT_INT_MAX {
        CABI_DIRENT_INT_MAX
    } else {
        len
    };
    syscall_result(cabi_getdents(fd, buf as *mut u8, len)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn posix_getdents(
    fd: c_int,
    buf: *mut c_void,
    len: SizeT,
    flags: c_int,
) -> SSizeT {
    if flags != 0 {
        ERRNO = CABI_EOPNOTSUPP;
        return -1;
    }
    let len = if len > CABI_DIRENT_INT_MAX {
        CABI_DIRENT_INT_MAX
    } else {
        len
    };
    syscall_result(cabi_getdents(fd, buf as *mut u8, len)) as SSizeT
}
