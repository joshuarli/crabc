// Stubs and minimal implementations for symbols required by libc-test
// regression cases that currently fail to link.

// Keep the diagnostic and termination sequence byte-for-byte compatible with
// musl's src/exit/assert.c.  In particular, fprintf writes to stderr before
// abort raises SIGABRT; callers rely on the child being terminated after the
// complete assertion line has been emitted.
#[no_mangle]
pub unsafe extern "C" fn __assert_fail(
    expr: *const c_char,
    file: *const c_char,
    line: c_int,
    func: *const c_char,
) -> ! {
    let format = b"Assertion failed: %s (%s: %s: %d)\n\0";
    let _ = fprintf(
        stderr,
        format.as_ptr() as *const c_char,
        expr,
        file,
        func,
        line,
    );
    // crabc's current stderr stream is backed by a buffer; musl configures
    // stderr unbuffered, so flush explicitly to preserve the observable
    // diagnostic-before-abort guarantee.
    let _ = fflush(stderr);
    abort()
}

// Linux's signal namespace is fixed by this libc's _NSIG == 65 ABI.  Keep
// this as a function export (rather than only a header constant), matching
// musl's runtime SIGRTMAX macro and allowing existing binaries to resolve it.
#[no_mangle]
pub unsafe extern "C" fn __libc_current_sigrtmax() -> c_int {
    _NSIG - 1
}

const _SC_PAGE_SIZE: c_int = 30;
const _SC_CLK_TCK: c_int = 2;
const AT_PAGESZ: c_ulong = 6;

/// Read the kernel's startup page-size contract without preserving a
/// target-default guess.  Linux always supplies `AT_PAGESZ` to a normally
/// started process; the checked conversion keeps a malformed startup vector
/// from manufacturing an invalid positive C page size.
#[inline]
unsafe fn startup_page_size() -> Option<c_int> {
    let size = getauxval(AT_PAGESZ);
    if size == 0 || size > c_int::MAX as c_ulong {
        None
    } else {
        Some(size as c_int)
    }
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn mmap(
    addr: *mut c_void,
    len: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    off: i64,
) -> *mut c_void {
    match unsafe {
        crabc_core::mm::mmap_raw(addr.cast(), len, prot as u32, flags as u32, fd, off as u64)
    } {
        Ok(mapping) => mapping.cast(),
        Err(errno) => {
            ERRNO = errno.raw();
            MMAP_FAILED.cast()
        }
    }
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn munmap(addr: *mut c_void, len: usize) -> c_int {
    match unsafe { crabc_core::mm::munmap_raw(addr.cast(), len) } {
        Ok(()) => 0,
        Err(errno) => {
            ERRNO = errno.raw();
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn sysconf(name: c_int) -> c_long {
    match name {
        // POSIX requires the number of clock ticks per second to be constant
        // for a system.  musl exposes Linux's USER_HZ contract as 100; the
        // Python runtime reads this during PyInit_posix and rejects failure.
        _SC_CLK_TCK => 100,
        _SC_PAGE_SIZE => match startup_page_size() {
            Some(size) => size as c_long,
            None => {
                crate::__errno_location().write(ENOSYS_VAL);
                -1
            }
        },
        _ => {
            crate::__errno_location().write(EINVAL);
            -1
        }
    }
}

// ============================================================
// POSIX path/configuration interfaces
// ============================================================

// Linux exposes the filesystem-dependent pathconf values through statfs(2).
// Keep this private layout local instead of depending on a public statfs
// header: the kernel ABI is 64-bit on all targets supported by this crate.
#[repr(C)]
struct CabiPathStatfs {
    f_type: c_ulong,
    f_bsize: c_ulong,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [c_int; 2],
    f_namelen: c_ulong,
    f_frsize: c_ulong,
    f_flags: c_ulong,
    f_spare: [c_ulong; 4],
}

const CABI_PC_LINK_MAX: c_int = 0;
const CABI_PC_MAX_CANON: c_int = 1;
const CABI_PC_MAX_INPUT: c_int = 2;
const CABI_PC_NAME_MAX: c_int = 3;
const CABI_PC_PATH_MAX: c_int = 4;
const CABI_PC_PIPE_BUF: c_int = 5;
const CABI_PC_CHOWN_RESTRICTED: c_int = 6;
const CABI_PC_NO_TRUNC: c_int = 7;
const CABI_PC_VDISABLE: c_int = 8;
const CABI_PC_SYNC_IO: c_int = 9;
const CABI_PC_ASYNC_IO: c_int = 10;
const CABI_PC_PRIO_IO: c_int = 11;
const CABI_PC_SOCK_MAXBUF: c_int = 12;
const CABI_PC_FILESIZEBITS: c_int = 13;
const CABI_PC_REC_INCR_XFER_SIZE: c_int = 14;
const CABI_PC_REC_MAX_XFER_SIZE: c_int = 15;
const CABI_PC_REC_MIN_XFER_SIZE: c_int = 16;
const CABI_PC_REC_XFER_ALIGN: c_int = 17;
const CABI_PC_ALLOC_SIZE_MIN: c_int = 18;
const CABI_PC_SYMLINK_MAX: c_int = 19;
const CABI_PC_2_SYMLINKS: c_int = 20;

#[inline]
fn cabi_pathconf_name_valid(name: c_int) -> bool {
    name >= CABI_PC_LINK_MAX && name <= CABI_PC_2_SYMLINKS
}

#[inline]
unsafe fn cabi_pathconf_statfs(path: *const c_char, buf: *mut CabiPathStatfs) -> c_int {
    let result = aarch64::syscall::syscall2(SYS_STATFS, path as i64, buf as i64);
    if result < 0 {
        syscall_result(result) as c_int
    } else {
        0
    }
}

#[inline]
unsafe fn cabi_fpathconf_statfs(fd: c_int, buf: *mut CabiPathStatfs) -> c_int {
    let result = aarch64::syscall::syscall2(SYS_FSTATFS, fd as i64, buf as i64);
    if result < 0 {
        syscall_result(result) as c_int
    } else {
        0
    }
}

// Return the fixed POSIX value for a selector whose value does not vary by
// Linux filesystem.  A negative result denotes an indeterminate value; in
// that case errno intentionally remains untouched, as required by POSIX.
#[inline]
unsafe fn cabi_pathconf_value(name: c_int, fs: &CabiPathStatfs) -> c_long {
    match name {
        CABI_PC_LINK_MAX => 8,
        CABI_PC_MAX_CANON => 255,
        CABI_PC_MAX_INPUT => 255,
        // statfs.f_namelen is the filesystem's actual component limit.  This
        // is the key distinction from a universal NAME_MAX constant.
        CABI_PC_NAME_MAX => fs.f_namelen as c_long,
        CABI_PC_PATH_MAX => 4096,
        CABI_PC_PIPE_BUF => 4096,
        CABI_PC_CHOWN_RESTRICTED => 1,
        CABI_PC_NO_TRUNC => 1,
        CABI_PC_VDISABLE => 0,
        CABI_PC_SYNC_IO => 1,
        CABI_PC_ASYNC_IO => -1,
        CABI_PC_PRIO_IO => -1,
        CABI_PC_SOCK_MAXBUF => -1,
        CABI_PC_FILESIZEBITS => 64,
        // Linux filesystems expose their preferred block size through statfs;
        // use it for transfer/allocation granularity where it is available.
        CABI_PC_REC_INCR_XFER_SIZE
        | CABI_PC_REC_MAX_XFER_SIZE
        | CABI_PC_REC_MIN_XFER_SIZE
        | CABI_PC_REC_XFER_ALIGN
        | CABI_PC_ALLOC_SIZE_MIN => {
            if fs.f_bsize == 0 {
                4096
            } else if fs.f_bsize > c_long::MAX as c_ulong {
                c_long::MAX
            } else {
                fs.f_bsize as c_long
            }
        }
        CABI_PC_SYMLINK_MAX => -1,
        CABI_PC_2_SYMLINKS => 1,
        _ => {
            // Callers validate the selector before reaching this helper.
            ERRNO = EINVAL;
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn confstr(name: c_int, buf: *mut c_char, len: usize) -> usize {
    // The POSIX environment strings are intentionally empty in this libc;
    // _CS_PATH is the one configured value musl exposes.
    let value: &[u8] = if name == 0 {
        b"/bin:/usr/bin\0"
    } else if name == 1 || name == 5 || (name >= 1116 && name <= 1151) {
        b"\0"
    } else {
        ERRNO = EINVAL;
        return 0;
    };

    let value_len = value.len() - 1;
    if !buf.is_null() && len != 0 {
        let copy_len = if len - 1 < value_len {
            len - 1
        } else {
            value_len
        };
        core::ptr::copy_nonoverlapping(value.as_ptr(), buf as *mut u8, copy_len);
        *buf.add(copy_len) = 0;
    }
    value_len + 1
}

#[no_mangle]
pub unsafe extern "C" fn fpathconf(fd: c_int, name: c_int) -> c_long {
    if !cabi_pathconf_name_valid(name) {
        ERRNO = EINVAL;
        return -1;
    }

    let mut fs: CabiPathStatfs = core::mem::zeroed();
    if cabi_fpathconf_statfs(fd, &mut fs) < 0 {
        return -1;
    }
    cabi_pathconf_value(name, &fs)
}

#[no_mangle]
pub unsafe extern "C" fn pathconf(path: *const c_char, name: c_int) -> c_long {
    if !cabi_pathconf_name_valid(name) {
        ERRNO = EINVAL;
        return -1;
    }

    let mut fs: CabiPathStatfs = core::mem::zeroed();
    if cabi_pathconf_statfs(path, &mut fs) < 0 {
        return -1;
    }
    cabi_pathconf_value(name, &fs)
}

const CABI_UL_GETFSIZE: c_int = 1;
const CABI_UL_SETFSIZE: c_int = 2;

#[no_mangle]
pub unsafe extern "C" fn ulimit(cmd: c_int, mut args: ...) -> c_long {
    let mut limit: Rlimit = core::mem::zeroed();
    if getrlimit(RLIMIT_FSIZE, &mut limit) != 0 {
        return -1;
    }

    if cmd == CABI_UL_SETFSIZE {
        let blocks: c_long = args.next_arg();
        // musl's historical ABI measures file size in 512-byte blocks.  The
        // cast before multiplication preserves the unsigned rlim_t behavior
        // for callers passing the full representable long range.
        limit.rlim_cur = (blocks as u64).wrapping_mul(512);
        if setrlimit(RLIMIT_FSIZE, &limit) != 0 {
            return -1;
        }
    } else if cmd != CABI_UL_GETFSIZE {
        // musl treats unknown commands like UL_GETFSIZE and reports the
        // current limit; no errno is manufactured for this legacy interface.
    }

    (limit.rlim_cur / 512) as c_long
}

#[no_mangle]
pub unsafe extern "C" fn execle(path: *const c_char, arg: *const c_char, mut args: ...) -> c_int {
    let mut argv: [*const c_char; 128] = [core::ptr::null(); 128];
    argv[0] = arg;
    let mut n = 1usize;
    loop {
        let a: *const c_char = args.next_arg();
        if a.is_null() {
            break;
        }
        if n >= argv.len() - 1 {
            crate::__errno_location().write(E2BIG);
            return -1;
        }
        argv[n] = a;
        n += 1;
    }
    argv[n] = core::ptr::null();
    let envp: *const *const c_char = args.next_arg();
    crate::syscall(
        SYS_EXECVE,
        path as c_long,
        argv.as_ptr() as c_long,
        envp as c_long,
        0,
        0,
        0,
    ) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn flockfile(f: *mut crate::FILE) {
    if !f.is_null() {
        if (*f).lockcount != c_long::MAX {
            (*f).lockcount += 1;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn funlockfile(f: *mut crate::FILE) {
    if !f.is_null() {
        if (*f).lockcount > 1 {
            (*f).lockcount -= 1;
        } else {
            (*f).lockcount = 0;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn __libc_current_sigrtmin() -> c_int {
    // musl 1.2.6 reserves 32, 33, and 34; application realtime signals start
    // at 35. Keep this tied to musl rather than glibc's moving SIGRTMIN.
    35
}

#[no_mangle]
pub unsafe extern "C" fn strdup(s: *const c_char) -> *mut c_char {
    if s.is_null() {
        return core::ptr::null_mut();
    }
    let len = crate::strlen(s);
    let p = crate::malloc(len + 1) as *mut c_char;
    if p.is_null() {
        return core::ptr::null_mut();
    }
    crate::memcpy(p as *mut c_void, s as *const c_void, len + 1);
    p
}

static mut MKTEMP_COUNTER: c_uint = 0;

unsafe fn mktemp_internal(
    template: *mut c_char,
    mkdir_fn: Option<unsafe extern "C" fn(*const c_char, c_uint) -> c_int>,
) -> *mut c_char {
    if template.is_null() {
        crate::__errno_location().write(EINVAL);
        return core::ptr::null_mut();
    }
    let len = crate::strlen(template);
    if len < 6 {
        crate::__errno_location().write(EINVAL);
        return core::ptr::null_mut();
    }
    let mut xcount = 0usize;
    while xcount < 6 {
        let ch = *template.add(len - 1 - xcount) as u8;
        if ch != b'X' {
            break;
        }
        xcount += 1;
    }
    if xcount != 6 {
        crate::__errno_location().write(EINVAL);
        return core::ptr::null_mut();
    }
    let _pid = crate::getpid();
    let mut c = MKTEMP_COUNTER;
    for _ in 0..1000 {
        let mut n = c;
        for i in 0..6 {
            let digit = (n % 36) as u8;
            let ch = if digit < 10 { b'0' + digit } else { b'a' + digit - 10 };
            *template.add(len - 6 + i) = ch as c_char;
            n /= 36;
        }
        c = c.wrapping_add(1);
        if mkdir_fn.is_some() {
            if crate::mkdir(template, 0o700) == 0 {
                MKTEMP_COUNTER = c;
                return template;
            }
            let e = crate::__errno_location().read();
            if e != EEXIST && e != EINTR {
                break;
            }
        } else {
            MKTEMP_COUNTER = c;
            return template;
        }
    }
    MKTEMP_COUNTER = c;
    template
}

#[no_mangle]
pub unsafe extern "C" fn mkdtemp(template: *mut c_char) -> *mut c_char {
    mktemp_internal(template, Some(crate::mkdir))
}

#[no_mangle]
pub unsafe extern "C" fn mktemp(template: *mut c_char) -> *mut c_char {
    mktemp_internal(template, None)
}
