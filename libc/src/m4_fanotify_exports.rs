// M4 Linux fanotify entry points.  These wrappers intentionally preserve the
// kernel's policy decision: an unprivileged namespace may reject a requested
// notification class, but crabc never substitutes a synthetic descriptor or
// mark result.

#[cfg(target_arch = "x86_64")]
const M4_SYS_FANOTIFY_INIT: i64 = 300;
#[cfg(target_arch = "x86_64")]
const M4_SYS_FANOTIFY_MARK: i64 = 301;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_FANOTIFY_INIT: i64 = 262;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_FANOTIFY_MARK: i64 = 263;

#[no_mangle]
pub unsafe extern "C" fn fanotify_init(flags: c_uint, event_f_flags: c_uint) -> c_int {
    let result = <Arch as Syscalls>::syscall2(
        M4_SYS_FANOTIFY_INIT,
        flags as i64,
        event_f_flags as i64,
    );
    if result < 0 {
        ERRNO = (-result) as c_int;
        -1
    } else {
        result as c_int
    }
}

#[no_mangle]
pub unsafe extern "C" fn fanotify_mark(
    fanotify_fd: c_int,
    flags: c_uint,
    mask: u64,
    dirfd: c_int,
    pathname: *const c_char,
) -> c_int {
    let result = <Arch as Syscalls>::syscall5(
        M4_SYS_FANOTIFY_MARK,
        fanotify_fd as i64,
        flags as i64,
        mask as i64,
        dirfd as i64,
        pathname as i64,
    );
    if result < 0 {
        ERRNO = (-result) as c_int;
        -1
    } else {
        result as c_int
    }
}
