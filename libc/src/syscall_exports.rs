// filesystem and process syscall exports.
//
// The underlying sys_* helpers intentionally retain Linux's negative-errno
// convention.  These public entry points are the C ABI boundary: each uses
// syscall_result so callers receive the usual -1 return and errno value.

#[no_mangle]
pub unsafe extern "C" fn fchmodat(
    dirfd: c_int,
    path: *const c_char,
    mode: mode_t,
    flags: c_int,
) -> c_int {
    syscall_result(sys_fchmodat(dirfd, path as *const u8, mode, flags)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn linkat(
    olddirfd: c_int,
    oldpath: *const c_char,
    newdirfd: c_int,
    newpath: *const c_char,
    flags: c_int,
) -> c_int {
    syscall_result(sys_linkat(
        olddirfd,
        oldpath as *const u8,
        newdirfd,
        newpath as *const u8,
        flags,
    )) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn mkdirat(
    dirfd: c_int,
    path: *const c_char,
    mode: mode_t,
) -> c_int {
    syscall_result(sys_mkdirat(dirfd, path as *const u8, mode)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn readlinkat(
    dirfd: c_int,
    path: *const c_char,
    buf: *mut c_char,
    bufsiz: SizeT,
) -> SSizeT {
    syscall_result(sys_readlinkat(
        dirfd,
        path as *const u8,
        buf as *mut u8,
        bufsiz,
    )) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn renameat(
    olddirfd: c_int,
    oldpath: *const c_char,
    newdirfd: c_int,
    newpath: *const c_char,
) -> c_int {
    syscall_result(sys_renameat2(
        olddirfd,
        oldpath as *const u8,
        newdirfd,
        newpath as *const u8,
        0,
    )) as c_int
}

// renameat2 is a Linux extension and is intentionally exposed without a
// public header declaration in this tree.  Its flags argument is unsigned in
// the Linux ABI, matching the kernel and musl declarations.
#[no_mangle]
pub unsafe extern "C" fn renameat2(
    olddirfd: c_int,
    oldpath: *const c_char,
    newdirfd: c_int,
    newpath: *const c_char,
    flags: c_uint,
) -> c_int {
    syscall_result(sys_renameat2(
        olddirfd,
        oldpath as *const u8,
        newdirfd,
        newpath as *const u8,
        flags,
    )) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn symlinkat(
    target: *const c_char,
    newdirfd: c_int,
    linkpath: *const c_char,
) -> c_int {
    syscall_result(sys_symlinkat(
        target as *const u8,
        newdirfd,
        linkpath as *const u8,
    )) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn unlinkat(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
) -> c_int {
    syscall_result(sys_unlinkat(dirfd, path as *const u8, flags)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn wait4(
    pid: c_int,
    status: *mut c_int,
    options: c_int,
    rusage: *mut c_void,
) -> c_int {
    syscall_result(sys_wait4(pid, status, options, rusage)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn wait3(
    status: *mut c_int,
    options: c_int,
    rusage: *mut c_void,
) -> c_int {
    syscall_result(sys_wait4(-1, status, options, rusage)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn gettid() -> c_int {
    crabc_core::thread::gettid() as c_int
}

// C11 _Fork is the fork primitive without pthread_atfork callbacks.  Keep it
// on the raw syscall path; fork() in lib.rs deliberately invokes those hooks.
#[no_mangle]
pub unsafe extern "C" fn _Fork() -> c_int {
    syscall_result(sys_fork(false)) as c_int
}
