// M4 Linux polling and event descriptors.
//
// These entry points keep the public C ABI at the edge and pass the native
// Linux syscall layouts through unchanged. `epoll_event` is packed only by the
// x86_64 kernel ABI. AArch64 uses its natural 16-byte C layout; using x86_64's
// packed shape there shifts `data` four bytes and corrupts returned events.

#[repr(C)]
pub struct M4PollFd {
    fd: c_int,
    events: i16,
    revents: i16,
}

#[cfg_attr(target_arch = "x86_64", repr(C, packed))]
#[cfg_attr(not(target_arch = "x86_64"), repr(C))]
pub struct M4EpollEvent {
    events: c_uint,
    data: u64,
}

#[cfg(target_arch = "x86_64")]
const M4_SYS_EPOLL_CREATE: i64 = 213;
#[cfg(target_arch = "x86_64")]
const M4_SYS_EPOLL_CTL: i64 = 233;
#[cfg(target_arch = "x86_64")]
const M4_SYS_EPOLL_WAIT: i64 = 232;
#[cfg(target_arch = "x86_64")]
const M4_SYS_EPOLL_PWAIT: i64 = 281;
#[cfg(target_arch = "x86_64")]
const M4_SYS_EPOLL_CREATE1: i64 = 291;
#[cfg(target_arch = "x86_64")]
const M4_SYS_EVENTFD2: i64 = 290;
#[cfg(target_arch = "x86_64")]
const M4_SYS_INOTIFY_ADD_WATCH: i64 = 254;
#[cfg(target_arch = "x86_64")]
const M4_SYS_INOTIFY_RM_WATCH: i64 = 255;
#[cfg(target_arch = "x86_64")]
const M4_SYS_INOTIFY_INIT1: i64 = 294;

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_EPOLL_CTL: i64 = 21;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_EPOLL_PWAIT: i64 = 22;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_EPOLL_CREATE1: i64 = 20;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_EVENTFD2: i64 = 19;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_INOTIFY_INIT1: i64 = 26;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_INOTIFY_ADD_WATCH: i64 = 27;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_INOTIFY_RM_WATCH: i64 = 28;

#[inline]
unsafe fn m4_ppoll(
    fds: *mut M4PollFd,
    nfds: usize,
    timeout: *const timespec,
    sigmask: *const c_void,
) -> i64 {
    // Linux's kernel sigset is one unsigned long even though the public
    // userspace sigset_t reserves space for 1024 signals. SigSetT is the
    // kernel-sized representation used by this crate's signal syscalls.
    match unsafe {
        crabc_core::event::ppoll_raw(
            fds.cast(),
            nfds,
            timeout.cast(),
            sigmask.cast(),
            core::mem::size_of::<SigSetT>(),
        )
    } {
        Ok(ready) => ready as i64,
        Err(errno) => -(errno.raw() as i64),
    }
}

#[inline]
#[cfg(target_arch = "aarch64")]
unsafe fn m4_epoll_pwait(
    epfd: c_int,
    events: *mut M4EpollEvent,
    maxevents: c_int,
    timeout: c_int,
    sigmask: *const c_void,
) -> i64 {
    match crabc_core::event::epoll_pwait_raw(
        epfd,
        events.cast(),
        maxevents as usize,
        timeout,
        sigmask.cast(),
        core::mem::size_of::<SigSetT>(),
    ) {
        Ok(ready) => ready as i64,
        Err(errno) => -(errno.raw() as i64),
    }
}

#[inline]
#[cfg(not(target_arch = "aarch64"))]
unsafe fn m4_epoll_pwait(
    epfd: c_int,
    events: *mut M4EpollEvent,
    maxevents: c_int,
    timeout: c_int,
    sigmask: *const c_void,
) -> i64 {
    <Arch as Syscalls>::syscall6(
        M4_SYS_EPOLL_PWAIT,
        epfd as i64,
        events as i64,
        maxevents as i64,
        timeout as i64,
        sigmask as i64,
        core::mem::size_of::<SigSetT>() as i64,
    )
}

#[no_mangle]
pub unsafe extern "C" fn poll(fds: *mut M4PollFd, nfds: usize, timeout: c_int) -> c_int {
    let timeout_storage = if timeout >= 0 {
        timespec {
            tv_sec: (timeout as c_long) / 1000,
            tv_nsec: ((timeout as c_long) % 1000) * 1_000_000,
        }
    } else {
        timespec { tv_sec: 0, tv_nsec: 0 }
    };
    let timeout_ptr = if timeout >= 0 {
        &timeout_storage as *const timespec
    } else {
        core::ptr::null()
    };
    syscall_result(m4_ppoll(fds, nfds, timeout_ptr, core::ptr::null())) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn ppoll(
    fds: *mut M4PollFd,
    nfds: usize,
    timeout: *const timespec,
    sigmask: *const c_void,
) -> c_int {
    syscall_result(m4_ppoll(fds, nfds, timeout, sigmask)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn epoll_create(size: c_int) -> c_int {
    if size <= 0 {
        ERRNO = EINVAL;
        return -1;
    }
    // epoll_create1(0) is the equivalent modern syscall on targets without
    // the historical epoll_create entry point.
    #[cfg(target_arch = "aarch64")]
    {
        return c_result_fd(crabc_core::event::epoll_create1(0));
    }
    #[cfg(target_arch = "x86_64")]
    {
        return syscall_result(<Arch as Syscalls>::syscall1(M4_SYS_EPOLL_CREATE, size as i64))
            as c_int;
    }
    #[cfg(target_arch = "riscv64")]
    {
        return syscall_result(<Arch as Syscalls>::syscall1(M4_SYS_EPOLL_CREATE1, 0)) as c_int;
    }
}

#[no_mangle]
pub unsafe extern "C" fn epoll_create1(flags: c_int) -> c_int {
    #[cfg(target_arch = "aarch64")]
    {
        return c_result_fd(crabc_core::event::epoll_create1(flags as u32));
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        return syscall_result(<Arch as Syscalls>::syscall1(M4_SYS_EPOLL_CREATE1, flags as i64))
            as c_int;
    }
}

#[no_mangle]
pub unsafe extern "C" fn epoll_ctl(
    epfd: c_int,
    op: c_int,
    fd: c_int,
    event: *const M4EpollEvent,
) -> c_int {
    #[cfg(target_arch = "aarch64")]
    {
        return c_result_unit(unsafe {
            crabc_core::event::epoll_ctl_raw(
                epfd,
                op as u32,
                fd,
                event.cast(),
            )
        });
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        return syscall_result(<Arch as Syscalls>::syscall4(
            M4_SYS_EPOLL_CTL,
            epfd as i64,
            op as i64,
            fd as i64,
            event as i64,
        )) as c_int;
    }
}

#[no_mangle]
pub unsafe extern "C" fn epoll_wait(
    epfd: c_int,
    events: *mut M4EpollEvent,
    maxevents: c_int,
    timeout: c_int,
) -> c_int {
    #[cfg(target_arch = "x86_64")]
    let result = <Arch as Syscalls>::syscall4(
        M4_SYS_EPOLL_WAIT,
        epfd as i64,
        events as i64,
        maxevents as i64,
        timeout as i64,
    );
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    let result = m4_epoll_pwait(epfd, events, maxevents, timeout, core::ptr::null());
    syscall_result(result) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn epoll_pwait(
    epfd: c_int,
    events: *mut M4EpollEvent,
    maxevents: c_int,
    timeout: c_int,
    sigmask: *const c_void,
) -> c_int {
    syscall_result(m4_epoll_pwait(epfd, events, maxevents, timeout, sigmask)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn eventfd(initval: c_uint, flags: c_int) -> c_int {
    match crabc_core::event::eventfd(initval, flags as c_uint) {
        Ok(fd) => fd,
        Err(errno) => {
            ERRNO = errno.raw();
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn eventfd_read(fd: c_int, value: *mut u64) -> c_int {
    let result = read(fd, value as *mut c_void, core::mem::size_of::<u64>());
    if result == core::mem::size_of::<u64>() as isize {
        0
    } else if result < 0 {
        -1
    } else {
        ERRNO = EINVAL;
        -1
    }
}

#[no_mangle]
pub unsafe extern "C" fn eventfd_write(fd: c_int, value: u64) -> c_int {
    let result = write(
        fd,
        &value as *const u64 as *const c_void,
        core::mem::size_of::<u64>(),
    );
    if result == core::mem::size_of::<u64>() as isize {
        0
    } else if result < 0 {
        -1
    } else {
        ERRNO = EINVAL;
        -1
    }
}

#[no_mangle]
pub unsafe extern "C" fn inotify_init() -> c_int {
    syscall_result(<Arch as Syscalls>::syscall1(M4_SYS_INOTIFY_INIT1, 0)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn inotify_init1(flags: c_int) -> c_int {
    syscall_result(<Arch as Syscalls>::syscall1(M4_SYS_INOTIFY_INIT1, flags as i64)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn inotify_add_watch(
    fd: c_int,
    path: *const c_char,
    mask: u32,
) -> c_int {
    syscall_result(<Arch as Syscalls>::syscall3(
        M4_SYS_INOTIFY_ADD_WATCH,
        fd as i64,
        path as i64,
        mask as i64,
    )) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn inotify_rm_watch(fd: c_int, wd: c_int) -> c_int {
    syscall_result(<Arch as Syscalls>::syscall2(
        M4_SYS_INOTIFY_RM_WATCH,
        fd as i64,
        wd as i64,
    )) as c_int
}
