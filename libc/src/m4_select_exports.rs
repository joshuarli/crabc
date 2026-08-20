// M4 select-family entry points.
//
// Linux exposes `pselect6`, not a separate modern `select` syscall on AArch64.
// `pselect` keeps its caller's const timeout untouched, while `select`
// deliberately passes a mutable converted timeout and writes back the kernel's
// remaining interval.

#[cfg(target_arch = "x86_64")]
const M4_SYS_PSELECT6: i64 = 270;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_PSELECT6: i64 = 72;

#[repr(C)]
struct M4PselectSigmask {
    mask: *const c_void,
    size: usize,
}

#[inline]
unsafe fn m4_pselect6(
    nfds: c_int,
    readfds: *mut c_void,
    writefds: *mut c_void,
    exceptfds: *mut c_void,
    timeout: *mut timespec,
    sigmask: *const c_void,
) -> i64 {
    let signal_argument = M4PselectSigmask {
        mask: sigmask,
        size: core::mem::size_of::<SigSetT>(),
    };
    <Arch as Syscalls>::syscall6(
        M4_SYS_PSELECT6,
        nfds as i64,
        readfds as i64,
        writefds as i64,
        exceptfds as i64,
        timeout as i64,
        &signal_argument as *const M4PselectSigmask as i64,
    )
}

#[no_mangle]
pub unsafe extern "C" fn pselect(
    nfds: c_int,
    readfds: *mut c_void,
    writefds: *mut c_void,
    exceptfds: *mut c_void,
    timeout: *const timespec,
    sigmask: *const c_void,
) -> c_int {
    // The public timeout is const. pselect6 updates its timeout pointer, so
    // route the syscall through a local copy exactly as musl does.
    let mut timeout_copy = if timeout.is_null() {
        timespec { tv_sec: 0, tv_nsec: 0 }
    } else {
        timespec {
            tv_sec: (*timeout).tv_sec,
            tv_nsec: (*timeout).tv_nsec,
        }
    };
    let timeout_ptr = if timeout.is_null() { core::ptr::null_mut() } else { &mut timeout_copy };
    syscall_result(m4_pselect6(
        nfds,
        readfds,
        writefds,
        exceptfds,
        timeout_ptr,
        sigmask,
    )) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn select(
    nfds: c_int,
    readfds: *mut c_void,
    writefds: *mut c_void,
    exceptfds: *mut c_void,
    timeout: *mut timeval,
) -> c_int {
    let mut timeout_copy = timespec { tv_sec: 0, tv_nsec: 0 };
    let timeout_ptr = if timeout.is_null() {
        core::ptr::null_mut()
    } else {
        timeout_copy.tv_sec = (*timeout).tv_sec;
        timeout_copy.tv_nsec = (*timeout).tv_usec * 1_000;
        &mut timeout_copy
    };
    let result = syscall_result(m4_pselect6(
        nfds,
        readfds,
        writefds,
        exceptfds,
        timeout_ptr,
        core::ptr::null(),
    ));
    if !timeout.is_null() {
        (*timeout).tv_sec = timeout_copy.tv_sec;
        (*timeout).tv_usec = timeout_copy.tv_nsec / 1_000;
    }
    result as c_int
}
