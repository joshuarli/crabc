// select-family entry points.
//
// Linux exposes `pselect6`, not a separate modern `select` syscall on AArch64.
// Both public entry points keep their caller's timeout untouched. The Linux
// `pselect6` ABI mutates its timeout pointer, so each wrapper passes a private
// temporary conversion instead.


const CABI_SYS_PSELECT6: i64 = 72;

#[repr(C)]
struct CabiPselectSigmask {
    mask: *const c_void,
    size: usize,
}

#[inline]
fn select_timespec(timeout: &timeval) -> Option<timespec> {
    // Match musl's legacy conversion policy: reject negative components,
    // carry every complete microsecond second into tv_sec, and reject a
    // carry which cannot be represented by the target C ABI.
    if timeout.tv_sec < 0 || timeout.tv_usec < 0 {
        return None;
    }
    let extra_seconds = timeout.tv_usec / 1_000_000;
    let tv_sec = timeout.tv_sec.checked_add(extra_seconds)?;
    let tv_nsec = (timeout.tv_usec % 1_000_000) * 1_000;
    Some(timespec { tv_sec, tv_nsec })
}

#[inline]
unsafe fn cabi_pselect6(
    nfds: c_int,
    readfds: *mut c_void,
    writefds: *mut c_void,
    exceptfds: *mut c_void,
    timeout: *mut timespec,
    sigmask: *const c_void,
) -> i64 {
    let signal_argument = CabiPselectSigmask {
        mask: sigmask,
        // Linux/AArch64 consumes the compact kernel signal set, not musl's
        // public 128-byte `sigset_t` representation.
        size: crabc_core::signal::KERNEL_SIGSET_SIZE,
    };
    aarch64_syscall::syscall6(
        CABI_SYS_PSELECT6,
        nfds as i64,
        readfds as i64,
        writefds as i64,
        exceptfds as i64,
        timeout as i64,
        &signal_argument as *const CabiPselectSigmask as i64,
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
    syscall_result(cabi_pselect6(
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
    let mut timeout_copy: timespec;
    let timeout_ptr = if timeout.is_null() {
        core::ptr::null_mut()
    } else {
        timeout_copy = match select_timespec(&*timeout) {
            Some(value) => value,
            None => {
                ERRNO = EINVAL;
                return -1;
            }
        };
        &mut timeout_copy
    };
    syscall_result(cabi_pselect6(
        nfds,
        readfds,
        writefds,
        exceptfds,
        timeout_ptr,
        core::ptr::null(),
    )) as c_int
}
