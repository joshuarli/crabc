// scheduling and CPU-affinity exports.
//
// The supported interfaces are thin Linux syscall adapters.  The sched_*
// functions use the normal libc convention (-1 plus errno), while the
// pthread affinity functions return the error number directly, as required by
// the pthread API.  Affinity masks are intentionally opaque at this boundary:
// Linux accepts the caller's byte buffer and supplies the kernel's CPU mask.
//
// sched_getparam/sched_setparam and sched_getscheduler/sched_setscheduler are
// intentionally not included here.  musl exports those process-scheduling
// names as ENOSYS because Linux's corresponding syscalls operate on threads;
// exposing the raw thread operations under the POSIX process API would be a
// behavioral mismatch, not a real compatibility implementation.
const CABI_ESRCH: c_int = 3;


const CABI_SYS_SCHED_YIELD: i64 = 124;




const CABI_SYS_SCHED_GET_PRIORITY_MAX: i64 = 125;
const CABI_SYS_SCHED_GET_PRIORITY_MIN: i64 = 126;
const CABI_SYS_SCHED_RR_GET_INTERVAL: i64 = 127;


const CABI_SYS_SCHED_SETAFFINITY: i64 = 122;


const CABI_SYS_SCHED_GETAFFINITY: i64 = 123;


const CABI_SYS_GETCPU: i64 = 168;

#[inline]
unsafe fn cabi_sched_rr_get_interval(pid: c_int, interval: *mut timespec) -> i64 {
    aarch64_syscall::syscall2(
        CABI_SYS_SCHED_RR_GET_INTERVAL,
        pid as i64,
        interval as i64,
    )
}

#[inline]
unsafe fn cabi_sched_setaffinity(pid: c_int, cpusetsize: SizeT, mask: *const c_void) -> i64 {
    aarch64_syscall::syscall3(
        CABI_SYS_SCHED_SETAFFINITY,
        pid as i64,
        cpusetsize as i64,
        mask as i64,
    )
}

#[inline]
unsafe fn cabi_sched_getaffinity(pid: c_int, cpusetsize: SizeT, mask: *mut c_void) -> i64 {
    let result = aarch64_syscall::syscall3(
        CABI_SYS_SCHED_GETAFFINITY,
        pid as i64,
        cpusetsize as i64,
        mask as i64,
    );

    // Linux returns the number of bytes written.  A result larger than the
    // caller's buffer means the kernel mask did not fit and is EINVAL in the
    // POSIX wrapper (this also matches musl's sched_getaffinity contract).
    if result >= 0 && (result as usize) > cpusetsize {
        return -(EINVAL as i64);
    }
    if result >= 0 && (result as usize) < cpusetsize {
        // sched_getaffinity only writes the bytes represented by the
        // kernel's current mask.  POSIX callers expect the rest of their
        // cpu_set_t to be clear, just as with musl's wrapper.
        let written = result as usize;
        core::ptr::write_bytes((mask as *mut u8).add(written), 0, cpusetsize - written);
    }
    result
}

#[inline]
unsafe fn cabi_getcpu(cpu: *mut c_uint, node: *mut c_uint) -> i64 {
    aarch64_syscall::syscall3(CABI_SYS_GETCPU, cpu as i64, node as i64, 0)
}

#[inline]
fn cabi_pthread_errno(result: i64) -> c_int {
    if result < 0 && result >= -4095 {
        (-result) as c_int
    } else if result < 0 {
        // Linux syscall results are always in the negative errno range for
        // this interface; retain a valid pthread error if that invariant is
        // ever violated by a future architecture.
        EINVAL
    } else {
        0
    }
}

#[inline]
unsafe fn cabi_thread_tid(thread: PthreadT) -> Result<c_int, c_int> {
    if thread == 0 {
        return Err(CABI_ESRCH);
    }
    let slot = thread as *const Thread;
    let tid = (*slot).tid;
    if tid <= 0 {
        Err(CABI_ESRCH)
    } else {
        Ok(tid)
    }
}

#[no_mangle]
pub unsafe extern "C" fn sched_yield() -> c_int {
    c_result_unit(crabc_core::thread::sched_yield())
}

#[no_mangle]
pub unsafe extern "C" fn sched_getcpu() -> c_int {
    let mut cpu = 0u32;
    let mut node = 0u32;
    if syscall_result(cabi_getcpu(&mut cpu, &mut node)) < 0 {
        -1
    } else {
        cpu as c_int
    }
}

#[no_mangle]
pub unsafe extern "C" fn sched_get_priority_max(policy: c_int) -> c_int {
    syscall_result(aarch64_syscall::syscall1(
        CABI_SYS_SCHED_GET_PRIORITY_MAX,
        policy as i64,
    )) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn sched_get_priority_min(policy: c_int) -> c_int {
    syscall_result(aarch64_syscall::syscall1(
        CABI_SYS_SCHED_GET_PRIORITY_MIN,
        policy as i64,
    )) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn sched_rr_get_interval(pid: c_int, interval: *mut timespec) -> c_int {
    syscall_result(cabi_sched_rr_get_interval(pid, interval)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn sched_getaffinity(
    pid: c_int,
    cpusetsize: SizeT,
    mask: *mut c_void,
) -> c_int {
    let result = cabi_sched_getaffinity(pid, cpusetsize, mask);
    if result < 0 {
        syscall_result(result) as c_int
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn sched_setaffinity(
    pid: c_int,
    cpusetsize: SizeT,
    mask: *const c_void,
) -> c_int {
    syscall_result(cabi_sched_setaffinity(pid, cpusetsize, mask)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn __sched_cpucount(cpusetsize: SizeT, mask: *const c_void) -> c_int {
    let bytes = mask as *const u8;
    let mut count = 0u32;
    let mut offset = 0usize;

    // Count whole machine words first, then the tail.  read_unaligned keeps
    // this helper valid for a byte buffer supplied by a caller with no extra
    // alignment guarantee.
    while offset + core::mem::size_of::<usize>() <= cpusetsize {
        let word = core::ptr::read_unaligned(bytes.add(offset) as *const usize);
        count = count.wrapping_add(word.count_ones());
        offset += core::mem::size_of::<usize>();
    }
    while offset < cpusetsize {
        count = count.wrapping_add((*bytes.add(offset)).count_ones());
        offset += 1;
    }
    count as c_int
}

#[no_mangle]
pub unsafe extern "C" fn pthread_getaffinity_np(
    thread: PthreadT,
    cpusetsize: SizeT,
    mask: *mut c_void,
) -> c_int {
    let tid = match cabi_thread_tid(thread) {
        Ok(tid) => tid,
        Err(error) => return error,
    };
    cabi_pthread_errno(cabi_sched_getaffinity(tid, cpusetsize, mask))
}

#[no_mangle]
pub unsafe extern "C" fn pthread_setaffinity_np(
    thread: PthreadT,
    cpusetsize: SizeT,
    mask: *const c_void,
) -> c_int {
    let tid = match cabi_thread_tid(thread) {
        Ok(tid) => tid,
        Err(error) => return error,
    };
    cabi_pthread_errno(cabi_sched_setaffinity(tid, cpusetsize, mask))
}
