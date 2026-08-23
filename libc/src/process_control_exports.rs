// process-control exports.
//
// These wrappers preserve the two error conventions used by this API family:
// process and scheduling interfaces return -1 and set errno, while
// pthread_getcpuclockid returns the positive error number directly.  The
// implementation intentionally goes through Linux's native syscalls rather
// than emulating process state in libc.

const CABI_PROCESS_ESRCH: c_int = 3;
// Linux's thread CPU clock is the scheduler clock kind (2) plus the
// per-thread mask (4), not CLOCK_THREAD_CPUTIME_ID's user-facing value.
const CABI_CLOCK_THREAD_CPUTIME_ID: c_int = 6;

#[cfg(target_arch = "x86_64")]
const CABI_SYS_WAITID: i64 = 247;
#[cfg(target_arch = "riscv64")]
const CABI_SYS_WAITID: i64 = 95;

// The calls operate on the kernel's task ID; pid 0 denotes the calling task,
// as it does for the POSIX wrappers. x86_64 uses its legacy syscall table;
// AArch64 and RISC-V use asm-generic's distinct scheduler range.
#[cfg(target_arch = "x86_64")]
const CABI_SYS_SCHED_SETPARAM: i64 = 142;
#[cfg(target_arch = "x86_64")]
const CABI_SYS_SCHED_GETPARAM: i64 = 143;
#[cfg(target_arch = "x86_64")]
const CABI_SYS_SCHED_SETSCHEDULER: i64 = 144;
#[cfg(target_arch = "x86_64")]
const CABI_SYS_SCHED_GETSCHEDULER: i64 = 145;

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_SCHED_SETPARAM: i64 = 118;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_SCHED_SETSCHEDULER: i64 = 119;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_SCHED_GETSCHEDULER: i64 = 120;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_SCHED_GETPARAM: i64 = 121;

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn cabi_waitid(
    idtype: c_int,
    id: c_uint,
    info: *mut siginfo_t,
    options: c_int,
) -> i64 {
    match unsafe {
        crabc_core::process::waitid_raw(idtype as u32, id, info.cast(), options as u32)
    } {
        Ok(()) => 0,
        Err(errno) => -(errno.raw() as i64),
    }
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
unsafe fn cabi_waitid(
    idtype: c_int,
    id: c_uint,
    info: *mut siginfo_t,
    options: c_int,
) -> i64 {
    <Arch as Syscalls>::syscall5(
        CABI_SYS_WAITID,
        idtype as i64,
        id as i64,
        info as i64,
        options as i64,
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn waitid(
    idtype: c_int,
    id: c_uint,
    info: *mut siginfo_t,
    options: c_int,
) -> c_int {
    syscall_result(cabi_waitid(idtype, id, info, options)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn killpg(pgrp: c_int, sig: c_int) -> c_int {
    // kill(2) interprets a negative pid as a process-group target.  Widen
    // before negating so even the INT_MIN pid_t value is represented safely.
    syscall_result(<Arch as Syscalls>::syscall2(
        SYS_KILL,
        -(pgrp as i64),
        sig as i64,
    )) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn sched_getparam(
    pid: c_int,
    param: *mut sched_param,
) -> c_int {
    syscall_result(<Arch as Syscalls>::syscall2(
        CABI_SYS_SCHED_GETPARAM,
        pid as i64,
        param as i64,
    )) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn sched_getscheduler(pid: c_int) -> c_int {
    syscall_result(<Arch as Syscalls>::syscall1(
        CABI_SYS_SCHED_GETSCHEDULER,
        pid as i64,
    )) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn sched_setparam(
    pid: c_int,
    param: *const sched_param,
) -> c_int {
    syscall_result(<Arch as Syscalls>::syscall2(
        CABI_SYS_SCHED_SETPARAM,
        pid as i64,
        param as i64,
    )) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn sched_setscheduler(
    pid: c_int,
    policy: c_int,
    param: *const sched_param,
) -> c_int {
    syscall_result(<Arch as Syscalls>::syscall3(
        CABI_SYS_SCHED_SETSCHEDULER,
        pid as i64,
        policy as i64,
        param as i64,
    )) as c_int
}

#[inline]
unsafe fn cabi_pthread_thread_tid(thread: PthreadT) -> Result<c_int, c_int> {
    if thread == 0 {
        return Err(CABI_PROCESS_ESRCH);
    }

    // pthread_t is an opaque pointer to one of libc's Thread slots.  Check
    // the slot range before dereferencing so an invalid handle reports the
    // pthread API's ESRCH error instead of faulting the process.
    let first = core::ptr::addr_of_mut!(THREADS[0]) as usize;
    let slot_size = core::mem::size_of::<Thread>();
    let last = first + slot_size * MAX_THREADS;
    let address = thread as usize;
    if address < first || address >= last || (address - first) % slot_size != 0 {
        return Err(CABI_PROCESS_ESRCH);
    }

    let slot = thread as *const Thread;
    let tid = core::ptr::read_volatile(core::ptr::addr_of!((*slot).tid));
    if tid <= 0 {
        Err(CABI_PROCESS_ESRCH)
    } else {
        Ok(tid)
    }
}

#[no_mangle]
pub unsafe extern "C" fn pthread_getcpuclockid(
    thread: PthreadT,
    clock: *mut c_int,
) -> c_int {
    if clock.is_null() {
        return EINVAL;
    }
    let tid = match cabi_pthread_thread_tid(thread) {
        Ok(tid) => tid,
        Err(error) => return error,
    };

    // Linux CPU-clock IDs encode the task ID as (~tid << 3) and use the low
    // three bits for the clock kind.  Compute in u32 to avoid signed overflow
    // while retaining the public clockid_t (int) representation.
    let id = (0u32
        .wrapping_sub(tid as u32)
        .wrapping_sub(1)
        .wrapping_shl(3)
        | CABI_CLOCK_THREAD_CPUTIME_ID as u32) as c_int;

    // A slot can become invalid between the range check and this syscall.  A
    // kernel EINVAL for the encoded ID therefore has the pthread API's ESRCH
    // meaning; preserve any other real kernel error as a direct return.
    let mut resolution: timespec = core::mem::zeroed();
    let result = sys_clock_getres(id, &mut resolution);
    if result == -(EINVAL as i64) {
        return CABI_PROCESS_ESRCH;
    }
    if result < 0 {
        return (-result) as c_int;
    }

    *clock = id;
    0
}
