// M4 clock-administration exports.
//
// The adjustment and clock-setting interfaces remain kernel-owned.  Keep
// these wrappers on raw Linux syscalls so a caller without CAP_SYS_TIME gets
// the kernel's EPERM (and never a fabricated success).  The timex layout is
// the native 64-bit musl/Linux ABI used by both x86_64 and AArch64.

#[cfg(target_arch = "x86_64")]
const M4_SYS_CLOCK_ADJTIME: i64 = 305;
#[cfg(target_arch = "x86_64")]
const M4_SYS_ADJTIMEX: i64 = 159;
#[cfg(target_arch = "x86_64")]
const M4_SYS_SETTIMEOFDAY: i64 = 164;
#[cfg(target_arch = "x86_64")]
const M4_SYS_STIME: i64 = 25;

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_CLOCK_ADJTIME: i64 = 266;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_ADJTIMEX: i64 = 171;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_SETTIMEOFDAY: i64 = 170;

#[repr(C)]
pub struct M4Timex {
    pub modes: c_uint,
    pub offset: c_long,
    pub freq: c_long,
    pub maxerror: c_long,
    pub esterror: c_long,
    pub status: c_int,
    pub constant: c_long,
    pub precision: c_long,
    pub tolerance: c_long,
    pub time: timeval,
    pub tick: c_long,
    pub ppsfreq: c_long,
    pub jitter: c_long,
    pub shift: c_int,
    pub stabil: c_long,
    pub jitcnt: c_long,
    pub calcnt: c_long,
    pub errcnt: c_long,
    pub stbcnt: c_long,
    pub tai: c_int,
    pub padding: [c_int; 11],
}

const M4_ADJ_OFFSET_SINGLESHOT: c_uint = 0x8001;

#[inline]
unsafe fn m4_clock_adjtime(clock_id: c_int, tx: *mut M4Timex) -> i64 {
    <Arch as Syscalls>::syscall2(M4_SYS_CLOCK_ADJTIME, clock_id as i64, tx as i64)
}

#[inline]
unsafe fn m4_adjtimex(tx: *mut M4Timex) -> i64 {
    <Arch as Syscalls>::syscall1(M4_SYS_ADJTIMEX, tx as i64)
}

#[inline]
unsafe fn m4_settimeofday(tv: *const timeval, tz: *const c_void) -> i64 {
    <Arch as Syscalls>::syscall2(M4_SYS_SETTIMEOFDAY, tv as i64, tz as i64)
}

#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn m4_stime(seconds: *const TimeT) -> i64 {
    <Arch as Syscalls>::syscall1(M4_SYS_STIME, seconds as i64)
}

#[no_mangle]
pub unsafe extern "C" fn clock_adjtime(clock_id: c_int, tx: *mut M4Timex) -> c_int {
    syscall_result(m4_clock_adjtime(clock_id, tx)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn adjtimex(tx: *mut M4Timex) -> c_int {
    // Linux has a dedicated realtime adjtimex syscall.  This is the path
    // musl's CLOCK_REALTIME clock_adjtime wrapper selects as well.
    syscall_result(m4_adjtimex(tx)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn adjtime(increment: *const timeval, remaining: *mut timeval) -> c_int {
    // ADJ_OFFSET_SINGLESHOT returns the previous outstanding adjustment in
    // tx.offset.  A zero-mode query is used when no new adjustment is given.
    let mut tx: M4Timex = core::mem::zeroed();
    if !increment.is_null() {
        // timeval permits a signed microsecond component here, but not one
        // that is a whole second or more.  Normalize the complete interval
        // only after proving it fits Linux's signed-long timex offset.
        if (*increment).tv_usec <= -1_000_000 || (*increment).tv_usec >= 1_000_000 {
            ERRNO = EINVAL;
            return -1;
        }
        let offset = (*increment).tv_sec as i128 * 1_000_000i128
            + (*increment).tv_usec as i128;
        if offset < c_long::MIN as i128 || offset > c_long::MAX as i128 {
            ERRNO = EINVAL;
            return -1;
        }
        tx.offset = offset as c_long;
        tx.modes = M4_ADJ_OFFSET_SINGLESHOT;
    }

    if adjtimex(&mut tx) < 0 {
        return -1;
    }
    if !remaining.is_null() {
        (*remaining).tv_sec = tx.offset / 1_000_000;
        (*remaining).tv_usec = tx.offset % 1_000_000;
        if (*remaining).tv_usec < 0 {
            (*remaining).tv_sec -= 1;
            (*remaining).tv_usec += 1_000_000;
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn settimeofday(tv: *const timeval, tz: *const c_void) -> c_int {
    // musl treats a missing timeval as the historical no-op form.  No
    // privileged operation is attempted in that case; a supplied timeval
    // always reaches Linux so CAP_SYS_TIME and its errno remain authoritative.
    if tv.is_null() {
        return 0;
    }
    syscall_result(m4_settimeofday(tv, tz)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn stime(seconds: *const TimeT) -> c_int {
    #[cfg(target_arch = "x86_64")]
    {
        return syscall_result(m4_stime(seconds)) as c_int;
    }

    // arm64 and riscv64 omit the legacy stime syscall.  Keep the musl
    // contract by translating to settimeofday's native syscall instead.
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    {
        if seconds.is_null() {
            ERRNO = EFAULT;
            return -1;
        }
        let tv = timeval {
            tv_sec: *seconds,
            tv_usec: 0,
        };
        return settimeofday(&tv, core::ptr::null());
    }
}
