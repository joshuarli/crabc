//! Static Linux/x86-64 C child-reaping boundary.
//!
//! This leaf owns the complete wait-status family already represented by the
//! project `<sys/wait.h>` record surface: [`wait`], [`waitpid`], and
//! [`waitid`]. It adapts only Linux's `wait4`/`waitid` syscall ABI to C's
//! initial-TLS `errno` convention. It does not select `fork`, `vfork`,
//! `execve`, process supervision, signal delivery, pthread-atfork hooks,
//! cancellation machinery, a dynamic libc, CRT, loader, sysroot, allocator,
//! or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/process/wait.c` maps `wait` to `waitpid(-1, status, 0)`.
//! - `src/process/waitpid.c` maps `waitpid` to
//!   `wait4(pid, status, options, NULL)`.
//! - `src/process/waitid.c` maps `waitid` to
//!   `waitid(idtype, id, info, options, NULL)`.
//!
//! Musl routes the latter two paths through `syscall_cp`, making them pthread
//! cancellation points. The selected static archive deliberately has no
//! pthread cancellation state, so these direct wrappers retain the same
//! kernel arguments and errno result mapping but not musl's cancellation
//! behavior. `WNOWAIT` and `WNOHANG` remain kernel-owned observation flags:
//! in particular, Linux reports a no-event `waitid(..., WNOHANG)` outcome
//! through a zeroed `siginfo_t` record only when the caller pre-zeroes it.

use core::ffi::{c_int, c_uint, c_void};

use super::{c_status, raw_syscall};

const WAIT_ANY: c_int = -1;
const NO_WAIT_OPTIONS: c_int = 0;

/// Issue Linux `wait4(pid, status, options, NULL)` without broadening the C
/// API to its `wait4` extension.
///
/// # Safety
///
/// If `status` is non-null, it must designate one writable x86 `int` for the
/// duration of the syscall. `pid` and `options` must obey Linux's `wait4(2)`
/// selection contract.
#[inline]
unsafe fn wait4_result(pid: c_int, status: *mut c_int, options: c_int) -> i64 {
    // SAFETY: the caller upholds the optional output-buffer and scalar wait4
    // contract. Linux/x86-64 receives its fourth null `rusage` argument in
    // `r10` through the raw syscall adapter.
    unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_WAIT4,
            i64::from(pid),
            status as usize as i64,
            i64::from(options),
            0,
        )
    }
}

/// Wait for any eligible child and return its process identifier.
///
/// `status` may be null. When non-null it must designate one writable x86
/// `int` for Linux to fill if this call reports a child. A `WNOHANG` no-event
/// result is zero and leaves that status word under Linux's normal wait4
/// contract. This function does not establish child creation, ownership,
/// cancellation, or pthread-atfork coordination.
#[no_mangle]
pub unsafe extern "C" fn wait(status: *mut c_int) -> c_int {
    // SAFETY: `wait` is the fixed `wait4(-1, status, 0, NULL)` spelling; the
    // caller upholds the optional status-pointer requirement above.
    let result = unsafe { wait4_result(WAIT_ANY, status, NO_WAIT_OPTIONS) };
    c_status(result)
}

/// Wait for an eligible child selected by `pid`.
///
/// `status` may be null; when non-null it must designate one writable x86
/// `int` for Linux's wait-status output. `options` is passed unchanged to
/// Linux, including `WNOHANG`; unsupported bits report the kernel's `EINVAL`
/// through the selected initial-TLS `errno` slot. This direct leaf omits the
/// musl pthread-cancellation point machinery.
#[no_mangle]
pub unsafe extern "C" fn waitpid(
    pid: c_int,
    status: *mut c_int,
    options: c_int,
) -> c_int {
    // SAFETY: the caller owns Linux's selection/options and optional
    // status-buffer contracts.
    let result = unsafe { wait4_result(pid, status, options) };
    c_status(result)
}

/// Observe or reap a selected child through Linux `waitid(2)`.
///
/// `info` is passed directly as Linux's 128-byte, eight-byte-aligned x86
/// `siginfo_t` output record. A C caller that supplies a non-null pointer must
/// keep that record writable for the syscall duration; invalid pointers are
/// left for Linux to reject with its normal error result. For a `WNOHANG`
/// no-event observation, callers that need to detect the Linux zero-`si_pid`
/// convention must pre-zero the record themselves. `WNOWAIT` observation does
/// not reap the child; a later eligible wait remains required.
///
/// This is a direct non-cancellation wrapper. It does not select `wait4`,
/// process creation, generic signal waits, or pthread lifecycle state.
#[no_mangle]
pub unsafe extern "C" fn waitid(
    id_type: c_int,
    id: c_uint,
    info: *mut c_void,
    options: c_int,
) -> c_int {
    // SAFETY: the caller owns Linux's id selector/options and `siginfo_t`
    // output-record contract. The raw adapter places `options`/NULL rusage in
    // Linux/x86-64's r10/r8 argument registers, respectively.
    let result = unsafe {
        raw_syscall::syscall5(
            raw_syscall::SYS_WAITID,
            i64::from(id_type),
            i64::from(id),
            info as usize as i64,
            i64::from(options),
            0,
        )
    };
    c_status(result)
}
