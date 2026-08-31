//! Selected static Linux/x86-64 `clock_getcpuclockid` C boundary.
//!
//! This private one-symbol process CPU-clock-ID query is a source-faithful
//! translation of pinned musl 1.2.6 release revision
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/time/clock_getcpuclockid.c`. Musl computes
//! `(-pid-1)*8U + 2`, probes that encoded Linux clock with
//! `clock_getres`, maps the kernel's `EINVAL` to positive `ESRCH`, and writes
//! the caller's `clockid_t` only after the probe succeeds.
//!
//! The exact source closure is one direct Linux 5.10 `clock_getres=229`
//! syscall with an otherwise private local `struct timespec`; it deliberately
//! does not call the separately selected C `clock_getres` ABI, so this
//! positive-status function has no errno/TLS, clock policy, or vDSO state.
//! As in the C source, `pid == INT_MIN` has signed-overflow before the unsigned
//! multiplication and is outside the selected source-defined input domain.
//!
//! This does not select `clock`, `clock_gettime`, C `clock_getres`, clock
//! mutation, timer or sleep APIs, scheduler policy, `pthread_getcpuclockid`,
//! signal actions/masks/delivery, process lifecycle, libc.so, CRT, loader,
//! sysroot, promotion, or public x86 support.

use core::ffi::{c_int, c_long};
use core::mem::{align_of, size_of, MaybeUninit};

use super::raw_syscall;

const CLOCK_PROCESS_CPUTIME_ID: u32 = 2;
const EINVAL: c_int = 22;
const ESRCH: c_int = 3;

/// Exact Linux/x86-64 `struct timespec` scratch storage for `clock_getres`.
#[repr(C)]
struct Timespec {
    seconds: c_long,
    nanoseconds: c_long,
}

const _: () = {
    assert!(size_of::<Timespec>() == 16);
    assert!(align_of::<Timespec>() == 8);
};

/// Encode musl's Linux process CPU-clock selector using its 32-bit word rule.
///
/// The source's unary negation is defined for every `pid_t` except `INT_MIN`.
/// This unsigned representation preserves the resulting x86-64 word value;
/// callers remain responsible for musl's defined-input domain.
#[inline]
fn process_cpu_clock_id(pid: c_int) -> c_int {
    (0u32
        .wrapping_sub(pid as u32)
        .wrapping_sub(1)
        .wrapping_shl(3)
        | CLOCK_PROCESS_CPUTIME_ID) as c_int
}

/// Return a Linux process CPU-clock ID through musl's positive-status ABI.
///
/// A valid process ID returns zero after storing one x86 `clockid_t` (`int`).
/// A process rejected by Linux's `clock_getres` probe returns `ESRCH`; another
/// kernel failure returns its positive errno. This function does not write C
/// `errno` or inspect the output pointer on a failed probe.
///
/// # Safety
///
/// `clock_id` must point to writable four-byte x86-64 `clockid_t` storage when
/// the encoded query succeeds. It may be invalid only when the query fails,
/// because musl dereferences it only after the successful probe. `pid` must
/// stay outside musl's `INT_MIN` signed-overflow input boundary.
#[no_mangle]
pub unsafe extern "C" fn clock_getcpuclockid(pid: c_int, clock_id: *mut c_int) -> c_int {
    let id = process_cpu_clock_id(pid);
    let mut resolution = MaybeUninit::<Timespec>::uninit();

    // SAFETY: Linux/x86-64 `clock_getres=229` receives the encoded signed
    // clock word and writable local timespec pointer in rdi/rsi. The local
    // output remains unobserved exactly as in musl's source.
    let mut result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_CLOCK_GETRES,
            i64::from(id),
            resolution.as_mut_ptr() as usize as i64,
        )
    } as c_int;
    if result == -EINVAL {
        result = -ESRCH;
    }
    if result != 0 {
        return result.wrapping_neg();
    }

    // SAFETY: after Linux accepted the encoded clock, the caller owns musl's
    // writable `clockid_t` output contract.
    unsafe { clock_id.write(id) };
    0
}
