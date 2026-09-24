//! Selected static Linux/x86-64 C `clock_gettime` boundary.
//!
//! This leaf owns only the ordinary C clock-observation result and errno
//! boundary. It translates Linux's raw `-errno` result through the selected
//! initial-TLS errno slot, returning zero on success and `-1` on failure.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/time/clock_gettime.c::__clock_gettime` maps to the strong internal
//! body below, while `weak_alias(__clock_gettime, clock_gettime)` supplies the
//! public C spelling. Like musl's `cgt_init`, the owned runtimes resolve the
//! kernel vDSO `__vdso_clock_gettime` once from the startup-published
//! `AT_SYSINFO_EHDR` and call it thereafter; the vDSO itself enters the kernel
//! for clocks its data page cannot serve. An absent or malformed vDSO, or a
//! call before startup publishes the auxiliary vector, uses the direct
//! syscall. The bare leaf roster without an owned runtime has no auxv owner
//! and keeps the direct syscall.
//!
//! This does not select `clock_getres`, `clock_settime`, `time`, POSIX timers,
//! calendar/time-zone state, pthread cancellation, libc.so, CRT, dynamic TLS,
//! loader, sysroot, or public x86 support.

use core::ffi::{c_int, c_void};

use super::{c_status, raw_syscall};

// Musl keeps the implementation non-preemptible and publishes the ordinary C
// spelling as a weak same-address alias. Keep the directives next to the Rust
// body: a forwarding wrapper would change both the archive override point and
// the ELF address contract. The final shared link localizes the hidden body.
core::arch::global_asm!(
    ".hidden __clock_gettime",
    ".weak clock_gettime",
    ".set clock_gettime, __clock_gettime",
);

/// Read one Linux clock through the ordinary POSIX C result convention.
///
/// A successful query returns zero and preserves the caller's errno. Linux
/// errors return `-1` after publication in the calling initial-TLS errno slot.
///
/// # Safety
///
/// `output` must point to writable 16-byte, align-eight x86-64 `struct
/// timespec` storage for the syscall duration. A null or invalid output
/// pointer is outside this selected static-artifact contract: musl may route
/// valid clocks through vDSO code before a kernel syscall would report EFAULT.
/// The caller owns the clock identifier's meaning and the output record
/// lifetime.

#[no_mangle]
pub unsafe extern "C" fn __clock_gettime(clock_id: c_int, output: *mut c_void) -> c_int {
    // SAFETY: the caller owns the raw Linux clock ID and output-pointer contract.
    c_status(unsafe { clock_gettime_raw(clock_id, output) })
}

/// Read one clock and return Linux's raw zero-or-negative-errno result.
///
/// This is the one libc clock route shared by `clock_gettime`, `time`,
/// `clock`, `timespec_get`, and `gettimeofday`, as musl routes each of those
/// through `__clock_gettime`.
///
/// # Safety
///
/// `output` must satisfy the `struct timespec` contract of [`__clock_gettime`].
#[inline]
pub(super) unsafe fn clock_gettime_raw(clock_id: c_int, output: *mut c_void) -> i64 {
    #[cfg(crabc_x86_owned_runtime)]
    if let Some(vdso) = vdso::clock_gettime() {
        // SAFETY: a validated kernel vDSO entry takes the same two words and
        // returns zero or a negative Linux errno.
        return i64::from(unsafe { vdso(clock_id, output.cast()) });
    }
    // SAFETY: Linux/x86-64 receives the clock ID and output in rdi/rsi.
    unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_CLOCK_GETTIME,
            i64::from(clock_id),
            output as usize as i64,
        )
    }
}

/// Process-lifetime cache of the kernel vDSO `clock_gettime` entry.
///
/// The cache holds one immutable code address that guards no other data, so
/// relaxed ordering suffices; racing first callers resolve the same address.
#[cfg(crabc_x86_owned_runtime)]
mod vdso {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::super::auxv_observation;

    const UNRESOLVED: usize = 0;
    // The kernel image is absent or invalid: use the direct syscall.
    const DIRECT: usize = 1;
    static ENTRY: AtomicUsize = AtomicUsize::new(UNRESOLVED);

    #[inline]
    pub(super) fn clock_gettime() -> Option<crabc_core::time::VdsoClockGettime> {
        let entry = match ENTRY.load(Ordering::Relaxed) {
            UNRESOLVED => resolve()?,
            entry => entry,
        };
        // SAFETY: every other cached value was produced by `resolve` from a
        // validated vDSO function address.
        (entry != DIRECT).then(|| unsafe {
            core::mem::transmute::<usize, crabc_core::time::VdsoClockGettime>(entry)
        })
    }

    // Before startup publishes the auxiliary vector there is nothing to
    // resolve; stay uncached so a later call can still find the vDSO.
    #[cold]
    fn resolve() -> Option<usize> {
        let base = auxv_observation::initial_sysinfo_ehdr()?;
        // SAFETY: `base` is this process's kernel `AT_SYSINFO_EHDR` value.
        let entry = unsafe { crabc_core::time::vdso_clock_gettime(base) }
            .map_or(DIRECT, |function| function as usize);
        ENTRY.store(entry, Ordering::Relaxed);
        Some(entry)
    }
}
