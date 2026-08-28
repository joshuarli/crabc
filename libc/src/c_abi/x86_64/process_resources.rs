//! Selected static Linux/x86-64 C process-resource boundary.
//!
//! This leaf owns one coherent, bounded native C resource block:
//! `getrlimit`, `setrlimit`, GNU `prlimit` (whose public header aliases
//! `prlimit64` to it), `getrusage`, `getpriority`, `setpriority`, and `nice`.
//! It composes only the raw Linux syscall register boundary and the selected
//! initial-TLS C `errno` slot. It is not process accounting through `times`,
//! scheduler policy or cgroups, C fork/wait/exec, a process supervisor, a
//! general C/POSIX runtime, libc.so, CRT, pthread/TLS lifecycle, dynamic TLS,
//! loader, sysroot, allocator, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/misc/getrlimit.c` and `src/misc/setrlimit.c` map to the two
//!   `prlimit64`-based limit wrappers below.
//! - `src/linux/prlimit.c` maps to [`prlimit`].
//! - `src/misc/getrusage.c`, `src/misc/getpriority.c`, and
//!   `src/misc/setpriority.c` map to their correspondingly named wrappers.
//! - `src/unistd/nice.c` maps to [`nice`], including its bounded query/clamp
//!   sequence, preserved successful-query `errno`, and `EACCES` to `EPERM`
//!   compatibility mapping.
//!
//! Linux 5.10 is the project baseline, where `prlimit64` is available. This
//! leaf deliberately omits musl's old `getrlimit`/`setrlimit` syscall fallbacks
//! and its `setrlimit` process-wide `__synccall` fallback: selecting either
//! would invent an unsupported pre-baseline or pthread coordination contract.
//! On LP64, musl's infinity conversion is a no-op. Linux initializes only the
//! 144-byte `rusage` prefix; this module passes the full public record directly
//! and therefore leaves its 128-byte compatibility tail caller-resident.

use core::ffi::{c_int, c_long, c_uint};
use core::mem::{align_of, offset_of, size_of};

use super::{c_status, errno, raw_syscall};

const EACCES: c_int = 13;
const EPERM: c_int = 1;
const PRIO_PROCESS: c_int = 0;
const NZERO: c_int = 20;

/// Exact x86 public `struct rlimit` storage.
///
/// The selected C ABI owns the public field spelling in `<sys/resource.h>`.
/// Rust-facing resource APIs remain separately typed in `crabc-rs`.
#[repr(C)]
pub struct Rlimit {
    current: u64,
    maximum: u64,
}

/// Private LP64 `timeval` representation inside the public resource record.
#[repr(C)]
struct Timeval {
    seconds: c_long,
    microseconds: c_long,
}

/// Exact x86 public `struct rusage` storage.
///
/// Linux fills only the prefix through `involuntary_context_switches`; the
/// trailing sixteen `long` values retain caller bytes, exactly as musl's
/// public compatibility record requires.
#[repr(C)]
pub struct Rusage {
    user_time: Timeval,
    system_time: Timeval,
    counters: [c_long; 14],
    reserved: [c_long; 16],
}

const _: () = {
    assert!(size_of::<Rlimit>() == 16);
    assert!(align_of::<Rlimit>() == 8);
    assert!(offset_of!(Rlimit, current) == 0);
    assert!(offset_of!(Rlimit, maximum) == 8);
    assert!(size_of::<Timeval>() == 16);
    assert!(align_of::<Timeval>() == 8);
    assert!(size_of::<Rusage>() == 272);
    assert!(align_of::<Rusage>() == 8);
    assert!(offset_of!(Rusage, user_time) == 0);
    assert!(offset_of!(Rusage, system_time) == 16);
    assert!(offset_of!(Rusage, counters) == 32);
    assert!(offset_of!(Rusage, reserved) == 144);
};

/// Query one calling-process resource limit through Linux `prlimit64(2)`.
///
/// # Safety
///
/// `output` must point to writable storage for one complete x86 public
/// `struct rlimit` for the syscall's duration. `resource` reaches Linux
/// unchanged; the caller owns any concurrent process resource policy.
#[no_mangle]
pub unsafe extern "C" fn getrlimit(resource: c_int, output: *mut Rlimit) -> c_int {
    // SAFETY: the caller owns the complete writable C limit-record contract;
    // Linux/x86 places the null new-limit in rdx and output in r10.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_PRLIMIT64,
            0,
            i64::from(resource),
            0,
            output as usize as i64,
        )
    };
    c_status(result)
}

/// Replace one calling-process resource limit through Linux `prlimit64(2)`.
///
/// # Safety
///
/// `input` must point to readable storage for one complete x86 public
/// `struct rlimit` for the syscall's duration. A successful limit mutation is
/// process-wide: callers must arrange authority, thread coordination, and
/// restoration. This leaf does not provide musl's pthread `__synccall`
/// behavior.
#[no_mangle]
pub unsafe extern "C" fn setrlimit(resource: c_int, input: *const Rlimit) -> c_int {
    // SAFETY: the caller owns the complete readable C limit-record and
    // process-wide mutation contract; the null old-limit is in x86 r10.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_PRLIMIT64,
            0,
            i64::from(resource),
            input as usize as i64,
            0,
        )
    };
    c_status(result)
}

/// Query or replace a target process's resource limit through `prlimit64(2)`.
///
/// # Safety
///
/// `input` and `output` must each be null or point to complete readable and
/// writable x86 public `struct rlimit` records, respectively, for the
/// syscall's duration. A non-null `input` changes another process's resource
/// limit subject to Linux permission and lifetime rules; callers must arrange
/// authority, target-process coordination, and restoration.
#[no_mangle]
pub unsafe extern "C" fn prlimit(
    process_id: c_int,
    resource: c_int,
    input: *const Rlimit,
    output: *mut Rlimit,
) -> c_int {
    // SAFETY: the caller owns both optional public-record contracts. Linux
    // uses x86 r10 for the fourth old-limit pointer rather than C ABI rcx.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_PRLIMIT64,
            i64::from(process_id),
            i64::from(resource),
            input as usize as i64,
            output as usize as i64,
        )
    };
    c_status(result)
}

/// Fill one public `struct rusage` through Linux `getrusage(2)`.
///
/// # Safety
///
/// `output` must point to writable storage for one complete x86 public
/// `struct rusage` for the syscall's duration. Linux initializes only its
/// first 144 bytes; this wrapper deliberately preserves the caller's 128-byte
/// musl compatibility tail and does not zero or otherwise interpret it.
#[no_mangle]
pub unsafe extern "C" fn getrusage(resource: c_int, output: *mut Rusage) -> c_int {
    // SAFETY: the caller owns the complete public record. Linux's initialized
    // prefix is ABI-compatible and does not touch the public tail.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_GETRUSAGE,
            i64::from(resource),
            output as usize as i64,
        )
    };
    c_status(result)
}

/// Return the calling priority value for one Linux priority subject.
///
/// Linux encodes a successful priority as `1..=40`; C exposes `20 - raw`.
/// A returned C value of `-1` can therefore be success, so this wrapper leaves
/// `errno` unchanged on every successful result as musl requires.
#[no_mangle]
pub extern "C" fn getpriority(which: c_int, who: c_uint) -> c_int {
    // SAFETY: both arguments are scalar Linux priority words. `id_t` is the
    // unsigned 32-bit C word, preserving selectors such as zero exactly.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_GETPRIORITY,
            i64::from(which),
            i64::from(who),
        )
    };
    if result < 0 {
        c_status(result)
    } else {
        NZERO - result as c_int
    }
}

/// Set one Linux priority subject's nice value.
///
/// Linux owns validation, permission, and target selection. This direct leaf
/// does not select scheduler policy, cgroups, or process-wide coordination.
#[no_mangle]
pub extern "C" fn setpriority(which: c_int, who: c_uint, priority: c_int) -> c_int {
    // SAFETY: all inputs are scalar Linux priority words passed unchanged.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_SETPRIORITY,
            i64::from(which),
            i64::from(who),
            i64::from(priority),
        )
    };
    c_status(result)
}

/// Adjust the calling process's nice value with musl-compatible semantics.
///
/// For increments in `(-40, 40)`, this reads the current priority and
/// preserves its pre-existing `errno` when that query succeeds, exactly as
/// musl does. It then clamps the target to `[-20, 19]`, requests it through
/// `setpriority(PRIO_PROCESS, 0, ...)`, and maps Linux `EACCES` to C `EPERM`.
/// The mutation remains process-sensitive: this leaf does not provide
/// authority, scheduler-policy, or pthread coordination.
#[no_mangle]
pub extern "C" fn nice(increment: c_int) -> c_int {
    let mut priority = increment;
    if increment > -2 * NZERO && increment < 2 * NZERO {
        // The bounded add cannot overflow. Like musl, a successful
        // getpriority leaves any prior errno intact; this wrapper makes no
        // extra error-disambiguation decision before the setpriority step.
        priority += getpriority(PRIO_PROCESS, 0);
    }
    if priority > NZERO - 1 {
        priority = NZERO - 1;
    }
    if priority < -NZERO {
        priority = -NZERO;
    }

    if setpriority(PRIO_PROCESS, 0, priority) != 0 {
        // Musl's nice wrapper exposes EPERM rather than the kernel's EACCES
        // when an unprivileged caller attempts a priority raise.
        // SAFETY: this leaf owns the selected calling-thread errno slot.
        if unsafe { errno::get_errno() } == EACCES {
            // SAFETY: publish the documented musl compatibility mapping.
            unsafe { errno::set_errno(EPERM) };
        }
        -1
    } else {
        priority
    }
}
