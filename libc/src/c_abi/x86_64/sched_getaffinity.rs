//! Bounded Linux/x86-64 static GNU scheduler-affinity observation boundary.
//!
//! This private static ABI leaf is source-mapped to pinned musl 1.2.6 release
//! commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/sched/affinity.c::do_getaffinity` supplies the raw result, successful
//! initialized-prefix preservation, and caller-tail zeroing, while
//! `src/sched/affinity.c::sched_getaffinity` supplies C `errno` translation.
//!
//! Linux 5.10 x86-64 syscall `sched_getaffinity=204` observes one thread's
//! affinity mask and returns its initialized byte count. For every successful
//! result smaller than the caller's `cpusetsize`, musl preserves that prefix
//! and clears the remaining caller-owned bytes before returning zero. Raw
//! errors become `-1` plus initial-TLS `errno`; the pointer is never touched
//! after an error. The direct x86 byte stores below are behavior-equivalent to
//! musl's `memset` tail clear but retain this one-symbol closure without
//! selecting a separate memory C ABI leaf.
//!
//! This leaf selects only GNU `sched_getaffinity(pid_t, size_t, cpu_set_t *)`.
//! It selects neither `sched_setaffinity`, CPU allocation/count/macro helpers,
//! scheduler policy or parameters, pthread affinity or lifecycle, dynamic or
//! loader TLS, CRT, sysroot, promotion, nor public x86 support.

use core::{arch::asm, ffi::{c_int, c_void}};

use super::{c_status, raw_syscall};

/// Read one Linux task's affinity mask with musl-compatible tail zeroing.
///
/// # Safety
///
/// `mask` must be valid writable storage for exactly `cpusetsize` bytes for
/// the syscall and, after a successful kernel return smaller than that size,
/// for the subsequent tail clear. The caller owns task lifetime and affinity
/// observation races; this leaf neither mutates affinity nor coordinates
/// pthread or process lifecycle state.
#[no_mangle]
pub unsafe extern "C" fn sched_getaffinity(
    task_id: c_int,
    cpusetsize: usize,
    mask: *mut c_void,
) -> c_int {
    // SAFETY: the caller owns the Linux writable-buffer contract documented
    // above. Linux/x86-64 receives pid, byte count, and mask in rdi/rsi/rdx.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_SCHED_GETAFFINITY,
            i64::from(task_id),
            cpusetsize as i64,
            mask as usize as i64,
        )
    };

    if result < 0 {
        return c_status(result);
    }

    let initialized = result as usize;
    if initialized < cpusetsize {
        let mut offset = initialized;
        while offset < cpusetsize {
            // SAFETY: success initialized the prefix; the caller promised the
            // entire byte extent is writable. This direct x86 store keeps the
            // one-symbol codegen closure while matching musl's zero values.
            unsafe {
                asm!(
                    "mov byte ptr [{address}], 0",
                    address = in(reg) mask.cast::<u8>().add(offset),
                    options(nostack, preserves_flags),
                );
            }
            offset += 1;
        }
    }
    0
}
