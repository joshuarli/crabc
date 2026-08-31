//! Selected static Linux/x86-64 GNU `sched_getcpu` observation boundary.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license,
//! maps `src/sched/sched_getcpu.c::sched_getcpu` to this leaf's public result
//! and errno convention. On x86-64 that source can first use its private
//! `VDSO_GETCPU_SYM` resolver and one-time atomic cache. Static Initial TLS v1
//! owns neither a vDSO resolver nor dynamic process-lifetime state, so this
//! selected artifact intentionally implements only musl's raw syscall fallback:
//! `__syscall(SYS_getcpu, &cpu, 0, 0)` followed by `__syscall_ret(r)` on
//! failure. The existing target-local typed seam separately takes the direct
//! Linux `getcpu` path with its own CPU/NUMA output pair; this C ABI leaf asks
//! only for CPU output and adds no new scheduler implementation.
//!
//! Linux 5.10 x86-64 `getcpu=309` writes a private unsigned CPU word through
//! `rdi`; the node and cache words are null in `rsi` and `rdx`. A successful
//! raw status is zero and the C result is the nonnegative CPU number while
//! preserving incoming errno. A raw Linux failure becomes `-1` plus the
//! calling initial-TLS errno through [`c_status`](super::c_status).
//!
//! This observes only the calling task's current CPU at one instant. It does
//! not select a vDSO resolver, NUMA-node observation, cache state, CPU-set or
//! scheduler-affinity APIs, scheduler policy/parameters, priority bounds,
//! scheduler yielding, thread or pthread state, clock/timer/calendar/timezone
//! policy, process migration, CPU topology, libc.so, CRT, dynamic TLS,
//! loader, sysroot, allocator, family completion, promotion, or public x86 support.

use core::ffi::{c_int, c_uint};

use super::{c_status, raw_syscall};

/// Return the CPU executing the calling task through musl's GNU C convention.
///
/// Success returns a nonnegative Linux CPU number and preserves the caller's
/// errno. A raw Linux error returns `-1` after publishing its positive errno
/// through the selected initial-TLS slot. The result is an instantaneous
/// observation: the task may migrate before any later operation, and this
/// leaf supplies neither affinity nor CPU-topology policy.
#[no_mangle]
pub extern "C" fn sched_getcpu() -> c_int {
    let mut cpu: c_uint = 0;
    // SAFETY: `cpu` is private writable unsigned-int storage for Linux
    // getcpu=309. The two null words request no NUMA-node or cache result,
    // exactly as musl's selected raw syscall fallback does.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_GETCPU,
            (&mut cpu as *mut c_uint) as usize as i64,
            0,
            0,
        )
    };
    if result == 0 {
        cpu as c_int
    } else {
        c_status(result)
    }
}
