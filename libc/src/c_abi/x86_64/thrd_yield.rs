//! Bounded Linux/x86-64 static C11 `thrd_yield` leaf.
//!
//! This private static ABI leaf is source-mapped to pinned musl 1.2.6 release
//! commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/thread/thrd_yield.c::thrd_yield` is the complete direct raw
//! `SYS_sched_yield` invocation below. Musl deliberately ignores that raw
//! result because C11 `thrd_yield` is void. In particular, a Linux error is
//! not translated through C `errno`; the public entry returns only after the
//! kernel boundary, exactly as the selected musl object does.
//!
//! Linux 5.10 x86-64 `sched_yield=24` has no arguments. This leaf does not
//! select the POSIX `sched_yield` C API, scheduler policy or parameter APIs,
//! affinity, pthread scheduling attributes, a scheduling guarantee, C11
//! lifecycle/synchronization/TSS/cancellation, dynamic or loader TLS, CRT,
//! sysroot, general pthread/C11 behavior, x86-64 parity, promotion, and public x86 support.

use super::raw_syscall;

/// Yield the calling task's remaining CPU time through the direct Linux C11
/// boundary.
///
/// The C11 API returns no status and does not publish a raw failure through errno.
/// It also does not accidentally expose the separate POSIX `sched_yield`
/// result convention.
#[no_mangle]
pub extern "C" fn thrd_yield() {
    // SAFETY: Linux/x86-64 `sched_yield=24` consumes no arguments. The raw
    // result is intentionally ignored by the C11 void-returning contract.
    let _ = unsafe { raw_syscall::syscall0(raw_syscall::SYS_SCHED_YIELD) };
}
