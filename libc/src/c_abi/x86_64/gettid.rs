//! Selected static Linux/x86-64 GNU `gettid` C ABI boundary.
//!
//! This private leaf owns exactly the no-argument current-task identifier
//! observation from pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.
//! The upstream source mapping is `src/linux/gettid.c::gettid`. Musl reads
//! `__pthread_self()->tid` from its complete thread control block. This
//! selected static archive deliberately owns no general TCB, thread list, or
//! dynamic-TLS lifecycle, so it obtains the same current Linux task ID with
//! the direct Linux 5.10 x86-64 `gettid=186` syscall instead.
//!
//! On the ordinary Linux success path both routes return the same positive
//! signed `pid_t`. The direct syscall is an intentional local adaptation, not
//! a claim that this archive supplies musl's TCB. A seccomp-injected raw
//! kernel failure is returned as its signed kernel word and does not invent an
//! errno write; musl's TCB read has no corresponding syscall failure path.
//! The public GNU declaration is `pid_t gettid(void)`, whose four-byte signed
//! result is returned in `eax` under the System V AMD64 ABI.
//!
//! This leaf selects no process identity aggregate, scheduler behavior,
//! pthread API, TCB/TLS state, errno, allocation, cancellation, signal,
//! loader, CRT, sysroot, family completion, promotion, or public x86 support.

use core::ffi::c_int;

use super::raw_syscall;

/// Return the calling Linux task identifier through the direct x86 syscall.
#[no_mangle]
pub extern "C" fn gettid() -> c_int {
    // SAFETY: Linux/x86-64 `gettid=186` has no arguments. The selected C ABI
    // preserves the raw signed result rather than publishing a C errno value.
    unsafe { raw_syscall::syscall0(raw_syscall::SYS_GETTID) as c_int }
}
