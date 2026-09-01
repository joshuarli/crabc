//! Private static Linux/x86-64 `wait3`/`wait4` C ABI boundary.
//!
//! This leaf owns exactly the historical GNU/BSD `wait3` and `wait4` spellings.
//! Both directly adapt Linux `wait4(2)` to the selected initial-TLS C `errno`
//! result boundary. They do not select the existing `wait`/`waitpid`/`waitid`
//! child-reaping artifact, C process creation, a process supervisor, signal
//! delivery, pthread cancellation or atfork state, a dynamic libc, CRT,
//! loader, sysroot, allocator, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/linux/wait3.c::wait3` delegates exactly to
//!   `wait4(-1, status, options, usage)`.
//! - `src/linux/wait4.c::wait4` takes the ordinary direct `SYS_wait4` route on
//!   x86-64 LP64. Its time64 conversion branch is for time32 targets and does
//!   not apply here.
//!
//! Unlike musl's `src/process/waitpid.c`, these two Linux extension sources do
//! not use the cancellation-point syscall route. Linux initializes only the
//! 144-byte prefix of the public 272-byte x86 `struct rusage`; its 128-byte
//! compatibility tail remains caller-resident, so this leaf neither clears nor
//! translates that record.

use core::ffi::c_int;

use super::{c_status, process_resources::Rusage, raw_syscall};

const WAIT_ANY: c_int = -1;

/// Reap or observe a Linux-selected child with optional resource accounting.
///
/// `status` and `usage` may each be null. A non-null `status` must designate a
/// writable x86 `int`; a non-null `usage` must designate one writable public
/// x86 `struct rusage`, both for the syscall's duration. Linux owns `pid` and
/// `options` validation and all resulting child-state transitions, including
/// a successful reaping operation. Callers arrange child ownership and any
/// concurrent wait policy; this direct leaf owns no cancellation protocol.
#[no_mangle]
pub unsafe extern "C" fn wait4(
    pid: c_int,
    status: *mut c_int,
    options: c_int,
    usage: *mut Rusage,
) -> c_int {
    // SAFETY: the caller upholds both optional writable-output contracts and
    // Linux's child selector/options contract. Linux/x86-64 receives usage in
    // r10, its fourth syscall argument register.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_WAIT4,
            i64::from(pid),
            status as usize as i64,
            i64::from(options),
            usage as usize as i64,
        )
    };
    c_status(result)
}

/// Reap or observe any eligible child through musl's `wait4(-1, ...)` form.
///
/// The optional `status` and `usage` outputs have the same writable-lifetime
/// obligations as [`wait4`]. This is a historical GNU/BSD C ABI spelling, not
/// an ownership or process-supervision abstraction.
#[no_mangle]
pub unsafe extern "C" fn wait3(
    status: *mut c_int,
    options: c_int,
    usage: *mut Rusage,
) -> c_int {
    // SAFETY: wait3 is exactly musl's wait4(-1, status, options, usage)
    // delegation, preserving the optional-output contracts documented above.
    unsafe { wait4(WAIT_ANY, status, options, usage) }
}
