//! Selected static Linux/x86-64 C `fcntl` record-lock boundary.
//!
//! This leaf owns the pointer-bearing nonblocking record-lock forms
//! `fcntl(fd, F_GETLK, struct flock *)` and
//! `fcntl(fd, F_SETLK, struct flock *)`. The owned runtime also admits
//! `F_SETLKW` through its syscall cancellation window. It composes Linux `fcntl=72`
//! and the selected initial-TLS C `errno` publisher. It is not generic C
//! `fcntl`, OFD locks, `lockf`, `flock`,
//! lock ownership/signalling, leases, seals, descriptor or pathname policy,
//! a filesystem capability, libc.so, CRT, pthread/TLS lifecycle, dynamic TLS,
//! loader, sysroot, allocator, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/fcntl/fcntl.c` forwards the first variadic word as the record
//!   pointer for `F_GETLK`, `F_SETLK`, and `F_SETLKW` to Linux `fcntl`.
//!
//! Musl routes only `F_SETLKW` through its cancellation-point syscall path.
//! Only the owned-runtime composition admits that blocking form. The raw
//! standalone profile retains its prior rejection. Other `fcntl` commands
//! remain excluded. The public assembly dispatcher has already established
//! that these selected calls carry the required third C vararg in x86 rdx;
//! Linux receives the same fd/command/record-pointer words in rdi/rsi/rdx.

use core::ffi::{c_int, c_void};

use super::{c_status, errno, raw_syscall};

const EINVAL: c_int = 22;
const F_GETLK: c_int = 5;
const F_SETLK: c_int = 6;
#[cfg(feature = "x86-owned-static-runtime")]
const F_SETLKW: c_int = 7;

/// Forward one selected pointer-bearing record-lock `fcntl` call.
///
/// # Safety
///
/// The caller must supply a live writable x86 Linux `struct flock` record for
/// syscall duration, including a blocking `F_SETLKW` wait. Linux reads it for
/// `F_SETLK`/`F_SETLKW` and may overwrite it
/// for `F_GETLK`; all record contents and lock-state effects remain caller
/// owned.
#[inline(never)]
pub(super) unsafe extern "C" fn fcntl_record_lock(
    descriptor: c_int,
    command: c_int,
    record: *mut c_void,
) -> c_int {
    #[cfg(feature = "x86-owned-static-runtime")]
    if command == F_SETLKW {
        // Musl's only canceling fcntl command. The assembly dispatcher proves
        // that the C caller supplied the record pointer in rdx; the caller
        // keeps that record live while Linux waits for the conflicting lock.
        return c_status(unsafe {
            super::pthread_cancel::syscall_cp(
                raw_syscall::SYS_FCNTL,
                i64::from(descriptor),
                i64::from(command),
                record as usize as i64,
                0, 0, 0,
            )
        });
    }
    if command != F_GETLK && command != F_SETLK {
        // SAFETY: the selected static C ABI owns the calling initial-TLS
        // errno slot. The assembly dispatch never reaches this branch, but
        // keeping the helper closed avoids a new generic fcntl back door.
        unsafe { errno::set_errno(EINVAL) };
        return -1;
    }
    // SAFETY: the assembly dispatcher reaches this helper only after C has
    // supplied its pointer vararg in rdx. The caller owns the complete
    // writable `struct flock` contract; Linux validates descriptor, command,
    // lock fields, and pointer accessibility.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_FCNTL,
            i64::from(descriptor),
            i64::from(command),
            record as usize as i64,
        )
    };
    c_status(result)
}
