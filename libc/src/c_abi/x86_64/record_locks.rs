//! Selected static Linux/x86-64 C `fcntl` record-lock boundary.
//!
//! This leaf owns exactly the pointer-bearing nonblocking record-lock forms
//! `fcntl(fd, F_GETLK, struct flock *)` and
//! `fcntl(fd, F_SETLK, struct flock *)`. It composes only Linux `fcntl=72`
//! and the selected initial-TLS C `errno` publisher. It is not generic C
//! `fcntl`, blocking `F_SETLKW` cancellation, OFD locks, `lockf`, `flock`,
//! lock ownership/signalling, leases, seals, descriptor or pathname policy,
//! a filesystem capability, libc.so, CRT, pthread/TLS lifecycle, dynamic TLS,
//! loader, sysroot, allocator, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/fcntl/fcntl.c` forwards the first variadic word as the record
//!   pointer for `F_GETLK` and `F_SETLK` to Linux `fcntl`.
//!
//! Musl routes only `F_SETLKW` through its cancellation-point syscall path.
//! This leaf deliberately admits neither that blocking form nor any other
//! `fcntl` command. The public assembly dispatcher has already established
//! that these selected calls carry the required third C vararg in x86 rdx;
//! Linux receives the same fd/command/record-pointer words in rdi/rsi/rdx.

use core::ffi::{c_int, c_void};

use super::{c_status, errno, raw_syscall};

const EINVAL: c_int = 22;
const F_GETLK: c_int = 5;
const F_SETLK: c_int = 6;

/// Forward one selected pointer-bearing record-lock `fcntl` call.
///
/// # Safety
///
/// The caller must supply a live writable x86 Linux `struct flock` record for
/// the raw syscall duration. Linux reads it for `F_SETLK` and may overwrite it
/// for `F_GETLK`; all record contents and lock-state effects remain caller
/// owned.
#[inline(never)]
pub(super) unsafe extern "C" fn fcntl_record_lock(
    descriptor: c_int,
    command: c_int,
    record: *mut c_void,
) -> c_int {
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
