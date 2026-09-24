//! Selected static Linux/x86-64 `membarrier` direct-branch C ABI boundary.
//!
//! This leaf carries one caller-selected `int membarrier(int, int)` request
//! unchanged to Linux/x86-64 `membarrier=324`, then translates only Linux's
//! reserved raw error range through the selected initial-TLS `errno` slot. It
//! supplies no command policy, registration state, RSEQ lifecycle,
//! process/thread coordination, memory-ordering guarantee, allocator contract,
//! or Rust-facing API.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.
//! `src/linux/membarrier.c` gives the public weak `membarrier` spelling as an
//! alias of `__membarrier`. Its `__syscall(SYS_membarrier, cmd, flags)` and
//! `__syscall_ret` path is translated directly.
//!
//! Musl also emulates `MEMBARRIER_CMD_PRIVATE_EXPEDITED` with no flags when
//! the kernel refuses it. That is not an old-kernel path: Linux 5.10 returns
//! `EPERM` for this command to any process that has not registered with
//! `MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED`, and a filter may refuse the
//! registration. Owned runtime products translate the emulation through
//! `owned_synccall::emulate_private_expedited_membarrier` and the
//! registration hook `__membarrier_init` as [`register_private_expedited`],
//! which `pthread_create` calls before the process's first thread as musl's
//! `__pthread_create` does. The frozen private leaf build has neither a
//! thread list nor that hook and keeps only the direct branch.
//!
//! This leaf retains a standalone weak public binding but does not translate
//! musl's weak-alias relationship to its internal target.
//! The pinned AArch64 static ABI inventory records `membarrier.lo` as the weak
//! public owner. The existing project `<sys/membarrier.h>` declaration and
//! Linux command constants are header oracle evidence; their meanings remain
//! Linux-owned. Musl's header lacks C++ linkage guards while the existing
//! project header deliberately supplies an unmangled C++ bridge; that
//! header-only difference is separately evidenced and is not a runtime-source
//! translation claim.
//!
//! This is not a broad barrier API, command registry, global expedited
//! barrier policy, CPU-flag operation, RSEQ support, or syscall dispatch
//! framework.

use core::ffi::c_int;

use super::{c_status, raw_syscall};

#[cfg(crabc_x86_owned_runtime)]
const MEMBARRIER_CMD_PRIVATE_EXPEDITED: c_int = 8;
#[cfg(crabc_x86_owned_runtime)]
const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED: i64 = 16;

/// Forward one caller-selected Linux membarrier command and flag word.
///
/// The caller owns the selected Linux command/flag validity and every
/// resulting process- or system-wide synchronization consequence. In owned
/// runtime products a refused flagless `MEMBARRIER_CMD_PRIVATE_EXPEDITED` is
/// emulated across this process's threads, and then succeeds, as in musl.
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn membarrier(command: c_int, flags: c_int) -> c_int {
    // SAFETY: Linux/x86-64 syscall 324 takes the two C `int` words in rdi/rsi.
    // The direct raw result has the usual Linux error encoding; `c_status`
    // changes only a reserved raw error into -1 plus selected C errno.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_MEMBARRIER,
            i64::from(command),
            i64::from(flags),
        )
    };
    #[cfg(crabc_x86_owned_runtime)]
    if result != 0
        && command == MEMBARRIER_CMD_PRIVATE_EXPEDITED
        && flags == 0
        && super::owned_synccall::emulate_private_expedited_membarrier()
    {
        return 0;
    }
    c_status(result)
}

/// Musl `__membarrier_init`: register for the private expedited command
/// while the process is still single-threaded, because registering later has
/// unbounded latency. The result is deliberately ignored; a refused
/// registration leaves [`membarrier`] to emulate the command.
#[cfg(crabc_x86_owned_runtime)]
pub(super) fn register_private_expedited() {
    // SAFETY: a two-word membarrier request with no memory operands.
    let _ = unsafe {
        raw_syscall::syscall2(raw_syscall::SYS_MEMBARRIER, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0)
    };
}
