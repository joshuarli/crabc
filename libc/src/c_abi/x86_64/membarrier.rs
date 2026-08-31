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
//! alias of `__membarrier`. Its initial `__syscall(SYS_membarrier, cmd, flags)`
//! and `__syscall_ret` path is the selected Linux 5.10 branch here. Musl also
//! carries an old-kernel `MEMBARRIER_CMD_PRIVATE_EXPEDITED` signal/semaphore
//! fallback and `__membarrier_init` registration hook; neither is translated
//! or exported by this leaf. The focused fixture therefore exercises only
//! `MEMBARRIER_CMD_QUERY` and direct invalid-command/invalid-flag results.
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
//! This private compatibility artifact is not full musl `membarrier`, a broad
//! barrier API, old-kernel fallback, command registry, global/private expedited
//! barrier policy, command registration, CPU-flag operation, RSEQ support,
//! syscall dispatch framework, libc.so, CRT, loader, sysroot,
//! allocator/runtime lifecycle, family completion, promotion, or public x86
//! support.

use core::ffi::c_int;

use super::{c_status, raw_syscall};

/// Forward one caller-selected Linux membarrier command and flag word.
///
/// The caller owns the selected Linux command/flag validity and every
/// resulting process- or system-wide synchronization consequence. This C ABI
/// bridge does not retain state or add a policy layer around that kernel
/// operation. It is the selected Linux 5.10 direct branch only: it does not
/// emulate musl's old-kernel PRIVATE_EXPEDITED fallback or call its registration
/// hook.
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
    c_status(result)
}
