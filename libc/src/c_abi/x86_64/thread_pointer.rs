//! Private Linux/x86-64 opaque thread-pointer leaf.
//!
//! Provenance is fixed to musl 1.2.6 (`9fa28ece75d8a2191de7c5bb53bed224c5947417`),
//! under musl's MIT license recorded in its `COPYRIGHT` file. The exact source
//! mapping is `arch/x86_64/pthread_arch.h::__get_tp()`'s `%fs:0` read to
//! [`thread_pointer_identity`]. The intentional difference is deliberate and
//! bounded: this leaf stops before musl's `__pthread_self()`/`TP_OFFSET`
//! arithmetic, returning only an opaque current-thread identity rather than a
//! project-defined TCB layout. The isolated native probe selects this file
//! directly; `crabc-libc` remains AArch64-only until the complete x86 C ABI and
//! runtime are proven.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 thread-pointer leaf requires little-endian Linux/x86-64");

use core::arch::asm;
use core::ffi::c_void;

/// Snapshot the calling thread's opaque musl x86 thread-pointer word.
///
/// The returned value must not be dereferenced, used for `pthread_t`, or
/// retained across thread exit or runtime/TLS transitions. A zero word remains
/// representable during earliest runtime setup; this leaf does not initialize
/// TLS, allocate it, or write an FS base.
///
/// # Safety
///
/// The caller must execute on native Linux/x86-64 in a thread runtime whose
/// `%fs` base permits a readable word at offset zero. A missing or invalid FS
/// base may fault before this function can return.
#[inline(always)]
pub(crate) unsafe fn thread_pointer_identity() -> *mut c_void {
    let thread_pointer: usize;
    // SAFETY: the caller supplies a native thread context with a readable
    // `%fs:0` word. This snapshots that word without dereferencing the result
    // or modifying TLS state. `readonly` is required because the instruction
    // reads memory; it neither uses the stack nor changes condition flags.
    unsafe {
        asm!(
            "mov {thread_pointer}, fs:[0]",
            thread_pointer = out(reg) thread_pointer,
            options(readonly, nostack, preserves_flags),
        );
    }
    thread_pointer as *mut c_void
}
