//! Selected static Linux/x86-64 `aio_error` C ABI boundary.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` maps
//! `src/aio/aio.c::aio_error` to this one read-only error-word observation.
//! Musl places a compiler-only `a_barrier()` before a volatile load of
//! `struct aiocb::__err`, then clears its sign bit. On Linux/x86-64 LP64 that
//! public field is a naturally aligned `volatile int` at byte offset 112 of
//! the 168-byte `struct aiocb`; the Rust compiler fence and volatile load
//! preserve that source-shaped boundary without creating runtime state.
//!
//! This target-local leaf owns no AIO request submission, `aio_return`, wait,
//! cancellation, fsync, list-I/O, completion, synchronization protocol,
//! thread, errno/TLS, allocation, syscall, descriptor I/O, resolver, socket,
//! loader, CRT, or public x86 support. It does not make an `aiocb` safe to
//! inspect concurrently: caller-provided AIO/external synchronization remains
//! the caller's responsibility.

use core::{
    arch::asm,
    ffi::{c_int, c_void},
    sync::atomic::{compiler_fence, Ordering},
};

const AIOCB_ERR_OFFSET: usize = 112;
const AIO_ERROR_MASK: c_int = 0x7fff_ffff;

/// Observe the selected `struct aiocb::__err` word with musl's sign-bit mask.
///
/// # Safety
///
/// `control_block` must be non-null and point to a live, naturally aligned
/// Linux/x86-64 LP64 `struct aiocb` whose `volatile int __err` field at byte
/// offset 112 is readable for this call. The caller must provide the same
/// external synchronization required to read that field while AIO state may
/// change. This function neither initializes nor synchronizes AIO state.
#[no_mangle]
pub unsafe extern "C" fn aio_error(control_block: *const c_void) -> c_int {
    // Musl's x86 a_barrier is a compiler-only empty asm with a memory clobber.
    // A SeqCst compiler fence supplies the corresponding compiler ordering
    // without a hardware barrier or a runtime dependency.
    compiler_fence(Ordering::SeqCst);

    let error: c_int;
    // SAFETY: the caller contract supplies a readable, aligned `__err` field
    // at the selected public LP64 offset. The direct x86 load avoids a Rust
    // debug precondition helper, preserving the archive-free closure while
    // retaining musl's volatile observation rather than adding an atomic
    // protocol.
    unsafe {
        asm!(
            "mov {error:e}, dword ptr [{control_block} + {error_offset}]",
            control_block = in(reg) control_block,
            error_offset = const AIOCB_ERR_OFFSET,
            error = lateout(reg) error,
            options(nostack, preserves_flags, readonly),
        );
    }
    error & AIO_ERROR_MASK
}
