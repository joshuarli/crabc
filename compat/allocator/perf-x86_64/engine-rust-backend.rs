// SPDX-License-Identifier: MIT
//! Rust persistent-engine implementation of the private engine performance
//! boundary declared in `engine-api.h`.
//!
//! Every operation enters the same hidden `crabc_mimalloc::__crabc_runtime`
//! entry point that crabc-libc's compile-time `native-mimalloc-shadow`
//! selection uses (`libc/src/allocator_native_mimalloc.rs`): `malloc` is
//! `native_allocate_aligned(size, 16, false)`, `calloc` zeroes through the
//! same primitive, `realloc` is `native_reallocate`, and `free` fail-stops on
//! any native refusal exactly like the libc adapter. Each allocating thread
//! therefore keeps its persistent source TLD/Theap across operations; the
//! fixture has no route, ledger, or scheduler of its own.
//!
//! This is a disposable benchmark staticlib built by
//! `compat/allocator/perf_engine_x86_64.py`. It adds no production allocator
//! API, C ABI, or backend selection.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use core::ffi::{c_char, c_int, c_ulong, c_void};
use core::ptr::{NonNull, null_mut};

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, NativeProcessStartupFacts, RuntimeStderrOutput,
    ThreadAttachResult,
    ThreadFinishResult, attach_current_thread, current_native_allocator_thread_descriptor,
    finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, native_reallocate, native_usable_size,
    prepare_native_later_thread_arena, publish_native_process_startup_facts,
    register_current_native_allocator_worker_descriptor,
};

/// The public C `malloc` alignment selected by crabc-libc's native adapter.
const C_MALLOC_ALIGNMENT: usize = 16;
/// Linux `AT_PAGESZ`.
const AT_PAGESZ: c_ulong = 6;

unsafe extern "C" {
    fn abort() -> !;
    fn getauxval(tag: c_ulong) -> c_ulong;
    fn fputs(message: *const c_char, stream: *mut c_void) -> c_int;
    static mut stderr: *mut c_void;
    static mut environ: *mut *mut c_char;
}

/// The fixture process's musl `environ`, the source `_mi_prim_getenv` input.
unsafe fn musl_environment() -> *const *const c_char {
    // SAFETY: reads musl's process-global environment word; the fixture
    // never mutates its environment after startup.
    unsafe { core::ptr::read(core::ptr::addr_of!(environ)).cast_const().cast() }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: musl's abort never returns and is callable from any thread.
    unsafe { abort() }
}

/// Pinned `_mi_prim_out_stderr` delivery through the fixture's musl stderr.
unsafe extern "C" fn musl_fputs_stderr(message: *const c_char) {
    // SAFETY: the engine passes one non-null NUL-terminated fragment, and the
    // fixture keeps musl's permanent `stderr` FILE live for the process.
    // Pinned `_mi_prim_out_stderr` ignores the integer result.
    unsafe {
        let _ = fputs(message, stderr);
    }
}

#[inline(always)]
fn allocation(result: NativePageAllocationResult) -> *mut c_void {
    match result {
        NativePageAllocationResult::Allocated(block) => block.as_ptr().cast(),
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn crabc_allocator_engine_process_init() -> c_int {
    // SAFETY: getauxval only reads the process auxiliary vector.
    let page_size = unsafe { getauxval(AT_PAGESZ) } as usize;
    if page_size == 0 {
        return -1;
    }
    // SAFETY: `musl_fputs_stderr` has the source callback shape, never
    // unwinds, and musl's stderr FILE outlives the process allocator.
    let output = unsafe { RuntimeStderrOutput::new(musl_fputs_stderr) };
    // SAFETY: `musl_environment` returns musl's live NUL-terminated
    // `environ`, never allocates through this engine, and never unwinds.
    let Some(facts) = (unsafe { NativeProcessStartupFacts::new(page_size, musl_environment, output) }) else {
        return -1;
    };
    if publish_native_process_startup_facts(facts) && initialize_process() && prepare_native_later_thread_arena() {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn crabc_allocator_engine_thread_init() -> c_int {
    let descriptor = current_native_allocator_thread_descriptor();
    // SAFETY: `descriptor` is this exact thread's own TLS record from this
    // allocator image. The fixture never forks, never closes the native
    // epoch, and never runs a registry visitor, so no terminal or fork writer
    // can scan the record; musl keeps its TLS mapping live until this thread
    // has returned from `thread_done` and exited.
    if !unsafe { register_current_native_allocator_worker_descriptor(descriptor) } {
        return -1;
    }
    if attach_current_thread() == ThreadAttachResult::Attached { 0 } else { -1 }
}

#[unsafe(no_mangle)]
pub extern "C" fn crabc_allocator_engine_thread_done() -> c_int {
    if finish_current_thread_native_after_user_destructors() == ThreadFinishResult::Finished {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn crabc_allocator_engine_malloc(size: usize) -> *mut c_void {
    allocation(native_allocate_aligned(size, C_MALLOC_ALIGNMENT, false))
}

/// # Safety
///
/// `block` is null or a live result of this backend that the caller consumes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crabc_allocator_engine_free(block: *mut c_void) {
    let Some(block) = NonNull::new(block.cast::<u8>()) else {
        return;
    };
    // SAFETY: forwarded from this function's live-allocation contract.
    if unsafe { native_free(block) } != NativePageFreeResult::Freed {
        // Match crabc-libc's native adapter: a native refusal cannot be
        // relabeled or sent to another allocator.
        // SAFETY: musl's abort never returns.
        unsafe { abort() }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn crabc_allocator_engine_calloc(count: usize, size: usize) -> *mut c_void {
    let Some(total) = count.checked_mul(size) else {
        return null_mut();
    };
    allocation(native_allocate_aligned(total, C_MALLOC_ALIGNMENT, true))
}

/// # Safety
///
/// `block` is null or a live result of this backend that the caller does not
/// access after a non-null result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crabc_allocator_engine_realloc(block: *mut c_void, size: usize) -> *mut c_void {
    // SAFETY: forwarded from this function's live-allocation contract.
    allocation(unsafe { native_reallocate(NonNull::new(block.cast::<u8>()), size) })
}

#[unsafe(no_mangle)]
pub extern "C" fn crabc_allocator_engine_aligned(alignment: usize, size: usize) -> *mut c_void {
    allocation(native_allocate_aligned(size, alignment, false))
}

/// # Safety
///
/// `block` is null or a live result of this backend.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crabc_allocator_engine_usable_size(block: *const c_void) -> usize {
    let Some(block) = NonNull::new(block.cast_mut().cast::<u8>()) else {
        return 0;
    };
    // SAFETY: forwarded from this function's live-allocation contract.
    match unsafe { native_usable_size(block) } {
        Some(size) => size,
        // SAFETY: musl's abort never returns.
        None => unsafe { abort() },
    }
}
