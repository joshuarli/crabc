// C allocation entry points backed by the nondefault Rust native-mimalloc
// shadow lane.
//
// This file is selected only by crabc-libc's
// `native-mimalloc-shadow` compile-time feature. It deliberately has no
// runtime selector and no C-backend fallback: a successful allocation must
// remain owned by the same native runtime that later receives its free or
// reallocation. Its bounded worker scheduling branch admits only local
// pointers recorded by the current parked owner session; that session starts
// with inline private ledger storage and may grow metadata-backed storage
// before another C allocation escapes. An attached worker may also source-push
// one exact, still-live ticket-zero client through its page's atomic remote
// head: that client itself pins the registered page, so this transfers no
// page engine, scheduler claim, or stored client capability. A worker with its
// own fully parked local session may use that same exact live-owner path; it
// briefly resumes and re-parks only its own session for that source
// publication. One detached multi-page regular route may later accept exact
// frees while keeping its ledger and admission private. `native_usable_size`
// never claims either that route or a live-owner registry entry: it returns
// the exact usable extent captured from immutable PageMap facts for an exact
// live native client. While A remains parked and live, a fresh no-page B may
// source-publish an exact free, but receives no registry- or ledger-derived
// query capability. Other cross-thread routing remains outside this early M5
// shadow slice rather than silently handing a native pointer to libmimalloc.

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, native_allocate_aligned, native_free,
    native_reallocate,
};

const NATIVE_MIMALLOC_MALLOC_ALIGNMENT: usize = 16;

#[inline]
fn native_mimalloc_is_power_of_two(value: usize) -> bool {
    value != 0 && (value & (value - 1)) == 0
}

#[inline]
unsafe fn native_mimalloc_allocation_result(
    result: NativePageAllocationResult,
) -> *mut c_void {
    match result {
        NativePageAllocationResult::Allocated(block) => block.as_ptr().cast(),
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            // The Rust runtime does not own libc errno. The C ABI reports
            // every native-shadow refusal as an ordinary allocation failure;
            // it never sends a native allocation to the C allocator.
            // SAFETY: this libc C-ABI entry writes only the current thread's
            // errno TLS cell, exactly as the default allocator wrapper.
            unsafe { ERRNO = ENOMEM };
            null_mut()
        }
    }
}

#[inline]
unsafe fn native_mimalloc_allocate(size: usize, alignment: usize, zero: bool) -> *mut c_void {
    // SAFETY: this helper preserves the C caller's allocation-failure errno
    // boundary while routing the returned pointer only to the native owner.
    unsafe { native_mimalloc_allocation_result(native_allocate_aligned(size, alignment, zero)) }
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn malloc(size: SizeT) -> *mut c_void {
    // The native engine normalizes zero to one source word, returning a
    // distinct freeable allocation while preserving the public 16-byte C ABI
    // alignment.
    unsafe { native_mimalloc_allocate(size, NATIVE_MIMALLOC_MALLOC_ALIGNMENT, false) }
}

#[no_mangle]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    // POSIX permits cleanup paths to call free without disturbing a prior
    // errno. Native engine failures cannot be relabeled as foreign-pointer
    // frees or passed to the C backend, because that would corrupt ownership.
    let errno = ERRNO;
    // SAFETY: the null case returned above, so this exact C pointer is
    // non-null and may be represented without a panic path.
    let block = unsafe { core::ptr::NonNull::new_unchecked(ptr.cast::<u8>()) };
    match unsafe { native_free(block) } {
        NativePageFreeResult::Freed => ERRNO = errno,
        NativePageFreeResult::InvalidPointer
        | NativePageFreeResult::Unavailable
        | NativePageFreeResult::Retained => {
            // A valid native-shadow caller can reach this only after a
            // terminal runtime ownership failure. There is no sound recovery
            // through the C allocator, so fail-stop rather than losing or
            // misrouting a page-owned pointer.
            unsafe { abort() }
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn calloc(count: SizeT, size: SizeT) -> *mut c_void {
    let total = match count.checked_mul(size) {
        Some(value) => value,
        None => {
            ERRNO = ENOMEM;
            return null_mut();
        }
    };
    unsafe { native_mimalloc_allocate(total, NATIVE_MIMALLOC_MALLOC_ALIGNMENT, true) }
}

#[no_mangle]
pub unsafe extern "C" fn realloc(ptr: *mut c_void, new_size: SizeT) -> *mut c_void {
    if ptr.is_null() {
        return unsafe {
            native_mimalloc_allocate(new_size, NATIVE_MIMALLOC_MALLOC_ALIGNMENT, false)
        };
    }
    // SAFETY: the null case returned above, so this exact C pointer is
    // non-null and may be represented without a panic path.
    let block = unsafe { core::ptr::NonNull::new_unchecked(ptr.cast::<u8>()) };
    // The native source core preserves its own `realloc(p, 0)` behavior: it
    // creates the distinct zero-size replacement before it releases `p`.
    unsafe { native_mimalloc_allocation_result(native_reallocate(Some(block), new_size)) }
}

#[no_mangle]
pub unsafe extern "C" fn aligned_alloc(alignment: SizeT, size: SizeT) -> *mut c_void {
    // musl accepts a non-multiple size for aligned_alloc, as does its current
    // mallocng implementation. Validate only the required power-of-two
    // alignment before entering the selected native backend.
    if !native_mimalloc_is_power_of_two(alignment) {
        ERRNO = EINVAL;
        return null_mut();
    }
    unsafe { native_mimalloc_allocate(size, alignment, false) }
}

#[no_mangle]
pub unsafe extern "C" fn posix_memalign(
    result: *mut *mut c_void,
    alignment: SizeT,
    size: SizeT,
) -> c_int {
    // POSIX requires the output pointer to remain untouched on every error.
    if result.is_null()
        || !native_mimalloc_is_power_of_two(alignment)
        || alignment % core::mem::size_of::<*mut c_void>() != 0
    {
        return EINVAL;
    }
    let allocation = unsafe { native_mimalloc_allocate(size, alignment, false) };
    if allocation.is_null() {
        return ENOMEM;
    }
    result.write(allocation);
    0
}
