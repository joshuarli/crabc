// C allocation entry points backed by the nondefault Rust native-mimalloc
// shadow lane.
//
// This file is selected only by crabc-libc's
// `native-mimalloc-shadow` compile-time feature. It deliberately has no
// runtime selector and no C-backend fallback: a successful allocation must
// remain owned by the same native runtime that later receives its free or
// reallocation. Persistent PageMap/page state, rather than a parked-owner
// handoff, names an exact live native allocation. An attached worker may
// source-push that exact client through the page's atomic remote head; the
// client pins its registered page, so the operation transfers no page engine,
// scheduler claim, or stored client capability. `native_usable_size` derives
// the exact live extent from immutable PageMap facts, and generic pointer-first
// free/reallocation continue to own post-exit dispatch. Other cross-thread
// routing remains outside this early M5 shadow slice rather than silently
// handing a native pointer to libmimalloc.

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

#[no_mangle]
pub unsafe extern "C" fn memalign(alignment: SizeT, size: SizeT) -> *mut c_void {
    // Preserve the historical zero-alignment adapter within the selected
    // native backend, matching the ordinary C-backed allocation owner.
    if alignment == 0 {
        unsafe { malloc(size) }
    } else {
        unsafe { aligned_alloc(alignment, size) }
    }
}

#[no_mangle]
pub unsafe extern "C" fn valloc(size: SizeT) -> *mut c_void {
    // The selected AArch64 runtime retains its 4 KiB base-page alignment.
    unsafe { memalign(4096, size) }
}
