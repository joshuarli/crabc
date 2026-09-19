//! x86 C allocation entries backed by the nondefault Rust native-mimalloc shadow.
//!
//! This is the x86 counterpart of the existing AArch64 shadow boundary, but
//! it keeps the x86 libc-owned errno and private `__libc_malloc` seams local.
//! The selected feature owns every pointer it returns through the Rust engine;
//! it never delegates a refusal, free, or reallocation to the bundled C
//! mimalloc backend.  The ordinary C backend remains the default build.
//!
//! Translation provenance for the C-facing argument/error rules is musl 1.2.6
//! release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's
//! MIT license: `src/malloc/{calloc,realloc,reallocarray,free,
//! posix_memalign,memalign}.c`, `src/malloc/mallocng/aligned_alloc.c`, and
//! `src/legacy/valloc.c`.  Native page ownership remains in the fixed
//! mimalloc v3.5.0 port; this module does not claim process shutdown,
//! unselected cross-thread routing, or allocator promotion.

use core::ffi::{c_int, c_void};
use core::ptr::null_mut;

use super::errno;
use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, native_allocate_aligned, native_free,
    native_reallocate,
};

const NATIVE_MIMALLOC_MALLOC_ALIGNMENT: usize = 16;
const MUSL_MALLOCNG_MAX_ALIGNMENT: usize = (1usize << 31) * NATIVE_MIMALLOC_MALLOC_ALIGNMENT;
type SizeT = usize;
const ENOMEM: c_int = 12;
const EINVAL: c_int = 22;

#[inline]
unsafe fn cabi_allocator_errno() -> c_int {
    unsafe { errno::get_errno() }
}

#[inline]
unsafe fn cabi_set_allocator_errno(value: c_int) {
    unsafe { errno::set_errno(value) };
}

#[inline]
fn native_mimalloc_is_power_of_two(value: usize) -> bool {
    value != 0 && (value & (value - 1)) == 0
}

#[inline]
unsafe fn native_mimalloc_allocation_result(result: NativePageAllocationResult) -> *mut c_void {
    match result {
        NativePageAllocationResult::Allocated(block) => block.as_ptr().cast(),
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            // The Rust engine never owns errno. Native refusal is a C
            // allocation failure, never a reason to reinterpret a native
            // pointer through the ordinary bundled backend.
            unsafe { cabi_set_allocator_errno(ENOMEM) };
            null_mut()
        }
    }
}

#[inline]
unsafe fn native_mimalloc_allocate(size: usize, alignment: usize, zero: bool) -> *mut c_void {
    unsafe { native_mimalloc_allocation_result(native_allocate_aligned(size, alignment, zero)) }
}

/// Release one private selected-native allocation without a public C symbol
/// lookup. Both public cleanup and libc's `__libc_free`-shaped clients retain
/// the caller's errno, but only the former crosses the weak `free` ABI.
unsafe fn native_mimalloc_deallocate(pointer: *mut c_void) {
    if pointer.is_null() {
        return;
    }
    let saved_errno = unsafe { cabi_allocator_errno() };
    let block = unsafe { core::ptr::NonNull::new_unchecked(pointer.cast::<u8>()) };
    match unsafe { native_free(block) } {
        NativePageFreeResult::Freed => unsafe { cabi_set_allocator_errno(saved_errno) },
        NativePageFreeResult::InvalidPointer
        | NativePageFreeResult::Unavailable
        | NativePageFreeResult::Retained => {
            // Native-selected pointer ownership has become terminal. The C
            // backend is not an error recovery path because it cannot own
            // this exact pointer.
            super::immediate_termination::_Exit(134)
        }
    }
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn malloc(size: SizeT) -> *mut c_void {
    unsafe { native_mimalloc_allocate(size, NATIVE_MIMALLOC_MALLOC_ALIGNMENT, false) }
}

#[no_mangle]
pub unsafe extern "C" fn free(pointer: *mut c_void) {
    unsafe { native_mimalloc_deallocate(pointer) }
}

#[no_mangle]
pub unsafe extern "C" fn calloc(count: SizeT, size: SizeT) -> *mut c_void {
    let Some(total) = count.checked_mul(size) else {
        unsafe { cabi_set_allocator_errno(ENOMEM) };
        return null_mut();
    };
    if total == 0 {
        return unsafe { malloc(0) };
    }
    unsafe { native_mimalloc_allocate(total, NATIVE_MIMALLOC_MALLOC_ALIGNMENT, true) }
}

#[no_mangle]
pub unsafe extern "C" fn realloc(pointer: *mut c_void, new_size: SizeT) -> *mut c_void {
    if pointer.is_null() {
        return unsafe { malloc(new_size) };
    }
    let block = unsafe { core::ptr::NonNull::new_unchecked(pointer.cast::<u8>()) };
    unsafe { native_mimalloc_allocation_result(native_reallocate(Some(block), new_size)) }
}

#[no_mangle]
pub unsafe extern "C" fn reallocarray(
    pointer: *mut c_void,
    count: SizeT,
    size: SizeT,
) -> *mut c_void {
    let Some(total) = count.checked_mul(size) else {
        unsafe { cabi_set_allocator_errno(ENOMEM) };
        return null_mut();
    };
    unsafe { realloc(pointer, total) }
}

#[no_mangle]
pub unsafe extern "C" fn aligned_alloc(alignment: SizeT, size: SizeT) -> *mut c_void {
    if alignment == 0 {
        return unsafe { malloc(size) };
    }
    if !native_mimalloc_is_power_of_two(alignment) {
        unsafe { cabi_set_allocator_errno(EINVAL) };
        return null_mut();
    }
    if size > usize::MAX - alignment || alignment >= MUSL_MALLOCNG_MAX_ALIGNMENT {
        unsafe { cabi_set_allocator_errno(ENOMEM) };
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
    if result.is_null() || alignment < core::mem::size_of::<*mut c_void>() {
        return EINVAL;
    }
    if !native_mimalloc_is_power_of_two(alignment) {
        unsafe { cabi_set_allocator_errno(EINVAL) };
        return EINVAL;
    }
    let allocation = unsafe { aligned_alloc(alignment, size) };
    if allocation.is_null() {
        return unsafe { cabi_allocator_errno() };
    }
    unsafe { result.write(allocation) };
    0
}

#[no_mangle]
pub unsafe extern "C" fn memalign(alignment: SizeT, size: SizeT) -> *mut c_void {
    if alignment == 0 {
        unsafe { malloc(size) }
    } else {
        unsafe { aligned_alloc(alignment, size) }
    }
}

#[no_mangle]
pub unsafe extern "C" fn valloc(size: SizeT) -> *mut c_void {
    unsafe { memalign(4096, size) }
}

/// Internal owned allocation through the same selected native owner.
///
/// # Safety
/// The caller has initialized x86 TLS and keeps the returned native pointer
/// within the selected libc owner until [`deallocate_internal`] consumes it.
pub(super) unsafe fn allocate_internal(size: usize) -> *mut c_void {
    unsafe { native_mimalloc_allocate(size, NATIVE_MIMALLOC_MALLOC_ALIGNMENT, false) }
}

/// Internal zeroed allocation through the selected native owner.
///
/// # Safety
/// The caller has the same ownership obligations as [`allocate_internal`].
pub(super) unsafe fn allocate_zeroed_internal(size: usize) -> *mut c_void {
    unsafe { native_mimalloc_allocate(size, NATIVE_MIMALLOC_MALLOC_ALIGNMENT, true) }
}

/// Release selected private native storage without crossing public `free`.
///
/// # Safety
/// `pointer` is null or an exact live result from this module's internal
/// allocation functions, and the caller transfers its final ownership here.
pub(super) unsafe fn deallocate_internal(pointer: *mut c_void) {
    unsafe { native_mimalloc_deallocate(pointer) }
}

/// Link-time witness for the selected native x86 allocator boundary.
#[no_mangle]
pub extern "C" fn __crabc_x86_native_mimalloc_shadow_v1() -> usize {
    1
}
