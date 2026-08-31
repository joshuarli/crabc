// C allocation entry points backed by mimalloc.
//
// Keep this boundary separate from the allocator implementation: callers see
// the musl malloc/free/realloc/alignment contracts here, while ownership and
// mapping management remain entirely inside mimalloc.  In particular, the
// `mi_*` symbols are deliberately not exported as libc symbols and the
// `override` feature is not enabled.

const MIMALLOC_MALLOC_ALIGNMENT: usize = 16;

#[inline]
fn mimalloc_is_power_of_two(value: usize) -> bool {
    value != 0 && (value & (value - 1)) == 0
}

#[inline]
unsafe fn mimalloc_failed<T>(ptr: *mut T) -> *mut T {
    if ptr.is_null() {
        // libmimalloc-sys intentionally does not own the process errno.  The
        // C ABI does, so publish the allocator failure at this boundary.
        cabi_set_allocator_errno(ENOMEM);
    }
    ptr
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn malloc(size: SizeT) -> *mut c_void {
    // The generic mimalloc entry point need not align zero-sized allocations
    // to the C ABI's 16-byte boundary.  Preserve that boundary for every
    // successful `malloc` result, including a distinct zero-sized object.
    mimalloc_failed(libmimalloc_sys::mi_malloc_aligned(size, MIMALLOC_MALLOC_ALIGNMENT))
}

#[no_mangle]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    if !ptr.is_null() {
        // POSIX permits cleanup code to call free without disturbing a prior
        // error.  mimalloc may internally issue VM calls while reclaiming a
        // page, so preserve the libc-owned errno around the implementation.
        let errno = cabi_allocator_errno();
        libmimalloc_sys::mi_free(ptr);
        cabi_set_allocator_errno(errno);
    }
}

#[no_mangle]
pub unsafe extern "C" fn calloc(count: SizeT, size: SizeT) -> *mut c_void {
    let total = match count.checked_mul(size) {
        Some(value) => value,
        None => {
            cabi_set_allocator_errno(ENOMEM);
            return null_mut();
        }
    };
    mimalloc_failed(libmimalloc_sys::mi_zalloc(total))
}

#[no_mangle]
pub unsafe extern "C" fn realloc(ptr: *mut c_void, new_size: SizeT) -> *mut c_void {
    // mimalloc's realloc follows the C contract for NULL and zero-sized
    // requests: NULL is malloc-like, while realloc(p, 0) returns a distinct
    // freeable object and releases p only after that allocation succeeds.
    mimalloc_failed(libmimalloc_sys::mi_realloc(ptr, new_size))
}

#[no_mangle]
pub unsafe extern "C" fn aligned_alloc(alignment: SizeT, size: SizeT) -> *mut c_void {
    // musl accepts a non-multiple size for aligned_alloc, as does its current
    // mallocng implementation.  Validate only the required power-of-two
    // alignment before entering mimalloc.
    if !mimalloc_is_power_of_two(alignment) {
        cabi_set_allocator_errno(EINVAL);
        return null_mut();
    }
    mimalloc_failed(libmimalloc_sys::mi_malloc_aligned(size, alignment))
}

#[no_mangle]
pub unsafe extern "C" fn posix_memalign(
    result: *mut *mut c_void,
    alignment: SizeT,
    size: SizeT,
) -> c_int {
    // POSIX requires the output pointer to remain untouched on every error.
    if result.is_null() {
        return EINVAL;
    }
    if !mimalloc_is_power_of_two(alignment)
        || alignment % core::mem::size_of::<*mut c_void>() != 0
    {
        // Musl's posix_memalign delegates this form to aligned_alloc after
        // rejecting only sub-pointer alignments, so its invalid-alignment
        // result also leaves EINVAL in the calling thread's errno slot.
        cabi_set_allocator_errno(EINVAL);
        return EINVAL;
    }
    let allocation = mimalloc_failed(libmimalloc_sys::mi_malloc_aligned(size, alignment));
    if allocation.is_null() {
        return ENOMEM;
    }
    result.write(allocation);
    0
}
