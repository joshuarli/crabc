// C allocation entry points backed by mimalloc.
//
// Keep this boundary separate from the allocator implementation: callers see
// the musl malloc/free/realloc/alignment contracts here, while ownership and
// mapping management remain entirely inside mimalloc.  In particular, the
// `mi_*` symbols are deliberately not exported as libc symbols and the
// `override` feature is not enabled.
//
// Translation provenance is musl 1.2.6 release commit
// 9fa28ece75d8a2191de7c5bb53bed224c5947417, under musl's MIT license.
// `calloc`, `realloc`, `free`, `reallocarray`, `posix_memalign`, `memalign`,
// and `valloc` map respectively to `src/malloc/{calloc,realloc,free,
// reallocarray,posix_memalign,memalign}.c` and `src/legacy/valloc.c`.
// `realloc` and `free` then dispatch to `src/malloc/mallocng/{realloc,free}.c`.
// `aligned_alloc` maps to `src/malloc/mallocng/aligned_alloc.c`. The
// underlying allocation engine is deliberately the existing pinned
// libmimalloc-sys backend, not a port of musl mallocng; this layer owns only
// the C wrapper's observable argument, overflow, errno, alignment, and
// lifetime boundary. It does not establish allocator lifecycle, threading,
// fork, dynamic-runtime, or public x86 support.

// musl 1.2.6 mallocng's `UNIT` is fixed at 16 for the active LP64 targets.
// Keep this oracle constant separate from the backend implementation detail:
// it sets both the C natural-allocation alignment and aligned_alloc's
// maximum accepted alignment.
const MUSL_MALLOCNG_UNIT: usize = 16;
const MIMALLOC_MALLOC_ALIGNMENT: usize = MUSL_MALLOCNG_UNIT;
const MUSL_MALLOCNG_MAX_ALIGNMENT: usize = (1usize << 31) * MUSL_MALLOCNG_UNIT;

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

    // musl's calloc reaches its malloc path after the checked multiplication.
    // In particular, a zero product inherits malloc(0)'s successful, distinct,
    // naturally aligned, freeable object instead of exposing a backend-specific
    // null zero-allocation result through the C ABI.
    if total == 0 {
        return malloc(0);
    }

    mimalloc_failed(libmimalloc_sys::mi_zalloc(total))
}

#[no_mangle]
pub unsafe extern "C" fn realloc(ptr: *mut c_void, new_size: SizeT) -> *mut c_void {
    // Musl sends a null input through malloc, so retain this wrapper's
    // explicit 16-byte natural-alignment boundary for realloc(NULL, n).
    // For a live allocation, mallocng may retain the existing object for a
    // zero-sized request; callers may only rely on the non-null result being
    // freeable, not on pointer identity or a particular reuse topology.
    if ptr.is_null() {
        return malloc(new_size);
    }

    // The generic mimalloc reallocator may return a word-aligned shrink
    // result. C realloc must remain suitable for every fundamental C type,
    // including after shrink, so retain the wrapper's natural alignment.
    mimalloc_failed(libmimalloc_sys::mi_realloc_aligned(
        ptr,
        new_size,
        MIMALLOC_MALLOC_ALIGNMENT,
    ))
}

#[no_mangle]
pub unsafe extern "C" fn reallocarray(
    ptr: *mut c_void,
    count: SizeT,
    size: SizeT,
) -> *mut c_void {
    // Keep musl's checked multiplication outside realloc: on overflow the
    // input allocation stays live and observable, while errno becomes ENOMEM.
    let total = match count.checked_mul(size) {
        Some(value) => value,
        None => {
            cabi_set_allocator_errno(ENOMEM);
            return null_mut();
        }
    };
    realloc(ptr, total)
}

#[no_mangle]
pub unsafe extern "C" fn aligned_alloc(alignment: SizeT, size: SizeT) -> *mut c_void {
    // musl's `(align & -align) != align` test accepts zero, then normalizes
    // it to its natural allocator alignment. Keep that observable historical
    // behavior without forwarding an invalid zero alignment into mimalloc.
    if alignment == 0 {
        return unsafe { malloc(size) };
    }
    // musl accepts a non-multiple size for aligned_alloc, as does its current
    // mallocng implementation. Validate the remaining power-of-two alignment
    // before entering mimalloc.
    if !mimalloc_is_power_of_two(alignment) {
        cabi_set_allocator_errno(EINVAL);
        return null_mut();
    }
    // Keep mallocng's pre-backend rejection order: after accepting zero and
    // rejecting non-powers, reject a size that would overflow the adjusted
    // allocation and every alignment mallocng cannot encode in its metadata.
    if size > usize::MAX - alignment || alignment >= MUSL_MALLOCNG_MAX_ALIGNMENT {
        cabi_set_allocator_errno(ENOMEM);
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
    if alignment < core::mem::size_of::<*mut c_void>() {
        // Musl returns EINVAL before calling aligned_alloc here, so errno
        // remains the caller's prior value and the output stays untouched.
        return EINVAL;
    }
    if !mimalloc_is_power_of_two(alignment) {
        // For all remaining invalid alignments musl delegates to
        // aligned_alloc, which publishes EINVAL in the calling thread's
        // errno slot and leaves the output untouched.
        cabi_set_allocator_errno(EINVAL);
        return EINVAL;
    }
    // Musl delegates every remaining case to aligned_alloc, including its
    // checked adjusted-size and maximum-alignment failures. Keep those
    // constraints in one wrapper rather than exposing a backend-specific
    // allocation path through posix_memalign.
    let allocation = aligned_alloc(alignment, size);
    if allocation.is_null() {
        return cabi_allocator_errno();
    }
    result.write(allocation);
    0
}

#[no_mangle]
pub unsafe extern "C" fn memalign(alignment: SizeT, size: SizeT) -> *mut c_void {
    // Musl keeps this historical entry as a thin adapter. Its zero-alignment
    // case retains the allocator's ordinary natural-alignment behavior rather
    // than forwarding an invalid alignment to aligned_alloc.
    if alignment == 0 {
        malloc(size)
    } else {
        aligned_alloc(alignment, size)
    }
}

#[no_mangle]
pub unsafe extern "C" fn valloc(size: SizeT) -> *mut c_void {
    // The active Linux/AArch64 runtime and staged Linux/x86-64 runtime both
    // select a 4 KiB base page. This legacy adapter changes only allocation
    // alignment; it does not expose page allocation policy.
    memalign(4096, size)
}
