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

// Run one backend allocation under musl's errno contract: failure publishes
// ENOMEM, and success leaves the caller's errno exactly as it was. mallocng
// never changes errno on success, and POSIX callers rely on that (for
// example `getpwnam` not-found, `readdir` end-of-directory, `strtol`, and
// a successful `getaddrinfo` all leave errno untouched). mimalloc's lazy
// process and thread initialization and its page reclaim issue libc calls
// that may fail internally, such as the NUMA node `access` probe that ends
// in ENOENT, so the previous value is restored rather than trusted to
// survive.
#[inline]
unsafe fn mimalloc_allocation<T>(allocate: impl FnOnce() -> *mut T) -> *mut T {
    let errno = cabi_allocator_errno();
    let ptr = allocate();
    // libmimalloc-sys intentionally does not own the process errno. The C ABI
    // does, so publish the allocator outcome at this boundary.
    cabi_set_allocator_errno(if ptr.is_null() { ENOMEM } else { errno });
    ptr
}

// Application replacement follows musl 1.2.6. A static program may define
// `malloc`, `free` and `realloc`, and optionally `calloc`, `reallocarray` and
// the aligned entries. Musl's libc.a keeps each entry in its own member with
// its own binding (weak `malloc`, strong others), so those definitions link
// without a duplicate symbol. On Linux/x86-64 each entry below is its own
// member of the installed static archive (`static_archive_member!`), and the
// strong entries are never inlined into libc callers, which therefore reach
// an application's replacement through the public symbol as musl's do.

// AArch64 includes this file at crate level, where the entries stay inline.
#[cfg(not(target_arch = "x86_64"))]
macro_rules! static_archive_member {
    ($module:ident { $($item:item)* }) => { $($item)* };
}

// Musl's `src/malloc/lite_malloc.c` object.
static_archive_member! { lite_malloc_source {
    // A hidden alias beside the weak `malloc`. The assembler resolves it to
    // this object's definition, so it names libc's body even when the
    // application's `malloc` preempts the public symbol; `calloc` and
    // `aligned_alloc` compare the two.
    #[cfg(target_arch = "x86_64")]
    core::arch::global_asm!(
        ".globl __crabc_x86_c_allocator_malloc_body",
        ".hidden __crabc_x86_c_allocator_malloc_body",
        ".type __crabc_x86_c_allocator_malloc_body,@function",
        ".set __crabc_x86_c_allocator_malloc_body, malloc",
    );

    // The static archive extracts a member only when a loaded object names
    // one of its symbols. The C backend's lifecycle module is otherwise
    // reached only through its `.init_array`/`.fini_array` entries, so
    // without this relocation an application that allocates would leave
    // mimalloc's process attach and detach out of the image. Every allocating
    // entry names `malloc` or this member's body alias, so naming the
    // initializer here extracts the lifecycle member with them; the pointer
    // is never called.
    #[cfg(crabc_owned_mimalloc_lifecycle)]
    #[used]
    static LIFECYCLE_MEMBER_ANCHOR: unsafe extern "C" fn() =
        crate::x86_64_static_c_abi::allocator_mimalloc_lifecycle::initialize;

    #[no_mangle]
    #[linkage = "weak"]
    pub unsafe extern "C" fn malloc(size: SizeT) -> *mut c_void {
        // The generic mimalloc entry point need not align zero-sized allocations
        // to the C ABI's 16-byte boundary.  Preserve that boundary for every
        // successful `malloc` result, including a distinct zero-sized object.
        mimalloc_allocation(|| unsafe { libmimalloc_sys::mi_malloc_aligned(size, MIMALLOC_MALLOC_ALIGNMENT) })
    }
}}

// Musl's `src/malloc/free.c` object.
static_archive_member! { free_source {
    #[no_mangle]
    #[cfg_attr(target_arch = "x86_64", inline(never))]
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
}}

// Musl's `src/malloc/calloc.c` object.
static_archive_member! { calloc_source {
    #[no_mangle]
    #[cfg_attr(target_arch = "x86_64", inline(never))]
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

        // With `malloc` replaced, musl's `calloc` allocates through the public
        // `malloc` and zeroes, so the result belongs to the replacement.
        #[cfg(target_arch = "x86_64")]
        if cabi_application_malloc_replaced() {
            let allocation = cabi_public_malloc(total);
            if !allocation.is_null() {
                core::ptr::write_bytes(allocation.cast::<u8>(), 0, total);
            }
            return allocation;
        }

        mimalloc_allocation(|| unsafe { libmimalloc_sys::mi_zalloc(total) })
    }
}}

// Musl's `src/malloc/realloc.c` object.
static_archive_member! { realloc_source {
    #[no_mangle]
    #[cfg_attr(target_arch = "x86_64", inline(never))]
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
        mimalloc_allocation(|| unsafe {
            libmimalloc_sys::mi_realloc_aligned(ptr, new_size, MIMALLOC_MALLOC_ALIGNMENT)
        })
    }
}}

// Musl's `src/malloc/reallocarray.c` object.
static_archive_member! { reallocarray_source {
    #[no_mangle]
    #[cfg_attr(target_arch = "x86_64", inline(never))]
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
}}

// Musl's `src/malloc/mallocng/aligned_alloc.c` object.
static_archive_member! { aligned_alloc_source {
    #[no_mangle]
    #[cfg_attr(target_arch = "x86_64", inline(never))]
    pub unsafe extern "C" fn aligned_alloc(alignment: SizeT, size: SizeT) -> *mut c_void {
        // Once `malloc` is replaced, mallocng's `DISABLE_ALIGNED_ALLOC` refuses
        // after its power-of-two test, so no backend pointer reaches the
        // application's `free`. Musl applies it in dynamic processes only; the
        // x86 static archive refuses too, as the native-shadow libc does
        // (compat/allocator/known-differences.md).
        #[cfg(target_arch = "x86_64")]
        if cabi_application_malloc_replaced() {
            let error = if alignment != 0 && !mimalloc_is_power_of_two(alignment) { EINVAL } else { ENOMEM };
            cabi_set_allocator_errno(error);
            return null_mut();
        }
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
        mimalloc_allocation(|| unsafe { libmimalloc_sys::mi_malloc_aligned(size, alignment) })
    }
}}

// Musl's `src/malloc/posix_memalign.c` object.
static_archive_member! { posix_memalign_source {
    #[no_mangle]
    #[cfg_attr(target_arch = "x86_64", inline(never))]
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
}}

// Musl's `src/malloc/memalign.c` object.
static_archive_member! { memalign_source {
    #[no_mangle]
    #[cfg_attr(target_arch = "x86_64", inline(never))]
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
}}

// Musl's `src/legacy/valloc.c` object.
static_archive_member! { valloc_source {
    #[no_mangle]
    #[cfg_attr(target_arch = "x86_64", inline(never))]
    pub unsafe extern "C" fn valloc(size: SizeT) -> *mut c_void {
        // The active Linux/AArch64 runtime and staged Linux/x86-64 runtime both
        // select a 4 KiB base page. This legacy adapter changes only allocation
        // alignment; it does not expose page allocation policy.
        memalign(4096, size)
    }
}}
