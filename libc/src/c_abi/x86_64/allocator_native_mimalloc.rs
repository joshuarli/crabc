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

// Application allocator replacement follows musl 1.2.6. A program (or, in a
// dynamic process, any preempting image) may replace `malloc`, `free` and
// `realloc`, and optionally `calloc`, the aligned entries and
// `malloc_usable_size`. Libc's derived entries then reach the replacement
// through the public symbols: `calloc` allocates with public `malloc` and
// zeroes (`calloc.c`), `reallocarray` calls public `realloc`
// (`reallocarray.c`), `posix_memalign` and `memalign` call public
// `aligned_alloc`, `valloc` calls public `memalign`, and libc's own
// `aligned_alloc` refuses with ENOMEM once `malloc` is replaced (mallocng
// `DISABLE_ALIGNED_ALLOC`), because a native pointer must never reach the
// application's `free`. Libc-private storage keeps using the `*_internal`
// seam below and never crosses either way.
//
// Each public name is an assembler alias of a private Rust body rather than
// a Rust definition. Rust binds a crate's own strong definitions locally, so
// libc code calling `free` or `realloc` would otherwise skip a replacement
// even though `malloc` (weak, hence interposable) reached it; with no Rust
// definition of the name, every libc reference is an ordinary preemptible
// external call, as in musl's libc.so with its dynamic list. Musl also keeps
// each entry in its own archive member, so a static program's definitions
// preempt libc.a without a duplicate-symbol error; these entries share one
// object, so the static archive binds each alias weak. libc.so keeps musl's
// dynamic bindings: weak `malloc`, strong others. Rust places module-level
// assembly in this module's object, so each alias resolves to its body.
macro_rules! public_allocator_alias {
    ($name:literal, $body:path, $binding:literal) => {
        core::arch::global_asm!(
            concat!(".", $binding, " ", $name),
            concat!(".type ", $name, ",@function"),
            concat!(".set ", $name, ", {body}"),
            body = sym $body,
        );
    };
}

#[cfg(crabc_x86_dynamic_runtime)]
macro_rules! derived_allocator_alias {
    ($name:literal, $body:path) => { public_allocator_alias!($name, $body, "globl"); };
}
#[cfg(not(crabc_x86_dynamic_runtime))]
macro_rules! derived_allocator_alias {
    ($name:literal, $body:path) => { public_allocator_alias!($name, $body, "weak"); };
}

public_allocator_alias!("malloc", libc_malloc, "weak");
derived_allocator_alias!("free", libc_free);
derived_allocator_alias!("calloc", libc_calloc);
derived_allocator_alias!("realloc", libc_realloc);
derived_allocator_alias!("reallocarray", libc_reallocarray);
derived_allocator_alias!("aligned_alloc", libc_aligned_alloc);
derived_allocator_alias!("posix_memalign", libc_posix_memalign);
derived_allocator_alias!("memalign", libc_memalign);
derived_allocator_alias!("valloc", libc_valloc);

/// The address the public `name` symbol resolves to in the final process,
/// read from its GOT slot, which honors ELF preemption in the static link and
/// through the dynamic loader alike.
macro_rules! public_entry {
    ($name:literal) => {{
        let address: usize;
        // SAFETY: a RIP-relative load of this image's GOT slot for `$name`;
        // the slot is immutable once relocation has completed.
        unsafe {
            core::arch::asm!(
                concat!("mov {0}, qword ptr [rip + ", $name, "@GOTPCREL]"),
                out(reg) address,
                options(nomem, nostack, preserves_flags, pure),
            )
        };
        address
    }};
}

/// Whether the resolved public `malloc` is not libc's own body.
#[inline]
fn application_malloc_replaced() -> bool {
    public_entry!("malloc") != libc_malloc as *const () as usize
}

// Calls through the resolved public entries use their GOT addresses as
// opaque pointers. A declared `malloc` would be a recognized library call:
// LLVM then folds `malloc` plus zeroing back into a call to `calloc`, which is
// this function itself.
#[inline]
unsafe fn public_malloc(size: SizeT) -> *mut c_void {
    let address = public_entry!("malloc");
    // SAFETY: the resolved `malloc` has the C `malloc` signature.
    let entry: unsafe extern "C" fn(SizeT) -> *mut c_void = unsafe { core::mem::transmute(address) };
    unsafe { entry(size) }
}

#[inline]
unsafe fn public_realloc(pointer: *mut c_void, size: SizeT) -> *mut c_void {
    let address = public_entry!("realloc");
    // SAFETY: the resolved `realloc` has the C `realloc` signature.
    let entry: unsafe extern "C" fn(*mut c_void, SizeT) -> *mut c_void =
        unsafe { core::mem::transmute(address) };
    unsafe { entry(pointer, size) }
}

#[inline]
unsafe fn public_aligned_alloc(alignment: SizeT, size: SizeT) -> *mut c_void {
    let address = public_entry!("aligned_alloc");
    // SAFETY: the resolved `aligned_alloc` has the C signature.
    let entry: unsafe extern "C" fn(SizeT, SizeT) -> *mut c_void =
        unsafe { core::mem::transmute(address) };
    unsafe { entry(alignment, size) }
}

#[inline]
unsafe fn public_memalign(alignment: SizeT, size: SizeT) -> *mut c_void {
    let address = public_entry!("memalign");
    // SAFETY: the resolved `memalign` has the C signature.
    let entry: unsafe extern "C" fn(SizeT, SizeT) -> *mut c_void =
        unsafe { core::mem::transmute(address) };
    unsafe { entry(alignment, size) }
}

unsafe extern "C" fn libc_malloc(size: SizeT) -> *mut c_void {
    unsafe { native_mimalloc_allocate(size, NATIVE_MIMALLOC_MALLOC_ALIGNMENT, false) }
}

unsafe extern "C" fn libc_free(pointer: *mut c_void) {
    unsafe { native_mimalloc_deallocate(pointer) }
}

unsafe extern "C" fn libc_calloc(count: SizeT, size: SizeT) -> *mut c_void {
    let Some(total) = count.checked_mul(size) else {
        unsafe { cabi_set_allocator_errno(ENOMEM) };
        return null_mut();
    };
    if application_malloc_replaced() {
        let allocation = unsafe { public_malloc(total) };
        if !allocation.is_null() {
            unsafe { core::ptr::write_bytes(allocation.cast::<u8>(), 0, total) };
        }
        return allocation;
    }
    unsafe { native_mimalloc_allocate(total, NATIVE_MIMALLOC_MALLOC_ALIGNMENT, total != 0) }
}

unsafe extern "C" fn libc_realloc(pointer: *mut c_void, new_size: SizeT) -> *mut c_void {
    // Musl's `realloc(NULL, n)` allocates internally, like this native path.
    if pointer.is_null() {
        return unsafe { native_mimalloc_allocate(new_size, NATIVE_MIMALLOC_MALLOC_ALIGNMENT, false) };
    }
    let block = unsafe { core::ptr::NonNull::new_unchecked(pointer.cast::<u8>()) };
    unsafe { native_mimalloc_allocation_result(native_reallocate(Some(block), new_size)) }
}

unsafe extern "C" fn libc_reallocarray(
    pointer: *mut c_void,
    count: SizeT,
    size: SizeT,
) -> *mut c_void {
    let Some(total) = count.checked_mul(size) else {
        unsafe { cabi_set_allocator_errno(ENOMEM) };
        return null_mut();
    };
    unsafe { public_realloc(pointer, total) }
}

unsafe extern "C" fn libc_aligned_alloc(alignment: SizeT, size: SizeT) -> *mut c_void {
    // Mallocng order: zero passes its power-of-two test, then the size and
    // alignment bounds, then the replaced-malloc refusal.
    if alignment != 0 && !native_mimalloc_is_power_of_two(alignment) {
        unsafe { cabi_set_allocator_errno(EINVAL) };
        return null_mut();
    }
    if size > usize::MAX - alignment || alignment >= MUSL_MALLOCNG_MAX_ALIGNMENT
        || application_malloc_replaced()
    {
        unsafe { cabi_set_allocator_errno(ENOMEM) };
        return null_mut();
    }
    let alignment = alignment.max(NATIVE_MIMALLOC_MALLOC_ALIGNMENT);
    unsafe { native_mimalloc_allocate(size, alignment, false) }
}

unsafe extern "C" fn libc_posix_memalign(
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
    let allocation = unsafe { public_aligned_alloc(alignment, size) };
    if allocation.is_null() {
        return unsafe { cabi_allocator_errno() };
    }
    unsafe { result.write(allocation) };
    0
}

unsafe extern "C" fn libc_memalign(alignment: SizeT, size: SizeT) -> *mut c_void {
    unsafe { public_aligned_alloc(alignment, size) }
}

unsafe extern "C" fn libc_valloc(size: SizeT) -> *mut c_void {
    unsafe { public_memalign(4096, size) }
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
