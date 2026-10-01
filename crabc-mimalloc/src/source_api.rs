// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0
// - `src/alloc.c:205-362` (`mi_malloc_small`, `mi_malloc`, `mi_zalloc_small`,
//   `mi_zalloc`, `mi_calloc`, the `u`-suffixed block-size entries, and
//   `mi_mallocn`), `src/alloc.c:365-510` (`mi_expand` and the realloc family),
//   `src/alloc.c:540-676` (`mi_strdup`, `mi_strndup`, `mi_path_max`, and
//   `mi_realpath`), and `src/alloc.c:693-858` (the plain-C `mi_new` family);
// - `src/alloc-aligned.c:18-28,158-241,247-316,352-424` (aligned allocation,
//   validation, and reallocation entries);
// - `src/alloc-posix.c:34-184` (the Posix, Unix, and Microsoft entries);
// - `src/free.c:251-363,546-549` (the free forms, `mi_cfree`, and
//   `mi_usable_size`);
// - `src/page-queue.c:114-124` (`mi_good_size`), `src/theap.c:158-161`
//   (`mi_collect`), `src/heap.c:250-283` (`mi_check_owned` through
//   `mi_any_heap_contains`), and `src/init.c:501-503` (`mi_is_redirected`).
//
// These are the default and explicit Theap public entries of the selected
// unguarded builds over the native runtime's allocation, free, reallocation,
// PageMap, and collection primitives. The engine owns no errno: each entry
// reports the errno effect the pinned source has on its path as data, and the
// C boundary applies it.

//! Pinned mimalloc default and explicit Theap allocation API over the native
//! runtime.
//!
//! Every function here is the source entry of the same `mi_` name with its
//! pointer arguments made explicit. The embedding C boundary supplies the
//! C-runtime inputs a few conveniences read (`getenv`, `realpath`,
//! `pathconf`, the C++ new handler, `abort`) through [`SourceCRuntime`], and
//! applies the returned [`SourceErrno`] to its own `errno`.
//!
//! The errno effects are those of a process with no `mi_register_error`
//! handler: pinned `mi_error_default` stores `EINVAL` for an `EINVAL` site
//! and `ENOMEM` for every other site only while errno is zero. Error and
//! warning messages are not rendered here.

use core::ffi::{c_char, c_int, c_long};
use core::ptr::{null_mut, NonNull};
use core::sync::atomic::{AtomicUsize, Ordering};

use crabc_core::Errno;

use crate::config::{MAX_ALLOC_SIZE, PAGE_MAX_OVERALLOC_ALIGN, PAGE_META_ALIGNMENT, PAGE_MAX_START_BLOCK_ALIGN2, PAGE_OSPAGE_BLOCK_ALIGN2};
use crate::runtime_lifecycle::{
    native_allocate, native_allocate_aligned_at, native_block_size, native_collect, native_free,
    native_os_page_size, native_pointer_is_mapped, native_reallocate_aligned_at,
    native_reallocate_source, native_usable_size, NativePageAllocationResult, NativePageFreeResult,
};
use crate::size_class;

/// Pinned `mi_os_mem_config.page_size` before `_mi_os_init` has run.
const SOURCE_DEFAULT_OS_PAGE_SIZE: usize = 4096;
/// `MI_TRY_NEW_MAX` of `src/alloc.c:690`.
pub(crate) const TRY_NEW_MAX: usize = 4;

/// The errno effect of one pinned source path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceErrno {
    /// The path leaves errno unchanged.
    Unchanged,
    /// `_mi_error_message` with no registered handler: `mi_error_default`
    /// stores this value only while errno is zero.
    DefaultIfZero(Errno),
    /// The path assigns errno unconditionally.
    Store(Errno),
}

impl SourceErrno {
    /// `_mi_error_message(err, ...)`'s errno effect for `err`: with a
    /// registered `mi_register_error` handler the handler, not
    /// `mi_error_default`, receives the code and errno is unchanged.
    pub(crate) fn error_message(error: Errno) -> Self {
        #[cfg(target_arch = "x86_64")]
        if crate::process_init::process_output_owner().is_some_and(|owner| owner.has_error_handler()) {
            return Self::Unchanged;
        }
        Self::DefaultIfZero(if error.raw() == Errno::INVAL.raw() { Errno::INVAL } else { Errno::NOMEM })
    }

    /// The combined effect of this effect followed by `later`.
    #[must_use]
    pub const fn then(self, later: Self) -> Self {
        match (self, later) {
            (_, Self::Store(value)) => Self::Store(value),
            (Self::Unchanged, later) => later,
            // A default store after any earlier effect finds errno either
            // unchanged-and-zero (handled above) or already nonzero.
            (earlier, _) => earlier,
        }
    }

    /// The errno value after this effect, given the value before it.
    #[must_use]
    pub const fn apply(self, errno: c_int) -> c_int {
        match self {
            Self::Unchanged => errno,
            Self::DefaultIfZero(value) if errno == 0 => value.raw(),
            Self::DefaultIfZero(_) => errno,
            Self::Store(value) => value.raw(),
        }
    }
}

/// One source result and the errno effect of the path that produced it.
#[must_use]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sourced<T> {
    pub value: T,
    pub errno: SourceErrno,
}

impl<T> Sourced<T> {
    const fn quiet(value: T) -> Self {
        Self { value, errno: SourceErrno::Unchanged }
    }

    const fn with(value: T, errno: SourceErrno) -> Self {
        Self { value, errno }
    }

    /// Prefixes an earlier path's errno effect.
    fn after(self, earlier: SourceErrno) -> Self {
        Self { value: self.value, errno: earlier.then(self.errno) }
    }
}

/// A nullable allocation result.
pub type Block = Option<NonNull<u8>>;

/// C-runtime inputs that the pinned conveniences read from the embedding
/// process.
///
/// # Safety
///
/// Implementations must provide the named C semantics for the process
/// lifetime. None of them may allocate through, free into, or unwind across
/// this allocator's current operation, except that the new handler is user
/// code which pinned `mi_try_new_handler` calls with no allocator state held.
pub unsafe trait SourceCRuntime {
    /// `getenv(name)`: null or a NUL-terminated value that remains valid
    /// until the caller copies it.
    ///
    /// # Safety
    ///
    /// `name` is a NUL-terminated string.
    unsafe fn getenv(&self, name: *const c_char) -> *const c_char;

    /// `realpath(fname, resolved)`, including its own errno assignments.
    ///
    /// # Safety
    ///
    /// `fname` is null or NUL-terminated; `resolved` is null or writable for
    /// the system `PATH_MAX` bytes.
    unsafe fn realpath(&self, fname: *const c_char, resolved: *mut c_char) -> *mut c_char;

    /// `pathconf("/", _PC_PATH_MAX)`.
    fn path_max(&self) -> c_long;

    /// `std::get_new_handler()` when a C++ runtime provides it, else `None`.
    fn new_handler(&self) -> Option<unsafe extern "C" fn()>;

    /// `abort()`.
    fn abort(&self) -> !;
}

#[inline]
fn native_block(result: NativePageAllocationResult) -> Block {
    match result {
        NativePageAllocationResult::Allocated(block) => Some(block),
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => None,
    }
}

/// `_mi_theap_malloc_zero`: its only failure sites are `mi_find_page`'s
/// oversized request (`EOVERFLOW`) and the generic fallback's out-of-memory
/// report (`ENOMEM`), both `ENOMEM` for errno.
fn malloc_zero(size: usize, zero: bool) -> Sourced<Block> {
    if let Some(selected) = crate::source_heap_api::default_theap_allocate(size, zero) {
        return selected;
    }
    malloc_zero_native(size, zero)
}

/// Allocate through the installed main or child owner after the default
/// Theap has been resolved by the caller.
pub(crate) fn malloc_zero_native(size: usize, zero: bool) -> Sourced<Block> {
    match native_block(native_allocate(size, zero)) {
        Some(block) => Sourced::quiet(Some(block)),
        None => Sourced::with(None, SourceErrno::error_message(Errno::NOMEM)),
    }
}

/// `mi_malloc`.
pub fn malloc(size: usize) -> Sourced<Block> {
    malloc_zero(size, false)
}

/// `mi_zalloc`.
pub fn zalloc(size: usize) -> Sourced<Block> {
    malloc_zero(size, true)
}

/// `mi_malloc_small`; the caller keeps `size <= MI_SMALL_SIZE_MAX`.
pub fn malloc_small(size: usize) -> Sourced<Block> {
    malloc_zero(size, false)
}

/// `mi_zalloc_small`; the caller keeps `size <= MI_SMALL_SIZE_MAX`.
pub fn zalloc_small(size: usize) -> Sourced<Block> {
    malloc_zero(size, true)
}

/// Keeps the disposition selected for this report. A callback may change
/// registration while it runs; that change selects later reports and does
/// not retroactively enable the default errno action for this one.
pub(crate) fn source_error_errno(report: crate::diagnostic_output::SourceErrorReport) -> SourceErrno {
    match crate::process_init::process_error_message(report) {
        crate::diagnostic_output::SourceErrorDisposition::Handled => SourceErrno::Unchanged,
        crate::diagnostic_output::SourceErrorDisposition::DefaultErrno(errno) => SourceErrno::DefaultIfZero(errno),
    }
}

/// The selected source diagnostic for a checked-count multiplication
/// overflow. Release builds are quiet; debug builds notify the error handler
/// before their ordinary default errno effect is applied by the C boundary.
pub(crate) fn count_size_overflow_errno(count: usize, size: usize) -> SourceErrno {
    #[cfg(feature = "mi-debug-1")]
    {
        let report = crate::diagnostic_output::SourceErrorReport::CountSizeOverflow { count, size };
        source_error_errno(report)
    }
    #[cfg(not(feature = "mi-debug-1"))]
    {
        let _ = (count, size);
        SourceErrno::Unchanged
    }
}

/// `mi_calloc`: an overflowing product fails before any allocation and, in
/// release, without a message.
pub fn calloc(count: usize, size: usize) -> Sourced<Block> {
    match size_class::count_size(count, size) {
        Some(total) => malloc_zero(total, true),
        None => Sourced::with(None, count_size_overflow_errno(count, size)),
    }
}

/// `mi_mallocn`.
pub fn mallocn(count: usize, size: usize) -> Sourced<Block> {
    match size_class::count_size(count, size) {
        Some(total) => malloc_zero(total, false),
        None => Sourced::with(None, count_size_overflow_errno(count, size)),
    }
}

/// `mi_theap_calloc`: overflow returns null before accessing the Theap.
///
/// # Safety
/// `theap` is a live Theap of the calling thread's TLD and Heap, retained
/// against destruction and thread exit for the complete allocation.
pub unsafe fn theap_calloc(theap: *mut core::ffi::c_void, count: usize, size: usize) -> Sourced<Block> {
    match size_class::count_size(count, size) {
        // SAFETY: forwarded current-thread Theap lifetime.
        Some(total) => unsafe { crate::source_heap_api::theap_malloc(theap, total, true) },
        None => Sourced::with(None, count_size_overflow_errno(count, size)),
    }
}

/// Direct offset-aligned Theap allocation after resolving no Heap selector.
/// The fixed main Theap uses its persistent owner; each non-main Theap
/// keeps the engine state stored in its own allocated image.
///
/// # Safety
/// `theap` is a live initialized Theap of the calling thread's TLD and
/// Heap, which both remain live throughout this call.
pub unsafe fn theap_malloc_aligned_at(
    theap: *mut core::ffi::c_void,
    size: usize,
    alignment: usize,
    offset: usize,
    zero: bool,
) -> Sourced<Block> {
    use crate::types::Theap;
    let Some(theap) = NonNull::new(theap.cast::<Theap>()) else { return Sourced::quiet(None) };
    let Some(current) = NonNull::new(crate::source_heap_api::theap_get_default().cast::<Theap>()) else {
        return Sourced::quiet(None);
    };
    // SAFETY: both Theaps stay retained by the calling thread.
    if unsafe { Theap::heap_at(theap) }.is_null()
        || unsafe { Theap::tld_at(theap) != Theap::tld_at(current) }
    {
        return Sourced::quiet(None);
    }
    if crate::source_heap_api::fixed_runtime_theap() == Some(theap) {
        return malloc_zero_aligned_at_native(size, alignment, offset, zero);
    }
    let report = if size_class::alignment_is_valid(alignment) && !size_class::request_size_is_valid(size) {
        Some(crate::diagnostic_output::SourceErrorReport::AlignedTooLarge { size, alignment })
    } else {
        crate::diagnostic_output::SourceErrorReport::aligned_precheck(size, alignment, offset)
    };
    if let Some(report) = report {
        return Sourced::with(None, source_error_errno(report));
    }
    let child = crate::subproc::lifecycle::current_thread_is_child_member();
    // SAFETY: validated alignment and retained current-thread Theap.
    let block = if child {
        unsafe { crate::subproc::lifecycle::native_child_theap_allocate_variant(
            theap, size, Some((alignment, offset)), zero,
        ) }.flatten()
    } else {
        unsafe { crate::subproc::main_heaps::native_theap_allocate_variant(
            theap, size, Some((alignment, offset)), zero,
        ) }
    };
    if block.is_some() { return Sourced::quiet(block); }
    if child && offset == 0 && alignment >= PAGE_META_ALIGNMENT {
        for _ in 0..2 {
            crate::process_init::process_warning_message(
                crate::diagnostic_output::SourceFormattedMessage::page_alignment_too_large(alignment),
            );
        }
        return Sourced::with(None, SourceErrno::Store(Errno::INVAL));
    }
    let os_page_size = native_os_page_size().expect("a retained initialized Theap has OS page-size facts");
    let request = crate::aligned::allocation_failure_request(size, alignment, offset, os_page_size);
    let mut errno = SourceErrno::Unchanged;
    if request > MAX_ALLOC_SIZE {
        for _ in 0..2 {
            errno = errno.then(source_error_errno(crate::diagnostic_output::SourceErrorReport::AllocationTooLarge { size: request }));
        }
    }
    if offset == 0 && alignment >= PAGE_META_ALIGNMENT && !naturally_aligned(size, alignment) {
        errno = SourceErrno::Store(Errno::INVAL).then(errno);
    }
    errno = errno.then(source_error_errno(crate::diagnostic_output::SourceErrorReport::OutOfMemory { size: request }));
    Sourced::with(None, errno)
}

/// `mi_theap_realloc` or, with `zero`, `mi_theap_rezalloc`. Reuse requires
/// the old page's Heap to equal the supplied Theap's Heap; replacement
/// allocation uses that exact Theap without selecting the cached root.
///
/// # Safety
/// `theap` is a retained initialized Theap of the calling thread's live TLD
/// and Heap. `block` is null or an exact live allocation exclusively held
/// for this call. A successful result consumes the old block; failure
/// leaves it unchanged and live.
pub unsafe fn theap_realloc(
    theap: *mut core::ffi::c_void,
    block: *mut u8,
    new_size: usize,
    zero: bool,
) -> Sourced<Block> {
    let Some(selected) = NonNull::new(theap.cast::<crate::types::Theap>()) else { return Sourced::quiet(None) };
    #[cfg(feature = "mi-debug-1")]
    // SAFETY: forwarded exact-live-client and exclusion obligations.
    if let Some(errno) = unsafe { pointer_validation_errno(block, crate::diagnostic_output::SourcePointerOperation::Realloc) } {
        return Sourced::with(None, errno);
    }
    let mut earlier = SourceErrno::Unchanged;
    let size = if let Some(live) = NonNull::new(block) {
        // SAFETY: the exact live allocation remains stable for the call.
        let Some(heap) = (unsafe { crate::subproc::main_heaps::heap_of_block(live) }) else {
            return Sourced::quiet(None);
        };
        let observed = unsafe { usable_size_sourced(block) };
        earlier = observed.errno;
        let size = observed.value;
        if new_size > 0 && new_size <= size && new_size >= size / 2
            && unsafe { crate::types::Theap::heap_at(selected) } == heap.as_ptr()
        {
            return Sourced::with(Some(live), earlier);
        }
        size
    } else {
        // SAFETY: forwarded Theap lifetime; source's null shortcut zeroes
        // the complete client extent for rezalloc.
        return unsafe { crate::source_heap_api::theap_malloc(theap, new_size, zero) };
    };
    // SAFETY: forwarded Theap lifetime; zeroing happens after allocation.
    let mut result = unsafe { crate::source_heap_api::theap_malloc(theap, new_size, false) }.after(earlier);
    let Some(replacement) = result.value else { return result };
    let copy = size.min(new_size);
    let word = core::mem::size_of::<usize>();
    let zero_start = copy.saturating_sub(word) & !(word - 1);
    // SAFETY: the two live exclusive allocations do not overlap, and the
    // queried usable extent belongs to the newly returned block.
    unsafe {
        let usable = usable_size_validated(replacement.as_ptr());
        if zero && usable > zero_start {
            replacement.as_ptr().add(zero_start).write_bytes(0, usable - zero_start);
        } else if new_size == 0 {
            replacement.as_ptr().write(0);
        }
        core::ptr::copy_nonoverlapping(block, replacement.as_ptr(), copy);
        result.errno = result.errno.then(free_sourced(block).errno);
    }
    result
}

/// The supplied Theap's aligned realloc kernel. Aligned reuse depends on
/// pointer alignment and usable extent; the source does not require Heap
/// equality for this path. A replacement belongs to the supplied Theap.
///
/// # Safety
/// The initialized Theap belongs to the calling thread's retained TLD and
/// Heap. The old block is null or an exact exclusively held live client.
/// Success consumes it; a failed allocation leaves it unchanged and live.
unsafe fn theap_realloc_aligned_at(
    theap: *mut core::ffi::c_void,
    block: *mut u8,
    new_size: usize,
    alignment: usize,
    offset: usize,
    zero: bool,
) -> Sourced<Block> {
    if !size_class::alignment_is_valid(alignment) {
        let report = crate::diagnostic_output::SourceErrorReport::BadAlignment { size: new_size, alignment, offset };
        return Sourced::with(None, source_error_errno(report));
    }
    if alignment <= core::mem::size_of::<usize>() && offset == 0 {
        // SAFETY: forwarded exact-live-client and Theap obligations.
        return unsafe { theap_realloc(theap, block, new_size, zero) };
    }
    let Some(live) = NonNull::new(block) else {
        // SAFETY: the caller retains the supplied current-thread Theap.
        return unsafe { theap_malloc_aligned_at(theap, new_size, alignment, offset, zero) };
    };
    // SAFETY: caller retains the exact live client for this observation.
    let observed = unsafe { usable_size_sourced(block) };
    let size = observed.value;
    if new_size <= size && new_size >= size - size / 2
        && block.addr().wrapping_add(offset) & (alignment - 1) == 0
    {
        return Sourced::with(Some(live), observed.errno);
    }
    // SAFETY: forwarded retained Theap lifetime; initialize after copying.
    let mut result = unsafe { theap_malloc_aligned_at(theap, new_size, alignment, offset, false) }.after(observed.errno);
    let Some(replacement) = result.value else { return result };
    let copy = size.min(new_size);
    let zero_start = copy.saturating_sub(core::mem::size_of::<usize>());
    // SAFETY: the fresh replacement and exact old client do not overlap;
    // their usable extents cover the zeroed and copied bytes respectively.
    unsafe {
        let usable = usable_size_validated(replacement.as_ptr());
        if zero && usable > zero_start {
            replacement.as_ptr().add(zero_start).write_bytes(0, usable - zero_start);
        }
        core::ptr::copy_nonoverlapping(block, replacement.as_ptr(), copy);
        result.errno = result.errno.then(free_sourced(block).errno);
    }
    result
}

/// `mi_ublock_size`: the page block size of a successful result.
fn with_block_size(result: Sourced<Block>) -> Sourced<(Block, Option<usize>)> {
    // SAFETY: a successful result is this caller's exact live allocation.
    let block_size = result.value.and_then(|block| unsafe { native_block_size(block) });
    Sourced::with((result.value, block_size), result.errno)
}

/// `mi_umalloc`: the result and, when it is non-null, its page block size.
pub fn umalloc(size: usize) -> Sourced<(Block, Option<usize>)> {
    with_block_size(malloc_zero(size, false))
}

/// `mi_umalloc_small`.
pub fn umalloc_small(size: usize) -> Sourced<(Block, Option<usize>)> {
    with_block_size(malloc_zero(size, false))
}

/// `mi_uzalloc_small`.
pub fn uzalloc_small(size: usize) -> Sourced<(Block, Option<usize>)> {
    with_block_size(malloc_zero(size, true))
}

/// `mi_ucalloc`.
pub fn ucalloc(count: usize, size: usize) -> Sourced<(Block, Option<usize>)> {
    match size_class::count_size(count, size) {
        Some(total) => with_block_size(malloc_zero(total, true)),
        None => Sourced::with((None, None), count_size_overflow_errno(count, size)),
    }
}

/// How a free entry ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreeOutcome {
    /// The block was freed, or the pointer was null.
    Freed,
    /// The PageMap registers no page for the pointer; the source returns
    /// without effect.
    Unmapped,
    /// The native runtime could not complete a legal free and has retained
    /// its owner; the embedding boundary must not continue as if it freed.
    Retained,
    /// Pointer or source padding validation rejected this free and left the
    /// block owned. The caller retains the live allocation after the diagnostic.
    #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
    RejectedCorruption,
}

#[cfg(feature = "mi-debug-1")]
/// Rejects an unregistered unaligned pointer while permitting an exact live
/// aligned-offset client through its existing PageMap geometry.
/// The pinned debug word-alignment check also rejects pointers successfully
/// returned by aligned-offset allocation. The native entry preserves those
/// clients' allocation/free contract while retaining diagnostic refusal for
/// unregistered unaligned pointers and the existing padding verification.
///
/// # Safety
/// `pointer` is null, an exact live native client retained for the call, or
/// unregistered by this allocator. The caller excludes registration changes
/// for its containing slice and concurrent access that ends a live client's
/// lifetime. Registration alone does not authenticate an arbitrary interior
/// pointer; a registered pointer relies on the caller's exact-client proof.
pub(crate) unsafe fn pointer_validation_errno(pointer: *const u8, operation: crate::diagnostic_output::SourcePointerOperation) -> Option<SourceErrno> {
    if pointer.addr() & (crate::config::WORD_SIZE - 1) == 0
        || crate::source_options_api::option_is_enabled(crate::config::SourceOption::GuardedPrecise as c_int)
    {
        return None;
    }
    // SAFETY: the caller retains the exact client or excludes registration
    // changes for this unregistered address. This query reads only PageMap
    // registration; it does not read client storage or ordinary page fields.
    if unsafe { native_pointer_is_mapped(pointer) } {
        let client = NonNull::new(pointer.cast_mut()).unwrap();
        // SAFETY: registration plus the caller's exact-live-client obligation
        // retains the canonical source block during this geometry projection.
        // Free and usable-size still perform their existing padding checks.
        if unsafe { native_block_size(client) }.is_some() {
            return None;
        }
    }
    let report = crate::diagnostic_output::SourceErrorReport::UnalignedPointer { operation, pointer: pointer.addr() };
    Some(source_error_errno(report))
}

/// `mi_free` with its source diagnostic errno effect.
///
/// # Safety
/// The exact live-client and exclusion obligations of [`free`] apply.
pub unsafe fn free_sourced(block: *mut u8) -> Sourced<FreeOutcome> {
    #[cfg(feature = "mi-debug-1")]
    // SAFETY: forwarded exact-live-client and exclusion obligations.
    if let Some(errno) = unsafe { pointer_validation_errno(block, crate::diagnostic_output::SourcePointerOperation::Free) } {
        return Sourced::with(FreeOutcome::RejectedCorruption, errno);
    }
    // SAFETY: forwarded exact live-client contract.
    Sourced::quiet(unsafe { free_validated(block) })
}

/// `mi_free`.
///
/// # Safety
///
/// `block` is null, unmapped by this allocator, or an exact live native
/// allocation that no other thread accesses during the call. For an unmapped
/// pointer, its containing slice must not be registered during the call. A `Freed`
/// result consumes it; a validation refusal leaves the block live.
pub unsafe fn free(block: *mut u8) -> FreeOutcome {
    // SAFETY: forwarded exact live-client contract.
    unsafe { free_sourced(block) }.value
}

unsafe fn free_validated(block: *mut u8) -> FreeOutcome {
    let Some(block) = NonNull::new(block) else {
        return FreeOutcome::Freed;
    };
    // SAFETY: forwarded from this function's contract.
    match unsafe { native_free(block) } {
        NativePageFreeResult::Freed => FreeOutcome::Freed,
        NativePageFreeResult::InvalidPointer => FreeOutcome::Unmapped,
        NativePageFreeResult::Unavailable | NativePageFreeResult::Retained => FreeOutcome::Retained,
        #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
        NativePageFreeResult::RejectedCorruption => FreeOutcome::RejectedCorruption,
    }
}

/// `mi_free_small` with its source pointer-validation errno effect.
///
/// # Safety
/// `block` is null or a live client from the small allocation family, held
/// exclusively as required by [`free`].
pub unsafe fn free_small_sourced(block: *mut u8) -> Sourced<FreeOutcome> {
    #[cfg(feature = "mi-debug-1")]
    // SAFETY: forwarded exact-live-client and exclusion obligations.
    if let Some(errno) = unsafe { pointer_validation_errno(block, crate::diagnostic_output::SourcePointerOperation::FreeSmall) } {
        return Sourced::with(FreeOutcome::RejectedCorruption, errno);
    }
    // SAFETY: the caller supplies the small exact-live-client contract.
    Sourced::quiet(unsafe { free_validated(block) })
}

/// `mi_ufree`: frees `block` and reports its page block size, or 0 for a
/// null or unmapped pointer.
///
/// # Safety
///
/// The obligations of [`free`].
pub unsafe fn ufree(block: *mut u8) -> (FreeOutcome, usize) {
    // SAFETY: forwarded free obligations.
    unsafe { ufree_sourced(block) }.value
}

/// `mi_ufree` with its pointer-validation errno effect.
///
/// # Safety
/// The exact live-client and exclusion obligations of [`free`] apply.
pub unsafe fn ufree_sourced(block: *mut u8) -> Sourced<(FreeOutcome, usize)> {
    #[cfg(feature = "mi-debug-1")]
    // SAFETY: forwarded exact-live-client and exclusion obligations.
    if let Some(errno) = unsafe { pointer_validation_errno(block, crate::diagnostic_output::SourcePointerOperation::UFree) } {
        return Sourced::with((FreeOutcome::RejectedCorruption, 0), errno);
    }
    // SAFETY: a live pointer stays live until the free below.
    let block_size = NonNull::new(block).and_then(|live| unsafe { native_block_size(live) }).unwrap_or(0);
    // SAFETY: forwarded from this function's contract.
    Sourced::quiet((unsafe { free_validated(block) }, block_size))
}

/// `mi_cfree`: frees `block` only if the PageMap registers a page for it,
/// and reports whether it did.
///
/// # Safety
///
/// `block` is null, an exact live native allocation with the obligations of
/// [`free`], or lies in memory the caller owns that this allocator never
/// mapped.
pub unsafe fn cfree(block: *mut u8) -> (FreeOutcome, bool) {
    // SAFETY: forwarded slice-exclusion contract.
    if block.is_null() || !unsafe { native_pointer_is_mapped(block) } {
        return (FreeOutcome::Freed, false);
    }
    // SAFETY: a mapped pointer is, by this contract, a live native client.
    (unsafe { free(block) }, true)
}

/// `mi_usable_size`: 0 for null, otherwise the PageMap-derived extent.
///
/// # Safety
///
/// `block` is null or an exact live native allocation.
pub unsafe fn usable_size(block: *const u8) -> usize {
    // SAFETY: forwarded exact live-client contract.
    unsafe { usable_size_sourced(block) }.value
}

/// `mi_usable_size` with its source diagnostic errno effect.
///
/// # Safety
/// `block` is null or an exact live native allocation retained for the call.
pub unsafe fn usable_size_sourced(block: *const u8) -> Sourced<usize> {
    #[cfg(feature = "mi-debug-1")]
    // SAFETY: forwarded exact-live-client and exclusion obligations.
    if let Some(errno) = unsafe { pointer_validation_errno(block, crate::diagnostic_output::SourcePointerOperation::UsableSize) } {
        return Sourced::with(0, errno);
    }
    // SAFETY: forwarded exact live-client contract.
    Sourced::quiet(unsafe { usable_size_validated(block) })
}

unsafe fn usable_size_validated(block: *const u8) -> usize {
    match NonNull::new(block.cast_mut()) {
        // SAFETY: forwarded exact-live-client contract.
        Some(block) => unsafe { native_usable_size(block) }.unwrap_or(0),
        None => 0,
    }
}

/// `mi_check_owned` = `mi_any_heap_contains`: whether the safe PageMap
/// lookup finds a page for `pointer`.
///
/// # Safety
///
/// The obligations of [`cfree`] for `pointer`.
pub unsafe fn check_owned(pointer: *const u8) -> bool {
    // SAFETY: forwarded slice-exclusion contract.
    !pointer.is_null() && unsafe { native_pointer_is_mapped(pointer) }
}

fn os_page_size() -> usize {
    native_os_page_size().unwrap_or(SOURCE_DEFAULT_OS_PAGE_SIZE)
}

/// `mi_good_size`.
pub fn good_size(size: usize) -> usize {
    size_class::good_size(size, os_page_size()).unwrap_or(size)
}

/// `mi_is_redirected`: the selected Linux primitive never redirects.
pub const fn is_redirected() -> bool {
    false
}

/// `mi_collect`.
pub fn collect(force: bool) {
    if let Some(main) = crate::source_heap_api::fixed_runtime_theap() {
        let selected = crate::compiler_tls::default_theap();
        if selected != main || crate::subproc::lifecycle::current_thread_is_child_member() {
            // SAFETY: this thread retains its selected default Theap.
            unsafe { theap_collect(selected.as_ptr().cast(), force) };
            return;
        }
    }
    native_collect(force);
}

/// `mi_theap_collect`: null or uninitialized images have no work. A live
/// Theap collects only its own page queues and then its owning arenas and
/// statistics, without selecting a different cached or default root.
///
/// # Safety
/// A non-null `theap` is an address-stable Theap image. If initialized, it
/// belongs to the calling thread's retained TLD and Heap; the caller excludes
/// destruction, thread exit, and another mutation of its page queues.
pub unsafe fn theap_collect(theap: *mut core::ffi::c_void, force: bool) {
    let Some(theap) = NonNull::new(theap.cast::<crate::types::Theap>()) else { return };
    // SAFETY: caller retains the image through this initialization check.
    if unsafe { crate::types::Theap::heap_at(theap) }.is_null() { return; }
    if crate::subproc::lifecycle::current_thread_is_child_member() {
        // SAFETY: forwarded retained current-thread Theap contract.
        unsafe { crate::subproc::lifecycle::native_child_theap_collect(theap, force) };
    } else if crate::source_heap_api::fixed_runtime_theap() == Some(theap) {
        native_collect(force);
    } else {
        // SAFETY: forwarded retained current-thread Theap contract.
        unsafe { crate::subproc::main_heaps::native_theap_collect(theap, force) };
    }
}

/// `mi_theap_stats_get`: copy this Theap's unmerged statistics without
/// changing the default or cached Theap or merging into its Heap.
///
/// # Safety
/// `theap` is a retained initialized Theap image. `stats` is null or an
/// aligned readable and writable source statistics image, excluded from
/// other accesses for the call and disjoint from the Theap metadata.
pub unsafe fn theap_stats_get(theap: *mut core::ffi::c_void, stats: *mut u8) -> bool {
    let Some(_operation) = crate::runtime_lifecycle::NativeSubprocessOperation::enter() else { return false };
    let Some(theap) = NonNull::new(theap.cast::<crate::types::Theap>()) else { return false };
    // SAFETY: the caller retains the exact Theap and destination images.
    unsafe { crate::types::Theap::copy_statistics_into_source_image_at(theap, stats) }
}

/// `mi_theap_visit_blocks`: visit only this Theap's ordinary and full page
/// queues, in source bin and queue order. A null Theap has no pages.
///
/// # Safety
/// A non-null `theap` and its Heap stay initialized, retained and quiescent
/// through the call. Each page, free-list node and block area remains mapped
/// and stable, without owner or remote-free mutations. If any page exists,
/// `visitor` is callable through the traversal, does not mutate or free a
/// visited page or block, and uses each offered area only within its callback.
/// `argument` satisfies the callback's lifetime and access obligations.
pub unsafe fn theap_visit_blocks(
    theap: *const core::ffi::c_void,
    visit_blocks: bool,
    visitor: Option<crate::source_heap_api::HeapBlockVisitor>,
    argument: *mut core::ffi::c_void,
) -> bool {
    let Some(_operation) = crate::runtime_lifecycle::NativeSubprocessOperation::enter() else { return false };
    let Some(theap) = NonNull::new(theap.cast_mut().cast::<crate::types::Theap>()) else { return true };
    for bin in 0..=crate::config::BIN_FULL {
        // SAFETY: caller excludes queue changes; this scalar head does not
        // keep a Theap projection across callback delivery.
        let mut page = unsafe { theap.as_ref() }.queue(bin).map_or(core::ptr::null_mut(), |queue| queue.first());
        while let Some(current) = NonNull::new(page) {
            let Some(visitor) = visitor else { return false };
            // SAFETY: the caller retains these immutable source identities
            // and the queue links through the callback's return.
            let heap = NonNull::new(unsafe { crate::types::Theap::heap_at(theap) });
            let Some(heap) = heap else { return false };
            let next = unsafe { crate::types::Page::queue_next_at(current) };
            if !unsafe { crate::source_heap_api::visit_heap_page(heap, current, visit_blocks, visitor, argument) } {
                return false;
            }
            page = next;
        }
    }
    true
}

/// `mi_expand`: the unchanged pointer when `new_size` fits its usable
/// extent, else null. It never allocates, moves, or frees.
///
/// # Safety
///
/// `block` is null or an exact live native allocation.
pub unsafe fn expand(block: *mut u8, new_size: usize) -> Block {
    if crate::config::PADDING_SIZE != 0 { return None; }
    let block = NonNull::new(block)?;
    // SAFETY: forwarded exact-live-client contract.
    let usable = unsafe { usable_size(block.as_ptr()) };
    crate::alloc::expansion_fits(usable, new_size).then_some(block)
}

/// `mi__expand`: [`expand`] storing `ENOMEM` on failure.
///
/// # Safety
///
/// The obligations of [`expand`].
pub unsafe fn expand_errno(block: *mut u8, new_size: usize) -> Sourced<Block> {
    // SAFETY: forwarded contract.
    match unsafe { expand(block, new_size) } {
        Some(block) => Sourced::quiet(Some(block)),
        None => Sourced::with(None, SourceErrno::Store(Errno::NOMEM)),
    }
}

/// The failure errno of the ordinary realloc kernel: an invalid pointer
/// returns null silently, and a replacement allocation fails at the
/// `_mi_theap_malloc_zero` sites.
fn realloc_result(result: NativePageAllocationResult) -> Sourced<Block> {
    match result {
        NativePageAllocationResult::Allocated(block) => Sourced::quiet(Some(block)),
        NativePageAllocationResult::Unavailable => Sourced::quiet(None),
        NativePageAllocationResult::AllocationFailed | NativePageAllocationResult::Retained => {
            Sourced::with(None, SourceErrno::error_message(Errno::NOMEM))
        }
    }
}

/// `mi_theap_realloc_zero_ex` for a present pointer, and for a null one in
/// the entries that call it directly (`mi_urealloc`, low-alignment aligned
/// realloc).
unsafe fn realloc_zero(block: *mut u8, new_size: usize, zero: bool) -> Sourced<Block> {
    if let Some(main) = crate::source_heap_api::fixed_runtime_theap() {
        let selected = crate::compiler_tls::default_theap();
        if selected != main {
            // SAFETY: the calling thread retains its substituted Theap and
            // the caller holds the exact live client throughout reallocation.
            return unsafe { theap_realloc(selected.as_ptr().cast(), block, new_size, zero) };
        }
    }
    // SAFETY: forwarded exact-live-client contract.
    unsafe { realloc_zero_native(block, new_size, zero) }
}

/// Reallocate on the fixed main-Heap Theap independently of the default root.
///
/// # Safety
/// `block` is null or an exact live client held exclusively for reallocation.
/// Success consumes the old block; failure leaves it live and unchanged.
pub(crate) unsafe fn realloc_zero_native(block: *mut u8, new_size: usize, zero: bool) -> Sourced<Block> {
    #[cfg(feature = "mi-debug-1")]
    // SAFETY: forwarded exact-live-client and exclusion obligations.
    if let Some(errno) = unsafe { pointer_validation_errno(block, crate::diagnostic_output::SourcePointerOperation::Realloc) } {
        return Sourced::with(None, errno);
    }

    // SAFETY: forwarded exact-live-client contract.
    realloc_result(unsafe { native_reallocate_source(NonNull::new(block), new_size, zero) })
}

/// `mi_realloc`.
///
/// # Safety
///
/// `block` is null or an exact live native allocation that no other thread
/// accesses during the call. On a non-null result the caller must not use
/// `block` again; on null it stays live and unchanged.
pub unsafe fn realloc(block: *mut u8, new_size: usize) -> Sourced<Block> {
    if block.is_null() {
        return malloc_zero(new_size, false);
    }
    // SAFETY: forwarded contract.
    unsafe { realloc_zero(block, new_size, false) }
}

/// `mi_reallocn`.
///
/// # Safety
///
/// The obligations of [`realloc`].
pub unsafe fn reallocn(block: *mut u8, count: usize, size: usize) -> Sourced<Block> {
    match size_class::count_size(count, size) {
        // SAFETY: forwarded contract.
        Some(total) => unsafe { realloc(block, total) },
        None => Sourced::with(None, count_size_overflow_errno(count, size)),
    }
}

/// `mi_reallocf`: [`realloc`] that frees `block` when it fails.
///
/// # Safety
///
/// The obligations of [`realloc`], except that `block` is consumed on every
/// path.
pub unsafe fn reallocf(block: *mut u8, new_size: usize) -> Sourced<(Block, FreeOutcome)> {
    // SAFETY: forwarded contract.
    let result = unsafe { realloc(block, new_size) };
    let freed = if result.value.is_none() && !block.is_null() {
        // SAFETY: the failed realloc left `block` live and unchanged.
        unsafe { free(block) }
    } else {
        FreeOutcome::Freed
    };
    Sourced::with((result.value, freed), result.errno)
}

/// `mi_rezalloc`.
///
/// # Safety
///
/// The obligations of [`realloc`].
pub unsafe fn rezalloc(block: *mut u8, new_size: usize) -> Sourced<Block> {
    if block.is_null() {
        return malloc_zero(new_size, true);
    }
    // SAFETY: forwarded contract.
    unsafe { realloc_zero(block, new_size, true) }
}

/// `mi_recalloc`.
///
/// # Safety
///
/// The obligations of [`realloc`].
pub unsafe fn recalloc(block: *mut u8, count: usize, size: usize) -> Sourced<Block> {
    match size_class::count_size(count, size) {
        // SAFETY: forwarded contract.
        Some(total) => unsafe { rezalloc(block, total) },
        None => Sourced::with(None, count_size_overflow_errno(count, size)),
    }
}

/// `mi_urealloc`: the result with the old and new page block sizes. Each
/// size is `None` where the source leaves its output untouched; an invalid
/// pointer reports 0 for both.
///
/// # Safety
///
/// The obligations of [`realloc`].
pub unsafe fn urealloc(block: *mut u8, new_size: usize) -> Sourced<(Block, Option<usize>, Option<usize>)> {
    #[cfg(feature = "mi-debug-1")]
    // SAFETY: forwarded exact-live-client and exclusion obligations.
    if let Some(errno) = unsafe { pointer_validation_errno(block, crate::diagnostic_output::SourcePointerOperation::Realloc) } {
        return Sourced::with((None, Some(0), Some(0)), errno);
    }
    let before = match NonNull::new(block) {
        None => 0,
        // SAFETY: forwarded exact-live-client contract.
        Some(live) => match unsafe { native_block_size(live) } {
            Some(block_size) => block_size,
            None => return Sourced::quiet((None, Some(0), Some(0))),
        },
    };
    // SAFETY: forwarded contract.
    let result = unsafe { realloc_zero(block, new_size, false) };
    // SAFETY: a successful result is the caller's exact live allocation.
    let after = result.value.and_then(|live| unsafe { native_block_size(live) });
    Sourced::with((result.value, Some(before), after), result.errno)
}

/// `mi_malloc_is_naturally_aligned`.
fn naturally_aligned(size: usize, alignment: usize) -> bool {
    if alignment > size {
        return false;
    }
    let block_size = good_size(size);
    (block_size <= PAGE_MAX_START_BLOCK_ALIGN2 && size_class::alignment_is_valid(block_size))
        || (alignment == PAGE_OSPAGE_BLOCK_ALIGN2 && block_size % PAGE_OSPAGE_BLOCK_ALIGN2 == 0)
}

/// The errno effect of a failed `mi_theap_malloc_zero_aligned_at` for a
/// valid alignment and in-range size, following the source's branch order.
fn aligned_failure_errno(size: usize, alignment: usize, offset: usize) -> SourceErrno {
    if offset == 0 && naturally_aligned(size, alignment) {
        return SourceErrno::error_message(Errno::NOMEM);
    }
    if alignment > PAGE_MAX_OVERALLOC_ALIGN {
        if offset != 0 {
            return SourceErrno::error_message(Errno::OVERFLOW);
        }
        if alignment >= PAGE_META_ALIGNMENT {
            // `arena.c:824-832` assigns EINVAL before the generic fallback's
            // out-of-memory report, which then finds errno nonzero.
            return SourceErrno::Store(Errno::INVAL);
        }
    }
    SourceErrno::error_message(Errno::NOMEM)
}

/// `mi_theap_malloc_zero_aligned_at`.
fn malloc_zero_aligned_at(size: usize, alignment: usize, offset: usize, zero: bool) -> Sourced<Block> {
    if let Some(main) = crate::source_heap_api::fixed_runtime_theap() {
        let selected = crate::compiler_tls::default_theap();
        if selected != main {
            // SAFETY: the calling thread retains its substituted default
            // Theap until restoration, including this entire allocation.
            return unsafe { theap_malloc_aligned_at(selected.as_ptr().cast(), size, alignment, offset, zero) };
        }
    }
    malloc_zero_aligned_at_native(size, alignment, offset, zero)
}

/// Aligned allocation on the fixed main-Heap Theap, independent of a
/// substituted default Theap. Heap-scoped calls use this after selection.
pub(crate) fn malloc_zero_aligned_at_native(size: usize, alignment: usize, offset: usize, zero: bool) -> Sourced<Block> {
    // The native aligned entry reports these pre-allocation refusals through
    // `_mi_error_message` (`alloc-aligned.c:81-84,163-166,191-193`) and then
    // fails; the errno effect follows each report.
    let refusal = if !size_class::alignment_is_valid(alignment) || !size_class::request_size_is_valid(size) {
        Some(Errno::INVAL)
    } else if alignment > PAGE_MAX_OVERALLOC_ALIGN && offset != 0 {
        Some(Errno::OVERFLOW)
    } else {
        None
    };
    match native_block(native_allocate_aligned_at(size, alignment, offset, zero)) {
        Some(block) => Sourced::quiet(Some(block)),
        None => Sourced::with(None, match refusal {
            Some(error) => SourceErrno::error_message(error),
            None => aligned_failure_errno(size, alignment, offset),
        }),
    }
}

/// `mi_malloc_aligned_at`.
pub fn malloc_aligned_at(size: usize, alignment: usize, offset: usize) -> Sourced<Block> {
    malloc_zero_aligned_at(size, alignment, offset, false)
}

/// `mi_malloc_aligned`.
pub fn malloc_aligned(size: usize, alignment: usize) -> Sourced<Block> {
    malloc_zero_aligned_at(size, alignment, 0, false)
}

/// `mi_zalloc_aligned_at`.
pub fn zalloc_aligned_at(size: usize, alignment: usize, offset: usize) -> Sourced<Block> {
    malloc_zero_aligned_at(size, alignment, offset, true)
}

/// `mi_zalloc_aligned`.
pub fn zalloc_aligned(size: usize, alignment: usize) -> Sourced<Block> {
    malloc_zero_aligned_at(size, alignment, 0, true)
}

/// `mi_calloc_aligned_at`.
pub fn calloc_aligned_at(count: usize, size: usize, alignment: usize, offset: usize) -> Sourced<Block> {
    match size_class::count_size(count, size) {
        Some(total) => malloc_zero_aligned_at(total, alignment, offset, true),
        None => Sourced::with(None, count_size_overflow_errno(count, size)),
    }
}

/// `mi_calloc_aligned`.
pub fn calloc_aligned(count: usize, size: usize, alignment: usize) -> Sourced<Block> {
    calloc_aligned_at(count, size, alignment, 0)
}

/// `mi_umalloc_aligned`.
pub fn umalloc_aligned(size: usize, alignment: usize) -> Sourced<(Block, Option<usize>)> {
    with_block_size(malloc_zero_aligned_at(size, alignment, 0, false))
}

/// `mi_uzalloc_aligned`.
pub fn uzalloc_aligned(size: usize, alignment: usize) -> Sourced<(Block, Option<usize>)> {
    with_block_size(malloc_zero_aligned_at(size, alignment, 0, true))
}

/// The fixed main Theap's aligned realloc kernel, independent of the default.
///
/// # Safety
/// `block` is null or an exact live client exclusively held for this call;
/// success consumes it and failure leaves it live and unchanged.
pub(crate) unsafe fn realloc_zero_aligned_at_native(
    block: *mut u8,
    new_size: usize,
    alignment: usize,
    offset: usize,
    zero: bool,
) -> Sourced<Block> {
    if !size_class::alignment_is_valid(alignment) {
        return Sourced::with(None, SourceErrno::error_message(Errno::INVAL));
    }
    if alignment <= core::mem::size_of::<usize>() && offset == 0 {
        // SAFETY: forwarded contract.
        return unsafe { realloc_zero_native(block, new_size, zero) };
    }
    let Some(live) = NonNull::new(block) else {
        return malloc_zero_aligned_at_native(new_size, alignment, offset, zero);
    };
    if !size_class::request_size_is_valid(new_size) {
        // The replacement allocation refuses the size before any lookup.
        return Sourced::with(None, SourceErrno::error_message(Errno::INVAL));
    }
    // SAFETY: forwarded exact-live-client contract.
    #[cfg(feature = "mi-debug-1")]
    // SAFETY: forwarded exact-live-client and exclusion obligations.
    if let Some(earlier) = unsafe { pointer_validation_errno(block, crate::diagnostic_output::SourcePointerOperation::UsableSize) } {
        if new_size == 0 && block.addr().wrapping_add(offset) & (alignment - 1) == 0 {
            return Sourced::with(Some(live), earlier);
        }
        let mut replacement = malloc_zero_aligned_at_native(new_size, alignment, offset, zero).after(earlier);
        if replacement.value.is_some() {
            let freed = unsafe { free_sourced(block) };
            replacement.errno = replacement.errno.then(freed.errno);
        }
        return replacement;
    }
    match unsafe { native_reallocate_aligned_at(Some(live), new_size, alignment, offset, zero) } {
        NativePageAllocationResult::Allocated(block) => Sourced::quiet(Some(block)),
        NativePageAllocationResult::Unavailable => Sourced::quiet(None),
        NativePageAllocationResult::AllocationFailed | NativePageAllocationResult::Retained => {
            Sourced::with(None, aligned_failure_errno(new_size, alignment, offset))
        }
    }
}

/// Reallocation using the current default Theap's aligned source kernel.
///
/// # Safety
/// The exact live-client obligations of `realloc` apply.
unsafe fn realloc_zero_aligned_at(block: *mut u8, new_size: usize, alignment: usize, offset: usize, zero: bool) -> Sourced<Block> {
    if let Some(main) = crate::source_heap_api::fixed_runtime_theap() {
        let selected = crate::compiler_tls::default_theap();
        if selected != main {
            // SAFETY: caller retains the exact live client; the calling
            // thread retains its substituted default Theap until restoration.
            return unsafe { theap_realloc_aligned_at(selected.as_ptr().cast(), block, new_size, alignment, offset, zero) };
        }
    }
    // SAFETY: forwarded exact-live-client contract.
    unsafe { realloc_zero_aligned_at_native(block, new_size, alignment, offset, zero) }
}

/// `mi_theap_realloc_zero_aligned`: an alignment of at most one word takes
/// the ordinary kernel before any validation.
unsafe fn realloc_zero_aligned(block: *mut u8, new_size: usize, alignment: usize, zero: bool) -> Sourced<Block> {
    if alignment <= core::mem::size_of::<usize>() {
        // SAFETY: forwarded contract.
        return unsafe { realloc_zero(block, new_size, zero) };
    }
    // SAFETY: forwarded contract.
    unsafe { realloc_zero_aligned_at(block, new_size, alignment, 0, zero) }
}

/// `mi_realloc_aligned_at`.
///
/// # Safety
///
/// The obligations of [`realloc`].
pub unsafe fn realloc_aligned_at(block: *mut u8, new_size: usize, alignment: usize, offset: usize) -> Sourced<Block> {
    // SAFETY: forwarded contract.
    unsafe { realloc_zero_aligned_at(block, new_size, alignment, offset, false) }
}

/// `mi_realloc_aligned`.
///
/// # Safety
///
/// The obligations of [`realloc`].
pub unsafe fn realloc_aligned(block: *mut u8, new_size: usize, alignment: usize) -> Sourced<Block> {
    // SAFETY: forwarded contract.
    unsafe { realloc_zero_aligned(block, new_size, alignment, false) }
}

/// `mi_rezalloc_aligned_at`.
///
/// # Safety
///
/// The obligations of [`realloc`].
pub unsafe fn rezalloc_aligned_at(block: *mut u8, new_size: usize, alignment: usize, offset: usize) -> Sourced<Block> {
    // SAFETY: forwarded contract.
    unsafe { realloc_zero_aligned_at(block, new_size, alignment, offset, true) }
}

/// `mi_rezalloc_aligned`.
///
/// # Safety
///
/// The obligations of [`realloc`].
pub unsafe fn rezalloc_aligned(block: *mut u8, new_size: usize, alignment: usize) -> Sourced<Block> {
    // SAFETY: forwarded contract.
    unsafe { realloc_zero_aligned(block, new_size, alignment, true) }
}

/// `mi_recalloc_aligned_at` and `mi_aligned_offset_recalloc`.
///
/// # Safety
///
/// The obligations of [`realloc`].
pub unsafe fn recalloc_aligned_at(
    block: *mut u8,
    count: usize,
    size: usize,
    alignment: usize,
    offset: usize,
) -> Sourced<Block> {
    match size_class::count_size(count, size) {
        // SAFETY: forwarded contract.
        Some(total) => unsafe { realloc_zero_aligned_at(block, total, alignment, offset, true) },
        None => Sourced::with(None, count_size_overflow_errno(count, size)),
    }
}

/// `mi_recalloc_aligned` and `mi_aligned_recalloc`.
///
/// # Safety
///
/// The obligations of [`realloc`].
pub unsafe fn recalloc_aligned(block: *mut u8, count: usize, size: usize, alignment: usize) -> Sourced<Block> {
    match size_class::count_size(count, size) {
        // SAFETY: forwarded contract.
        Some(total) => unsafe { realloc_zero_aligned(block, total, alignment, true) },
        None => Sourced::with(None, count_size_overflow_errno(count, size)),
    }
}

/// `mi_malloc_good_size`.
pub fn malloc_good_size(size: usize) -> usize {
    good_size(size)
}

/// `mi_posix_memalign`: the return code, the value to store through the
/// output pointer (`None` leaves it untouched), and the errno effect.
pub fn posix_memalign(out_is_null: bool, alignment: usize, size: usize) -> Sourced<(c_int, Option<Block>)> {
    if out_is_null {
        return Sourced::quiet((Errno::INVAL.raw(), None));
    }
    if alignment < core::mem::size_of::<*mut u8>() || !size_class::alignment_is_valid(alignment) {
        return Sourced::quiet((Errno::INVAL.raw(), None));
    }
    let result = malloc_aligned(size, alignment);
    if result.value.is_none() && size != 0 {
        return Sourced::with((Errno::NOMEM.raw(), None), result.errno);
    }
    Sourced::with((0, Some(result.value)), result.errno)
}

/// `mi_memalign`.
pub fn memalign(alignment: usize, size: usize) -> Sourced<Block> {
    malloc_aligned(size, alignment)
}

/// `mi_valloc`.
pub fn valloc(size: usize) -> Sourced<Block> {
    memalign(os_page_size(), size)
}

/// `mi_pvalloc`.
pub fn pvalloc(size: usize) -> Sourced<Block> {
    let page = os_page_size();
    if size >= usize::MAX - page {
        return Sourced::quiet(None);
    }
    malloc_aligned((size + page - 1) & !(page - 1), page)
}

/// `mi_aligned_alloc`: the pinned entry skips the C11 size-multiple check.
pub fn aligned_alloc(alignment: usize, size: usize) -> Sourced<Block> {
    malloc_aligned(size, alignment)
}

/// `mi_reallocarray`.
///
/// # Safety
///
/// The obligations of [`realloc`].
pub unsafe fn reallocarray(block: *mut u8, count: usize, size: usize) -> Sourced<Block> {
    let Some(total) = size_class::count_size(count, size) else {
        let earlier = count_size_overflow_errno(count, size);
        return Sourced::with(None, earlier.then(SourceErrno::Store(Errno::OVERFLOW)));
    };
    // SAFETY: forwarded contract.
    let result = unsafe { realloc(block, total) };
    match result.value {
        Some(_) => result,
        None => Sourced::with(None, result.errno.then(SourceErrno::Store(Errno::NOMEM))),
    }
}

/// The outcome of `mi_reallocarr` for its `*ptrp`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReallocarrStore {
    /// `*ptrp` is left untouched.
    Keep,
    /// `*ptrp` receives this pointer (null after freeing a zero request).
    Store(*mut u8),
}

/// `mi_reallocarr` given the current `*ptrp` (`None` for a null `ptrp`):
/// the return code, the update of `*ptrp`, the free outcome of a zero-total
/// request, and the errno effect.
///
/// # Safety
///
/// A present `current` obeys the obligations of [`realloc`].
pub unsafe fn reallocarr(current: Option<*mut u8>, count: usize, size: usize) -> Sourced<(c_int, ReallocarrStore, FreeOutcome)> {
    let Some(current) = current.filter(|_| size != 0) else {
        return Sourced::with((Errno::INVAL.raw(), ReallocarrStore::Keep, FreeOutcome::Freed), SourceErrno::Store(Errno::INVAL));
    };
    let Some(total) = size_class::count_size(count, size) else {
        let earlier = count_size_overflow_errno(count, size);
        return Sourced::with((Errno::OVERFLOW.raw(), ReallocarrStore::Keep, FreeOutcome::Freed), earlier.then(SourceErrno::Store(Errno::OVERFLOW)));
    };
    if total == 0 {
        // SAFETY: forwarded contract.
        let freed = unsafe { free(current) };
        return Sourced::quiet((0, ReallocarrStore::Store(null_mut()), freed));
    }
    // SAFETY: forwarded contract.
    let result = unsafe { realloc(current, total) };
    match result.value {
        Some(block) => Sourced::with((0, ReallocarrStore::Store(block.as_ptr()), FreeOutcome::Freed), result.errno),
        None => Sourced::with(
            (Errno::NOMEM.raw(), ReallocarrStore::Keep, FreeOutcome::Freed),
            result.errno.then(SourceErrno::Store(Errno::NOMEM)),
        ),
    }
}

/// `_mi_strnlen` for a NUL-terminated string read at most `max` bytes.
///
/// # Safety
///
/// `text` is readable up to its terminator or `max` bytes.
pub(crate) unsafe fn strnlen(text: *const c_char, max: usize) -> usize {
    let mut length = 0;
    // SAFETY: forwarded readability contract; the loop stops at the first
    // terminator or the bound.
    while length < max && unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    length
}

/// `mi_theap_strndup`'s copy after its length is known.
unsafe fn duplicate(text: *const c_char, length: usize) -> Sourced<Block> {
    if length > MAX_ALLOC_SIZE - 1 {
        return Sourced::quiet(None);
    }
    let result = malloc_zero(length + 1, false);
    if let Some(copy) = result.value {
        // SAFETY: `text` has `length` readable bytes and `copy` is a fresh
        // allocation of `length + 1` bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(text.cast::<u8>(), copy.as_ptr(), length);
            copy.as_ptr().add(length).write(0);
        }
    }
    result
}

/// `mi_strdup`.
///
/// # Safety
///
/// `text` is null or NUL-terminated.
pub unsafe fn strdup(text: *const c_char) -> Sourced<Block> {
    if text.is_null() {
        return Sourced::quiet(None);
    }
    // SAFETY: forwarded NUL-termination contract.
    unsafe { duplicate(text, strnlen(text, usize::MAX)) }
}

/// `mi_strndup`.
///
/// # Safety
///
/// `text` is null, or readable up to its terminator or `max` bytes.
pub unsafe fn strndup(text: *const c_char, max: usize) -> Sourced<Block> {
    if text.is_null() {
        return Sourced::quiet(None);
    }
    // SAFETY: forwarded readability contract.
    unsafe { duplicate(text, strnlen(text, max)) }
}

/// `mi_mbsdup`.
///
/// # Safety
///
/// The obligations of [`strdup`].
pub unsafe fn mbsdup(text: *const u8) -> Sourced<Block> {
    // SAFETY: forwarded contract.
    unsafe { strdup(text.cast()) }
}

/// `mi_wcsdup` for the four-byte Linux `wchar_t`.
///
/// # Safety
///
/// `text` is null or a NUL-terminated wide string.
pub unsafe fn wcsdup(text: *const i32) -> Sourced<Block> {
    if text.is_null() {
        return Sourced::quiet(None);
    }
    let mut length = 0usize;
    // SAFETY: forwarded NUL-termination contract.
    while unsafe { *text.add(length) } != 0 && length < isize::MAX as usize {
        length += 1;
    }
    let Some(size) = (length + 1).checked_mul(core::mem::size_of::<i32>()).filter(|size| *size <= isize::MAX as usize) else {
        return Sourced::quiet(None);
    };
    let result = malloc_zero(size, false);
    if let Some(copy) = result.value {
        // SAFETY: the source copies `size` bytes: the text and terminator.
        unsafe { core::ptr::copy_nonoverlapping(text.cast::<u8>(), copy.as_ptr(), size) };
    }
    result
}

/// `mi_dupenv_s`: the return code, the value for `*buf` (`None` leaves it
/// untouched), the value for `*size` (`None` leaves it untouched), and the
/// errno effect.
///
/// # Safety
///
/// `name` is null or NUL-terminated.
pub unsafe fn dupenv_s(
    runtime: &impl SourceCRuntime,
    buf_is_null: bool,
    size_is_null: bool,
    name: *const c_char,
) -> Sourced<(c_int, Option<Block>, Option<usize>)> {
    let cleared_size = (!size_is_null).then_some(0);
    if buf_is_null || name.is_null() {
        return Sourced::quiet((Errno::INVAL.raw(), None, cleared_size));
    }
    // SAFETY: `name` is NUL-terminated.
    let value = unsafe { runtime.getenv(name) };
    if value.is_null() {
        return Sourced::quiet((0, Some(None), cleared_size));
    }
    // SAFETY: `getenv` returned a NUL-terminated value.
    let copy = unsafe { strdup(value) };
    if copy.value.is_none() {
        return Sourced::with((Errno::NOMEM.raw(), Some(None), cleared_size), copy.errno);
    }
    // SAFETY: the same value is still NUL-terminated.
    let length = unsafe { strnlen(value, usize::MAX) } + 1;
    Sourced::with((0, Some(copy.value), (!size_is_null).then_some(length)), copy.errno)
}

/// `mi_wdupenv_s` on a non-Windows target: always `EINVAL`.
pub fn wdupenv_s(buf_is_null: bool, size_is_null: bool, name_is_null: bool) -> (c_int, Option<Block>, Option<usize>) {
    let cleared_size = (!size_is_null).then_some(0);
    if buf_is_null || name_is_null {
        return (Errno::INVAL.raw(), None, cleared_size);
    }
    (Errno::INVAL.raw(), Some(None), cleared_size)
}

/// `mi_path_max`'s process-wide cache.
static PATH_MAX: AtomicUsize = AtomicUsize::new(0);

/// `mi_path_max`.
pub(crate) fn path_max(runtime: &impl SourceCRuntime) -> usize {
    let cached = PATH_MAX.load(Ordering::Acquire);
    if cached != 0 {
        return cached;
    }
    let configured = runtime.path_max();
    let value = if configured <= 0 {
        4096
    } else if configured < 256 {
        256
    } else if configured > 64 * 1024 {
        64 * 1024
    } else {
        configured as usize
    };
    let _ = PATH_MAX.compare_exchange(0, value, Ordering::AcqRel, Ordering::Acquire);
    value
}

/// `mi_realpath`.
///
/// # Safety
///
/// `name` is null or NUL-terminated; `resolved` is null or writable for the
/// system `PATH_MAX` bytes.
pub unsafe fn realpath(runtime: &impl SourceCRuntime, name: *const c_char, resolved: *mut c_char) -> Sourced<*mut c_char> {
    if !resolved.is_null() {
        // SAFETY: forwarded contract.
        return Sourced::quiet(unsafe { runtime.realpath(name, resolved) });
    }
    let limit = path_max(runtime);
    let buffer = malloc_zero(limit + 1, true);
    let Some(buffer) = buffer.value else {
        return Sourced::with(null_mut(), buffer.errno.then(SourceErrno::Store(Errno::NOMEM)));
    };
    // SAFETY: `buffer` is a fresh zeroed allocation of `limit + 1` bytes.
    let resolved = unsafe { runtime.realpath(name, buffer.as_ptr().cast()) };
    // SAFETY: `resolved` is null or the NUL-terminated result in `buffer`.
    let result = unsafe { strndup(resolved, limit) };
    // SAFETY: `buffer` is this call's own live allocation.
    let _ = unsafe { free(buffer.as_ptr()) };
    Sourced::with(result.value.map_or(null_mut(), |copy| copy.as_ptr().cast()), result.errno)
}

/// Plain-C `mi_try_new_handler`: `true` after calling the installed new
/// handler, otherwise the out-of-memory report and, unless `nothrow`,
/// `abort`.
pub(crate) fn try_new_handler(runtime: &impl SourceCRuntime, nothrow: bool) -> (bool, SourceErrno) {
    match runtime.new_handler() {
        None => {
            if !nothrow {
                runtime.abort();
            }
            (false, SourceErrno::error_message(Errno::NOMEM))
        }
        Some(handler) => {
            // SAFETY: the C++ runtime's installed new handler is user code
            // with no arguments; no allocator state is held across it.
            unsafe { handler() };
            (true, SourceErrno::Unchanged)
        }
    }
}

/// `mi_theap_try_new`.
fn try_new(runtime: &impl SourceCRuntime, size: usize, nothrow: bool, earlier: SourceErrno) -> Sourced<Block> {
    let mut errno = earlier;
    for _ in 0..TRY_NEW_MAX {
        let (retry, effect) = try_new_handler(runtime, nothrow);
        errno = errno.then(effect);
        if !retry {
            break;
        }
        if size > MAX_ALLOC_SIZE {
            return Sourced::with(None, errno);
        }
        let result = malloc_zero(size, false).after(errno);
        errno = result.errno;
        if result.value.is_some() {
            return result;
        }
    }
    Sourced::with(None, errno)
}

/// `mi_new`.
pub fn new(runtime: &impl SourceCRuntime, size: usize) -> Sourced<Block> {
    let result = malloc_zero(size, false);
    if result.value.is_some() {
        return result;
    }
    try_new(runtime, size, false, result.errno)
}

/// `mi_new_nothrow`.
pub fn new_nothrow(runtime: &impl SourceCRuntime, size: usize) -> Sourced<Block> {
    let result = malloc_zero(size, false);
    if result.value.is_some() {
        return result;
    }
    try_new(runtime, size, true, result.errno)
}

/// `mi_new_n`.
pub fn new_n(runtime: &impl SourceCRuntime, count: usize, size: usize) -> Sourced<Block> {
    match size_class::count_size(count, size) {
        Some(total) => new(runtime, total),
        None => {
            let earlier = count_size_overflow_errno(count, size);
            let (_, errno) = try_new_handler(runtime, false);
            Sourced::with(None, earlier.then(errno))
        }
    }
}

/// `mi_try_new_aligned`.
fn try_new_aligned(
    runtime: &impl SourceCRuntime,
    size: usize,
    alignment: usize,
    nothrow: bool,
    earlier: SourceErrno,
) -> Sourced<Block> {
    let mut errno = earlier;
    for _ in 0..TRY_NEW_MAX {
        let (retry, effect) = try_new_handler(runtime, nothrow);
        errno = errno.then(effect);
        if !retry {
            break;
        }
        if !size_class::alignment_is_valid(alignment) {
            return Sourced::with(None, errno);
        }
        let result = malloc_aligned(size, alignment).after(errno);
        errno = result.errno;
        if result.value.is_some() {
            return result;
        }
    }
    Sourced::with(None, errno)
}

/// `mi_new_aligned`.
pub fn new_aligned(runtime: &impl SourceCRuntime, size: usize, alignment: usize) -> Sourced<Block> {
    let result = malloc_aligned(size, alignment);
    if result.value.is_some() {
        return result;
    }
    try_new_aligned(runtime, size, alignment, false, result.errno)
}

/// `mi_new_aligned_nothrow`.
pub fn new_aligned_nothrow(runtime: &impl SourceCRuntime, size: usize, alignment: usize) -> Sourced<Block> {
    let result = malloc_aligned(size, alignment);
    if result.value.is_some() {
        return result;
    }
    try_new_aligned(runtime, size, alignment, true, result.errno)
}

/// `mi_new_realloc`.
///
/// # Safety
///
/// The obligations of [`realloc`].
pub unsafe fn new_realloc(runtime: &impl SourceCRuntime, block: *mut u8, new_size: usize) -> Sourced<Block> {
    // SAFETY: forwarded contract.
    let first = unsafe { realloc(block, new_size) };
    if first.value.is_some() {
        return first;
    }
    let mut errno = first.errno;
    for _ in 0..TRY_NEW_MAX {
        let (retry, effect) = try_new_handler(runtime, false);
        errno = errno.then(effect);
        if !retry {
            break;
        }
        if new_size > MAX_ALLOC_SIZE {
            return Sourced::with(None, errno);
        }
        // SAFETY: the failed attempt left `block` live and unchanged.
        let result = unsafe { realloc(block, new_size) }.after(errno);
        errno = result.errno;
        if result.value.is_some() {
            return result;
        }
    }
    Sourced::with(None, errno)
}

/// `mi_new_reallocn`.
///
/// # Safety
///
/// The obligations of [`realloc`].
pub unsafe fn new_reallocn(runtime: &impl SourceCRuntime, block: *mut u8, count: usize, size: usize) -> Sourced<Block> {
    match size_class::count_size(count, size) {
        // SAFETY: forwarded contract.
        Some(total) => unsafe { new_realloc(runtime, block, total) },
        None => {
            let earlier = count_size_overflow_errno(count, size);
            let (_, errno) = try_new_handler(runtime, false);
            Sourced::with(None, earlier.then(errno))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SourceErrno;
    use crabc_core::Errno;

    #[cfg(all(target_arch = "x86_64", feature = "mi-guarded", not(miri)))]
    #[test]
    fn cold_public_aligned_allocation_samples_only_after_thread_initialization() {
        crate::test_process::run_in_fresh_process(
            "source_api::tests::cold_public_aligned_allocation_samples_only_after_thread_initialization",
            || {
                unsafe extern "C" fn discard(_: *const core::ffi::c_char) {}
                std::env::set_var("mimalloc_guarded_sample_rate", "1");
                // SAFETY: the fresh process retains its live host environment
                // and the static output callback throughout lazy startup.
                let facts = unsafe { crate::__crabc_runtime::NativeProcessStartupFacts::new(
                    4096, crate::runtime_lifecycle::test_host_process_environment,
                    crate::__crabc_runtime::RuntimeStderrOutput::new(discard),
                ) }.unwrap();
                assert!(crate::__crabc_runtime::publish_native_process_startup_facts(facts));
                let cold = crate::compiler_tls::default_theap();
                // SAFETY: this is the immutable empty compiler-TLS image.
                assert!(unsafe { crate::types::Theap::heap_at(cold) }.is_null());
                let first = super::malloc_aligned_at(81, 64, 0).value.unwrap();
                let second = super::malloc_aligned_at(81, 64, 0).value.unwrap();
                let permission = |address| {
                    std::fs::read_to_string("/proc/self/maps").unwrap().lines().find_map(|line| {
                        let mut fields = line.split_whitespace();
                        let (start, end) = fields.next()?.split_once('-')?;
                        let start = usize::from_str_radix(start, 16).ok()?;
                        let end = usize::from_str_radix(end, 16).ok()?;
                        (start <= address && address < end).then(|| std::string::String::from(fields.next().unwrap()))
                    }).unwrap()
                };
                // SAFETY: both successful public clients remain exclusively
                // owned through usable-size observations and terminal frees.
                unsafe {
                    let first_tail = first.as_ptr().addr() + super::usable_size(first.as_ptr());
                    let second_tail = second.as_ptr().addr() + super::usable_size(second.as_ptr());
                    assert!(permission(first_tail).starts_with("rw"),
                        "the empty source Theap cannot sample its initializing allocation");
                    assert!(permission(second_tail).starts_with("---"),
                        "the initialized source Theap samples the following allocation");
                    assert_eq!(super::free(first.as_ptr()), super::FreeOutcome::Freed);
                    assert_eq!(super::free(second.as_ptr()), super::FreeOutcome::Freed);
                }
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-guarded", not(miri)))]
    #[test]
    fn sampled_guarded_aligned_refusal_precedes_ordinary_size_validation() {
        crate::test_process::run_in_fresh_process(
            "source_api::tests::sampled_guarded_aligned_refusal_precedes_ordinary_size_validation",
            || {
                unsafe extern "C" fn discard(_: *const core::ffi::c_char) {}
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(
                    4096, unsafe { crate::__crabc_runtime::RuntimeStderrOutput::new(discard) },
                ));
                assert!(crate::__crabc_runtime::prepare_native_initial_thread_owner());
                let selected = crate::source_heap_api::theap_get_default();
                assert!(!selected.is_null());
                // SAFETY: this fresh-process thread exclusively retains its
                // initialized Theap and sampler throughout these public calls.
                unsafe {
                    crate::source_heap_api::theap_guarded_set_size_bound(selected, 0, usize::MAX);
                    crate::source_heap_api::theap_guarded_set_sample_rate(selected, 1, 0);
                }
                let sampled = super::malloc_aligned_at(usize::MAX, 64, 0);
                assert!(sampled.value.is_none());
                assert_eq!(sampled.errno.apply(0), Errno::NOMEM.raw(),
                    "a sampled guarded overflow must not fall through to ordinary EINVAL");
                assert_eq!(sampled.errno.apply(29), 29);
                let invalid = super::malloc_aligned_at(usize::MAX, 3, 0);
                assert!(invalid.value.is_none());
                assert_eq!(invalid.errno.apply(0), Errno::INVAL.raw(),
                    "alignment validity precedes the guarded sampler");
                let offset = super::malloc_aligned_at(usize::MAX, 64, 1);
                assert!(offset.value.is_none());
                assert_eq!(offset.errno.apply(0), Errno::INVAL.raw(),
                    "offset allocation excludes guarded sampling");
            },
        );
    }

    #[cfg(all(feature = "mi-xmalloc", target_arch = "x86_64"))]
    #[test]
    fn xmalloc_oversized_allocation_aborts_in_a_fresh_process() {
        use std::os::unix::process::ExitStatusExt;
        const CHILD: &str = "CRABC_MI_XMALLOC_ALLOCATION_CHILD";
        const TEST: &str = "source_api::tests::xmalloc_oversized_allocation_aborts_in_a_fresh_process";
        if std::env::var_os(CHILD).is_some() {
            unsafe extern "C" fn discard(_: *const core::ffi::c_char) {}
            assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(
                4096, unsafe { crate::__crabc_runtime::RuntimeStderrOutput::new(discard) },
            ));
            std::println!("xmalloc.allocation.entered");
            let failed = super::malloc(usize::MAX);
            assert!(failed.value.is_none());
            std::process::exit(0);
        }
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([TEST, "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .output().expect("run isolated oversized allocation");
        let stdout = std::string::String::from_utf8_lossy(&child.stdout);
        assert!(stdout.contains("xmalloc.allocation.entered"), "{stdout}");
        assert_eq!(child.status.signal(), Some(6), "child status {:?}, stderr {:?}",
            child.status, std::string::String::from_utf8_lossy(&child.stderr));
    }

    #[cfg(all(feature = "mi-xmalloc", target_arch = "x86_64"))]
    #[test]
    fn xmalloc_registered_handler_and_release_count_overflow_return() {
        crate::test_process::run_in_fresh_process(
            "source_api::tests::xmalloc_registered_handler_and_release_count_overflow_return",
            || {
                unsafe extern "C" fn discard(_: *const core::ffi::c_char) {}
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(
                    4096, unsafe { crate::__crabc_runtime::RuntimeStderrOutput::new(discard) },
                ));
                unsafe extern "C" fn observe(code: core::ffi::c_int, argument: *mut core::ffi::c_void) {
                    // SAFETY: the synchronous test retains this atomic until
                    // the allocation report and callback have returned.
                    let seen = unsafe { &*argument.cast::<core::sync::atomic::AtomicI32>() };
                    seen.store(code, core::sync::atomic::Ordering::Relaxed);
                }
                let seen = core::sync::atomic::AtomicI32::new(0);
                // SAFETY: the callback's one context outlives this report.
                unsafe { crate::source_options_api::register_error(Some(observe),
                    core::ptr::from_ref(&seen).cast_mut().cast()) };
                let failed = super::malloc(usize::MAX);
                assert!(failed.value.is_none());
                assert_eq!(seen.load(core::sync::atomic::Ordering::Relaxed), Errno::NOMEM.raw());
                assert_eq!(failed.errno.apply(0), 0);
                unsafe { crate::source_options_api::register_error(None, core::ptr::null_mut()) };
                #[cfg(not(feature = "mi-debug-1"))]
                {
                    // The release source does not report multiplication
                    // overflow, so the default error handler never runs.
                    let failed = super::calloc(usize::MAX, 2);
                    assert!(failed.value.is_none());
                    assert_eq!(failed.errno, super::SourceErrno::Unchanged);
                }
                let live = super::malloc(64).value.expect("valid allocation after handled failure");
                assert_eq!(unsafe { super::free(live.as_ptr()) }, super::FreeOutcome::Freed);
            },
        );
    }

    #[cfg(feature = "mi-debug-1")]
    #[test]
    fn debug_unaligned_client_validation_preserves_live_contract_and_domain_refusal() {
        crate::test_process::run_in_fresh_process(
            "source_api::tests::debug_unaligned_client_validation_preserves_live_contract_and_domain_refusal",
            || {
                unsafe extern "C" fn discard(_: *const core::ffi::c_char) {}
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(
                    4096, unsafe { crate::__crabc_runtime::RuntimeStderrOutput::new(discard) },
                ));
                let original = super::zalloc_aligned_at(64, 8, 7).value.unwrap();
                assert_eq!(original.as_ptr().addr() & 7, 1);
                // SAFETY: this fixture exclusively owns the exact successful
                // aligned-offset client, including every replacement below.
                unsafe {
                    original.as_ptr().write_bytes(0xa7, 64);
                    let size = super::usable_size_sourced(original.as_ptr());
                    assert_eq!(size.value, 70);
                    assert_eq!(size.errno.apply(0), 0);
                    let failed = super::rezalloc(original.as_ptr(), usize::MAX);
                    assert!(failed.value.is_none());
                    assert!(core::slice::from_raw_parts(original.as_ptr(), 64).iter().all(|byte| *byte == 0xa7));
                    let replacement = super::rezalloc_aligned_at(original.as_ptr(), 200, 16, 0);
                    assert_eq!(replacement.errno.apply(0), 0);
                    let replacement = replacement.value.unwrap();
                    assert!(core::slice::from_raw_parts(replacement.as_ptr(), 64).iter().all(|byte| *byte == 0xa7));
                    assert!(core::slice::from_raw_parts(replacement.as_ptr().add(64), 136).iter().all(|byte| *byte == 0));
                    assert_eq!(super::free(replacement.as_ptr()), super::FreeOutcome::Freed);
                }
                let outside_domain = core::ptr::without_provenance_mut::<u8>(1);
                // SAFETY: this low address is unregistered throughout this
                // fresh process and is never dereferenced by the refusal.
                let refused = unsafe { super::free_sourced(outside_domain) };
                assert_eq!(refused.value, super::FreeOutcome::RejectedCorruption);
                assert_eq!(refused.errno.apply(0), Errno::INVAL.raw());
                assert_eq!(refused.errno.apply(29), 29);
            },
        );
    }

    #[cfg(feature = "mi-debug-1")]
    #[test]
    fn count_overflow_keeps_handled_disposition_after_callback_unregistration() {
        crate::test_process::run_in_fresh_process(
            "source_api::tests::count_overflow_keeps_handled_disposition_after_callback_unregistration",
            || {
                unsafe extern "C" fn discard(_: *const core::ffi::c_char) {}
                unsafe extern "C" fn unregister(error: core::ffi::c_int, argument: *mut core::ffi::c_void) {
                    // SAFETY: the synchronous fixture retains this one
                    // atomic context until the error delivery returns.
                    let observed = unsafe { &*argument.cast::<core::sync::atomic::AtomicUsize>() };
                    observed.store(error as usize, core::sync::atomic::Ordering::Relaxed);
                    unsafe { crate::source_options_api::register_error(None, core::ptr::null_mut()) };
                }
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(
                    4096, unsafe { crate::__crabc_runtime::RuntimeStderrOutput::new(discard) },
                ));
                let observed = core::sync::atomic::AtomicUsize::new(0);
                // SAFETY: this callback and its context remain live through
                // the synchronous report; it clears its own registration.
                unsafe { crate::source_options_api::register_error(Some(unregister), core::ptr::from_ref(&observed).cast_mut().cast()) };
                let effect = super::count_size_overflow_errno(usize::MAX, 2);
                assert_eq!(observed.load(core::sync::atomic::Ordering::Relaxed), Errno::OVERFLOW.raw() as usize);
                assert_eq!(effect, super::SourceErrno::Unchanged);
                assert_eq!(effect.apply(0), 0);
            },
        );
    }

    #[test]
    fn switched_default_aligned_allocation_keeps_selected_heap() {
        crate::test_process::run_in_fresh_process(
            "source_api::tests::switched_default_aligned_allocation_keeps_selected_heap",
            || {
                unsafe extern "C" fn discard(_: *const core::ffi::c_char) {}
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(
                    4096, unsafe { crate::__crabc_runtime::RuntimeStderrOutput::new(discard) },
                ));
                let heap = crate::source_heap_api::heap_new();
                assert!(!heap.is_null());
                // SAFETY: the fresh process retains this Heap and its TLD.
                let selected = unsafe { crate::source_heap_api::heap_theap(heap) };
                let base = crate::source_heap_api::theap_get_default();
                unsafe { crate::source_heap_api::theap_set_default(selected) };
                let block = super::zalloc_aligned(73, 4096).value.expect("aligned allocation");
                assert_eq!(unsafe { crate::source_heap_api::heap_of(block.as_ptr()) }, heap);
                assert_eq!(crate::source_heap_api::theap_get_default(), selected);
                assert!(unsafe { core::slice::from_raw_parts(block.as_ptr(), 73) }.iter().all(|byte| *byte == 0));
                unsafe {
                    super::free(block.as_ptr());
                    crate::source_heap_api::theap_set_default(base);
                    crate::source_heap_api::heap_release(heap, true);
                }
            },
        );
    }

    #[test]
    fn switched_default_reallocation_keeps_selected_heap() {
        crate::test_process::run_in_fresh_process(
            "source_api::tests::switched_default_reallocation_keeps_selected_heap",
            || {
                unsafe extern "C" fn discard(_: *const core::ffi::c_char) {}
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(
                    4096, unsafe { crate::__crabc_runtime::RuntimeStderrOutput::new(discard) },
                ));
                let heap = crate::source_heap_api::heap_new();
                let selected = unsafe { crate::source_heap_api::heap_theap(heap) };
                let base = crate::source_heap_api::theap_get_default();
                // SAFETY: the fresh process retains the Heap, Theap and TLD.
                unsafe { crate::source_heap_api::theap_set_default(selected) };
                let block = super::zalloc(48).value.expect("selected allocation");
                let grown = unsafe { super::rezalloc(block.as_ptr(), 8192) }.value.expect("selected growth");
                assert_eq!(unsafe { crate::source_heap_api::heap_of(grown.as_ptr()) }, heap);
                assert!(unsafe { core::slice::from_raw_parts(grown.as_ptr(), 8192) }.iter().all(|byte| *byte == 0));
                assert_eq!(crate::source_heap_api::theap_get_default(), selected);
                unsafe {
                    super::free(grown.as_ptr());
                    crate::source_heap_api::theap_set_default(base);
                    crate::source_heap_api::heap_release(heap, true);
                }
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-secure-3", not(feature = "mi-debug-1")))]
    #[test]
    fn secure_selected_default_aligned_rezalloc_preserves_zero_client_extent() {
        crate::test_process::run_in_fresh_process(
            "source_api::tests::secure_selected_default_aligned_rezalloc_preserves_zero_client_extent",
            || {
                unsafe extern "C" fn discard(_: *const core::ffi::c_char) {}
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(
                    4096, unsafe { crate::__crabc_runtime::RuntimeStderrOutput::new(discard) },
                ));
                let heap = crate::source_heap_api::heap_new();
                assert!(!heap.is_null());
                let selected = unsafe { crate::source_heap_api::heap_theap(heap) };
                let base = crate::source_heap_api::theap_get_default();
                // SAFETY: this fresh-process thread retains the actual Heap,
                // selected member and every exact client through restoration.
                unsafe {
                    crate::source_heap_api::theap_set_default(selected);
                    let old = super::zalloc_aligned(81, 4096).value.expect("selected zero aligned client");
                    assert!(core::slice::from_raw_parts(old.as_ptr(), 81).iter().all(|byte| *byte == 0));
                    let grown = super::rezalloc_aligned(old.as_ptr(), 8192, 4096)
                        .value.expect("selected aligned growth");
                    assert_eq!(crate::source_heap_api::heap_of(grown.as_ptr()), heap);
                    assert_eq!(grown.as_ptr().addr() % 4096, 0);
                    assert!(core::slice::from_raw_parts(grown.as_ptr(), 8192).iter().all(|byte| *byte == 0),
                        "old zero client plus expanded client must remain zero");
                    assert_eq!(crate::source_heap_api::theap_get_default(), selected);
                    assert_eq!(super::free(grown.as_ptr()), super::FreeOutcome::Freed);
                    crate::source_heap_api::theap_set_default(base);
                    assert!(crate::source_heap_api::heap_release(heap, false));
                }
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-secure-3", not(feature = "mi-debug-1")))]
    #[test]
    fn secure_selected_theap_rezalloc_preserves_full_reported_usable_client() {
        crate::test_process::run_in_fresh_process(
            "source_api::tests::secure_selected_theap_rezalloc_preserves_full_reported_usable_client",
            || {
                unsafe extern "C" fn discard(_: *const core::ffi::c_char) {}
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(
                    4096, unsafe { crate::__crabc_runtime::RuntimeStderrOutput::new(discard) },
                ));
                let heap = crate::source_heap_api::heap_new();
                assert!(!heap.is_null());
                let selected = unsafe { crate::source_heap_api::heap_theap(heap) };
                // SAFETY: this fresh-process thread retains the actual Heap
                // and selected member, and exclusively owns each exact client.
                unsafe {
                    // The small C entry forwards this same Theap allocation.
                    let old = crate::source_heap_api::theap_malloc(selected, 128, false)
                        .value.expect("selected small client");
                    old.as_ptr().write_bytes(0x6b, 128);
                    let reused = super::theap_realloc(selected, old.as_ptr(), 96, false)
                        .value.expect("source reuse");
                    assert_eq!(reused, old);
                    let old_usable = super::usable_size(reused.as_ptr());
                    // Bound every subsequent write and slice by the actual
                    // public extent, and exclude subtraction underflow.
                    assert!((128..=512).contains(&old_usable));
                    std::println!("secure.selected.old_usable={old_usable}");
                    reused.as_ptr().write_bytes(0x6b, old_usable);
                    let grown = super::theap_realloc(selected, reused.as_ptr(), 512, true)
                        .value.expect("selected zero growth after full usable write");
                    assert_eq!(crate::source_heap_api::heap_of(grown.as_ptr()), heap);
                    assert!(core::slice::from_raw_parts(grown.as_ptr(), old_usable).iter().all(|byte| *byte == 0x6b));
                    assert!(core::slice::from_raw_parts(grown.as_ptr().add(old_usable), 512 - old_usable)
                        .iter().all(|byte| *byte == 0));
                    assert_eq!(super::free(grown.as_ptr()), super::FreeOutcome::Freed);
                    assert!(crate::source_heap_api::heap_release(heap, false));
                }
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-secure-3", not(miri)))]
    fn initialize_secure_source_after_joined_worker() -> *mut core::ffi::c_void {
        unsafe extern "C" fn discard(_: *const core::ffi::c_char) {}
        assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(
            4096, unsafe { crate::__crabc_runtime::RuntimeStderrOutput::new(discard) },
        ));
        assert!(crate::__crabc_runtime::prepare_native_initial_thread_owner());
        let base = crate::source_heap_api::theap_get_default();
        assert!(!base.is_null());
        let main = super::malloc(64).value.expect("initial source client");
        // SAFETY: this thread owns the exact successful source client.
        assert_eq!(unsafe { super::free(main.as_ptr()) }, super::FreeOutcome::Freed);
        std::thread::spawn(|| {
            let descriptor = crate::__crabc_runtime::current_native_allocator_thread_descriptor();
            // SAFETY: this real worker retains its compiler-TLS descriptor
            // through attachment, all source calls and its explicit finish.
            assert!(unsafe { crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(descriptor) });
            assert_eq!(crate::__crabc_runtime::attach_current_thread(), crate::__crabc_runtime::ThreadAttachResult::Attached);
            let heap = crate::source_heap_api::heap_new();
            assert!(!heap.is_null());
            // SAFETY: this worker retains the actual Heap and owns its client
            // until the one terminal free, before releasing its empty Heap.
            unsafe {
                assert!(!crate::source_heap_api::heap_theap(heap).is_null());
                let client = crate::source_heap_api::heap_malloc(heap, 64).value.expect("worker source client");
                client.as_ptr().write_bytes(0x47, 64);
                assert_eq!(super::free(client.as_ptr()), super::FreeOutcome::Freed);
                assert!(crate::source_heap_api::heap_release(heap, false));
            }
            assert_eq!(crate::__crabc_runtime::finish_current_thread_native_after_user_destructors(),
                crate::__crabc_runtime::ThreadFinishResult::Finished);
        }).join().expect("the real source worker finishes before the next Heap creation");
        assert_eq!(crate::source_heap_api::theap_get_default(), base);
        base
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-secure-3", not(miri)))]
    #[test]
    fn joined_secure_source_worker_preserves_public_auxiliary_heap_creation() {
        crate::test_process::run_in_fresh_process(
            "source_api::tests::joined_secure_source_worker_preserves_public_auxiliary_heap_creation",
            || {
                let base = initialize_secure_source_after_joined_worker();
                let heap = crate::source_heap_api::heap_new();
                assert!(!heap.is_null(), "joined-worker parent creates a source Heap");
                // SAFETY: this thread retains the actual new Heap and its
                // member through public allocation, free and terminal delete.
                unsafe {
                    let other = crate::source_heap_api::heap_theap(heap);
                    assert!(!other.is_null());
                    assert_ne!(other, base);
                    let client = crate::source_heap_api::heap_malloc(heap, 64).value.expect("post-worker source client");
                    assert_eq!(super::free(client.as_ptr()), super::FreeOutcome::Freed);
                    assert!(crate::source_heap_api::heap_release(heap, false));
                }
                assert_eq!(crate::source_heap_api::theap_get_default(), base);
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-secure-3", not(miri)))]
    #[test]
    fn ordinary_fork_after_joined_secure_source_worker_preserves_auxiliary_heap_creation() {
        crate::test_process::run_in_fresh_process(
            "source_api::tests::ordinary_fork_after_joined_secure_source_worker_preserves_auxiliary_heap_creation",
            || {
                unsafe extern "C" { fn fork() -> core::ffi::c_int; }
                let base = initialize_secure_source_after_joined_worker();
                // SAFETY: call ordinary linked libc fork after the worker
                // joined. No allocator fork callbacks are registered here:
                // the standalone source adapter has no such registrations.
                let pid = unsafe { fork() };
                assert!(pid >= 0);
                if pid == 0 {
                    let main = crate::source_heap_api::heap_main();
                    let child_base = crate::source_heap_api::theap_get_default();
                    if main.is_null() || child_base.is_null() { crabc_core::process::exit_immediately(20); }
                    let heap = crate::source_heap_api::heap_new();
                    if heap.is_null() { crabc_core::process::exit_immediately(21); }
                    // SAFETY: the single child thread retains this newly
                    // created Heap and exclusively owns its successful client.
                    unsafe {
                        if crate::source_heap_api::heap_theap(heap).is_null() { crabc_core::process::exit_immediately(22); }
                        let Some(client) = crate::source_heap_api::heap_malloc(heap, 64).value
                            else { crabc_core::process::exit_immediately(23); };
                        client.as_ptr().write_bytes(0x61, 64);
                        if super::free(client.as_ptr()) != super::FreeOutcome::Freed {
                            crabc_core::process::exit_immediately(24);
                        }
                        if !crate::source_heap_api::heap_release(heap, false) { crabc_core::process::exit_immediately(25); }
                    }
                    crabc_core::process::exit_immediately(0);
                }
                let mut status = 0;
                let mut joined = false;
                for _ in 0..500 {
                    // SAFETY: this parent owns the status slot and exact child.
                    let waited = unsafe { crabc_core::process::wait4_raw(pid, &mut status, 1) }.unwrap();
                    if waited == pid { joined = true; break; }
                    assert_eq!(waited, 0);
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                if !joined {
                    let _ = crabc_core::process::kill(pid, 9);
                    // SAFETY: reap the same timed-out child before failure.
                    let _ = unsafe { crabc_core::process::wait4_raw(pid, &mut status, 0) };
                }
                assert!(joined, "ordinary fork child must complete its source Heap calls");
                assert_eq!(status, 0, "ordinary fork child completion status {status}");
                assert_eq!(crate::source_heap_api::theap_get_default(), base);
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn selected_theap_realloc_keeps_replacement_when_consumed_old_mapping_is_retained() {
        crate::test_process::run_in_fresh_process(
            "source_api::tests::selected_theap_realloc_keeps_replacement_when_consumed_old_mapping_is_retained",
            || {
                unsafe extern "C" fn discard(_: *const core::ffi::c_char) {}
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(
                    4096, unsafe { crate::__crabc_runtime::RuntimeStderrOutput::new(discard) },
                ));
                let heap = crate::source_heap_api::heap_new();
                assert!(!heap.is_null());
                let selected = unsafe { crate::source_heap_api::heap_theap(heap) };
                let (binding, _) = crate::process_init::ProcessMainInitializationStorage::global()
                    .ready_child_subprocess_inputs().unwrap();
                let root = binding.page_map();
                // SAFETY: this fresh-process thread retains the actual Heap
                // and member, owns each exact client, and excludes teardown.
                let (warm, old, new_size) = unsafe {
                    let old = super::theap_malloc_aligned_at(selected, 17, 128 * 1024, 0, false)
                        .value.expect("separate OS-aligned source client");
                    let old_usable = super::usable_size(old.as_ptr());
                    let new_size = old_usable.checked_add(1).unwrap().max(512);
                    std::println!("realloc.old_usable={old_usable},new_size={new_size}");
                    let warm = crate::source_heap_api::theap_malloc(selected, new_size, false)
                        .value.expect("live ordinary page warms replacement allocation");
                    warm.as_ptr().write_bytes(0x63, new_size);
                    old.as_ptr().write_bytes(0xa7, 17);
                    (warm, old, new_size)
                };
                let fault = crate::os::fault::install(crate::os::fault::Plan::at(
                    crate::os::fault::Point::Unmap, 1, Errno::NOMEM));
                let unmaps = fault.capture_unmap_ranges();
                // SAFETY: the exact old client belongs to this retained Theap.
                // The live ordinary page supplies the fresh replacement; the
                // first selected unmap must therefore be old-client cleanup.
                let result = unsafe { super::theap_realloc(selected, old.as_ptr(), new_size, false) };
                let replacement = result.value.expect("old mapping retention must not erase the replacement");
                assert_eq!(result.errno, super::SourceErrno::Unchanged);
                assert_ne!(replacement, old);
                // SAFETY: the successful returned client and warm client are
                // still owned. No old-client access or repeated free follows.
                unsafe {
                    assert!(core::slice::from_raw_parts(replacement.as_ptr(), 17).iter().all(|byte| *byte == 0xa7));
                    assert!(core::slice::from_raw_parts(warm.as_ptr(), new_size).iter().all(|byte| *byte == 0x63));
                }
                let (ranges, count) = unmaps.all().expect("bounded actual unmap trace");
                assert_eq!(count, 1, "replacement must use its warmed ordinary page");
                let (address, length) = ranges[0];
                let end = address.checked_add(length).unwrap();
                assert!(address <= old.as_ptr().addr() && old.as_ptr().addr() < end,
                    "the fault must select the actual old-client mapping");
                assert!(replacement.as_ptr().addr() < address || replacement.as_ptr().addr() >= end);
                let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
                let mut mapped_until = address;
                for line in maps.lines() {
                    let Some(range) = line.split_whitespace().next() else { continue };
                    let Some((start, stop)) = range.split_once('-') else { continue };
                    let (Ok(start), Ok(stop)) = (usize::from_str_radix(start, 16), usize::from_str_radix(stop, 16))
                        else { continue };
                    if start <= mapped_until && mapped_until < stop {
                        mapped_until = stop;
                    }
                    if mapped_until >= end { break; }
                }
                assert!(mapped_until >= end, "refused unmap must retain the entire original backing");
                let map = root.test_retained_page_map().expect("the actual process retains its map");
                // SAFETY: these are address-only map observations after the
                // synchronous release ended. The isolated thread excludes
                // overlapping registration and never dereferences old metadata.
                unsafe {
                    assert!(map.checked_lookup(old.as_ptr()).is_null(),
                        "old client consumption must be distinct from retained backing");
                    assert!(!map.checked_lookup(replacement.as_ptr()).is_null(),
                        "the returned replacement keeps its registered source page");
                }
                std::println!("realloc.cleanup=old-consumed,mapping-retained,replacement-owned");
                drop(unmaps);
                fault.set(crate::os::fault::Plan::disabled());
                // The fixture ends with the replacement and warm client still
                // owned by this retained process. Retention is not authority to
                // retry the consumed old client or destroy the terminal Heap.
            },
        );
    }

    #[test]
    fn direct_theap_variants_preserve_roots_and_reallocation_lifetime() {
        crate::test_process::run_in_fresh_process(
            "source_api::tests::direct_theap_variants_preserve_roots_and_reallocation_lifetime",
            || {
                unsafe extern "C" fn discard(_: *const core::ffi::c_char) {}
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(
                    4096, unsafe { crate::__crabc_runtime::RuntimeStderrOutput::new(discard) },
                ));
                let heap = crate::source_heap_api::heap_new();
                let selected = unsafe { crate::source_heap_api::heap_theap(heap) };
                let base = crate::source_heap_api::theap_get_default();
                let first = unsafe { crate::source_heap_api::theap_malloc(selected, 128, false) }
                    .value.expect("the exact Theap has a warmed page");
                let cached = crate::compiler_tls::cached_theap();
                // SAFETY: every raw client is held exclusively until its
                // successful reallocation or its one terminal free.
                unsafe {
                    first.as_ptr().write_bytes(0x63, 128);
                    let reused = super::theap_realloc(selected, first.as_ptr(), 96, false).value.unwrap();
                    assert_eq!(reused, first);
                    let zero = super::theap_calloc(selected, 3, 41).value.unwrap();
                    assert!(core::slice::from_raw_parts(zero.as_ptr(), 123).iter().all(|byte| *byte == 0));
                    assert_eq!(crate::compiler_tls::cached_theap(), cached);
                    assert_eq!(crate::source_heap_api::theap_get_default(), base);
                    assert!(super::theap_calloc(selected, usize::MAX, 2).value.is_none());
                    let refusal = super::theap_realloc(selected, reused.as_ptr(), usize::MAX, false);
                    assert!(refusal.value.is_none());
                    assert_eq!(refusal.errno.apply(91), 91);
                    assert_eq!(reused.as_ptr().read(), 0x63);
                    let grown = super::theap_realloc(selected, reused.as_ptr(), 512, true).value.unwrap();
                    assert_eq!(grown.as_ptr().read(), 0x63);
                    assert!(core::slice::from_raw_parts(grown.as_ptr().add(128), 384).iter().all(|byte| *byte == 0));
                    assert_eq!(crate::source_heap_api::heap_of(grown.as_ptr()), heap);
                    let moved = super::theap_realloc(base, grown.as_ptr(), 384, false).value.unwrap();
                    assert_ne!(moved, grown);
                    assert_eq!(crate::source_heap_api::heap_of(moved.as_ptr()), crate::source_heap_api::heap_main());
                    let aligned = super::theap_malloc_aligned_at(selected, 73, 4096, 0, true).value.unwrap();
                    assert_eq!(aligned.as_ptr().addr() % 4096, 0);
                    assert!(core::slice::from_raw_parts(aligned.as_ptr(), 73).iter().all(|byte| *byte == 0));
                    assert_eq!(crate::source_heap_api::heap_of(aligned.as_ptr()), heap);
                    super::free(zero.as_ptr());
                    super::free(moved.as_ptr());
                    // Heap deletion moves a still-live exact-Theap block to
                    // the main Heap; its final free follows its page identity.
                    assert!(crate::source_heap_api::heap_release(heap, false));
                    assert_eq!(crate::source_heap_api::heap_of(aligned.as_ptr()), crate::source_heap_api::heap_main());
                    super::free(aligned.as_ptr());
                }
                assert_eq!(crate::source_heap_api::theap_get_default(), base);
            },
        );
    }

    #[test]
    fn errno_effects_compose_like_sequential_source_assignments() {
        let default = SourceErrno::DefaultIfZero(Errno::NOMEM);
        let store = SourceErrno::Store(Errno::OVERFLOW);
        for before in [0, 7] {
            for (first, second) in [
                (default, store),
                (store, default),
                (default, SourceErrno::DefaultIfZero(Errno::INVAL)),
                (SourceErrno::Unchanged, default),
                (store, SourceErrno::Unchanged),
            ] {
                assert_eq!(first.then(second).apply(before), second.apply(first.apply(before)));
            }
        }
    }
}
