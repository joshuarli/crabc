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
// These are the default-Theap public entry points of the selected release
// profile (`MI_DEBUG=0`, `MI_SECURE=0`, `MI_PADDING=0`, no guarded or
// override build) over the native runtime's allocation, free, reallocation,
// PageMap, and collection primitives. The engine owns no errno: each entry
// reports the errno effect the pinned source has on its path as data, and the
// C boundary applies it.

//! Pinned mimalloc default-Theap public allocation API over the native
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
const TRY_NEW_MAX: usize = 4;

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

/// `mi_calloc`: an overflowing product fails before any allocation and, in
/// release, without a message.
pub fn calloc(count: usize, size: usize) -> Sourced<Block> {
    match size_class::count_size(count, size) {
        Some(total) => malloc_zero(total, true),
        None => Sourced::quiet(None),
    }
}

/// `mi_mallocn`.
pub fn mallocn(count: usize, size: usize) -> Sourced<Block> {
    match size_class::count_size(count, size) {
        Some(total) => malloc_zero(total, false),
        None => Sourced::quiet(None),
    }
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
        None => Sourced::quiet((None, None)),
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
}

/// `mi_free`.
///
/// # Safety
///
/// `block` is null, unmapped by this allocator, or an exact live native
/// allocation that no other thread accesses during the call and that the
/// caller never uses again.
pub unsafe fn free(block: *mut u8) -> FreeOutcome {
    let Some(block) = NonNull::new(block) else {
        return FreeOutcome::Freed;
    };
    // SAFETY: forwarded from this function's contract.
    match unsafe { native_free(block) } {
        NativePageFreeResult::Freed => FreeOutcome::Freed,
        NativePageFreeResult::InvalidPointer => FreeOutcome::Unmapped,
        NativePageFreeResult::Unavailable | NativePageFreeResult::Retained => FreeOutcome::Retained,
    }
}

/// `mi_ufree`: frees `block` and reports its page block size, or 0 for a
/// null or unmapped pointer.
///
/// # Safety
///
/// The obligations of [`free`].
pub unsafe fn ufree(block: *mut u8) -> (FreeOutcome, usize) {
    // SAFETY: a live pointer stays live until the free below.
    let block_size = NonNull::new(block).and_then(|live| unsafe { native_block_size(live) }).unwrap_or(0);
    // SAFETY: forwarded from this function's contract.
    (unsafe { free(block) }, block_size)
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
    native_collect(force);
}

/// `mi_expand`: the unchanged pointer when `new_size` fits its usable
/// extent, else null. It never allocates, moves, or frees.
///
/// # Safety
///
/// `block` is null or an exact live native allocation.
pub unsafe fn expand(block: *mut u8, new_size: usize) -> Block {
    let block = NonNull::new(block)?;
    // SAFETY: forwarded exact-live-client contract.
    let usable = unsafe { usable_size(block.as_ptr()) };
    (new_size <= usable).then_some(block)
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
        None => Sourced::quiet(None),
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
        None => Sourced::quiet(None),
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
    // The native aligned entry reports these pre-allocation refusals through
    // `_mi_error_message` (`alloc-aligned.c:81-84,163-166,191-193`) and then
    // fails; the errno effect follows each report.
    let refusal = if !size_class::alignment_is_valid(alignment) || size > MAX_ALLOC_SIZE {
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
        None => Sourced::quiet(None),
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

/// `mi_theap_realloc_zero_aligned_at`.
unsafe fn realloc_zero_aligned_at(
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
        return unsafe { realloc_zero(block, new_size, zero) };
    }
    let Some(live) = NonNull::new(block) else {
        return malloc_zero_aligned_at(new_size, alignment, offset, zero);
    };
    if new_size > MAX_ALLOC_SIZE {
        // The replacement allocation refuses the size before any lookup.
        return Sourced::with(None, SourceErrno::error_message(Errno::INVAL));
    }
    // SAFETY: forwarded exact-live-client contract.
    match unsafe { native_reallocate_aligned_at(Some(live), new_size, alignment, offset, zero) } {
        NativePageAllocationResult::Allocated(block) => Sourced::quiet(Some(block)),
        NativePageAllocationResult::Unavailable => Sourced::quiet(None),
        NativePageAllocationResult::AllocationFailed | NativePageAllocationResult::Retained => {
            Sourced::with(None, aligned_failure_errno(new_size, alignment, offset))
        }
    }
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
        None => Sourced::quiet(None),
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
        None => Sourced::quiet(None),
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
        return Sourced::with(None, SourceErrno::Store(Errno::OVERFLOW));
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
        return Sourced::with((Errno::OVERFLOW.raw(), ReallocarrStore::Keep, FreeOutcome::Freed), SourceErrno::Store(Errno::OVERFLOW));
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
unsafe fn strnlen(text: *const c_char, max: usize) -> usize {
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
fn path_max(runtime: &impl SourceCRuntime) -> usize {
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
fn try_new_handler(runtime: &impl SourceCRuntime, nothrow: bool) -> (bool, SourceErrno) {
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
            let (_, errno) = try_new_handler(runtime, false);
            Sourced::with(None, errno)
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
            let (_, errno) = try_new_handler(runtime, false);
            Sourced::with(None, errno)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SourceErrno;
    use crabc_core::Errno;

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
