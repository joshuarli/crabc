// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0
// - `src/heap.c:149-157` (`mi_heap_new_in_arena`, `mi_heap_new`) and
//   `src/heap.c:228-261` (`mi_heap_delete`, `mi_heap_destroy`);
// - `src/subproc.c:113-115` (`mi_heap_main`);
// - `src/alloc.c:213-304,357-360` (`mi_heap_malloc_small`, `mi_heap_malloc`,
//   `mi_heap_zalloc_small`, `mi_heap_zalloc`, `mi_heap_calloc`,
//   `mi_heap_mallocn`) and `src/alloc-aligned.c:318-340` (the
//   `mi_heap_*_aligned[_at]` allocation entries);
// - `src/arena.c:1886-1922` (`mi_reserve_os_memory_ex2`,
//   `mi_reserve_os_memory_ex`, `mi_reserve_os_memory`).

//! Pinned mimalloc first-class Heap and OS-reservation public entries over
//! the native runtime.
//!
//! Each function is the source entry of the same `mi_` name. A Heap is the
//! source `mi_heap_t*`, passed as an opaque pointer. A calling thread of the
//! process main subprocess uses `subproc::main_heaps`; a thread admitted to a
//! child subprocess uses that child's Heap lifecycle, whose allocation is the
//! plain `mi_heap_malloc` form only. As in [`crate::source_api`], each
//! allocation reports the errno effect of its source path as data.
//!
//! Not provided: an exclusive-arena Heap (`mi_heap_new_in_arena` with an
//! arena), reservation from a thread of a child subprocess (refused with
//! `ENOMEM`), and the `_mi_verbose_message` reservation reports.

use core::ffi::{c_int, c_void};
use core::ptr::{null_mut, NonNull};

use crabc_core::Errno;

use crate::diagnostic_output::{SourceErrorReport, SourceFormattedMessage};
use crate::source_api::{Block, SourceErrno, Sourced};
use crate::subproc::main_heaps;
use crate::subproc::MainSubprocess;
use crate::types::heap_registry::lifecycle::HeapReleaseOutcome;
use crate::types::Heap;

/// `mi_heap_main()`: the calling thread's subprocess main Heap.
pub fn heap_main() -> *mut c_void {
    if crate::subproc::lifecycle::current_thread_is_child_member() {
        return crate::subproc::lifecycle::current_child_main_heap().map_or(null_mut(), |heap| heap.as_ptr().cast());
    }
    MainSubprocess::global().ready_main_heap_pointer().cast()
}

/// `mi_heap_new()`: null when the Heap cannot be created.
pub fn heap_new() -> *mut c_void {
    if let Some(created) = crate::subproc::lifecycle::native_child_heap_new() {
        return created.ok().and_then(Result::ok).map_or(null_mut(), |heap| heap.as_ptr().cast());
    }
    main_heaps::native_heap_new().map_or(null_mut(), |heap| heap.as_ptr().cast())
}

fn is_main_heap(heap: NonNull<Heap>) -> bool {
    core::ptr::eq(heap.as_ptr(), MainSubprocess::global().ready_main_heap_pointer())
}

/// The shape of one Heap allocation request.
#[derive(Clone, Copy)]
enum Request {
    Plain,
    Aligned { alignment: usize, offset: usize },
}

/// `_mi_heap_theap(heap)` then the Theap allocation of `request`.
///
/// # Safety
/// `heap` is null or a live Heap of the calling thread's subprocess.
unsafe fn heap_allocate(heap: *mut c_void, size: usize, request: Request, zero: bool) -> Sourced<Block> {
    let Some(heap) = NonNull::new(heap.cast::<Heap>()) else {
        return Sourced { value: None, errno: SourceErrno::Unchanged };
    };
    if is_main_heap(heap) {
        main_heaps::select_main_heap_theap();
        return match (request, zero) {
            (Request::Plain, false) => crate::source_api::malloc(size),
            (Request::Plain, true) => crate::source_api::zalloc(size),
            (Request::Aligned { alignment, offset }, false) => crate::source_api::malloc_aligned_at(size, alignment, offset),
            (Request::Aligned { alignment, offset }, true) => crate::source_api::zalloc_aligned_at(size, alignment, offset),
        };
    }
    if let Request::Aligned { alignment, offset } = request {
        // `mi_theap_malloc_zero_aligned_at`'s refusals before any Theap work.
        if let Some(report) = SourceErrorReport::aligned_precheck(size, alignment, offset) {
            let _ = crate::process_init::process_error_message(report);
            return Sourced { value: None, errno: SourceErrno::error_message(report.error()) };
        }
    }
    let block = if crate::subproc::lifecycle::current_thread_is_child_member() {
        match (request, zero) {
            // SAFETY: forwarded Heap contract.
            (Request::Plain, false) => unsafe { crate::subproc::lifecycle::native_child_heap_allocate(heap, size) }.flatten(),
            _ => None,
        }
    } else {
        let aligned = match request {
            Request::Plain => None,
            Request::Aligned { alignment, offset } => Some((alignment, offset)),
        };
        // SAFETY: forwarded Heap contract.
        unsafe { main_heaps::native_heap_allocate(heap, size, aligned, zero) }
    };
    if block.is_some() {
        return Sourced { value: block, errno: SourceErrno::Unchanged };
    }
    Sourced { value: None, errno: report_failure(size, request) }
}

/// The failed `_mi_malloc_generic`'s reports: `mi_find_page` refuses a
/// too-large request before and after its forced collection, then the
/// generic fallback reports out of memory.
fn report_failure(size: usize, request: Request) -> SourceErrno {
    let mut errno = SourceErrno::Unchanged;
    if matches!(request, Request::Plain) && size > crate::config::MAX_ALLOC_SIZE {
        for _ in 0..2 {
            let report = SourceErrorReport::AllocationTooLarge { size };
            let _ = crate::process_init::process_error_message(report);
            errno = errno.then(SourceErrno::error_message(report.error()));
        }
    }
    let report = SourceErrorReport::OutOfMemory { size };
    let _ = crate::process_init::process_error_message(report);
    errno.then(SourceErrno::error_message(Errno::NOMEM))
}

/// `mi_heap_malloc`.
///
/// # Safety
/// `heap` is null or a live Heap of the calling thread's subprocess.
pub unsafe fn heap_malloc(heap: *mut c_void, size: usize) -> Sourced<Block> {
    // SAFETY: forwarded.
    unsafe { heap_allocate(heap, size, Request::Plain, false) }
}

/// `mi_heap_zalloc`.
///
/// # Safety
/// As [`heap_malloc`].
pub unsafe fn heap_zalloc(heap: *mut c_void, size: usize) -> Sourced<Block> {
    // SAFETY: forwarded.
    unsafe { heap_allocate(heap, size, Request::Plain, true) }
}

/// `mi_heap_calloc`: an overflowing product fails before any allocation.
///
/// # Safety
/// As [`heap_malloc`].
pub unsafe fn heap_calloc(heap: *mut c_void, count: usize, size: usize) -> Sourced<Block> {
    match crate::size_class::count_size(count, size) {
        // SAFETY: forwarded.
        Some(total) => unsafe { heap_zalloc(heap, total) },
        None => Sourced { value: None, errno: SourceErrno::Unchanged },
    }
}

/// `mi_heap_mallocn`.
///
/// # Safety
/// As [`heap_malloc`].
pub unsafe fn heap_mallocn(heap: *mut c_void, count: usize, size: usize) -> Sourced<Block> {
    match crate::size_class::count_size(count, size) {
        // SAFETY: forwarded.
        Some(total) => unsafe { heap_malloc(heap, total) },
        None => Sourced { value: None, errno: SourceErrno::Unchanged },
    }
}

/// `mi_heap_malloc_aligned_at` and `mi_heap_zalloc_aligned_at`.
///
/// # Safety
/// As [`heap_malloc`].
pub unsafe fn heap_malloc_aligned_at(
    heap: *mut c_void,
    size: usize,
    alignment: usize,
    offset: usize,
    zero: bool,
) -> Sourced<Block> {
    // SAFETY: forwarded.
    unsafe { heap_allocate(heap, size, Request::Aligned { alignment, offset }, zero) }
}

/// `mi_heap_calloc_aligned_at`.
///
/// # Safety
/// As [`heap_malloc`].
pub unsafe fn heap_calloc_aligned_at(
    heap: *mut c_void,
    count: usize,
    size: usize,
    alignment: usize,
    offset: usize,
) -> Sourced<Block> {
    match crate::size_class::count_size(count, size) {
        // SAFETY: forwarded.
        Some(total) => unsafe { heap_malloc_aligned_at(heap, total, alignment, offset, true) },
        None => Sourced { value: None, errno: SourceErrno::Unchanged },
    }
}

/// `mi_heap_delete` or, with `destroy`, `mi_heap_destroy`. `false` when a
/// legal release could not complete (its owners are retained).
///
/// # Safety
/// `heap` is null or a live Heap of the calling thread's subprocess that no
/// other thread uses during the call; after a destroy no block of it is used
/// again.
pub unsafe fn heap_release(heap: *mut c_void, destroy: bool) -> bool {
    let Some(heap) = NonNull::new(heap.cast::<Heap>()) else { return true };
    // SAFETY: forwarded; the child route checks its own membership.
    if let Some(released) = unsafe { crate::subproc::lifecycle::native_child_heap_release(heap, destroy) } {
        return match released {
            Ok(Ok(HeapReleaseOutcome::MainHeapRefused)) => {
                warn_main_heap(destroy);
                true
            }
            Ok(Ok(_)) => true,
            _ => false,
        };
    }
    if is_main_heap(heap) {
        warn_main_heap(destroy);
        return true;
    }
    // SAFETY: forwarded.
    match unsafe { main_heaps::native_heap_release(heap, destroy) } {
        Ok(HeapReleaseOutcome::MainHeapRefused) => {
            warn_main_heap(destroy);
            true
        }
        Ok(_) => true,
        Err(_) => false,
    }
}

/// The `_mi_warning_message` of a main-Heap delete or destroy.
fn warn_main_heap(destroy: bool) {
    let message = if destroy { c"cannot destroy the main heap\n" } else { c"cannot delete the main heap\n" };
    if let Some(binding) = crate::process_init::ProcessMainInitializationStorage::global()
        .ready_child_subprocess_inputs()
        .map(|(binding, _)| binding)
    {
        binding.process().policy().source_warning(SourceFormattedMessage::from_source_formatted(message));
    }
}

/// `mi_reserve_os_memory_ex`: `0` or `ENOMEM`, writing the reserved arena's
/// id (or none) through `arena_id` when it is not null. The errno effect is
/// that of the failing step: a too-large report, or the failed `mmap` or
/// `munmap` code musl leaves in `errno`.
///
/// # Safety
/// `arena_id` is null or writable.
pub unsafe fn reserve_os_memory_ex(
    size: usize,
    commit: bool,
    allow_large: bool,
    exclusive: bool,
    arena_id: *mut *mut c_void,
) -> Sourced<c_int> {
    use crate::arena::ReserveOsMemoryFailure;
    if !arena_id.is_null() {
        // SAFETY: the caller's writable output.
        unsafe { arena_id.write(null_mut()) };
    }
    if crate::subproc::lifecycle::current_thread_is_child_member() {
        return Sourced { value: Errno::NOMEM.raw(), errno: SourceErrno::Unchanged };
    }
    match main_heaps::native_reserve_os_memory(size, commit, allow_large, exclusive) {
        Ok(id) => {
            if !arena_id.is_null() {
                // SAFETY: as above.
                unsafe { arena_id.write(id.as_ptr().cast()) };
            }
            Sourced { value: 0, errno: SourceErrno::Unchanged }
        }
        Err(failure) => Sourced {
            value: Errno::NOMEM.raw(),
            errno: match failure {
                ReserveOsMemoryFailure::TooLarge => SourceErrno::error_message(Errno::OVERFLOW),
                ReserveOsMemoryFailure::Os(error) => SourceErrno::Store(error),
                ReserveOsMemoryFailure::Unmanaged => SourceErrno::Unchanged,
            },
        },
    }
}

/// `mi_reserve_os_memory`.
pub fn reserve_os_memory(size: usize, commit: bool, allow_large: bool) -> Sourced<c_int> {
    // SAFETY: a null output is never written.
    unsafe { reserve_os_memory_ex(size, commit, allow_large, false, null_mut()) }
}

// ---------------------------------------------------------------------------
// Heap reallocation (`alloc.c:379-530`, `alloc-aligned.c:344-424`)
// ---------------------------------------------------------------------------

use crate::source_api::{FreeOutcome, SourceCRuntime};

const WORD: usize = core::mem::size_of::<usize>();

/// The Heap argument of a reallocation entry: the main Heap (handled by the
/// default-Theap entries, whose Theap is that Heap's), or a non-main Heap.
enum Target {
    Main,
    NonMain(NonNull<Heap>),
}

fn target(heap: *mut c_void) -> Option<Target> {
    let heap = NonNull::new(heap.cast::<Heap>())?;
    if is_main_heap(heap) {
        main_heaps::select_main_heap_theap();
        return Some(Target::Main);
    }
    Some(Target::NonMain(heap))
}

fn freed_with(result: Sourced<Block>) -> Sourced<(Block, FreeOutcome)> {
    Sourced { value: (result.value, FreeOutcome::Freed), errno: result.errno }
}

/// `mi_theap_realloc_zero_ex` through a non-main Heap's Theap. The block is
/// reused only when it fits with at most half waste and its page belongs to
/// that Heap; otherwise a block of the Heap replaces it (its expanded part
/// zeroed from the last copied word when `zero`) and the old block is freed.
///
/// # Safety
/// `block` is null or an exact live block no other thread uses; on a
/// non-null result it is consumed.
unsafe fn heap_realloc_zero(heap: NonNull<Heap>, block: *mut u8, new_size: usize, zero: bool) -> Sourced<(Block, FreeOutcome)> {
    let Some(live) = NonNull::new(block) else {
        // SAFETY: forwarded Heap contract.
        return freed_with(unsafe { heap_allocate(heap.as_ptr().cast(), new_size, Request::Plain, zero) });
    };
    // `mi_validate_ptr_page`: an unregistered pointer returns null.
    // SAFETY: forwarded live-block contract.
    let Some(page_heap) = (unsafe { main_heaps::heap_of_block(live) }) else {
        return Sourced { value: (None, FreeOutcome::Freed), errno: SourceErrno::Unchanged };
    };
    // SAFETY: as above.
    let size = unsafe { crate::source_api::usable_size(block) };
    if new_size <= size && new_size >= size / 2 && new_size > 0 && page_heap == heap {
        return Sourced { value: (Some(live), FreeOutcome::Freed), errno: SourceErrno::Unchanged };
    }
    // SAFETY: forwarded Heap contract.
    let result = unsafe { heap_allocate(heap.as_ptr().cast(), new_size, Request::Plain, false) };
    let Some(replacement) = result.value else { return freed_with(result) };
    let copy = new_size.min(size);
    let zero_start = (if copy >= WORD { copy - WORD } else { 0 }) & !(WORD - 1);
    // SAFETY: the fresh block is live and exclusively ours; `block` holds at
    // least `copy` usable bytes and does not overlap it.
    unsafe {
        let usable = crate::source_api::usable_size(replacement.as_ptr());
        if zero && usable > zero_start {
            replacement.as_ptr().add(zero_start).write_bytes(0, usable - zero_start);
        } else if new_size == 0 {
            replacement.as_ptr().write(0);
        }
        core::ptr::copy_nonoverlapping(block, replacement.as_ptr(), copy);
    }
    // SAFETY: the old block is freed once, after the copy.
    let freed = unsafe { crate::source_api::free(block) };
    Sourced { value: (Some(replacement), freed), errno: result.errno }
}

/// `mi_theap_realloc_zero_aligned_at` through a non-main Heap's Theap.
///
/// # Safety
/// As [`heap_realloc_zero`].
unsafe fn heap_realloc_zero_aligned_at(
    heap: NonNull<Heap>,
    block: *mut u8,
    new_size: usize,
    alignment: usize,
    offset: usize,
    zero: bool,
) -> Sourced<(Block, FreeOutcome)> {
    if !crate::size_class::alignment_is_valid(alignment) {
        let report = SourceErrorReport::BadAlignment { size: new_size, alignment, offset };
        let _ = crate::process_init::process_error_message(report);
        return Sourced { value: (None, FreeOutcome::Freed), errno: SourceErrno::error_message(report.error()) };
    }
    if alignment <= WORD && offset == 0 {
        // SAFETY: forwarded.
        return unsafe { heap_realloc_zero(heap, block, new_size, zero) };
    }
    if block.is_null() {
        // SAFETY: forwarded Heap contract.
        return freed_with(unsafe { heap_allocate(heap.as_ptr().cast(), new_size, Request::Aligned { alignment, offset }, zero) });
    }
    // SAFETY: forwarded live-block contract.
    let size = unsafe { crate::source_api::usable_size(block) };
    if new_size <= size && new_size >= size - size / 2 && (block.addr().wrapping_add(offset) & (alignment - 1)) == 0 {
        return Sourced { value: (NonNull::new(block), FreeOutcome::Freed), errno: SourceErrno::Unchanged };
    }
    // SAFETY: forwarded Heap contract.
    let result = unsafe { heap_allocate(heap.as_ptr().cast(), new_size, Request::Aligned { alignment, offset }, false) };
    let Some(replacement) = result.value else { return freed_with(result) };
    let copy = new_size.min(size);
    let zero_start = if copy >= WORD { copy - WORD } else { 0 };
    // SAFETY: as in `heap_realloc_zero`.
    unsafe {
        let usable = crate::source_api::usable_size(replacement.as_ptr());
        if zero && usable > zero_start {
            replacement.as_ptr().add(zero_start).write_bytes(0, usable - zero_start);
        }
        core::ptr::copy_nonoverlapping(block, replacement.as_ptr(), copy);
    }
    // SAFETY: the old block is freed once, after the copy.
    let freed = unsafe { crate::source_api::free(block) };
    Sourced { value: (Some(replacement), freed), errno: result.errno }
}

/// `mi_heap_realloc` or, with `zero`, `mi_heap_rezalloc`. The free outcome
/// is that of the replaced block.
///
/// # Safety
/// `heap` is null or a live Heap of the calling thread's subprocess; `block`
/// is null or an exact live block no other thread uses, consumed on a
/// non-null result.
pub unsafe fn heap_realloc(heap: *mut c_void, block: *mut u8, new_size: usize, zero: bool) -> Sourced<(Block, FreeOutcome)> {
    match target(heap) {
        None => Sourced { value: (None, FreeOutcome::Freed), errno: SourceErrno::Unchanged },
        // SAFETY: forwarded.
        Some(Target::Main) if zero => freed_with(unsafe { crate::source_api::rezalloc(block, new_size) }),
        // SAFETY: forwarded.
        Some(Target::Main) => freed_with(unsafe { crate::source_api::realloc(block, new_size) }),
        // SAFETY: forwarded.
        Some(Target::NonMain(heap)) => unsafe { heap_realloc_zero(heap, block, new_size, zero) },
    }
}

/// `mi_heap_reallocn` or, with `zero`, `mi_heap_recalloc`.
///
/// # Safety
/// As [`heap_realloc`].
pub unsafe fn heap_reallocn(heap: *mut c_void, block: *mut u8, count: usize, size: usize, zero: bool) -> Sourced<(Block, FreeOutcome)> {
    match crate::size_class::count_size(count, size) {
        // SAFETY: forwarded.
        Some(total) => unsafe { heap_realloc(heap, block, total, zero) },
        None => Sourced { value: (None, FreeOutcome::Freed), errno: SourceErrno::Unchanged },
    }
}

/// `mi_heap_reallocf`: `block` is freed when the reallocation fails.
///
/// # Safety
/// As [`heap_realloc`], except that `block` is consumed on every path.
pub unsafe fn heap_reallocf(heap: *mut c_void, block: *mut u8, new_size: usize) -> Sourced<(Block, FreeOutcome)> {
    // SAFETY: forwarded.
    let result = unsafe { heap_realloc(heap, block, new_size, false) };
    if result.value.0.is_none() && !block.is_null() {
        // SAFETY: the failed reallocation left `block` live.
        let freed = unsafe { crate::source_api::free(block) };
        return Sourced { value: (None, freed), errno: result.errno };
    }
    result
}

/// `mi_heap_realloc_aligned_at` and, with `zero`, `mi_heap_rezalloc_aligned_at`.
/// `offset: None` is the `_aligned` form, whose word-sized or smaller
/// alignment takes the ordinary kernel before any validation.
///
/// # Safety
/// As [`heap_realloc`].
pub unsafe fn heap_realloc_aligned(
    heap: *mut c_void,
    block: *mut u8,
    new_size: usize,
    alignment: usize,
    offset: Option<usize>,
    zero: bool,
) -> Sourced<(Block, FreeOutcome)> {
    if offset.is_none() && alignment <= WORD {
        // SAFETY: forwarded.
        return unsafe { heap_realloc(heap, block, new_size, zero) };
    }
    let offset = offset.unwrap_or(0);
    match target(heap) {
        None => Sourced { value: (None, FreeOutcome::Freed), errno: SourceErrno::Unchanged },
        // SAFETY: forwarded.
        Some(Target::Main) if zero => freed_with(unsafe { crate::source_api::rezalloc_aligned_at(block, new_size, alignment, offset) }),
        // SAFETY: forwarded.
        Some(Target::Main) => freed_with(unsafe { crate::source_api::realloc_aligned_at(block, new_size, alignment, offset) }),
        // SAFETY: forwarded.
        Some(Target::NonMain(heap)) => unsafe { heap_realloc_zero_aligned_at(heap, block, new_size, alignment, offset, zero) },
    }
}

/// `mi_heap_recalloc_aligned[_at]`.
///
/// # Safety
/// As [`heap_realloc`].
pub unsafe fn heap_recalloc_aligned(
    heap: *mut c_void,
    block: *mut u8,
    count: usize,
    size: usize,
    alignment: usize,
    offset: Option<usize>,
) -> Sourced<(Block, FreeOutcome)> {
    match crate::size_class::count_size(count, size) {
        // SAFETY: forwarded.
        Some(total) => unsafe { heap_realloc_aligned(heap, block, total, alignment, offset, true) },
        None => Sourced { value: (None, FreeOutcome::Freed), errno: SourceErrno::Unchanged },
    }
}

// ---------------------------------------------------------------------------
// Heap strings and `new` (`alloc.c:540-676,771-810`)
// ---------------------------------------------------------------------------

/// `mi_theap_strndup` after its length is known.
///
/// # Safety
/// `text` has `length` readable bytes; `heap` as for [`heap_malloc`].
unsafe fn heap_duplicate(heap: *mut c_void, text: *const core::ffi::c_char, length: usize) -> Sourced<Block> {
    if length > crate::config::MAX_ALLOC_SIZE - 1 {
        return Sourced { value: None, errno: SourceErrno::Unchanged };
    }
    // SAFETY: forwarded Heap contract.
    let result = unsafe { heap_malloc(heap, length + 1) };
    if let Some(copy) = result.value {
        // SAFETY: a fresh block of `length + 1` bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(text.cast::<u8>(), copy.as_ptr(), length);
            copy.as_ptr().add(length).write(0);
        }
    }
    result
}

/// `mi_heap_strdup`.
///
/// # Safety
/// `text` is null or NUL-terminated; `heap` as for [`heap_malloc`].
pub unsafe fn heap_strdup(heap: *mut c_void, text: *const core::ffi::c_char) -> Sourced<Block> {
    if text.is_null() {
        return Sourced { value: None, errno: SourceErrno::Unchanged };
    }
    // SAFETY: forwarded.
    unsafe { heap_duplicate(heap, text, crate::source_api::strnlen(text, usize::MAX)) }
}

/// `mi_heap_strndup`.
///
/// # Safety
/// `text` is null or readable up to its terminator or `max` bytes.
pub unsafe fn heap_strndup(heap: *mut c_void, text: *const core::ffi::c_char, max: usize) -> Sourced<Block> {
    if text.is_null() {
        return Sourced { value: None, errno: SourceErrno::Unchanged };
    }
    // SAFETY: forwarded.
    unsafe { heap_duplicate(heap, text, crate::source_api::strnlen(text, max)) }
}

/// `mi_heap_realpath`: the resolution buffer comes from the default Theap
/// (`mi_zalloc`), the result from the Heap.
///
/// # Safety
/// `name` is null or NUL-terminated; `resolved` is null or writable for the
/// system `PATH_MAX` bytes.
pub unsafe fn heap_realpath(
    runtime: &impl SourceCRuntime,
    heap: *mut c_void,
    name: *const core::ffi::c_char,
    resolved: *mut core::ffi::c_char,
) -> Sourced<*mut core::ffi::c_char> {
    if !resolved.is_null() {
        // SAFETY: forwarded.
        return Sourced { value: unsafe { runtime.realpath(name, resolved) }, errno: SourceErrno::Unchanged };
    }
    let limit = crate::source_api::path_max(runtime);
    let buffer = crate::source_api::zalloc(limit + 1);
    let Some(buffer) = buffer.value else {
        return Sourced { value: null_mut(), errno: buffer.errno.then(SourceErrno::Store(Errno::NOMEM)) };
    };
    // SAFETY: a fresh zeroed buffer of `limit + 1` bytes.
    let rname = unsafe { runtime.realpath(name, buffer.as_ptr().cast()) };
    // SAFETY: `rname` is null or the NUL-terminated result in `buffer`.
    let result = unsafe { heap_strndup(heap, rname, limit) };
    // SAFETY: this call's own buffer.
    let _ = unsafe { crate::source_api::free(buffer.as_ptr()) };
    Sourced { value: result.value.map_or(null_mut(), |copy| copy.as_ptr().cast()), errno: result.errno }
}

/// `mi_heap_alloc_new`: `mi_heap_malloc`, then `mi_theap_try_new`.
///
/// # Safety
/// As [`heap_malloc`].
pub unsafe fn heap_alloc_new(runtime: &impl SourceCRuntime, heap: *mut c_void, size: usize) -> Sourced<Block> {
    // SAFETY: forwarded.
    let first = unsafe { heap_malloc(heap, size) };
    if first.value.is_some() {
        return first;
    }
    let mut errno = first.errno;
    for _ in 0..crate::source_api::TRY_NEW_MAX {
        let (retry, effect) = crate::source_api::try_new_handler(runtime, false);
        errno = errno.then(effect);
        if !retry {
            break;
        }
        // The handler runs at least once before this size refusal.
        if size > crate::config::MAX_ALLOC_SIZE {
            return Sourced { value: None, errno };
        }
        // SAFETY: forwarded.
        let result = unsafe { heap_malloc(heap, size) };
        errno = errno.then(result.errno);
        if result.value.is_some() {
            return Sourced { value: result.value, errno };
        }
    }
    Sourced { value: None, errno }
}

/// `mi_heap_alloc_new_n`.
///
/// # Safety
/// As [`heap_malloc`].
pub unsafe fn heap_alloc_new_n(runtime: &impl SourceCRuntime, heap: *mut c_void, count: usize, size: usize) -> Sourced<Block> {
    match crate::size_class::count_size(count, size) {
        // SAFETY: forwarded.
        Some(total) => unsafe { heap_alloc_new(runtime, heap, total) },
        None => {
            let (_, errno) = crate::source_api::try_new_handler(runtime, false);
            Sourced { value: None, errno }
        }
    }
}

/// `mi_heap_collect(heap, force)`.
///
/// # Safety
/// `heap` is null or a live Heap of the calling thread's subprocess.
pub unsafe fn heap_collect(heap: *mut c_void, force: bool) {
    match target(heap) {
        Some(Target::Main) => crate::source_api::collect(force),
        // A child-subprocess thread's Theaps are collected at its finish.
        Some(Target::NonMain(_)) if crate::subproc::lifecycle::current_thread_is_child_member() => {}
        // SAFETY: forwarded.
        Some(Target::NonMain(heap)) => unsafe { main_heaps::native_heap_collect(heap, force) },
        None => {}
    }
}

// ---------------------------------------------------------------------------
// Subprocesses (`subproc.c:113-133,158-313`)
// ---------------------------------------------------------------------------

use crate::subproc::lifecycle::{NativeChildThreadAdd, NativeSubprocessId};

/// A Heap visitor (`mi_heap_visit_fun`).
pub type HeapVisitor = unsafe extern "C" fn(heap: *mut c_void, argument: *mut c_void) -> bool;

/// The outcome of `mi_subproc_add_current_thread`, for the embedding boundary
/// that binds threads to the runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubprocAddCurrentThread {
    /// The thread now belongs to the child and allocates from it.
    Added,
    /// Nothing changed (the thread was already initialized, or the id is
    /// null or the main subprocess).
    Unchanged,
    /// Admission failed; the thread is unchanged.
    Failed,
}

fn main_id() -> *mut c_void {
    MainSubprocess::global().identity().as_ptr().cast()
}

/// `mi_subproc_main()`.
pub fn subproc_main() -> *mut c_void {
    main_id()
}

/// `mi_subproc_current()`.
pub fn subproc_current() -> *mut c_void {
    crate::subproc::lifecycle::current_child_id().map_or_else(main_id, NativeSubprocessId::as_ptr)
}

/// `mi_subproc_new()`: null when the child cannot be created.
pub fn subproc_new() -> *mut c_void {
    crate::subproc::lifecycle::native_subproc_new().map_or(null_mut(), NativeSubprocessId::as_ptr)
}

/// `mi_subproc_destroy(id)`: the main subprocess and null are ignored; a
/// child that threads still belong to is destroyed under them. `false` when
/// a step retained the child.
///
/// # Safety
/// `id` is null, the main id, or a live child id from [`subproc_new`]; no
/// block of the child is used again, and a thread that still belongs to it
/// makes no allocator call afterwards other than its own thread finish.
pub unsafe fn subproc_destroy(id: *mut c_void) -> bool {
    let Some(pointer) = NonNull::new(id) else { return true };
    if pointer.as_ptr() == main_id() {
        return true;
    }
    // SAFETY: forwarded live-id contract.
    unsafe { crate::subproc::lifecycle::native_subproc_destroy(NativeSubprocessId::from_ptr(pointer)) }.is_ok()
}

/// The source warning of a thread that already belongs to another
/// subprocess (`subproc.c:292-294`).
fn warn_other_subprocess(other: *mut c_void) {
    let mut text = [0u8; 128];
    let prefix = b"unable to add thread to the subprocess as it was already in another subprocess (at 0x";
    let mut length = prefix.len();
    text[..length].copy_from_slice(prefix);
    // `%p` as `_mi_vsnprintf` renders it: uppercase, 8, 12, or 16 digits.
    let address = other.addr();
    let digits = if address <= u32::MAX as usize { 8 } else if address >> 16 <= u32::MAX as usize { 12 } else { 16 };
    for index in (0..digits).rev() {
        text[length] = b"0123456789ABCDEF"[(address >> (index * 4)) & 0xf];
        length += 1;
    }
    text[length] = b')';
    text[length + 1] = b'\n';
    let Ok(message) = core::ffi::CStr::from_bytes_until_nul(&text[..length + 3]) else { return };
    if let Some(binding) = crate::process_init::ProcessMainInitializationStorage::global()
        .ready_child_subprocess_inputs()
        .map(|(binding, _)| binding)
    {
        binding.process().policy().source_warning(SourceFormattedMessage::from_source_formatted(message));
    }
}

/// `mi_subproc_add_current_thread(id)`.
///
/// # Safety
/// `id` is null, the main id, or a live child id; the calling thread has
/// registered with the runtime but made no allocation, and owns its
/// thread roots until it finishes.
pub unsafe fn subproc_add_current_thread(id: *mut c_void) -> SubprocAddCurrentThread {
    let Some(pointer) = NonNull::new(id) else { return SubprocAddCurrentThread::Unchanged };
    if pointer.as_ptr() == main_id() {
        // A thread of the main subprocess is initialized on its first
        // operation; a child member is already initialized elsewhere.
        if let Some(child) = crate::subproc::lifecycle::current_child_id() {
            warn_other_subprocess(child.as_ptr());
        }
        return SubprocAddCurrentThread::Unchanged;
    }
    // SAFETY: forwarded live-id and current-thread contracts.
    match unsafe { crate::subproc::lifecycle::native_subproc_add_current_thread(NativeSubprocessId::from_ptr(pointer)) } {
        Ok(NativeChildThreadAdd::Added) => SubprocAddCurrentThread::Added,
        Ok(NativeChildThreadAdd::AlreadyInitialized { in_other_subprocess }) => {
            if in_other_subprocess {
                warn_other_subprocess(subproc_current());
            }
            SubprocAddCurrentThread::Unchanged
        }
        _ => SubprocAddCurrentThread::Failed,
    }
}

/// `mi_subproc_visit_heaps(id, visitor, argument)`: visits the subprocess's
/// Heaps in list order until the visitor returns `false`.
///
/// # Safety
/// `id` is null, the main id, or a live child id; `visitor` is a valid C
/// function that does not operate on that subprocess's Heap list.
pub unsafe fn subproc_visit_heaps(id: *mut c_void, visitor: HeapVisitor, argument: *mut c_void) -> bool {
    let Some(pointer) = NonNull::new(id) else { return false };
    // SAFETY: the visitor's C contract.
    let mut visit = |heap: NonNull<Heap>| unsafe { visitor(heap.as_ptr().cast(), argument) };
    if pointer.as_ptr() == main_id() {
        return MainSubprocess::global().identity().heap_list().visit_heaps(&mut visit).unwrap_or(false);
    }
    // SAFETY: forwarded live-id contract.
    unsafe { crate::subproc::lifecycle::native_subproc_visit_heaps(NativeSubprocessId::from_ptr(pointer), visit) }
        .unwrap_or(false)
}
