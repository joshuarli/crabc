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
