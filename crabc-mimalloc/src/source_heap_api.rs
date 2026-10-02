// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0
// - `src/theap.c:190-205` (the public guarded sampler controls);
// - `src/alloc.c:868-947` (guarded request geometry and placement) and
//   `src/alloc-aligned.c:30-49` (guarded alignment adjustment);
// - `src/heap.c:22-25` (`mi_heap_set_numa_affinity`);
// - `src/heap.c:149-157` (`mi_heap_new_in_arena`, `mi_heap_new`) and
//   `src/heap.c:228-261` (`mi_heap_delete`, `mi_heap_destroy`);
// - `src/subproc.c:113-115` (`mi_heap_main`);
// - `src/alloc.c:213-304,357-360` (`mi_heap_malloc_small`, `mi_heap_malloc`,
//   `mi_heap_zalloc_small`, `mi_heap_zalloc`, `mi_heap_calloc`,
//   `mi_heap_mallocn`) and `src/alloc-aligned.c:318-340` (the
//   `mi_heap_*_aligned[_at]` allocation entries);
// - `src/arena.c:1886-1922` (`mi_reserve_os_memory_ex2`,
//   `mi_reserve_os_memory_ex`, `mi_reserve_os_memory`) and
//   `src/arena.c:2170-2247` (the huge OS reservation entries);
// - `src/arena.c:2471-2520` (`_mi_heap_visit_blocks`,
//   `mi_heap_visit_blocks`, `mi_heap_visit_abandoned_blocks`).

//! Pinned mimalloc first-class Heap and OS-reservation public entries over
//! the native runtime.
//!
//! Each function is the source entry of the same `mi_` name. A Heap is the
//! source `mi_heap_t*`, passed as an opaque pointer. A calling thread of the
//! process main subprocess uses `subproc::main_heaps`; a thread admitted to a
//! child subprocess uses that child's Heap lifecycle. As in [`crate::source_api`], each
//! allocation reports the errno effect of its source path as data.
//!
//! The `_mi_verbose_message` reservation reports are not provided.

use core::ffi::{c_int, c_void};
use core::ptr::{null_mut, NonNull};

use crabc_core::Errno;

use crate::diagnostic_output::{SourceErrorReport, SourceFormattedMessage};
use crate::source_api::{Block, SourceErrno, Sourced};
use crate::subproc::main_heaps;
use crate::subproc::MainSubprocess;
use crate::types::heap_registry::lifecycle::HeapReleaseOutcome;
use crate::types::{Heap, Page, Theap};

/// Callback ABI retained by a caller-managed arena. A true commit result
/// means the requested span is accessible; a true purge result means it must
/// be recommitted before reuse.
pub type ManagedCommitFunction = unsafe extern "C" fn(
    commit: bool,
    start: *mut u8,
    size: usize,
    is_zero: *mut bool,
    user_argument: *mut c_void,
) -> bool;

/// `mi_heap_main()`: the calling thread's subprocess main Heap.
pub fn heap_main() -> *mut c_void {
    if crate::subproc::lifecycle::current_thread_is_child_member() {
        return crate::subproc::lifecycle::current_child_main_heap().map_or(null_mut(), |heap| heap.as_ptr().cast());
    }
    MainSubprocess::global().ready_main_heap_pointer().cast()
}

/// Copies the full source-selected Heap statistics; null selects the
/// calling thread's subprocess main Heap. Its existing Theap merge occurs
/// before validating the caller's output header.
///
/// # Safety
/// The Heap and the caller's selected Theap/owning Heap remain live through
/// the call. `stats` is null or an exclusive complete source statistics image.
pub unsafe fn heap_stats_get(heap: *mut c_void, stats: *mut c_void) -> bool {
    // SAFETY: forwarded source identity and complete output image contracts.
    unsafe { crate::runtime_lifecycle::native_heap_stats_get(heap, stats.cast()) }
}

/// Renders selected Heap statistics into a fixed or allocator-owned buffer.
///
/// # Safety
/// The selected Heap and calling thread's roots remain live during snapshot.
/// `buffer` is null or writable for `size` bytes; free an owned result.
pub unsafe fn heap_stats_json(heap: *mut c_void, size: usize, buffer: *mut core::ffi::c_char) -> *mut core::ffi::c_char {
    // SAFETY: forwarded source Heap and writable buffer contracts.
    unsafe { crate::runtime_lifecycle::native_heap_stats_json(heap, size, buffer.cast()) }.cast()
}

/// Prints selected Heap statistics after releasing its source projections.
///
/// # Safety
/// The selected Heap and caller's roots remain live during snapshot. `out`
/// and `argument` stay callable for each message; callbacks may allocate.
pub unsafe fn heap_stats_print_out(heap: *mut c_void, out: Option<crate::source_options_api::OutputFunction>, argument: *mut c_void) {
    // SAFETY: forwarded source Heap and synchronous callback contracts.
    unsafe { crate::runtime_lifecycle::native_heap_stats_print_out(heap, out, argument) };
}

/// Merges the Heap record directly into its owning subprocess and clears it.
/// This does not merge the calling thread's Theap. Null selects its main Heap.
///
/// # Safety
/// The Heap and its subprocess remain live through the merge/reset; the
/// caller supplies the source exclusion against other merges and destruction.
pub unsafe fn heap_stats_merge_to_subproc(heap: *mut c_void) {
    let Some(_operation) = crate::runtime_lifecycle::NativeSubprocessOperation::enter() else { return; };
    let heap = if heap.is_null() { heap_main() } else { heap };
    let Some(heap) = NonNull::new(heap.cast::<Heap>()) else { return; };
    // SAFETY: caller retains this Heap and its initialized subprocess.
    let _ = unsafe { Heap::merge_statistics_into_owning_subprocess_at(heap) };
}

/// Set the source Heap's NUMA affinity; null selects the current main Heap.
/// Negative values clear affinity, while nonnegative values wrap by the
/// process-wide cached node count. This selects arena search order and does
/// not migrate existing pages or promise hardware placement.
///
/// # Safety
/// A non-null `heap` remains live through the call. The caller excludes
/// concurrent affinity setters, allocation reads and Heap destruction.
pub unsafe fn heap_set_numa_affinity(heap: *mut c_void, numa_node: c_int) {
    let heap = if heap.is_null() { heap_main() } else { heap };
    let Some(heap) = NonNull::new(heap.cast::<Heap>()) else { return };
    let node = if numa_node < 0 { -1 } else {
        let Some((binding, _)) = crate::process_init::ProcessMainInitializationStorage::global()
            .ready_child_subprocess_inputs() else { return };
        numa_node % binding.process().policy().numa_node_count() as i32
    };
    // SAFETY: forwarded live Heap and synchronization obligations.
    unsafe { Heap::set_numa_affinity_at(heap, node) };
}

/// The pinned Linux x86-64 `mi_heap_t` image occupies 6464 bytes in all
/// selected debug/statistics profiles. Heap birth makes this ordinary zeroed
/// request from the subprocess main Heap; private Rust image fields must fit
/// that extent rather than changing publicly counted requested bytes.
#[cfg(target_arch = "x86_64")]
pub(crate) const SOURCE_HEAP_IMAGE_REQUEST_SIZE: usize = 6464;

// Ordinary source class geometry supplies the native image alignment. Keep
// the layout bound explicit so a future private image cannot underallocate.
#[cfg(target_arch = "x86_64")]
const _: () = {
    type Image = crate::types::heap_registry::lifecycle::NonMainHeapImage;
    assert!(core::mem::size_of::<Image>() <= SOURCE_HEAP_IMAGE_REQUEST_SIZE);
    let bin = match crate::size_class::bin_for_request(SOURCE_HEAP_IMAGE_REQUEST_SIZE) {
        Some(bin) => bin,
        None => panic!("Heap image request must select an ordinary class"),
    };
    let size = match crate::size_class::bin_size(bin) {
        Some(size) => size,
        None => panic!("Heap image class must have a block size"),
    };
    assert!(size % core::mem::align_of::<Image>() == 0);
    assert!(crate::config::ARENA_SLICE_SIZE % core::mem::align_of::<Image>() == 0);
};

/// `mi_heap_new()`: null when the Heap cannot be created.
pub fn heap_new() -> *mut c_void {
    if let Some(created) = crate::subproc::lifecycle::native_child_heap_new() {
        return created.ok().and_then(Result::ok).map_or(null_mut(), |heap| heap.as_ptr().cast());
    }
    main_heaps::native_heap_new().map_or(null_mut(), |heap| heap.as_ptr().cast())
}

/// `mi_heap_new_in_arena`: null selects the ordinary Heap allocation policy.
///
/// # Safety
/// A non-null `arena` is a live parent arena ID owned by the calling
/// thread's subprocess.
/// Its backing must outlive the Heap and every Theap and page it owns. No
/// concurrent arena destruction may overlap this call.
pub unsafe fn heap_new_in_arena(arena: *mut c_void) -> *mut c_void {
    let Some(arena) = (unsafe { crate::arena::ArenaId::from_arena(arena.cast()) }) else {
        return null_mut();
    };
    if arena.as_ptr().is_null() {
        return heap_new();
    }
    if crate::subproc::lifecycle::current_thread_is_child_member() {
        return crate::subproc::lifecycle::native_child_heap_new_in_arena(arena)
            .and_then(Result::ok)
            .and_then(Result::ok)
            .map_or(null_mut(), |heap| heap.as_ptr().cast());
    }
    // SAFETY: forwarded live process-parent ID and lifetime obligations.
    unsafe { main_heaps::native_heap_new_in_arena(arena) }
        .map_or(null_mut(), |heap| heap.as_ptr().cast())
}

/// `mi_arena_area`: a null ID yields null and a zero size.
///
/// # Safety
/// `size` is null or writable. A non-null ID names a live parent arena in
/// this process and its backing is retained through this query.
pub unsafe fn arena_area(arena: *mut c_void, size: *mut usize) -> *mut c_void {
    if !size.is_null() {
        // SAFETY: the caller supplies a writable output.
        unsafe { size.write(0) };
    }
    let Some(id) = (unsafe { crate::arena::ArenaId::from_arena(arena.cast()) }) else {
        return null_mut();
    };
    // SAFETY: forwarded live arena ID and backing obligation.
    let Some((start, length)) = (unsafe { id.area() }) else { return null_mut() };
    if !size.is_null() {
        // SAFETY: as above.
        unsafe { size.write(length) };
    }
    start.cast()
}

/// The calling thread's source arena group, including child subprocess
/// membership, held only for the duration of one public arena operation.
fn with_current_arena_registry<R>(operation: impl FnOnce(&crate::arena::ArenaRegistry) -> R) -> Option<R> {
    let _active = crate::runtime_lifecycle::NativeSubprocessOperation::enter()?;
    // SAFETY: this thread alone owns its initialized default Theap and TLD.
    let current = unsafe { Theap::initialized_default_subprocess_at(crate::compiler_tls::default_theap()) };
    let identity = current.and_then(NonNull::new).map_or(
        MainSubprocess::global().identity(),
        |identity| {
            // SAFETY: current membership and the active operation retain the
            // selected subprocess for this short projection.
            unsafe { identity.as_ref() }
        },
    );
    Some(operation(identity.arena_backing().registry()))
}

/// `mi_debug_show_arenas`: the calling subprocess's main-Heap arena image.
///
/// # Safety
/// Published arenas and pages remain live during the traversal. The caller
/// excludes ordinary page-field mutation while each short image is copied,
/// and excludes map registration changes for each lookup. Registered output
/// callbacks remain callable and retain the traversed arena backing. They
/// may allocate or free between projections, as the source permits, and
/// must satisfy the source output-registration serialization contract.
pub unsafe fn debug_show_arenas() {
    with_current_arena_registry(|registry| {
        // SAFETY: the operation retains subprocess membership; the caller
        // retains mapped arena/page geometry and callback state.
        unsafe { crate::arena_print::print(registry) };
    });
}

/// `mi_arenas_print`, the source alias of `mi_debug_show_arenas`.
///
/// # Safety
/// The caller satisfies [`debug_show_arenas`]'s traversal and output duties.
pub unsafe fn arenas_print() {
    // SAFETY: forwarded traversal and output obligations.
    unsafe { debug_show_arenas() }
}

/// `mi_arena_contains` checks the parent's own slice range, then published
/// child ranges in the calling thread's subprocess arena group.
///
/// # Safety
/// A non-null `arena` is a live parent ID and its backing remains live for
/// this query; no arena destruction overlaps it.
pub unsafe fn arena_contains(arena: *mut c_void, pointer: *const c_void) -> bool {
    let Some(id) = (unsafe { crate::arena::ArenaId::from_arena(arena.cast()) }) else { return false };
    with_current_arena_registry(|registry| {
        // SAFETY: caller retains the ID, and the operation guard retains the
        // selected registry's published arenas.
        unsafe { id.contains_in(registry, pointer.cast()) }
    }).unwrap_or(false)
}

/// Pinned public geometry for this native allocator configuration.
pub const fn arena_min_size() -> usize { crate::config::ARENA_MIN_SIZE }

/// Pinned public alignment for externally registered arena memory.
pub const fn arena_min_alignment() -> usize { crate::config::ARENA_ALIGNMENT }

/// `mi_arena_max_object_size` observes the live source option value.
pub fn arena_max_object_size() -> usize {
    let Some((binding, _)) = crate::process_init::ProcessMainInitializationStorage::global()
        .ready_child_subprocess_inputs() else { return crate::config::ARENA_MIN_OBJ_SIZE };
    crate::arena::arena_max_object_size(binding.process().policy())
}

/// `mi_manage_os_memory_ex` registers caller-owned mapped backing in the
/// current subprocess. A child member publishes into its pinned child arena
/// group; the caller retains the mapping's unmap right through teardown.
///
/// # Safety
/// `start..start + size` is one live external mapping that outlives
/// every arena, Heap, Theap and page registered over it. Commitment and zero
/// flags describe its actual initial state; uncommitted pages may be
/// inaccessible until this allocator commits them. `arena_id` is null or writable;
/// concurrent access or unmapping of the region is excluded during setup.
pub unsafe fn manage_os_memory_ex(
    start: *mut c_void,
    size: usize,
    is_committed: bool,
    is_pinned: bool,
    is_zero: bool,
    numa_node: c_int,
    exclusive: bool,
    arena_id: *mut *mut c_void,
) -> bool {
    if !arena_id.is_null() {
        // SAFETY: caller supplied a writable output.
        unsafe { arena_id.write(null_mut()) };
    }
    if crate::subproc::lifecycle::current_thread_is_child_member() {
        // SAFETY: the public caller retains the mapped range and its initial
        // flags. The child record pins the exact subprocess through setup.
        let Some(managed) = (unsafe { crate::subproc::lifecycle::native_child_manage_os_memory_ex(
            start.cast(), size, is_committed, is_pinned, is_zero, numa_node, exclusive,
        ) }) else { return false };
        if !arena_id.is_null() {
            // SAFETY: as above.
            unsafe { arena_id.write(managed.as_ptr().cast()) };
        }
        return true;
    }
    let Some((binding, _)) = crate::process_init::ProcessMainInitializationStorage::global()
        .ready_child_subprocess_inputs() else { return false };
    let Ok(config) = binding.page_map().memory_config() else { return false };
    let Some(_active) = crate::runtime_lifecycle::NativeSubprocessOperation::enter() else { return false };
    // SAFETY: caller retains the external backing; the process-static owner
    // records its address without taking an unmap right.
    let Ok(managed) = (unsafe { MainSubprocess::global().arena_backing().install_owned_external_os_arena(
        binding.process(), config, start.cast(), size, is_committed, is_pinned,
        is_zero, numa_node, exclusive,
    ) }) else { return false };
    if !arena_id.is_null() {
        // SAFETY: as above.
        unsafe { arena_id.write(managed.arena_id().as_ptr().cast()) };
    }
    true
}

/// `mi_manage_memory` retains the caller's external mapping and optional
/// commit/purge callback in the calling subprocess's arena group.
///
/// # Safety
/// `start..start + size` is one live caller-owned mapping until every arena,
/// Heap, Theap, and page using it is quiescent. The initial memory flags are
/// truthful. When present, `callback` and `user_argument` remain valid for
/// every metadata commit, page commit, and purge until arena retirement;
/// callback code accepts contained raw spans, synchronizes concurrent and
/// reentrant calls, and makes a successful commit span accessible before
/// returning. `arena_id` is null or writable. Setup excludes overlapping
/// mappings, concurrent unmapping, and concurrent mutation of these inputs.
pub unsafe fn manage_memory(
    start: *mut c_void,
    size: usize,
    is_committed: bool,
    is_pinned: bool,
    is_zero: bool,
    numa_node: c_int,
    exclusive: bool,
    callback: Option<ManagedCommitFunction>,
    user_argument: *mut c_void,
    arena_id: *mut *mut c_void,
) -> bool {
    let Some(callback) = callback else {
        // SAFETY: without a callback, source uses the ordinary external OS
        // path with exactly these flags and output ownership.
        return unsafe { manage_os_memory_ex(start, size, is_committed, is_pinned,
            is_zero, numa_node, exclusive, arena_id) };
    };
    if !arena_id.is_null() {
        // SAFETY: caller supplied a writable output.
        unsafe { arena_id.write(null_mut()) };
    }
    let Some(lease) = (unsafe { crate::arena::ProcessExternalArenaLease::new(
        start.cast(), size, is_committed, is_pinned, is_zero,
        crate::arena::CommitHook::new(callback, user_argument),
    ) }) else { return false };
    if crate::subproc::lifecycle::current_thread_is_child_member() {
        // SAFETY: the public caller retains the mapping and callback through
        // child teardown. The child record retains its image and exact arena
        // registry while the lease is admitted or returned on failure.
        let Some(managed) = (unsafe { crate::subproc::lifecycle::native_child_manage_memory(
            size, lease, numa_node, exclusive,
        ) }) else { return false };
        if !arena_id.is_null() {
            // SAFETY: caller supplied a writable output.
            unsafe { arena_id.write(managed.as_ptr().cast()) };
        }
        return true;
    }
    let Some((binding, _)) = crate::process_init::ProcessMainInitializationStorage::global()
        .ready_child_subprocess_inputs() else { return false };
    let Ok(config) = binding.page_map().memory_config() else { return false };
    let Some(_active) = crate::runtime_lifecycle::NativeSubprocessOperation::enter() else { return false };
    // SAFETY: the public caller retains the mapping and callback for every
    // published owner. The process-static arena backing retains the lease;
    // failed prepublication setup returns it without taking the unmap right.
    let managed = unsafe { MainSubprocess::global().arena_backing()
        .install_owned_external_callback_arena(
            binding.process(), config, size, lease, numa_node, exclusive,
        ) };
    match managed {
        Ok(managed) => {
            if !arena_id.is_null() {
                // SAFETY: caller supplied a writable output.
                unsafe { arena_id.write(managed.arena_id().as_ptr().cast()) };
            }
            true
        }
        Err(failure) => {
            // A returned lease has no published owner and no unmap right.
            // A retained lease stays in its arena slot after publication.
            let _ = failure.into_returned_lease();
            false
        }
    }
}

/// `mi_manage_os_memory` forwards to the managed-memory entry with ordinary
/// nonexclusive arena selection and no arena-ID output.
///
/// # Safety
/// `start..start + size` remains one live caller-owned mapping through every
/// arena, Heap, Theap and page that uses it. The initial commitment and zero
/// flags are truthful; uncommitted pages may be inaccessible until committed.
pub unsafe fn manage_os_memory(
    start: *mut c_void,
    size: usize,
    is_committed: bool,
    is_pinned: bool,
    is_zero: bool,
    numa_node: c_int,
) -> bool {
    // SAFETY: the public caller retains the same mapping and true flags;
    // source selects a nonexclusive arena and requests no arena-ID output.
    unsafe { manage_os_memory_ex(
        start, size, is_committed, is_pinned, is_zero, numa_node, false, null_mut(),
    ) }
}

#[cfg(test)]
mod manage_os_alias_tests {
    extern crate std;

    use super::*;
    use crate::config::{ARENA_ALIGNMENT, ARENA_MIN_SIZE};
    use crate::types::MemoryKind;

    unsafe extern "C" fn no_output(_: *const core::ffi::c_char) {}

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn public_manage_os_memory_uses_nonexclusive_external_owner() {
        crate::test_process::run_in_fresh_process(
            "source_heap_api::manage_os_alias_tests::public_manage_os_memory_uses_nonexclusive_external_owner",
            || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
                // SAFETY: this test owns the raw reservation and trims only
                // the unobserved prefix and suffix outside its arena span.
                let raw = unsafe { crabc_core::mm::mmap_raw(
                    core::ptr::null_mut(), ARENA_MIN_SIZE + ARENA_ALIGNMENT,
                    0, 0x22, -1, 0,
                ) }.expect("caller reservation");
                let aligned = (raw as usize + ARENA_ALIGNMENT - 1) & !(ARENA_ALIGNMENT - 1);
                let prefix = aligned - raw as usize;
                let suffix = ARENA_ALIGNMENT - prefix;
                if prefix != 0 {
                    // SAFETY: the prefix is outside the managed range and
                    // no arena or page can reference it yet.
                    unsafe { crabc_core::mm::munmap_raw(raw, prefix) }.unwrap();
                }
                if suffix != 0 {
                    // SAFETY: the suffix is outside the managed range and
                    // no arena or page can reference it yet.
                    unsafe { crabc_core::mm::munmap_raw((aligned + ARENA_MIN_SIZE) as *mut u8, suffix) }.unwrap();
                }
                let area = aligned as *mut core::ffi::c_void;
                assert!(unsafe { manage_os_memory(area, ARENA_MIN_SIZE, false, false, true, -1) });
                let registry = MainSubprocess::global().arena_backing().registry();
                let arena = (0..registry.count()).find_map(|index| {
                    // SAFETY: this isolated process has no concurrent arena
                    // destruction, and every published slot is stable.
                    unsafe { registry.arena_at(index) }.filter(|arena| arena.start == aligned as *mut u8)
                }).expect("alias publishes an arena for its external range");
                assert_eq!(arena.memid.kind(), MemoryKind::External);
                assert!(!arena.is_exclusive);
                assert!(arena.commit_function.is_none());
                assert_eq!(arena.subprocess, MainSubprocess::global().identity().as_ptr());
                assert!(!unsafe { manage_os_memory(area, ARENA_MIN_SIZE - 1, false, false, true, -1) });
                let mut residency = 0u8;
                // SAFETY: the allocator retained only the arena metadata;
                // the caller's raw mapping is still live through this query.
                assert!(unsafe { crabc_core::mm::mincore_raw(aligned as *mut u8, 4096, &mut residency) }.is_ok());
            },
        );
    }
}

/// The initialized default Theap of the calling thread. A cold main-subprocess
/// thread attaches its owner; a child member already retains its own owner.
pub fn theap_get_default() -> *mut c_void {
    if !crate::subproc::lifecycle::current_thread_is_child_member()
        && !crate::runtime_lifecycle::prepare_current_thread_native_owner_for_heap_theaps()
    {
        return null_mut();
    }
    let theap = crate::compiler_tls::default_theap();
    // SAFETY: the default root names this thread's Theap or the immutable
    // empty image; a non-null Heap marks the initialized case.
    if unsafe { Theap::heap_at(theap) }.is_null() {
        null_mut()
    } else {
        theap.as_ptr().cast()
    }
}

/// Select the calling thread's Theap for a live Heap.
///
/// # Safety
/// `heap` is a live Heap of this thread's subprocess and remains live through
/// the selection. The calling thread keeps its Theap and TLD attached.
pub unsafe fn heap_theap(heap: *mut c_void) -> *mut c_void {
    let Some(heap) = NonNull::new(heap.cast::<Heap>()) else { return null_mut() };
    if theap_get_default().is_null() { return null_mut(); }
    if crate::subproc::lifecycle::current_thread_is_child_member() {
        // SAFETY: the caller retains the live child Heap for this selection.
        return unsafe { crate::subproc::lifecycle::native_child_heap_theap(heap) }
            .map_or(null_mut(), |theap| theap.as_ptr().cast());
    }
    main_heaps::native_heap_theap(heap).map_or(null_mut(), |theap| theap.as_ptr().cast())
}

/// The persistent runtime page owner differs from a freshly selected sibling.
pub(crate) fn fixed_runtime_theap() -> Option<NonNull<Theap>> {
    if crate::subproc::lifecycle::current_thread_is_child_member() {
        crate::compiler_tls::fast_slot_peek().map(|slot| slot.cast())
    } else {
        main_heaps::fixed_main_theap()
    }
}

/// Replace this thread's default Theap and return its previous one. Null and
/// uninitialized candidates leave the root unchanged.
///
/// # Safety
/// A non-null `theap` points to an address-stable Theap of the calling
/// thread's live TLD and Heap. It remains live until the caller restores the
/// previous default. The caller excludes concurrent destruction or exit.
pub unsafe fn theap_set_default(theap: *mut c_void) -> *mut c_void {
    let previous = theap_get_default();
    let Some(candidate) = NonNull::new(theap.cast::<Theap>()) else { return previous };
    let Some(current) = NonNull::new(previous.cast::<Theap>()) else { return previous };
    // SAFETY: caller retains the candidate and this thread retains current.
    let initialized = unsafe { !Theap::heap_at(candidate).is_null() };
    let same_tld = unsafe { Theap::tld_at(candidate) == Theap::tld_at(current) };
    if !initialized || !same_tld { return previous; }
    crate::compiler_tls::set_default_theap(candidate);
    previous
}

/// `mi_theap_guarded_set_sample_rate`: initializes the selected source sampler.
/// The seed selects its initial countdown; zero draws from the Theap random
/// state only when the rate exceeds one. Non-guarded builds have no effect.
///
/// # Safety
/// In a guarded build, `theap` is a live writable initialized Theap owned by
/// the calling thread. The caller excludes allocation, other guarded setters,
/// random-state access, initialization and teardown for the duration of this call.
pub unsafe fn theap_guarded_set_sample_rate(theap: *mut c_void, rate: usize, seed: usize) {
    #[cfg(all(target_arch = "x86_64", feature = "mi-guarded"))]
    {
        let Some(theap) = NonNull::new(theap.cast::<Theap>()) else { return };
        // SAFETY: the caller exclusively retains the initialized sampler and,
        // for a zero seed with rate greater than one, its random state.
        unsafe { Theap::guarded_set_sample_rate_at(theap, rate, seed) };
    }
    #[cfg(not(all(target_arch = "x86_64", feature = "mi-guarded")))]
    let _ = (theap, rate, seed);
}

/// `mi_theap_guarded_set_size_bound`: sets inclusive sampler bounds,
/// normalizing the maximum upward to the minimum. Non-guarded builds have no effect.
///
/// # Safety
/// In a guarded build, `theap` is a live writable initialized Theap owned by
/// the calling thread. The caller excludes allocation, other guarded setters,
/// initialization and teardown for the duration of this call.
pub unsafe fn theap_guarded_set_size_bound(theap: *mut c_void, minimum: usize, maximum: usize) {
    #[cfg(all(target_arch = "x86_64", feature = "mi-guarded"))]
    {
        let Some(theap) = NonNull::new(theap.cast::<Theap>()) else { return };
        // SAFETY: the caller exclusively owns the selected live bound fields.
        unsafe { Theap::guarded_set_size_bound_at(theap, minimum, maximum) };
    }
    #[cfg(not(all(target_arch = "x86_64", feature = "mi-guarded")))]
    let _ = (theap, minimum, maximum);
}

/// A source sampling decision never turns a sampled refusal into an ordinary
/// allocation. Only `NotSampled` permits the caller's ordinary engine route.
#[cfg(all(target_arch = "x86_64", feature = "mi-guarded"))]
pub(crate) enum GuardedAllocationResult {
    NotSampled,
    Allocated(Sourced<NonNull<u8>>),
    Refused(SourceErrno),
}

/// Samples before admission, then retains one actual selected owner through
/// geometry, canonical allocation, placement and consuming refusal cleanup.
/// Only an unsampled request permits the caller's ordinary allocation route.
///
/// # Safety
/// The caller retains the current-thread selected Heap, Theap and member,
/// excluding teardown and overlapping sampler mutation for the entire call.
/// An immutable empty compiler-TLS image is permitted on its read-only sampler
/// path. A supplied alignment is nonzero and a power of two. All allocator
/// projections and locks have ended; callbacks cannot consume an in-flight
/// client or tear down its selected owner.
#[cfg(all(target_arch = "x86_64", feature = "mi-guarded"))]
pub(crate) unsafe fn guarded_allocate_selected(
    theap: NonNull<Theap>, size: usize, aligned: Option<(usize, usize)>, zero: bool,
) -> GuardedAllocationResult {
    let Some(sampled) = (unsafe { guarded_sample_source_request(theap, size, aligned) }) else {
        return GuardedAllocationResult::NotSampled;
    };
    let checked = match sampled.check_size() {
        Ok(checked) => checked,
        Err(report) => return GuardedAllocationResult::Refused(crate::source_api::source_error_errno(report)),
    };
    // SAFETY: the selected metadata and member remain retained before any
    // canonical client is created and through synchronous callback delivery.
    unsafe { crate::runtime_lifecycle::with_native_allocation_owner(theap, |owner| {
        let Some(page_size) = owner.page_map().ok()
            .and_then(|map| map.memory_config().ok()).map(|config| config.page_size()) else {
                return GuardedAllocationResult::Refused(SourceErrno::Unchanged);
            };
        // The source's live option table belongs to this same admitted owner;
        // lazy option warnings run with no engine or metadata projection held.
        let precise = owner.output().option_value(crate::config::SourceOption::GuardedPrecise) != 0;
        let report_errno = |report: SourceErrorReport| {
            match owner.output().error_message(report.error(), report.message()) {
                crate::diagnostic_output::SourceErrorDisposition::Handled => SourceErrno::Unchanged,
                crate::diagnostic_output::SourceErrorDisposition::DefaultErrno(errno) => SourceErrno::DefaultIfZero(errno),
            }
        };
        let geometry = match checked.geometry(page_size, precise) {
            Ok(geometry) => geometry,
            Err(report) => return GuardedAllocationResult::Refused(report_errno(report)),
        };
        use crate::runtime_lifecycle::NativeGuardedAllocationOutcome;
        match crate::runtime_lifecycle::native_guarded_allocate_in_owner(&owner, geometry.source_size(),
            |owner, candidate| guarded_place_candidate(owner, candidate, &geometry, zero)) {
            NativeGuardedAllocationOutcome::Placed { client, .. } => GuardedAllocationResult::Allocated(
                Sourced { value: client, errno: SourceErrno::Unchanged }),
            NativeGuardedAllocationOutcome::SourceOutOfMemory => GuardedAllocationResult::Refused(
                report_errno(SourceErrorReport::OutOfMemory { size: geometry.source_size() })),
            NativeGuardedAllocationOutcome::ShortGeometry | NativeGuardedAllocationOutcome::AdmissionRefused =>
                GuardedAllocationResult::Refused(SourceErrno::Unchanged),
        }
    }) }.unwrap_or(GuardedAllocationResult::Refused(SourceErrno::Unchanged))
}

#[cfg(all(target_arch = "x86_64", feature = "mi-guarded"))]
fn guarded_public_result(result: GuardedAllocationResult) -> Option<Sourced<Block>> {
    match result {
        GuardedAllocationResult::NotSampled => None,
        GuardedAllocationResult::Allocated(result) => Some(Sourced { value: Some(result.value), errno: result.errno }),
        GuardedAllocationResult::Refused(errno) => Some(Sourced { value: None, errno }),
    }
}

/// Scalar source selection, not an admitted owner or allocation capability.
#[cfg(all(target_arch = "x86_64", feature = "mi-guarded"))]
pub(crate) struct GuardedSampledRequest {
    size: usize,
    alignment: Option<usize>,
}

/// Advances the selected Theap's source sampler exactly once at allocation
/// ingress. Offset or large-alignment requests do not take this guarded path.
/// Plain zero-size requests normalize before sampling, as the small source
/// entry does; aligned sampling observes the original unrounded size.
///
/// # Safety
/// `theap` is address-stable and its initialized sampler fields are exclusively
/// owned by the calling thread, excluding initialization and teardown. An
/// immutable empty image is permitted only on its read-only rate-zero path.
/// A nonempty image has mutable provenance for countdown writes. `aligned`,
/// when present, contains a validated nonzero power-of-two alignment.
#[cfg(all(target_arch = "x86_64", feature = "mi-guarded"))]
pub(crate) unsafe fn guarded_sample_source_request(
    theap: NonNull<Theap>,
    size: usize,
    aligned: Option<(usize, usize)>,
) -> Option<GuardedSampledRequest> {
    let (size, alignment) = match aligned {
        None => (if size == 0 { core::mem::size_of::<usize>() } else { size }, None),
        Some((alignment, 0)) if alignment < crate::config::PAGE_MAX_OVERALLOC_ALIGN =>
            (size, Some(alignment)),
        Some(_) => return None,
    };
    // SAFETY: only initialized current-thread sampler fields are projected;
    // that projection ends before owner admission or any diagnostic callback.
    if !unsafe { Theap::guarded_sample_at(theap, size) } { return None; }
    Some(GuardedSampledRequest { size, alignment })
}

/// Source guarded allocation extents, before any engine client exists.
#[cfg(all(target_arch = "x86_64", feature = "mi-guarded"))]
pub(crate) struct GuardedRequestGeometry {
    object_size: usize,
    source_size: usize,
    counted_request: usize,
    alignment: Option<usize>,
}

/// A sampled request whose source size refusal has already been checked.
/// It carries no admitted owner, mapping, or release authority.
#[cfg(all(target_arch = "x86_64", feature = "mi-guarded"))]
pub(crate) struct GuardedCheckedRequest {
    size: usize,
    alignment: Option<usize>,
}

#[cfg(all(target_arch = "x86_64", feature = "mi-guarded"))]
impl GuardedSampledRequest {
    /// Checks source overflow before acquiring an allocation owner or client.
    /// The diagnostic retains the original public aligned operands.
    pub(crate) fn check_size(self) -> Result<GuardedCheckedRequest, SourceErrorReport> {
        let size = if let Some(alignment) = self.alignment {
            if self.size > crate::config::MAX_ALLOC_SIZE - crate::config::PADDING_SIZE - alignment {
                return Err(SourceErrorReport::GuardedAlignedAllocationTooLarge { size: self.size, alignment });
            }
            self.size + alignment - 1
        } else {
            self.size
        };
        if size >= crate::config::MAX_ALLOC_SIZE - crate::config::PADDING_SIZE {
            return Err(SourceErrorReport::GuardedAllocationTooLarge { size });
        }
        Ok(GuardedCheckedRequest { size, alignment: self.alignment })
    }
}

#[cfg(all(target_arch = "x86_64", feature = "mi-guarded"))]
impl GuardedCheckedRequest {
    /// Computes the source canonical extent from the admitted owner's page
    /// size and the selected precise-guard policy, without allocating a client.
    pub(crate) fn geometry(self, os_page_size: crate::os::PageSize, precise: bool) -> Result<GuardedRequestGeometry, SourceErrorReport> {
        let os_page_size = os_page_size.bytes();
        let size = self.size;
        let round_up = |value: usize, alignment: usize| {
            value.checked_add(alignment - 1).map(|value| value & !(alignment - 1))
        };
        let overflow = SourceErrorReport::GuardedAllocationTooLarge { size };
        let rounded = round_up(size, crate::config::MAX_ALIGN_SIZE).ok_or(overflow)?;
        let object_size = if precise { size } else { rounded };
        let bsize = round_up(rounded.checked_add(core::mem::size_of::<usize>()).ok_or(overflow)?,
            crate::config::MAX_ALIGN_SIZE).ok_or(overflow)?;
        let source_size = round_up(bsize.checked_add(os_page_size).ok_or(overflow)?,
            os_page_size).ok_or(overflow)?;
        Ok(GuardedRequestGeometry { object_size, source_size, counted_request: size, alignment: self.alignment })
    }
}

#[cfg(all(target_arch = "x86_64", feature = "mi-guarded"))]
impl GuardedRequestGeometry {
    /// The raw, already-padded extent received by the source generic engine.
    pub(crate) fn source_size(&self) -> usize { self.source_size }
}

#[cfg(all(target_arch = "x86_64", feature = "mi-guarded"))]
pub(crate) enum GuardedCandidatePlacement {
    ShortGeometry,
    Placed { client: NonNull<u8>, usable_size: usize },
}

/// Places a source guard while retaining the original canonical client under
/// the same admitted allocation owner. A short block returns that original
/// token for the issuing engine's consuming cleanup; it never becomes OOM or
/// admission refusal. Protection refusal still publishes the tagged client.
/// The returned usable extent includes any source offset-cap slack.
///
/// # Safety
/// `candidate` is the exclusive completed canonical return of `owner`'s
/// selected engine for `geometry.source_size()`. The caller retains its
/// Heap/member and excludes overlapping metadata or client mutation and
/// teardown. All engine and Heap/Theap/Page projections and locks ended before
/// entry. Warning callbacks cannot consume the in-flight client or change its
/// selected owner's lifetime. No statistics merge/reset overlaps the final
/// current-thread accounting projection after those callbacks return.
#[cfg(all(target_arch = "x86_64", feature = "mi-guarded"))]
pub(crate) unsafe fn guarded_place_candidate<'owner, 'scope>(
    owner: &crate::runtime_lifecycle::NativeAllocationOwner<'_>,
    candidate: crate::runtime_lifecycle::NativeGuardedCanonical<'owner, 'scope>,
    geometry: &GuardedRequestGeometry,
    zero: bool,
) -> Result<
    (crate::runtime_lifecycle::NativeGuardedCanonical<'owner, 'scope>, GuardedCandidatePlacement),
    crate::runtime_lifecycle::NativeGuardedCanonicalFactsFailure<'owner, 'scope>,
> {
    let object_size = geometry.object_size;
    // SAFETY: the original token and same admitted issuer remain retained;
    // the leaf ends geometry projections before synchronous warning callbacks.
    let result = unsafe { crate::runtime_lifecycle::with_guarded_live_block_in_owner(owner, candidate, |facts| {
        // Source tags the canonical first word before the short-geometry check.
        // SAFETY: this exclusively held canonical client contains its first word.
        facts.canonical.cast::<usize>().as_ptr().write(usize::MAX);
        let Some(required) = object_size.checked_add(facts.os_page_size)
            .and_then(|size| size.checked_add(core::mem::size_of::<usize>())) else {
                return GuardedCandidatePlacement::ShortGeometry;
            };
        if facts.block_size < required { return GuardedCandidatePlacement::ShortGeometry; }
        let tail = facts.canonical.as_ptr().add(facts.block_size - facts.os_page_size);
        if !facts.is_pinned && tail.addr() % facts.os_page_size == 0 {
            // The exact original client and admitted owner retain this live
            // tail; protection failure warns but does not consume the client.
            let protected = crate::os::protect_guarded_live_range(
                tail, facts.os_page_size, true, facts.process,
            );
            if protected != Ok(true) {
                owner.output().warning_from_source_options(SourceFormattedMessage::guarded_protect_failure(
                    facts.canonical.as_ptr().addr(), facts.block_size,
                ));
            }
        } else {
            owner.output().warning_from_source_options(SourceFormattedMessage::guarded_pinned_memory(
                facts.canonical.as_ptr().addr(), facts.block_size,
            ));
        }
        let offset = (facts.block_size - facts.os_page_size - object_size)
            .min(crate::config::PAGE_MAX_OVERALLOC_ALIGN);
        let base = facts.canonical.as_ptr().add(offset);
        // Source zeroing follows protection and warning callbacks. The checked
        // geometry retains a writable object extent before the guard page.
        if zero { base.write_bytes(0, object_size); }
        let adjustment = geometry.alignment.map_or(0, |alignment| base.addr().wrapping_neg() & (alignment - 1));
        let client = NonNull::new_unchecked(base.add(adjustment));
        let usable_size = facts.block_size - facts.os_page_size - offset - adjustment;
        GuardedCandidatePlacement::Placed { client, usable_size }
    }) }?;
    if matches!(&result.1, GuardedCandidatePlacement::Placed { .. }) {
        // SAFETY: the selected current-thread statistics tail remains live;
        // all page/engine projections and warning callbacks have ended.
        unsafe { Theap::record_guarded_allocation_statistics_at(
            owner.selected_theap(), geometry.source_size, geometry.counted_request,
        ) };
    }
    Ok(result)
}

/// Direct allocation from an initialized Theap of the calling thread.
///
/// # Safety
/// `theap` is a live Theap of this thread's TLD and Heap, retained against
/// Heap destruction and thread exit for the entire allocation.
pub unsafe fn theap_malloc(theap: *mut c_void, size: usize, zero: bool) -> Sourced<Block> {
    let Some(theap) = NonNull::new(theap.cast::<Theap>()) else {
        return Sourced { value: None, errno: SourceErrno::Unchanged };
    };
    let Some(current) = NonNull::new(theap_get_default().cast::<Theap>()) else {
        return Sourced { value: None, errno: SourceErrno::Unchanged };
    };
    // SAFETY: both Theaps are retained by this thread for the call.
    if unsafe { Theap::tld_at(theap) != Theap::tld_at(current) }
        || unsafe { Theap::heap_at(theap) }.is_null()
    {
        return Sourced { value: None, errno: SourceErrno::Unchanged };
    }
    #[cfg(all(target_arch = "x86_64", feature = "mi-guarded"))]
    if let Some(result) = guarded_public_result(unsafe { guarded_allocate_selected(theap, size, None, zero) }) {
        return result;
    }
    // SAFETY: the selected initialized current-thread Theap was validated above.
    unsafe { theap_allocate_ordinary(theap, size, zero) }
}

/// Ordinary continuation after the selected ingress sampler has already run.
unsafe fn theap_allocate_ordinary(theap: NonNull<Theap>, size: usize, zero: bool) -> Sourced<Block> {
    // The retained fixed Theap uses its runtime engine independently of
    // the default and source fast selector. A main-Heap sibling uses its
    // own allocated engine image.
    if fixed_runtime_theap() == Some(theap) {
        return crate::source_api::malloc_zero_native(size, zero);
    }
    // SAFETY: the current thread retains this auxiliary Theap and its Heap.
    let block = if crate::subproc::lifecycle::current_thread_is_child_member() {
        unsafe { crate::subproc::lifecycle::native_child_theap_allocate(theap, size, zero) }.flatten()
    } else {
        unsafe { main_heaps::native_theap_allocate(theap, size, zero) }
    };
    match block {
        Some(block) => Sourced { value: Some(block), errno: SourceErrno::Unchanged },
        None => Sourced { value: None, errno: report_failure(size, Request::Plain) },
    }
}

/// The default Theap's allocation route when it differs from this thread's
/// main-Heap Theap; `None` keeps the existing main-owner fast path.
pub(crate) fn default_theap_allocate(size: usize, zero: bool) -> Option<Sourced<Block>> {
    let selected = crate::compiler_tls::default_theap();
    #[cfg(all(target_arch = "x86_64", feature = "mi-guarded"))]
    if let Some(result) = guarded_public_result(unsafe { guarded_allocate_selected(selected, size, None, zero) }) {
        return Some(result);
    }
    // The default remains initialized after child destruction clears the
    // fast root. An auxiliary default still selects its own Heap.
    // SAFETY: the calling thread retains its default Theap through routing.
    let heap = unsafe { Theap::heap_at(selected) };
    if heap.is_null() || fixed_runtime_theap() == Some(selected) { return None; }
    // SAFETY: only the calling thread changes its default, which must stay
    // live through every allocation until it is restored.
    Some(unsafe { theap_allocate_ordinary(selected, size, zero) })
}

/// `mi_heap_of`: the Heap currently named by the page containing `pointer`.
/// An interior pointer has the same Heap as its containing live block.
///
/// # Safety
/// `pointer` is null, inside a live allocation held through this call, or
/// inside memory the caller owns that this allocator never mapped. The
/// caller excludes a concurrent Heap move for the containing page.
pub unsafe fn heap_of(pointer: *const u8) -> *mut c_void {
    // SAFETY: forwarded slice and Heap-transition exclusions.
    unsafe { main_heaps::heap_of_pointer(pointer) }.map_or(null_mut(), |heap| heap.as_ptr().cast())
}

/// `mi_any_heap_contains`: whether the safe PageMap lookup finds a page.
///
/// # Safety
/// The obligations of [`heap_of`].
pub unsafe fn any_heap_contains(pointer: *const u8) -> bool {
    // SAFETY: forwarded PageMap slice-exclusion obligation.
    unsafe { crate::source_api::check_owned(pointer) }
}

/// `mi_is_in_heap_region`: whether the safe PageMap lookup finds a page.
///
/// # Safety
/// The obligations of [`any_heap_contains`].
pub unsafe fn is_in_heap_region(pointer: *const u8) -> bool {
    // SAFETY: the same safe PageMap lookup answers both public queries.
    unsafe { any_heap_contains(pointer) }
}

/// `mi_heap_contains`: a null Heap selects this thread's subprocess main
/// Heap before comparing it with the pointer's page Heap.
///
/// # Safety
/// The obligations of [`heap_of`]; `heap` is null or a live Heap identity.
pub unsafe fn heap_contains(heap: *mut c_void, pointer: *const u8) -> bool {
    let heap = if heap.is_null() { heap_main() } else { heap };
    // SAFETY: forwarded pointer and Heap-lifetime obligations.
    !heap.is_null() && heap == unsafe { heap_of(pointer) }
}

/// `mi_unsafe_heap_page_is_under_utilized`: checks one page's ordinary
/// queue, commitment, Heap identity, and used-block count without collecting.
///
/// # Safety
/// `pointer` is null, inside a live allocation retained through this call,
/// or in caller-owned memory this allocator never mapped. The containing
/// page and its PageMap slice must remain registered and stable, with no
/// concurrent allocation, free, collection, queue move, or Heap move. `heap`
/// is null or a live Heap identity retained through this call.
pub unsafe fn heap_page_is_under_utilized(
    heap: *mut c_void,
    pointer: *mut u8,
    percentage: usize,
) -> bool {
    let Some(pointer) = NonNull::new(pointer) else { return false };
    let Some(_operation) = crate::runtime_lifecycle::NativeSubprocessOperation::enter() else {
        return false;
    };
    let Some((binding, _)) = crate::process_init::ProcessMainInitializationStorage::global()
        .ready_child_subprocess_inputs() else { return false };
    // SAFETY: the caller excludes PageMap entry mutation for this exact slice.
    let Some(page) = (unsafe { binding.page_map().lookup_registered_page(pointer.as_ptr()) }).ok().flatten() else {
        return false;
    };
    // SAFETY: the caller keeps this page and all of its ordinary fields
    // stable until the utilization predicate has copied its scalar values.
    unsafe { page.as_ref() }.is_under_utilized_for_heap(heap.cast(), percentage)
}

#[cfg(test)]
mod heap_membership_tests {
    extern crate std;

    use super::*;
    use crate::runtime_lifecycle::{
        attach_current_thread, finish_current_thread_native_after_user_destructors, native_free,
        NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    };
    use crate::subproc::main_heaps::{native_heap_allocate, native_heap_new, native_heap_release};
    use std::vec::Vec;

    unsafe extern "C" fn no_output(_: *const core::ffi::c_char) {}

    fn initialize_test_owner() {
        assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
            crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
        }));
        assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-guarded", not(miri)))]
    #[test]
    fn public_theap_guarded_controls_preserve_seed_countdown_and_inclusive_bounds() {
        crate::test_process::run_in_fresh_process(
            "source_heap_api::heap_membership_tests::public_theap_guarded_controls_preserve_seed_countdown_and_inclusive_bounds",
            || {
                initialize_test_owner();
                let heap = heap_new();
                assert!(!heap.is_null());
                // SAFETY: this thread retains the new Heap and initialized
                // selected sampler, excluding allocation and teardown while
                // its public controls and countdown are observed.
                unsafe {
                    let theap = heap_theap(heap);
                    let selected = NonNull::new(theap.cast::<Theap>()).unwrap();
                    theap_guarded_set_size_bound(theap, 81, 64);
                    theap_guarded_set_sample_rate(theap, 3, 1);
                    assert!(!Theap::guarded_sample_at(selected, 81));
                    assert!(Theap::guarded_sample_at(selected, 81));
                    assert!(!Theap::guarded_sample_at(selected, 81));
                    assert!(!Theap::guarded_sample_at(selected, 81));
                    assert!(!Theap::guarded_sample_at(selected, 80));
                    assert!(Theap::guarded_sample_at(selected, 81));
                    theap_guarded_set_sample_rate(theap, 1, 0);
                    assert!(Theap::guarded_sample_at(selected, 81));
                    assert!(!Theap::guarded_sample_at(selected, 82));
                    theap_guarded_set_sample_rate(theap, 0, 0);
                    assert!(!Theap::guarded_sample_at(selected, 81));
                    assert!(heap_release(heap, false));
                }
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-guarded", not(miri)))]
    unsafe fn guarded_tail_faults(client: NonNull<u8>, usable: usize) -> bool {
        unsafe extern "C" {
            fn fork() -> c_int;
            fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
            fn _exit(status: c_int) -> !;
        }
        // SAFETY: the isolated child only probes the retained client's tail
        // and exits without allocation or acquiring inherited owner locks.
        let child = unsafe { fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe { core::ptr::read_volatile(client.as_ptr().add(usable)); _exit(0) }
        }
        let mut status = 0;
        // SAFETY: this parent waits for its own probe child and retains its
        // stack status word until the synchronous wait returns.
        assert_eq!(unsafe { waitpid(child, &mut status, 0) }, child);
        status & 0x7f == 11
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-guarded", not(miri)))]
    #[test]
    fn aligned_guarded_eligibility_excludes_large_alignment_before_countdown() {
        crate::test_process::run_in_fresh_process(
            "source_heap_api::heap_membership_tests::aligned_guarded_eligibility_excludes_large_alignment_before_countdown",
            || {
                initialize_test_owner();
                let heap = heap_new();
                assert!(!heap.is_null());
                // SAFETY: this thread retains the initialized selected sampler;
                // all supplied alignments are valid powers of two.
                unsafe {
                    let theap = heap_theap(heap);
                    let selected = NonNull::new(theap.cast::<Theap>()).unwrap();
                    theap_guarded_set_sample_rate(theap, 2, 2);
                    theap_guarded_set_size_bound(theap, 81, 81);
                    for alignment in [crate::config::PAGE_MAX_OVERALLOC_ALIGN, 1usize << (usize::BITS - 1)] {
                        assert!(guarded_sample_source_request(selected, 81, Some((alignment, 0))).is_none());
                    }
                    assert!(guarded_sample_source_request(selected, 81, Some((64, 1))).is_none());
                    // The excluded calls did not advance the seed's first
                    // countdown: this eligible call samples immediately.
                    let sampled = guarded_sample_source_request(selected, 81, Some((64, 0)))
                        .expect("eligible alignment retains the first sample");
                    assert!(sampled.check_size().is_ok());
                    assert!(guarded_sample_source_request(selected, 81, Some((64, 0))).is_none());
                    assert!(heap_release(heap, false));
                }
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-guarded", not(miri)))]
    #[test]
    fn public_heap_guarded_sample_preserves_source_tag_and_usable_extent() {
        crate::test_process::run_in_fresh_process(
            "source_heap_api::heap_membership_tests::public_heap_guarded_sample_preserves_source_tag_and_usable_extent",
            || {
                initialize_test_owner();
                let heap = heap_new();
                assert!(!heap.is_null());
                // SAFETY: this thread retains its new Heap and selected Theap
                // until all clients are freed and the Heap is released.
                unsafe {
                    let theap = heap_theap(heap);
                    assert!(!theap.is_null());
                    theap_guarded_set_sample_rate(theap, 1, 1);
                    theap_guarded_set_size_bound(theap, 0, 100_000);
                    let block = heap_malloc(heap, 81).value.expect("a sampled Heap client");
                    let (binding, _) = crate::process_init::ProcessMainInitializationStorage::global()
                        .ready_child_subprocess_inputs().expect("the actual process owner");
                    let observed = binding.page_map().lookup_live_allocation(block)
                        .expect("registered page").expect("live client");
                    assert!(observed.is_guarded(), "a rate-one public Heap request must carry the source guarded tag");
                    assert_eq!(observed.usable_size(), 96);
                    drop(observed);
                    assert!(guarded_tail_faults(block, 96), "the selected Heap client's tail is physically protected");
                    block.as_ptr().write_bytes(0x61, 81);
                    let replaced = heap_realloc(heap, block.as_ptr(), 244, false).value.0
                        .expect("a replacement client");
                    for index in 0..81 { assert_eq!(replaced.as_ptr().add(index).read(), 0x61); }
                    assert!(guarded_tail_faults(replaced, crate::source_api::usable_size(replaced.as_ptr())),
                        "the sampled replacement keeps its physical tail guard");
                    assert_eq!(crate::source_api::free_sourced(replaced.as_ptr()).value, FreeOutcome::Freed);
                    assert!(heap_release(heap, false));
                }
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-guarded", not(miri)))]
    struct GuardedWarningProbe {
        heap: *mut c_void,
        os_warnings: core::sync::atomic::AtomicUsize,
        object_warnings: core::sync::atomic::AtomicUsize,
        nested_clients: core::sync::atomic::AtomicUsize,
        warning_order: core::sync::atomic::AtomicUsize,
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-guarded", not(miri)))]
    unsafe extern "C" fn guarded_heap_warning_reentry(message: *const core::ffi::c_char, argument: *mut c_void) {
        use core::sync::atomic::Ordering;
        if message.is_null() { return; }
        // SAFETY: the synchronous registration retains this fixture and the
        // NUL-terminated fragment. This projection is not allocator metadata.
        let probe = unsafe { &*argument.cast::<GuardedWarningProbe>() };
        let message = unsafe { core::ffi::CStr::from_ptr(message) }.to_bytes();
        if message.starts_with(b"cannot protect OS memory") {
            assert_eq!(probe.warning_order.compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed), Ok(0));
            probe.os_warnings.fetch_add(1, Ordering::Relaxed);
        }
        if !message.starts_with(b"failed to set a guard page behind an object") { return; }
        assert_eq!(probe.warning_order.compare_exchange(1, 2, Ordering::Relaxed, Ordering::Relaxed), Ok(1));
        probe.object_warnings.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the outer call retains this actual selected Heap and member.
        // No engine or Heap/Theap/Page reference survives warning dispatch.
        let nested = unsafe { heap_malloc(probe.heap, 32) }.value.expect("a legal nested Heap allocation");
        let (binding, _) = crate::process_init::ProcessMainInitializationStorage::global()
            .ready_child_subprocess_inputs().unwrap();
        let observed = unsafe { binding.page_map().lookup_live_allocation(nested) }.unwrap().unwrap();
        assert!(!observed.is_guarded(), "the source size bounds exclude the nested client");
        drop(observed);
        // SAFETY: this callback owns exactly the nested client through its free.
        unsafe { nested.as_ptr().write_bytes(0x47, 32) };
        assert_eq!(unsafe { crate::source_api::free_sourced(nested.as_ptr()) }.value, FreeOutcome::Freed);
        probe.nested_clients.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-guarded", not(miri)))]
    #[test]
    fn public_heap_guard_protection_refusal_keeps_client_and_allows_nested_allocation() {
        use core::sync::atomic::{AtomicUsize, Ordering};
        crate::test_process::run_in_fresh_process(
            "source_heap_api::heap_membership_tests::public_heap_guard_protection_refusal_keeps_client_and_allows_nested_allocation",
            || {
                initialize_test_owner();
                crate::source_options_api::option_set(crate::config::SourceOption::ShowErrors as c_int, 1);
                let heap = heap_new();
                assert!(!heap.is_null());
                let probe = GuardedWarningProbe { heap, os_warnings: AtomicUsize::new(0),
                    object_warnings: AtomicUsize::new(0), nested_clients: AtomicUsize::new(0),
                    warning_order: AtomicUsize::new(0) };
                let output = crate::process_init::process_output_owner().unwrap();
                // SAFETY: this thread exclusively retains the selected live
                // Heap fields and synchronous callback argument until reset.
                unsafe {
                    let selected = NonNull::new(heap_theap(heap).cast::<Theap>()).unwrap();
                    theap_guarded_set_sample_rate(selected.as_ptr().cast(), 1, 1);
                    theap_guarded_set_size_bound(selected.as_ptr().cast(), 81, 81);
                    output.register_output(Some(guarded_heap_warning_reentry),
                        (&probe as *const GuardedWarningProbe).cast_mut().cast());
                }
                let fault = crate::os::fault::install(crate::os::fault::Plan::at(
                    crate::os::fault::Point::Protect, 1, Errno::PERM));
                let protections = fault.capture_protection_ranges();
                // SAFETY: this actual Heap and its selected member remain live
                // across the real protection primitive and nested callback.
                let outer = unsafe { heap_malloc(heap, 81) }.value.expect("protection refusal keeps the client");
                let (binding, _) = crate::process_init::ProcessMainInitializationStorage::global()
                    .ready_child_subprocess_inputs().unwrap();
                let observed = unsafe { binding.page_map().lookup_live_allocation(outer) }.unwrap().unwrap();
                assert!(observed.is_guarded());
                assert_eq!(observed.usable_size(), 96);
                drop(observed);
                assert_eq!(probe.os_warnings.load(Ordering::Relaxed), 1);
                assert_eq!(probe.object_warnings.load(Ordering::Relaxed), 1);
                assert_eq!(probe.nested_clients.load(Ordering::Relaxed), 1);
                assert_eq!(probe.warning_order.load(Ordering::Relaxed), 2);
                // SAFETY: the exact outer client remains writable and is
                // returned once; its actual Heap remains live through cleanup.
                unsafe { outer.as_ptr().write_bytes(0x61, 81) };
                let guard_address = outer.as_ptr().addr() + 96;
                assert_eq!(unsafe { crate::source_api::free_sourced(outer.as_ptr()) }.value, FreeOutcome::Freed);
                let (ranges, count) = protections.attempts().expect("the real protection trace");
                let guard: Vec<_> = ranges[..count].iter().filter(|(address, length, _)|
                    *address == guard_address && *length == 4096).copied().collect();
                assert_eq!(guard, std::vec![(guard_address, 4096, 0), (guard_address, 4096, 3)],
                    "one refused PROT_NONE and one terminal read/write unprotect");
                unsafe { output.register_output(None, null_mut()) };
                drop(protections);
                fault.set(crate::os::fault::Plan::disabled());
                assert!(unsafe { heap_release(heap, false) });
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn live_interior_foreign_and_moved_page_queries_follow_page_identity() {
        crate::test_process::run_in_fresh_process(
            "source_heap_api::heap_membership_tests::live_interior_foreign_and_moved_page_queries_follow_page_identity",
            || {
                initialize_test_owner();
                let heap = native_heap_new().expect("a non-main Heap");
                // SAFETY: this newly created Heap stays live until its page
                // has moved to the main Heap.
                let block = unsafe { native_heap_allocate(heap, 64, None, false) }.expect("a live block");
                let pointer = block.as_ptr();
                let interior = pointer.wrapping_add(1);
                let foreign = 0u8;
                let selected = heap.as_ptr().cast();
                // SAFETY: the allocation and its PageMap slice stay live,
                // and no other thread can mutate this page in the fixture.
                unsafe {
                    assert_eq!(heap_of(pointer), selected);
                    assert_eq!(heap_of(interior), selected);
                    assert!(heap_contains(selected, pointer));
                    assert!(any_heap_contains(interior));
                    assert!(is_in_heap_region(interior));
                    assert!(!heap_contains(core::ptr::null_mut(), pointer));
                    assert!(!heap_page_is_under_utilized(selected, pointer, 100));
                    assert!(heap_of(core::ptr::null()).is_null());
                    assert!(!any_heap_contains(core::ptr::null()));
                    assert!(!is_in_heap_region(core::ptr::null()));
                    assert!(heap_of(&foreign).is_null());
                    assert!(!any_heap_contains(&foreign));
                    assert!(!is_in_heap_region(&foreign));
                    assert!(!heap_contains(selected, &foreign));
                    assert!(!heap_page_is_under_utilized(selected, (&foreign as *const u8).cast_mut(), 100));
                }
                // SAFETY: the Heap is live, its only page and block stay
                // mapped, and this thread alone performs the move.
                assert_eq!(unsafe { native_heap_release(heap, false) }, Ok(HeapReleaseOutcome::Released));
                let main = heap_main();
                // SAFETY: the moved block still retains its registered page;
                // no concurrent owner may move or retire it during the query.
                unsafe {
                    assert_eq!(heap_of(pointer), main);
                    assert_eq!(heap_of(interior), main);
                    assert!(heap_contains(core::ptr::null_mut(), interior));
                    assert!(any_heap_contains(pointer));
                    assert!(is_in_heap_region(interior));
                    assert!(!heap_page_is_under_utilized(main, pointer, 100));
                }
                // SAFETY: `block` remains exact and live after its Heap move.
                assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn live_aligned_block_frees_after_heap_delete() {
        crate::test_process::run_in_fresh_process(
            "source_heap_api::heap_membership_tests::live_aligned_block_frees_after_heap_delete",
            || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                crate::source_options_api::option_set(crate::config::SourceOption::ArenaReserve as i32, 0);
                let heap = native_heap_new().expect("a non-main Heap");
                // SAFETY: the Heap is live and this thread keeps the exact
                // block live through Heap deletion and the following free.
                let block = unsafe { native_heap_allocate(heap, 81, Some((128, 11)), true) }
                    .expect("one live aligned block");
                assert_eq!((block.as_ptr().addr() + 11) % 128, 0);
                // SAFETY: the exact live block has at least 81 initialized bytes.
                assert_eq!(unsafe { block.as_ptr().read() }, 0);
                // SAFETY: no other thread uses the Heap or its page here.
                assert_eq!(unsafe { native_heap_release(heap, false) }, Ok(HeapReleaseOutcome::Released));
                let (binding, _) = crate::process_init::ProcessMainInitializationStorage::global()
                    .ready_child_subprocess_inputs().expect("the live page map");
                // SAFETY: the exact live allocation retains its page, and
                // this thread excludes any concurrent page ownership move.
                let page = unsafe { binding.page_map().lookup_registered_page(block.as_ptr()) }
                    .expect("a readable map").expect("a registered page");
                let page_theap = unsafe { Page::theap_at(page) };
                assert_eq!(unsafe { heap_of(block.as_ptr()) }, heap.as_ptr().cast());
                assert!(!page_theap.is_null());
                assert_eq!(crate::subproc::main_heaps::retained_deleted_heap_owner_count_for_test(), Some(1));
                // SAFETY: deleting the Heap retains this exact live block
                // and its page registration until the caller frees it.
                assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
                assert_eq!(crate::subproc::main_heaps::retained_deleted_heap_owner_count_for_test(), Some(0));
                // The final retired OS page has left the process PageMap;
                // this lookup only probes its former address and dereferences nothing.
                assert!(unsafe { binding.page_map().lookup_registered_page(block.as_ptr()) }
                    .expect("a readable map").is_none());
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn deleted_heap_keeps_theap_until_last_os_page_retires() {
        crate::test_process::run_in_fresh_process(
            "source_heap_api::heap_membership_tests::deleted_heap_keeps_theap_until_last_os_page_retires",
            || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                crate::source_options_api::option_set(crate::config::SourceOption::ArenaReserve as i32, 0);
                let heap = native_heap_new().expect("a non-main Heap");
                // SAFETY: both exact allocations stay live until their
                // respective frees, and this thread owns the Heap throughout.
                let first = unsafe { native_heap_allocate(heap, 81, Some((128, 11)), true) }
                    .expect("the first aligned page");
                let last = unsafe { native_heap_allocate(heap, 1000, Some((128, 7)), true) }
                    .expect("the second aligned page");
                let (binding, _) = crate::process_init::ProcessMainInitializationStorage::global()
                    .ready_child_subprocess_inputs().expect("the live page map");
                // SAFETY: both client blocks are live and exclude concurrent
                // page movement during these registration observations.
                let first_page = unsafe { binding.page_map().lookup_registered_page(first.as_ptr()) }
                    .expect("a readable map").expect("the first page");
                let last_page = unsafe { binding.page_map().lookup_registered_page(last.as_ptr()) }
                    .expect("a readable map").expect("the last page");
                assert_ne!(first_page, last_page);
                assert!(unsafe { first_page.as_ref() }.memid().is_os());
                assert!(unsafe { last_page.as_ref() }.memid().is_os());
                // SAFETY: this thread excludes concurrent Heap use.
                assert_eq!(unsafe { native_heap_release(heap, false) }, Ok(HeapReleaseOutcome::Released));
                assert_eq!(crate::subproc::main_heaps::retained_deleted_heap_owner_count_for_test(), Some(1));
                // SAFETY: each exact live block is returned once, with no
                // competing owner of either ordinary page queue.
                assert_eq!(unsafe { native_free(first) }, NativePageFreeResult::Freed);
                assert_eq!(crate::subproc::main_heaps::retained_deleted_heap_owner_count_for_test(), Some(1));
                assert!(unsafe { binding.page_map().lookup_registered_page(last.as_ptr()) }
                    .expect("a readable map").is_some());
                assert_eq!(unsafe { native_free(last) }, NativePageFreeResult::Freed);
                assert_eq!(crate::subproc::main_heaps::retained_deleted_heap_owner_count_for_test(), Some(0));
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn remote_final_free_after_deleted_heap_owner_exit_preserves_page_membership() {
        crate::test_process::run_in_fresh_process(
            "source_heap_api::heap_membership_tests::remote_final_free_after_deleted_heap_owner_exit_preserves_page_membership",
            || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                crate::source_options_api::option_set(crate::config::SourceOption::ArenaReserve as i32, 0);
                let (sender, receiver) = std::sync::mpsc::channel();
                let (allow_exit, wait_for_exit) = std::sync::mpsc::channel();
                let (remote_handoff, remote_wait) = std::sync::mpsc::channel();
                let owner = std::thread::spawn(move || {
                    let descriptor = crate::__crabc_runtime::current_native_allocator_thread_descriptor();
                    // SAFETY: this fresh worker registers its own descriptor once.
                    assert!(unsafe { crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(descriptor) });
                    assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
                    let heap = native_heap_new().expect("a non-main Heap");
                    // SAFETY: this worker owns the Heap and the exact live
                    // block through deletion; it transfers the block address
                    // only after its page is retained by the process.
                    let block = unsafe { native_heap_allocate(heap, 81, Some((128, 11)), true) }
                        .expect("one OS-backed aligned block");
                    assert_eq!(unsafe { native_heap_release(heap, false) }, Ok(HeapReleaseOutcome::Released));
                    sender.send(block.as_ptr().addr()).expect("the block handoff");
                    wait_for_exit.recv().expect("the remote worker exists before owner exit");
                    assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
                });
                let remote = std::thread::spawn(move || {
                    let address = remote_wait.recv().expect("the former owner has exited");
                    let descriptor = crate::__crabc_runtime::current_native_allocator_thread_descriptor();
                    // SAFETY: this different worker registers its own descriptor once.
                    assert!(unsafe { crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(descriptor) });
                    let block = NonNull::new(address as *mut u8).expect("the transferred block");
                    // SAFETY: the original owner has exited, this worker is
                    // the sole holder of the exact live block, and it frees
                    // it once through the page's remote atomic list.
                    assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
                    assert!(unsafe { is_in_heap_region(block.as_ptr()) });
                    assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::NotAttached);
                });
                let address = receiver.recv().expect("the deleted Heap block");
                allow_exit.send(()).expect("allow the owner to finish");
                owner.join().expect("the original owner exits first");
                let block = NonNull::new(address as *mut u8).expect("the retained client address");
                assert!(unsafe { is_in_heap_region(block.as_ptr()) });
                remote_handoff.send(address).expect("give the remote worker its block");
                remote.join().expect("the remote free finishes");
                // Source leaves this detached OS page registered after both
                // workers have finished and the final client is gone.
                assert!(unsafe { is_in_heap_region(block.as_ptr()) });
                assert_eq!(crate::subproc::main_heaps::retained_deleted_heap_owner_count_for_test(), Some(1));
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-secure-3", not(miri)))]
    #[test]
    fn secure_page_visitation_decodes_free_chain_and_null_before_live_bitmap() {
        unsafe extern "C" fn collect_live(
            _: *const c_void, _: *const HeapArea, block: *mut c_void,
            _: usize, argument: *mut c_void,
        ) -> bool {
            if !block.is_null() {
                // SAFETY: the caller owns this vector throughout the synchronous visit.
                unsafe { &mut *argument.cast::<Vec<usize>>() }.push(block.addr());
            }
            true
        }
        crate::test_process::run_in_fresh_process(
            "source_heap_api::heap_membership_tests::secure_page_visitation_decodes_free_chain_and_null_before_live_bitmap",
            || {
                initialize_test_owner();
                let heap = native_heap_new().expect("a live Heap");
                // SAFETY: this thread owns the Heap and retains both clients and their page.
                let (first, survivor) = unsafe {
                    (native_heap_allocate(heap, 64, None, false).unwrap(),
                     native_heap_allocate(heap, 64, None, false).unwrap())
                };
                let (binding, _) = crate::process_init::ProcessMainInitializationStorage::global()
                    .ready_child_subprocess_inputs().unwrap();
                // SAFETY: both allocations retain their registered page, with no concurrent owner.
                let page = unsafe { binding.page_map().lookup_registered_page(survivor.as_ptr()) }
                    .unwrap().unwrap();
                assert_eq!(unsafe { binding.page_map().lookup_registered_page(first.as_ptr()) }.unwrap(), Some(page));
                // SAFETY: the live page and its immutable source keys remain retained.
                let keys = unsafe { Page::source_page_keys_at(page) };
                let metadata = unsafe { page.as_ref() };
                let blocks = unsafe { metadata.start() };
                let size = metadata.block_size();
                let capacity = metadata.capacity() as usize;
                let mut cursor = metadata.free_list_head();
                let mut count = 0;
                let mut expected = std::vec![0usize; capacity.div_ceil(usize::BITS as usize)];
                while !cursor.is_null() {
                    let index = (cursor.addr() - blocks.addr()) / size;
                    assert!(index < capacity && count < capacity);
                    expected[index / usize::BITS as usize] |= 1usize << (index % usize::BITS as usize);
                    // SAFETY: the quiescent production free chain owns this initialized next word.
                    let encoded = unsafe { cursor.cast::<usize>().read() };
                    let next = crate::free_list::decode_page_link(page.as_ptr().addr(), keys, encoded);
                    if next == 0 { assert_ne!(encoded, 0, "source NULL is encoded"); }
                    cursor = if next == 0 { null_mut() } else { cursor.map_addr(|_| next) };
                    count += 1;
                }
                assert!(count > 1, "a production chain ends in encoded NULL");
                let mut bitmap = std::vec![0usize; expected.len()];
                // SAFETY: the actual production page/free chain is stable for this bounded read.
                assert_eq!(unsafe { super::heap_visit_free_map(page, metadata.free_list_head(),
                    blocks, capacity * size, size, capacity, &mut bitmap) }, Some(count));
                assert_eq!(bitmap, expected);
                // SAFETY: first is returned once; survivor retains the page through collection.
                assert_eq!(unsafe { native_free(first) }, NativePageFreeResult::Freed);
                let mut live = Vec::new();
                // SAFETY: no callback moves pages or mutates the Heap, and the vector is retained.
                assert!(unsafe { heap_visit_blocks(heap.as_ptr().cast(), true, Some(collect_live),
                    (&mut live as *mut Vec<usize>).cast()) });
                assert_eq!(live, std::vec![survivor.as_ptr().addr()]);
                // SAFETY: the sole live client is returned once before releasing its owner.
                assert_eq!(unsafe { native_free(survivor) }, NativePageFreeResult::Freed);
                assert_eq!(unsafe { native_heap_release(heap, true) }, Ok(HeapReleaseOutcome::Released));
            },
        );
    }

    struct UtilizationPages {
        blocks: Vec<usize>,
        pairs: Vec<(usize, usize)>,
    }

    unsafe extern "C" fn find_utilization_pages(
        _: *const c_void,
        area: *const HeapArea,
        block: *mut c_void,
        _: usize,
        argument: *mut c_void,
    ) -> bool {
        if !block.is_null() || area.is_null() || argument.is_null() { return true; }
        // SAFETY: the test owns both the callback argument and this borrowed
        // area image until the callback returns; neither outlives this call.
        let probe = unsafe { &mut *argument.cast::<UtilizationPages>() };
        let area = unsafe { &*area };
        let start = area.blocks.addr();
        let end = start.saturating_add(area.committed);
        let mut found = probe.blocks.iter().copied().filter(|address| *address >= start && *address < end);
        if let (Some(victim), Some(survivor)) = (found.next(), found.next()) {
            probe.pairs.push((victim, survivor));
        }
        true
    }

    unsafe extern "C" fn collect_utilization_page(
        _: *const c_void,
        _: *const HeapArea,
        _: *mut c_void,
        _: usize,
        _: *mut c_void,
    ) -> bool {
        true
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn joined_remote_free_exposes_non_head_page_utilization() {
        crate::test_process::run_in_fresh_process(
            "source_heap_api::heap_membership_tests::joined_remote_free_exposes_non_head_page_utilization",
            || {
                initialize_test_owner();
                let heap = native_heap_new().expect("a non-main Heap");
                let selected = heap.as_ptr().cast();
                let mut probe = UtilizationPages { blocks: Vec::with_capacity(10_000), pairs: Vec::new() };
                for _ in 0..10_000 {
                    // SAFETY: the creating thread holds this Heap until its
                    // worker has joined and all queries have completed.
                    let block = unsafe { native_heap_allocate(heap, 64, None, false) }.expect("a page block");
                    probe.blocks.push(block.as_ptr().addr());
                }
                // SAFETY: all pages and the callback's borrowed probe remain
                // stable while this sole owner identifies page-local pairs.
                assert!(unsafe { heap_visit_blocks(selected, false, Some(find_utilization_pages),
                    (&mut probe as *mut UtilizationPages).cast()) });
                assert!(probe.pairs.len() >= 3);
                let victims: Vec<usize> = probe.pairs.iter().map(|pair| pair.0).collect();
                std::thread::spawn(move || {
                    let descriptor = crate::__crabc_runtime::current_native_allocator_thread_descriptor();
                    // SAFETY: this new worker registers its own descriptor once.
                    assert!(unsafe {
                        crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(descriptor)
                    });
                    assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
                    for address in victims {
                        let block = NonNull::new(address as *mut u8).expect("a retained victim");
                        // SAFETY: each exact block is transferred once to
                        // this worker; its Heap stays live until the join.
                        assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
                    }
                    assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
                }).join().expect("the remote producer finished");
                // SAFETY: the producer has joined, the Heap and pages remain
                // live, and the visitor only collects and observes them.
                assert!(unsafe { heap_visit_blocks(selected, true, Some(collect_utilization_page),
                    core::ptr::null_mut()) });
                let main = heap_main();
                let mut positives = 0usize;
                for (_, survivor) in &probe.pairs {
                    let pointer = *survivor as *mut u8;
                    // SAFETY: the survivor is an exact live block. The only
                    // remote producer joined before collection and queries.
                    if unsafe { heap_page_is_under_utilized(selected, pointer, 100) } {
                        positives += 1;
                        let interior = pointer.wrapping_add(1);
                        // SAFETY: the same retained block and quiescent page
                        // back every threshold and Heap-identity observation.
                        unsafe {
                            assert!(!heap_page_is_under_utilized(selected, pointer, 50));
                            assert!(!heap_page_is_under_utilized(main, pointer, 100));
                            assert!(heap_page_is_under_utilized(selected, interior, 100));
                            assert_eq!(heap_of(interior), selected);
                            assert!(is_in_heap_region(interior));
                        }
                    }
                }
                assert!(positives > 0, "a collected non-head page is observable");
                // SAFETY: no worker remains and this live Heap owns all
                // retained pages until destruction finishes.
                assert_eq!(unsafe { native_heap_release(heap, true) }, Ok(HeapReleaseOutcome::Released));
            },
        );
    }
}

/// The C `mi_heap_area_t` image passed only while one visitor call runs.
#[repr(C)]
pub struct HeapArea {
    blocks: *mut c_void,
    reserved: usize,
    committed: usize,
    used: usize,
    block_size: usize,
    full_block_size: usize,
    reserved1: *mut c_void,
}

/// The C `mi_block_visit_fun` callback.
///
/// # Safety
/// `heap`, `area`, and `block` belong to the current live visitor step;
/// the callee may inspect them only before returning. `argument` is the
/// caller-supplied pointer and must be used under that caller's contract.
pub type HeapBlockVisitor = unsafe extern "C" fn(
    heap: *const c_void,
    area: *const HeapArea,
    block: *mut c_void,
    block_size: usize,
    argument: *mut c_void,
) -> bool;

/// Marks one free block in the page-local visit bitmap.
fn mark_heap_visit_free_block(bitmap: &mut [usize], index: usize) -> bool {
    let word = index / usize::BITS as usize;
    let mask = 1usize << (index % usize::BITS as usize);
    if bitmap[word] & mask != 0 { return false; }
    bitmap[word] |= mask;
    true
}

/// Copies a stable page's immediate free-list membership into a visit bitmap.
///
/// # Safety
/// `free` is null or points inside the retained, exclusively owned `blocks`
/// area of `page`; its initialized links and immutable encoding keys remain
/// stable throughout traversal.
unsafe fn heap_visit_free_map(
    page: NonNull<Page>,
    mut free: *mut crate::types::Block,
    blocks: *mut u8,
    committed: usize,
    block_size: usize,
    capacity: usize,
    bitmap: &mut [usize],
) -> Option<usize> {
    #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
    // SAFETY: the caller retains the initialized page and its immutable keys.
    let keys = unsafe { Page::source_page_keys_at(page) };
    #[cfg(not(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3"))))]
    let _ = page;
    let mut free_count = 0usize;
    while !free.is_null() {
        let offset = (free as usize).checked_sub(blocks as usize)?;
        if offset >= committed || offset % block_size != 0 || free_count >= capacity { return None; }
        let index = offset / block_size;
        if !mark_heap_visit_free_block(bitmap, index) { return None; }
        free_count += 1;
        // SAFETY: the validated node is in the caller-retained free block
        // area, whose initialized next word remains stable during visitation.
        #[cfg(not(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3"))))]
        { free = unsafe { core::ptr::read(free.cast::<*mut crate::types::Block>()) }; }
        #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
        {
            // SAFETY: encoded links occupy the same initialized first word.
            let encoded = unsafe { core::ptr::read(free.cast::<usize>()) };
            let address = crate::free_list::decode_page_link(page.as_ptr().addr(), keys, encoded);
            free = if address == 0 { null_mut() } else { free.map_addr(|_| address) };
        }
    }
    Some(free_count)
}

/// Visits one page's area before any of its live blocks.
///
/// # Safety
/// `page` is a live page of `heap`, and no callback may retire or move that
/// page, mutate its free lists, or race its ordinary-field owner. The caller
/// keeps the page's arena slice registered for the whole call.
pub(crate) unsafe fn visit_heap_page(
    heap: NonNull<Heap>,
    page: NonNull<Page>,
    visit_blocks: bool,
    visitor: HeapBlockVisitor,
    argument: *mut c_void,
) -> bool {
    let (blocks, area, full_block_size) = {
        // SAFETY: the caller holds the live page and excludes ordinary-field
        // mutation while these source geometry scalars are copied.
        let page_ref = unsafe { page.as_ref() };
        if page_ref.heap() != heap.as_ptr() { return false; }
        let full_block_size = page_ref.block_size();
        let Some(block_size) = full_block_size.checked_sub(crate::config::PADDING_SIZE) else { return false };
        let Some(reserved) = full_block_size.checked_mul(page_ref.reserved() as usize) else { return false };
        let Some(committed) = full_block_size.checked_mul(page_ref.capacity() as usize) else { return false };
        // SAFETY: the caller's live page geometry covers the complete area.
        let blocks = unsafe { page_ref.start() };
        let area = HeapArea {
            blocks: blocks.cast(), reserved, committed, used: page_ref.used(),
            block_size, full_block_size, reserved1: page.as_ptr().cast(),
        };
        (blocks, area, full_block_size)
    };
    // SAFETY: the C caller supplied a live callback and argument; the area
    // image stays on this stack until it returns.
    if !unsafe { visitor(heap.as_ptr().cast(), &area, null_mut(), area.block_size, argument) } {
        return false;
    }
    if !visit_blocks { return true; }
    const MAX_BLOCKS: usize = crate::config::SMALL_PAGE_SIZE / core::mem::size_of::<usize>();
    const WORD_BITS: usize = usize::BITS as usize;
    // SAFETY: the callback left this page and its ordinary fields stable.
    let page_ref = unsafe { page.as_ref() };
    let capacity = page_ref.capacity() as usize;
    let used = page_ref.used();
    if capacity > MAX_BLOCKS || full_block_size == 0 { return false; }
    let mut free_map = [0usize; MAX_BLOCKS.div_ceil(WORD_BITS)];
    // SAFETY: the caller excludes mutation of every page free-list node.
    let Some(mut free_count) = (unsafe {
        heap_visit_free_map(page, page_ref.free_list_head(), blocks, area.committed, full_block_size, capacity, &mut free_map)
    }) else { return false };
    // When the immediate free list accounts for every unused block and no
    // remote head is published, forced collection cannot change this page's
    // live-block image. This also covers a page whose owner has exited.
    if free_count + used != capacity || page_ref.has_published_remote_free() {
        // SAFETY: the caller owns the stable page and its block area through
        // the remote and local collection steps for this page identity.
        if !unsafe { Page::collect_for_heap_visit_at(page) } { return false; }
        free_map.fill(0);
        // SAFETY: collection left the same page and block area live.
        let Some(collected_count) = (unsafe {
            heap_visit_free_map(page, page.as_ref().free_list_head(), blocks, area.committed, full_block_size, capacity, &mut free_map)
        }) else { return false };
        free_count = collected_count;
    }
    // SAFETY: any collection has finished before this ordinary-field read.
    let used = unsafe { page.as_ref() }.used();
    if free_count + used != capacity { return false; }
    if used == 0 { return true; }
    if capacity == 1 {
        // SAFETY: the one live block is the page area's first block.
        return unsafe { visitor(heap.as_ptr().cast(), &area, blocks.cast(), area.block_size, argument) };
    }
    for index in 0..capacity {
        if free_map[index / WORD_BITS] & (1usize << (index % WORD_BITS)) != 0 { continue; }
        // SAFETY: every index below capacity names a live block in the
        // caller-retained page area, and the callback cannot retire it.
        let block = unsafe { blocks.add(index * full_block_size) };
        if !unsafe { visitor(heap.as_ptr().cast(), &area, block.cast(), area.block_size, argument) } {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod heap_visit_tests {
    #[cfg(all(target_arch = "x86_64", feature = "mi-guarded", not(miri)))]
    struct GuardedVisitCapture {
        heap: *mut core::ffi::c_void,
        clients: [Option<core::ptr::NonNull<u8>>; 4],
        usable: [usize; 4],
        seen: [bool; 4],
        valid: bool,
        calls: usize,
        blocks: usize,
        stop: usize,
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-guarded", not(miri)))]
    unsafe extern "C" fn capture_guarded_visit(
        heap: *const core::ffi::c_void, area: *const super::HeapArea,
        block: *mut core::ffi::c_void, block_size: usize, argument: *mut core::ffi::c_void,
    ) -> bool {
        // SAFETY: the synchronous caller retains this exclusive capture and
        // the visitor's stack area image for the complete callback.
        let capture = unsafe { &mut *argument.cast::<GuardedVisitCapture>() };
        let area = unsafe { &*area };
        capture.calls += 1;
        capture.valid &= heap == capture.heap.cast_const()
            && area.full_block_size == area.block_size + crate::config::PADDING_SIZE
            && block_size == area.block_size;
        if !block.is_null() {
            capture.blocks += 1;
            let canonical = block.addr();
            // Source visitors expose canonical slots, including a guarded
            // client's tag word and guard page in the full slot geometry.
            capture.valid &= unsafe { block.cast::<usize>().read() } == usize::MAX;
            let mut matches = 0;
            for index in 0..capture.clients.len() {
                let Some(client) = capture.clients[index] else { continue };
                let offset = client.as_ptr().addr().wrapping_sub(canonical);
                if offset >= area.full_block_size { continue; }
                matches += 1;
                capture.valid &= !capture.seen[index] && offset >= core::mem::size_of::<usize>()
                    && area.full_block_size.checked_sub(offset).and_then(|size| size.checked_sub(4096))
                        == Some(capture.usable[index]);
                capture.seen[index] = true;
                // SAFETY: this exact retained client has its initialized
                // first object byte before the protected tail page.
                capture.valid &= unsafe { client.as_ptr().read() } == (index + 1) as u8;
            }
            capture.valid &= matches == 1;
        }
        capture.stop == 0 || capture.calls < capture.stop
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-guarded", not(miri)))]
    #[test]
    fn guarded_heap_visitation_reports_canonical_slots_and_retained_usable_prefixes() {
        crate::test_process::run_in_fresh_process(
            "source_heap_api::heap_visit_tests::guarded_heap_visitation_reports_canonical_slots_and_retained_usable_prefixes",
            || {
                unsafe extern "C" fn no_output(_: *const core::ffi::c_char) {}
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
                let heap = super::heap_new();
                assert!(!heap.is_null());
                // SAFETY: this thread retains the Heap, selected Theap and
                // all clients through quiescent traversal and final cleanup.
                unsafe {
                    let theap = super::heap_theap(heap);
                    super::theap_guarded_set_size_bound(theap, 0, usize::MAX);
                    super::theap_guarded_set_sample_rate(theap, 1, 1);
                    let mut clients = [None; 4];
                    let mut usable = [0; 4];
                    for (index, size) in [81, 97, 5000, 81].into_iter().enumerate() {
                        let result = if index == 3 {
                            super::heap_malloc_aligned_at(heap, size, 64, 0, false)
                        } else { super::heap_malloc(heap, size) };
                        let client = result.value.expect("a public sampled client");
                        client.as_ptr().write_bytes((index + 1) as u8, size);
                        usable[index] = crate::source_api::usable_size(client.as_ptr());
                        clients[index] = Some(client);
                    }
                    for stop in [0, 1, 2] {
                        let mut capture = GuardedVisitCapture { heap, clients, usable, seen: [false; 4],
                            valid: true, calls: 0, blocks: 0, stop };
                        assert_eq!(super::heap_visit_blocks(heap, true, Some(capture_guarded_visit),
                            core::ptr::from_mut(&mut capture).cast()), stop == 0);
                        assert!(capture.valid);
                        if stop == 0 {
                            assert_eq!(capture.blocks, clients.len());
                            assert_eq!(capture.seen, [true; 4]);
                        } else { assert_eq!(capture.calls, stop); }
                    }
                    let mut capture = GuardedVisitCapture { heap, clients, usable, seen: [false; 4],
                        valid: true, calls: 0, blocks: 0, stop: 0 };
                    assert!(crate::source_api::theap_visit_blocks(theap, true, Some(capture_guarded_visit),
                        core::ptr::from_mut(&mut capture).cast()));
                    assert!(capture.valid && capture.blocks > 0);
                    let freed = clients[1].take().unwrap();
                    assert_eq!(crate::source_api::free_sourced(freed.as_ptr()).value,
                        crate::source_api::FreeOutcome::Freed);
                    let mut capture = GuardedVisitCapture { heap, clients, usable, seen: [false; 4],
                        valid: true, calls: 0, blocks: 0, stop: 0 };
                    assert!(super::heap_visit_blocks(heap, true, Some(capture_guarded_visit),
                        core::ptr::from_mut(&mut capture).cast()));
                    assert!(capture.valid);
                    assert_eq!(capture.blocks, 3);
                    assert_eq!(capture.seen, [true, false, true, true]);
                    for client in clients.into_iter().flatten() {
                        assert_eq!(crate::source_api::free_sourced(client.as_ptr()).value,
                            crate::source_api::FreeOutcome::Freed);
                    }
                    assert!(super::heap_release(heap, false));
                }
            },
        );
    }

    #[test]
    fn cyclic_free_list_is_rejected_before_a_live_callback() {
        let mut blocks = [0usize; 2];
        let block_size = core::mem::size_of::<usize>();
        let second = blocks.as_mut_ptr().wrapping_add(1);
        let mut page = crate::types::Page::remote_free_test_page(2, 0);
        let page = core::ptr::NonNull::from(&mut page);
        #[cfg(not(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3"))))]
        let link = second.addr();
        #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
        // SAFETY: this initialized test page remains exclusive through traversal.
        let link = crate::free_list::encode_page_link(page.as_ptr().addr(),
            unsafe { crate::types::Page::source_page_keys_at(page) }, second.addr());
        // SAFETY: the second block is retained for this call and its next
        // word deliberately points back to itself to model a malformed list.
        unsafe { second.write(link) };
        let mut bitmap = [0usize; 1];
        // SAFETY: both blocks and the cyclic next word stay initialized and
        // exclusively owned through the bounded traversal.
        assert_eq!(unsafe {
            super::heap_visit_free_map(
                page, second.cast(), blocks.as_mut_ptr().cast(), 2 * block_size,
                block_size, 2, &mut bitmap,
            )
        }, None);
        assert_eq!(bitmap, [1usize << 1]);
    }
}

/// `mi_heap_visit_blocks` for a quiescent Heap of a live subprocess.
/// A null visitor is refused before Heap selection.
///
/// # Safety
/// `heap` is null or a live Heap of the calling thread's subprocess.
/// Every page of the selected Heap, its arena bitmap, and its block area stay
/// mapped and stable throughout traversal; no other thread owns or mutates
/// their ordinary fields or publishes remote frees during traversal. The
/// callback and `argument` remain callable, and the callback does not free,
/// move, or mutate a visited page or its blocks.
pub unsafe fn heap_visit_blocks(
    heap: *mut c_void,
    visit_blocks: bool,
    visitor: Option<HeapBlockVisitor>,
    argument: *mut c_void,
) -> bool {
    // SAFETY: caller retains the selected Heap, pages, and callback through
    // the same quiescent traversal used for the abandoned-only selection.
    unsafe { heap_visit_blocks_selected(heap, false, visit_blocks, visitor, argument) }
}

/// Visits only abandoned arena pages and OS-abandoned pages of a quiescent
/// Heap in a live subprocess. A null visitor is refused before
/// selecting the Heap.
///
/// # Safety
/// `heap` is null or a live Heap of the calling thread's subprocess. Every
/// selected page, arena bitmap, and block area stays mapped and stable during
/// traversal; no producer publishes a remote free. The callback and
/// `argument` remain callable and do not free, move, or mutate a visited
/// page or its blocks.
pub unsafe fn heap_visit_abandoned_blocks(
    heap: *mut c_void,
    visit_blocks: bool,
    visitor: Option<HeapBlockVisitor>,
    argument: *mut c_void,
) -> bool {
    // SAFETY: caller retains the selected abandoned pages and callback for
    // the quiescent source traversal.
    unsafe { heap_visit_blocks_selected(heap, true, visit_blocks, visitor, argument) }
}

/// Selects either all arena pages or only their abandoned-bin bitmaps.
///
/// # Safety
/// The caller retains the selected Heap, its published bitmap images, every
/// selected page and block area, and the callback without concurrent mutation.
unsafe fn heap_visit_blocks_selected(
    heap: *mut c_void,
    abandoned_only: bool,
    visit_blocks: bool,
    visitor: Option<HeapBlockVisitor>,
    argument: *mut c_void,
) -> bool {
    let Some(visitor) = visitor else { return false };
    let selected = if heap.is_null() { heap_main() } else { heap };
    let Some(heap) = NonNull::new(selected.cast::<Heap>()) else { return false };
    // SAFETY: caller keeps the Heap live and traversal quiescent.
    let heap_ref = unsafe { heap.as_ref() };
    // SAFETY: the caller retains the Heap's owning subprocess through this
    // traversal; its identity is immutable after Heap initialization.
    let Some(subprocess) = (unsafe { heap_ref.subprocess_pointer().as_ref() }) else { return false };
    // The caller retains this Heap's owning subprocess, including its
    // parent metadata custody. Registration admits every nesting depth;
    // traversal uses only this subprocess's own arena registry.
    if !subprocess.is_process_main() && !subprocess.is_registered() {
        return false;
    }
    let Some((binding, _)) = crate::process_init::ProcessMainInitializationStorage::global()
        .ready_child_subprocess_inputs() else { return false };
    let registry = subprocess.arena_backing().registry();
    for index in 0..registry.count() {
        // SAFETY: the caller excludes arena retirement for this traversal.
        let Some(arena) = (unsafe { registry.arena_at(index) }) else { continue };
        // SAFETY: the registered arena remains mapped and published.
        let Some(view) = (unsafe { crate::arena::ArenaView::from_ptr(core::ptr::from_ref(arena).cast_mut()) }) else {
            return false;
        };
        let pages = if heap_ref.is_subprocess_main() {
            if heap_ref.arena_pages_at(index) != Some(NonNull::from(&view.arena().pages_main)) {
                continue;
            }
            // SAFETY: the installed main Heap slot retains this arena's
            // embedded bitmap, and the caller excludes its retirement.
            unsafe { view.pages() }
        } else {
            // SAFETY: the installed Heap bitmap and arena remain live.
            unsafe { heap_ref.non_main_arena_pages_bitmap(&view, 0) }
        };
        let Some(pages) = pages else { continue };
        let visit_page_set = |selected: &crate::bitmap::BitmapView<'_>| selected.visit_set_bits(|slice, _| {
            let Some(start) = view.slice_start(slice) else { return false };
            // SAFETY: a set Heap bit retains the registered page at this
            // slice; caller exclusion keeps its mapping stable.
            let Some(page) = (unsafe { binding.page_map().lookup_registered_page(start) }).ok().flatten() else {
                return false;
            };
            // SAFETY: forwarded Heap, page, and callback stability.
            unsafe { visit_heap_page(heap, page, visit_blocks, visitor, argument) }
        });
        if abandoned_only {
            for bin in 0..crate::config::ARENA_BIN_COUNT {
                if !heap_ref.has_abandoned_page_in_bin(bin) { continue; }
                let abandoned = if heap_ref.is_subprocess_main() {
                    let Some(layout) = crate::bitmap::BitmapLayout::for_bit_count(view.arena().slice_count) else {
                        return false;
                    };
                    // SAFETY: the installed process-main arena image retains
                    // this initialized bin bitmap for the complete visit.
                    unsafe { crate::bitmap::BitmapView::attach(
                        view.arena().pages_main.pages_abandoned[bin], layout.byte_size(), layout,
                    ) }
                } else {
                    // SAFETY: the non-main Heap's published arena-pages image
                    // and its bin bitmap remain live during this traversal.
                    unsafe { heap_ref.non_main_arena_pages_bitmap(&view, bin + 1) }
                };
                let Some(abandoned) = abandoned else { return false };
                if !visit_page_set(&abandoned) { return false; }
            }
        } else if !visit_page_set(&pages) {
            return false;
        }
    }
    // Source visits the Heap's OS-abandoned list after all arena bitmaps.
    // SAFETY: caller exclusion keeps the private list stable.
    let mut current = unsafe { Heap::os_abandoned_head_at(heap) };
    while let Some(page) = NonNull::new(current) {
        // SAFETY: read the successor before invoking the callback.
        current = unsafe { Page::next_at(page) };
        // SAFETY: forwarded stable Heap and page obligations.
        if !unsafe { visit_heap_page(heap, page, visit_blocks, visitor, argument) } { return false; }
    }
    true
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
    // SAFETY: this live Heap belongs to the calling thread's subprocess.
    let selected = unsafe { heap_theap(heap.as_ptr().cast()) };
    if selected.is_null() {
        return Sourced { value: None, errno: SourceErrno::Unchanged };
    }
    if let Request::Aligned { alignment, offset } = request {
        if !crate::size_class::alignment_is_valid(alignment) {
            return Sourced { value: None, errno: crate::source_api::source_error_errno(
                SourceErrorReport::BadAlignment { size, alignment, offset }) };
        }
    }
    #[cfg(all(target_arch = "x86_64", feature = "mi-guarded"))]
    {
        let selected_theap = NonNull::new(selected.cast::<Theap>()).unwrap();
        let aligned = match request {
            Request::Plain => None,
            Request::Aligned { alignment, offset } => Some((alignment, offset)),
        };
        // Fixed aligned ingress delegates its one sample to the native aligned
        // entry. Plain and auxiliary aligned ingress sample this exact Theap.
        let native_aligned = aligned.is_some() && (fixed_runtime_theap() == Some(selected_theap)
            || crate::subproc::lifecycle::current_child_main_heap() == Some(heap));
        if !native_aligned {
            if let Some(result) = guarded_public_result(unsafe {
                guarded_allocate_selected(selected_theap, size, aligned, zero)
            }) { return result; }
        }
    }
    if fixed_runtime_theap().is_some_and(|fixed| fixed.as_ptr().cast::<c_void>() == selected) {
        return match (request, zero) {
            (Request::Plain, false) => crate::source_api::malloc_zero_native(size, false),
            (Request::Plain, true) => crate::source_api::malloc_zero_native(size, true),
            (Request::Aligned { alignment, offset }, false) => crate::source_api::malloc_zero_aligned_at_native(size, alignment, offset, false),
            (Request::Aligned { alignment, offset }, true) => crate::source_api::malloc_zero_aligned_at_native(size, alignment, offset, true),
        };
    }
    if crate::subproc::lifecycle::current_child_main_heap() == Some(heap) {
        // The child main Heap uses this member's fixed Theap. Selecting it
        // restores the cached source Theap before direct Heap allocation.
        // SAFETY: the current child member retains its main Heap and Theap.
        if !unsafe { crate::subproc::lifecycle::native_child_heap_select_theap(heap) } {
            return Sourced { value: None, errno: report_failure(size, request) };
        }
        return match (request, zero) {
            (Request::Plain, false) => crate::source_api::malloc_zero_native(size, false),
            (Request::Plain, true) => crate::source_api::malloc_zero_native(size, true),
            (Request::Aligned { alignment, offset }, false) => crate::source_api::malloc_zero_aligned_at_native(size, alignment, offset, false),
            (Request::Aligned { alignment, offset }, true) => crate::source_api::malloc_zero_aligned_at_native(size, alignment, offset, true),
        };
    }
    if let Request::Aligned { alignment, offset } = request {
        if let Some(report) = SourceErrorReport::aligned_precheck(size, alignment, offset) {
            return Sourced { value: None, errno: crate::source_api::source_error_errno(report) };
        }
    }
    let child_member = crate::subproc::lifecycle::current_thread_is_child_member();
    let child_page_alignment_refusal = match request {
        Request::Aligned { alignment, offset: 0 }
            if child_member && alignment >= crate::config::PAGE_META_ALIGNMENT => Some(alignment),
        _ => None,
    };
    if child_page_alignment_refusal.is_some() {
        // `_mi_heap_theap` precedes the allocation attempt even when the OS
        // page geometry later refuses this alignment.
        // SAFETY: forwarded Heap and current-child obligations.
        if !unsafe { crate::subproc::lifecycle::native_child_heap_select_theap(heap) } {
            return Sourced { value: None, errno: report_failure(size, request) };
        }
    }
    let block = if child_member {
        let aligned = match request {
            Request::Plain => None,
            Request::Aligned { alignment, offset } => Some((alignment, offset)),
        };
        // SAFETY: forwarded Heap contract.
        unsafe { crate::subproc::lifecycle::native_child_heap_allocate_variant(heap, size, aligned, zero) }.flatten()
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
    let prior_errno = if let Some(alignment) = child_page_alignment_refusal {
        // Each of `mi_find_page`'s two attempts reaches the same OS-page
        // alignment refusal before the generic fallback reports OOM.
        for _ in 0..2 {
            crate::process_init::process_warning_message(
                SourceFormattedMessage::page_alignment_too_large(alignment),
            );
        }
        SourceErrno::Store(Errno::INVAL)
    } else {
        SourceErrno::Unchanged
    };
    Sourced { value: None, errno: prior_errno.then(report_failure(size, request)) }
}

/// The failed `_mi_malloc_generic`'s reports: `mi_find_page` refuses a
/// too-large request before and after its forced collection, then the
/// generic fallback reports out of memory.
fn report_failure(size: usize, request: Request) -> SourceErrno {
    let size = match request {
        Request::Plain => size,
        Request::Aligned { alignment, offset } => {
            let Some((binding, _)) = crate::process_init::ProcessMainInitializationStorage::global()
                .ready_child_subprocess_inputs() else { return SourceErrno::Unchanged };
            let Ok(config) = binding.page_map().memory_config() else { return SourceErrno::Unchanged };
            crate::aligned::allocation_failure_request(size, alignment, offset, config.page_size().bytes())
        }
    };
    let mut errno = SourceErrno::Unchanged;
    if size > crate::config::MAX_ALLOC_SIZE {
        for _ in 0..2 {
            let report = SourceErrorReport::AllocationTooLarge { size };
            errno = errno.then(crate::source_api::source_error_errno(report));
        }
    }
    let report = SourceErrorReport::OutOfMemory { size };
    errno.then(crate::source_api::source_error_errno(report))
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
        None => Sourced { value: None, errno: crate::source_api::count_size_overflow_errno(count, size) },
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
        None => Sourced { value: None, errno: crate::source_api::count_size_overflow_errno(count, size) },
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
        None => {
            // SAFETY: the aligned Heap wrapper selects before checking counts.
            let _ = unsafe { resolve_heap_target(heap) };
            Sourced { value: None, errno: crate::source_api::count_size_overflow_errno(count, size) }
        },
    }
}

/// `mi_heap_delete` or, with `destroy`, `mi_heap_destroy`. `false` when a
/// legal release could not complete (its owners are retained).
///
/// # Safety
/// `heap` is null or a live Heap that no other thread uses during the call;
/// after a destroy no block of it is used again. A foreign child Heap may be
/// destroyed after its owner thread exits.
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
    let reserved = if crate::subproc::lifecycle::current_thread_is_child_member() {
        crate::subproc::lifecycle::native_child_reserve_os_memory(size, commit, allow_large, exclusive)
            .unwrap_or(Err(crate::arena::ReserveOsMemoryFailure::Unmanaged))
    } else {
        main_heaps::native_reserve_os_memory(size, commit, allow_large, exclusive)
    };
    match reserved {
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

#[cfg(test)]
mod reserve_os_failure_tests {
    extern crate std;
    use super::*;
    use crate::os::fault;

    unsafe extern "C" fn no_output(_: *const core::ffi::c_char) {}

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn public_reserve_os_memory_map_failure_clears_output_and_keeps_arena_count() {
        crate::test_process::run_in_fresh_process(
            "source_heap_api::reserve_os_failure_tests::public_reserve_os_memory_map_failure_clears_output_and_keeps_arena_count",
            || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
                let backing = MainSubprocess::global().arena_backing();
                let before = backing.registry().count();
                let fault = fault::install(fault::Plan::every(fault::Point::Map, Errno::NOMEM));
                let mut arena_id = 1usize as *mut c_void;
                // SAFETY: the local output is writable and every primitive
                // map attempt is forced to fail before arena publication.
                let result = unsafe { reserve_os_memory_ex(64 * 1024 * 1024,
                    true, false, true, &mut arena_id) };
                assert_eq!(result.value, Errno::NOMEM.raw());
                assert_eq!(result.errno, SourceErrno::Store(Errno::NOMEM));
                assert!(arena_id.is_null());
                assert!(fault.observed() > 0);
                assert_eq!(backing.registry().count(), before);
            },
        );
    }
}

/// `mi_reserve_huge_os_pages_at_ex` clears its output before the zero-page
/// return, then reserves huge backing in the calling subprocess arena group.
/// A child reservation retains its own VM and detached metadata admission.
/// A failed primitive returns `ENOMEM`; the actual failing mapping error
/// remains the C `errno` effect.
///
/// # Safety
/// `arena_id` is null or writable. A returned non-null arena ID stays live
/// until its owning subprocess retires the arena.
pub unsafe fn reserve_huge_os_pages_at_ex(
    pages: usize,
    numa_node: c_int,
    timeout_milliseconds: usize,
    exclusive: bool,
    arena_id: *mut *mut c_void,
) -> Sourced<c_int> {
    if !arena_id.is_null() {
        // SAFETY: the caller supplies the writable output.
        unsafe { arena_id.write(null_mut()) };
    }
    if pages == 0 {
        return Sourced { value: 0, errno: SourceErrno::Unchanged };
    }
    #[cfg(target_arch = "x86_64")]
    if let Some(admission) = crate::subproc::lifecycle::NativeChildArenaAdmission::acquire_current() {
        let Ok(admission) = admission else {
            return Sourced { value: Errno::NOMEM.raw(), errno: SourceErrno::Unchanged };
        };
        // SAFETY: this member alone owns its default Theap random image.
        let mut random = unsafe { crate::os::CurrentDefaultTheapRandom::new() };
        let warning = crate::process_init::process_output_owner()
            .map(crate::diagnostic_output::HugePageWarningRoute::new);
        // SAFETY: the owned admission retains every unpublished child mapping
        // and transfers publication only into its own arena registry.
        let (reserved, errno) = unsafe { crate::arena::ProcessArenaBacking::reserve_huge_at_for_child(
            admission, pages, numa_node, timeout_milliseconds, exclusive, Some(&mut random), warning) };
        return unsafe { huge_reservation_public_result(reserved, errno, arena_id) };
    }
    #[cfg(not(target_arch = "x86_64"))]
    if crate::subproc::lifecycle::current_thread_is_child_member() {
        return Sourced { value: Errno::NOMEM.raw(), errno: SourceErrno::Unchanged };
    }
    let Some((binding, _)) = crate::process_init::ProcessMainInitializationStorage::global()
        .ready_child_subprocess_inputs() else {
            return Sourced { value: Errno::NOMEM.raw(), errno: SourceErrno::Unchanged };
        };
    let Ok(config) = binding.page_map().memory_config() else {
        return Sourced { value: Errno::NOMEM.raw(), errno: SourceErrno::Unchanged };
    };
    let Some(_active) = crate::runtime_lifecycle::NativeSubprocessOperation::enter() else {
        return Sourced { value: Errno::NOMEM.raw(), errno: SourceErrno::Unchanged };
    };
    let process = binding.process();
    let mut random = unsafe { crate::os::CurrentDefaultTheapRandom::new() };
    let backing = MainSubprocess::global().arena_backing();
    let metadata = crate::meta::MetaAllocator::global();
    #[cfg(target_arch = "x86_64")]
    let warning = crate::process_init::process_output_owner()
        .map(crate::diagnostic_output::HugePageWarningRoute::new);
    // SAFETY: the admitted operation retains the process and arena group;
    // the calling Theap exclusively owns the random image during this call.
    let (reserved, primitive_errno) = unsafe { backing.reserve_huge_at_reporting_errno(
        process, config, metadata, pages, numa_node, timeout_milliseconds, exclusive,
        Some(&mut random), #[cfg(target_arch = "x86_64")] warning) };
    unsafe { huge_reservation_public_result(reserved, primitive_errno, arena_id) }
}

/// Caller retains the writable output through this exact publication result.
unsafe fn huge_reservation_public_result(
    reserved: Result<Option<crate::arena::ArenaId>, crate::arena::HugeArenaReserveError>,
    primitive_errno: SourceErrno, arena_id: *mut *mut c_void,
) -> Sourced<c_int> {
    match reserved {
        Ok(arena) => {
            if let (Some(arena), false) = (arena, arena_id.is_null()) {
                // SAFETY: forwarded writable output and published arena owner.
                unsafe { arena_id.write(arena.as_ptr().cast()) };
            }
            Sourced { value: 0, errno: primitive_errno }
        }
        Err(_) => Sourced { value: Errno::NOMEM.raw(), errno: primitive_errno },
    }
}

/// Reserve huge pages in the calling thread's subprocess arena group.
/// A nonempty partial primitive prefix is a successful reservation.
pub fn reserve_huge_os_pages_at(
    pages: usize, numa_node: c_int, timeout_milliseconds: usize,
) -> Sourced<c_int> {
    // SAFETY: no arena output is requested; the owning subprocess retains it.
    unsafe { reserve_huge_os_pages_at_ex(pages, numa_node, timeout_milliseconds, false, null_mut()) }
}

/// Distribute huge pages across NUMA nodes, stopping at the first failed node.
/// Previously published arenas remain owned by the calling subprocess.
pub fn reserve_huge_os_pages_interleave(
    pages: usize, numa_nodes: usize, timeout_milliseconds: usize,
) -> Sourced<c_int> {
    if pages == 0 { return Sourced { value: 0, errno: SourceErrno::Unchanged }; }
    let detected_nodes = if numa_nodes > 0 && numa_nodes <= c_int::MAX as usize { 1 }
        else { crate::process_init::ProcessMainInitializationStorage::global()
            .ready_child_subprocess_inputs().map_or(1, |(binding, _)| binding.process().policy().numa_node_count()) };
    let mut errno = SourceErrno::Unchanged;
    let result = crate::arena::ProcessArenaBacking::interleave_huge_reservations(
        pages, numa_nodes, detected_nodes, timeout_milliseconds, |count, node, timeout| {
            let result = reserve_huge_os_pages_at(count, node, timeout);
            if result.errno != SourceErrno::Unchanged { errno = result.errno; }
            if result.value == 0 { Ok(()) } else { Err(result.value) }
        });
    Sourced { value: result.err().unwrap_or(0), errno }
}

/// Deprecated source entry: warn, clear the output, and interleave reservations.
/// The output reports the requested count only when every node succeeds;
/// partial successful arenas remain live after a later node fails.
///
/// # Safety
/// `pages_reserved` is null or writable for one `usize`.
pub unsafe fn reserve_huge_os_pages(
    pages: usize, max_seconds: f64, pages_reserved: *mut usize,
) -> Sourced<c_int> {
    // The deprecation warning can call user output before any node request.
    // Retain an actual child admission across that callback and the complete
    // interleave sequence, without borrowing its record or membership slot.
    #[cfg(target_arch = "x86_64")]
    let _warning_admission = crate::subproc::lifecycle::NativeChildArenaAdmission::acquire_current();
    if let Some((binding, _)) = crate::process_init::ProcessMainInitializationStorage::global()
        .ready_child_subprocess_inputs() {
        binding.process().policy().source_warning(SourceFormattedMessage::from_source_formatted(
            c"mi_reserve_huge_os_pages is deprecated: use mi_reserve_huge_os_pages_interleave/at instead\n"));
    }
    if !pages_reserved.is_null() {
        // SAFETY: the caller supplies the writable output.
        unsafe { pages_reserved.write(0) };
    }
    let result = reserve_huge_os_pages_interleave(pages, 0, (max_seconds * 1000.0) as usize);
    if result.value == 0 && !pages_reserved.is_null() {
        // SAFETY: the same output remains writable through this call.
        unsafe { pages_reserved.write(pages) };
    }
    result
}

#[cfg(test)]
mod huge_at_ex_tests {
    extern crate std;
    use super::*;
    use crate::os::fault;

    unsafe extern "C" fn no_output(_: *const core::ffi::c_char) {}

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn public_huge_partial_success_keeps_the_failed_mapping_errno() {
        crate::test_process::run_in_fresh_process(
            "source_heap_api::huge_at_ex_tests::public_huge_partial_success_keeps_the_failed_mapping_errno",
            || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
                let before = MainSubprocess::global().arena_backing().registry().count();
                let fault = fault::install(fault::Plan::at(fault::Point::HugeMap, 2, Errno::IO));
                fault.enable_one_synthetic_huge_map();
                let result = reserve_huge_os_pages_at(2, -1, 0);
                assert_eq!(result.value, 0);
                assert_eq!(MainSubprocess::global().arena_backing().registry().count(), before + 1);
                assert_eq!(result.errno, SourceErrno::Store(Errno::IO));
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn public_huge_interleave_keeps_successful_nodes_after_a_later_failure() {
        crate::test_process::run_in_fresh_process(
            "source_heap_api::huge_at_ex_tests::public_huge_interleave_keeps_successful_nodes_after_a_later_failure",
            || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
                let backing = MainSubprocess::global().arena_backing();
                let before = backing.registry().count();
                let fault = fault::install(fault::Plan::at(fault::Point::HugeMap, 2, Errno::IO));
                fault.enable_one_synthetic_huge_map();
                let result = reserve_huge_os_pages_interleave(2, 2, 0);
                assert_eq!(result.value, Errno::NOMEM.raw());
                assert_eq!(result.errno, SourceErrno::Store(Errno::IO));
                assert_eq!(backing.registry().count(), before + 1);
                assert!(!backing.huge_cleanup_pending());
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn deprecated_huge_reservation_reports_requested_pages_for_a_partial_prefix() {
        crate::test_process::run_in_fresh_process(
            "source_heap_api::huge_at_ex_tests::deprecated_huge_reservation_reports_requested_pages_for_a_partial_prefix",
            || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
                let fault = fault::install(fault::Plan::at(fault::Point::HugeMap, 2, Errno::IO));
                fault.enable_one_synthetic_huge_map();
                let mut pages_reserved = usize::MAX;
                // SAFETY: the source output remains writable through the call.
                let result = unsafe { reserve_huge_os_pages(2, 0.0, &mut pages_reserved) };
                assert_eq!(result.value, 0);
                assert_eq!(result.errno, SourceErrno::Store(Errno::IO));
                assert_eq!(pages_reserved, 2);
                fault.set(fault::Plan::every(fault::Point::HugeMap, Errno::IO));
                let result = unsafe { reserve_huge_os_pages(1, 0.0, &mut pages_reserved) };
                assert_eq!(result.value, Errno::NOMEM.raw());
                assert_eq!(pages_reserved, 0);
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn public_child_huge_reservation_uses_its_own_primitive_and_arena_group() {
        use crate::subproc::lifecycle::{native_subproc_new, native_subproc_add_current_thread,
            native_child_thread_done, native_subproc_destroy, NativeChildThreadAdd};
        crate::test_process::run_in_fresh_process(
            "source_heap_api::huge_at_ex_tests::public_child_huge_reservation_uses_its_own_primitive_and_arena_group",
            || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
                let main_count = MainSubprocess::global().arena_backing().registry().count();
                let id = native_subproc_new().expect("child");
                std::thread::spawn(move || {
                    assert!(unsafe { crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(
                        crate::__crabc_runtime::current_native_allocator_thread_descriptor()) });
                    assert_eq!(unsafe { native_subproc_add_current_thread(id) }, Ok(NativeChildThreadAdd::Added));
                    let admission = crate::subproc::lifecycle::NativeChildArenaAdmission::acquire_current()
                        .expect("child member").expect("original identity admission");
                    let child_identity = unsafe { admission.process() }.subprocess() as *const _ as *mut c_void;
                    drop(admission);
                    let fault = fault::install(fault::Plan::every(fault::Point::HugeMap, Errno::IO));
                    let failed = reserve_huge_os_pages_at(1, -1, 0);
                    assert_eq!(failed.value, Errno::NOMEM.raw());
                    assert_eq!(failed.errno, SourceErrno::Store(Errno::IO));
                    fault.set(fault::Plan::disabled());
                    fault.enable_one_synthetic_huge_map();
                    let mut arena = null_mut();
                    // SAFETY: the output is writable; the child owns its arena.
                    let result = unsafe { reserve_huge_os_pages_at_ex(1, -1, 0, true, &mut arena) };
                    assert_eq!(result.value, 0);
                    assert!(!arena.is_null());
                    // SAFETY: publication returned a live arena of this member.
                    assert_eq!(unsafe { (*arena.cast::<crate::types::Arena>()).subprocess }.cast::<c_void>(), child_identity);
                    // SAFETY: this thread retains the published child arena
                    // and the explicit Heap through its client and final free.
                    let heap = unsafe { heap_new_in_arena(arena) };
                    assert!(!heap.is_null());
                    let block = unsafe { heap_malloc(heap, 80) }.value.expect("client from exclusive child huge arena");
                    let mut area_size = 0;
                    let area = unsafe { arena_area(arena, &mut area_size) };
                    assert!(block.as_ptr().addr() >= area.addr());
                    assert!(block.as_ptr().addr() + 80 <= area.addr() + area_size);
                    unsafe {
                        block.as_ptr().write_volatile(0x3c);
                        block.as_ptr().add(79).write_volatile(0x6d);
                        assert_eq!(block.as_ptr().read_volatile(), 0x3c);
                        assert_eq!(block.as_ptr().add(79).read_volatile(), 0x6d);
                        assert_eq!(crate::source_api::free(block.as_ptr()), crate::source_api::FreeOutcome::Freed);
                        assert!(heap_release(heap, false));
                    }
                    assert_eq!(MainSubprocess::global().arena_backing().registry().count(), main_count);
                    assert_eq!(native_child_thread_done(), Some(Ok(())));
                }).join().expect("child huge reservation");
                assert_eq!(unsafe { native_subproc_destroy(id) }, Ok(()));
            },
        );
    }

    #[test]
    fn public_huge_reservation_variants_accept_zero_without_an_arena() {
        assert_eq!(reserve_huge_os_pages_at(0, -2, usize::MAX).value, 0);
        assert_eq!(reserve_huge_os_pages_interleave(0, usize::MAX, usize::MAX).value, 0);
        let mut reserved = usize::MAX;
        // SAFETY: the reserved-page output is writable.
        let result = unsafe { reserve_huge_os_pages(0, 0.0, &mut reserved) };
        assert_eq!(result.value, 0);
        assert_eq!(reserved, 0);
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn public_huge_at_ex_zero_and_failed_primitive_preserve_arena_owner() {
        crate::test_process::run_in_fresh_process(
            "source_heap_api::huge_at_ex_tests::public_huge_at_ex_zero_and_failed_primitive_preserve_arena_owner",
            || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
                let mut id = 1usize as *mut c_void;
                // SAFETY: `id` is writable, and zero pages require no backing.
                let zero = unsafe { reserve_huge_os_pages_at_ex(0, -2, usize::MAX, true, &mut id) };
                assert_eq!(zero.value, 0);
                assert_eq!(zero.errno, SourceErrno::Unchanged);
                assert!(id.is_null());
                let backing = MainSubprocess::global().arena_backing();
                let before = backing.registry().count();
                let _fault = fault::install(fault::Plan::every(fault::Point::HugeMap, Errno::NOMEM));
                id = 1usize as *mut c_void;
                // SAFETY: `id` is writable; every huge primitive mapping is
                // forced to fail before an arena can own physical backing.
                let failed = unsafe { reserve_huge_os_pages_at_ex(1, -2, 0, true, &mut id) };
                assert_eq!(failed.value, Errno::NOMEM.raw());
                assert_eq!(failed.errno, SourceErrno::Store(Errno::NOMEM));
                assert!(id.is_null());
                assert_eq!(backing.registry().count(), before);
                assert!(!backing.huge_cleanup_pending());
            },
        );
    }
}

// ---------------------------------------------------------------------------
// Heap reallocation (`alloc.c:379-530`, `alloc-aligned.c:344-424`)
// ---------------------------------------------------------------------------

use crate::source_api::{FreeOutcome, SourceCRuntime};

const WORD: usize = core::mem::size_of::<usize>();

/// An explicit main Heap uses its fixed Theap; every other Heap uses the
/// calling thread's selected Theap image of that Heap.
enum Target {
    Main,
    NonMain(NonNull<Heap>),
}

/// Resolve the Heap before a kernel can reuse a block or refuse its request.
///
/// # Safety
/// `heap` is null or a live Heap of the calling thread's subprocess.
unsafe fn resolve_heap_target(heap: *mut c_void) -> Option<Target> {
    let identity = NonNull::new(heap.cast::<Heap>())?;
    // SAFETY: forwarded current-thread Heap and Theap lifetime.
    if unsafe { heap_theap(heap) }.is_null() { return None; }
    if is_main_heap(identity) { Some(Target::Main) } else { Some(Target::NonMain(identity)) }
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
    #[cfg(feature = "mi-debug-1")]
    // SAFETY: forwarded null/exact-live-block and exclusion obligations.
    if let Some(errno) = unsafe { crate::source_api::pointer_validation_errno(block, crate::diagnostic_output::SourcePointerOperation::Realloc) } {
        return Sourced { value: (None, FreeOutcome::RejectedCorruption), errno };
    }
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
    let size = unsafe { crate::runtime_lifecycle::native_usable_size(live) }.unwrap_or(0);
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
        let usable = crate::runtime_lifecycle::native_usable_size(replacement).unwrap_or(0);
        if zero && usable > zero_start {
            replacement.as_ptr().add(zero_start).write_bytes(0, usable - zero_start);
        } else if new_size == 0 {
            replacement.as_ptr().write(0);
        }
        core::ptr::copy_nonoverlapping(block, replacement.as_ptr(), copy);
    }
    // SAFETY: the old block is freed once, after the copy.
    let freed = unsafe { crate::source_api::free_sourced(block) };
    Sourced { value: (Some(replacement), freed.value), errno: result.errno.then(freed.errno) }
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
        return Sourced { value: (None, FreeOutcome::Freed), errno: crate::source_api::source_error_errno(report) };
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
    let observed = unsafe { crate::source_api::usable_size_sourced(block) };
    let size = observed.value;
    if new_size <= size && new_size >= size - size / 2 && (block.addr().wrapping_add(offset) & (alignment - 1)) == 0 {
        return Sourced { value: (NonNull::new(block), FreeOutcome::Freed), errno: observed.errno };
    }
    // SAFETY: forwarded Heap contract.
    let mut result = unsafe { heap_allocate(heap.as_ptr().cast(), new_size, Request::Aligned { alignment, offset }, false) };
    result.errno = observed.errno.then(result.errno);
    let Some(replacement) = result.value else { return freed_with(result) };
    let copy = new_size.min(size);
    let zero_start = if copy >= WORD { copy - WORD } else { 0 };
    // SAFETY: as in `heap_realloc_zero`.
    unsafe {
        let usable = crate::runtime_lifecycle::native_usable_size(replacement).unwrap_or(0);
        if zero && usable > zero_start {
            replacement.as_ptr().add(zero_start).write_bytes(0, usable - zero_start);
        }
        core::ptr::copy_nonoverlapping(block, replacement.as_ptr(), copy);
    }
    // SAFETY: the old block is freed once, after the copy.
    let freed = unsafe { crate::source_api::free_sourced(block) };
    Sourced { value: (Some(replacement), freed.value), errno: result.errno.then(freed.errno) }
}

/// `mi_heap_realloc` or, with `zero`, `mi_heap_rezalloc`. The free outcome
/// is that of the replaced block.
///
/// # Safety
/// `heap` is null or a live Heap of the calling thread's subprocess; `block`
/// is null or an exact live block no other thread uses, consumed on a
/// non-null result.
pub unsafe fn heap_realloc(heap: *mut c_void, block: *mut u8, new_size: usize, zero: bool) -> Sourced<(Block, FreeOutcome)> {
    // SAFETY: forwarded public Heap contract.
    match unsafe { resolve_heap_target(heap) } {
        None => Sourced { value: (None, FreeOutcome::Freed), errno: SourceErrno::Unchanged },
        // SAFETY: forwarded.
        Some(Target::Main) => freed_with(unsafe { crate::source_api::realloc_zero_native(block, new_size, zero) }),
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
        None => {
            // SAFETY: forwarded public Heap contract.
            let _ = unsafe { resolve_heap_target(heap) };
            Sourced { value: (None, FreeOutcome::Freed), errno: crate::source_api::count_size_overflow_errno(count, size) }
        }
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
        let freed = unsafe { crate::source_api::free_sourced(block) };
        return Sourced { value: (None, freed.value), errno: result.errno.then(freed.errno) };
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
    // SAFETY: forwarded public Heap contract.
    match unsafe { resolve_heap_target(heap) } {
        None => Sourced { value: (None, FreeOutcome::Freed), errno: SourceErrno::Unchanged },
        // SAFETY: forwarded.
        Some(Target::Main) => freed_with(unsafe { crate::source_api::realloc_zero_aligned_at_native(block, new_size, alignment, offset, zero) }),
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
        None => {
            // SAFETY: forwarded public Heap contract.
            let _ = unsafe { resolve_heap_target(heap) };
            Sourced { value: (None, FreeOutcome::Freed), errno: crate::source_api::count_size_overflow_errno(count, size) }
        }
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
    // SAFETY: the Heap selection precedes the string kernel's early returns.
    let _ = unsafe { resolve_heap_target(heap) };
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
    // SAFETY: the Heap selection precedes the string kernel's early returns.
    let _ = unsafe { resolve_heap_target(heap) };
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
    // SAFETY: the Heap selection precedes the string kernel's early returns.
    let _ = unsafe { resolve_heap_target(heap) };
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
            // SAFETY: forwarded live Heap selection precedes the count report.
            let _ = unsafe { resolve_heap_target(heap) };
            let overflow = crate::source_api::count_size_overflow_errno(count, size);
            let (_, errno) = crate::source_api::try_new_handler(runtime, false);
            Sourced { value: None, errno: overflow.then(errno) }
        }
    }
}

/// `mi_heap_collect(heap, force)`.
///
/// # Safety
/// `heap` is null or a live Heap of the calling thread's subprocess.
pub unsafe fn heap_collect(heap: *mut c_void, force: bool) {
    // SAFETY: the selected current-thread Theap remains retained by the
    // caller's live Heap and TLD throughout this collection.
    unsafe { crate::source_api::theap_collect(heap_theap(heap), force) };
}

// ---------------------------------------------------------------------------
// Subprocesses (`subproc.c:113-133,158-313`)
// ---------------------------------------------------------------------------

use crate::subproc::lifecycle::{NativeChildThreadAdd, NativeSubprocessId};

/// A Heap visitor (`mi_heap_visit_fun`).
pub type HeapVisitor = unsafe extern "C" fn(heap: *mut c_void, argument: *mut c_void) -> bool;

#[cfg(all(test, target_arch = "x86_64", not(miri)))]
mod nested_heap_visit_tests {
    use super::*;
    use crate::subproc::lifecycle::{native_subproc_new, native_subproc_add_current_thread,
        native_child_thread_done, native_subproc_destroy, NativeChildThreadAdd};
    unsafe extern "C" fn no_output(_: *const core::ffi::c_char) {}

    unsafe fn register_worker() {
        // SAFETY: this newly spawned worker publishes its own descriptor once.
        assert!(unsafe { crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(
            crate::__crabc_runtime::current_native_allocator_thread_descriptor()) });
    }

    unsafe extern "C" fn count_client(_: *const c_void, _: *const HeapArea,
        block: *mut c_void, _: usize, argument: *mut c_void) -> bool {
        // SAFETY: the synchronous visitor owns the count for the entire call.
        if !block.is_null() { unsafe { *argument.cast::<usize>() += 1 }; }
        true
    }

    unsafe extern "C" fn stop_visit(_: *const c_void, _: *const HeapArea,
        _: *mut c_void, _: usize, _: *mut c_void) -> bool { false }

    unsafe extern "C" fn count_heap(_: *mut c_void, argument: *mut c_void) -> bool {
        // SAFETY: the synchronous visitor owns the count for the entire call.
        unsafe { *argument.cast::<usize>() += 1 };
        true
    }

    #[test]
    fn nested_child_heap_visits_its_live_client_and_empty_abandoned_set() {
        crate::test_process::run_in_fresh_process(
            "source_heap_api::nested_heap_visit_tests::nested_child_heap_visits_its_live_client_and_empty_abandoned_set",
            || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
                let parent = native_subproc_new().unwrap();
                let nested = std::thread::spawn(move || {
                    unsafe { register_worker() };
                    assert_eq!(unsafe { native_subproc_add_current_thread(parent) }, Ok(NativeChildThreadAdd::Added));
                    let nested = native_subproc_new().unwrap();
                    assert_eq!(native_child_thread_done(), Some(Ok(())));
                    nested
                }).join().unwrap();
                std::thread::spawn(move || {
                    unsafe { register_worker() };
                    assert_eq!(unsafe { native_subproc_add_current_thread(nested) }, Ok(NativeChildThreadAdd::Added));
                    let mut arena = null_mut();
                    // SAFETY: the output, owned arena, Heap and client remain
                    // live in this sole member through traversal and release.
                    unsafe {
                        assert_eq!(reserve_os_memory_ex(64 * crate::config::MIB, true, false, true, &mut arena).value, 0);
                        let heap = heap_new_in_arena(arena);
                        assert!(!heap.is_null());
                        let client = heap_malloc(heap, 80).value.unwrap();
                        client.as_ptr().write_bytes(0x41, 80);
                        assert!(heap_contains(heap, client.as_ptr()));
                        let mut count = 0usize;
                        assert!(heap_visit_blocks(heap, true, Some(count_client), (&mut count as *mut usize).cast()));
                        assert_eq!(count, 1);
                        assert!(!heap_visit_blocks(heap, false, Some(stop_visit), null_mut()));
                        count = 0;
                        assert!(subproc_visit_heaps(nested.as_ptr(), count_heap, (&mut count as *mut usize).cast()));
                        assert_eq!(count, 2, "the child's main Heap and its explicit arena Heap");
                        count = 0;
                        assert!(heap_visit_abandoned_blocks(heap, true, Some(count_client), (&mut count as *mut usize).cast()));
                        assert_eq!(count, 0);
                        assert_eq!(crate::source_api::free(client.as_ptr()), crate::source_api::FreeOutcome::Freed);
                        assert!(heap_release(heap, true));
                    }
                    assert_eq!(native_child_thread_done(), Some(Ok(())));
                }).join().unwrap();
                assert_eq!(unsafe { native_subproc_destroy(nested) }, Ok(()));
                assert_eq!(unsafe { native_subproc_destroy(parent) }, Ok(()));
            },
        );
    }
}

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
    let Some(_operation) = crate::runtime_lifecycle::NativeSubprocessOperation::enter() else {
        return false;
    };
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
