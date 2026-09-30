#![cfg(target_arch = "x86_64")]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use core::ffi::{c_int, c_void};
use core::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crabc_mimalloc::__crabc_runtime::{
    source_api as api, source_heap_api as arenas,
    current_native_allocator_thread_descriptor, register_current_native_allocator_worker_descriptor,
    finish_current_thread_native_after_user_destructors, ThreadFinishResult,
};

unsafe extern "C" {
    fn mmap(address: *mut c_void, size: usize, protection: c_int,
            flags: c_int, descriptor: c_int, offset: isize) -> *mut c_void;
    fn munmap(address: *mut c_void, size: usize) -> c_int;
    fn mprotect(address: *mut c_void, size: usize, protection: c_int) -> c_int;
    fn mincore(address: *mut c_void, size: usize, residency: *mut u8) -> c_int;
}

struct CallerRegion {
    start: usize,
    size: usize,
}

impl CallerRegion {
    fn map(protection: c_int) -> Self {
        let size = arenas::arena_min_size();
        let alignment = arenas::arena_min_alignment();
        assert!(alignment.is_power_of_two());
        // SAFETY: reserve a fresh anonymous range, then unmap only its unused
        // prefix and suffix. The retained aligned range has one caller owner.
        unsafe {
            let raw = mmap(null_mut(), size + alignment, protection, 0x22, -1, 0);
            assert_ne!(raw as usize, usize::MAX);
            let start = (raw as usize + alignment - 1) & !(alignment - 1);
            let prefix = start - raw as usize;
            let suffix = alignment - prefix;
            if prefix != 0 { assert_eq!(munmap(raw, prefix), 0); }
            if suffix != 0 { assert_eq!(munmap((start + size) as *mut c_void, suffix), 0); }
            Self { start, size }
        }
    }

    fn pointer(&self) -> *mut c_void { self.start as *mut c_void }

    fn mapped(&self) {
        let mut residency = 0;
        // SAFETY: mincore observes the caller's retained first page without
        // reading it, including when that page is inaccessible after purge.
        assert_eq!(unsafe { mincore(self.pointer(), 4096, &mut residency) }, 0);
    }

    unsafe fn unmap(self) {
        // SAFETY: the caller has joined every user and destroyed its child
        // arena group before exercising its original terminal unmap right.
        assert_eq!(unsafe { munmap(self.pointer(), self.size) }, 0);
    }
}

struct CallerTransitions {
    start: usize,
    size: usize,
    refuse_metadata: AtomicBool,
    calls: AtomicUsize,
    valid: AtomicBool,
}

unsafe extern "C" fn transition(commit: bool, start: *mut u8, size: usize,
                                is_zero: *mut bool, argument: *mut c_void) -> bool {
    // SAFETY: the test retains this caller-owned callback state until child
    // destruction and both worker joins. Only atomics change across callbacks.
    let state = unsafe { &*argument.cast::<CallerTransitions>() };
    state.calls.fetch_add(1, Ordering::Relaxed);
    let offset = (start as usize).checked_sub(state.start);
    if offset.is_none_or(|offset| size > state.size || offset > state.size - size)
        || start as usize % 4096 != 0 || size % 4096 != 0 {
        state.valid.store(false, Ordering::Relaxed);
        return false;
    }
    if commit && is_zero.is_null() && state.refuse_metadata.swap(false, Ordering::Relaxed) {
        return false;
    }
    // SAFETY: the validated span belongs wholly to the caller's mapped range.
    // A successful commit makes it accessible before returning to allocation.
    if unsafe { mprotect(start.cast(), size, if commit { 3 } else { 0 }) } != 0 {
        state.valid.store(false, Ordering::Relaxed);
        return false;
    }
    if !is_zero.is_null() {
        // SAFETY: the allocator supplies its writable callback result word.
        unsafe { is_zero.write(false) };
    }
    true
}

unsafe fn query_boundaries(arena: *mut c_void, region: &CallerRegion) {
    let mut size = usize::MAX;
    // SAFETY: the live arena and its external range outlive all these queries;
    // the end and preceding addresses are scalar containment probes only.
    unsafe {
        assert_eq!(arenas::arena_area(arena, &mut size), region.pointer());
        assert_eq!(size, region.size);
        assert!(arenas::arena_contains(arena, region.pointer()));
        assert!(arenas::arena_contains(arena, (region.start + region.size - 1) as *const c_void));
        assert!(!arenas::arena_contains(arena, (region.start + region.size) as *const c_void));
        assert!(!arenas::arena_contains(arena, (region.start - 1) as *const c_void));
        assert!(!arenas::arena_contains(arena, null_mut()));
    }
}

unsafe fn selected_allocation(arena: *mut c_void, region: &CallerRegion) {
    // SAFETY: this member owns the live selected arena and every Heap/block
    // below. The external range remains mapped through matching release.
    unsafe {
        let heap = arenas::heap_new_in_arena(arena);
        assert!(!heap.is_null());
        let theap = arenas::heap_theap(heap);
        assert!(!theap.is_null());
        assert!(arenas::arena_contains(arena, theap));
        let block = arenas::heap_malloc(heap, 96).value.unwrap();
        let address = block.as_ptr() as usize;
        assert!(address >= region.start && address - region.start < region.size);
        assert_eq!(arenas::heap_of(block.as_ptr()), heap);
        assert!(arenas::arena_contains(arena, block.as_ptr().cast()));
        block.as_ptr().write_bytes(0x67, 96);
        assert!(core::slice::from_raw_parts(block.as_ptr(), 96).iter().all(|byte| *byte == 0x67));
        api::free(block.as_ptr());
        assert!(arenas::heap_release(heap, true));
        api::collect(true);
        query_boundaries(arena, region);
        region.mapped();
    }
}

fn register_worker() {
    let descriptor = current_native_allocator_thread_descriptor();
    // SAFETY: this worker's TLS descriptor lives through its explicit finish.
    // Registration precedes every allocator entry and child membership call.
    assert!(unsafe { register_current_native_allocator_worker_descriptor(descriptor) });
}

#[test]
fn public_managed_arena_refusal_selection_membership_and_caller_lifetime() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    assert_eq!(arenas::subproc_current(), arenas::subproc_main());
    let main_region = CallerRegion::map(3);
    let mut main_arena = main_region.pointer();
    let mut size = usize::MAX;
    // SAFETY: the main caller owns this fresh committed mapping. A refused
    // region cannot publish an arena; output words are writable local storage.
    unsafe {
        assert_eq!(arenas::arena_area(null_mut(), &mut size), null_mut());
        assert_eq!(size, 0);
        let mut refused_reservation = main_region.pointer();
        assert_eq!(arenas::reserve_os_memory_ex(usize::MAX, true, false, true,
            &mut refused_reservation).value, crabc_core::Errno::NOMEM.raw());
        assert!(refused_reservation.is_null());
        assert!(!arenas::manage_memory(main_region.pointer(), main_region.size - 1,
            true, false, true, -1, true, None, null_mut(), &mut main_arena));
        assert!(main_arena.is_null());
        main_region.mapped();
        assert!(arenas::manage_memory(main_region.pointer(), main_region.size,
            true, false, true, -1, true, None, null_mut(), &mut main_arena));
        assert!(!main_arena.is_null());
        query_boundaries(main_arena, &main_region);
        selected_allocation(main_arena, &main_region);
    }

    let child_region = CallerRegion::map(0);
    let transitions = Box::new(CallerTransitions {
        start: child_region.start, size: child_region.size,
        refuse_metadata: AtomicBool::new(true), calls: AtomicUsize::new(0),
        valid: AtomicBool::new(true),
    });
    let callback = (&*transitions as *const CallerTransitions) as usize;
    let child = arenas::subproc_new() as usize;
    assert_ne!(child, 0);
    let region_start = child_region.start;
    let region_size = child_region.size;
    let main = main_arena as usize;
    let arena = std::thread::spawn(move || {
        register_worker();
        // SAFETY: the parent retains the child, both mappings and callback
        // state through this join. This fresh registered worker has allocated
        // nothing from the runtime before joining its selected child group.
        unsafe {
            assert_eq!(arenas::subproc_add_current_thread(child as *mut c_void),
                       arenas::SubprocAddCurrentThread::Added);
            assert_eq!(arenas::subproc_current() as usize, child);
            assert_ne!(arenas::subproc_current(), arenas::subproc_main());
            let region = CallerRegion { start: region_start, size: region_size };
            let mut arena = region.pointer();
            assert!(!arenas::manage_memory(region.pointer(), region.size,
                false, false, true, -1, true, Some(transition), callback as *mut c_void, &mut arena));
            assert!(arena.is_null());
            region.mapped();
            assert!(arenas::manage_memory(region.pointer(), region.size,
                false, false, true, -1, true, Some(transition), callback as *mut c_void, &mut arena));
            assert!(!arena.is_null());
            assert!(!arenas::arena_contains(main as *mut c_void, region.pointer()));
            selected_allocation(arena, &region);
            assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
            arena as usize
        }
    }).join().unwrap();
    child_region.mapped();
    let second = std::thread::spawn(move || {
        register_worker();
        // SAFETY: the same parent retains the child, arena and callback until
        // this second owner finishes and joins; no earlier Heap is reused.
        unsafe {
            assert_eq!(arenas::subproc_add_current_thread(child as *mut c_void),
                       arenas::SubprocAddCurrentThread::Added);
            let region = CallerRegion { start: region_start, size: region_size };
            query_boundaries(arena as *mut c_void, &region);
            selected_allocation(arena as *mut c_void, &region);
            assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
        }
    });
    second.join().unwrap();
    assert_eq!(arenas::subproc_current(), arenas::subproc_main());
    // SAFETY: queries accept either live process arena ID independently of
    // membership; both workers have joined before child destruction.
    unsafe {
        query_boundaries(arena as *mut c_void, &child_region);
        assert!(arenas::subproc_destroy(child as *mut c_void));
        child_region.mapped();
        assert!(transitions.valid.load(Ordering::Relaxed));
        assert!(transitions.calls.load(Ordering::Relaxed) > 1);
        child_region.unmap();
        query_boundaries(main_arena, &main_region);
        main_region.mapped();
    }
    // The process-main arena retains metadata inside this external mapping.
    // Keep the caller's range mapped until process exit, rather than unmapping
    // it merely because its auxiliary Heap and user block were released.
}
