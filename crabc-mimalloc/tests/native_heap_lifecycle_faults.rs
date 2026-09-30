#![cfg(all(target_arch = "x86_64", feature = "native-runtime-test-audit"))]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use core::ffi::{c_int, c_void};
use core::ptr::null_mut;
use crabc_mimalloc::__crabc_runtime::{source_api as api, source_heap_api as heaps};

unsafe extern "C" {
    fn mmap(address: *mut c_void, size: usize, protection: c_int, flags: c_int,
            fd: c_int, offset: isize) -> *mut c_void;
    fn mprotect(address: *mut c_void, size: usize, protection: c_int) -> c_int;
    fn munmap(address: *mut c_void, size: usize) -> c_int;
    fn mincore(address: *mut c_void, size: usize, resident: *mut u8) -> c_int;
}

struct CommitState { area: usize, size: usize, refused: usize, refuse: bool }

unsafe extern "C" fn commit(
    committing: bool, start: *mut u8, size: usize, zero: *mut bool, argument: *mut c_void,
) -> bool {
    // SAFETY: the test retains this boxed state for the registered arena's
    // process lifetime and excludes concurrent allocator operations.
    let state = unsafe { &mut *argument.cast::<CommitState>() };
    assert!(start.addr() >= state.area && size <= state.size
        && start.addr() - state.area <= state.size - size);
    if !committing { return false; }
    if state.refuse { state.refused += 1; return false; }
    // SAFETY: the validated span lies inside the caller-owned reservation.
    assert_eq!(unsafe { mprotect(start.cast(), size, 3) }, 0);
    if !zero.is_null() {
        // SAFETY: the allocator lends this output only for the callback.
        unsafe { zero.write(false) };
    }
    true
}

unsafe extern "C" fn count_pages(
    _: *const c_void, _: *const heaps::HeapArea, _: *mut c_void,
    _: usize, argument: *mut c_void,
) -> bool {
    // SAFETY: this synchronous visitor retains its exclusive scalar output.
    unsafe { *argument.cast::<usize>() += 1 };
    true
}

unsafe fn page_count(heap: *mut c_void) -> usize {
    let mut count = 0usize;
    // SAFETY: the calling test owns the Heap and excludes page mutation.
    assert!(unsafe { heaps::heap_visit_blocks(heap, false, Some(count_pages),
        (&mut count as *mut usize).cast()) });
    count
}

fn emit(index: usize, value: bool) {
    assert!(value, "source ownership observation {index}");
    println!("m6.heap.fault.{index}={}", usize::from(value));
}

unsafe fn reserve(size: usize, alignment: usize) -> usize {
    // SAFETY: this test reserves and trims only its own anonymous mapping.
    unsafe {
        let raw = mmap(null_mut(), size + alignment, 0, 0x22, -1, 0);
        assert_ne!(raw.addr(), usize::MAX);
        let start = (raw.addr() + alignment - 1) & !(alignment - 1);
        let prefix = start - raw.addr();
        if prefix != 0 { assert_eq!(munmap(raw, prefix), 0); }
        assert_eq!(munmap((start + size) as *mut c_void, alignment - prefix), 0);
        start
    }
}

unsafe extern "C" fn count_heaps(_: *mut c_void, argument: *mut c_void) -> bool {
    // SAFETY: the synchronous visitor retains its exclusive scalar output.
    unsafe { *argument.cast::<usize>() += 1 };
    true
}

unsafe fn heap_count() -> usize {
    let mut count = 0usize;
    // SAFETY: this test excludes subprocess Heap list mutation during visit.
    assert!(unsafe { heaps::subproc_visit_heaps(heaps::subproc_main(), count_heaps,
        (&mut count as *mut usize).cast()) });
    count
}

fn heap_image_refusal() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    let size = heaps::arena_min_size();
    // SAFETY: this test alone owns the reservation and its alignment trims.
    let start = unsafe { reserve(size, heaps::arena_min_alignment()) };
    let state = Box::leak(Box::new(CommitState { area: start, size, refused: 0, refuse: false }));
    let state_pointer = state as *mut CommitState;
    let mut arena = null_mut();
    let image = |index, value: bool| {
        assert!(value, "source Heap image ownership observation {index}");
        println!("m6.heap.image_fault.{index}={}", usize::from(value));
    };
    // SAFETY: the registered callback, reservation, Heap and exact caller
    // client remain owned by this test across every refusal and retry.
    unsafe {
        assert!(heaps::manage_memory(start as *mut c_void, size, false, false, true,
            -1, false, Some(commit), state_pointer.cast(), &mut arena));
        // The public option API takes the pinned disallow_os_alloc ordinal.
        crabc_mimalloc::source_options_api::option_set(17, 1);
        let base = heaps::theap_get_default();
        let caller = api::malloc(64).value.unwrap();
        caller.as_ptr().write_bytes(0x59, 64);
        let count = heap_count();
        (*state_pointer).refuse = true;
        for attempt in 0..2 {
            let before = (*state_pointer).refused;
            image(attempt * 3, heaps::heap_new().is_null());
            image(attempt * 3 + 1, (*state_pointer).refused > before);
            image(attempt * 3 + 2, heap_count() == count);
        }
        (*state_pointer).refuse = false;
        let retry = heaps::heap_new();
        assert!(!retry.is_null());
        image(6, heap_count() == count + 1);
        image(7, heaps::theap_get_default() == base);
        image(8, caller.as_ptr().read() == 0x59 && heaps::heap_of(caller.as_ptr()) == heaps::heap_main());
        assert!(heaps::heap_release(retry, true));
        image(9, heap_count() == count);
        image(10, caller.as_ptr().read() == 0x59);
        let mut resident = 0;
        image(11, mincore(start as *mut c_void, page_size, &mut resident) == 0);
        api::free(caller.as_ptr());
    }
    // The process-lifetime registered arena retains this mapping and callback.
}

#[test]
fn managed_commit_refusal_preserves_heap_theap_and_caller_until_retry() {
    std::env::set_var("mimalloc_arena_reserve", "0");
    std::env::set_var("mimalloc_purge_delay", "0");
    if std::env::var("CRABC_HEAP_FAULT_CASE").as_deref() == Ok("heap-image") {
        heap_image_refusal();
        return;
    }
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    let size = heaps::arena_min_size();
    let alignment = heaps::arena_min_alignment();
    // SAFETY: this test reserves and trims its own anonymous inaccessible
    // mapping. The retained exact aligned span belongs to its registered arena.
    let start = unsafe { reserve(size, alignment) };
    let state = Box::leak(Box::new(CommitState { area: start, size, refused: 0, refuse: false }));
    let state_pointer = state as *mut CommitState;
    let mut arena = null_mut();
    // SAFETY: the reservation and leaked callback state remain live until
    // process exit. Only this test uses the Heap and its allocation clients.
    unsafe {
        assert!(heaps::manage_memory(start as *mut c_void, size, false, false, true,
            -1, true, Some(commit), state_pointer.cast(), &mut arena));
        let heap = heaps::heap_new_in_arena(arena);
        assert!(!heap.is_null());
        let base = heaps::theap_get_default();
        let caller = api::malloc(64).value.unwrap();
        caller.as_ptr().write_bytes(0x59, 64);
        (*state_pointer).refuse = true;
        for attempt in 0..2 {
            let before = (*state_pointer).refused;
            emit(attempt * 3, heaps::heap_malloc(heap, 64).value.is_none());
            emit(attempt * 3 + 1, (*state_pointer).refused > before);
            emit(attempt * 3 + 2, page_count(heap) == 0);
        }
        assert_eq!(heaps::theap_get_default(), base);
        assert_eq!(caller.as_ptr().read(), 0x59);
        (*state_pointer).refuse = false;
        let first = heaps::heap_malloc(heap, 64).value.unwrap();
        first.as_ptr().write_bytes(0x6b, 64);
        let selected = heaps::heap_theap(heap);
        emit(6, heaps::heap_of(first.as_ptr()) == heap);
        emit(7, first.as_ptr().addr() >= start && first.as_ptr().addr() < start + size);
        emit(8, selected != base && selected == heaps::heap_theap(heap));
        (*state_pointer).refuse = true;
        let before = (*state_pointer).refused;
        emit(9, heaps::heap_malloc(heap, 589824).value.is_none() && (*state_pointer).refused > before);
        assert_eq!(page_count(heap), 1, "a refused page has no published Heap member");
        emit(10, heaps::heap_theap(heap) == selected);
        emit(11, first.as_ptr().read() == 0x6b && heaps::heap_of(first.as_ptr()) == heap);
        (*state_pointer).refuse = false;
        let retry = heaps::heap_malloc(heap, 589824).value.unwrap();
        assert_eq!(page_count(heap), 2, "retry publishes exactly its successful page");
        emit(12, heaps::heap_of(retry.as_ptr()) == heap);
        emit(13, heaps::heap_theap(heap) == selected && heaps::theap_get_default() == base);
        api::free(first.as_ptr());
        api::free(retry.as_ptr());
        assert!(heaps::heap_release(heap, true));
        emit(14, caller.as_ptr().read() == 0x59 && heaps::heap_of(caller.as_ptr()) == heaps::heap_main());
        let mut resident = 0;
        emit(15, mincore(start as *mut c_void, page_size, &mut resident) == 0);
        api::free(caller.as_ptr());
    }
    // Registered arena metadata still names this caller-owned mapping and
    // callback; neither is released before the test process exits.
}
