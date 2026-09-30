#![cfg(target_arch = "x86_64")]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use core::ffi::{CStr, c_void};
use crabc_mimalloc::{source_api as api, source_heap_api as heaps};

fn requested_total(heap: *mut c_void) -> i64 {
    let mut buffer = [0_i8; 65536];
    // SAFETY: the caller retains the live Heap through this fixed-buffer
    // snapshot; no result allocation can change the measured statistics.
    let json = unsafe {
        assert_eq!(heaps::heap_stats_json(heap, buffer.len(), buffer.as_mut_ptr()), buffer.as_mut_ptr());
        CStr::from_ptr(buffer.as_ptr()).to_str().unwrap()
    };
    json.split_once("\"malloc_requested\"").unwrap().1
        .split_once("\"total\":").unwrap().1.split(',').next().unwrap()
        .trim().parse().unwrap()
}

#[test]
fn subprocess_main_heap_birth_uses_source_parent_request() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    let main = heaps::heap_main();
    let auxiliary = heaps::heap_new();
    assert!(!auxiliary.is_null());
    // SAFETY: this owner keeps both Theaps and their Heaps live until the
    // original default is restored, before deleting the empty auxiliary Heap.
    let previous = unsafe { heaps::theap_set_default(heaps::heap_theap(auxiliary)) };
    assert!(!previous.is_null());
    let main_before = requested_total(main);
    let auxiliary_before = requested_total(auxiliary);
    let child = heaps::subproc_new();
    assert!(!child.is_null());
    let main_requested = requested_total(main) - main_before;
    let auxiliary_requested = requested_total(auxiliary) - auxiliary_before;
    let child_address = child.addr();
    let parent_address = main.addr();
    let (usable, aligned, parent_owned) = std::thread::spawn(move || {
        use crabc_mimalloc::__crabc_runtime as runtime;
        // SAFETY: this fresh worker registers before admission; its creator
        // retains the child and parent through the joined owner exit.
        unsafe {
            assert!(runtime::register_current_native_allocator_worker_descriptor(
                runtime::current_native_allocator_thread_descriptor()));
            assert_eq!(heaps::subproc_add_current_thread(child_address as *mut c_void),
                heaps::SubprocAddCurrentThread::Added);
            let heap = heaps::heap_main();
            // The child main Heap is an ordinary parent allocation in the
            // source algorithm. This observes that live Heap allocation,
            // never the opaque subprocess ID.
            let observations = (api::usable_size(heap.cast()), heap.addr() % 32 == 0,
                heaps::heap_of(heap.cast()) == parent_address as *mut c_void);
            assert_eq!(runtime::finish_current_thread_native_after_user_destructors(),
                runtime::ThreadFinishResult::Finished);
            observations
        }
    }).join().unwrap();
    // SAFETY: the joined child owner has no client; restore the default
    // before deleting the empty auxiliary Heap retained by this thread.
    unsafe {
        assert!(heaps::subproc_destroy(child));
        heaps::theap_set_default(previous);
        assert!(heaps::heap_release(auxiliary, false));
    }
    let expected_requested = if cfg!(feature = "mi-stat-2") { 6464 } else { 0 };
    let expected_usable = if cfg!(feature = "mi-debug-1") { 6464 } else { 7168 };
    println!("birth.main.requested={main_requested}\nbirth.aux.requested={auxiliary_requested}\nbirth.usable={usable}\nbirth.aligned32={}\nbirth.parent_owned={}",
        usize::from(aligned), usize::from(parent_owned));
    assert_eq!(main_requested, expected_requested);
    assert_eq!(auxiliary_requested, 0);
    assert_eq!(usable, expected_usable);
    assert!(aligned && parent_owned);
}
