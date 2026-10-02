#![cfg(target_arch = "x86_64")]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use core::ffi::c_void;
use crabc_mimalloc::__crabc_runtime::{
    source_api as api, source_heap_api as heaps, source_options_api as options,
    current_native_allocator_thread_descriptor, register_current_native_allocator_worker_descriptor,
    finish_current_thread_native_after_user_destructors, ThreadFinishResult,
};

#[repr(C)]
#[derive(Default)]
struct Count { total: i64, peak: i64, current: i64 }

// Retain the complete source image while observing only its first count.
#[repr(C)]
struct StatisticsImage {
    size: usize,
    version: usize,
    pages: Count,
    remaining: [i64; 541],
}

impl StatisticsImage {
    fn new() -> Self {
        Self { size: core::mem::size_of::<Self>(), version: 5,
               pages: Count::default(), remaining: [0; 541] }
    }
}

unsafe fn exclusive_pages(child: *mut c_void) -> i64 {
    let mut image = StatisticsImage::new();
    // SAFETY: the caller retains this child; the complete image is exclusive.
    assert!(unsafe { options::subproc_stats_get_exclusive(child, (&mut image as *mut StatisticsImage).cast()) });
    image.pages.current
}

unsafe fn theap_pages(theap: *mut c_void) -> i64 {
    let mut image = StatisticsImage::new();
    // SAFETY: the caller retains this initialized Theap and the exclusive image.
    assert!(unsafe { api::theap_stats_get(theap, (&mut image as *mut StatisticsImage).cast()) });
    image.pages.current
}

#[test]
fn reset_merges_the_callers_child_main_heap_into_its_subprocess() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    let child = heaps::subproc_new();
    assert!(!child.is_null());
    let child_address = child as usize;
    let client_address = std::thread::spawn(move || {
        // SAFETY: this fresh worker retains its own TLS descriptor until exit.
        assert!(unsafe { register_current_native_allocator_worker_descriptor(current_native_allocator_thread_descriptor()) });
        let child = child_address as *mut c_void;
        // SAFETY: the coordinator retains the child until after join and free.
        unsafe {
            assert_eq!(heaps::subproc_add_current_thread(child), heaps::SubprocAddCurrentThread::Added);
            let client = api::malloc(80).value.unwrap();
            let root_before = exclusive_pages(heaps::subproc_main());
            let before = exclusive_pages(child);
            options::stats_reset();
            let after = exclusive_pages(child);
            println!("reset.child.pages.delta={}", after - before);
            assert_eq!(after - before, 1, "reset transfers the live Page to its child subprocess");
            options::stats_reset();
            assert_eq!(exclusive_pages(child), after, "a repeated reset cannot duplicate the Page event");
            assert_eq!(exclusive_pages(heaps::subproc_main()), root_before, "child reset leaves the process-main Page record alone");

            let main_theap = heaps::heap_theap(heaps::heap_main());
            let auxiliary = heaps::heap_new();
            assert!(!auxiliary.is_null());
            let auxiliary_theap = heaps::heap_theap(auxiliary);
            assert!(!auxiliary_theap.is_null());
            let previous = heaps::theap_set_default(auxiliary_theap);
            let auxiliary_client = api::malloc(192).value.unwrap();
            let auxiliary_before = theap_pages(auxiliary_theap);
            assert_eq!(auxiliary_before, 1);
            options::stats_reset();
            assert_eq!(theap_pages(main_theap), 0, "reset drains the existing main-Heap Theap");
            assert_eq!(theap_pages(auxiliary_theap), auxiliary_before, "reset keeps the independently selected auxiliary Theap unmerged");
            println!("reset.auxiliary.pages.retained={auxiliary_before}");
            assert_eq!(api::free(auxiliary_client.as_ptr()), api::FreeOutcome::Freed);
            heaps::theap_set_default(previous);
            assert!(heaps::heap_release(auxiliary, true));
            assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
            client.as_ptr() as usize
        }
    }).join().unwrap();
    // SAFETY: the exited owner leaves this exact client and child live.
    unsafe {
        assert_eq!(api::free(client_address as *mut u8), api::FreeOutcome::Freed);
        assert!(heaps::subproc_destroy(child));
    }
}
