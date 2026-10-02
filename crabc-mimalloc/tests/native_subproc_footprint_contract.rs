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

// Retain the complete writable source image while projecting the committed
// count used to observe the parent's metadata allocation footprint.
#[repr(C)]
struct StatisticsImage {
    size: usize,
    version: usize,
    pages: Count,
    reserved: Count,
    committed: Count,
    remaining: [i64; 535],
}
impl StatisticsImage {
    fn new() -> Self {
        Self { size: core::mem::size_of::<Self>(), version: 5,
            pages: Count::default(), reserved: Count::default(),
            committed: Count::default(), remaining: [0; 535] }
    }
}

#[test]
fn nested_subprocess_creation_preserves_parent_metadata_footprint() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    let parent = heaps::subproc_new();
    assert!(!parent.is_null());
    let address = parent as usize;
    let committed = std::thread::spawn(move || {
        // SAFETY: the new thread registers before allocator attachment; the
        // coordinator retains the parent through join and destruction.
        unsafe {
            assert!(register_current_native_allocator_worker_descriptor(current_native_allocator_thread_descriptor()));
            let parent = address as *mut c_void;
            assert_eq!(heaps::subproc_add_current_thread(parent), heaps::SubprocAddCurrentThread::Added);
            let extra = heaps::heap_new();
            assert!(!extra.is_null());
            let first = api::malloc(80).value.unwrap();
            let second = heaps::heap_malloc(extra, 192).value.unwrap();
            first.as_ptr().write_bytes(0x54, 80);
            second.as_ptr().write_bytes(0x65, 192);
            let main_heap = heaps::heap_main();
            assert_eq!(heaps::heap_of(first.as_ptr()), main_heap);
            assert_eq!(heaps::heap_of(second.as_ptr()), extra);
            let mut before = StatisticsImage::new();
            assert!(options::subproc_stats_get_exclusive(parent, (&mut before as *mut StatisticsImage).cast()));
            let nested = heaps::subproc_new();
            assert!(!nested.is_null());
            let mut after = StatisticsImage::new();
            assert!(options::subproc_stats_get_exclusive(parent, (&mut after as *mut StatisticsImage).cast()));
            let committed = after.committed.total - before.committed.total;
            // No thread or client belongs to the nested subprocess. Destroy
            // it before its metadata parent and retain the parent clients.
            assert!(heaps::subproc_destroy(nested));
            assert!(core::slice::from_raw_parts(first.as_ptr(), 80).iter().all(|byte| *byte == 0x54));
            assert!(core::slice::from_raw_parts(second.as_ptr(), 192).iter().all(|byte| *byte == 0x65));
            assert_eq!(heaps::heap_of(first.as_ptr()), main_heap);
            assert_eq!(heaps::heap_of(second.as_ptr()), extra);
            assert_eq!(api::free(second.as_ptr()), api::FreeOutcome::Freed);
            assert!(heaps::heap_release(extra, true));
            assert_eq!(api::free(first.as_ptr()), api::FreeOutcome::Freed);
            assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
            committed
        }
    }).join().unwrap();
    // SAFETY: the only parent owner has exited and every client was freed.
    assert!(unsafe { heaps::subproc_destroy(parent) });
    println!("child.birth.committed={committed}");
    assert_eq!(committed, 64 * 1024);
}
