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
#[derive(Clone, Default, PartialEq, Eq, Debug)]
struct Count {
    total: i64,
    peak: i64,
    current: i64,
}

// The selected statistics ABI begins with two machine-word header fields,
// then the page count. Retain the complete writable image for the getter.
#[repr(C)]
#[derive(Clone, PartialEq, Eq, Debug)]
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

#[test]
fn current_subprocess_statistics_include_its_live_page() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    let child = heaps::subproc_new();
    assert!(!child.is_null());
    let child_address = child as usize;
    let (client_address, pages) = std::thread::spawn(move || {
        // SAFETY: this fresh thread's allocator descriptor is retained until
        // owner finish and thread return. It has made no allocator entry.
        assert!(unsafe {
            register_current_native_allocator_worker_descriptor(current_native_allocator_thread_descriptor())
        });
        let child = child_address as *mut c_void;
        // SAFETY: the coordinator keeps the child live until after join,
        // client release and destruction; this worker starts unattached.
        unsafe {
            assert_eq!(heaps::subproc_add_current_thread(child), heaps::SubprocAddCurrentThread::Added);
            assert_eq!(heaps::subproc_current(), child);
            let client = api::malloc(80).value.unwrap();
            let mut image = StatisticsImage::new();
            assert!(options::stats_get((&mut image as *mut StatisticsImage).cast()));
            let pages = image.pages.current;
            let mut exclusive = StatisticsImage::new();
            assert!(options::subproc_stats_get_exclusive(child, (&mut exclusive as *mut StatisticsImage).cast()));
            assert_eq!(exclusive.pages.current, 0);
            let extra = heaps::heap_new();
            assert!(!extra.is_null());
            let extra_client = heaps::heap_malloc(extra, 192).value.unwrap();
            let mut invalid = StatisticsImage::new();
            invalid.version = 0;
            invalid.remaining.fill(0x37);
            let untouched = invalid.clone();
            assert!(!options::subproc_stats_get(child, (&mut invalid as *mut StatisticsImage).cast()));
            assert_eq!(invalid, untouched);
            // A Heap getter merges its existing Theap even when the output
            // header is invalid. The direct merge below must then transfer
            // that page event, without performing a second Theap merge.
            assert!(!heaps::heap_stats_get(extra, (&mut invalid as *mut StatisticsImage).cast()));
            assert_eq!(invalid, untouched);
            heaps::heap_stats_merge_to_subproc(extra);
            assert!(options::subproc_stats_get_exclusive(child, (&mut exclusive as *mut StatisticsImage).cast()));
            assert_eq!(exclusive.pages.current, 1);
            assert!(options::subproc_stats_get(child, (&mut image as *mut StatisticsImage).cast()));
            // Creating the extra Heap and its Theap also allocates metadata
            // from the child main Heap, as in the pinned source workload.
            assert_eq!(image.pages.current, 4);
            let mut heap_image = StatisticsImage::new();
            assert!(heaps::heap_stats_get(extra, (&mut heap_image as *mut StatisticsImage).cast()));
            assert_eq!(heap_image.pages.current, 0);
            let json = options::subproc_stats_json(child, 0, core::ptr::null_mut());
            assert!(!json.is_null());
            assert_eq!(heaps::heap_of(json.cast()), heaps::heap_main());
            assert_eq!(api::free(json.cast()), api::FreeOutcome::Freed);
            assert_eq!(api::free(extra_client.as_ptr()), api::FreeOutcome::Freed);
            assert!(heaps::heap_release(extra, true));
            assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
            (client.as_ptr() as usize, pages)
        }
    }).join().unwrap();
    // SAFETY: the exited owner left this exact client and child live; the
    // coordinator releases the client before destroying its subprocess.
    unsafe {
        assert_eq!(api::free(client_address as *mut u8), api::FreeOutcome::Freed);
        assert!(heaps::subproc_destroy(child));
    }
    assert_eq!(pages, 1);
}
