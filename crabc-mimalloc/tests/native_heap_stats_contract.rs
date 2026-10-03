#![cfg(target_arch = "x86_64")]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use crabc_mimalloc::__crabc_runtime::{source_api as api, source_heap_api as heaps, source_options_api as options};

#[test]
fn heap_json_and_free_statistics_use_the_callers_default_theap() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    // SAFETY: this process owns the fresh Heap and every client through
    // collection, statistics transfer, and its final destruction.
    unsafe { collection_flushes_exact_allocation_records() };
    let main_heap = heaps::heap_main();
    let auxiliary = heaps::heap_new();
    assert!(!auxiliary.is_null());
    // SAFETY: this thread retains its auxiliary Heap and both Theaps until
    // the old default is restored; every client is released before destroy.
    let (ordinary_owner, json_owner, length, usable, ordinary_usable, commit_before, commit_owned) = unsafe {
        let selected = heaps::heap_theap(auxiliary);
        assert!(!selected.is_null());
        let previous = heaps::theap_set_default(selected);
        let ordinary = api::malloc(192).value.unwrap();
        let ordinary_owner = heaps::heap_of(ordinary.as_ptr());
        // Null selects the main Heap statistics while allocation of the
        // growing result follows the caller's independently selected default.
        let mut fixed = [0_i8; 65536];
        assert_eq!(heaps::heap_stats_json(core::ptr::null_mut(), fixed.len(), fixed.as_mut_ptr()), fixed.as_mut_ptr());
        let commit_before = json_commit_current(core::ffi::CStr::from_ptr(fixed.as_ptr()).to_str().unwrap());
        let json = heaps::heap_stats_json(core::ptr::null_mut(), 0, core::ptr::null_mut());
        assert!(!json.is_null());
        let json_owner = heaps::heap_of(json.cast());
        let text = core::ffi::CStr::from_ptr(json);
        let length = text.to_bytes().len();
        let commit_owned = json_commit_current(text.to_str().unwrap());
        let usable = api::usable_size(json.cast());
        let mut capacity = api::good_size(12 * 1024);
        while capacity <= length { capacity *= 2; }
        let zeroed = api::rezalloc(core::ptr::null_mut(), capacity).value.unwrap();
        let ordinary_usable = api::usable_size(zeroed.as_ptr());
        assert_eq!(api::free(zeroed.as_ptr()), api::FreeOutcome::Freed);
        assert_eq!(api::free(json.cast()), api::FreeOutcome::Freed);
        assert_eq!(api::free(ordinary.as_ptr()), api::FreeOutcome::Freed);
        heaps::theap_set_default(previous);
        assert!(heaps::heap_release(auxiliary, true));
        (ordinary_owner, json_owner, length, usable, ordinary_usable, commit_before, commit_owned)
    };
    assert_eq!(ordinary_owner, auxiliary);
    assert!(length > 12 * 1024, "the owned JSON traverses its growing-buffer path");
    assert_eq!(usable, ordinary_usable);
    assert_ne!(json_owner, main_heap);
    assert_eq!(json_owner, auxiliary);
    assert!(commit_owned > commit_before, "JSON observes process commitment after its initial buffer allocation");
    // SAFETY: both Heaps and the client stay live throughout these owner-
    // quiescent getters. Free consumes the client before Heap destruction.
    let (aux_delta, main_delta) = unsafe {
        let auxiliary = heaps::heap_new();
        assert!(!auxiliary.is_null());
        let client = heaps::heap_malloc(auxiliary, 96).value.unwrap();
        let main_before = heap_normal_current(main_heap);
        let aux_before = heap_normal_current(auxiliary);
        assert_eq!(api::free(client.as_ptr()), api::FreeOutcome::Freed);
        let aux_after = heap_normal_current(auxiliary);
        let main_after = heap_normal_current(main_heap);
        assert!(heaps::heap_release(auxiliary, true));
        (aux_after - aux_before, main_after - main_before)
    };
    // The allocation belongs to the auxiliary Heap; source free statistics
    // belong to this caller's independently selected main default Theap.
    assert_eq!(aux_delta, 0);
    if cfg!(feature = "mi-stat-1") {
        assert!(main_delta <= -96);
    } else {
        assert_eq!(main_delta, 0);
    }
    // SAFETY: this caller holds both live Heaps and the main-Heap client,
    // and restores its previous default before destroying the auxiliary.
    let (reverse_aux_delta, reverse_main_delta) = unsafe {
        let auxiliary = heaps::heap_new();
        assert!(!auxiliary.is_null());
        let client = heaps::heap_malloc(main_heap, 96).value.unwrap();
        let selected = heaps::heap_theap(auxiliary);
        let previous = heaps::theap_set_default(selected);
        let main_before = heap_normal_current(main_heap);
        let aux_before = heap_normal_current(auxiliary);
        assert_eq!(api::free(client.as_ptr()), api::FreeOutcome::Freed);
        let aux_after = heap_normal_current(auxiliary);
        let main_after = heap_normal_current(main_heap);
        heaps::theap_set_default(previous);
        assert!(heaps::heap_release(auxiliary, true));
        (aux_after - aux_before, main_after - main_before)
    };
    // A main-Heap page may use a local fast free, but that does not make its
    // page owner the statistics owner when the caller selected another Theap.
    assert_eq!(reverse_main_delta, 0);
    if cfg!(feature = "mi-stat-1") {
        assert!(reverse_aux_delta <= -96);
    } else {
        assert_eq!(reverse_aux_delta, 0);
    }
}

fn json_commit_current(text: &str) -> usize {
    text.split_once("\"commit_current\":").unwrap().1
        .trim_start().split(',').next().unwrap().trim().parse().unwrap()
}

unsafe fn heap_normal_current(heap: *mut core::ffi::c_void) -> i64 {
    let mut fixed = [0_i8; 65536];
    // SAFETY: forwarded live Heap and exclusive complete buffer contracts.
    unsafe {
        assert_eq!(heaps::heap_stats_json(heap, fixed.len(), fixed.as_mut_ptr()), fixed.as_mut_ptr());
        let text = core::ffi::CStr::from_ptr(fixed.as_ptr()).to_str().unwrap();
        text.split_once("\"malloc_normal\":").unwrap().1
            .split_once("\"current\":").unwrap().1
            .split('}').next().unwrap().trim().parse().unwrap()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Count { total: i64, peak: i64, current: i64 }

// Complete pinned statistics layout: bin tails must remain writable even
// when this witness only examines selected allocation and page records.
#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
struct StatisticsImage {
    size: usize,
    version: usize,
    pages: Count,
    reserved: Count,
    committed: Count,
    reset: i64,
    purged: i64,
    page_committed: Count,
    pages_abandoned: Count,
    threads: Count,
    malloc_normal: Count,
    malloc_huge: Count,
    malloc_requested: Count,
    mmap_calls: i64,
    commit_calls: i64,
    reset_calls: i64,
    purge_calls: i64,
    arena_count: i64,
    malloc_normal_count: i64,
    malloc_huge_count: i64,
    malloc_guarded_count: i64,
    arena_rollback_count: i64,
    arena_purges: i64,
    pages_extended: i64,
    pages_retire: i64,
    page_searches: i64,
    page_searches_count: i64,
    segments: [Count; 4],
    heaps: Count,
    theaps: Count,
    page_counters: [i64; 5],
    reserved_counts: [Count; 4],
    reserved_counters: [i64; 4],
    malloc_bins: [Count; 74],
    page_bins: [Count; 74],
    chunk_bins: [Count; 6],
}

impl StatisticsImage {
    fn new() -> Self {
        // SAFETY: every field is an integer or an integer array; zero is valid.
        let mut image: Self = unsafe { core::mem::zeroed() };
        image.size = core::mem::size_of::<Self>();
        image.version = 5;
        image
    }
}

unsafe fn heap_statistics(heap: *mut core::ffi::c_void) -> StatisticsImage {
    let mut image = StatisticsImage::new();
    // SAFETY: the caller retains the Heap and this complete output is exclusive.
    assert!(unsafe { heaps::heap_stats_get(heap, (&mut image as *mut StatisticsImage).cast()) });
    image
}

unsafe fn theap_statistics(theap: *mut core::ffi::c_void) -> StatisticsImage {
    let mut image = StatisticsImage::new();
    // SAFETY: the caller retains the Theap and this complete output is exclusive.
    assert!(unsafe { api::theap_stats_get(theap, (&mut image as *mut StatisticsImage).cast()) });
    image
}

unsafe fn subprocess_statistics(subprocess: *mut core::ffi::c_void) -> StatisticsImage {
    let mut image = StatisticsImage::new();
    // SAFETY: the caller retains the subprocess and the full output is exclusive.
    assert!(unsafe { options::subproc_stats_get_exclusive(subprocess, (&mut image as *mut StatisticsImage).cast()) });
    image
}

unsafe fn collection_flushes_exact_allocation_records() {
    // SAFETY: this thread exclusively owns both the fresh Heap and its Theap;
    // all clients are freed before destruction and the old default restored.
    unsafe {
        let heap = heaps::heap_new();
        assert!(!heap.is_null());
        let theap = heaps::heap_theap(heap);
        assert!(!theap.is_null());
        let previous = heaps::theap_set_default(theap);
        let empty = theap_statistics(theap);
        assert_eq!(empty.pages.current, 0);
        assert_eq!(empty.malloc_normal, Count::default());
        let first = api::malloc(81).value.unwrap();
        let second = api::malloc(161).value.unwrap();
        first.as_ptr().write_bytes(0x37, 81);
        second.as_ptr().write_bytes(0x71, 161);
        // Statistics charge class capacity, including bytes beyond the
        // requested extent. The physical class also contains source padding.
        let padding = if cfg!(feature = "mi-debug-1") || cfg!(feature = "mi-secure-3") { 8 } else { 0 };
        let usable = (api::good_size(81) + api::good_size(161) - 2 * padding) as i64;
        let allocated = theap_statistics(theap);
        assert_eq!(allocated.pages.current, 2);
        let expected_normal = if cfg!(feature = "mi-stat-1") { usable } else { 0 };
        assert_eq!(allocated.malloc_normal, Count {
            total: expected_normal, peak: expected_normal, current: expected_normal,
        });
        let expected_requested = if cfg!(feature = "mi-stat-2") { 242 } else { 0 };
        assert_eq!(allocated.malloc_requested, Count {
            total: expected_requested, peak: expected_requested, current: expected_requested,
        });
        assert_eq!(allocated.malloc_normal_count, if cfg!(feature = "mi-stat-2") { 2 } else { 0 });
        assert_eq!(allocated.malloc_bins.iter().map(|count| count.current).sum::<i64>(),
                   if cfg!(feature = "mi-stat-2") { 2 } else { 0 });
        heaps::heap_collect(heap, false);
        assert_eq!(theap_statistics(theap), empty, "collection resets the complete Theap record");
        let collected = heap_statistics(heap);
        assert_eq!(collected.malloc_normal, allocated.malloc_normal);
        assert_eq!(collected.malloc_requested, allocated.malloc_requested);
        assert_eq!(collected.malloc_normal_count, allocated.malloc_normal_count);
        assert_eq!(collected.malloc_bins, allocated.malloc_bins);
        assert_eq!(heap_statistics(heap), collected, "repeated getter does not count an event twice");
        assert!(core::slice::from_raw_parts(first.as_ptr(), 81).iter().all(|byte| *byte == 0x37));
        assert!(core::slice::from_raw_parts(second.as_ptr(), 161).iter().all(|byte| *byte == 0x71));
        assert_eq!(api::free(first.as_ptr()), api::FreeOutcome::Freed);
        assert_eq!(api::free(second.as_ptr()), api::FreeOutcome::Freed);
        let freed = theap_statistics(theap);
        assert_eq!(freed.malloc_normal.current, -expected_normal);
        assert_eq!(freed.malloc_normal.total, 0);
        assert_eq!(freed.malloc_requested, Count::default(), "free does not debit requested bytes");
        assert_eq!(freed.malloc_bins.iter().map(|count| count.current).sum::<i64>(),
                   if cfg!(feature = "mi-stat-2") { -2 } else { 0 });
        heaps::heap_collect(heap, true);
        assert_eq!(theap_statistics(theap), empty);
        let released = heap_statistics(heap);
        assert_eq!(released.pages.current, 0);
        assert_eq!(released.page_bins.iter().map(|count| count.current).sum::<i64>(), 0);
        assert_eq!(released.malloc_normal.current, 0);
        assert_eq!(released.malloc_normal.total, expected_normal);
        assert_eq!(released.malloc_requested, allocated.malloc_requested);
        assert_eq!(released.malloc_normal_count, allocated.malloc_normal_count);
        assert_eq!(released.malloc_bins.iter().map(|count| count.current).sum::<i64>(), 0);
        assert_eq!(released.malloc_bins.iter().map(|count| count.total).sum::<i64>(),
                   if cfg!(feature = "mi-stat-2") { 2 } else { 0 });
        let subprocess = heaps::subproc_current();
        let before_transfer = subprocess_statistics(subprocess);
        heaps::heap_stats_merge_to_subproc(heap);
        let after_transfer = subprocess_statistics(subprocess);
        assert_eq!(after_transfer.pages.total - before_transfer.pages.total, released.pages.total);
        assert_eq!(after_transfer.malloc_normal.total - before_transfer.malloc_normal.total, expected_normal);
        assert_eq!(after_transfer.malloc_normal.current, before_transfer.malloc_normal.current);
        assert_eq!(after_transfer.malloc_requested.total - before_transfer.malloc_requested.total, expected_requested);
        assert_eq!(after_transfer.malloc_requested.current - before_transfer.malloc_requested.current, expected_requested);
        assert_eq!(after_transfer.malloc_normal_count - before_transfer.malloc_normal_count, allocated.malloc_normal_count);
        for bin in 0..released.malloc_bins.len() {
            assert_eq!(after_transfer.malloc_bins[bin].total - before_transfer.malloc_bins[bin].total,
                       released.malloc_bins[bin].total);
            assert_eq!(after_transfer.malloc_bins[bin].current, before_transfer.malloc_bins[bin].current);
        }
        let transferred = heap_statistics(heap);
        assert_eq!(transferred, empty, "direct subprocess merge resets the Heap record");
        heaps::heap_stats_merge_to_subproc(heap);
        assert_eq!(heap_statistics(heap), empty);
        assert_eq!(subprocess_statistics(subprocess), after_transfer);
        heaps::theap_set_default(previous);
        assert!(heaps::heap_release(heap, true));
    }
}
