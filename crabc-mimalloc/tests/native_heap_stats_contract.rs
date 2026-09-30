#![cfg(target_arch = "x86_64")]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use crabc_mimalloc::__crabc_runtime::{source_api as api, source_heap_api as heaps};

#[test]
fn heap_json_and_free_statistics_use_the_callers_default_theap() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
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
