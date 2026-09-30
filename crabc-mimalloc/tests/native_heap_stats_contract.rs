#![cfg(target_arch = "x86_64")]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use crabc_mimalloc::__crabc_runtime::{source_api as api, source_heap_api as heaps};

#[test]
fn heap_json_growth_uses_the_callers_selected_default_theap() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    let main_heap = heaps::heap_main();
    let auxiliary = heaps::heap_new();
    assert!(!auxiliary.is_null());
    // SAFETY: this thread retains its auxiliary Heap and both Theaps until
    // the old default is restored; every client is released before destroy.
    let (ordinary_owner, json_owner, length, usable, ordinary_usable) = unsafe {
        let selected = heaps::heap_theap(auxiliary);
        assert!(!selected.is_null());
        let previous = heaps::theap_set_default(selected);
        let ordinary = api::malloc(192).value.unwrap();
        let ordinary_owner = heaps::heap_of(ordinary.as_ptr());
        // Null selects the main Heap statistics while allocation of the
        // growing result follows the caller's independently selected default.
        let json = heaps::heap_stats_json(core::ptr::null_mut(), 0, core::ptr::null_mut());
        assert!(!json.is_null());
        let json_owner = heaps::heap_of(json.cast());
        let length = core::ffi::CStr::from_ptr(json).to_bytes().len();
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
        (ordinary_owner, json_owner, length, usable, ordinary_usable)
    };
    assert_eq!(ordinary_owner, auxiliary);
    assert!(length > 12 * 1024, "the owned JSON traverses its growing-buffer path");
    assert_eq!(usable, ordinary_usable);
    assert_ne!(json_owner, main_heap);
    assert_eq!(json_owner, auxiliary);
}
