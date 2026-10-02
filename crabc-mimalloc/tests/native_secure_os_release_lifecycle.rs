#![cfg(all(target_arch = "x86_64", feature = "mi-secure-5", feature = "native-runtime-test-audit", feature = "native-runtime-test-fault"))]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use core::ptr::NonNull;
use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    finish_current_thread_native_after_user_destructors, native_allocate_aligned,
    native_collect, native_free, native_runtime_live_client_memory_kind_test_audit,
    native_runtime_live_client_page_geometry_test_audit,
    native_runtime_first_arena_policy_test_audit, native_runtime_terminal_vm_current_test_audit,
    native_runtime_test_fail_next_unmap,
};

// The public source option API accepts the fixed C enumerator value.
const MI_OPTION_PAGE_COMMIT_ON_DEMAND: i32 = 40;

struct LiveClient(NonNull<u8>);

// Each value owns one successful native allocation. Source PageMap custody
// keeps it live after allocating-worker teardown until one receiving worker
// consumes it, so transferring the original pointer preserves its provenance.
unsafe impl Send for LiveClient {}

impl LiveClient {
    fn into_pointer(self) -> NonNull<u8> { self.0 }
}

fn vm_current() -> (i64, i64) {
    let image = native_runtime_terminal_vm_current_test_audit().unwrap();
    (image.reserved, image.committed)
}

fn fully_committed_os_page_returns_its_allocation_charge() {
    const REQUEST: usize = 64 * 1024;
    let owner = std::thread::spawn(|| {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        let NativePageAllocationResult::Allocated(warm) = native_allocate_aligned(48, 16, false)
            else { panic!("warm the worker's ordinary Heap metadata"); };
        assert_eq!(unsafe { native_free(warm) }, NativePageFreeResult::Freed);
        native_collect(true);
        let baseline = vm_current();
        let NativePageAllocationResult::Allocated(client) = native_allocate_aligned(REQUEST, 16, false)
            else { panic!("allocate the fully committed OS Page control"); };
        let geometry = unsafe { native_runtime_live_client_page_geometry_test_audit(client) }.unwrap();
        assert_eq!(geometry.slice_pcommitted, 0);
        assert_eq!(unsafe { native_runtime_live_client_memory_kind_test_audit(client) }, Some(3));
        let allocated = vm_current();
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
        (LiveClient(client), baseline, allocated)
    });
    let (live_client, baseline, allocated) = owner.join().unwrap();
    let consumer = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        let client = live_client.into_pointer();
        let before = vm_current();
        // SAFETY: the joined producer transferred this still-live exact
        // client; this receiver consumes it once and never reuses its pointer.
        assert_eq!(unsafe { native_free(client) }, NativePageFreeResult::Freed);
        let after = vm_current();
        native_collect(true);
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
        println!("secure.full.release allocation_reserved={} allocation_committed={} release_reserved={} release_committed={} residual_reserved={} residual_committed={}",
            allocated.0-baseline.0, allocated.1-baseline.1, before.0-after.0, before.1-after.1,
            after.0-baseline.0, after.1-baseline.1);
        assert_eq!(after, baseline, "the full OS Page retires its actual allocation charge");
    });
    consumer.join().unwrap();
}

#[test]
fn secure_partial_os_page_reset_is_accounted_once_before_terminal_failed_unmap() {
    const REQUEST: usize = 64 * 1024;
    std::env::set_var("mimalloc_disallow_arena_alloc", "1");
    std::env::set_var("mimalloc_page_commit_on_demand", "0");
    std::env::set_var("mimalloc_page_full_retain", "-1");
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    assert!(crabc_mimalloc::__crabc_runtime::prepare_native_initial_thread_owner());
    let NativePageAllocationResult::Allocated(warm) = native_allocate_aligned(48, 16, false)
        else { panic!("the initial caller publishes the ordinary PageMap"); };
    assert_eq!(unsafe { native_free(warm) }, NativePageFreeResult::Freed);
    native_collect(true);
    assert!(crabc_mimalloc::__crabc_runtime::native_runtime_first_arena_policy_test_audit().is_some());
    fully_committed_os_page_returns_its_allocation_charge();
    let owner = std::thread::spawn(|| {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        let NativePageAllocationResult::Allocated(warm) = native_allocate_aligned(48, 16, false)
            else { panic!("warm the worker's ordinary Heap metadata"); };
        assert_eq!(unsafe { native_free(warm) }, NativePageFreeResult::Freed);
        native_collect(true);
        // Metadata attaches with the ordinary commitment policy; only this
        // client allocation selects the public on-demand option.
        crabc_mimalloc::source_options_api::option_set(MI_OPTION_PAGE_COMMIT_ON_DEMAND, 1);
        let before = vm_current();
        let NativePageAllocationResult::Allocated(client) = native_allocate_aligned(REQUEST, 16, false)
            else { panic!("the ordinary worker allocates its on-demand source Page"); };
        // SAFETY: this worker exclusively owns the live client and its Page.
        let geometry = unsafe { native_runtime_live_client_page_geometry_test_audit(client) }.unwrap();
        assert_eq!(unsafe { native_runtime_live_client_memory_kind_test_audit(client) }, Some(3));
        assert!(geometry.slice_pcommitted > 0);
        assert!(geometry.capacity < geometry.reserved, "only an initial prefix is committed");
        let after = vm_current();
        crabc_mimalloc::source_options_api::option_set(MI_OPTION_PAGE_COMMIT_ON_DEMAND, 0);
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
        (LiveClient(client), geometry, before, after)
    });
    let (live_client, geometry, before_allocation, after_allocation) = owner.join().unwrap();
    let consumer = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        let client = live_client.into_pointer();
        let before = vm_current();
        let before_map = native_runtime_first_arena_policy_test_audit().unwrap().page_map_registered_entry_count;
        let fault = native_runtime_test_fail_next_unmap();
        let capture = fault.capture_range();
        // SAFETY: the joined producer transferred this still-live exact
        // client; this receiver consumes it once and never reuses its pointer.
        assert_eq!(unsafe { native_free(client) }, NativePageFreeResult::Freed);
        let failed_range = capture.single().expect("one exact source release attempt");
        let after = vm_current();
        let after_map = native_runtime_first_arena_policy_test_audit().unwrap().page_map_registered_entry_count;
        assert!(after_map < before_map);
        native_collect(true);
        native_collect(true);
        assert_eq!(vm_current(), after);
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
        assert_eq!(vm_current(), after);
        assert_eq!(capture.single(), Some(failed_range));
        assert_eq!(fault.observed(), 1);
        (failed_range, before, after)
    });
    let (range, before, after) = consumer.join().unwrap();
    let prefix = i64::from(geometry.slice_pcommitted) * page_size as i64;
    println!("secure.partial.release prefix={prefix} reserved_drop={} committed_drop={} allocation_reserved={} allocation_committed={} range_base=0x{:X} range_size={} residual_reserved={} residual_committed={}",
        before.0-after.0, before.1-after.1,
        after_allocation.0-before_allocation.0, after_allocation.1-before_allocation.1, range.0, range.1, after.0-before_allocation.0, after.1-before_allocation.1);
    // SAFETY: the source Page and its only client have been consumed, both
    // workers joined, and only this exact failed syscall extent remains mapped.
    assert!(unsafe { crabc_core::mm::munmap_raw(range.0 as *mut u8, range.1) }.is_ok());
    assert_eq!(vm_current(), after);
    assert_eq!(after_allocation.0-before_allocation.0, range.1 as i64);
    assert_eq!(after_allocation.1-before_allocation.1, prefix);
    assert_eq!(before.0-after.0, range.1 as i64);
    assert_eq!(before.1-after.1, prefix,
        "whole OS release retires both the committed prefix and the successful tail reset charge");
    assert_eq!(after, before_allocation, "terminal free returns the allocation ledger to baseline");
}
