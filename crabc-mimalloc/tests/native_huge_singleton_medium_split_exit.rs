#![cfg(all(target_arch = "x86_64", feature = "native-runtime-test-audit", feature = "native-runtime-test-fault"))]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use std::sync::mpsc;
use core::ffi::c_void;
use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    finish_current_thread_native_after_user_destructors, native_allocate_aligned,
    native_block_size, native_collect, native_free, native_usable_size,
    native_runtime_arena_span_state_test_audit,
    native_runtime_current_local_page_same_test_audit,
    native_runtime_current_local_page_test_audit,
    native_runtime_first_arena_policy_test_audit,
    native_runtime_lifecycle_test_audit,
    native_runtime_live_client_arena_span_test_audit,
    native_runtime_live_client_memory_kind_test_audit,
    native_runtime_live_client_page_test_audit,
    native_runtime_live_client_page_map_span_test_audit,
    native_runtime_terminal_vm_current_test_audit,
    prepare_native_later_thread_arena, source_options_api,
};

const HUGE_REQUEST: usize = 5 * 1024 * 1024;
const MEDIUM_REQUEST: usize = 64 * 1024;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PageClasses {
    registered_slices: usize,
    small_empty_slices: usize,
    small_used_slices: usize,
    medium_empty_slices: usize,
    medium_used_slices: usize,
    large_empty_slices: usize,
    large_used_slices: usize,
    singleton_empty_slices: usize,
    singleton_used_slices: usize,
    unknown_kind_slices: usize,
    abandoned_slices: usize,
    detached_slices: usize,
    attached_slices: usize,
    nonprimary_slices: usize,
    medium_abandoned_slices: usize,
    medium_detached_slices: usize,
    medium_attached_slices: usize,
    medium_remote_pending_slices: usize,
    medium_reusable_slices: usize,
    medium_retired_slices: usize,
}

unsafe extern "C" {
    fn __crabc_mimalloc_page_map_class_test_audit(output: *mut c_void, bytes: usize) -> i32;
}

fn page_classes() -> PageClasses {
    native_runtime_first_arena_policy_test_audit().expect("the selected process owns its PageMap");
    let mut classes = PageClasses::default();
    // SAFETY: every participating owner is parked or joined while the selected
    // PageMap and its published pages are scanned.
    assert_eq!(unsafe { __crabc_mimalloc_page_map_class_test_audit(
        (&mut classes as *mut PageClasses).cast(), core::mem::size_of::<PageClasses>(),
    ) }, 0);
    classes
}

fn client(address: usize) -> core::ptr::NonNull<u8> {
    core::ptr::NonNull::new(address as *mut u8).expect("the exact live client is nonnull")
}

fn allocate(request: usize) -> usize {
    let NativePageAllocationResult::Allocated(block) = native_allocate_aligned(request, 16, false)
    else { panic!("the source page supplies the requested exact client"); };
    block.as_ptr().addr()
}

fn free_client(address: usize) {
    assert_eq!(unsafe { native_free(client(address)) }, NativePageFreeResult::Freed);
}

fn vm_current() -> (i64, i64) {
    let current = native_runtime_terminal_vm_current_test_audit().unwrap();
    (current.reserved, current.committed)
}

fn os_list_empty() -> bool {
    native_runtime_lifecycle_test_audit().unwrap().main_heap_os_abandoned_pages_empty == 1
}

#[test]
fn huge_arena_singleton_and_medium_page_release_on_separate_survivors() {
    std::env::set_var("mimalloc_page_full_retain", "-1");
    std::env::set_var("mimalloc_page_reclaim_on_free", "1");
    std::env::set_var("mimalloc_purge_delay", "1000000");
    std::env::set_var("mimalloc_purge_decommits", "1");
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native process exposes its Linux page size");
    assert!(native_runtime_test_support::initialize(page_size));
    let warmup = allocate(48);
    free_client(warmup);
    native_collect(true);
    assert!(prepare_native_later_thread_arena());
    free_client(allocate(48));
    let initial = native_runtime_lifecycle_test_audit().unwrap();

    let (owner_sender, owner_receiver) = mpsc::sync_channel(0);
    let (owner_exit_sender, owner_exit_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        let huge = allocate(HUGE_REQUEST);
        let medium = [allocate(MEDIUM_REQUEST), allocate(MEDIUM_REQUEST)];
        let local = unsafe { native_runtime_current_local_page_test_audit(client(medium[0])) }.unwrap();
        assert_eq!((local.used, local.reserved, local.regular_queue_count), (2, 6, 1));
        assert!(unsafe { native_runtime_current_local_page_same_test_audit(
            client(medium[0]), client(medium[1])) }.unwrap());
        assert_eq!(unsafe { native_block_size(client(huge)) }, Some(5505024));
        assert_eq!(unsafe { native_block_size(client(medium[0])) }, Some(81920));
        owner_sender.send((huge, medium)).unwrap();
        owner_exit_receiver.recv().unwrap();
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    });
    let (huge, medium) = owner_receiver.recv().unwrap();
    assert_eq!(unsafe { native_runtime_live_client_memory_kind_test_audit(client(huge)) }, Some(6));
    assert_eq!(unsafe { native_runtime_live_client_memory_kind_test_audit(client(medium[1])) }, Some(6));
    let huge_map = unsafe { native_runtime_live_client_page_test_audit(client(huge)) }.unwrap();
    let medium_map = unsafe { native_runtime_live_client_page_test_audit(client(medium[1])) }.unwrap();
    let huge_arena = unsafe { native_runtime_live_client_arena_span_test_audit(client(huge)) }.unwrap();
    let medium_arena = unsafe { native_runtime_live_client_arena_span_test_audit(client(medium[1])) }.unwrap();
    assert_eq!((huge_map.arena_slice_count(), huge_map.registered_slice_count()), (84, 63));
    assert_eq!((medium_map.arena_slice_count(), medium_map.registered_slice_count()), (8, 8));
    assert_eq!((huge_arena.slice_count(), medium_arena.slice_count()), (84, 8));

    let (medium_ready_sender, medium_ready_receiver) = mpsc::sync_channel(0);
    let (medium_first_sender, medium_first_receiver) = mpsc::sync_channel(0);
    let (medium_first_done_sender, medium_first_done_receiver) = mpsc::sync_channel(0);
    let (medium_final_sender, medium_final_receiver) = mpsc::sync_channel(0);
    let (medium_final_done_sender, medium_final_done_receiver) = mpsc::sync_channel(0);
    let medium_survivor = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        medium_ready_sender.send(()).unwrap();
        medium_first_receiver.recv().unwrap();
        free_client(medium[0]);
        let reclaimed = unsafe { native_runtime_current_local_page_test_audit(client(medium[1])) }.unwrap();
        assert_eq!((reclaimed.used, reclaimed.reserved, reclaimed.regular_queue_count), (1, 6, 1));
        medium_first_done_sender.send(()).unwrap();
        medium_final_receiver.recv().unwrap();
        free_client(medium[1]);
        let retained = unsafe { native_runtime_live_client_page_map_span_test_audit(medium_map) }
            .unwrap().matching_page_entry_count == 8;
        assert!(retained);
        native_collect(true);
        let released = unsafe { native_runtime_live_client_page_map_span_test_audit(medium_map) }
            .unwrap().non_null_entry_count == 0;
        assert!(released);
        medium_final_done_sender.send((retained, released)).unwrap();
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    });

    let (huge_ready_sender, huge_ready_receiver) = mpsc::sync_channel(0);
    let (huge_go_sender, huge_go_receiver) = mpsc::sync_channel(0);
    let (huge_done_sender, huge_done_receiver) = mpsc::sync_channel(0);
    let huge_survivor = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        huge_ready_sender.send(()).unwrap();
        huge_go_receiver.recv().unwrap();
        assert!(unsafe { native_usable_size(client(huge)) }.is_some_and(|bytes| bytes >= HUGE_REQUEST));
        free_client(huge);
        let released = unsafe { native_runtime_live_client_page_map_span_test_audit(huge_map) }
            .unwrap().non_null_entry_count == 0;
        assert!(released);
        huge_done_sender.send(released).unwrap();
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    });

    medium_ready_receiver.recv().unwrap();
    huge_ready_receiver.recv().unwrap();
    let before_exit_classes = page_classes();
    owner_exit_sender.send(()).unwrap();
    owner.join().unwrap();
    let after_exit_classes = page_classes();
    let exit_huge_map = unsafe { native_runtime_live_client_page_map_span_test_audit(huge_map) }.unwrap();
    let exit_medium_map = unsafe { native_runtime_live_client_page_map_span_test_audit(medium_map) }.unwrap();
    let both_registered_after_exit = exit_huge_map.matching_page_entry_count == 63
        && exit_medium_map.matching_page_entry_count == 8;
    assert!(both_registered_after_exit);
    let exit_huge_arena = unsafe { native_runtime_arena_span_state_test_audit(huge_arena) }.unwrap();
    let exit_medium_arena = unsafe { native_runtime_arena_span_state_test_audit(medium_arena) }.unwrap();
    let both_arena_claimed_after_exit = exit_huge_arena.page_record_set == 1
        && exit_medium_arena.page_record_set == 1;
    assert!(both_arena_claimed_after_exit);
    assert_eq!((exit_huge_arena.abandoned_record_set, exit_medium_arena.abandoned_record_set), (0, 1));
    let huge_unmapped_after_exit = after_exit_classes.abandoned_slices
        == before_exit_classes.abandoned_slices + huge_map.registered_slice_count()
            + medium_map.registered_slice_count()
        && exit_huge_arena.abandoned_record_set == 0;
    let medium_mapped_after_exit = after_exit_classes.medium_abandoned_slices
        == before_exit_classes.medium_abandoned_slices + medium_map.registered_slice_count()
        && exit_medium_arena.abandoned_record_set == 1;
    assert!(huge_unmapped_after_exit && medium_mapped_after_exit);
    let os_list_empty_after_exit = os_list_empty();
    assert!(os_list_empty_after_exit);

    medium_first_sender.send(()).unwrap();
    medium_first_done_receiver.recv().unwrap();
    let after_medium_reclaim_classes = page_classes();
    assert_eq!(after_medium_reclaim_classes.abandoned_slices,
        before_exit_classes.abandoned_slices + huge_map.registered_slice_count());
    assert_eq!(after_medium_reclaim_classes.medium_abandoned_slices,
        before_exit_classes.medium_abandoned_slices);
    let huge_still_registered = unsafe { native_runtime_live_client_page_map_span_test_audit(huge_map) }
        .unwrap().matching_page_entry_count == 63;
    let medium_still_registered = unsafe { native_runtime_live_client_page_map_span_test_audit(medium_map) }
        .unwrap().matching_page_entry_count == 8;
    assert!(huge_still_registered && medium_still_registered);
    let vm_before_huge = vm_current();

    huge_go_sender.send(()).unwrap();
    let huge_final_release = huge_done_receiver.recv().unwrap();
    let after_huge_release_classes = page_classes();
    assert_eq!(after_huge_release_classes.abandoned_slices,
        before_exit_classes.abandoned_slices);
    let after_huge = unsafe { native_runtime_arena_span_state_test_audit(huge_arena) }.unwrap();
    let after_medium = unsafe { native_runtime_arena_span_state_test_audit(medium_arena) }.unwrap();
    assert_eq!((after_huge.page_record_set, after_huge.abandoned_record_set,
        after_huge.free_slices, after_huge.committed_slices, after_huge.purge_slices),
        (0, 0, 84, 84, 84));
    let medium_retained_after_huge = after_medium.page_record_set == 1
        && unsafe { native_runtime_live_client_page_map_span_test_audit(medium_map) }
            .unwrap().matching_page_entry_count == 8;
    assert!(medium_retained_after_huge);
    let vm_after_huge = vm_current();
    assert_eq!(vm_before_huge, vm_after_huge);

    medium_final_sender.send(()).unwrap();
    let (medium_retained_before_collect, medium_final_release) = medium_final_done_receiver.recv().unwrap();
    let after_medium_final = unsafe { native_runtime_arena_span_state_test_audit(medium_arena) }.unwrap();
    let after_huge_final = unsafe { native_runtime_arena_span_state_test_audit(huge_arena) }.unwrap();
    let huge_still_clear = unsafe { native_runtime_live_client_page_map_span_test_audit(huge_map) }
        .unwrap().non_null_entry_count == 0;
    assert!(huge_still_clear && medium_final_release);
    assert_eq!((after_medium_final.page_record_set, after_medium_final.free_slices,
        after_medium_final.committed_slices), (0, 8, 8));
    assert_eq!(after_huge_final.purge_slices, 0);
    let os_list_empty_after_final = os_list_empty();
    assert!(os_list_empty_after_final);
    let vm_after_medium = vm_current();
    assert_eq!(vm_after_huge, vm_after_medium);
    medium_survivor.join().unwrap();
    huge_survivor.join().unwrap();
    let final_state = native_runtime_lifecycle_test_audit().unwrap();
    assert_eq!(final_state.arena_registry_count, initial.arena_registry_count);
    assert_eq!(source_options_api::option_get(0), 0);

    std::println!("CRABC_MI_HUGE_SINGLETON_MEDIUM_SPLIT_EXIT_BEGIN");
    for (key, value) in [
        ("huge_request", HUGE_REQUEST as i64), ("medium_request", MEDIUM_REQUEST as i64),
        ("huge_block_size", 5505024), ("medium_block_size", 81920),
        ("medium_reserved", 6),
        ("huge_slice_count", huge_map.arena_slice_count() as i64),
        ("huge_map_count", huge_map.registered_slice_count() as i64),
        ("medium_slice_count", medium_map.arena_slice_count() as i64),
        ("medium_map_count", medium_map.registered_slice_count() as i64),
        ("setup_valid", 1), ("two_survivors_ready", 1),
        ("huge_unmapped_after_exit", i64::from(huge_unmapped_after_exit)),
        ("medium_mapped_after_exit", i64::from(medium_mapped_after_exit)),
        ("both_registered_after_exit", i64::from(both_registered_after_exit)),
        ("both_arena_claimed_after_exit", i64::from(both_arena_claimed_after_exit)),
        ("os_list_empty_after_exit", i64::from(os_list_empty_after_exit)),
        ("medium_reclaimed", 1),
        ("huge_still_registered", i64::from(huge_still_registered)),
        ("medium_still_registered", i64::from(medium_still_registered)),
        ("huge_final_release", i64::from(huge_final_release)),
        ("huge_claim_clear", i64::from(after_huge.page_record_set == 0)),
        ("huge_slices_free", i64::from(after_huge.free_slices == 84)),
        ("medium_retained_after_huge", i64::from(medium_retained_after_huge)),
        ("huge_free_after_release", after_huge.free_slices as i64),
        ("huge_committed_after_release", after_huge.committed_slices as i64),
        ("huge_purge_after_release", after_huge.purge_slices as i64),
        ("huge_reserved_drop", vm_before_huge.0 - vm_after_huge.0),
        ("huge_committed_drop", vm_before_huge.1 - vm_after_huge.1),
        ("medium_retained_before_collect", i64::from(medium_retained_before_collect)),
        ("medium_final_release", i64::from(medium_final_release)),
        ("medium_claim_clear", i64::from(after_medium_final.page_record_set == 0)),
        ("huge_still_clear", i64::from(huge_still_clear)),
        ("os_list_empty_after_final", i64::from(os_list_empty_after_final)),
        ("medium_reserved_drop", vm_after_huge.0 - vm_after_medium.0),
        ("medium_committed_drop", vm_after_huge.1 - vm_after_medium.1),
        ("warning_enabled", source_options_api::option_get(0)),
    ] { std::println!("{key}={value}"); }
    std::println!("CRABC_MI_HUGE_SINGLETON_MEDIUM_SPLIT_EXIT_END");
}
