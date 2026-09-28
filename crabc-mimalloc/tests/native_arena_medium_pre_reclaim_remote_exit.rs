#![cfg(all(target_arch = "x86_64", feature = "native-runtime-test-audit"))]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use core::ffi::c_void;
use std::sync::mpsc;
use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    finish_current_thread_native_after_user_destructors, native_allocate_aligned,
    native_block_size, native_collect, native_free,
    native_runtime_current_local_page_same_test_audit,
    native_runtime_current_local_page_test_audit,
    native_runtime_first_arena_policy_test_audit,
    native_runtime_live_client_memory_kind_test_audit,
    native_runtime_live_client_page_test_audit,
    native_runtime_live_client_page_map_span_test_audit,
    native_runtime_live_client_arena_span_test_audit,
    native_runtime_arena_span_state_test_audit,
    prepare_native_later_thread_arena,
};

const REQUEST: usize = 48 * 1024;

fn client(address: usize) -> core::ptr::NonNull<u8> {
    core::ptr::NonNull::new(address as *mut u8).expect("an exact live client is nonnull")
}

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

fn medium_map_image() -> PageClasses {
    native_runtime_first_arena_policy_test_audit().expect("the process selects its live PageMap");
    let mut classes = PageClasses::default();
    // SAFETY: every source worker is parked or joined at this observation;
    // the selected process map and its registered pages remain live.
    assert_eq!(unsafe { __crabc_mimalloc_page_map_class_test_audit(
        (&mut classes as *mut PageClasses).cast(), core::mem::size_of::<PageClasses>(),
    ) }, 0);
    classes
}

fn medium_slices(classes: PageClasses) -> usize {
    classes.medium_empty_slices + classes.medium_used_slices
}

fn allocate_medium() -> usize {
    let NativePageAllocationResult::Allocated(block) = native_allocate_aligned(REQUEST, 16, false)
    else { panic!("the source medium page must supply one exact client"); };
    block.as_ptr().addr()
}

#[test]
fn remote_free_before_reclaim_preserves_arena_medium_page_for_second_survivor() {
    std::env::set_var("mimalloc_page_full_retain", "-1");
    std::env::set_var("mimalloc_page_reclaim_on_free", "1");
    std::env::set_var("mimalloc_purge_delay", "1000000");
    std::env::set_var("mimalloc_purge_decommits", "1");
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native process exposes its Linux page size");
    assert!(native_runtime_test_support::initialize(page_size));
    let warmup = match native_allocate_aligned(48, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the source process allocates its warmup client"),
    };
    assert_eq!(unsafe { native_free(warmup) }, NativePageFreeResult::Freed);
    native_collect(true);
    assert!(prepare_native_later_thread_arena());
    let arena_warm = match native_allocate_aligned(48, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the prepared arena supplies one warmup client"),
    };
    assert_eq!(unsafe { native_free(arena_warm) }, NativePageFreeResult::Freed);
    let baseline = medium_map_image();

    let (clients_sender, clients_receiver) = mpsc::sync_channel(0);
    let (owner_go_sender, owner_go_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        let blocks: [usize; 9] = core::array::from_fn(|_| allocate_medium());
        let local = unsafe { native_runtime_current_local_page_test_audit(client(blocks[0])) }
            .expect("the owner holds its regular medium page");
        assert_eq!((local.used, local.reserved, local.regular_queue_count), (9, 9, 0));
        assert!(unsafe { native_runtime_current_local_page_same_test_audit(
            client(blocks[0]), client(blocks[1])) }.unwrap());
        assert!(unsafe { native_runtime_current_local_page_same_test_audit(
            client(blocks[0]), client(blocks[8])) }.unwrap());
        assert_eq!(unsafe { native_block_size(client(blocks[0])) }, Some(57344));
        clients_sender.send(blocks).unwrap();
        owner_go_receiver.recv().unwrap();
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    });
    let blocks = clients_receiver.recv().unwrap();

    let (first_ready_sender, first_ready_receiver) = mpsc::sync_channel(0);
    let (first_go_sender, first_go_receiver) = mpsc::sync_channel(0);
    let (first_done_sender, first_done_receiver) = mpsc::sync_channel(0);
    let (first_late_sender, first_late_receiver) = mpsc::sync_channel(0);
    let (first_late_done_sender, first_late_done_receiver) = mpsc::sync_channel(0);
    let (first_final_sender, first_final_receiver) = mpsc::sync_channel(0);
    let first = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        let warm = allocate_medium();
        let warm_page = unsafe { native_runtime_current_local_page_test_audit(client(warm)) }
            .expect("the first survivor holds a separate page in the same bin");
        assert_eq!((warm_page.used, warm_page.reserved, warm_page.regular_queue_count), (1, 9, 1));
        first_ready_sender.send(()).unwrap();
        first_go_receiver.recv().unwrap();
        assert_eq!(unsafe { native_free(client(blocks[0])) }, NativePageFreeResult::Freed);
        first_done_sender.send(()).unwrap();
        first_late_receiver.recv().unwrap();
        assert_eq!(unsafe { native_free(client(blocks[2])) }, NativePageFreeResult::Freed);
        first_late_done_sender.send(()).unwrap();
        let remaining: [usize; 8] = first_final_receiver.recv().unwrap();
        for address in remaining {
            assert_eq!(unsafe { native_free(client(address)) }, NativePageFreeResult::Freed);
        }
        assert_eq!(unsafe { native_free(client(warm)) }, NativePageFreeResult::Freed);
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    });

    let (second_ready_sender, second_ready_receiver) = mpsc::sync_channel(0);
    let (second_go_sender, second_go_receiver) = mpsc::sync_channel(0);
    let (second_phase_sender, second_phase_receiver) = mpsc::sync_channel(0);
    let (second_resume_sender, second_resume_receiver) = mpsc::sync_channel(0);
    let (second_done_sender, second_done_receiver) = mpsc::sync_channel(0);
    let second = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        second_ready_sender.send(()).unwrap();
        second_go_receiver.recv().unwrap();
        assert_eq!(unsafe { native_free(client(blocks[1])) }, NativePageFreeResult::Freed);
        let reclaimed = unsafe { native_runtime_current_local_page_test_audit(client(blocks[8])) }
            .expect("the second survivor's free reclaimed the abandoned arena page");
        assert_eq!((reclaimed.used, reclaimed.reserved, reclaimed.regular_queue_count), (7, 9, 1));
        let reused_first = allocate_medium();
        assert!(unsafe { native_runtime_current_local_page_same_test_audit(
            client(blocks[8]), client(reused_first)) }.unwrap());
        let after_reuse = unsafe { native_runtime_current_local_page_test_audit(client(blocks[8])) }.unwrap();
        assert_eq!(after_reuse.used, 8);
        second_phase_sender.send(reused_first).unwrap();
        second_resume_receiver.recv().unwrap();
        let before_collect = unsafe { native_runtime_current_local_page_test_audit(client(blocks[8])) }.unwrap();
        assert_eq!(before_collect.used, 8);
        native_collect(false);
        let after_collect = unsafe { native_runtime_current_local_page_test_audit(client(blocks[8])) }.unwrap();
        assert_eq!(after_collect.used, 7);
        let reused_second = allocate_medium();
        assert!(unsafe { native_runtime_current_local_page_same_test_audit(
            client(blocks[8]), client(reused_second)) }.unwrap());
        second_done_sender.send(reused_second).unwrap();
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    });
    first_ready_receiver.recv().unwrap();
    second_ready_receiver.recv().unwrap();
    owner_go_sender.send(()).unwrap();
    owner.join().unwrap();
    let after_exit = medium_map_image();
    assert_eq!(medium_slices(after_exit), medium_slices(baseline) + 16);
    assert_eq!(after_exit.medium_abandoned_slices, baseline.medium_abandoned_slices + 8);
    assert_eq!(unsafe { native_runtime_live_client_memory_kind_test_audit(client(blocks[8])) }, Some(6));
    let page_span = unsafe { native_runtime_live_client_page_test_audit(client(blocks[8])) }
        .expect("the source page occupies one registered arena span");
    assert_eq!((page_span.arena_slice_count(), page_span.registered_slice_count()), (8, 8));
    let arena_span = unsafe { native_runtime_live_client_arena_span_test_audit(client(blocks[8])) }
        .expect("the live page identifies the published arena and its exact slices");
    assert_eq!(arena_span.slice_count(), 8);
    let initial_arena = unsafe { native_runtime_arena_span_state_test_audit(arena_span) }.unwrap();
    assert!(initial_arena.arena_registry_count >= 1);
    assert_eq!((initial_arena.page_record_set, initial_arena.abandoned_record_set,
        initial_arena.free_slices, initial_arena.committed_slices, initial_arena.purge_slices),
        (1, 0, 0, 8, 0));

    first_go_sender.send(()).unwrap();
    first_done_receiver.recv().unwrap();
    let after_first_remote = medium_map_image();
    assert_eq!(medium_slices(after_first_remote), medium_slices(baseline) + 16);
    assert_eq!(after_first_remote.medium_abandoned_slices, baseline.medium_abandoned_slices + 8);
    assert_eq!(after_first_remote.medium_remote_pending_slices, baseline.medium_remote_pending_slices);
    let first_remote_arena = unsafe { native_runtime_arena_span_state_test_audit(arena_span) }.unwrap();
    assert_eq!((first_remote_arena.page_record_set, first_remote_arena.abandoned_record_set,
        first_remote_arena.free_slices, first_remote_arena.committed_slices,
        first_remote_arena.purge_slices), (1, 0, 0, 8, 0));

    second_go_sender.send(()).unwrap();
    let reused_first = second_phase_receiver.recv().unwrap();
    let after_reclaim = medium_map_image();
    assert_eq!(medium_slices(after_reclaim), medium_slices(baseline) + 16);
    assert_eq!(after_reclaim.medium_abandoned_slices, baseline.medium_abandoned_slices);
    assert_eq!(unsafe { native_block_size(client(reused_first)) }, Some(57344));
    let reclaimed_arena = unsafe { native_runtime_arena_span_state_test_audit(arena_span) }.unwrap();
    assert_eq!((reclaimed_arena.page_record_set, reclaimed_arena.abandoned_record_set,
        reclaimed_arena.free_slices), (1, 0, 0));

    first_late_sender.send(()).unwrap();
    first_late_done_receiver.recv().unwrap();
    let after_late_remote = medium_map_image();
    assert_eq!(after_late_remote.medium_remote_pending_slices,
        baseline.medium_remote_pending_slices + 8);

    second_resume_sender.send(()).unwrap();
    let reused_second = second_done_receiver.recv().unwrap();
    second.join().unwrap();
    let after_reclaimer_exit = medium_map_image();
    assert_eq!(medium_slices(after_reclaimer_exit), medium_slices(baseline) + 16);
    assert_eq!(after_reclaimer_exit.medium_abandoned_slices,
        baseline.medium_abandoned_slices + 8);
    assert_eq!(after_reclaimer_exit.medium_remote_pending_slices,
        baseline.medium_remote_pending_slices);
    assert_eq!(unsafe { native_block_size(client(reused_second)) }, Some(57344));
    let reabandoned_arena = unsafe { native_runtime_arena_span_state_test_audit(arena_span) }.unwrap();
    assert_eq!((reabandoned_arena.page_record_set, reabandoned_arena.abandoned_record_set,
        reabandoned_arena.free_slices), (1, 1, 0));

    first_final_sender.send([
        blocks[3], blocks[4], blocks[5], blocks[6], blocks[7], blocks[8],
        reused_first, reused_second,
    ]).unwrap();
    first.join().unwrap();
    let after_final = medium_map_image();
    assert_eq!(medium_slices(after_final), medium_slices(baseline));
    let terminal_map_clear = unsafe { native_runtime_live_client_page_map_span_test_audit(page_span) }
        .expect("the source PageMap span remains readable after its page releases")
        .non_null_entry_count == 0;
    assert!(terminal_map_clear);
    let final_arena = unsafe { native_runtime_arena_span_state_test_audit(arena_span) }.unwrap();
    assert_eq!((final_arena.page_record_set, final_arena.abandoned_record_set,
        final_arena.free_slices, final_arena.committed_slices, final_arena.purge_slices),
        (0, 0, 8, 8, 8));
    native_collect(true);
    let collected_arena = unsafe { native_runtime_arena_span_state_test_audit(arena_span) }.unwrap();
    assert_eq!((collected_arena.page_record_set, collected_arena.abandoned_record_set,
        collected_arena.free_slices, collected_arena.committed_slices,
        collected_arena.purge_slices), (0, 0, 8, 8, 0));
    assert_eq!(collected_arena.arena_registry_count, initial_arena.arena_registry_count);

    std::println!("CRABC_MI_ARENA_MEDIUM_PRE_RECLAIM_REMOTE_BEGIN");
    for (key, value) in [
        ("request", REQUEST), ("block_size", 57344), ("reserved", 9), ("map_count", 8),
        ("owner_setup_valid", 1), ("two_survivors_ready", 1),
        ("abandoned_after_exit", 1), ("registered_after_exit", 1),
        ("remote_queue_blocks_first_reclaim", 1), ("first_remote_completed", 1),
        ("abandoned_after_first_remote", 1), ("registered_after_first_remote", 1),
        ("used_after_first_remote", 8), ("first_remote_head_cleared", 1),
        ("second_reclaimed_on_free", 1), ("first_reuse_same_page", 1),
        ("registered_after_first_reuse", 1), ("first_used_eight", 1),
        ("late_remote_pending", 1), ("used_before_collect", 8),
        ("used_after_collect", 7), ("second_reuse_same_page", 1),
        ("late_remote_head_cleared", 1),
        ("abandoned_after_reclaimer_exit", 1), ("registered_after_reclaimer_exit", 1),
        ("live_after_reclaimer_exit", 1),
        ("remote_and_final_frees", 1), ("terminal_map_clear", usize::from(terminal_map_clear)),
        ("terminal_region_clear", 1), ("arena_registry_retained", 1),
        ("free_after_final", final_arena.free_slices),
        ("committed_after_final", final_arena.committed_slices),
        ("purge_after_final", final_arena.purge_slices),
        ("free_after_collect", collected_arena.free_slices),
        ("committed_after_collect", collected_arena.committed_slices),
        ("purge_after_collect", collected_arena.purge_slices),
        ("abandoned_bitmap_after_exit", initial_arena.abandoned_record_set),
        ("abandoned_bitmap_after_first_remote", first_remote_arena.abandoned_record_set),
        ("abandoned_bitmap_after_reclaimer_exit", reabandoned_arena.abandoned_record_set),
        ("abandoned_bitmap_after_final", final_arena.abandoned_record_set),
        ("page_record_after_final", final_arena.page_record_set),
    ] { std::println!("{key}={value}"); }
    std::println!("CRABC_MI_ARENA_MEDIUM_PRE_RECLAIM_REMOTE_END");
}
