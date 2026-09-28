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
};

const REQUEST: usize = 64 * 1024;

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
fn remote_free_between_post_exit_reclaim_and_reuse_keeps_os_page_owned() {
    std::env::set_var("mimalloc_disallow_arena_alloc", "1");
    std::env::set_var("mimalloc_page_full_retain", "-1");
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native process exposes its Linux page size");
    assert!(native_runtime_test_support::initialize(page_size));
    assert_eq!(native_runtime_first_arena_policy_test_audit().unwrap()
        .vm_policy_disallow_arena_alloc, 1);
    let warmup = match native_allocate_aligned(48, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the source process allocates its warmup client"),
    };
    assert_eq!(unsafe { native_free(warmup) }, NativePageFreeResult::Freed);
    native_collect(true);
    let baseline = medium_map_image();

    let (clients_sender, clients_receiver) = mpsc::sync_channel(0);
    let (owner_go_sender, owner_go_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        let blocks = [allocate_medium(), allocate_medium(), allocate_medium()];
        let local = unsafe { native_runtime_current_local_page_test_audit(client(blocks[0])) }
            .expect("the owner holds its regular medium page");
        assert_eq!((local.used, local.reserved, local.regular_queue_count), (3, 6, 1));
        assert!(unsafe { native_runtime_current_local_page_same_test_audit(
            client(blocks[0]), client(blocks[1])) }.unwrap());
        assert!(unsafe { native_runtime_current_local_page_same_test_audit(
            client(blocks[0]), client(blocks[2])) }.unwrap());
        assert_eq!(unsafe { native_block_size(client(blocks[0])) }, Some(81920));
        clients_sender.send(blocks).unwrap();
        owner_go_receiver.recv().unwrap();
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    });
    let blocks = clients_receiver.recv().unwrap();

    let (first_ready_sender, first_ready_receiver) = mpsc::sync_channel(0);
    let (first_go_sender, first_go_receiver) = mpsc::sync_channel(0);
    let (first_phase_sender, first_phase_receiver) = mpsc::sync_channel(0);
    let (first_resume_sender, first_resume_receiver) = mpsc::sync_channel(0);
    let (first_done_sender, first_done_receiver) = mpsc::sync_channel(0);
    let first = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        first_ready_sender.send(()).unwrap();
        first_go_receiver.recv().unwrap();
        assert_eq!(unsafe { native_free(client(blocks[0])) }, NativePageFreeResult::Freed);
        let reclaimed = unsafe { native_runtime_current_local_page_test_audit(client(blocks[2])) }
            .expect("the first survivor reclaimed the OS page");
        assert_eq!((reclaimed.used, reclaimed.reserved), (2, 6));
        let reused_first = allocate_medium();
        assert!(unsafe { native_runtime_current_local_page_same_test_audit(
            client(blocks[2]), client(reused_first)) }.unwrap());
        let after_reuse = unsafe { native_runtime_current_local_page_test_audit(client(blocks[2])) }.unwrap();
        assert_eq!(after_reuse.used, 3);
        first_phase_sender.send(reused_first).unwrap();
        first_resume_receiver.recv().unwrap();
        let before_collect = unsafe { native_runtime_current_local_page_test_audit(client(blocks[2])) }.unwrap();
        assert_eq!(before_collect.used, 3);
        native_collect(false);
        let after_collect = unsafe { native_runtime_current_local_page_test_audit(client(blocks[2])) }.unwrap();
        assert_eq!(after_collect.used, 2);
        let reused_second = allocate_medium();
        assert!(unsafe { native_runtime_current_local_page_same_test_audit(
            client(blocks[2]), client(reused_second)) }.unwrap());
        first_done_sender.send(reused_second).unwrap();
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    });

    let (second_ready_sender, second_ready_receiver) = mpsc::sync_channel(0);
    let (remote_go_sender, remote_go_receiver) = mpsc::sync_channel(0);
    let (remote_done_sender, remote_done_receiver) = mpsc::sync_channel(0);
    let (final_sender, final_receiver) = mpsc::sync_channel(0);
    let second = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        second_ready_sender.send(()).unwrap();
        remote_go_receiver.recv().unwrap();
        assert_eq!(unsafe { native_free(client(blocks[1])) }, NativePageFreeResult::Freed);
        remote_done_sender.send(()).unwrap();
        let remaining: [usize; 3] = final_receiver.recv().unwrap();
        for address in remaining {
            assert_eq!(unsafe { native_free(client(address)) }, NativePageFreeResult::Freed);
        }
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    });
    first_ready_receiver.recv().unwrap();
    second_ready_receiver.recv().unwrap();
    owner_go_sender.send(()).unwrap();
    owner.join().unwrap();
    let after_exit = medium_map_image();
    assert_eq!(medium_slices(after_exit), medium_slices(baseline) + 8);
    assert_eq!(after_exit.medium_abandoned_slices, baseline.medium_abandoned_slices + 8);
    assert_eq!(unsafe { native_runtime_live_client_memory_kind_test_audit(client(blocks[2])) }, Some(3));

    first_go_sender.send(()).unwrap();
    let reused_first = first_phase_receiver.recv().unwrap();
    let after_first = medium_map_image();
    assert_eq!(medium_slices(after_first), medium_slices(baseline) + 8);
    assert_eq!(after_first.medium_abandoned_slices, baseline.medium_abandoned_slices);
    assert_eq!(unsafe { native_block_size(client(reused_first)) }, Some(81920));

    remote_go_sender.send(()).unwrap();
    remote_done_receiver.recv().unwrap();
    let after_remote = medium_map_image();
    assert_eq!(medium_slices(after_remote), medium_slices(baseline) + 8);
    assert_eq!(after_remote.medium_remote_pending_slices,
        baseline.medium_remote_pending_slices + 8);

    first_resume_sender.send(()).unwrap();
    let reused_second = first_done_receiver.recv().unwrap();
    first.join().unwrap();
    let after_reuser_exit = medium_map_image();
    assert_eq!(medium_slices(after_reuser_exit), medium_slices(baseline) + 8);
    assert_eq!(after_reuser_exit.medium_abandoned_slices,
        baseline.medium_abandoned_slices + 8);
    assert_eq!(after_reuser_exit.medium_remote_pending_slices,
        baseline.medium_remote_pending_slices);
    assert_eq!(unsafe { native_block_size(client(reused_second)) }, Some(81920));

    final_sender.send([blocks[2], reused_first, reused_second]).unwrap();
    second.join().unwrap();
    let after_final = medium_map_image();
    assert_eq!(medium_slices(after_final), medium_slices(baseline));
    let page_address = blocks[2] & !(page_size - 1);
    let mut residency = 0u8;
    let region_clear = unsafe { crabc_core::mm::mincore_raw(
        page_address as *mut u8, page_size, &mut residency) } == Err(crabc_core::Errno::NOMEM);
    assert!(region_clear, "the final OS medium mapping has been unmapped");

    std::println!("CRABC_MI_OS_MEDIUM_INTERLEAVED_REUSE_BEGIN");
    for (key, value) in [
        ("request", REQUEST), ("block_size", 81920), ("reserved", 6), ("map_count", 8),
        ("owner_setup_valid", 1), ("two_survivors_ready", 1),
        ("abandoned_after_exit", 1), ("registered_after_exit", 1),
        ("first_reclaimed", 1), ("first_reuse_same_page", 1),
        ("registered_after_first_reuse", 1), ("first_used_three", 1),
        ("remote_pending", 1), ("used_before_collect", 3), ("used_after_collect", 2),
        ("second_reuse_same_page", 1), ("remote_head_cleared", 1),
        ("abandoned_after_reuser_exit", 1), ("registered_after_reuser_exit", 1),
        ("live_after_reuser_exit", 1),
        ("remote_and_final_frees", 1), ("terminal_map_clear", 1),
        ("terminal_region_clear", usize::from(region_clear)),
    ] { std::println!("{key}={value}"); }
    std::println!("CRABC_MI_OS_MEDIUM_INTERLEAVED_REUSE_END");
}
