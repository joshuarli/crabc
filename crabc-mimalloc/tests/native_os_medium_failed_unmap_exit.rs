#![cfg(all(target_arch = "x86_64", feature = "native-runtime-test-audit", feature = "native-runtime-test-fault"))]

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
    native_runtime_terminal_vm_current_test_audit,
    native_runtime_test_fail_next_unmap,
};

const REQUEST: usize = 64 * 1024;

fn client(address: usize) -> core::ptr::NonNull<u8> {
    core::ptr::NonNull::new(address as *mut u8).expect("a live source client is nonnull")
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
    let mut classes = PageClasses::default();
    // SAFETY: every mutating worker is parked or joined; the process audit
    // selected the exact current PageMap before terminal release.
    assert_eq!(unsafe { __crabc_mimalloc_page_map_class_test_audit(
        (&mut classes as *mut PageClasses).cast(), core::mem::size_of::<PageClasses>(),
    ) }, 0);
    classes
}

fn medium_slices(classes: PageClasses) -> usize {
    classes.medium_empty_slices + classes.medium_used_slices
}

fn vm_current() -> Option<(i64, i64)> {
    native_runtime_terminal_vm_current_test_audit()
        .map(|image| (image.reserved, image.committed))
}

#[test]
fn final_os_medium_unmap_failure_retains_one_terminal_owner() {
    std::env::set_var("mimalloc_disallow_arena_alloc", "1");
    std::env::set_var("mimalloc_page_full_retain", "-1");
    std::env::set_var("mimalloc_show_errors", "1");
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native test process exposes its page size");
    assert!(native_runtime_test_support::initialize(page_size));
    assert_eq!(native_runtime_first_arena_policy_test_audit()
        .expect("the process selects its PageMap").vm_policy_disallow_arena_alloc, 1);
    let warmup = match native_allocate_aligned(48, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the source process allocates its warmup client"),
    };
    assert_eq!(unsafe { native_free(warmup) }, NativePageFreeResult::Freed);
    native_collect(true);
    let baseline = medium_map_image();

    let (clients_sender, clients_receiver) = mpsc::sync_channel(0);
    let (exit_sender, exit_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        let blocks = core::array::from_fn::<_, 2, _>(|_| {
            let NativePageAllocationResult::Allocated(block) = native_allocate_aligned(REQUEST, 16, false)
            else { panic!("the source OS medium page allocates both clients"); };
            block
        });
        let local = unsafe { native_runtime_current_local_page_test_audit(blocks[0]) }
            .expect("the owner holds the regular page");
        assert!(unsafe { native_runtime_current_local_page_same_test_audit(blocks[0], blocks[1]) }
            .expect("both clients share the exact page"));
        assert_eq!((local.used, local.reserved), (2, 6));
        assert_eq!(unsafe { native_block_size(blocks[0]) }, Some(81920));
        clients_sender.send(blocks.map(|block| block.as_ptr().addr())).unwrap();
        exit_receiver.recv().unwrap();
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    });

    let clients = clients_receiver.recv().unwrap();
    let mut survivors = Vec::new();
    let mut go = Vec::new();
    for (index, address) in clients.into_iter().enumerate() {
        let (ready_sender, ready_receiver) = mpsc::sync_channel(0);
        let (go_sender, go_receiver) = mpsc::sync_channel(0);
        let survivor = std::thread::spawn(move || {
            assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
            ready_sender.send(()).unwrap();
            go_receiver.recv().unwrap();
            if index == 0 {
                assert_eq!(unsafe { native_free(client(address)) }, NativePageFreeResult::Freed);
                let local = unsafe { native_runtime_current_local_page_test_audit(client(clients[1])) }
                    .expect("the first survivor reclaimed the second live client page");
                assert_eq!((local.used, local.reserved), (1, 6));
                assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
                None
            } else {
                let before = vm_current().expect("source statistics before terminal release");
                let fault = native_runtime_test_fail_next_unmap();
                let range = fault.capture_range();
                assert_eq!(unsafe { native_free(client(address)) }, NativePageFreeResult::Retained);
                let failed_range = range.single().expect("one exact failed terminal unmap");
                let after = vm_current();
                let mut residency = 0u8;
                let physical_retained = unsafe {
                    crabc_core::mm::mincore_raw(failed_range.0 as *mut u8, page_size, &mut residency)
                }.is_ok();
                assert_eq!(unsafe { native_free(client(address)) }, NativePageFreeResult::InvalidPointer);
                let attempts = fault.observed();
                drop(range);
                drop(fault);
                let finish = finish_current_thread_native_after_user_destructors();
                Some((failed_range, before, after, physical_retained, attempts, finish))
            }
        });
        ready_receiver.recv().unwrap();
        survivors.push(survivor);
        go.push(go_sender);
    }
    exit_sender.send(()).unwrap();
    owner.join().unwrap();
    let after_exit = medium_map_image();
    assert_eq!(medium_slices(after_exit), medium_slices(baseline) + 8);
    assert_eq!(after_exit.medium_abandoned_slices, baseline.medium_abandoned_slices + 8);
    assert_eq!(unsafe { native_runtime_live_client_memory_kind_test_audit(client(clients[1])) }, Some(3));

    go.remove(0).send(()).unwrap();
    assert!(survivors.remove(0).join().unwrap().is_none());
    let after_first = medium_map_image();
    assert_eq!(medium_slices(after_first), medium_slices(baseline) + 8);
    assert_eq!(unsafe { native_block_size(client(clients[1])) }, Some(81920));

    go.remove(0).send(()).unwrap();
    let (range, before, after, physical_retained, attempts, finish) = survivors.remove(0).join().unwrap().unwrap();
    let after_final = medium_map_image();
    assert_eq!(medium_slices(after_final), medium_slices(baseline));
    assert_eq!(attempts, 1);
    assert!(physical_retained);
    assert_eq!(finish, ThreadFinishResult::Finished);
    assert!(range.0 <= clients[1] && clients[1] < range.0 + range.1);
    assert_eq!(range.1, 9 * 64 * 1024);
    let counters_released = after.map(|after| {
        before.0 - after.0 == range.1 as i64 && before.1 - after.1 == 8 * 64 * 1024
    }).unwrap_or(false);

    std::println!("CRABC_MI_OS_MEDIUM_FAILED_UNMAP_BEGIN");
    for (key, value) in [
        ("request", REQUEST), ("block_size", 81920), ("reserved", 6), ("map_count", 8),
        ("owner_setup_valid", 1), ("two_releasers_ready", 1), ("owner_joined_before_free", 1),
        ("os_backed", 1), ("registered_after_exit", 1), ("medium_used_after_exit", 1),
        ("first_free_completed", 1), ("first_reclaimed_before_exit", 1), ("first_registered", 1),
        ("second_client_live", 1), ("second_free_completed", 1), ("terminal_map_clear", 1),
        ("failed_unmap_attempts", attempts), ("failed_range_exact", 1),
        ("mapping_retained", usize::from(physical_retained)),
        ("counters_released", usize::from(counters_released)), ("os_size", range.1),
        ("reserved_drop", after.map(|after| before.0 - after.0).unwrap_or(0) as usize),
        ("committed_drop", after.map(|after| before.1 - after.1).unwrap_or(0) as usize),
    ] { std::println!("{key}={value}"); }
    std::println!("CRABC_MI_OS_MEDIUM_FAILED_UNMAP_END");
    std::println!("CRABC_MI_OS_MEDIUM_FAILED_RANGE base=0x{:X} length={}", range.0, range.1);
    assert!(counters_released, "the failed source unmap still decrements VM counters once");
}
