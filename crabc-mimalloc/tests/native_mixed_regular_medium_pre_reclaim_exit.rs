#![cfg(all(target_arch = "x86_64", feature = "native-runtime-test-audit", feature = "native-runtime-test-fault"))]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use core::ffi::c_void;
use std::sync::mpsc;
use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    finish_current_thread_native_after_user_destructors, native_allocate_aligned,
    native_block_size, native_collect, native_free,
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

const REQUEST: usize = 48 * 1024;
const DISALLOW_ARENA_ALLOC: i32 = 26;
const SHOW_ERRORS: i32 = 0;

fn client(address: usize) -> core::ptr::NonNull<u8> {
    core::ptr::NonNull::new(address as *mut u8).expect("the exact live client is nonnull")
}

fn allocate_medium() -> usize {
    let NativePageAllocationResult::Allocated(block) = native_allocate_aligned(REQUEST, 16, false)
    else { panic!("the source medium page supplies an exact client"); };
    block.as_ptr().addr()
}

fn free_client(address: usize) {
    assert_eq!(unsafe { native_free(client(address)) }, NativePageFreeResult::Freed);
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

fn map_image() -> PageClasses {
    native_runtime_first_arena_policy_test_audit().expect("the process selects a live PageMap");
    let mut classes = PageClasses::default();
    // SAFETY: every mutating worker is parked or joined at this sample.
    assert_eq!(unsafe { __crabc_mimalloc_page_map_class_test_audit(
        (&mut classes as *mut PageClasses).cast(), core::mem::size_of::<PageClasses>(),
    ) }, 0);
    classes
}

fn medium_slices(classes: PageClasses) -> usize {
    classes.medium_empty_slices + classes.medium_used_slices
}

fn os_list_empty() -> bool {
    native_runtime_lifecycle_test_audit().unwrap().main_heap_os_abandoned_pages_empty == 1
}

fn vm_current() -> (i64, i64) {
    let current = native_runtime_terminal_vm_current_test_audit().unwrap();
    (current.reserved, current.committed)
}

enum RemotePhase {
    First,
    FinalArena(usize),
    FinalOs(usize),
    Exit,
}

#[test]
fn mixed_regular_medium_pages_reclaim_independently_after_pre_reclaim_remote_frees() {
    std::env::set_var("mimalloc_page_full_retain", "-1");
    std::env::set_var("mimalloc_page_reclaim_on_free", "1");
    std::env::set_var("mimalloc_purge_delay", "1000000");
    std::env::set_var("mimalloc_purge_decommits", "1");
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native process exposes its Linux page size");
    assert!(native_runtime_test_support::initialize(page_size));
    let warmup = native_allocate_aligned(48, 16, false);
    let NativePageAllocationResult::Allocated(warmup) = warmup else { panic!("warmup client"); };
    assert_eq!(unsafe { native_free(warmup) }, NativePageFreeResult::Freed);
    native_collect(true);
    assert!(prepare_native_later_thread_arena());
    let NativePageAllocationResult::Allocated(arena_warm) = native_allocate_aligned(48, 16, false)
    else { panic!("the prepared arena supplies a warmup client"); };
    assert_eq!(unsafe { native_free(arena_warm) }, NativePageFreeResult::Freed);
    let baseline = map_image();

    let (owner_sender, owner_receiver) = mpsc::sync_channel(0);
    let (owner_exit_sender, owner_exit_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        let arena: [usize; 9] = core::array::from_fn(|_| allocate_medium());
        let arena_local = unsafe { native_runtime_current_local_page_test_audit(client(arena[0])) }.unwrap();
        assert_eq!((arena_local.used, arena_local.reserved, arena_local.regular_queue_count), (9, 9, 0));
        assert!(unsafe { native_runtime_current_local_page_same_test_audit(client(arena[0]), client(arena[8])) }.unwrap());
        source_options_api::option_set(DISALLOW_ARENA_ALLOC, 1);
        assert_eq!(source_options_api::option_get(DISALLOW_ARENA_ALLOC), 1);
        let os: [usize; 9] = core::array::from_fn(|_| allocate_medium());
        let os_local = unsafe { native_runtime_current_local_page_test_audit(client(os[0])) }.unwrap();
        assert_eq!((os_local.used, os_local.reserved, os_local.regular_queue_count), (9, 9, 0));
        assert!(unsafe { native_runtime_current_local_page_same_test_audit(client(os[0]), client(os[8])) }.unwrap());
        assert!(!unsafe { native_runtime_current_local_page_same_test_audit(client(arena[0]), client(os[0])) }.unwrap());
        owner_sender.send((arena, os)).unwrap();
        owner_exit_receiver.recv().unwrap();
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    });
    let (arena_clients, os_clients) = owner_receiver.recv().unwrap();
    assert_eq!(unsafe { native_runtime_live_client_memory_kind_test_audit(client(arena_clients[8])) }, Some(6));
    assert_eq!(unsafe { native_runtime_live_client_memory_kind_test_audit(client(os_clients[8])) }, Some(3));
    assert_eq!(unsafe { native_block_size(client(arena_clients[8])) }, Some(57344));
    assert_eq!(unsafe { native_block_size(client(os_clients[8])) }, Some(57344));
    let arena_span = unsafe { native_runtime_live_client_arena_span_test_audit(client(arena_clients[8])) }.unwrap();
    let arena_map = unsafe { native_runtime_live_client_page_test_audit(client(arena_clients[8])) }.unwrap();
    assert_eq!((arena_span.slice_count(), arena_map.registered_slice_count()), (8, 8));
    assert!(unsafe { native_runtime_live_client_arena_span_test_audit(client(os_clients[8])) }.is_none());

    let (remote_ready_sender, remote_ready_receiver) = mpsc::sync_channel(0);
    let (remote_phase_sender, remote_phase_receiver) = mpsc::sync_channel(0);
    let (remote_done_sender, remote_done_receiver) = mpsc::sync_channel(0);
    let remote = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        let warm = allocate_medium();
        let local = unsafe { native_runtime_current_local_page_test_audit(client(warm)) }.unwrap();
        assert_eq!((local.used, local.reserved, local.regular_queue_count), (1, 9, 1));
        remote_ready_sender.send(()).unwrap();
        match remote_phase_receiver.recv().unwrap() {
            RemotePhase::First => { free_client(arena_clients[0]); free_client(os_clients[0]); }
            _ => panic!("remote first phase"),
        }
        remote_done_sender.send(()).unwrap();
        match remote_phase_receiver.recv().unwrap() {
            RemotePhase::FinalArena(reused) => {
                for address in arena_clients.iter().copied().skip(2) { free_client(address); }
                free_client(reused);
            }
            _ => panic!("remote arena final phase"),
        }
        remote_done_sender.send(()).unwrap();
        match remote_phase_receiver.recv().unwrap() {
            RemotePhase::FinalOs(reused) => {
                for address in os_clients.iter().copied().skip(2) { free_client(address); }
                free_client(reused);
            }
            _ => panic!("remote OS final phase"),
        }
        remote_done_sender.send(()).unwrap();
        assert!(matches!(remote_phase_receiver.recv().unwrap(), RemotePhase::Exit));
        free_client(warm);
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    });

    let (arena_ready_sender, arena_ready_receiver) = mpsc::sync_channel(0);
    let (arena_go_sender, arena_go_receiver) = mpsc::sync_channel(0);
    let (arena_done_sender, arena_done_receiver) = mpsc::sync_channel(0);
    let (arena_exit_sender, arena_exit_receiver) = mpsc::sync_channel(0);
    let arena_reclaimer = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        arena_ready_sender.send(()).unwrap();
        arena_go_receiver.recv().unwrap();
        free_client(arena_clients[1]);
        let page = unsafe { native_runtime_current_local_page_test_audit(client(arena_clients[8])) }.unwrap();
        assert_eq!((page.used, page.reserved, page.regular_queue_count), (7, 9, 1));
        let reused = allocate_medium();
        assert!(unsafe { native_runtime_current_local_page_same_test_audit(client(reused), client(arena_clients[8])) }.unwrap());
        assert_eq!(unsafe { native_runtime_current_local_page_test_audit(client(reused)) }.unwrap().used, 8);
        arena_done_sender.send(reused).unwrap();
        arena_exit_receiver.recv().unwrap();
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    });

    let (os_ready_sender, os_ready_receiver) = mpsc::sync_channel(0);
    let (os_go_sender, os_go_receiver) = mpsc::sync_channel(0);
    let (os_done_sender, os_done_receiver) = mpsc::sync_channel(0);
    let (os_exit_sender, os_exit_receiver) = mpsc::sync_channel(0);
    let os_reclaimer = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        os_ready_sender.send(()).unwrap();
        os_go_receiver.recv().unwrap();
        free_client(os_clients[1]);
        let page = unsafe { native_runtime_current_local_page_test_audit(client(os_clients[8])) }.unwrap();
        assert_eq!((page.used, page.reserved, page.regular_queue_count), (7, 9, 1));
        let reused = allocate_medium();
        assert!(unsafe { native_runtime_current_local_page_same_test_audit(client(reused), client(os_clients[8])) }.unwrap());
        assert_eq!(unsafe { native_runtime_current_local_page_test_audit(client(reused)) }.unwrap().used, 8);
        os_done_sender.send(reused).unwrap();
        os_exit_receiver.recv().unwrap();
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    });
    remote_ready_receiver.recv().unwrap();
    arena_ready_receiver.recv().unwrap();
    os_ready_receiver.recv().unwrap();
    owner_exit_sender.send(()).unwrap();
    owner.join().unwrap();
    let after_exit = map_image();
    assert_eq!(medium_slices(after_exit), medium_slices(baseline) + 24);
    assert_eq!(after_exit.medium_abandoned_slices, baseline.medium_abandoned_slices + 16);
    let exit_os_list = !os_list_empty();
    assert!(exit_os_list);
    let exit_arena = unsafe { native_runtime_arena_span_state_test_audit(arena_span) }.unwrap();
    assert_eq!((exit_arena.page_record_set, exit_arena.abandoned_record_set), (1, 0));

    remote_phase_sender.send(RemotePhase::First).unwrap();
    remote_done_receiver.recv().unwrap();
    let after_remote = map_image();
    assert_eq!(after_remote.medium_abandoned_slices, baseline.medium_abandoned_slices + 16);
    assert_eq!(after_remote.medium_remote_pending_slices, baseline.medium_remote_pending_slices);
    assert!(!os_list_empty());
    assert_eq!(unsafe { native_runtime_arena_span_state_test_audit(arena_span) }.unwrap().abandoned_record_set, 0);

    arena_go_sender.send(()).unwrap();
    let arena_reuse = arena_done_receiver.recv().unwrap();
    let after_arena_reclaim = map_image();
    assert_eq!(after_arena_reclaim.medium_abandoned_slices, baseline.medium_abandoned_slices + 8);
    let arena_map_after_reclaim = unsafe { native_runtime_live_client_page_map_span_test_audit(arena_map) }
        .unwrap().matching_page_entry_count == 8;
    assert!(arena_map_after_reclaim);
    let os_list_while_arena_reclaimed = !os_list_empty();
    assert!(os_list_while_arena_reclaimed);
    os_go_sender.send(()).unwrap();
    let os_reuse = os_done_receiver.recv().unwrap();
    let after_os_reclaim = map_image();
    assert_eq!(after_os_reclaim.medium_abandoned_slices, baseline.medium_abandoned_slices);
    let os_map_after_reclaim = unsafe {
        native_runtime_live_client_memory_kind_test_audit(client(os_clients[8]))
    } == Some(3);
    assert!(os_map_after_reclaim);
    let os_list_after_reclaim_empty = os_list_empty();
    assert!(os_list_after_reclaim_empty);

    arena_exit_sender.send(()).unwrap();
    os_exit_sender.send(()).unwrap();
    arena_reclaimer.join().unwrap();
    os_reclaimer.join().unwrap();
    let after_reexit = map_image();
    assert_eq!(after_reexit.medium_abandoned_slices, baseline.medium_abandoned_slices + 16);
    let reexit_arena = unsafe { native_runtime_arena_span_state_test_audit(arena_span) }.unwrap();
    let reexit_os_list = !os_list_empty();
    assert_eq!(reexit_arena.abandoned_record_set, 1);
    assert!(reexit_os_list);
    assert_eq!(medium_slices(after_reexit), medium_slices(baseline) + 24);
    let reexit_both_mapped = unsafe { native_runtime_live_client_page_map_span_test_audit(arena_map) }
        .unwrap().matching_page_entry_count == 8
        && unsafe { native_runtime_live_client_memory_kind_test_audit(client(os_clients[8])) } == Some(3);
    assert!(reexit_both_mapped);

    let vm_before = vm_current();
    remote_phase_sender.send(RemotePhase::FinalArena(arena_reuse)).unwrap();
    remote_done_receiver.recv().unwrap();
    let after_arena_final = map_image();
    assert_eq!(medium_slices(after_arena_final), medium_slices(baseline) + 16);
    let arena_map_clear = unsafe { native_runtime_live_client_page_map_span_test_audit(arena_map) }.unwrap().non_null_entry_count == 0;
    assert!(arena_map_clear);
    assert!(!os_list_empty());
    let os_map_retained = unsafe {
        native_runtime_live_client_memory_kind_test_audit(client(os_clients[8]))
    } == Some(3);
    assert!(os_map_retained);
    let final_arena = unsafe { native_runtime_arena_span_state_test_audit(arena_span) }.unwrap();
    assert_eq!((final_arena.page_record_set, final_arena.abandoned_record_set,
        final_arena.free_slices, final_arena.committed_slices, final_arena.purge_slices),
        (0, 0, 8, 8, 8));
    let vm_after_arena = vm_current();
    assert_eq!(vm_before, vm_after_arena);

    remote_phase_sender.send(RemotePhase::FinalOs(os_reuse)).unwrap();
    remote_done_receiver.recv().unwrap();
    let after_os_final = map_image();
    assert_eq!(medium_slices(after_os_final), medium_slices(baseline) + 8);
    assert!(os_list_empty());
    let vm_after_os = vm_current();
    let os_reserved_drop = vm_after_arena.0 - vm_after_os.0;
    let os_committed_drop = vm_after_arena.1 - vm_after_os.1;
    assert_eq!((os_reserved_drop, os_committed_drop), (589824, 524288));
    let os_page_address = os_clients[8] & !(page_size - 1);
    let mut residency = 0u8;
    let os_map_clear = unsafe { crabc_core::mm::mincore_raw(
        os_page_address as *mut u8, page_size, &mut residency) } == Err(crabc_core::Errno::NOMEM);
    assert!(os_map_clear);
    remote_phase_sender.send(RemotePhase::Exit).unwrap();
    remote.join().unwrap();
    native_collect(true);
    let collected_arena = unsafe { native_runtime_arena_span_state_test_audit(arena_span) }.unwrap();
    assert_eq!(collected_arena.purge_slices, 0);
    assert_eq!(source_options_api::option_get(SHOW_ERRORS), 0);

    std::println!("CRABC_MI_MIXED_MEDIUM_PRE_RECLAIM_BEGIN");
    for (key, value) in [
        ("request", REQUEST as i64), ("block_size", 57344),
        ("arena_map_count", arena_map.registered_slice_count() as i64),
        ("os_map_count", (medium_slices(after_exit) - medium_slices(baseline) - 16) as i64),
        ("arena_slice_count", arena_span.slice_count() as i64),
        ("os_mapping_size", os_reserved_drop),
        ("setup_valid", 1), ("remote_queue_ready", 1),
        ("exit_arena_abandoned", 1), ("exit_os_abandoned", 1),
        ("exit_os_list", i64::from(exit_os_list)),
        ("exit_arena_bitmap", exit_arena.abandoned_record_set as i64),
        ("first_remote_class", 1),
        ("arena_reclaimed", 1), ("arena_reused", 1),
        ("arena_map_after_reclaim", i64::from(arena_map_after_reclaim)),
        ("os_list_while_arena_reclaimed", i64::from(os_list_while_arena_reclaimed)),
        ("os_reclaimed", 1), ("os_reused", 1),
        ("os_map_after_reclaim", i64::from(os_map_after_reclaim)),
        ("os_list_after_reclaim_empty", i64::from(os_list_after_reclaim_empty)),
        ("reexit_arena_bitmap", reexit_arena.abandoned_record_set as i64),
        ("reexit_os_list", i64::from(reexit_os_list)),
        ("reexit_both_mapped", i64::from(reexit_both_mapped)),
        ("final_arena_freed", 1), ("arena_map_clear", i64::from(arena_map_clear)),
        ("os_map_retained", i64::from(os_map_retained)), ("arena_bitmap_final_clear", i64::from(final_arena.abandoned_record_set == 0)),
        ("arena_free_after_final", final_arena.free_slices as i64),
        ("arena_committed_after_final", final_arena.committed_slices as i64),
        ("arena_purge_after_final", final_arena.purge_slices as i64),
        ("arena_reserved_drop", vm_before.0 - vm_after_arena.0),
        ("arena_committed_drop", vm_before.1 - vm_after_arena.1),
        ("final_os_freed", 1), ("os_map_clear", i64::from(os_map_clear)),
        ("os_list_final_empty", i64::from(os_list_empty())),
        ("os_reserved_drop", os_reserved_drop),
        ("os_committed_drop", os_committed_drop),
        ("arena_purge_after_collect", collected_arena.purge_slices as i64),
        ("warning_enabled", source_options_api::option_get(SHOW_ERRORS)),
    ] { std::println!("{key}={value}"); }
    std::println!("CRABC_MI_MIXED_MEDIUM_PRE_RECLAIM_END");
}
