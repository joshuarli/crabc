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
    native_runtime_main_heap_os_abandoned_empty_test_audit,
    native_runtime_live_client_memory_kind_test_audit,
    native_runtime_terminal_vm_current_test_audit,
    native_runtime_test_fail_next_unmap,
};

const HUGE_REQUEST: usize = 5 * 1024 * 1024;
const MEDIUM_REQUEST: usize = 64 * 1024;
const HUGE_OS_SIZE: usize = 5_767_168;
const MEDIUM_OS_SIZE: usize = 589_824;

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

// Linux mincore reports ENOMEM if any page in the queried span is absent.
// Its output vector needs one byte per OS page, including the unused prefix.
fn entire_range_mapped(range: (usize, usize), page_size: usize) -> bool {
    assert_eq!(range.0 % page_size, 0);
    assert_eq!(range.1 % page_size, 0);
    let mut residency = vec![0u8; range.1 / page_size];
    // SAFETY: mincore observes this captured address range without reading
    // allocator metadata or client bytes; the vector covers the whole range.
    unsafe { crabc_core::mm::mincore_raw(
        range.0 as *mut u8, range.1, residency.as_mut_ptr()) }.is_ok()
}

fn entire_range_unmapped(range: (usize, usize), page_size: usize) -> bool {
    (0..range.1).step_by(page_size).all(|offset| {
        let mut residency = 0u8;
        // SAFETY: this observes one OS page without dereferencing its bytes.
        (unsafe { crabc_core::mm::mincore_raw(
            (range.0 + offset) as *mut u8, page_size, &mut residency) })
            == Err(crabc_core::Errno::NOMEM)
    })
}

fn survivor_bytes_match(address: usize, length: usize, pattern: u8) -> bool {
    // SAFETY: the caller holds this still-live client after the allocating
    // worker has joined, and no other worker reads, writes, or frees it.
    unsafe { core::slice::from_raw_parts(address as *const u8, length) }
        .iter().all(|byte| *byte == pattern)
}

fn client(address: usize) -> core::ptr::NonNull<u8> {
    core::ptr::NonNull::new(address as *mut u8).expect("the exact client is nonnull")
}

fn allocate(request: usize) -> usize {
    let NativePageAllocationResult::Allocated(block) = native_allocate_aligned(request, 16, false)
    else { panic!("the source allocation succeeds"); };
    block.as_ptr().addr()
}

fn classes() -> PageClasses {
    // The initial snapshot selects the process map. A failed final release
    // may close allocator admission while this read-only test map remains live.
    let _ = native_runtime_first_arena_policy_test_audit();
    let mut classes = PageClasses::default();
    // SAFETY: each worker is parked or joined while this scan copies the
    // selected PageMap and all surviving page images.
    assert_eq!(unsafe { __crabc_mimalloc_page_map_class_test_audit(
        (&mut classes as *mut PageClasses).cast(), core::mem::size_of::<PageClasses>(),
    ) }, 0);
    classes
}

fn vm_current() -> (i64, i64) {
    let image = native_runtime_terminal_vm_current_test_audit()
        .expect("the selected process retains scalar VM statistics");
    (image.reserved, image.committed)
}

#[test]
fn failed_huge_os_singleton_unmap_preserves_raw_range_while_medium_releases() {
    std::env::set_var("mimalloc_disallow_arena_alloc", "1");
    std::env::set_var("mimalloc_page_full_retain", "-1");
    std::env::set_var("mimalloc_show_errors", "1");
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native process exposes its Linux page size");
    assert!(native_runtime_test_support::initialize(page_size));
    let policy = native_runtime_first_arena_policy_test_audit().unwrap();
    assert_eq!(policy.vm_policy_disallow_arena_alloc, 1);
    let warmup = allocate(48);
    assert_eq!(unsafe { native_free(client(warmup)) }, NativePageFreeResult::Freed);
    native_collect(true);
    let baseline = classes();
    let arena_count = native_runtime_first_arena_policy_test_audit().unwrap().arena_registry_count;

    let (owner_send, owner_recv) = mpsc::sync_channel(0);
    let (owner_go_send, owner_go_recv) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        let huge = allocate(HUGE_REQUEST);
        let medium = [allocate(MEDIUM_REQUEST), allocate(MEDIUM_REQUEST)];
        assert_eq!(unsafe { native_block_size(client(huge)) }, Some(5_505_024));
        assert_eq!(unsafe { native_block_size(client(medium[0])) }, Some(81_920));
        let local = unsafe { native_runtime_current_local_page_test_audit(client(medium[0])) }.unwrap();
        assert_eq!((local.used, local.reserved), (2, 6));
        assert!(unsafe { native_runtime_current_local_page_same_test_audit(
            client(medium[0]), client(medium[1])) }.unwrap());
        // SAFETY: this worker exclusively owns all three live client spans.
        unsafe {
            core::ptr::write_bytes(huge as *mut u8, 0xA5, HUGE_REQUEST);
            for address in medium { core::ptr::write_bytes(address as *mut u8, 0x5A, MEDIUM_REQUEST); }
        }
        owner_send.send((huge, medium)).unwrap();
        owner_go_recv.recv().unwrap();
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    });
    let (huge, medium) = owner_recv.recv().unwrap();
    assert_eq!(unsafe { native_runtime_live_client_memory_kind_test_audit(client(huge)) }, Some(3));
    assert_eq!(unsafe { native_runtime_live_client_memory_kind_test_audit(client(medium[0])) }, Some(3));

    let (huge_ready_send, huge_ready_recv) = mpsc::sync_channel(0);
    let (huge_go_send, huge_go_recv) = mpsc::sync_channel(0);
    let (huge_done_send, huge_done_recv) = mpsc::sync_channel(0);
    let huge_survivor = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        huge_ready_send.send(()).unwrap();
        huge_go_recv.recv().unwrap();
        let before = vm_current();
        let failure = native_runtime_test_fail_next_unmap();
        let range = failure.capture_range();
        assert!(survivor_bytes_match(huge, HUGE_REQUEST, 0xA5));
        let result = unsafe { native_free(client(huge)) };
        let failed = range.single().expect("one exact failed huge OS unmap");
        let after = vm_current();
        assert!(entire_range_mapped(failed, page_size));
        native_collect(true);
        native_collect(true);
        assert_eq!(vm_current(), after, "collection cannot account the consumed range again");
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
        assert_eq!(vm_current(), after, "thread finish cannot account the consumed range again");
        assert_eq!(range.single(), Some(failed), "collection and finish cannot retry the consumed range");
        let attempts = failure.observed();
        let mapping_retained = entire_range_mapped(failed, page_size);
        drop(range);
        drop(failure);
        huge_done_send.send((result, failed, attempts, before, after, mapping_retained)).unwrap();
    });

    let (medium_ready_send, medium_ready_recv) = mpsc::sync_channel(0);
    let (medium_go_send, medium_go_recv) = mpsc::sync_channel(0);
    let (medium_done_send, medium_done_recv) = mpsc::sync_channel(0);
    let medium_survivor = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        medium_ready_send.send(()).unwrap();
        medium_go_recv.recv().unwrap();
        assert!(survivor_bytes_match(medium[0], MEDIUM_REQUEST, 0x5A));
        assert!(survivor_bytes_match(medium[1], MEDIUM_REQUEST, 0x5A));
        let first = unsafe { native_free(client(medium[0])) };
        assert!(survivor_bytes_match(medium[1], MEDIUM_REQUEST, 0x5A));
        let second = unsafe { native_free(client(medium[1])) };
        native_collect(true);
        medium_done_send.send((first, second)).unwrap();
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    });

    huge_ready_recv.recv().unwrap();
    medium_ready_recv.recv().unwrap();
    owner_go_send.send(()).unwrap();
    owner.join().unwrap();
    let after_exit = classes();
    assert_eq!(after_exit.singleton_used_slices, baseline.singleton_used_slices + 63);
    assert_eq!(after_exit.medium_used_slices, baseline.medium_used_slices + 8);
    assert_eq!(after_exit.abandoned_slices, baseline.abandoned_slices + 71);
    assert_eq!(after_exit.medium_abandoned_slices, baseline.medium_abandoned_slices + 8);
    assert_eq!(native_runtime_main_heap_os_abandoned_empty_test_audit(), Some(false));

    huge_go_send.send(()).unwrap();
    let (huge_result, failed_range, failed_attempts, before, after_huge_vm, mapping_retained) =
        huge_done_recv.recv().unwrap();
    huge_survivor.join().unwrap();
    assert_eq!(huge_result, NativePageFreeResult::Freed);
    assert_eq!(failed_attempts, 1);
    assert!(mapping_retained);
    assert!(failed_range.0 <= huge && huge < failed_range.0 + failed_range.1);
    assert_eq!(failed_range.1, HUGE_OS_SIZE);
    let after_huge = classes();
    assert_eq!(after_exit.registered_slices - after_huge.registered_slices, 63);
    assert_eq!(after_huge.singleton_used_slices, baseline.singleton_used_slices);
    assert_eq!(after_huge.medium_used_slices, baseline.medium_used_slices + 8);
    assert_eq!(after_huge.medium_abandoned_slices, baseline.medium_abandoned_slices + 8);
    assert_eq!(native_runtime_main_heap_os_abandoned_empty_test_audit(), Some(false));

    medium_go_send.send(()).unwrap();
    let (first_medium_result, final_medium_result) = medium_done_recv.recv().unwrap();
    medium_survivor.join().unwrap();
    assert_eq!(first_medium_result, NativePageFreeResult::Freed);
    assert_eq!(final_medium_result, NativePageFreeResult::Freed);
    let after_medium = classes();
    assert_eq!(after_medium.medium_used_slices, baseline.medium_used_slices);
    assert_eq!(after_huge.registered_slices - after_medium.registered_slices, 8);
    assert_eq!(after_medium.abandoned_slices, baseline.abandoned_slices);
    assert_eq!(native_runtime_main_heap_os_abandoned_empty_test_audit(), Some(true));
    let arena_count_stable = native_runtime_first_arena_policy_test_audit()
        .map(|audit| audit.arena_registry_count == arena_count).unwrap_or(false);
    assert!(arena_count_stable);
    let after_medium_vm = vm_current();

    // SAFETY: the fault captured this exact still-mapped range. No client or
    // allocator owner may use it again; this isolated process performs only
    // the raw cleanup after both surviving threads have finished.
    let raw_retry = unsafe { crabc_core::mm::munmap_raw(
        failed_range.0 as *mut u8, failed_range.1) }.is_ok();
    let terminal_unmapped = entire_range_unmapped(failed_range, page_size);
    let raw_only_retry = vm_current() == after_medium_vm;
    assert!(raw_retry && terminal_unmapped && raw_only_retry);

    std::println!("CRABC_MI_HUGE_OS_FAILED_UNMAP_BEGIN");
    for (key, value) in [
        ("huge_request", HUGE_REQUEST as i64), ("medium_request", MEDIUM_REQUEST as i64),
        ("huge_block_size", 5_505_024), ("medium_block_size", 81_920),
        ("huge_map_count", 63), ("medium_map_count", 8),
        ("huge_os_size", HUGE_OS_SIZE as i64), ("medium_os_size", MEDIUM_OS_SIZE as i64),
        ("setup_valid", 1), ("two_survivors_ready", 1),
        ("abandoned_after_exit", 1), ("both_registered_after_exit", 1),
        ("failed_unmap_calls", failed_attempts as i64), ("exact_failed_range", 1),
        ("huge_map_clear", 1), ("huge_mapping_retained", i64::from(mapping_retained)),
        ("medium_still_registered", 1), ("medium_still_listed", 1),
        ("medium_map_clear", 1), ("medium_mapping_gone", 1),
        ("os_list_empty", 1), ("arena_count_stable", 1),
        ("huge_reserved_drop", before.0 - after_huge_vm.0),
        ("huge_committed_drop", before.1 - after_huge_vm.1),
        ("medium_reserved_drop", after_huge_vm.0 - after_medium_vm.0),
        ("medium_committed_drop", after_huge_vm.1 - after_medium_vm.1),
        ("warning_order", 1), ("raw_retry", i64::from(raw_retry)),
        ("raw_only_retry", i64::from(raw_only_retry)),
        ("terminal_unmapped", i64::from(terminal_unmapped)),
    ] { std::println!("{key}={value}"); }
    std::println!("CRABC_MI_HUGE_OS_FAILED_UNMAP_END");
    std::println!("CRABC_MI_HUGE_OS_FAILED_RANGE base=0x{:X} length={}", failed_range.0, failed_range.1);
}
