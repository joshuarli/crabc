#![cfg(feature = "native-runtime-test-audit")]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use core::ffi::c_void;
use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    finish_current_thread_native_after_user_destructors, native_allocate_aligned, native_free,
    native_runtime_lifecycle_test_audit, prepare_native_later_thread_arena,
};

const REQUEST: usize = 10248;
const BLOCKS_PER_PAGE: usize = 42;
const PAGES: usize = 16;
const BLOCKS: usize = BLOCKS_PER_PAGE * PAGES;

// The native test audit has the same C layout as the selected libc bridge.
// Its overlapping medium buckets describe the exact quiescent page image.
#[repr(C)]
#[derive(Default)]
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

fn page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes its page size")
}

/// Reads only when the owner is parked and every remote publisher has joined.
fn classes(phase: &str) -> PageClasses {
    let process = native_runtime_lifecycle_test_audit().expect("the active process is auditable");
    let mut classes = PageClasses::default();
    // SAFETY: the process scalar audit just selected the live map; all owners
    // are parked or joined for this snapshot, so its pages cannot be freed.
    assert_eq!(unsafe {
        __crabc_mimalloc_page_map_class_test_audit(
            (&mut classes as *mut PageClasses).cast(), core::mem::size_of::<PageClasses>(),
        )
    }, 0);
    assert_eq!(classes.registered_slices, process.page_map_registered_entry_count);
    std::println!(
        "trace.medium_churn.{phase}.entries={} medium_used={} medium_abandoned={} medium_remote_pending={}",
        classes.registered_slices, classes.medium_used_slices,
        classes.medium_abandoned_slices, classes.medium_remote_pending_slices,
    );
    classes
}

#[test]
fn full_medium_remote_churn_releases_at_source_collection_point() {
    let nonabandoning = std::env::var("MIMALLOC_PAGE_FULL_RETAIN").as_deref() == Ok("-1");
    assert!(native_runtime_test_support::initialize(page_size()));
    assert!(prepare_native_later_thread_arena());
    let baseline = classes("baseline");

    let (blocks_sender, blocks_receiver) = mpsc::sync_channel(0);
    let (resume_sender, resume_receiver) = mpsc::sync_channel(0);
    let (cleared_sender, cleared_receiver) = mpsc::sync_channel(0);
    let (exit_sender, exit_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        let mut blocks = Vec::with_capacity(BLOCKS);
        for index in 0..BLOCKS {
            let block = match native_allocate_aligned(REQUEST, 16, false) {
                NativePageAllocationResult::Allocated(block) => block,
                _ => panic!("the owner allocates a source medium client"),
            };
            // SAFETY: the returned block has at least REQUEST writable bytes
            // and remains exclusively owned until it is handed to the worker.
            unsafe { core::ptr::write_bytes(block.as_ptr(), (index & 255) as u8, REQUEST) };
            blocks.push(block.as_ptr().addr());
        }
        blocks_sender.send(blocks.clone()).expect("the coordinator receives the exact clients");
        resume_receiver.recv().expect("the owner waits for all remote frees to join");
        for index in (BLOCKS_PER_PAGE - 1..BLOCKS).step_by(BLOCKS_PER_PAGE) {
            // SAFETY: the worker deliberately retained this live client, and
            // its join precedes the owner's local final free.
            let block = unsafe { core::ptr::NonNull::new_unchecked(blocks[index] as *mut u8) };
            assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
        }
        cleared_sender.send(()).expect("the owner parks after clearing every survivor");
        exit_receiver.recv().expect("the coordinator observes release before thread exit");
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    });

    let blocks = blocks_receiver.recv().expect("the owner allocates the medium image");
    let allocated = classes("allocated");
    assert!(allocated.medium_used_slices >= PAGES * 8);
    if nonabandoning {
        assert_eq!(allocated.medium_abandoned_slices, 0);
        assert!(allocated.medium_attached_slices >= PAGES * 8);
    } else {
        assert!(allocated.medium_abandoned_slices >= PAGES * 8);
    }

    let remote = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        for (index, address) in blocks.into_iter().enumerate() {
            if index % BLOCKS_PER_PAGE == BLOCKS_PER_PAGE - 1 { continue; }
            // SAFETY: the owner has parked with this exact client live and
            // does not resume until this worker has joined.
            let block = unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) };
            assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
        }
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    });
    remote.join().expect("the remote worker completes every selected free");
    let published = classes("remote_joined");
    assert_eq!(published.medium_used_slices, allocated.medium_used_slices);
    assert_eq!(published.registered_slices, allocated.registered_slices);
    if nonabandoning {
        assert!(published.medium_remote_pending_slices >= PAGES * 8);
    }

    resume_sender.send(()).expect("the owner clears the retained clients");
    cleared_receiver.recv().expect("the owner parks before exiting");
    let cleared = classes("owner_cleared");
    if nonabandoning {
        assert_eq!(cleared.medium_used_slices, allocated.medium_used_slices);
        assert_eq!(cleared.registered_slices, allocated.registered_slices);
        assert!(cleared.medium_remote_pending_slices >= PAGES * 8);
    } else {
        assert_eq!(cleared.medium_used_slices, baseline.medium_used_slices);
        assert!(cleared.registered_slices + PAGES * 8 <= allocated.registered_slices);
    }
    exit_sender.send(()).expect("the owner may finish after release is observed");
    owner.join().expect("the medium owner exits normally");
    let finished = classes("owner_joined");
    assert_eq!(finished.medium_used_slices, baseline.medium_used_slices);
    if nonabandoning {
        assert!(finished.registered_slices + PAGES * 8 <= allocated.registered_slices);
    } else {
        assert_eq!(finished.registered_slices, cleared.registered_slices);
    }
}
