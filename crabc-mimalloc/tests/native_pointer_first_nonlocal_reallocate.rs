use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    attach_current_thread, finish_current_thread_native_after_user_destructors,
    initialize_process, native_allocate_aligned, native_free, native_reallocate, native_usable_size,
};

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

/// A foreign live allocation is a pointer/page operation, not a request to
/// borrow its source owner. The caller obtains its replacement through its
/// own persistent owner, then the old client follows the existing generic
/// pointer-first nonlocal free path.
#[test]
fn native_pointer_first_nonlocal_reallocate_replaces_through_the_callers_owner() {
    assert!(
        initialize_process(current_page_size()),
        "the isolated process initializes the native runtime"
    );

    let source = match native_allocate_aligned(67, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            panic!("the initial owner creates the foreign live source")
        }
    };
    // SAFETY: the initial owner keeps this source allocation live and does
    // not access it while the worker executes the nonlocal realloc operation.
    unsafe {
        source.as_ptr().write(0x61);
        source.as_ptr().add(31).write(0x62);
        source.as_ptr().add(66).write(0x63);
    }
    let source_address = source.as_ptr().addr();

    let (worker_ready_sender, worker_ready_receiver) = mpsc::sync_channel(0);
    let (initial_resume_sender, initial_resume_receiver) = mpsc::sync_channel(0);
    let worker = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        // SAFETY: the initial owner sent exactly one still-live native client
        // and remains quiescent through this worker operation.
        let source = unsafe { core::ptr::NonNull::new_unchecked(source_address as *mut u8) };

        assert!(matches!(
            unsafe { native_reallocate(Some(source), usize::MAX) },
            NativePageAllocationResult::AllocationFailed
        ));
        // SAFETY: invalid-size rejection has not allocated, copied, or freed
        // the source client, so all sentinels remain live and unchanged.
        unsafe {
            assert_eq!(source.as_ptr().read(), 0x61);
            assert_eq!(source.as_ptr().add(31).read(), 0x62);
            assert_eq!(source.as_ptr().add(66).read(), 0x63);
        }

        let replacement = match unsafe { native_reallocate(Some(source), 8192) } {
            NativePageAllocationResult::Allocated(block) => block,
            NativePageAllocationResult::Unavailable => panic!(
                "the worker finds the live foreign source through PageMap facts"
            ),
            NativePageAllocationResult::AllocationFailed => panic!(
                "the worker allocates the replacement through its persistent owner"
            ),
            NativePageAllocationResult::Retained => panic!(
                "the generic source-consumption tail completes after replacement allocation"
            ),
        };
        assert_ne!(
            replacement, source,
            "the foreign source cannot use the caller's local in-place realloc path"
        );
        assert!(
            unsafe { native_usable_size(replacement) }.is_some_and(|usable_size| usable_size >= 8192),
            "the caller-owned replacement covers the requested extent"
        );
        // SAFETY: successful replacement copied the source-defined prefix
        // before consuming the old source through generic pointer-first free.
        unsafe {
            assert_eq!(replacement.as_ptr().read(), 0x61);
            assert_eq!(replacement.as_ptr().add(31).read(), 0x62);
            assert_eq!(replacement.as_ptr().add(66).read(), 0x63);
        }
        assert_eq!(
            unsafe { native_free(replacement) },
            NativePageFreeResult::Freed,
            "the caller may locally free its independently owned replacement"
        );
        worker_ready_sender
            .send(())
            .expect("the initial owner waits until the old source is consumed");
        initial_resume_receiver
            .recv()
            .expect("the initial owner releases the worker after its source collection");
        finish_current_thread_native_after_user_destructors()
    });

    worker_ready_receiver
        .recv()
        .expect("the worker completes its replacement before initial collection");
    // A normal initial operation collects the remote old-source free without
    // ever exposing that consumed pointer again.
    let collected = match native_allocate_aligned(19, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            panic!("the initial owner continues after generic nonlocal source free")
        }
    };
    assert_eq!(
        unsafe { native_free(collected) },
        NativePageFreeResult::Freed,
        "the initial owner remains usable after collecting the foreign source free"
    );
    initial_resume_sender
        .send(())
        .expect("the worker may complete its all-free lifecycle");
    assert_eq!(
        worker.join().expect("the worker joins after its local replacement free"),
        ThreadFinishResult::Finished,
        "the caller's persistent owner completes after its nonlocal replacement"
    );
}
