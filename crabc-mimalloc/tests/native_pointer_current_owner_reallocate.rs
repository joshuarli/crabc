use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    attach_current_thread, finish_current_thread_native_after_user_destructors,
    initialize_process, native_allocate_aligned, native_free, native_reallocate,
    native_usable_size,
};

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

/// A direct native pointer operation first derives its exact source facts
/// from the PageMap. Usable-size returns those immutable facts directly. A
/// source associated with the caller may use that owner's in-place engine;
/// a `LiveOwnerAssociated` source owned by another live thread instead follows
/// pinned `mi_theap_realloc_zero_ex`'s replacement path through the caller's
/// current owner.
#[test]
fn native_pointer_reallocate_replaces_live_foreign_sources_through_current_owner() {
    assert!(
        initialize_process(current_page_size()),
        "the isolated process initializes the native runtime"
    );

    let initial = match native_allocate_aligned(41, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            panic!("the initial owner creates its current native client")
        }
    };
    // SAFETY: `initial` remains the initial owner's exact current client
    // through the pointer-derived usable-size and in-place realloc below.
    unsafe { initial.as_ptr().write(0x39) };
    let initial_usable = unsafe { native_usable_size(initial) }
        .expect("the initial owner reads its pointer-derived usable extent");
    assert!(initial_usable >= 41);
    let initial_before_reuse = initial;
    let initial = match unsafe { native_reallocate(Some(initial), initial_usable) } {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            panic!("the initial owner reuses its exact current allocation")
        }
    };
    assert_eq!(
        initial, initial_before_reuse,
        "a same-usable current-owner realloc remains in place"
    );
    assert_eq!(
        unsafe { initial.as_ptr().read() },
        0x39,
        "the in-place initial reallocation preserves its source prefix"
    );

    let initial_before_zero = initial;
    let initial = match unsafe { native_reallocate(Some(initial), 0) } {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            panic!("zero-size realloc returns its source-defined non-null replacement")
        }
    };
    assert_ne!(
        initial, initial_before_zero,
        "non-null zero-size realloc allocates before it frees the old client"
    );
    assert_eq!(
        unsafe { initial.as_ptr().read() },
        0,
        "the zero-size replacement clears its first source byte"
    );
    assert_eq!(
        unsafe { native_free(initial) },
        NativePageFreeResult::Freed,
        "the initial replacement returns through the pointer-first free seam"
    );
    let null_zero = match unsafe { native_reallocate(None, 0) } {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            panic!("null zero-size realloc returns a natural allocation")
        }
    };
    assert_eq!(
        null_zero.as_ptr().addr() & 15,
        0,
        "null zero-size realloc uses the natural C allocation alignment"
    );
    assert_eq!(
        unsafe { native_free(null_zero) },
        NativePageFreeResult::Freed,
        "the null zero-size allocation returns through pointer-first free"
    );

    let initial_foreign = match native_allocate_aligned(67, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            panic!("the initial owner keeps one exact client live for the worker replacement")
        }
    };
    let initial_foreign_usable = unsafe { native_usable_size(initial_foreign) }
        .expect("the initial owner reads its foreign source's PageMap extent");
    assert!(initial_foreign_usable >= 67);
    // SAFETY: this client stays live through the worker's nonlocal source
    // operation. Both bytes are inside its captured usable extent.
    unsafe {
        initial_foreign.as_ptr().write(0x6c);
        initial_foreign
            .as_ptr()
            .add(initial_foreign_usable - 1)
            .write(0x6d);
    }
    let initial_foreign_address = initial_foreign.as_ptr().addr();

    // A live initial owner cannot be parked or lent through
    // `prepare_native_later_thread_arena`; this worker attaches through its
    // independent current owner while the initial source remains live.
    let (owner_sender, owner_receiver) = mpsc::sync_channel(0);
    let (resume_sender, resume_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let local = match native_allocate_aligned(53, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            NativePageAllocationResult::Unavailable
            | NativePageAllocationResult::AllocationFailed
            | NativePageAllocationResult::Retained => {
                panic!("the worker creates its current native client")
            }
        };
        // SAFETY: `local` remains the worker's exact current client through
        // its local reallocation below, then the initial thread consumes it
        // through the nonlocal replacement path while the worker is paused.
        unsafe { local.as_ptr().write(0xa7) };
        let usable = unsafe { native_usable_size(local) }
            .expect("the worker reads its pointer-derived usable extent");
        assert!(usable >= 53);
        // SAFETY: the full captured usable extent belongs to this live local
        // client through its local reallocation below.
        unsafe { local.as_ptr().add(usable - 1).write(0xa8) };
        let local_before_reuse = local;
        let local = match unsafe { native_reallocate(Some(local), usable) } {
            NativePageAllocationResult::Allocated(block) => block,
            NativePageAllocationResult::Unavailable
            | NativePageAllocationResult::AllocationFailed
            | NativePageAllocationResult::Retained => {
                panic!("the worker reuses only its exact current allocation")
            }
        };
        assert_eq!(
            local, local_before_reuse,
            "a same-usable worker realloc remains in place"
        );
        assert_eq!(
            unsafe { local.as_ptr().read() },
            0xa7,
            "the worker's in-place reallocation preserves its source prefix"
        );
        assert_eq!(
            unsafe { local.as_ptr().add(usable - 1).read() },
            0xa8,
            "the worker's in-place reallocation preserves its source extent"
        );
        // SAFETY: the initial owner retains this exact live client until the
        // worker completes its one nonlocal source operation below.
        let initial_foreign = unsafe {
            core::ptr::NonNull::new_unchecked(initial_foreign_address as *mut u8)
        };
        assert_eq!(
            unsafe { native_usable_size(initial_foreign) },
            Some(initial_foreign_usable),
            "the worker reads the initial source's captured PageMap extent"
        );
        let initial_replacement =
            match unsafe { native_reallocate(Some(initial_foreign), 4096) } {
            NativePageAllocationResult::Allocated(block) => block,
            NativePageAllocationResult::Unavailable
            | NativePageAllocationResult::AllocationFailed
            | NativePageAllocationResult::Retained => {
                panic!("the worker replaces the initial owner's live PageMap source")
            }
        };
        assert!(
            unsafe { native_usable_size(initial_replacement) }.is_some_and(|size| size >= 4096),
            "the worker receives a replacement with its requested usable extent"
        );
        assert_eq!(
            unsafe { initial_replacement.as_ptr().read() },
            0x6c,
            "the worker replacement preserves the bounded initial source prefix"
        );
        assert_eq!(
            unsafe {
                initial_replacement
                    .as_ptr()
                    .add(initial_foreign_usable - 1)
                    .read()
            },
            0x6d,
            "the worker replacement preserves the bounded initial source extent"
        );
        assert_eq!(
            unsafe { native_free(initial_replacement) },
            NativePageFreeResult::Freed,
            "the worker frees the returned replacement through its current owner"
        );
        owner_sender
            .send((local.as_ptr().addr(), usable))
            .expect("the initial thread receives the worker's still-live foreign source");
        resume_receiver
            .recv()
            .expect("the worker resumes after the initial owner replaces its foreign source");
        // The initial owner consumed `local` through successful nonlocal
        // reallocation, so the old worker pointer is intentionally not read
        // or freed here.
        finish_current_thread_native_after_user_destructors()
    });

    let (foreign_address, foreign_usable) = owner_receiver
        .recv()
        .expect("the worker publishes one still-live foreign source address");
    // SAFETY: the worker keeps this exact allocation live and does not access
    // it concurrently while the initial thread performs its nonlocal source
    // operation.
    let foreign = unsafe { core::ptr::NonNull::new_unchecked(foreign_address as *mut u8) };
    assert_eq!(
        unsafe { native_usable_size(foreign) },
        Some(foreign_usable),
        "usable-size returns the foreign source's captured PageMap extent"
    );
    let foreign_replacement = match unsafe { native_reallocate(Some(foreign), foreign_usable) } {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            panic!("the initial owner replaces the worker's live PageMap source")
        }
    };
    assert!(
        unsafe { native_usable_size(foreign_replacement) }
            .is_some_and(|size| size >= foreign_usable),
        "the initial owner receives a replacement with the source-sized usable extent"
    );
    assert_eq!(
        unsafe { foreign_replacement.as_ptr().read() },
        0xa7,
        "the initial replacement preserves the worker source prefix"
    );
    assert_eq!(
        unsafe { foreign_replacement.as_ptr().add(foreign_usable - 1).read() },
        0xa8,
        "the initial replacement preserves the worker's bounded source extent"
    );
    assert_eq!(
        unsafe { native_free(foreign_replacement) },
        NativePageFreeResult::Freed,
        "the initial owner frees the returned replacement through pointer-first free"
    );
    resume_sender
        .send(())
        .expect("the worker resumes after its old foreign source is consumed");
    assert_eq!(
        owner.join().expect("the worker joins after its source is consumed"),
        ThreadFinishResult::Finished,
        "the worker completes after both owners free their returned replacements"
    );
}
