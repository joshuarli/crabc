// Automatic integration-test discovery still compiles this file in ordinary
// allocator builds. The fork-preservation witness stays default-off and
// exposes no owner, PageMap, scheduler, route, or client capability.
#![cfg(feature = "native-runtime-test-audit")]

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, after_fork_child,
    after_fork_parent, before_fork, initialize_process, native_allocate_aligned, native_free,
    native_usable_size, prepare_native_later_thread_arena, process_is_active,
};

// Linux's raw wait4 ABI uses bit zero for WNOHANG. The copied child owns this
// bounded wait rather than depending on libc state while it proves the
// pinned initial TLS owner survives only the prepared quiescent fork path.
const WNOHANG: u32 = 1;

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn wait_for_preserved_initial_owner_child(pid: i32) {
    let mut status = 0;
    for _ in 0..500 {
        let waited = unsafe {
            crabc_core::process::wait4_raw(pid, &mut status, WNOHANG)
                .expect("the parent polls the promoted-initial-owner fork child")
        };
        if waited == 0 {
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }
        assert_eq!(waited, pid, "wait4 returns the exact preserved fork child");
        assert_eq!(
            status, 0,
            "the copied dormant initial owner stays usable in the prepared child"
        );
        return;
    }
    let _ = crabc_core::process::kill(pid, 9);
    let _ = unsafe { crabc_core::process::wait4_raw(pid, &mut status, 0) };
    panic!("the promoted-initial-owner fork child exceeded its five-second deadline");
}

fn dormant_initial_persistent_owner_fork_child() -> ! {
    after_fork_child(true);
    if !process_is_active() {
        crabc_core::process::exit_immediately(101);
    }
    let block = match native_allocate_aligned(73, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => crabc_core::process::exit_immediately(102),
    };
    // SAFETY: the child just obtained this exact local client from the
    // copied pinned initial owner and has not transferred or freed it.
    if unsafe { native_usable_size(block) }.is_none() {
        crabc_core::process::exit_immediately(103);
    }
    // SAFETY: this is the child's one local pointer-first free of the exact
    // copied initial-owner client above.
    if unsafe { native_free(block) } != NativePageFreeResult::Freed {
        crabc_core::process::exit_immediately(104);
    }
    crabc_core::process::exit_immediately(0);
}

/// `before_fork` preserves the initial thread's compiler-TLS owner only when
/// it is source-dormant. This starts from the startup-equivalent dormant-arena
/// preparation, which promotes the static staging owner into the pinned
/// initial TLS cell and returns it to `DormantExistingArena`; the child then
/// proves that it can continue direct local allocate/query/free without
/// reopening the vacated process-static slot.
#[test]
fn dormant_promoted_initial_owner_is_preserved_across_prepared_fork() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the promoted-owner fork witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "pre-fork preparation promotes and leaves the initial source owner dormant"
    );

    before_fork();
    match crabc_core::process::fork_raw() {
        Ok(0) => dormant_initial_persistent_owner_fork_child(),
        Ok(pid) => {
            after_fork_parent();
            wait_for_preserved_initial_owner_child(pid);
        }
        Err(error) => {
            after_fork_parent();
            panic!("the promoted-owner raw fork succeeds: {error:?}");
        }
    }
    assert!(
        process_is_active(),
        "the parent retains its same direct dormant initial owner after fork"
    );
    let parent_block = match native_allocate_aligned(97, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            panic!("the parent keeps the promoted initial owner after the child exits")
        }
    };
    // SAFETY: the parent owns this exact direct initial client until its one
    // pointer-first free.
    assert_eq!(unsafe { native_free(parent_block) }, NativePageFreeResult::Freed);
}
