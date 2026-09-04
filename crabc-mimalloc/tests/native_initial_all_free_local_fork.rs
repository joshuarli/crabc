// Automatic integration-test discovery still compiles this file in ordinary
// allocator builds. The fork-preservation witness stays default-off and
// exposes no owner, PageMap, scheduler, route, or client capability.
#![cfg(feature = "native-runtime-test-audit")]

use core::ptr::NonNull;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, after_fork_child,
    after_fork_parent, before_fork, initialize_process, native_allocate_aligned, native_free,
    native_reallocate, prepare_native_later_thread_arena, process_is_active,
};

// Linux's raw wait4 ABI uses bit zero for WNOHANG. The parent owns this
// bounded wait rather than depending on libc state while the child proves a
// prepared copied initial owner stays usable.
const WNOHANG: u32 = 1;

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn allocate_current_initial_client(request: usize) -> NonNull<u8> {
    match native_allocate_aligned(request, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            panic!("the current copied initial owner allocates its local client")
        }
    }
}

fn reallocate_current_initial_client(block: NonNull<u8>, request: usize) -> NonNull<u8> {
    // SAFETY: the caller retains this exact local client until the returned
    // replacement is freed below.
    match unsafe { native_reallocate(Some(block), request) } {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            panic!("the current copied initial owner reallocates its local client")
        }
    }
}

fn free_current_initial_client(block: NonNull<u8>) {
    // SAFETY: the caller owns this exact local client and performs its one
    // pointer-first free without a remote producer or prior release.
    assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
}

fn exercise_current_initial_client(prefix: u8) {
    let block = allocate_current_initial_client(73);
    // SAFETY: the just-allocated current client remains local through the
    // following exact realloc.
    unsafe { block.as_ptr().write(prefix) };
    let replacement = reallocate_current_initial_client(block, 149);
    assert_eq!(
        unsafe { replacement.as_ptr().read() },
        prefix,
        "ordinary local realloc preserves the copied initial client's prefix"
    );
    free_current_initial_client(replacement);
}

fn wait_for_all_free_initial_owner_child(pid: i32) {
    let mut status = 0;
    for _ in 0..500 {
        let waited = unsafe {
            crabc_core::process::wait4_raw(pid, &mut status, WNOHANG)
                .expect("the parent polls the all-free-initial-owner fork child")
        };
        if waited == 0 {
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }
        assert_eq!(waited, pid, "wait4 returns the exact all-free fork child");
        assert_eq!(
            status, 0,
            "the copied all-free initial owner remains usable in the prepared child"
        );
        return;
    }
    let _ = crabc_core::process::kill(pid, 9);
    let _ = unsafe { crabc_core::process::wait4_raw(pid, &mut status, 0) };
    panic!("the all-free-initial-owner fork child exceeded its five-second deadline");
}

fn all_free_initial_local_fork_child() -> ! {
    after_fork_child(true);
    if !process_is_active() {
        crabc_core::process::exit_immediately(101);
    }
    exercise_current_initial_client(0x61);
    crabc_core::process::exit_immediately(0);
}

/// Native-shadow startup first prepares its dormant first-arena pair, then
/// normal local `mi_free` deliberately retains a reactivated all-free initial
/// engine for the next initial-thread allocation. `before_fork` is a distinct
/// held, zero-admission boundary: it must force-collect that engine only after
/// its all-free proof, so the prepared child preserves the same dormant source
/// image without requiring another later-worker handoff first.
#[test]
fn all_free_resident_initial_engine_is_preserved_across_prepared_fork() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the all-free initial fork witness"
    );

    assert!(
        prepare_native_later_thread_arena(),
        "startup-equivalent preparation leaves the initial source owner dormant"
    );
    // Normal local free leaves this reactivated all-free initial engine
    // resident, which is the state this test supplies to the held fork gate.
    exercise_current_initial_client(0x51);

    before_fork();
    match crabc_core::process::fork_raw() {
        Ok(0) => all_free_initial_local_fork_child(),
        Ok(pid) => {
            after_fork_parent();
            wait_for_all_free_initial_owner_child(pid);
        }
        Err(error) => {
            after_fork_parent();
            panic!("the all-free initial-owner raw fork succeeds: {error:?}");
        }
    }
    assert!(
        process_is_active(),
        "the parent retains its same all-free initial owner after fork"
    );
    exercise_current_initial_client(0x71);
}
