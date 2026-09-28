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
};

const REQUEST: usize = 64 * 1024;

fn client(address: usize) -> core::ptr::NonNull<u8> {
    core::ptr::NonNull::new(address as *mut u8).expect("an exact live client is nonnull")
}

// This exact C-layout image is copied by the existing PageMap test audit.
// Its medium buckets include both live and retired registered page slices.
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
    // SAFETY: each caller waits for all mutating threads to park or join;
    // the test audit copies scalar PageMap counts without releasing pages.
    assert_eq!(unsafe {
        __crabc_mimalloc_page_map_class_test_audit(
            (&mut classes as *mut PageClasses).cast(), core::mem::size_of::<PageClasses>(),
        )
    }, 0);
    classes
}

fn medium_map_counts(classes: PageClasses) -> (usize, usize) {
    (classes.medium_empty_slices + classes.medium_used_slices, classes.medium_used_slices)
}

#[test]
fn two_survivors_release_os_medium_page_after_owner_exit() {
    // The option table is read once during process startup. This selected
    // integration-test executable runs one test and starts no allocator owner
    // before installing these source option values.
    std::env::set_var("mimalloc_disallow_arena_alloc", "1");
    std::env::set_var("mimalloc_page_full_retain", "-1");
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native test process exposes its Linux page size");
    assert!(native_runtime_test_support::initialize(page_size));
    assert_eq!(native_runtime_first_arena_policy_test_audit()
        .expect("the source process is active").vm_policy_disallow_arena_alloc, 1);
    let warmup = match native_allocate_aligned(48, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the source process allocates its warmup client"),
    };
    // SAFETY: the warmup block is the exact live allocation just returned.
    assert_eq!(unsafe { native_free(warmup) }, NativePageFreeResult::Freed);
    native_collect(true);
    let baseline = medium_map_image();

    let (clients_sender, clients_receiver) = mpsc::sync_channel(0);
    let (exit_sender, exit_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        let blocks = core::array::from_fn::<_, 2, _>(|_| {
            let NativePageAllocationResult::Allocated(block) = native_allocate_aligned(REQUEST, 16, false)
            else {
                panic!("the source OS medium page allocates both clients");
            };
            block
        });
        // SAFETY: the owner holds both exact clients and no remote publisher
        // has been released while it reads this one local page image.
        let local = unsafe { native_runtime_current_local_page_test_audit(blocks[0]) }
            .expect("the medium page is locally owned");
        assert!(unsafe { native_runtime_current_local_page_same_test_audit(blocks[0], blocks[1]) }
            .expect("both clients share one source page"));
        assert_eq!(local.used, 2);
        assert_eq!(local.reserved, 6);
        assert_eq!(local.regular_queue_count, 1);
        assert_eq!(unsafe { native_block_size(blocks[0]) }, Some(81920));
        assert!(unsafe { native_runtime_live_client_page_test_audit(blocks[0]) }.is_none(),
            "the selected live medium page has no arena claim");
        clients_sender.send((blocks.map(|block| block.as_ptr().addr()), local.reserved))
            .expect("both survivors receive exact live clients");
        exit_receiver.recv().expect("the source owner may complete TLS exit");
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    });

    let (clients, reserved) = clients_receiver.recv().expect("the source owner publishes two clients");
    let mut survivor_threads = Vec::new();
    let mut survivor_go = Vec::new();
    for address in clients {
        let (ready_sender, ready_receiver) = mpsc::sync_channel(0);
        let (go_sender, go_receiver) = mpsc::sync_channel(0);
        let survivor = std::thread::spawn(move || {
            assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
            ready_sender.send(()).expect("the survivor is attached before owner exit");
            go_receiver.recv().expect("the owner has completed source exit");
            // SAFETY: this survivor alone owns its transferred exact client.
            assert_eq!(unsafe { native_free(client(address)) }, NativePageFreeResult::Freed);
            assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
        });
        ready_receiver.recv().expect("both releasers survive their source owner");
        survivor_threads.push(survivor);
        survivor_go.push(go_sender);
    }
    exit_sender.send(()).expect("the source owner may complete exit");
    owner.join().expect("the owner finishes before either remote free");
    let after_exit = medium_map_image();
    assert_eq!(medium_map_counts(after_exit).0, medium_map_counts(baseline).0 + 8);
    assert_eq!(medium_map_counts(after_exit).1, medium_map_counts(baseline).1 + 8);
    assert_eq!(after_exit.medium_abandoned_slices, baseline.medium_abandoned_slices + 8);
    // SAFETY: the second client is exact and live; both survivors are parked.
    assert_eq!(unsafe { native_block_size(client(clients[1])) }, Some(81920));
    assert!(unsafe { native_runtime_live_client_page_test_audit(client(clients[1])) }.is_none());
    assert_eq!(unsafe { native_runtime_live_client_memory_kind_test_audit(client(clients[1])) }, Some(3));

    survivor_go.remove(0).send(()).expect("first survivor may free after owner exit");
    survivor_threads.remove(0).join().expect("first survivor completes its remote free");
    let after_first = medium_map_image();
    assert_eq!(medium_map_counts(after_first).0, medium_map_counts(baseline).0 + 8);
    assert_eq!(medium_map_counts(after_first).1, medium_map_counts(baseline).1 + 8);
    // SAFETY: only the first client's lifetime ended; the second remains live.
    let second_client_live = unsafe { native_block_size(client(clients[1])) } == Some(81920);
    assert!(second_client_live);

    survivor_go.remove(0).send(()).expect("second survivor may free after the first");
    survivor_threads.remove(0).join().expect("second survivor completes terminal release");
    let after_final = medium_map_image();
    assert_eq!(medium_map_counts(after_final), medium_map_counts(baseline));

    std::println!("CRABC_MI_OS_MEDIUM_SPLIT_EXIT_BEGIN");
    std::println!("request={REQUEST}");
    std::println!("block_size=81920");
    std::println!("reserved={reserved}");
    std::println!("map_count={}", medium_map_counts(after_exit).0 - medium_map_counts(baseline).0);
    for key in ["owner_setup_valid", "two_releasers_ready", "owner_joined_before_free",
                "os_backed", "registered_after_exit", "medium_used_after_exit",
                "first_free_completed", "first_registered", "second_client_live",
                "second_free_completed", "terminal_map_clear"] {
        std::println!("{key}=1");
    }
    std::println!("CRABC_MI_OS_MEDIUM_SPLIT_EXIT_END");
}
