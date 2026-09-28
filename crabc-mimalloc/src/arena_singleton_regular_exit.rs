//! A later owner's arena singleton and regular page cross distinct exit routes.

use core::ffi::c_char;
use core::ptr::NonNull;
use std::sync::mpsc;
use std::thread;

use crate::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, NativeProcessStartupFacts,
    NativeTheapTraceFact, NativeTheapTracePage, RuntimeStderrOutput,
    ThreadAttachResult, ThreadFinishResult,
    attach_current_thread, current_native_allocator_thread_descriptor,
    finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_collect, native_free,
    native_runtime_current_local_page_same_test_audit,
    native_runtime_current_local_page_test_audit,
    native_runtime_current_owner_theap_trace_test_audit,
    native_runtime_live_client_page_map_span_test_audit,
    native_runtime_live_client_page_test_audit, prepare_native_later_thread_arena,
    publish_native_process_startup_facts, register_current_native_allocator_worker_descriptor,
};

const SINGLETON_REQUEST: usize = 524289;
const REGULAR_REQUEST: usize = 64 * 1024;
const TEST_NAME: &str = "arena_singleton_regular_exit::arena_singleton_and_regular_reclaim_after_owner_exit";

struct SourceEnvironment([*const c_char; 3]);

// SAFETY: the environment vector and its C string are immutable process-lifetime data.
unsafe impl Sync for SourceEnvironment {}

static SOURCE_ENVIRONMENT: SourceEnvironment = SourceEnvironment([
    c"mimalloc_page_full_retain=-1".as_ptr(),
    c"mimalloc_page_reclaim_on_free=1".as_ptr(),
    core::ptr::null(),
]);

unsafe fn source_environment() -> *const *const c_char {
    SOURCE_ENVIRONMENT.0.as_ptr()
}

unsafe extern "C" fn discard_stderr(_message: *const c_char) {}

fn client(address: usize) -> NonNull<u8> {
    NonNull::new(address as *mut u8).expect("a live source client is nonnull")
}

fn allocate(request: usize) -> NonNull<u8> {
    let NativePageAllocationResult::Allocated(block) = native_allocate_aligned(request, 16, false)
    else {
        panic!("the source arena allocates its client");
    };
    block
}

fn current_queue_page(client_address: usize) -> Option<NativeTheapTracePage> {
    let mut found = None;
    let complete = native_runtime_current_owner_theap_trace_test_audit(&mut |fact| {
        let NativeTheapTraceFact::Page { bin, page } = fact else { return };
        let Some(end) = page.block_size.checked_mul(page.reserved)
            .and_then(|size| page.start.checked_add(size)) else { return };
        if page.start <= client_address && client_address < end {
            if page.in_full {
                assert_eq!(bin, crate::config::BIN_FULL);
            } else {
                assert_eq!(Some(bin), crate::size_class::bin(page.block_size));
            }
            assert!(found.replace(page).is_none(), "one client belongs to one source queue page");
        }
    });
    assert!(complete, "the active owner yields a complete source Theap walk");
    found
}

#[test]
fn arena_singleton_and_regular_reclaim_after_owner_exit() {
    crate::test_process::run_in_fresh_process(TEST_NAME, || {
        // SAFETY: the static option vector and no-op output callback remain
        // valid for the fresh process and cannot reenter the allocator.
        let facts = unsafe {
            NativeProcessStartupFacts::new(
                4096,
                source_environment,
                RuntimeStderrOutput::new(discard_stderr),
            )
        }.expect("the native source page size is valid");
        assert!(publish_native_process_startup_facts(facts));
        assert!(initialize_process());
        let warmup = allocate(48);
        // SAFETY: this is the exact live warmup client.
        assert_eq!(unsafe { native_free(warmup) }, NativePageFreeResult::Freed);
        assert!(prepare_native_later_thread_arena());
        let after_arena = allocate(48);
        assert_eq!(unsafe { native_free(after_arena) }, NativePageFreeResult::Freed);

        let (clients_sender, clients_receiver) = mpsc::sync_channel(0);
        let (exit_sender, exit_receiver) = mpsc::sync_channel(0);
        let owner = thread::spawn(move || {
            let descriptor = current_native_allocator_thread_descriptor();
            // SAFETY: the worker registers its exact current TLS descriptor
            // before attachment and completes source exit itself.
            assert!(unsafe { register_current_native_allocator_worker_descriptor(descriptor) });
            assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
            let singleton = allocate(SINGLETON_REQUEST);
            let regular = [allocate(REGULAR_REQUEST), allocate(REGULAR_REQUEST)];
            // SAFETY: this worker owns all three live clients while reading
            // only their current page and queue metadata.
            let singleton_local = unsafe { native_runtime_current_local_page_test_audit(singleton) }
                .expect("arena singleton source page");
            let regular_local = unsafe { native_runtime_current_local_page_test_audit(regular[0]) }
                .expect("arena regular source page");
            assert!(unsafe { native_runtime_current_local_page_same_test_audit(regular[0], regular[1]) }
                .expect("regular clients share a source page"));
            assert_eq!(singleton_local.used, 1);
            assert_eq!(singleton_local.reserved, 1);
            assert_eq!(regular_local.used, 2);
            assert!(regular_local.reserved > 2);
            assert_eq!(regular_local.regular_queue_count, 1);
            let singleton_queue_page = current_queue_page(singleton.as_ptr().addr())
                .expect("the singleton remains in its source queue");
            assert!(singleton_queue_page.in_full);
            let singleton_size = singleton_queue_page.block_size;
            assert_eq!(singleton_size, 589824);
            clients_sender.send((singleton.as_ptr().addr(),
                                 regular.map(|block| block.as_ptr().addr()),
                                 regular_local.reserved, singleton_size))
                .expect("the active survivor receives the exact clients");
            exit_receiver.recv().expect("the survivor begins source TLS exit");
            assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
        });

        let (singleton, regular, regular_reserved, singleton_block_size) = clients_receiver.recv()
            .expect("the source owner publishes its clients");
        exit_sender.send(()).expect("the worker may finish source TLS exit");
        owner.join().expect("the later source owner joins");
        // SAFETY: both clients remain live after join, and no other owner
        // mutates these source PageMap spans during each observation.
        let singleton_page = unsafe { native_runtime_live_client_page_test_audit(client(singleton)) }
            .expect("singleton is arena backed and registered");
        let regular_page = unsafe { native_runtime_live_client_page_test_audit(client(regular[1])) }
            .expect("regular page is arena backed and registered");
        assert_ne!(singleton_page.page_address(), regular_page.page_address());
        assert_eq!(singleton_page.arena_slice_count(), 9);
        assert_eq!(regular_page.arena_slice_count(), 8);
        assert_eq!(singleton_page.registered_slice_count(), 9);
        assert_eq!(regular_page.registered_slice_count(), 8);
        assert_eq!(unsafe { native_runtime_live_client_page_map_span_test_audit(singleton_page) }
            .expect("singleton span after exit").matching_page_entry_count, 9);
        assert_eq!(unsafe { native_runtime_live_client_page_map_span_test_audit(regular_page) }
            .expect("regular span after exit").matching_page_entry_count, 8);

        // SAFETY: each free consumes one exact transferred live client.
        assert_eq!(unsafe { native_free(client(regular[0])) }, NativePageFreeResult::Freed);
        let regular_reclaimed = current_queue_page(regular[1])
            .expect("the active survivor reclaims the regular page");
        assert_eq!(regular_reclaimed.used, 1);
        assert_eq!(regular_reclaimed.retire_expire, 0);
        assert_eq!(unsafe { native_runtime_live_client_page_map_span_test_audit(singleton_page) }
            .expect("singleton survives regular reclaim").matching_page_entry_count, 9);
        assert_eq!(unsafe { native_free(client(singleton)) }, NativePageFreeResult::Freed);
        let singleton_map_clear = unsafe { native_runtime_live_client_page_map_span_test_audit(singleton_page) }
            .expect("singleton span after release").non_null_entry_count == 0;
        let regular_still_registered = unsafe { native_runtime_live_client_page_map_span_test_audit(regular_page) }
            .expect("regular span before final free").matching_page_entry_count == 8;
        assert!(singleton_map_clear && regular_still_registered);
        assert_eq!(unsafe { native_free(client(regular[1])) }, NativePageFreeResult::Freed);
        let retired = current_queue_page(regular[1])
            .expect("the source regular page retires on its final local free");
        assert_eq!(retired.used, 0);
        assert_eq!(retired.retire_expire, 4);
        assert_eq!(unsafe { native_runtime_live_client_page_map_span_test_audit(regular_page) }
            .expect("retired regular span").matching_page_entry_count, 8);
        native_collect(true);
        let regular_map_clear = unsafe { native_runtime_live_client_page_map_span_test_audit(regular_page) }
            .expect("regular span after forced collection").non_null_entry_count == 0;
        assert!(regular_map_clear);
        let survivor = allocate(64);
        assert_eq!(unsafe { native_free(survivor) }, NativePageFreeResult::Freed);

        std::println!("CRABC_MI_ARENA_SINGLETON_REGULAR_EXIT_BEGIN");
        std::println!("singleton_request={SINGLETON_REQUEST}");
        std::println!("regular_request={REGULAR_REQUEST}");
        std::println!("singleton_block_size={singleton_block_size}");
        std::println!("regular_reserved={regular_reserved}");
        std::println!("singleton_slice_count={}", singleton_page.arena_slice_count());
        std::println!("regular_slice_count={}", regular_page.arena_slice_count());
        std::println!("singleton_map_count={}", singleton_page.registered_slice_count());
        std::println!("regular_map_count={}", regular_page.registered_slice_count());
        for key in ["owner_setup_valid", "both_arena_backed", "both_map_registered",
                    "regular_reclaimed", "singleton_retained", "singleton_map_clear",
                    "regular_still_registered", "regular_retired", "regular_map_clear",
                    "survivor_usable"] {
            std::println!("{key}=1");
        }
        std::println!("CRABC_MI_ARENA_SINGLETON_REGULAR_EXIT_END");
    });
}
