//! Distinct survivor threads release two arena singletons after one owner exits.

use core::ffi::c_char;
use core::ptr::NonNull;
use std::sync::mpsc;
use std::thread;
use std::vec::Vec;

use crate::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, NativeProcessStartupFacts,
    NativeTheapTraceFact, RuntimeStderrOutput, ThreadAttachResult, ThreadFinishResult,
    attach_current_thread, current_native_allocator_thread_descriptor,
    finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, native_runtime_current_local_page_test_audit,
    native_runtime_current_owner_theap_trace_test_audit,
    native_runtime_live_client_page_map_span_test_audit,
    native_runtime_live_client_page_test_audit, prepare_native_later_thread_arena,
    publish_native_process_startup_facts, register_current_native_allocator_worker_descriptor,
};

const REQUEST: usize = 524289;
const TEST_NAME: &str = "arena_singleton_split_exit::two_survivors_release_distinct_arena_singletons_after_owner_exit";

struct SourceEnvironment([*const c_char; 2]);

// SAFETY: the environment vector and C string are immutable process-lifetime data.
unsafe impl Sync for SourceEnvironment {}

static SOURCE_ENVIRONMENT: SourceEnvironment = SourceEnvironment([
    c"mimalloc_page_full_retain=-1".as_ptr(),
    core::ptr::null(),
]);

unsafe fn source_environment() -> *const *const c_char {
    SOURCE_ENVIRONMENT.0.as_ptr()
}

unsafe extern "C" fn discard_stderr(_message: *const c_char) {}

fn client(address: usize) -> NonNull<u8> {
    NonNull::new(address as *mut u8).expect("an exact live client is nonnull")
}

fn allocate(request: usize) -> NonNull<u8> {
    let NativePageAllocationResult::Allocated(block) = native_allocate_aligned(request, 16, false)
    else {
        panic!("the source arena allocates its client");
    };
    block
}

fn singleton_block_size(client_address: usize) -> usize {
    let mut found = None;
    let complete = native_runtime_current_owner_theap_trace_test_audit(&mut |fact| {
        let NativeTheapTraceFact::Page { bin, page } = fact else { return };
        let Some(end) = page.block_size.checked_mul(page.reserved)
            .and_then(|size| page.start.checked_add(size)) else { return };
        if page.start <= client_address && client_address < end {
            assert_eq!(bin, crate::config::BIN_FULL);
            assert!(page.in_full);
            assert!(found.replace(page.block_size).is_none(), "one client belongs to one singleton page");
        }
    });
    assert!(complete, "the source owner yields a complete Theap queue walk");
    found.expect("the singleton remains in its full queue")
}

#[test]
fn two_survivors_release_distinct_arena_singletons_after_owner_exit() {
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
            // SAFETY: this worker registers its exact current TLS descriptor
            // before attachment, then completes source exit itself.
            assert!(unsafe { register_current_native_allocator_worker_descriptor(descriptor) });
            assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
            let blocks = [allocate(REQUEST), allocate(REQUEST)];
            for block in blocks {
                // SAFETY: the owner still holds this exact live client and no
                // concurrent thread mutates its queue or PageMap entry.
                let local = unsafe { native_runtime_current_local_page_test_audit(block) }
                    .expect("the arena singleton is a local source page");
                assert_eq!(local.used, 1);
                assert_eq!(local.reserved, 1);
                assert_eq!(singleton_block_size(block.as_ptr().addr()), 589824);
            }
            clients_sender.send(blocks.map(|block| block.as_ptr().addr()))
                .expect("both survivor threads receive their exact clients");
            exit_receiver.recv().expect("the owner begins source TLS exit");
            assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
        });

        let clients = clients_receiver.recv().expect("the source owner publishes both clients");
        let mut survivor_threads = Vec::new();
        let mut survivor_go = Vec::new();
        for address in clients {
            let (ready_sender, ready_receiver) = mpsc::sync_channel(0);
            let (go_sender, go_receiver) = mpsc::sync_channel(0);
            let survivor = thread::spawn(move || {
                let descriptor = current_native_allocator_thread_descriptor();
                // SAFETY: each survivor attaches using only its own current
                // descriptor and never borrows the exited owner's Theap.
                assert!(unsafe { register_current_native_allocator_worker_descriptor(descriptor) });
                assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
                ready_sender.send(()).expect("the survivor announces attachment");
                go_receiver.recv().expect("the owner has completed source exit");
                // SAFETY: this survivor alone owns its transferred live client.
                assert_eq!(unsafe { native_free(client(address)) }, NativePageFreeResult::Freed);
                assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
            });
            ready_receiver.recv().expect("both releasers survive the source owner");
            survivor_threads.push(survivor);
            survivor_go.push(go_sender);
        }
        exit_sender.send(()).expect("the source owner may complete exit");
        owner.join().expect("the owner has completed source TLS exit");

        // SAFETY: both exact clients remain live, all participating threads
        // are quiescent, and neither survivor may free before signaled.
        let first = unsafe { native_runtime_live_client_page_test_audit(client(clients[0])) }
            .expect("first singleton is arena backed and mapped");
        let second = unsafe { native_runtime_live_client_page_test_audit(client(clients[1])) }
            .expect("second singleton is arena backed and mapped");
        assert_ne!(first.page_address(), second.page_address());
        for page in [first, second] {
            assert_eq!(page.arena_slice_count(), 9);
            assert_eq!(page.registered_slice_count(), 9);
            assert_eq!(unsafe { native_runtime_live_client_page_map_span_test_audit(page) }
                .expect("each source PageMap span remains registered after exit")
                .matching_page_entry_count, 9);
        }

        survivor_go.remove(0).send(()).expect("first survivor may free after owner exit");
        survivor_threads.remove(0).join().expect("first survivor completes its terminal free");
        let first_map_clear = unsafe { native_runtime_live_client_page_map_span_test_audit(first) }
            .expect("first singleton PageMap span after release").non_null_entry_count == 0;
        let second_retained = unsafe { native_runtime_live_client_page_map_span_test_audit(second) }
            .expect("second singleton remains live").matching_page_entry_count == 9;
        assert!(first_map_clear && second_retained);

        survivor_go.remove(0).send(()).expect("second survivor may free after first release");
        survivor_threads.remove(0).join().expect("second survivor completes its terminal free");
        let second_map_clear = unsafe { native_runtime_live_client_page_map_span_test_audit(second) }
            .expect("second singleton PageMap span after release").non_null_entry_count == 0;
        let first_still_clear = unsafe { native_runtime_live_client_page_map_span_test_audit(first) }
            .expect("first singleton remains released").non_null_entry_count == 0;
        assert!(second_map_clear && first_still_clear);

        std::println!("CRABC_MI_ARENA_SINGLETON_SPLIT_EXIT_BEGIN");
        std::println!("request={REQUEST}");
        std::println!("block_size=589824");
        std::println!("first_slice_count={}", first.arena_slice_count());
        std::println!("second_slice_count={}", second.arena_slice_count());
        std::println!("first_map_count={}", first.registered_slice_count());
        std::println!("second_map_count={}", second.registered_slice_count());
        for key in ["owner_setup_valid", "two_releasers_ready", "owner_joined_before_free",
                    "both_arena_backed", "both_map_registered", "first_free_completed",
                    "first_map_clear", "second_retained", "second_free_completed",
                    "second_map_clear", "first_still_clear"] {
            std::println!("{key}=1");
        }
        std::println!("CRABC_MI_ARENA_SINGLETON_SPLIT_EXIT_END");
    });
}
