//! Source-shaped later-owner exit for mapped regular pages and an OS singleton.

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
use crate::config::{ARENA_SLICE_SIZE, LARGE_PAGE_SIZE, MEDIUM_MAX_OBJ_SIZE, MEDIUM_PAGE_SIZE};

const LARGE_REQUEST: usize = MEDIUM_MAX_OBJ_SIZE + 64 * 1024;
const MEDIUM_REQUEST: usize = 64 * 1024;
const TEST_NAME: &str = "mapped_large_owner_exit::nonabandoning_mapped_large_and_medium_reclaim_after_owner_exit";

/// One exact live client transferred before its source owner exits.
struct TransferredLiveClient(NonNull<u8>);

// SAFETY: the channel transfers exclusive client access; the receiver consumes
// it once after the allocating worker has completed source owner exit.
unsafe impl Send for TransferredLiveClient {}

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
    NonNull::new(address as *mut u8).expect("a live source client is nonnull")
}

fn allocate(request: usize) -> NonNull<u8> {
    let NativePageAllocationResult::Allocated(block) = native_allocate_aligned(request, 16, false)
    else {
        panic!("the source regular page allocates its client");
    };
    block
}

fn round_trip(request: usize) {
    let block = allocate(request);
    // SAFETY: the caller owns this exact live client until this free returns.
    assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
}

fn current_queue_page(client_address: usize) -> Option<NativeTheapTracePage> {
    let mut found = None;
    let complete = native_runtime_current_owner_theap_trace_test_audit(&mut |fact| {
        let NativeTheapTraceFact::Page { bin, page } = fact else { return };
        let Some(end) = page.block_size.checked_mul(page.reserved)
            .and_then(|size| page.start.checked_add(size)) else { return };
        if page.start <= client_address && client_address < end {
            assert_eq!(Some(bin), crate::size_class::bin(page.block_size));
            assert!(found.replace(page).is_none(), "one client belongs to one current queue page");
        }
    });
    assert!(complete, "the active initial owner yields a complete source Theap walk");
    found
}

#[test]
fn nonabandoning_mapped_large_and_medium_reclaim_after_owner_exit() {
    crate::test_process::run_in_fresh_process(TEST_NAME, || {
        // SAFETY: the static option vector and no-op output callback remain
        // valid for the entire fresh process; the allocator never calls back
        // into itself through either source startup dependency.
        let facts = unsafe {
            NativeProcessStartupFacts::new(
                4096,
                source_environment,
                RuntimeStderrOutput::new(discard_stderr),
            )
        }.expect("the native source page size is valid");
        assert!(publish_native_process_startup_facts(facts));
        assert!(initialize_process());
        round_trip(48);
        assert!(prepare_native_later_thread_arena());
        round_trip(48);

        let (clients_sender, clients_receiver) = mpsc::sync_channel(0);
        let (exit_sender, exit_receiver) = mpsc::sync_channel(0);
        let owner = thread::spawn(move || {
            let descriptor = current_native_allocator_thread_descriptor();
            // SAFETY: the worker registers its exact current TLS descriptor
            // before attachment and completes its normal source exit.
            assert!(unsafe { register_current_native_allocator_worker_descriptor(descriptor) });
            assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
            let large = [allocate(LARGE_REQUEST), allocate(LARGE_REQUEST)];
            let medium = [allocate(MEDIUM_REQUEST), allocate(MEDIUM_REQUEST)];
            let NativePageAllocationResult::Allocated(os) = native_allocate_aligned(7, 128 * 1024, false)
            else { panic!("the owner allocates an independent OS-aligned singleton"); };
            let os = TransferredLiveClient(os);
            // SAFETY: this worker owns all five live clients and has no
            // concurrent source queue mutation while taking scalar audits.
            let large_local = unsafe { native_runtime_current_local_page_test_audit(large[0]) }
                .expect("large source queue audit");
            let medium_local = unsafe { native_runtime_current_local_page_test_audit(medium[0]) }
                .expect("medium source queue audit");
            assert!(unsafe { native_runtime_current_local_page_same_test_audit(large[0], large[1]) }
                .expect("two large clients share a source page"));
            assert!(unsafe { native_runtime_current_local_page_same_test_audit(medium[0], medium[1]) }
                .expect("two medium clients share a source page"));
            for audit in [large_local, medium_local] {
                assert_eq!(audit.used, 2);
                assert!(audit.reserved > 2);
                assert_eq!(audit.in_full, 0);
                assert_eq!(audit.regular_queue_count, 1);
                assert_eq!(audit.member_link_coherent, 1);
            }
            clients_sender.send((large.map(|block| block.as_ptr().addr()),
                                 medium.map(|block| block.as_ptr().addr()),
                                 large_local.reserved, medium_local.reserved, os))
                .expect("the active survivor receives all source clients");
            exit_receiver.recv().expect("the survivor starts source TLS exit");
            assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
        });

        let (large, medium, large_reserved, medium_reserved, os) = clients_receiver.recv()
            .expect("the owner publishes both regular source pages");
        exit_sender.send(()).expect("the later owner may complete source TLS exit");
        owner.join().expect("the later source owner completes its exit");
        // SAFETY: every client remains live, the owner has joined, and no
        // other allocator operation can mutate these PageMap spans now.
        let large_page = unsafe { native_runtime_live_client_page_test_audit(client(large[1])) }
            .expect("the large page remains registered after exit");
        let medium_page = unsafe { native_runtime_live_client_page_test_audit(client(medium[1])) }
            .expect("the medium page remains registered after exit");
        assert_ne!(large_page.page_address(), medium_page.page_address());
        assert_eq!(large_page.arena_slice_count(), LARGE_PAGE_SIZE / ARENA_SLICE_SIZE);
        assert_eq!(medium_page.arena_slice_count(), MEDIUM_PAGE_SIZE / ARENA_SLICE_SIZE);
        assert!(large_page.registered_slice_count() > 0
            && large_page.registered_slice_count() <= large_page.arena_slice_count());
        assert!(medium_page.registered_slice_count() > 0
            && medium_page.registered_slice_count() <= medium_page.arena_slice_count());
        assert_eq!(unsafe { native_runtime_live_client_page_map_span_test_audit(large_page) }
            .expect("large source PageMap span remains live").matching_page_entry_count,
            large_page.registered_slice_count());
        assert_eq!(unsafe { native_runtime_live_client_page_map_span_test_audit(medium_page) }
            .expect("medium source PageMap span remains live").matching_page_entry_count,
            medium_page.registered_slice_count());

        // SAFETY: each call consumes one transferred live client. A large
        // abandoned page remains mapped after its nonterminal free, while
        // the medium page can be reclaimed into this active Theap.
        assert_eq!(unsafe { native_free(client(large[0])) }, NativePageFreeResult::Freed);
        assert!(current_queue_page(large[1]).is_none(),
            "a large page is not reclaimed on free into the active Theap");
        assert_eq!(unsafe { native_runtime_live_client_page_map_span_test_audit(large_page) }
            .expect("the large page stays mapped after its first free").matching_page_entry_count,
            large_page.registered_slice_count());
        assert_eq!(unsafe { native_free(client(medium[0])) }, NativePageFreeResult::Freed);
        let medium_reclaimed = current_queue_page(medium[1])
            .expect("the active survivor now owns the medium regular queue");
        assert_eq!(medium_reclaimed.used, 1);
        assert!(!medium_reclaimed.in_full);
        assert_eq!(medium_reclaimed.retire_expire, 0);
        // SAFETY: the receiver exclusively owns this still-live medium client;
        // both terminal releases below concern disjoint source allocations.
        unsafe { client(medium[1]).as_ptr().write_bytes(0x5a, 32) };
        assert_eq!(unsafe { native_free(client(large[1])) }, NativePageFreeResult::Freed);
        let large_released_on_final = unsafe { native_runtime_live_client_page_map_span_test_audit(large_page) }
            .expect("the large span is readable after terminal release").matching_page_entry_count == 0;
        let medium_registered_after_large_final = unsafe { native_runtime_live_client_page_map_span_test_audit(medium_page) }
            .expect("the independent medium span stays registered").matching_page_entry_count
            == medium_page.registered_slice_count();
        assert!(large_released_on_final && medium_registered_after_large_final);

        // SAFETY: the transferred singleton is still live and all source owners
        // are quiescent. Its source memory kind distinguishes it from arenas.
        assert_eq!(unsafe { crate::__crabc_runtime::native_runtime_live_client_memory_kind_test_audit(os.0) }, Some(3));
        let before_os_map = crate::__crabc_runtime::native_runtime_lifecycle_test_audit()
            .expect("the source process retains its PageMap counters");
        #[cfg(feature = "native-runtime-test-fault")]
        let before_os_vm = crate::__crabc_runtime::native_runtime_terminal_vm_current_test_audit()
            .expect("the source subprocess retains VM accounting");
        #[cfg(feature = "native-runtime-test-fault")]
        let failure = crate::__crabc_runtime::native_runtime_test_fail_next_unmap();
        #[cfg(feature = "native-runtime-test-fault")]
        let capture = failure.capture_range();
        // The last-client release consumes this token. Later observations use
        // process counters and the refused raw syscall range only.
        let TransferredLiveClient(os_client) = os;
        #[cfg(feature = "native-runtime-test-fault")]
        let os_address = os_client.as_ptr().addr();
        // SAFETY: this is the one free of the exact transferred live client.
        assert_eq!(unsafe { native_free(os_client) }, NativePageFreeResult::Freed);
        let after_os_map = crate::__crabc_runtime::native_runtime_lifecycle_test_audit()
            .expect("the consumed OS release retains process counters");
        assert!(after_os_map.page_map_registered_entry_count < before_os_map.page_map_registered_entry_count);
        assert_eq!(after_os_map.main_heap_os_abandoned_pages_empty, 1);
        assert_eq!(unsafe { native_runtime_live_client_page_map_span_test_audit(medium_page) }
            .expect("OS release leaves the independent live medium span").matching_page_entry_count,
            medium_page.registered_slice_count());
        for offset in 0..32 {
            // SAFETY: the retained medium client remains live and exclusively
            // held, including after both independent terminal releases.
            assert_eq!(unsafe { client(medium[1]).as_ptr().add(offset).read() }, 0x5a);
        }
        #[cfg(feature = "native-runtime-test-fault")]
        let refused_range = {
            assert_eq!(failure.observed(), 1);
            let range = capture.single().expect("one exact refused terminal mapping release");
            assert!(range.0 <= os_address && os_address < range.0 + range.1);
            let after_os_vm = crate::__crabc_runtime::native_runtime_terminal_vm_current_test_audit()
                .expect("the consumed source release retains subprocess accounting");
            assert_eq!(before_os_vm.reserved - after_os_vm.reserved, range.1 as i64,
                "refused unmap retires the exact reservation while other source pages remain live");
            range
        };
        assert_eq!(unsafe { native_free(client(medium[1])) }, NativePageFreeResult::Freed);
        let medium_retired_page = current_queue_page(medium[1])
            .expect("the active owner retains the empty medium queue member");
        assert_eq!(medium_retired_page.used, 0);
        assert_eq!(medium_retired_page.retire_expire, 4);
        let medium_retained = unsafe { native_runtime_live_client_page_map_span_test_audit(medium_page) }
            .expect("the medium retired page keeps its span").matching_page_entry_count
            == medium_page.registered_slice_count();
        assert!(medium_retained);
        native_collect(true);
        let large_released = unsafe { native_runtime_live_client_page_map_span_test_audit(large_page) }
            .expect("the large span is readable after release").matching_page_entry_count == 0;
        let medium_released = unsafe { native_runtime_live_client_page_map_span_test_audit(medium_page) }
            .expect("the medium span is readable after release").matching_page_entry_count == 0;
        assert!(large_released && medium_released);
        round_trip(64);
        #[cfg(feature = "native-runtime-test-fault")]
        {
            assert_eq!(failure.observed(), 1, "independent collection cannot retry the consumed release");
            assert_eq!(capture.single(), Some(refused_range));
            for offset in (0..refused_range.1).step_by(4096) {
                let mut residency = 0u8;
                // SAFETY: this kernel query uses only the captured refused raw
                // range and never reads a consumed client or retired Page.
                assert!(unsafe { crabc_core::mm::mincore_raw(
                    (refused_range.0 + offset) as *mut u8, 4096, &mut residency,
                ) }.is_ok());
            }
            // SAFETY: no source client or PageMap entry names this consumed
            // mapping. The test owns only the exact refused syscall range.
            assert!(unsafe { crabc_core::mm::munmap_raw(
                refused_range.0 as *mut u8, refused_range.1,
            ) }.is_ok());
        }

        std::println!("CRABC_MI_MAPPED_LARGE_OWNER_EXIT_BEGIN");
        std::println!("full_retain=-1");
        std::println!("large_request={LARGE_REQUEST}");
        std::println!("medium_request={MEDIUM_REQUEST}");
        std::println!("large_reserved={large_reserved}");
        std::println!("medium_reserved={medium_reserved}");
        std::println!("large_slice_count={}", large_page.arena_slice_count());
        std::println!("medium_slice_count={}", medium_page.arena_slice_count());
        std::println!("large_registered_slice_count={}", large_page.registered_slice_count());
        std::println!("medium_registered_slice_count={}", medium_page.registered_slice_count());
        std::println!("owner_queues_valid=1");
        std::println!("large_registered_after_exit=1");
        std::println!("medium_registered_after_exit=1");
        std::println!("large_stays_registered_nonlocal=1");
        std::println!("medium_requeued=1");
        std::println!("large_released_on_final=1");
        std::println!("medium_registered_after_large_final=1");
        std::println!("medium_registered_before_collect=1");
        std::println!("large_released=1");
        std::println!("medium_released=1");
        std::println!("survivor_usable=1");
        std::println!("CRABC_MI_MAPPED_LARGE_OWNER_EXIT_END");
    });
}
