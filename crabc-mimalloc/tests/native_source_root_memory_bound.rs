#![cfg(all(target_arch = "x86_64", feature = "native-runtime-test-audit"))]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use std::sync::{Arc, Barrier, mpsc};

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    finish_current_thread_native_after_user_destructors, native_allocate_aligned, native_free,
    native_runtime_lifecycle_test_audit, prepare_native_later_thread_arena,
};

const SEED: u64 = 0x713a_29be_18cd_4f60;
const REQUESTS: [usize; 4] = [37, 2048, 10248, 86699];
const CLIENTS: usize = 64;

fn next(random: &mut u64) -> usize {
    // This deterministic workload permutation is not an entropy source.
    *random ^= *random << 13;
    *random ^= *random >> 7;
    *random ^= *random << 17;
    *random as usize
}

fn free_client((address, request, pattern): (usize, usize, u8)) {
    let client = core::ptr::NonNull::new(address as *mut u8).unwrap();
    // SAFETY: this exact client is exclusively owned by its allocating worker
    // or transferred once to a releaser after the allocating worker joined.
    // No other worker receives or accesses this block.
    unsafe {
        assert_eq!(*client.as_ptr(), pattern);
        assert_eq!(*client.as_ptr().add(request - 1), pattern);
        assert_eq!(native_free(client), NativePageFreeResult::Freed);
    }
}

fn churn(workers: usize, seed: u64) {
    let parked = Arc::new(Barrier::new(workers + 1));
    let (sender, receiver) = mpsc::channel();
    let mut owners = Vec::with_capacity(workers);
    for worker in 0..workers {
        let sender = sender.clone();
        let parked = parked.clone();
        owners.push(std::thread::spawn(move || {
            assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
            let mut clients = Vec::with_capacity(CLIENTS);
            for index in 0..CLIENTS {
                let request = REQUESTS[index % REQUESTS.len()];
                let client = match native_allocate_aligned(request, 16, false) {
                    NativePageAllocationResult::Allocated(client) => client,
                    _ => panic!("the bounded source working set allocates"),
                };
                let pattern = (index ^ worker) as u8;
                // SAFETY: allocation returned request writable bytes; this
                // worker alone owns the client until its channel publication.
                unsafe { core::ptr::write_bytes(client.as_ptr(), pattern, request) };
                clients.push((client.as_ptr().addr(), request, pattern));
            }
            let mut random = seed ^ (worker as u64 + 1);
            for index in (1..clients.len()).rev() {
                let other = next(&mut random) % (index + 1);
                clients.swap(index, other);
            }
            for client in clients.drain(..CLIENTS / 2) { free_client(client); }
            sender.send(clients).unwrap();
            parked.wait();
            assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
        }));
    }
    drop(sender);
    let mut remote = (0..workers).map(|_| Vec::new()).collect::<Vec<_>>();
    for clients in receiver.iter().take(workers) {
        for (index, client) in clients.into_iter().enumerate() {
            remote[index % workers].push(client);
        }
    }
    parked.wait();
    for owner in owners { owner.join().unwrap(); }
    let releasers = remote.into_iter().map(|clients| std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        for client in clients { free_client(client); }
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    })).collect::<Vec<_>>();
    for releaser in releasers { releaser.join().unwrap(); }
}

// The process owns retained metadata pages and PageMap submaps. Repeating the
// same maximum live working set must reuse that capacity after every client,
// worker TLD and worker Theap is released. Child subprocess destruction has a
// separate direct-OS lifetime contract and is not exercised by this witness.
#[test]
fn seeded_worker_churn_reuses_source_metadata_arena_and_page_map_capacity() {
    let epochs = std::env::var("CRABC_MI_SOURCE_ROOT_EPOCHS")
        .map(|value| value.parse::<usize>().expect("the bounded epoch count is an integer"))
        .unwrap_or(32);
    assert!((32..=512).contains(&epochs), "the seeded soak runs 32 through 512 epochs");
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    assert!(prepare_native_later_thread_arena());
    churn(8, SEED);
    let warm = native_runtime_lifecycle_test_audit().unwrap();
    // SAFETY: all owners and releasers joined before this scalar observation.
    let applications = unsafe { native_runtime_test_support::quiescent_application_page_map_entry_count() };
    assert_eq!(applications, 0);
    for epoch in 0..epochs {
        for workers in [1, 2, 4, 8] {
            let seed = SEED.wrapping_add((epoch * 4 + workers) as u64);
            churn(workers, seed);
            let now = native_runtime_lifecycle_test_audit().unwrap();
            // SAFETY: every participating owner and releaser joined.
            assert_eq!(unsafe { native_runtime_test_support::quiescent_application_page_map_entry_count() }, 0);
            assert_eq!(now.live_thread_count, warm.live_thread_count);
            assert_eq!(now.shared_later_theap_count, warm.shared_later_theap_count);
            assert_eq!(now.metadata_live_capability_count, warm.metadata_live_capability_count);
            assert_eq!(now.metadata_high_water_capability_count, warm.metadata_high_water_capability_count);
            assert_eq!(now.arena_registry_count, warm.arena_registry_count);
            assert_eq!(now.process_arena_size, warm.process_arena_size);
            assert_eq!(now.page_map_registered_entry_count, warm.page_map_registered_entry_count);
            assert_eq!(now.page_map_published_submap_count, warm.page_map_published_submap_count);
            assert_eq!(now.page_map_lazy_submap_allocation_count, warm.page_map_lazy_submap_allocation_count);
            std::println!("source_root_bound seed={seed} epoch={epoch} workers={workers} clients={} live={} metadata_high_water={} arenas={} arena_bytes={} registered_slices={} submaps={}",
                workers * CLIENTS, now.metadata_live_capability_count,
                now.metadata_high_water_capability_count, now.arena_registry_count,
                now.process_arena_size, now.page_map_registered_entry_count,
                now.page_map_published_submap_count);
        }
    }
}
