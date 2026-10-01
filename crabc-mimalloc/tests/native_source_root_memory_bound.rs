#![cfg(all(target_arch = "x86_64", feature = "native-runtime-test-audit"))]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use std::sync::mpsc;
use std::time::Duration;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    finish_current_thread_native_after_user_destructors, native_allocate_aligned, native_free,
    native_runtime_lifecycle_test_audit, prepare_native_later_thread_arena,
};

const SEED: u64 = 0x713a_29be_18cd_4f60;
const REQUESTS: [usize; 4] = [37, 2048, 10248, 86699];
const CLIENTS: usize = 64;

type Client = (usize, usize, u8);

// A dropped batch still owns every client remaining in its vector. Unwind can
// free those clients from their allocating worker or the parked coordinator.
struct ClientBatch(Vec<Client>);

impl Drop for ClientBatch {
    fn drop(&mut self) {
        for (address, _, _) in self.0.drain(..) {
            let client = core::ptr::NonNull::new(address as *mut u8).unwrap();
            // SAFETY: removing the client consumes this batch's exclusive
            // ownership exactly once, including during panic cleanup.
            let result = unsafe { native_free(client) };
            if !std::thread::panicking() { assert_eq!(result, NativePageFreeResult::Freed); }
        }
    }
}

struct NativeWorker;

impl Drop for NativeWorker {
    fn drop(&mut self) {
        let result = finish_current_thread_native_after_user_destructors();
        if !std::thread::panicking() { assert_eq!(result, ThreadFinishResult::Finished); }
    }
}

// Release senders belong to the same guard as the JoinHandles. Dropping all
// senders wakes every parked owner before any join, even if another owner
// panicked before publishing or the coordinator unwinds after publication.
#[derive(Default)]
struct JoinedWorkers {
    release: Vec<mpsc::Sender<()>>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl JoinedWorkers {
    fn finish(mut self) {
        self.release.clear();
        let mut successful = true;
        for thread in self.threads.drain(..) { successful &= thread.join().is_ok(); }
        assert!(successful, "every joined source worker completes");
    }
}

impl Drop for JoinedWorkers {
    fn drop(&mut self) {
        self.release.clear();
        for thread in self.threads.drain(..) { let _ = thread.join(); }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum PanicControl { None, AllocatingOwner, ParkedCoordinator }

struct ChurnWatchdog {
    done: mpsc::Sender<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ChurnWatchdog {
    fn start() -> Self {
        let (done, receiver) = mpsc::channel();
        let seconds = 180;
        let thread = std::thread::spawn(move || {
            if receiver.recv_timeout(Duration::from_secs(seconds)).is_err() {
                std::eprintln!("source-root churn exceeded its {seconds}-second watchdog");
                std::process::abort();
            }
        });
        Self { done, thread: Some(thread) }
    }
}

impl Drop for ChurnWatchdog {
    fn drop(&mut self) {
        let _ = self.done.send(());
        let _ = self.thread.take().unwrap().join();
    }
}

fn next(random: &mut u64) -> usize {
    // This deterministic workload permutation is not an entropy source.
    *random ^= *random << 13;
    *random ^= *random >> 7;
    *random ^= *random << 17;
    *random as usize
}

fn free_client((address, request, pattern): Client) {
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

fn churn(workers: usize, seed: u64, panic_control: PanicControl) {
    let (sender, receiver) = mpsc::channel();
    let mut owners = JoinedWorkers::default();
    for worker in 0..workers {
        let sender = sender.clone();
        let (release, resume) = mpsc::channel();
        owners.release.push(release);
        owners.threads.push(std::thread::spawn(move || {
            assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
            let _attachment = NativeWorker;
            let mut clients = ClientBatch(Vec::with_capacity(CLIENTS));
            for index in 0..CLIENTS {
                if worker == 0 && index == 4 && panic_control == PanicControl::AllocatingOwner {
                    panic!("injected allocating-owner unwind");
                }
                let request = REQUESTS[index % REQUESTS.len()];
                let client = match native_allocate_aligned(request, 16, false) {
                    NativePageAllocationResult::Allocated(client) => client,
                    _ => panic!("the bounded source working set allocates"),
                };
                let pattern = (index ^ worker) as u8;
                // SAFETY: allocation returned request writable bytes; this
                // worker alone owns the client until its channel publication.
                unsafe { core::ptr::write_bytes(client.as_ptr(), pattern, request) };
                clients.0.push((client.as_ptr().addr(), request, pattern));
            }
            let mut random = seed ^ (worker as u64 + 1);
            for index in (1..clients.0.len()).rev() {
                let other = next(&mut random) % (index + 1);
                clients.0.swap(index, other);
            }
            for _ in 0..CLIENTS / 2 { free_client(clients.0.pop().unwrap()); }
            if let Err(error) = sender.send(clients) { drop(error.0); }
            drop(sender);
            let _ = resume.recv();
        }));
    }
    drop(sender);
    let mut remote = (0..workers).map(|_| ClientBatch(Vec::new())).collect::<Vec<_>>();
    for _ in 0..workers {
        let mut clients = receiver.recv().expect("every owner publishes or closes its sender");
        for (index, client) in clients.0.drain(..).enumerate() {
            remote[index % workers].0.push(client);
        }
    }
    if panic_control == PanicControl::ParkedCoordinator { panic!("injected parked-coordinator unwind"); }
    owners.finish();
    let mut releasers = JoinedWorkers::default();
    for clients in remote {
        releasers.threads.push(std::thread::spawn(move || {
            assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
            let _attachment = NativeWorker;
            let mut clients = clients;
            while let Some(client) = clients.0.pop() { free_client(client); }
        }));
    }
    releasers.finish();
}

// The process owns retained metadata pages and PageMap submaps. Repeating the
// same maximum live working set must reuse that capacity after every client,
// worker TLD and worker Theap is released. Child subprocess destruction has a
// separate direct-OS lifetime contract and is not exercised by this witness.
#[test]
fn seeded_worker_churn_reuses_source_metadata_arena_and_page_map_capacity() {
    let _watchdog = ChurnWatchdog::start();
    let epochs = std::env::var("CRABC_MI_SOURCE_ROOT_EPOCHS")
        .map(|value| value.parse::<usize>().expect("the bounded epoch count is an integer"))
        .unwrap_or(32);
    assert!((32..=512).contains(&epochs), "the seeded soak runs 32 through 512 epochs");
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    assert!(prepare_native_later_thread_arena());
    churn(8, SEED, PanicControl::None);
    let warm = native_runtime_lifecycle_test_audit().unwrap();
    // SAFETY: all owners and releasers joined before this scalar observation.
    let applications = unsafe { native_runtime_test_support::quiescent_application_page_map_entry_count() };
    assert_eq!(applications, 0);
    for control in [PanicControl::AllocatingOwner, PanicControl::ParkedCoordinator] {
        assert!(std::panic::catch_unwind(|| churn(4, SEED, control)).is_err());
        let after = native_runtime_lifecycle_test_audit().unwrap();
        assert_eq!(after.live_thread_count, warm.live_thread_count);
        assert_eq!(after.shared_later_theap_count, warm.shared_later_theap_count);
        assert_eq!(after.metadata_live_capability_count, warm.metadata_live_capability_count);
        // SAFETY: unwind released every waiter and joined every worker before
        // catch_unwind returned; no client remains owned by the control.
        assert_eq!(unsafe { native_runtime_test_support::quiescent_application_page_map_entry_count() }, 0);
        std::println!("source_root_bound panic_control={} joined=true clients=0 live_metadata={}",
            if control == PanicControl::AllocatingOwner { "allocating-owner" } else { "parked-coordinator" },
            after.metadata_live_capability_count);
    }
    for epoch in 0..epochs {
        for workers in [1, 2, 4, 8] {
            let seed = SEED.wrapping_add((epoch * 4 + workers) as u64);
            churn(workers, seed, PanicControl::None);
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
