use core::ffi::c_char;
use core::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, mpsc};

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, NativeProcessStartupFacts,
    RuntimeStderrOutput, ThreadAttachResult, ThreadFinishResult,
    attach_current_thread, current_native_allocator_thread_descriptor,
    finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_collect, native_free, native_pointer_is_mapped,
    native_runtime_current_local_page_same_test_audit,
    native_runtime_current_local_page_test_audit,
    prepare_native_later_thread_arena, publish_native_process_startup_facts,
    register_current_native_allocator_worker_descriptor,
};

const PRODUCERS: usize = 3;
const CLIENTS: usize = PRODUCERS + 1;
const REQUEST: usize = 64 * 1024;
static WARNINGS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" {
    fn write(fd: i32, buffer: *const u8, count: usize) -> isize;
}

struct SourceEnvironment([*const c_char; 2]);
// SAFETY: both the vector and C string have static lifetime and are immutable.
unsafe impl Sync for SourceEnvironment {}
static SOURCE_ENVIRONMENT: SourceEnvironment = SourceEnvironment([
    c"mimalloc_page_full_retain=-1".as_ptr(), core::ptr::null(),
]);

unsafe fn source_environment() -> *const *const c_char {
    SOURCE_ENVIRONMENT.0.as_ptr()
}

unsafe extern "C" fn source_stderr(message: *const c_char) {
    WARNINGS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the source callback supplies one valid NUL-terminated fragment.
    let fragment = unsafe { std::ffi::CStr::from_ptr(message) }.to_bytes();
    // SAFETY: stderr remains a live descriptor for this fixture process.
    let _ = unsafe { write(2, fragment.as_ptr(), fragment.len()) };
}

fn client(address: usize) -> NonNull<u8> {
    NonNull::new(address as *mut u8).expect("the source client is nonnull")
}

fn attach_worker() {
    let descriptor = current_native_allocator_thread_descriptor();
    // SAFETY: this worker's descriptor names its live compiler TLS cell.
    assert!(unsafe { register_current_native_allocator_worker_descriptor(descriptor) });
    assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
}

fn main() {
    // SAFETY: startup retains both the static environment and callback.
    let facts = unsafe {
        NativeProcessStartupFacts::new(
            4096, source_environment, RuntimeStderrOutput::new(source_stderr),
        )
    }.expect("the Linux page size is valid");
    assert!(publish_native_process_startup_facts(facts));
    assert!(initialize_process());
    assert!(prepare_native_later_thread_arena());

    let (clients_sender, clients_receiver) = mpsc::sync_channel(0);
    let (collect_sender, collect_receiver) = mpsc::sync_channel(0);
    let (results_sender, results_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        attach_worker();
        let clients: [NonNull<u8>; CLIENTS] = std::array::from_fn(|_| {
            let NativePageAllocationResult::Allocated(block) =
                native_allocate_aligned(REQUEST, 16, false)
            else { panic!("the owner allocates a medium client") };
            block
        });
        for sibling in &clients[1..] {
            // SAFETY: both arguments are distinct, current clients of this owner.
            assert!(unsafe { native_runtime_current_local_page_same_test_audit(clients[0], *sibling) }
                .expect("the source page is observable"));
        }
        // SAFETY: the owner retains the last live client through the remote phase.
        let setup = unsafe { native_runtime_current_local_page_test_audit(clients[3]) }
            .expect("the medium page is owner-associated");
        assert_eq!(setup.used, CLIENTS);
        clients_sender.send(clients.map(|block| block.as_ptr().addr()))
            .expect("the coordinator receives the current client addresses");
        collect_receiver.recv().expect("all foreign publishers finish before collection");
        // SAFETY: all publishers joined, and this owner still holds the last client.
        let used_before = unsafe { native_runtime_current_local_page_test_audit(clients[3]) }
            .expect("pending frees leave the owner page live").used;
        let mapped_before = unsafe { native_pointer_is_mapped(clients[3].as_ptr()) };
        native_collect(false);
        // SAFETY: owner collection is complete and the last client remains live.
        let used_after = unsafe { native_runtime_current_local_page_test_audit(clients[3]) }
            .expect("the collected page remains owner-associated").used;
        let mapped_after = unsafe { native_pointer_is_mapped(clients[3].as_ptr()) };
        // SAFETY: this owner holds the exact last live client.
        assert_eq!(unsafe { native_free(clients[3]) }, NativePageFreeResult::Freed);
        native_collect(true);
        let released = !unsafe { native_pointer_is_mapped(clients[3].as_ptr()) };
        native_collect(true);
        let still_released = !unsafe { native_pointer_is_mapped(clients[3].as_ptr()) };
        results_sender.send((used_before, mapped_before, used_after, mapped_after, released, still_released))
            .expect("the coordinator receives the collected source facts");
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    });
    let addresses = clients_receiver.recv().expect("the owner publishes its clients");
    let start = Arc::new(Barrier::new(PRODUCERS + 1));
    let mut workers = Vec::new();
    for address in addresses[..PRODUCERS].iter().copied() {
        let start = Arc::clone(&start);
        workers.push(std::thread::spawn(move || {
            attach_worker();
            start.wait();
            // SAFETY: the producer owns this distinct exact client, while the
            // remaining live owner client retains the page and PageMap entry.
            assert_eq!(unsafe { native_free(client(address)) }, NativePageFreeResult::Freed);
            assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
        }));
    }
    start.wait();
    for worker in workers { worker.join().expect("foreign publisher completed"); }
    collect_sender.send(()).expect("the owner may collect after all publishers join");
    let (used_before, mapped_before, used_after, mapped_after, released, still_released) =
        results_receiver.recv().expect("the owner reports the final source state");
    owner.join().expect("the owner completes its allocator lifecycle");
    assert_eq!(WARNINGS.load(Ordering::Relaxed), 0);
    println!("CRABC_MI_M5_REMOTE_OWNER_COLLECT_BEGIN");
    println!("producer_count={PRODUCERS}\nrequest={REQUEST}\nused_before={used_before}");
    println!("mapped_before={}\nused_after={used_after}\nmapped_after={}",
        usize::from(mapped_before), usize::from(mapped_after));
    println!("released={}\nstill_released={}", usize::from(released), usize::from(still_released));
    println!("CRABC_MI_M5_REMOTE_OWNER_COLLECT_END");
    assert_eq!((used_before, used_after), (CLIENTS, 1));
    assert!(mapped_before && mapped_after && released && still_released);
}
