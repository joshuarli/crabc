use core::ffi::c_char;
use core::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Barrier};
use std::thread;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, NativeProcessStartupFacts,
    RuntimeStderrOutput, ThreadAttachResult, ThreadFinishResult, attach_current_thread,
    current_native_allocator_thread_descriptor, finish_current_thread_native_after_user_destructors,
    initialize_process, native_allocate_aligned, native_collect, native_free,
    native_runtime_current_local_page_same_test_audit, native_runtime_current_local_page_test_audit,
    native_runtime_live_client_page_map_span_test_audit, native_runtime_live_client_page_test_audit,
    native_usable_size, prepare_native_later_thread_arena, publish_native_process_startup_facts,
    register_current_native_allocator_worker_descriptor,
};

const REQUEST: usize = 64 * 1024;
static WARNINGS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" {
    fn write(fd: i32, buffer: *const u8, count: usize) -> isize;
}

struct SourceEnvironment([*const c_char; 3]);

// SAFETY: the environment vector and C strings are immutable process-lifetime data.
unsafe impl Sync for SourceEnvironment {}

static SOURCE_ENVIRONMENT: SourceEnvironment = SourceEnvironment([
    c"mimalloc_page_full_retain=-1".as_ptr(),
    c"mimalloc_page_reclaim_on_free=1".as_ptr(),
    core::ptr::null(),
]);

unsafe fn source_environment() -> *const *const c_char {
    SOURCE_ENVIRONMENT.0.as_ptr()
}

unsafe extern "C" fn source_stderr(message: *const c_char) {
    WARNINGS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the source supplies a NUL-terminated diagnostic for this call.
    let fragment = unsafe { std::ffi::CStr::from_ptr(message) }.to_bytes();
    // SAFETY: standard error is this test process's own descriptor.
    let _ = unsafe { write(2, fragment.as_ptr(), fragment.len()) };
}

fn client(address: usize) -> NonNull<u8> {
    NonNull::new(address as *mut u8).expect("the source client remains nonnull")
}

fn attach_worker() {
    let descriptor = current_native_allocator_thread_descriptor();
    // SAFETY: the descriptor names this worker's live compiler TLS cell.
    assert!(unsafe { register_current_native_allocator_worker_descriptor(descriptor) });
    assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
}

fn allocate() -> NonNull<u8> {
    let NativePageAllocationResult::Allocated(block) = native_allocate_aligned(REQUEST, 16, false)
    else { panic!("the owner allocates one medium client") };
    block
}

fn mapped(page: crabc_mimalloc::__crabc_runtime::NativeRuntimeLiveClientPageAudit) -> bool {
    // SAFETY: callers sample only after the participating workers joined;
    // the copied identity grants no page ownership or lifetime extension.
    unsafe { native_runtime_live_client_page_map_span_test_audit(page) }
        .expect("the source PageMap span is readable").matching_page_entry_count
        == page.registered_slice_count()
}

fn main() {
    // SAFETY: the static environment and callback remain valid for the process.
    let facts = unsafe {
        NativeProcessStartupFacts::new(
            4096, source_environment, RuntimeStderrOutput::new(source_stderr),
        )
    }.expect("the native page size is valid");
    assert!(publish_native_process_startup_facts(facts));
    assert!(initialize_process());
    let NativePageAllocationResult::Allocated(warmup) = native_allocate_aligned(48, 16, false)
    else { panic!("the initial owner warms its small page") };
    // SAFETY: this exact warm-up client is owned by the current thread.
    assert_eq!(unsafe { native_free(warmup) }, NativePageFreeResult::Freed);
    assert!(prepare_native_later_thread_arena());
    let NativePageAllocationResult::Allocated(active_warmup) = native_allocate_aligned(48, 16, false)
    else { panic!("the surviving owner reactivates its default Theap") };
    // SAFETY: this exact warm-up client is owned by the current thread.
    assert_eq!(unsafe { native_free(active_warmup) }, NativePageFreeResult::Freed);

    let (clients_sender, clients_receiver) = mpsc::sync_channel(0);
    let owner = thread::spawn(move || {
        attach_worker();
        let clients = [allocate(), allocate(), allocate()];
        // SAFETY: the owner still holds every client and no other worker mutates the page.
        let audit = unsafe { native_runtime_current_local_page_test_audit(clients[0]) }
            .expect("the owner sees its medium page");
        assert_eq!(audit.used, 3);
        assert!(audit.reserved > 3);
        // SAFETY: all three clients are still live on this owner and cannot race a free.
        assert!(unsafe { native_runtime_current_local_page_same_test_audit(clients[0], clients[1]) }
            .expect("the first two clients share a page"));
        assert!(unsafe { native_runtime_current_local_page_same_test_audit(clients[1], clients[2]) }
            .expect("the last two clients share a page"));
        clients_sender.send((clients.map(|block| block.as_ptr().addr()), audit.reserved))
            .expect("the coordinator receives three live clients");
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    });
    let (addresses, capacity) = clients_receiver.recv().expect("the owner publishes its clients");
    owner.join().expect("the owner abandons its page before either publication");
    // SAFETY: the three clients are live and their former owner has exited.
    let page = unsafe { native_runtime_live_client_page_test_audit(client(addresses[2])) }
        .expect("the final client has a registered arena page");
    let registered_after_exit = mapped(page);

    let start = Arc::new(Barrier::new(3));
    let publishers: Vec<_> = addresses[..2].iter().copied().map(|address| {
        let start = Arc::clone(&start);
        thread::spawn(move || {
            attach_worker();
            start.wait();
            let block = client(address);
            // SAFETY: the owner has exited and each worker receives one distinct live client.
            let usable = unsafe { native_usable_size(block) }
                .expect("the published client still resolves through PageMap");
            assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
            assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
            usable
        })
    }).collect();
    start.wait();
    let mut usable = [0; 2];
    for (index, publisher) in publishers.into_iter().enumerate() {
        usable[index] = publisher.join().expect("the publisher finishes after its free");
    }
    let registered_after_publications = mapped(page);
    let final_client = client(addresses[2]);
    // SAFETY: the final client stays live while both publishers complete.
    let final_usable = unsafe { native_usable_size(final_client) }
        .expect("the final client remains mapped after both remote frees");
    assert_eq!(unsafe { native_free(final_client) }, NativePageFreeResult::Freed);
    native_collect(true);
    // SAFETY: the final free and collection completed before these scalar PageMap samples.
    let released_after_collect = !mapped(page);
    native_collect(true);
    let still_released = !mapped(page);
    assert_eq!(WARNINGS.load(Ordering::Relaxed), 0);

    println!("CRABC_MI_M5_POST_EXIT_PARALLEL_RECLAIM_BEGIN");
    println!("request={REQUEST}");
    println!("capacity={capacity}");
    println!("setup_valid=1");
    println!("registered_after_exit={}", usize::from(registered_after_exit));
    println!("publisher_usable_equal={}", usize::from(usable[0] == usable[1] && usable[0] != 0));
    println!("registered_after_publications={}", usize::from(registered_after_publications));
    println!("final_usable={final_usable}");
    println!("released_after_collect={}", usize::from(released_after_collect));
    println!("still_released={}", usize::from(still_released));
    println!("CRABC_MI_M5_POST_EXIT_PARALLEL_RECLAIM_END");
}
