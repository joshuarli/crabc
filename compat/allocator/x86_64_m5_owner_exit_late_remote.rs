use core::ffi::c_char;
use core::ptr::NonNull;
use std::sync::mpsc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, NativeProcessStartupFacts,
    NativeTheapTraceFact, NativeTheapTracePage, RuntimeStderrOutput,
    ThreadAttachResult, ThreadFinishResult, attach_current_thread,
    current_native_allocator_thread_descriptor,
    finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_collect, native_free, native_runtime_current_local_page_same_test_audit,
    native_runtime_current_local_page_test_audit, native_runtime_current_owner_theap_trace_test_audit,
    native_runtime_live_client_page_map_span_test_audit, native_runtime_live_client_page_test_audit,
    native_usable_size, prepare_native_later_thread_arena,
    publish_native_process_startup_facts, register_current_native_allocator_worker_descriptor,
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
    // SAFETY: the source supplies a NUL-terminated diagnostic fragment for
    // this call; a direct descriptor write preserves it without allocator use.
    let fragment = unsafe { std::ffi::CStr::from_ptr(message) }.to_bytes();
    // SAFETY: standard error is the live native test process's own descriptor.
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

fn current_queue_page(address: usize) -> Option<NativeTheapTracePage> {
    let mut found = None;
    assert!(native_runtime_current_owner_theap_trace_test_audit(&mut |fact| {
        let NativeTheapTraceFact::Page { page, .. } = fact else { return };
        let Some(end) = page.block_size.checked_mul(page.reserved)
            .and_then(|bytes| page.start.checked_add(bytes)) else { return };
        if page.start <= address && address < end {
            assert!(found.replace(page).is_none());
        }
    }));
    found
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
    // SAFETY: this exact warm-up client is current and owned by this thread.
    assert_eq!(unsafe { native_free(warmup) }, NativePageFreeResult::Freed);
    assert!(prepare_native_later_thread_arena());
    let NativePageAllocationResult::Allocated(active_warmup) = native_allocate_aligned(48, 16, false)
    else { panic!("the surviving owner reactivates its default Theap") };
    // SAFETY: the surviving owner retains this exact current warm-up client.
    assert_eq!(unsafe { native_free(active_warmup) }, NativePageFreeResult::Freed);
    let mut full_retain = None;
    assert!(native_runtime_current_owner_theap_trace_test_audit(&mut |fact| {
        if let NativeTheapTraceFact::Options { page_full_retain, .. } = fact {
            assert!(full_retain.replace(page_full_retain).is_none());
        }
    }));
    let full_retain_negative_one = full_retain == Some(-1);

    let (clients_sender, clients_receiver) = mpsc::sync_channel(0);
    let (exit_sender, exit_receiver) = mpsc::sync_channel(0);
    let owner = thread::spawn(move || {
        attach_worker();
        let clients = [allocate(), allocate(), allocate()];
        // SAFETY: the owner has not transferred or freed these three clients.
        let audit = unsafe { native_runtime_current_local_page_test_audit(clients[0]) }
            .expect("the owner sees the medium source page");
        assert!(unsafe { native_runtime_current_local_page_same_test_audit(clients[0], clients[1]) }
            .expect("the first two clients share a source page"));
        assert!(unsafe { native_runtime_current_local_page_same_test_audit(clients[1], clients[2]) }
            .expect("the last two clients share a source page"));
        assert_eq!(audit.used, 3);
        assert!(audit.reserved > 3);
        clients_sender.send((clients.map(|block| block.as_ptr().addr()), audit.reserved))
            .expect("the coordinator receives the three live clients");
        exit_receiver.recv().expect("the first remote publication precedes exit");
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    });
    let (addresses, capacity) = clients_receiver.recv().expect("the owner publishes its clients");
    let (first_sender, first_receiver) = mpsc::sync_channel(0);
    let first_address = addresses[0];
    let first = thread::spawn(move || {
        attach_worker();
        let block = client(first_address);
        // SAFETY: the owner retains the exact client and does not exit until this free completes.
        let usable = unsafe { native_usable_size(block) }.expect("the first client resolves through PageMap");
        assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
        first_sender.send(usable).expect("the coordinator observes the first publication");
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    });
    let first_usable = first_receiver.recv().expect("the first worker published");
    first.join().expect("the first worker completed its independent lifecycle");

    // SAFETY: the owner is blocked, both remaining clients are live, and the
    // first publisher joined before these PageMap observations.
    let page = unsafe { native_runtime_live_client_page_test_audit(client(addresses[2])) }
        .expect("the source page remains registered before owner exit");
    let first_registered = unsafe { native_runtime_live_client_page_map_span_test_audit(page) }
        .expect("the source PageMap span is readable").matching_page_entry_count
        == page.registered_slice_count();
    exit_sender.send(()).expect("the owner collects and abandons the page");
    owner.join().expect("the owner completes its source exit");

    // SAFETY: no worker mutates the surviving page at this quiescent point.
    let registered_after_exit = unsafe { native_runtime_live_client_page_map_span_test_audit(page) }
        .expect("the abandoned page remains registered").matching_page_entry_count
        == page.registered_slice_count();
    let second = client(addresses[1]);
    let second_usable = unsafe { native_usable_size(second) }
        .expect("the second producer resolves a current abandoned client");
    // SAFETY: this is the exact second live client; the first publisher and owner joined.
    assert_eq!(unsafe { native_free(second) }, NativePageFreeResult::Freed);
    let reclaimed = current_queue_page(addresses[2])
        .expect("the active second producer reclaims the abandoned page");
    let used_after_second = reclaimed.used;
    let reclaimed_after_second = used_after_second == 1 && !reclaimed.in_full;
    let registered_after_second = unsafe { native_runtime_live_client_page_map_span_test_audit(page) }
        .expect("the reclaimed page remains registered").matching_page_entry_count
        == page.registered_slice_count();
    // SAFETY: the active producer now owns the remaining exact client.
    assert_eq!(unsafe { native_free(client(addresses[2])) }, NativePageFreeResult::Freed);
    let retired = current_queue_page(addresses[2]).expect("the empty page retires on the active owner");
    let used_before_collect = retired.used;
    let retire_expire = retired.retire_expire;
    let registered_before_collect = unsafe { native_runtime_live_client_page_map_span_test_audit(page) }
        .expect("the retired page remains registered").matching_page_entry_count
        == page.registered_slice_count();
    native_collect(true);
    let released_after_collect = unsafe { native_runtime_live_client_page_map_span_test_audit(page) }
        .expect("the released span remains readable").matching_page_entry_count == 0;
    native_collect(true);
    let still_released = unsafe { native_runtime_live_client_page_map_span_test_audit(page) }
        .expect("the second collection leaves the span clear").matching_page_entry_count == 0;
    let NativePageAllocationResult::Allocated(survivor) = native_allocate_aligned(64, 16, false)
    else { panic!("the survivor allocates after terminal collection") };
    let survivor_usable = unsafe { native_usable_size(survivor) }.is_some();
    assert_eq!(unsafe { native_free(survivor) }, NativePageFreeResult::Freed);
    assert_eq!(WARNINGS.load(Ordering::Relaxed), 0);

    println!("CRABC_MI_M5_OWNER_EXIT_LATE_REMOTE_BEGIN");
    println!("full_retain_negative_one={}", usize::from(full_retain_negative_one));
    println!("reclaim_on_free=1");
    println!("request={REQUEST}");
    println!("capacity={capacity}");
    println!("setup_valid=1");
    println!("first_usable={first_usable}");
    println!("first_registered={}", usize::from(first_registered));
    println!("registered_after_exit={}", usize::from(registered_after_exit));
    println!("second_usable={second_usable}");
    println!("registered_after_second={}", usize::from(registered_after_second));
    println!("used_after_second={used_after_second}");
    println!("reclaimed_after_second={}", usize::from(reclaimed_after_second));
    println!("registered_before_collect={}", usize::from(registered_before_collect));
    println!("used_before_collect={used_before_collect}");
    println!("retire_expire={retire_expire}");
    println!("released_after_collect={}", usize::from(released_after_collect));
    println!("still_released={}", usize::from(still_released));
    println!("survivor_usable={}", usize::from(survivor_usable));
    println!("CRABC_MI_M5_OWNER_EXIT_LATE_REMOTE_END");
}
