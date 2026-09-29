use core::ffi::{c_char, c_void};
use core::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, NativeProcessStartupFacts, NativeTheapTraceFact,
    RuntimeStderrOutput, ThreadAttachResult, ThreadFinishResult, attach_current_thread,
    current_native_allocator_thread_descriptor, finish_current_thread_native_after_user_destructors,
    initialize_process, native_allocate_aligned, native_collect, native_free,
    native_runtime_current_local_page_same_test_audit, native_runtime_current_local_page_test_audit,
    native_runtime_current_owner_theap_trace_test_audit,
    native_runtime_live_client_page_map_span_test_audit, native_runtime_live_client_page_test_audit,
    native_usable_size, prepare_native_later_thread_arena, publish_native_process_startup_facts,
    register_current_native_allocator_worker_descriptor, register_native_deferred_free_callback,
};

const REQUEST: usize = 64 * 1024;
static FIRST: AtomicUsize = AtomicUsize::new(0);
static CALLBACK_CLIENT: AtomicUsize = AtomicUsize::new(0);
static CALLBACKS: AtomicUsize = AtomicUsize::new(0);
static CALLBACK_FORCE: AtomicUsize = AtomicUsize::new(0);
static CALLBACK_SAME_PAGE: AtomicUsize = AtomicUsize::new(0);
static CALLBACK_USED: AtomicUsize = AtomicUsize::new(0);
static WARNINGS: AtomicUsize = AtomicUsize::new(0);

struct SourceEnvironment([*const c_char; 2]);
// SAFETY: this vector and its C strings are immutable process-lifetime data.
unsafe impl Sync for SourceEnvironment {}
static SOURCE_ENVIRONMENT: SourceEnvironment = SourceEnvironment([
    c"mimalloc_page_reclaim_on_free=1".as_ptr(), core::ptr::null(),
]);

unsafe fn source_environment() -> *const *const c_char {
    SOURCE_ENVIRONMENT.0.as_ptr()
}

unsafe extern "C" fn source_stderr(_message: *const c_char) {
    WARNINGS.fetch_add(1, Ordering::Relaxed);
}

unsafe extern "C" fn deferred_callback(force: bool, _heartbeat: u64, _context: *mut c_void) {
    CALLBACKS.fetch_add(1, Ordering::Relaxed);
    CALLBACK_FORCE.fetch_add(usize::from(force), Ordering::Relaxed);
    if let NativePageAllocationResult::Allocated(second) = native_allocate_aligned(REQUEST, 16, false) {
        let first = client(FIRST.load(Ordering::Acquire));
        // SAFETY: both clients belong to this active worker. The callback
        // performs each scalar observation after its nested allocation ends.
        let same = unsafe { native_runtime_current_local_page_same_test_audit(first, second) }
            .unwrap_or(false);
        let used = unsafe { native_runtime_current_local_page_test_audit(second) }
            .map_or(0, |page| page.used as usize);
        CALLBACK_SAME_PAGE.store(usize::from(same), Ordering::Release);
        CALLBACK_USED.store(used, Ordering::Release);
        CALLBACK_CLIENT.store(second.as_ptr().addr(), Ordering::Release);
    }
}

fn client(address: usize) -> NonNull<u8> {
    NonNull::new(address as *mut u8).expect("the exact source client remains live")
}

fn registered(page: crabc_mimalloc::__crabc_runtime::NativeRuntimeLiveClientPageAudit) -> bool {
    // SAFETY: callers sample the PageMap only after the owner joined, while
    // one of its exact clients remains live and no other worker mutates it.
    unsafe { native_runtime_live_client_page_map_span_test_audit(page) }
        .is_some_and(|span| span.matching_page_entry_count == page.registered_slice_count())
}

fn current_page(address: usize) -> Option<crabc_mimalloc::__crabc_runtime::NativeTheapTracePage> {
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
    // SAFETY: the startup vector and diagnostic function remain valid through process exit.
    let facts = unsafe {
        NativeProcessStartupFacts::new(
            4096, source_environment, RuntimeStderrOutput::new(source_stderr),
        )
    }.expect("the page size is valid");
    assert!(publish_native_process_startup_facts(facts));
    assert!(initialize_process());
    let NativePageAllocationResult::Allocated(warmup) = native_allocate_aligned(48, 16, false)
    else { panic!("the initial owner warms its Theap") };
    assert_eq!(unsafe { native_free(warmup) }, NativePageFreeResult::Freed);
    assert!(prepare_native_later_thread_arena());
    let NativePageAllocationResult::Allocated(active_warmup) = native_allocate_aligned(48, 16, false)
    else { panic!("the initial owner reactivates its default Theap") };
    assert_eq!(unsafe { native_free(active_warmup) }, NativePageFreeResult::Freed);
    let owner = thread::spawn(|| {
        let descriptor = current_native_allocator_thread_descriptor();
        // SAFETY: this descriptor identifies the worker's live compiler TLS.
        assert!(unsafe { register_current_native_allocator_worker_descriptor(descriptor) });
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let NativePageAllocationResult::Allocated(first) = native_allocate_aligned(REQUEST, 16, false)
        else { panic!("the worker allocates its first medium client") };
        FIRST.store(first.as_ptr().addr(), Ordering::Release);
        // SAFETY: the static callback and its null context remain valid until
        // the joined worker has returned from its source exit callback.
        unsafe { register_native_deferred_free_callback(Some(deferred_callback), core::ptr::null_mut()) };
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    });
    owner.join().expect("the owner completes its callback and source exit");
    // SAFETY: no callback remains in flight after the worker joined.
    unsafe { register_native_deferred_free_callback(None, core::ptr::null_mut()) };

    let first = client(FIRST.load(Ordering::Acquire));
    let second = client(CALLBACK_CLIENT.load(Ordering::Acquire));
    let first_usable = unsafe { native_usable_size(first) }.expect("the first client survives exit");
    let callback_usable = unsafe { native_usable_size(second) }.expect("the callback client survives exit");
    let first_page = unsafe { native_runtime_live_client_page_test_audit(first) }
        .expect("the original client retains its arena page");
    let page = unsafe { native_runtime_live_client_page_test_audit(second) }
        .expect("the callback client retains its arena page");
    assert_eq!(first_page.page_address(), page.page_address());
    let first_registered = registered(first_page);
    let callback_registered = registered(page);
    assert_eq!(unsafe { native_free(first) }, NativePageFreeResult::Freed);
    let reclaimed_after_first = current_page(second.as_ptr().addr()).is_some();
    let second_registered = registered(page);
    assert_eq!(unsafe { native_free(second) }, NativePageFreeResult::Freed);
    let retire_expire = current_page(second.as_ptr().addr()).map_or(0, |page| page.retire_expire);
    let registered_before_collect = unsafe { native_runtime_live_client_page_map_span_test_audit(page) }
        .is_some_and(|span| span.matching_page_entry_count == page.registered_slice_count());
    native_collect(true);
    let released_after_collect = unsafe { native_runtime_live_client_page_map_span_test_audit(page) }
        .is_some_and(|span| span.matching_page_entry_count == 0);
    println!("CRABC_MI_M5_EXIT_CALLBACK_SURVIVOR_BEGIN");
    println!("request={REQUEST}");
    println!("callbacks={}", CALLBACKS.load(Ordering::Acquire));
    println!("callback_force={}", CALLBACK_FORCE.load(Ordering::Acquire));
    println!("callback_same_page={}", CALLBACK_SAME_PAGE.load(Ordering::Acquire));
    println!("callback_used={}", CALLBACK_USED.load(Ordering::Acquire));
    println!("first_usable={first_usable}");
    println!("callback_usable={callback_usable}");
    println!("first_registered={}", usize::from(first_registered));
    println!("callback_registered={}", usize::from(callback_registered));
    println!("second_registered={}", usize::from(second_registered));
    println!("reclaimed_after_first={}", usize::from(reclaimed_after_first));
    println!("retire_expire={retire_expire}");
    println!("registered_before_collect={}", usize::from(registered_before_collect));
    println!("released_after_collect={}", usize::from(released_after_collect));
    println!("warnings={}", WARNINGS.load(Ordering::Acquire));
    println!("CRABC_MI_M5_EXIT_CALLBACK_SURVIVOR_END");
}
