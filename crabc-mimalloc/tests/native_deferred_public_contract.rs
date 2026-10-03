#![cfg(target_arch = "x86_64")]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crabc_mimalloc::source_api as api;

static REQUEST: AtomicUsize = AtomicUsize::new(33);
static CALLS: AtomicUsize = AtomicUsize::new(0);
static FORCED: AtomicUsize = AtomicUsize::new(0);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static SUPPRESSED: AtomicBool = AtomicBool::new(true);
static ALLOCATED: AtomicBool = AtomicBool::new(true);
static FREED: AtomicBool = AtomicBool::new(true);
static CONTEXT_MATCHES: AtomicBool = AtomicBool::new(true);
static DEFAULT_PRESERVED: AtomicBool = AtomicBool::new(true);
static HEARTBEAT_ORDERED: AtomicBool = AtomicBool::new(true);
static LAST_HEARTBEAT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static CONTEXT: AtomicUsize = AtomicUsize::new(0);
static MARKER: u8 = 0x5a;

unsafe extern "C" fn deferred(force: bool, heartbeat: u64, context: *mut c_void) {
    if ACTIVE.swap(true, Ordering::SeqCst) {
        SUPPRESSED.store(false, Ordering::SeqCst);
        return;
    }
    let previous = LAST_HEARTBEAT.swap(heartbeat, Ordering::SeqCst);
    if heartbeat <= previous {
        HEARTBEAT_ORDERED.store(false, Ordering::SeqCst);
    }
    let original_default = crabc_mimalloc::source_heap_api::theap_get_default();
    CALLS.fetch_add(1, Ordering::SeqCst);
    FORCED.fetch_add(usize::from(force), Ordering::SeqCst);
    if context as usize != CONTEXT.load(Ordering::SeqCst) {
        CONTEXT_MATCHES.store(false, Ordering::SeqCst);
    }
    let size = REQUEST.load(Ordering::SeqCst);
    if let Some(block) = api::malloc(size).value {
        // SAFETY: the callback exclusively owns this successful allocation
        // through its writes and matching free; no outer allocation is freed.
        unsafe {
            block.as_ptr().write(0x39);
            block.as_ptr().add(size - 1).write(0x71);
            if block.as_ptr().read() != 0x39 || block.as_ptr().add(size - 1).read() != 0x71 {
                ALLOCATED.store(false, Ordering::SeqCst);
            }
            if api::free(block.as_ptr()) != api::FreeOutcome::Freed {
                FREED.store(false, Ordering::SeqCst);
            }
        }
    } else {
        ALLOCATED.store(false, Ordering::SeqCst);
    }
    // A nested explicit collection advances the source heartbeat while the
    // same recursion marker suppresses selected user code.
    api::collect(true);
    if crabc_mimalloc::source_heap_api::theap_get_default() != original_default {
        DEFAULT_PRESERVED.store(false, Ordering::SeqCst);
    }
    ACTIVE.store(false, Ordering::SeqCst);
}

#[test]
fn public_collection_and_worker_exit_callbacks_allow_nested_small_and_large_allocation() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    let warm = api::malloc(33).value.expect("ordinary warm allocation");
    // SAFETY: this test owns the complete warm client until this release.
    assert_eq!(unsafe { api::free(warm.as_ptr()) }, api::FreeOutcome::Freed);
    for request in [33, 524_289] {
        for context in [core::ptr::null_mut(), core::ptr::from_ref(&MARKER).cast_mut().cast()] {
            REQUEST.store(request, Ordering::SeqCst);
            CONTEXT.store(context as usize, Ordering::SeqCst);
            LAST_HEARTBEAT.store(0, Ordering::SeqCst);
            CALLS.store(0, Ordering::SeqCst);
            FORCED.store(0, Ordering::SeqCst);
            ALLOCATED.store(true, Ordering::SeqCst);
            FREED.store(true, Ordering::SeqCst);
            // SAFETY: the static function and marker outlive every selected
            // synchronous callback; registration is cleared before assertions.
            unsafe { crabc_mimalloc::source_options_api::register_deferred_free(Some(deferred), context) };
            api::collect(false);
            api::collect(true);
            api::collect(false);
            // SAFETY: all callback invocations returned on this thread.
            unsafe { crabc_mimalloc::source_options_api::register_deferred_free(None, core::ptr::null_mut()) };
            assert!(ALLOCATED.load(Ordering::SeqCst), "public callback request {request} was refused");
            assert!(FREED.load(Ordering::SeqCst), "public callback request {request} could not be freed");
            assert!(SUPPRESSED.load(Ordering::SeqCst), "nested allocation recursively invoked the callback");
            assert!(CONTEXT_MATCHES.load(Ordering::SeqCst), "callback registration context changed");
            assert_eq!(CALLS.load(Ordering::SeqCst), 3);
            assert_eq!(FORCED.load(Ordering::SeqCst), 1);
            assert!(DEFAULT_PRESERVED.load(Ordering::SeqCst));
            assert!(HEARTBEAT_ORDERED.load(Ordering::SeqCst));
        }
    }
    assert!(crabc_mimalloc::__crabc_runtime::prepare_native_later_thread_arena());
    for request in [33, 524_289] {
        for context in [core::ptr::null_mut(), core::ptr::from_ref(&MARKER).cast_mut().cast()] {
            let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
            let (continue_tx, continue_rx) = std::sync::mpsc::sync_channel(0);
            let worker = std::thread::spawn(move || {
                assert_eq!(native_runtime_test_support::attach_current_thread(),
                    crabc_mimalloc::__crabc_runtime::ThreadAttachResult::Attached);
                let warm = api::malloc(33).value.expect("worker warm allocation");
                // SAFETY: this worker owns its complete warm client.
                assert_eq!(unsafe { api::free(warm.as_ptr()) }, api::FreeOutcome::Freed);
                ready_tx.send(()).unwrap();
                continue_rx.recv().unwrap();
                api::collect(false);
                // This hosted worker owns no allocator pthread key. Enter
                // the retained-owner exit boundary after its user work, with
                // every callback context still live through the join.
                assert_eq!(crabc_mimalloc::__crabc_runtime::finish_current_thread_native_after_user_destructors(),
                    crabc_mimalloc::__crabc_runtime::ThreadFinishResult::Finished);
            });
            ready_rx.recv().unwrap();
            REQUEST.store(request, Ordering::SeqCst);
            CONTEXT.store(context as usize, Ordering::SeqCst);
            LAST_HEARTBEAT.store(0, Ordering::SeqCst);
            CALLS.store(0, Ordering::SeqCst);
            FORCED.store(0, Ordering::SeqCst);
            ALLOCATED.store(true, Ordering::SeqCst);
            FREED.store(true, Ordering::SeqCst);
            // SAFETY: this static pair stays valid until the only worker has
            // returned from both synchronous collection and exit callbacks.
            unsafe { crabc_mimalloc::source_options_api::register_deferred_free(Some(deferred), context) };
            continue_tx.send(()).unwrap();
            worker.join().unwrap();
            // SAFETY: joining excludes every callback before replacement.
            unsafe { crabc_mimalloc::source_options_api::register_deferred_free(None, core::ptr::null_mut()) };
            assert!(ALLOCATED.load(Ordering::SeqCst), "worker callback request {request} was refused");
            assert!(FREED.load(Ordering::SeqCst));
            assert!(SUPPRESSED.load(Ordering::SeqCst));
            assert!(CONTEXT_MATCHES.load(Ordering::SeqCst));
            assert_eq!(CALLS.load(Ordering::SeqCst), 2);
            assert_eq!(FORCED.load(Ordering::SeqCst), 1);
            assert!(DEFAULT_PRESERVED.load(Ordering::SeqCst));
            assert!(HEARTBEAT_ORDERED.load(Ordering::SeqCst));
            api::collect(false);
            api::collect(true);
            assert_eq!(CALLS.load(Ordering::SeqCst), 2, "clearing registration suppresses later callbacks");
        }
    }
}
