#![cfg(all(target_arch = "x86_64", feature = "native-runtime-test-audit", not(miri)))]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use core::ffi::c_void;
use core::ptr::NonNull;
use crabc_mimalloc::__crabc_runtime::{
    source_api as api, source_heap_api as heaps,
    current_native_allocator_thread_descriptor, register_current_native_allocator_worker_descriptor,
    finish_current_thread_native_after_user_destructors, prepare_native_later_thread_arena,
    ThreadFinishResult,
};

#[derive(Clone, Copy)]
struct SharedChild(NonNull<c_void>);

// SAFETY: this opaque identity is shared only for fresh-thread admission while
// the coordinator retains the child. No operation uses it after destruction.
unsafe impl Send for SharedChild {}

impl SharedChild {
    fn pointer(self) -> *mut c_void { self.0.as_ptr() }
}

fn register_fresh_worker() {
    // SAFETY: the current worker retains its compiler-TLS descriptor through
    // explicit allocator finish and its subsequent ordinary thread return.
    assert!(unsafe {
        register_current_native_allocator_worker_descriptor(current_native_allocator_thread_descriptor())
    });
}

#[test]
fn parked_member_finishes_after_child_destruction_without_reentering_child_storage() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    assert!(prepare_native_later_thread_arena());
    let child = SharedChild(NonNull::new(heaps::subproc_new()).expect("a live child"));
    let (ready_send, ready_receive) = std::sync::mpsc::channel();
    let (resume_send, resume_receive) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        register_fresh_worker();
        // SAFETY: this fresh worker has no allocator attachment; the
        // coordinator keeps the child alive until the worker parks.
        assert_eq!(unsafe { heaps::subproc_add_current_thread(child.pointer()) },
                   heaps::SubprocAddCurrentThread::Added);
        assert_eq!(heaps::subproc_current(), child.pointer());
        let client = api::malloc(200).value.expect("a live child client");
        let heap = heaps::heap_new();
        assert!(!heap.is_null());
        // SAFETY: this worker retains its own live Heap through allocation.
        let heap_client = unsafe { heaps::heap_malloc(heap, 64) }.value.expect("an auxiliary client");
        // SAFETY: each client belongs exclusively to this worker and retains
        // its requested writable extent until the coordinator is notified.
        unsafe {
            client.as_ptr().write_bytes(0x55, 200);
            heap_client.as_ptr().write_bytes(0x66, 64);
        }
        ready_send.send(()).unwrap();
        resume_receive.recv().unwrap();
        // The coordinator has destroyed the child. No local handle or client
        // is read again; finish must withdraw the worker's retained TLS roots.
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    });
    ready_receive.recv().unwrap();
    // SAFETY: the admitted member is parked outside allocator operations and
    // never uses any child allocation again. Its later finish uses only the
    // retained thread-lifecycle capability, without a public child-ID call.
    assert!(unsafe { heaps::subproc_destroy(child.pointer()) });
    resume_send.send(()).unwrap();
    worker.join().expect("the parked member finishes after destruction");
    joined_member_withdraws_before_parked_member_finishes_after_destruction();
}

fn joined_member_withdraws_before_parked_member_finishes_after_destruction() {
    let child = SharedChild(NonNull::new(heaps::subproc_new()).expect("a second live child"));
    let (parked_send, parked_receive) = std::sync::mpsc::channel();
    let (destroyed_send, destroyed_receive) = std::sync::mpsc::channel();
    let parked = std::thread::spawn(move || {
        register_fresh_worker();
        // SAFETY: the coordinator retains this child while both workers
        // admit themselves and while this worker creates its own clients.
        assert_eq!(unsafe { heaps::subproc_add_current_thread(child.pointer()) },
                   heaps::SubprocAddCurrentThread::Added);
        assert_eq!(heaps::subproc_current(), child.pointer());
        let client = api::malloc(200).value.expect("a parked main-Heap client");
        let heap = heaps::heap_new();
        assert!(!heap.is_null());
        // SAFETY: this worker owns its live auxiliary Heap and each client's
        // writable extent until it parks; neither is used after that point.
        unsafe {
            let heap_client = heaps::heap_malloc(heap, 64).value.expect("a parked auxiliary client");
            client.as_ptr().write_bytes(0x73, 200);
            heap_client.as_ptr().write_bytes(0x74, 64);
        }
        parked_send.send(()).unwrap();
        destroyed_receive.recv().unwrap();
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
        // This source identity query reads the current TLS membership only;
        // it performs no operation on the now-invalid child identity.
        assert_eq!(heaps::subproc_current(), heaps::subproc_main());
    });
    parked_receive.recv().unwrap();
    let joined = std::thread::spawn(move || {
        register_fresh_worker();
        // SAFETY: the coordinator keeps the child live until this worker
        // finishes and joins; the other admitted worker remains parked.
        assert_eq!(unsafe { heaps::subproc_add_current_thread(child.pointer()) },
                   heaps::SubprocAddCurrentThread::Added);
        assert_eq!(heaps::subproc_current(), child.pointer());
        let client = api::malloc(200).value.expect("a joined main-Heap client");
        let heap = heaps::heap_new();
        assert!(!heap.is_null());
        // SAFETY: this worker owns both clients and the auxiliary Heap. It
        // returns every client and deletes that Heap before finishing.
        unsafe {
            let heap_client = heaps::heap_malloc(heap, 64).value.expect("a joined auxiliary client");
            client.as_ptr().write_bytes(0x81, 200);
            heap_client.as_ptr().write_bytes(0x82, 64);
            assert_eq!(api::free(heap_client.as_ptr()), api::FreeOutcome::Freed);
            assert_eq!(api::free(client.as_ptr()), api::FreeOutcome::Freed);
            assert!(heaps::heap_release(heap, false));
        }
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
        assert_eq!(heaps::subproc_current(), heaps::subproc_main());
    });
    joined.join().expect("the first member's real TLS lifetime ended");
    // SAFETY: the joined worker has withdrawn its clients and TLS roots and
    // cannot be revisited. The other worker is parked outside allocator
    // operations and makes no later call except its own thread finish.
    assert!(unsafe { heaps::subproc_destroy(child.pointer()) });
    destroyed_send.send(()).unwrap();
    parked.join().expect("the remaining member finishes after child destruction");
}
