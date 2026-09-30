#![cfg(target_arch = "x86_64")]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use core::ffi::c_void;
use crabc_mimalloc::{__crabc_runtime as runtime, source_api, source_heap_api as heaps};

fn register_worker() {
    let descriptor = runtime::current_native_allocator_thread_descriptor();
    // SAFETY: the worker owns this TLS descriptor through its explicit finish.
    assert!(unsafe { runtime::register_current_native_allocator_worker_descriptor(descriptor) });
}

unsafe fn delete_preserving_auxiliary_default(heap: *mut c_void) {
    let auxiliary = heaps::heap_new();
    assert!(!auxiliary.is_null());
    // SAFETY: this caller owns the auxiliary Heap and both Theaps through
    // restoration; only the separate joined worker's Heap is deleted here.
    unsafe {
        let selected = heaps::heap_theap(auxiliary);
        assert!(!selected.is_null());
        let original = heaps::theap_set_default(selected);
        assert_ne!(original, selected);
        assert!(heaps::heap_release(heap, false));
        assert_eq!(heaps::theap_get_default(), selected);
        assert_eq!(heaps::theap_set_default(original), selected);
        assert!(heaps::heap_release(auxiliary, true));
    }
}

#[test]
fn joined_child_heap_delete_preserves_clients_and_caller_membership() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    assert!(runtime::prepare_native_later_thread_arena());
    for foreign_child_caller in [false, true] {
        let root = heaps::heap_main() as usize;
        let child = heaps::subproc_new() as usize;
        assert_ne!(child, 0);
        let (main, auxiliary, main_block, auxiliary_block) = std::thread::spawn(move || {
            register_worker();
            // SAFETY: this fresh registered worker has not allocated; the caller
            // retains the child until the worker has joined and its clients die.
            unsafe {
                assert_eq!(heaps::subproc_add_current_thread(child as *mut c_void),
                           heaps::SubprocAddCurrentThread::Added);
                let main = heaps::heap_main();
                let auxiliary = heaps::heap_new();
                assert!(!auxiliary.is_null());
                let main_block = heaps::heap_malloc(main, 333).value.unwrap();
                let auxiliary_block = heaps::heap_malloc(auxiliary, 777).value.unwrap();
                main_block.as_ptr().write_bytes(0x39, 333);
                auxiliary_block.as_ptr().write_bytes(0x73, 777);
                assert_eq!(runtime::finish_current_thread_native_after_user_destructors(),
                           runtime::ThreadFinishResult::Finished);
                (main as usize, auxiliary as usize, main_block.as_ptr() as usize,
                 auxiliary_block.as_ptr() as usize)
            }
        }).join().unwrap();
        assert_ne!(main, root);
        assert_eq!(heaps::subproc_current(), heaps::subproc_main());
        let caller_default = heaps::theap_get_default();
        // SAFETY: the worker joined. Both clients and their child remain live;
        // no owner uses the auxiliary Heap concurrently with its deletion.
        unsafe {
            assert_eq!(heaps::heap_of(auxiliary_block as *const u8) as usize, auxiliary);
            if foreign_child_caller {
                let caller_child = heaps::subproc_new() as usize;
                assert_ne!(caller_child, 0);
                std::thread::spawn(move || {
                    register_worker();
                    // SAFETY: the fresh caller joins its own live child, while
                    // the joined owner's Heap and clients remain separately live.
                    unsafe {
                        assert_eq!(heaps::subproc_add_current_thread(caller_child as *mut c_void),
                                   heaps::SubprocAddCurrentThread::Added);
                        let caller_default = heaps::theap_get_default();
                        delete_preserving_auxiliary_default(auxiliary as *mut c_void);
                        assert_eq!(heaps::subproc_current() as usize, caller_child);
                        assert_eq!(heaps::theap_get_default(), caller_default);
                        assert_eq!(heaps::heap_of(auxiliary_block as *const u8) as usize, main);
                        assert_eq!(runtime::finish_current_thread_native_after_user_destructors(),
                                   runtime::ThreadFinishResult::Finished);
                    }
                }).join().unwrap();
                assert!(heaps::subproc_destroy(caller_child as *mut c_void));
            } else {
                delete_preserving_auxiliary_default(auxiliary as *mut c_void);
            }
            // The released Heap handle is never used again. Only retained
            // clients and the live child main Heap participate in these queries.
            assert_eq!(heaps::heap_of(auxiliary_block as *const u8) as usize, main);
            assert!(heaps::heap_contains(main as *mut c_void, auxiliary_block as *const u8));
            assert!(!heaps::heap_contains(root as *mut c_void, auxiliary_block as *const u8));
            for index in 0..333 {
                assert_eq!((main_block as *const u8).add(index).read(), 0x39);
            }
            for index in 0..777 {
                assert_eq!((auxiliary_block as *const u8).add(index).read(), 0x73);
            }
            assert_eq!(heaps::subproc_current(), heaps::subproc_main());
            assert_eq!(heaps::theap_get_default(), caller_default);
            assert_eq!(source_api::free(main_block as *mut u8), source_api::FreeOutcome::Freed);
            assert_eq!(source_api::free(auxiliary_block as *mut u8), source_api::FreeOutcome::Freed);
            assert!(heaps::subproc_destroy(child as *mut c_void));
        }
    }
}
