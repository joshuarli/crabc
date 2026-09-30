#![cfg(target_arch = "x86_64")]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use core::ffi::c_void;
use core::ptr::null_mut;
use crabc_mimalloc::__crabc_runtime::{
    ThreadAttachResult, ThreadFinishResult, current_native_allocator_thread_descriptor,
    finish_current_thread_native_after_user_destructors,
    register_current_native_allocator_worker_descriptor,
    source_api as api, source_heap_api as heaps,
};

struct Visit {
    heaps: Vec<usize>,
    stop_after: Option<usize>,
}

unsafe extern "C" fn visit_heap(heap: *mut c_void, argument: *mut c_void) -> bool {
    // SAFETY: the synchronous caller supplies its exclusively borrowed Visit;
    // this callback records identities and never operates on the Heap list.
    let visit = unsafe { &mut *argument.cast::<Visit>() };
    visit.heaps.push(heap as usize);
    visit.stop_after.is_none_or(|limit| visit.heaps.len() < limit)
}

unsafe fn heap_list(child: *mut c_void, stop_after: Option<usize>) -> (bool, Vec<usize>) {
    let mut visit = Visit { heaps: Vec::new(), stop_after };
    // SAFETY: the caller keeps the child live and its list quiescent; the
    // callback's borrowed state stays alive for this synchronous traversal.
    let completed = unsafe {
        heaps::subproc_visit_heaps(child, visit_heap, (&mut visit as *mut Visit).cast())
    };
    (completed, visit.heaps)
}

fn register_fresh_thread() {
    // SAFETY: this thread owns the runtime descriptor in its allocator TLS,
    // which remains mapped through its explicit finish and thread return.
    assert!(unsafe {
        register_current_native_allocator_worker_descriptor(current_native_allocator_thread_descriptor())
    });
}

#[test]
fn production_subprocess_identity_membership_and_nested_lifetime() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    let main = heaps::subproc_main();
    let initial_heap = heaps::heap_main();
    assert!(!main.is_null() && !initial_heap.is_null());
    assert_eq!(heaps::subproc_current(), main);

    // SAFETY: null and process-main IDs are explicit no-ops; the initialized
    // test thread retains its own roots and has made no application allocation.
    unsafe {
        assert_eq!(heaps::subproc_add_current_thread(null_mut()), heaps::SubprocAddCurrentThread::Unchanged);
        assert_eq!(heaps::subproc_add_current_thread(main), heaps::SubprocAddCurrentThread::Unchanged);
        assert!(heaps::subproc_destroy(null_mut()));
        assert!(heaps::subproc_destroy(main));
        assert!(!heap_list(null_mut(), None).0);
    }
    let outer = heaps::subproc_new();
    assert!(!outer.is_null() && outer != main);
    let outer_address = outer as usize;
    let main_address = main as usize;

    // An initialized main member cannot switch to this child. It has made
    // no application allocation, so this exercises admission without asking
    // an already-bound thread to move any live allocation or owner roots.
    std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        // SAFETY: the coordinator retains the live child until this thread
        // joins; the caller owns its freshly initialized main-thread roots.
        assert_eq!(unsafe { heaps::subproc_add_current_thread(outer_address as *mut c_void) },
                   heaps::SubprocAddCurrentThread::Unchanged);
        assert_eq!(heaps::subproc_current() as usize, main_address);
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    }).join().unwrap();

    let (inner_address, outer_heap_address, outer_block_address) = std::thread::spawn(move || {
        register_fresh_thread();
        let outer = outer_address as *mut c_void;
        // SAFETY: this registered worker has no allocator attachment or
        // application allocation; its child and roots stay live through finish.
        unsafe {
            assert_eq!(heaps::subproc_add_current_thread(outer), heaps::SubprocAddCurrentThread::Added);
            assert_eq!(heaps::subproc_add_current_thread(outer), heaps::SubprocAddCurrentThread::Unchanged);
            assert_eq!(heaps::subproc_add_current_thread(main_address as *mut c_void),
                       heaps::SubprocAddCurrentThread::Unchanged);
        }
        assert_eq!(heaps::subproc_current(), outer);
        let outer_heap = heaps::heap_main();
        let first = heaps::heap_new();
        let second = heaps::heap_new();
        assert!(!outer_heap.is_null() && !first.is_null() && !second.is_null());
        assert!(first != second && first != outer_heap && second != outer_heap);
        // SAFETY: all Heap handles belong to this sole child member. The
        // live blocks remain exclusive through delete, ownership query and free.
        unsafe {
            assert_eq!(heap_list(outer, None), (true, vec![second as usize, first as usize, outer_heap as usize]));
            assert_eq!(heap_list(outer, Some(1)), (false, vec![second as usize]));
            let moved = heaps::heap_malloc(first, 48).value.unwrap();
            moved.as_ptr().write_bytes(0x37, 48);
            assert_eq!(heaps::heap_of(moved.as_ptr()), first);
            assert!(heaps::heap_release(first, false));
            assert_eq!(heaps::heap_of(moved.as_ptr()), outer_heap);
            assert!(core::slice::from_raw_parts(moved.as_ptr(), 48).iter().all(|byte| *byte == 0x37));
            api::free(moved.as_ptr());
            assert!(heaps::heap_release(second, true));
            assert_eq!(heap_list(outer, None), (true, vec![outer_heap as usize]));
        }
        let block = api::malloc(80).value.unwrap();
        let inner = heaps::subproc_new();
        assert!(!inner.is_null() && inner != outer);
        // SAFETY: the exact live client and nested child metadata stay owned
        // until the coordinator frees/destroys them after both workers join.
        unsafe {
            block.as_ptr().write_bytes(0x5a, 80);
            assert_eq!(heaps::heap_of(block.as_ptr()), outer_heap);
            assert_eq!(heaps::heap_of(inner.cast::<u8>()), outer_heap);
            assert_eq!(heap_list(outer, None), (true, vec![outer_heap as usize]));
        }
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
        (inner as usize, outer_heap as usize, block.as_ptr() as usize)
    }).join().unwrap();

    let (inner_heap_address, inner_block_address) = std::thread::spawn(move || {
        register_fresh_thread();
        let inner = inner_address as *mut c_void;
        // SAFETY: this fresh registered worker has made no allocator entry;
        // the nested child is retained by the coordinator until after join.
        assert_eq!(unsafe { heaps::subproc_add_current_thread(inner) }, heaps::SubprocAddCurrentThread::Added);
        assert_eq!(heaps::subproc_current(), inner);
        let inner_heap = heaps::heap_main();
        assert!(!inner_heap.is_null() && inner_heap as usize != outer_heap_address);
        let block = api::malloc(128).value.unwrap();
        // SAFETY: the child, main Heap metadata and exact live client remain
        // live across owner exit; no visitor modifies their list.
        unsafe {
            block.as_ptr().write_bytes(0x6b, 128);
            assert_eq!(heaps::heap_of(block.as_ptr()), inner_heap);
            assert_eq!(heaps::heap_of(inner_heap.cast::<u8>()), outer_heap_address as *mut c_void);
            assert_eq!(heap_list(inner, None), (true, vec![inner_heap as usize]));
        }
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
        (inner_heap as usize, block.as_ptr() as usize)
    }).join().unwrap();

    // SAFETY: both child members have finished and joined. Their surviving
    // clients retain the source Heap identities and initialized extents. The
    // nested child is freed/destroyed before its parent, and no released ID,
    // Heap or block is used after its consuming boundary.
    unsafe {
        let outer_block = outer_block_address as *mut u8;
        let inner_block = inner_block_address as *mut u8;
        assert_eq!(heaps::heap_of(outer_block), outer_heap_address as *mut c_void);
        assert_eq!(heaps::heap_of(inner_block), inner_heap_address as *mut c_void);
        assert!(core::slice::from_raw_parts(outer_block, 80).iter().all(|byte| *byte == 0x5a));
        assert!(core::slice::from_raw_parts(inner_block, 128).iter().all(|byte| *byte == 0x6b));
        api::free(inner_block);
        assert!(heaps::subproc_destroy(inner_address as *mut c_void));
        api::free(outer_block);
        assert!(heaps::subproc_destroy(outer));
        assert_eq!(heaps::subproc_current(), main);
        assert_eq!(heaps::heap_main(), initial_heap);
    }
}
