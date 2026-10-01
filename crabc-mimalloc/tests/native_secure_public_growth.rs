#![cfg(all(target_arch = "x86_64", feature = "mi-secure-3"))]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use crabc_mimalloc::{source_api as api, source_heap_api as heaps};

fn repeated_birth_and_growth() {
    let base = heaps::theap_get_default();
    assert!(!base.is_null());
    for cycle in 0..8 {
        println!("secure.heap.birth.cycle={cycle}");
        let heap = heaps::heap_new();
        assert!(!heap.is_null(), "secure Heap birth {cycle}");
        // SAFETY: this sole thread retains the Heap and its Theap through
        // every public operation; each successful realloc consumes the prior
        // exact client, and only the final client is freed before Heap deletion.
        unsafe {
            let selected = heaps::heap_theap(heap);
            assert!(!selected.is_null());
            assert_ne!(selected, base);
            let old = heaps::theap_malloc(selected, 73, false).value.unwrap();
            let usable = api::usable_size(old.as_ptr());
            assert!(usable >= 73);
            old.as_ptr().write_bytes(0xa7, usable);
            let grown = api::theap_realloc(selected, old.as_ptr(), 1024, true).value.unwrap();
            assert_ne!(grown, old);
            let grown_usable = api::usable_size(grown.as_ptr());
            assert!(grown_usable >= 1024);
            let bytes = core::slice::from_raw_parts(grown.as_ptr(), grown_usable);
            assert!(bytes[..usable].iter().all(|byte| *byte == 0xa7));
            assert!(bytes[usable..].iter().all(|byte| *byte == 0));
            assert_eq!(heaps::heap_of(grown.as_ptr()), heap);
            assert_eq!(api::free(grown.as_ptr()), api::FreeOutcome::Freed);
            assert!(heaps::heap_release(heap, false));
        }
        assert_eq!(heaps::theap_get_default(), base);
    }
}

#[test]
fn repeated_secure_heap_birth_and_growth_survive_joined_worker_and_fork() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    assert!(crabc_mimalloc::__crabc_runtime::prepare_native_initial_thread_owner());
    println!("secure.context=main");
    repeated_birth_and_growth();
    std::thread::spawn(|| {
        assert_eq!(native_runtime_test_support::attach_current_thread(),
            crabc_mimalloc::__crabc_runtime::ThreadAttachResult::Attached);
        println!("secure.context=worker");
        repeated_birth_and_growth();
        assert_eq!(crabc_mimalloc::__crabc_runtime::finish_current_thread_native_after_user_destructors(),
            crabc_mimalloc::__crabc_runtime::ThreadFinishResult::Finished);
    }).join().unwrap();
    println!("secure.context=joined-worker-parent");
    repeated_birth_and_growth();

    unsafe extern "C" { fn fork() -> core::ffi::c_int; }
    // SAFETY: the sole allocator worker has joined. This standalone hosted
    // test has no allocator atfork registration, matching ordinary adapter fork.
    let pid = unsafe { fork() };
    assert!(pid >= 0);
    if pid == 0 {
        println!("secure.context=fork-child");
        repeated_birth_and_growth();
        crabc_core::process::exit_immediately(0);
    }
    let mut status = 0;
    let mut joined = false;
    for _ in 0..500 {
        // SAFETY: the parent owns the exact child and exclusive status slot.
        let waited = unsafe { crabc_core::process::wait4_raw(pid, &mut status, 1) }.unwrap();
        if waited == pid { joined = true; break; }
        assert_eq!(waited, 0);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if !joined {
        let _ = crabc_core::process::kill(pid, 9);
        // SAFETY: reap the same timed-out child before reporting failure.
        let _ = unsafe { crabc_core::process::wait4_raw(pid, &mut status, 0) };
    }
    assert!(joined, "the fork child completes repeated secure Heap growth");
    assert_eq!(status, 0, "the secure growth child exits successfully");
    println!("secure.context=fork-parent");
    repeated_birth_and_growth();
}
