#![cfg(all(target_arch = "x86_64", any(feature = "mi-secure-3", feature = "mi-guarded")))]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use crabc_mimalloc::{source_api as api, source_heap_api as heaps};

#[cfg(feature = "mi-secure-3")]
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
#[cfg(feature = "mi-secure-3")]
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
    #[cfg(feature = "mi-guarded")]
    guarded_public_aligned_growth();
}

#[cfg(feature = "mi-guarded")]
fn permissions(address: usize) -> Option<String> {
    std::fs::read_to_string("/proc/self/maps").unwrap().lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let (start, end) = fields.next()?.split_once('-')?;
        let start = usize::from_str_radix(start, 16).ok()?;
        let end = usize::from_str_radix(end, 16).ok()?;
        (start <= address && address < end).then(|| fields.next().unwrap().to_owned())
    })
}

#[cfg(feature = "mi-guarded")]
fn guarded_public_aligned_growth() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    let selected = heaps::theap_get_default();
    assert!(!selected.is_null());
    // SAFETY: this thread exclusively owns its retained initialized Theap
    // and does not allocate between the two sampler setters.
    unsafe {
        heaps::theap_guarded_set_size_bound(selected, 0, usize::MAX);
        heaps::theap_guarded_set_sample_rate(selected, 1, 0);
    }
    let old = api::malloc_aligned_at(81, 64, 0).value.unwrap();
    let keeper = api::malloc_aligned_at(81, 64, 0).value.unwrap();
    // SAFETY: these successful public clients remain exclusively owned.
    let usable = unsafe { api::usable_size(old.as_ptr()) };
    assert!(usable >= 81);
    assert_eq!(old.as_ptr().addr() % 64, 0);
    let tail = old.as_ptr().addr().checked_add(usable).unwrap();
    assert!(permissions(tail).unwrap().starts_with("---"), "the actual public client ends at its protected guard");
    assert_eq!(tail % page_size, 0);
    // SAFETY: the full reported usable client is writable and owned. Failed
    // realloc leaves it live; success consumes it, retaining only replacement.
    unsafe {
        old.as_ptr().write_bytes(0x63, usable);
        assert!(api::realloc_aligned_at(old.as_ptr(), usize::MAX, 64, 0).value.is_none());
        assert!(permissions(tail).unwrap().starts_with("---"));
        let growth_size = usable.checked_add(1024).unwrap();
        let replacement = api::rezalloc_aligned_at(old.as_ptr(), growth_size, 64, 0).value.unwrap();
        assert_ne!(replacement, old);
        let new_usable = api::usable_size(replacement.as_ptr());
        assert!(new_usable >= growth_size);
        let bytes = core::slice::from_raw_parts(replacement.as_ptr(), new_usable);
        assert!(bytes[..usable].iter().all(|byte| *byte == 0x63));
        assert!(bytes[usable..].iter().all(|byte| *byte == 0));
        let new_tail = replacement.as_ptr().addr().checked_add(new_usable).unwrap();
        assert!(permissions(new_tail).unwrap().starts_with("---"));
        assert!(permissions(tail).unwrap().starts_with("rw"), "consumed old client has no protected guard");
        assert_eq!(api::free(replacement.as_ptr()), api::FreeOutcome::Freed);
        assert_eq!(api::free(keeper.as_ptr()), api::FreeOutcome::Freed);
        let plain = api::malloc(81).value.unwrap();
        let plain_keeper = api::malloc(81).value.unwrap();
        let plain_usable = api::usable_size(plain.as_ptr());
        assert!(plain_usable >= 81);
        let plain_tail = plain.as_ptr().addr().checked_add(plain_usable).unwrap();
        assert!(permissions(plain_tail).unwrap().starts_with("---"));
        plain.as_ptr().write_bytes(0x37, plain_usable);
        assert!(api::realloc(plain.as_ptr(), usize::MAX).value.is_none());
        assert!(permissions(plain_tail).unwrap().starts_with("---"));
        let plain_growth_size = plain_usable.checked_add(1024).unwrap();
        let plain_replacement = api::rezalloc(plain.as_ptr(), plain_growth_size).value.unwrap();
        assert_ne!(plain_replacement, plain);
        let plain_new_usable = api::usable_size(plain_replacement.as_ptr());
        assert!(plain_new_usable >= plain_growth_size);
        let plain_bytes = core::slice::from_raw_parts(plain_replacement.as_ptr(), plain_new_usable);
        assert!(plain_bytes[..plain_usable].iter().all(|byte| *byte == 0x37));
        assert!(plain_bytes[plain_usable..].iter().all(|byte| *byte == 0));
        let plain_new_tail = plain_replacement.as_ptr().addr().checked_add(plain_new_usable).unwrap();
        assert!(permissions(plain_new_tail).unwrap().starts_with("---"));
        assert!(permissions(plain_tail).unwrap().starts_with("rw"));
        assert_eq!(api::free(plain_replacement.as_ptr()), api::FreeOutcome::Freed);
        assert_eq!(api::free(plain_keeper.as_ptr()), api::FreeOutcome::Freed);
        heaps::theap_guarded_set_sample_rate(selected, 0, 0);
    }
}

#[cfg(all(feature = "mi-guarded", not(feature = "mi-secure-3")))]
#[test]
fn public_guarded_aligned_sampling_protects_reported_tail_and_consumes_on_growth() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    assert!(crabc_mimalloc::__crabc_runtime::prepare_native_initial_thread_owner());
    guarded_public_aligned_growth();
}
