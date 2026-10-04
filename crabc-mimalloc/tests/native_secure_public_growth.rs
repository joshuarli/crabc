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
    // Exercise the installed fixed owner directly. The source API wrappers
    // below perform their own sampling and cannot prove native ingress.
    {
        use crabc_mimalloc::__crabc_runtime as native;
        let mut clients = std::vec::Vec::new();
        for (size, alignment) in [(64usize, None), (8, Some(16usize)), (64, Some(16))] {
            for zero in [false, true] {
                let result = match alignment {
                    None => native::native_allocate(size, zero),
                    Some(alignment) => native::native_allocate_aligned(size, alignment, zero),
                };
                let native::NativePageAllocationResult::Allocated(client) = result else {
                    panic!("the installed owner returns its explicitly sampled native client");
                };
                if let Some(alignment) = alignment {
                    assert_eq!(client.as_ptr().addr() % alignment, 0);
                }
                // SAFETY: the exact successful native client stays exclusively
                // live through its capacity query and subsequent matching free.
                let usable = unsafe { native::native_usable_size(client) }.unwrap();
                assert!(usable >= size);
                let tail = client.as_ptr().addr().checked_add(usable).unwrap();
                assert_eq!(tail % page_size, 0);
                assert!(permissions(tail).unwrap().starts_with("---"),
                    "native allocation honors the installed owner's sampler");
                let pattern = clients.len() as u8 + 0x40;
                // SAFETY: only the reported writable extent is accessed. The
                // following protected mapping is queried but never dereferenced.
                unsafe {
                    let bytes = core::slice::from_raw_parts_mut(client.as_ptr(), usable);
                    if zero { assert!(bytes[..size].iter().all(|byte| *byte == 0)); }
                    bytes.fill(pattern);
                }
                clients.push((client, usable, pattern, size == 8 && !zero));
            }
        }
        for (client, usable, pattern, grow) in clients {
            // SAFETY: siblings remain live until their own exact free. Growth
            // retains this old client until the successful result consumes it.
            unsafe {
                assert!(core::slice::from_raw_parts(client.as_ptr(), usable)
                    .iter().all(|byte| *byte == pattern));
                let final_client = if grow {
                    let growth_size = usable.checked_add(64).unwrap();
                    let native::NativePageAllocationResult::Allocated(replacement) =
                        native::native_reallocate_aligned_zeroed(Some(client), growth_size, 16)
                    else { panic!("the installed owner replaces its sampled tiny client"); };
                    assert_ne!(replacement, client);
                    assert_eq!(replacement.as_ptr().addr() % 16, 0);
                    let capacity = native::native_usable_size(replacement).unwrap();
                    assert!(capacity >= growth_size);
                    let bytes = core::slice::from_raw_parts(replacement.as_ptr(), capacity);
                    assert!(bytes[..usable].iter().all(|byte| *byte == pattern));
                    assert!(bytes[usable..growth_size].iter().all(|byte| *byte == 0));
                    let tail = replacement.as_ptr().addr().checked_add(capacity).unwrap();
                    assert!(permissions(tail).unwrap().starts_with("---"));
                    replacement
                } else { client };
                assert_eq!(native::native_free(final_client), native::NativePageFreeResult::Freed);
            }
        }
        // Seed one unsampled call before each selected call. Ordinary aligned
        // base allocation must not consume a second countdown step.
        // SAFETY: this thread exclusively owns the initialized sampler and
        // no allocation overlaps this deterministic countdown reset.
        unsafe { heaps::theap_guarded_set_sample_rate(selected, 2, 1); }
        let mut alternating = std::vec::Vec::new();
        for sampled in [false, true, false, true] {
            let native::NativePageAllocationResult::Allocated(client) =
                native::native_allocate_aligned(8, 16, false)
            else { panic!("the native sampler returns each live alternating client"); };
            assert_eq!(client.as_ptr().addr() % 16, 0);
            // SAFETY: this successful exact client stays live until its free;
            // querying its tail mapping does not access any protected bytes.
            let usable = unsafe { native::native_usable_size(client) }.unwrap();
            assert!(usable >= 8);
            let tail = client.as_ptr().addr().checked_add(usable).unwrap();
            assert_eq!(permissions(tail).unwrap().starts_with("---"), sampled,
                "one original request consumes one source sampler step");
            alternating.push(client);
        }
        for client in alternating {
            // SAFETY: consume each retained exact client once, without any
            // access to its adjacent protected or unallocated memory.
            assert_eq!(unsafe { native::native_free(client) }, native::NativePageFreeResult::Freed);
        }
        // SAFETY: no native client remains in this segment, and this thread
        // exclusively owns the initialized sampler through its restoration.
        unsafe { heaps::theap_guarded_set_sample_rate(selected, 1, 0); }
    }
    // Both the tiny overallocated shape and a naturally aligned small shape
    // must still obey this explicit sample selection before taking a local
    // head. Keep their exact clients live together to check independent tails.
    let mut sampled_clients = std::vec::Vec::new();
    for (size, alignment) in [(8usize, 16usize), (64, 16)] {
        for zero in [false, true] {
            let client = if zero {
                api::zalloc_aligned_at(size, alignment, 0)
            } else {
                api::malloc_aligned_at(size, alignment, 0)
            }.value.unwrap();
            assert_eq!(client.as_ptr().addr() % alignment, 0);
            // SAFETY: only this exact live client's reported writable extent
            // is read or written. Its following mapping is inspected via proc.
            let usable = unsafe { api::usable_size(client.as_ptr()) };
            assert!(usable >= size);
            let tail = client.as_ptr().addr().checked_add(usable).unwrap();
            assert_eq!(tail % page_size, 0);
            assert!(permissions(tail).unwrap().starts_with("---"),
                "the explicitly sampled {size}/{alignment} client reports its guarded tail");
            let pattern = sampled_clients.len() as u8 + 1;
            // SAFETY: this owned live payload contains exactly `usable`
            // writable bytes; its tail is observed but never dereferenced.
            unsafe {
                let bytes = core::slice::from_raw_parts_mut(client.as_ptr(), usable);
                if zero { assert!(bytes.iter().all(|byte| *byte == 0)); }
                bytes.fill(pattern);
            }
            sampled_clients.push((client, usable, pattern));
        }
    }
    for (client, usable, pattern) in sampled_clients {
        // SAFETY: each sibling remains live until its own exact free. Neither
        // payload observation extends into the protected following mapping.
        unsafe {
            assert!(core::slice::from_raw_parts(client.as_ptr(), usable)
                .iter().all(|byte| *byte == pattern));
            assert_eq!(api::free(client.as_ptr()), api::FreeOutcome::Freed);
        }
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
