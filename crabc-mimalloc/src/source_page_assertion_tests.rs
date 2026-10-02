use super::{FreeOutcome, free, malloc};
use crate::runtime_lifecycle as runtime;

fn start_source_runtime() {
    // Keep full pages local so an ordinary local free can reuse its exact
    // client before the page is retired by the final source collection.
    std::env::set_var("mimalloc_page_full_retain", "-1");
    unsafe extern "C" fn stderr(message: *const core::ffi::c_char) {
        unsafe extern "C" {
            fn fputs(message: *const core::ffi::c_char, stream: *mut core::ffi::c_void) -> core::ffi::c_int;
            #[link_name = "stderr"] static mut STREAM: *mut core::ffi::c_void;
        }
        // SAFETY: the source supplies a terminated fragment and this process
        // retains its stderr stream through synchronous diagnostic delivery.
        unsafe { let _ = fputs(message, STREAM); }
    }
    // SAFETY: the static stderr primitive retains no borrowed argument.
    let output = unsafe { crate::diagnostic_output::RuntimeStderrOutput::new(stderr) };
    assert!(runtime::test_initialize_process_from_host_environment(4096, output));
}

fn allocate(request: usize) -> core::ptr::NonNull<u8> {
    let result = malloc(request);
    result.value.unwrap_or_else(|| panic!("source malloc({request}) refused: {:?}", result.errno))
}

fn source_page_counts(client: core::ptr::NonNull<u8>) -> (usize, usize) {
    let selected = crate::compiler_tls::default_theap();
    // SAFETY: the exact live client retains its Page and owner in this sole
    // thread. The short PageMap/Page projections end before any allocation,
    // free or collection resumes. Only copied counts escape.
    unsafe { runtime::with_native_allocation_owner(selected, |owner| {
        let map = owner.page_map().unwrap().page_map().unwrap();
        let page = core::ptr::NonNull::new(map.checked_lookup(client.as_ptr())).unwrap();
        (usize::from(page.as_ref().reserved()), usize::from(page.as_ref().capacity()))
    }) }.unwrap()
}

fn fill_reuse_and_release_source_page(request: usize) {
    let first = allocate(request);
    let (reserved, initial_capacity) = source_page_counts(first);
    let mut clients = std::vec![first];
    while clients.len() < reserved {
        if clients.len() + 1 == reserved && request > crate::config::SMALL_MAX_OBJ_SIZE {
            let selected = crate::compiler_tls::default_theap();
            // SAFETY: only copied metadata escapes this short observation;
            // all clients remain exclusively held until allocation resumes.
            let final_slot = unsafe { runtime::with_native_allocation_owner(selected, |owner| {
                let map = owner.page_map().unwrap().page_map().unwrap();
                let page = core::ptr::NonNull::new(map.checked_lookup(first.as_ptr())).unwrap();
                let page = page.as_ref();
                let memory = page.memid();
                let os_size = memory.os_memory().map(|os| os.size);
                (page.capacity(), page.used(), page.slice_pcommitted(), page.page_offset(),
                    memory.kind(), memory.initially_committed(), os_size)
            }) }.unwrap();
            std::println!("source medium before final slot: {final_slot:?}");
        }
        let result = malloc(request);
        clients.push(result.value.unwrap_or_else(|| panic!(
            "source malloc({request}) refused client {} of {reserved}, initial capacity {initial_capacity}: {:?}",
            clients.len() + 1, result.errno)));
    }
    if reserved > 1 {
        let returned = clients.pop().unwrap();
        // SAFETY: this exact client is exclusively held and all
        // PageMap/owner observations ended before ordinary free.
        assert_eq!(unsafe { free(returned.as_ptr()) }, FreeOutcome::Freed);
        let reused = allocate(request);
        assert_eq!(reused, returned, "local source reuse for {request}");
        clients.push(reused);
    }
    for client in clients {
        // SAFETY: the source caller exclusively owns each client;
        // no ownership or metadata projection survives this call.
        assert_eq!(unsafe { free(client.as_ptr()) }, FreeOutcome::Freed);
    }
}

#[test]
fn source_malloc_after_small_page_full_reuse_history_allocates_first_medium() {
    crate::test_process::run_in_fresh_process(
        "source_api::source_page_assertion_tests::source_malloc_after_small_page_full_reuse_history_allocates_first_medium", || {
            start_source_runtime();
            let seed = allocate(32);
            // SAFETY: each exact client is freed once, with no observers live.
            assert_eq!(unsafe { free(seed.as_ptr()) }, FreeOutcome::Freed);
            super::collect(true);
            for bin in 1..crate::config::BIN_HUGE {
                let block_size = crate::size_class::bin_size(bin).unwrap();
                if block_size > crate::config::SMALL_MAX_OBJ_SIZE { break; }
                if crate::size_class::bin(block_size) != Some(bin)
                    || block_size <= crate::config::PADDING_SIZE { continue; }
                fill_reuse_and_release_source_page(block_size - crate::config::PADDING_SIZE);
            }
            fill_reuse_and_release_source_page(12_288 - crate::config::PADDING_SIZE);
            super::collect(true);
        },
    );
}

#[test]
fn source_malloc_fills_and_reuses_first_medium_page_without_prior_small_history() {
    crate::test_process::run_in_fresh_process(
        "source_api::source_page_assertion_tests::source_malloc_fills_and_reuses_first_medium_page_without_prior_small_history", || {
            start_source_runtime();
            fill_reuse_and_release_source_page(12_288 - crate::config::PADDING_SIZE);
            super::collect(true);
        },
    );
}

#[cfg(all(target_arch = "x86_64", feature = "mi-debug-3", not(miri)))]
#[test]
fn source_live_clients_validate_regular_huge_full_and_exact_heap_slots() {
    use core::ptr::NonNull;
    use crate::page_validity::{PageSourceOwnerSnapshot, source_page_is_valid};
    use crate::types::{Heap, Page, Theap};

    crate::test_process::run_in_fresh_process(
        "source_api::source_page_assertion_tests::source_live_clients_validate_regular_huge_full_and_exact_heap_slots", || {
            start_source_runtime();
            let seed = allocate(32);
            let heap_a = NonNull::new(crate::source_heap_api::heap_new().cast::<Heap>()).unwrap();
            let heap_b = NonNull::new(crate::source_heap_api::heap_new().cast::<Heap>()).unwrap();
            // SAFETY: both actual newly created Heaps remain live. An empty
            // regular slot must stay absent; peeking cannot initialize it.
            assert!(unsafe { Heap::source_theap_peek_at(heap_a) }.is_null());
            assert!(unsafe { Heap::source_theap_peek_at(heap_b) }.is_null());
            let mut clients = std::vec![seed];
            for heap in [heap_a, heap_b] {
                for request in [32, 12_288 - crate::config::PADDING_SIZE,
                    131_072 - crate::config::PADDING_SIZE,
                    crate::config::LARGE_MAX_OBJ_SIZE + crate::config::WORD_SIZE] {
                    // SAFETY: this calling thread retains the genuine Heap
                    // and every returned live client until its consuming free.
                    let block = unsafe { crate::source_heap_api::heap_malloc(heap.as_ptr().cast(), request) }
                        .value.unwrap_or_else(|| panic!("legal Heap client for {request}"));
                    clients.push(block);
                }
            }
            let cached = crate::compiler_tls::cached_theap();
            let fast = crate::compiler_tls::fast_slot_peek();
            let default = crate::compiler_tls::default_theap();
            let (binding, _) = crate::process_init::ProcessMainInitializationStorage::global()
                .ready_child_subprocess_inputs().unwrap();
            // SAFETY: this sole current thread retains all actual clients,
            // owner images and the active map, with no teardown or mutation
            // during these short copied-field and owner-queue projections.
            let map = unsafe { binding.page_map().page_map_for_owned_ranges() }.unwrap();
            let mut huge_full = false;
            let mut regular = false;
            for client in &clients {
                let page = unsafe { binding.page_map().lookup_registered_page(client.as_ptr()) }.unwrap().unwrap();
                let state = unsafe { Page::validity_snapshot_at(page) };
                let theap = NonNull::new(state.theap).unwrap();
                let bin = if state.in_full { crate::config::BIN_FULL }
                    else if state.is_huge { crate::config::BIN_HUGE }
                    else { crate::size_class::bin(state.block_size).unwrap() };
                let queue = unsafe { Theap::local_queue_at(theap, bin) }.unwrap();
                let mut next = queue.first();
                let mut contains = false;
                for _ in 0..queue.count() {
                    if next == page.as_ptr() { contains = true; break; }
                    let Some(node) = NonNull::new(next) else { break; };
                    next = unsafe { Page::queue_next_at(node) };
                }
                let owner = unsafe { PageSourceOwnerSnapshot::observe_at(&state, contains, Some(queue.block_size())) };
                assert!(owner.heap_theap_matches, "actual cache or versioned slot names the Page's original Theap");
                assert_eq!(unsafe { source_page_is_valid(&state, map, &owner, true) }, Ok(()));
                huge_full |= state.is_huge && state.in_full;
                regular |= !state.is_huge && !state.in_full;
            }
            assert!(regular && huge_full, "actual regular and full huge queues were observed");
            assert_eq!(crate::compiler_tls::cached_theap(), cached);
            assert_eq!(crate::compiler_tls::fast_slot_peek(), fast);
            assert_eq!(crate::compiler_tls::default_theap(), default);
            for client in clients {
                // SAFETY: every exact client is still exclusively live; all
                // metadata and queue projections ended before consuming free.
                assert_eq!(unsafe { free(client.as_ptr()) }, FreeOutcome::Freed);
            }
            for heap in [heap_a, heap_b] {
                // SAFETY: the test retains these actual Heaps, with no live
                // clients or concurrent users at their explicit destruction.
                assert!(unsafe { crate::source_heap_api::heap_release(heap.as_ptr().cast(), true) });
            }
            super::collect(true);
        },
    );
}

#[cfg(all(target_arch = "x86_64", feature = "mi-debug-3", not(miri)))]
#[test]
fn source_malloc_live_validity_assertion_reenters_after_original_owner_projections_end() {
    use core::{ffi::{c_char, c_void, CStr}, ptr::NonNull};
    use crate::types::{Heap, Page, PageValiditySnapshot, Theap};
    use std::os::unix::process::ExitStatusExt;

    const CHILD: &str = "CRABC_MI_SOURCE_LIVE_VALIDITY_CHILD";
    struct Context {
        page: NonNull<Page>,
        client: NonNull<u8>,
        theap: NonNull<Theap>,
        heap: NonNull<Heap>,
        request: usize,
        check: &'static str,
        observed: bool,
        entered: bool,
    }
    fn write_bytes(bytes: &[u8]) {
        use std::io::Write;
        let _ = std::io::stderr().write_all(bytes);
    }
    unsafe fn observe(snapshot: &PageValiditySnapshot, argument: *mut c_void) -> Option<usize> {
        let context = argument.cast::<Context>();
        // SAFETY: this synchronous fixture retains its original context;
        // these short scalar accesses create no borrow across callbacks.
        if unsafe { (*context).check != "used" || (*context).observed || (*context).page != snapshot.page } { return None; }
        unsafe { (*context).observed = true; }
        Some(usize::from(snapshot.capacity) + 1)
    }
    unsafe fn observe_owner(snapshot: &PageValiditySnapshot,
        owner: &mut crate::page_validity::PageSourceOwnerSnapshot, argument: *mut c_void,
    ) {
        let context = argument.cast::<Context>();
        // SAFETY: only copied scalar predicate inputs change. The fixture's
        // actual Page, client and retained issuer remain valid and untouched.
        let (check, seen, selected) = unsafe { ((*context).check, (*context).observed, (*context).page) };
        if seen || selected != snapshot.page || check == "used" { return; }
        if matches!(check, "queue" | "bin" | "key") && owner.queue_block_size.is_none() { return; }
        match check {
            "heap" => owner.heap_present = false,
            "theap" => {
                owner.heap_theap_absent = false;
                owner.heap_theap_matches = false;
                owner.page_theap_detached = false;
            }
            "queue" => owner.queue_contains = false,
            "bin" => owner.queue_block_size = Some(owner.block_size + crate::config::WORD_SIZE),
            "key" => owner.secure_key = 0,
            _ => return,
        }
        unsafe { (*context).observed = true; }
    }
    unsafe extern "C" fn output(message: *const c_char, argument: *mut c_void) {
        // SAFETY: the registered source callback receives a terminated
        // fragment that remains live through this synchronous invocation.
        let bytes = unsafe { CStr::from_ptr(message) }.to_bytes();
        write_bytes(bytes);
        let context = argument.cast::<Context>();
        if !bytes.windows(b"assertion failed:".len()).any(|part| part == b"assertion failed:")
            || unsafe { (*context).entered } { return; }
        // SAFETY: the context remains owned by the original allocation. Copy
        // only scalar identities before nested allocation invokes observers.
        unsafe { (*context).entered = true; }
        let (page, client, theap, heap, request) = unsafe {
            ((*context).page, (*context).client, (*context).theap, (*context).heap, (*context).request)
        };
        // SAFETY: the fixture keeps its actual original client and issuer
        // live. Every owner/map projection ends before the nested malloc.
        let original = unsafe { runtime::with_native_allocation_owner(theap, |owner| {
            let registered = owner.page_map().ok()?.lookup_registered_page(client.as_ptr()).ok()?;
            Some(owner.selected_theap() == theap && owner.heap() == heap && registered == Some(page))
        }) }.ok().flatten().unwrap_or(false);
        write_bytes(if original { b"original-owner-and-page=retained\n" } else { b"original-owner-and-page=lost\n" });
        let nested = malloc(request);
        if let Some(nested) = nested.value {
            // SAFETY: both exact clients remain live and the short source
            // owner observation finishes before the nested client's free.
            let distinct = unsafe { runtime::with_native_allocation_owner(theap, |owner| {
                let nested_page = owner.page_map().ok()?.lookup_registered_page(nested.as_ptr()).ok()?;
                Some(owner.selected_theap() == theap && nested_page.is_some_and(|nested| nested != page))
            }) }.ok().flatten().unwrap_or(false);
            write_bytes(if distinct { b"nested-page=distinct\n" } else { b"nested-page=failed-page\n" });
            // SAFETY: this callback owns the new client exclusively; no
            // metadata projection survives this one consuming source free.
            let freed = unsafe { free(nested.as_ptr()) } == FreeOutcome::Freed;
            write_bytes(if freed { b"nested-client=freed\n" } else { b"nested-client=retained\n" });
        } else {
            write_bytes(b"nested-allocation=refused\n");
        }
    }
    unsafe extern "C" fn error(_: core::ffi::c_int, _: *mut c_void) {
        write_bytes(b"unexpected-error-handler\n");
    }

    let checks = [
        ("used", "page->used <= page->capacity"),
        ("heap", "page->heap!=NULL"),
        ("theap", "page_theap == NULL || mi_page_theap(page)==page_theap || mi_page_theap(page)->tld->thread_id == MI_THREADID_DETACHED"),
        ("queue", "mi_page_queue_contains(pq, page)"),
        ("bin", "pq->block_size==mi_page_block_size(page) || mi_page_is_huge(page) || mi_page_is_in_full(page)"),
        ("key", "page->keys[0] != 0"),
    ];
    if let Some(child_check) = std::env::var_os(CHILD) {
        let check = checks.iter().find(|(check, _)| child_check == *check).unwrap().0;
        start_source_runtime();
        let request = 12_288 - crate::config::PADDING_SIZE;
        let client = allocate(request);
        let selected = crate::compiler_tls::default_theap();
        // SAFETY: the exact live client retains its original Page; only
        // copied validity inputs and scalar issuer identities escape.
        let (snapshot, theap, heap) = unsafe { runtime::with_native_allocation_owner(selected, |owner| {
            let page = owner.page_map().unwrap().lookup_registered_page(client.as_ptr()).unwrap().unwrap();
            (Page::validity_snapshot_at(page), owner.selected_theap(), owner.heap())
        }) }.unwrap();
        assert_eq!(snapshot.capacity, 1);
        assert_eq!(snapshot.used, 1);
        assert!(snapshot.free.is_null());
        assert!(snapshot.reserved > snapshot.capacity);
        let mut context = Context { page: snapshot.page, client, theap, heap, request, check, observed: false, entered: false };
        let argument = core::ptr::addr_of_mut!(context).cast();
        // SAFETY: this child serializes callback registration and retains
        // the context, original client and original issuer through abort.
        unsafe {
            crate::source_options_api::register_output(Some(output), argument);
            crate::source_options_api::register_error(Some(error), core::ptr::null_mut());
            let result = crate::page_validity::with_live_page_validity_observer_for_test(
                observe, argument, || crate::page_validity::with_live_page_owner_validity_observer_for_test(
                    observe_owner, argument, || malloc(request),
                ),
            );
            std::eprintln!("ordinary-return: client={}, errno={:?}, observed={}", result.value.is_some(), result.errno, context.observed);
            crate::source_options_api::register_output(None, core::ptr::null_mut());
            crate::source_options_api::register_error(None, core::ptr::null_mut());
        }
        return;
    }
    for (check, assertion) in checks {
        if check == "key" && crate::config::SECURE_LEVEL == 0 { continue; }
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", "source_api::source_page_assertion_tests::source_malloc_live_validity_assertion_reenters_after_original_owner_projections_end",
            "--nocapture", "--test-threads=1"]).env(CHILD, check);
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("mimalloc_") { command.env_remove(name); }
        }
        let result = command.output().unwrap();
        let stderr = std::string::String::from_utf8_lossy(&result.stderr);
        std::println!("copied-input={check}, status={}\n{stderr}", result.status);
        assert_eq!(result.status.signal(), Some(6), "{check}: {stderr}");
        assert!(stderr.contains(&std::format!("assertion: \"{assertion}\"")), "{check}: {stderr}");
        assert!(stderr.contains("original-owner-and-page=retained\n"), "{check}: {stderr}");
        assert!(stderr.contains("nested-page=distinct\n"), "{check}: {stderr}");
        assert!(stderr.contains("nested-client=freed\n"), "{check}: {stderr}");
        assert!(!stderr.contains("ordinary-return:"), "{check}: {stderr}");
        assert!(!stderr.contains("unexpected-error-handler"), "{check}: {stderr}");
    }
}
