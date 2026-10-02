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
        nested_heap: NonNull<Heap>,
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
        if unsafe { !matches!((*context).check, "used" | "retire" | "unfull" | "release" | "exit" | "collect") || (*context).observed || (*context).page != snapshot.page } { return None; }
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
        if seen || selected != snapshot.page || matches!(check, "used" | "retire" | "unfull" | "release" | "exit") { return; }
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
        let (page, client, theap, heap, nested_heap, request) = unsafe {
            ((*context).page, (*context).client, (*context).theap, (*context).heap, (*context).nested_heap, (*context).request)
        };
        // SAFETY: the operation keeps its actual original issuer and Page
        // backing retained, including after local client consumption. The
        // address is only a registered-range identity here. Every short
        // owner/map projection ends before the nested malloc.
        let original = unsafe { runtime::with_native_allocation_owner(theap, |owner| {
            let registered = owner.page_map().ok()?.lookup_registered_page(client.as_ptr()).ok()?;
            Some(owner.selected_theap() == theap && owner.heap() == heap && registered == Some(page))
        }) }.ok().flatten().unwrap_or(false);
        write_bytes(if original { b"original-owner-and-page=retained\n" } else { b"original-owner-and-page=lost\n" });
        // SAFETY: the original task and admission retain this genuine Heap;
        // nested allocation selects that exact issuer's current-thread slot.
        let nested = unsafe { crate::source_heap_api::heap_malloc(nested_heap.as_ptr().cast(), request) };
        if let Some(nested) = nested.value {
            // SAFETY: the original task retains its Page backing and this
            // callback owns its nested live client. This short owner query
            // finishes before the nested client's consuming free.
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
        ("collect", "page->used <= page->capacity"),
        ("collect-worker", "page->used <= page->capacity"),
        ("collect-auxiliary", "page->used <= page->capacity"),
        ("collect-child", "page->used <= page->capacity"),
        ("retire", "page->used <= page->capacity"),
        ("unfull", "page->used <= page->capacity"),
        ("release", "page->used <= page->capacity"),
        ("retire-worker", "page->used <= page->capacity"),
        ("unfull-worker", "page->used <= page->capacity"),
        ("release-worker", "page->used <= page->capacity"),
        ("exit-worker", "page->used <= page->capacity"),
        ("exit-auxiliary-worker", "page->used <= page->capacity"),
        ("exit-child", "page->used <= page->capacity"),
        ("exit-childauxiliary", "page->used <= page->capacity"),
        ("retire-auxiliary", "page->used <= page->capacity"),
        ("unfull-auxiliary", "page->used <= page->capacity"),
        ("release-auxiliary", "page->used <= page->capacity"),
        ("retire-child", "page->used <= page->capacity"),
        ("unfull-child", "page->used <= page->capacity"),
        ("release-child", "page->used <= page->capacity"),
        ("heap", "page->heap!=NULL"),
        ("theap", "page_theap == NULL || mi_page_theap(page)==page_theap || mi_page_theap(page)->tld->thread_id == MI_THREADID_DETACHED"),
        ("queue", "mi_page_queue_contains(pq, page)"),
        ("bin", "pq->block_size==mi_page_block_size(page) || mi_page_is_huge(page) || mi_page_is_in_full(page)"),
        ("key", "page->keys[0] != 0"),
    ];
    if let Some(child_check) = std::env::var_os(CHILD) {
        let selected_check = checks.iter().find(|(check, _)| child_check == *check).unwrap().0;
        let (check, domain) = selected_check.split_once('-').unwrap_or((selected_check, "initial"));
        start_source_runtime();
        if matches!(domain, "worker" | "auxiliary-worker" | "child" | "childauxiliary") { assert!(runtime::prepare_native_later_thread_arena()); }
        let child = if matches!(domain, "child" | "childauxiliary") { Some(crate::subproc::lifecycle::native_subproc_new().unwrap()) } else { None };
        // The parent retains a distinct initialized Heap before the worker
        // exit. Its ordinary API route can attach a fresh auxiliary Theap in
        // the callback without reopening the failed fixed owner's queues.
        let diagnostic_heap = if check == "exit" && !matches!(domain, "child" | "childauxiliary") {
            crate::source_heap_api::heap_new() as usize
        } else { 0 };
        let run = || {
        if matches!(domain, "child" | "childauxiliary") {
            // SAFETY: this genuine worker attaches to the retained child and
            // remains its sole member through terminal assertion dispatch.
            assert_eq!(unsafe { crate::subproc::lifecycle::native_subproc_add_current_thread(child.unwrap()) },
                Ok(crate::subproc::lifecycle::NativeChildThreadAdd::Added));
        }
        let diagnostic_heap = if check == "exit" && matches!(domain, "child" | "childauxiliary") {
            crate::source_heap_api::heap_new() as usize
        } else { diagnostic_heap };
        if check == "exit" && matches!(domain, "child" | "childauxiliary") {
            assert_ne!(diagnostic_heap, 0, "an independently retained child Heap is initialized");
            // Establish its actual healthy Theap before source owner exit.
            // The callback uses this retained cached/list member rather than
            // requesting a new issuer through the failed main Page engine.
            let seed = unsafe { crate::source_heap_api::heap_malloc(diagnostic_heap as *mut _, 32) }
                .value.expect("healthy child Heap initializes before exit");
            assert_eq!(unsafe { free(seed.as_ptr()) }, FreeOutcome::Freed);
        }
        let selected_heap = if matches!(domain, "auxiliary" | "auxiliary-worker" | "childauxiliary") { crate::source_heap_api::heap_new() } else { core::ptr::null_mut() };
        let allocate_selected = |request| {
            if selected_heap.is_null() { allocate(request) }
            else {
                // SAFETY: this current thread retains its actual new Heap.
                unsafe { crate::source_heap_api::heap_malloc(selected_heap, request) }.value.unwrap()
            }
        };
        let request = if matches!(check, "retire" | "release" | "exit") { 32 }
            else { 12_288 - crate::config::PADDING_SIZE };
        let client = allocate_selected(request);
        let selected = crate::compiler_tls::default_theap();
        // SAFETY: the exact live client retains its original Page; only
        // copied validity inputs and scalar issuer identities escape.
        let (snapshot, theap, heap) = unsafe { runtime::with_native_allocation_owner(selected, |owner| {
            let page = owner.page_map().unwrap().lookup_registered_page(client.as_ptr()).unwrap().unwrap();
            let snapshot = Page::validity_snapshot_at(page);
            (snapshot, NonNull::new(snapshot.theap).unwrap(), NonNull::new(snapshot.heap).unwrap())
        }) }.unwrap();
        let mut retained_clients = std::vec::Vec::new();
        if check == "unfull" {
            for _ in 1..snapshot.reserved { retained_clients.push(allocate_selected(request)); }
        } else if matches!(check, "release" | "exit") {
            // SAFETY: this exclusively held client becomes a retired Page's
            // local-free block. Its backing stays owned until collection.
            assert_eq!(unsafe { free(client.as_ptr()) }, FreeOutcome::Freed);
        } else if check != "retire" {
            assert_eq!(snapshot.capacity, 1);
            assert_eq!(snapshot.used, 1);
            assert!(snapshot.free.is_null());
            assert!(snapshot.reserved > snapshot.capacity);
        }
        let nested_heap = NonNull::new(diagnostic_heap as *mut Heap).unwrap_or(heap);
        let mut context = Context { page: snapshot.page, client, theap, heap, nested_heap, request, check, observed: false, entered: false };
        let argument = core::ptr::addr_of_mut!(context).cast();
        // SAFETY: this child serializes callback registration and retains
        // the context, original client and original issuer through abort.
        unsafe {
            crate::source_options_api::register_output(Some(output), argument);
            crate::source_options_api::register_error(Some(error), core::ptr::null_mut());
            let result = crate::page_validity::with_live_page_validity_observer_for_test(
                observe, argument, || crate::page_validity::with_live_page_owner_validity_observer_for_test(
                    observe_owner, argument, || match check {
                        "retire" | "unfull" => {
                            let outcome = free(client.as_ptr());
                            std::eprintln!("ordinary-free-return: {outcome:?}");
                            malloc(request)
                        }
                        "collect" => {
                            super::theap_collect(theap.as_ptr().cast(), false);
                            malloc(request)
                        }
                        "exit" => {
                            let finish = runtime::finish_current_thread_native_after_user_destructors();
                            std::eprintln!("ordinary-exit-return: {finish:?}");
                            malloc(request)
                        }
                        "release" => {
                            super::theap_collect(theap.as_ptr().cast(), true);
                            malloc(request)
                        }
                        _ => malloc(request),
                    },
                ),
            );
            std::eprintln!("ordinary-return: client={}, errno={:?}, observed={}", result.value.is_some(), result.errno, context.observed);
            crate::source_options_api::register_output(None, core::ptr::null_mut());
            crate::source_options_api::register_error(None, core::ptr::null_mut());
        }
        };
        if matches!(domain, "worker" | "auxiliary-worker" | "child" | "childauxiliary") {
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    // SAFETY: this actual worker publishes its own native
                    // descriptor before any source thread attachment.
                    assert!(unsafe { crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(
                        crate::__crabc_runtime::current_native_allocator_thread_descriptor()) });
                    if matches!(domain, "worker" | "auxiliary-worker") {
                        assert_eq!(runtime::attach_current_thread(), runtime::ThreadAttachResult::Attached);
                    }
                    run();
                }).join().unwrap();
            });
        } else { run(); }
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
        assert!(!stderr.contains("ordinary-exit-return:"), "{check}: {stderr}");
        assert!(!stderr.contains("ordinary-free-return:"), "{check}: {stderr}");
        assert!(!stderr.contains("unexpected-error-handler"), "{check}: {stderr}");
    }
}

#[cfg(all(target_arch = "x86_64", feature = "mi-debug-3", not(miri)))]
#[test]
fn source_local_free_validates_full_unfull_and_retired_page_before_release() {
    use core::{ffi::c_void, ptr::NonNull};
    use crate::types::{Page, PageValiditySnapshot};

    struct Observation { page: NonNull<Page>, expected_used: usize, in_full: bool, seen: bool }
    unsafe fn observe(state: &PageValiditySnapshot, argument: *mut c_void) -> Option<usize> {
        let observation = argument.cast::<Observation>();
        // SAFETY: this synchronous scope retains its scalar fixture. The
        // callback copies facts only and never mutates live allocator state.
        unsafe {
            if state.page == (*observation).page && state.used == (*observation).expected_used
                && state.in_full == (*observation).in_full { (*observation).seen = true; }
        }
        None
    }
    crate::test_process::run_in_fresh_process(
        "source_api::source_page_assertion_tests::source_local_free_validates_full_unfull_and_retired_page_before_release", || {
            start_source_runtime();
            for request in [32, 12_288 - crate::config::PADDING_SIZE] {
                let first = allocate(request);
                let selected = crate::compiler_tls::default_theap();
                // SAFETY: the live client retains its Page; only its identity
                // and copied reserved count leave this short owner access.
                let (page, reserved) = unsafe { runtime::with_native_allocation_owner(selected, |owner| {
                    let page = owner.page_map().unwrap().lookup_registered_page(first.as_ptr()).unwrap().unwrap();
                    (page, usize::from(Page::validity_snapshot_at(page).reserved))
                }) }.unwrap();
                let mut clients = std::vec![first];
                while clients.len() < reserved { clients.push(allocate(request)); }
                // A small direct-cache page enters the full queue only when
                // the following generic miss selects a successor.
                let successor = allocate(request);
                let mut observation = Observation { page, expected_used: reserved - 1, in_full: true, seen: false };
                let client = clients.pop().unwrap();
                // SAFETY: this exact local client is consumed once. The
                // observer changes no live metadata or client bytes.
                assert_eq!(unsafe { crate::page_validity::with_live_page_validity_observer_for_test(
                    observe, core::ptr::addr_of_mut!(observation).cast(), || free(client.as_ptr()),
                ) }, FreeOutcome::Freed);
                assert!(observation.seen, "full page was validated after local publication and before unfull");
                for client in clients.iter().skip(1) {
                    // SAFETY: every remaining client is held exclusively.
                    assert_eq!(unsafe { free(client.as_ptr()) }, FreeOutcome::Freed);
                }
                // The medium retirement rule retains a sole regular page.
                // Release its successor while the original client stays live.
                assert_eq!(unsafe { free(successor.as_ptr()) }, FreeOutcome::Freed);
                super::collect(true);
                observation.expected_used = 0;
                observation.in_full = false;
                observation.seen = false;
                // SAFETY: this final client is still exclusively live; its
                // return reaches retirement while the observer is retained.
                assert_eq!(unsafe { crate::page_validity::with_live_page_validity_observer_for_test(
                    observe, core::ptr::addr_of_mut!(observation).cast(), || free(first.as_ptr()),
                ) }, FreeOutcome::Freed);
                assert!(observation.seen, "empty regular page was validated before retirement");
                observation.seen = false;
                // SAFETY: the observer records scalar identity only. The
                // source owner retains its retired backing until collection.
                unsafe { crate::page_validity::with_live_page_validity_observer_for_test(
                    observe, core::ptr::addr_of_mut!(observation).cast(), || super::collect(true),
                ) };
                assert!(observation.seen, "retired page was validated before terminal release");
            }
        },
    );
}

#[cfg(all(target_arch = "x86_64", not(miri)))]
#[test]
fn source_thread_done_collects_auxiliary_theaps_with_automatic_abandon_disabled() {
    use core::ptr::NonNull;
    use crate::types::{Heap, Page};
    #[cfg(feature = "mi-debug-3")]
    struct ExitObservation { theap: *mut crate::types::Theap, seen: bool }
    #[cfg(feature = "mi-debug-3")]
    unsafe fn observe_exit(snapshot: &crate::types::PageValiditySnapshot, argument: *mut core::ffi::c_void) -> Option<usize> {
        let observation = unsafe { &mut *argument.cast::<ExitObservation>() };
        if snapshot.theap == observation.theap {
            assert!(crate::compiler_tls::fast_slot_peek().is_none(),
                "source clears the independent fast slot before Theap page traversal");
            observation.seen = true;
        }
        None
    }
    crate::test_process::run_in_fresh_process(
        "source_api::source_page_assertion_tests::source_thread_done_collects_auxiliary_theaps_with_automatic_abandon_disabled", || {
            start_source_runtime();
            assert!(runtime::prepare_native_later_thread_arena());
            for child_domain in [false, true] {
                let child = child_domain.then(|| crate::subproc::lifecycle::native_subproc_new().unwrap());
                let (heap, addresses) = std::thread::scope(|scope| scope.spawn(|| {
                    // SAFETY: this worker publishes its actual native descriptor
                    // before source attachment and remains the sole local owner.
                    assert!(unsafe { crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(
                        crate::__crabc_runtime::current_native_allocator_thread_descriptor()) });
                    if let Some(child) = child {
                        assert_eq!(unsafe { crate::subproc::lifecycle::native_subproc_add_current_thread(child) },
                            Ok(crate::subproc::lifecycle::NativeChildThreadAdd::Added));
                    } else {
                        assert_eq!(runtime::attach_current_thread(), runtime::ThreadAttachResult::Attached);
                    }
                    let heap = crate::source_heap_api::heap_new();
                    assert!(!heap.is_null());
                    let mut released = std::vec::Vec::new();
                    #[cfg(feature = "mi-debug-3")]
                    let mut exit_observation = ExitObservation { theap: core::ptr::null_mut(), seen: false };
                    for request in [32, 12_288 - crate::config::PADDING_SIZE] {
                        let first = unsafe { crate::source_heap_api::heap_malloc(heap, request) }.value.unwrap();
                        let selected = crate::compiler_tls::default_theap();
                        let reserved = unsafe { runtime::with_native_allocation_owner(selected, |owner| {
                            let page = owner.page_map().unwrap().lookup_registered_page(first.as_ptr()).unwrap().unwrap();
                            let snapshot = Page::validity_snapshot_at(page);
                            let actual = NonNull::new(snapshot.theap).unwrap();
                            #[cfg(feature = "mi-debug-3")]
                            { exit_observation.theap = actual.as_ptr(); }
                            assert!(!actual.as_ref().allows_page_abandon(), "ordinary Heap source default");
                            usize::from(snapshot.reserved)
                        }) }.unwrap();
                        let mut clients = std::vec![first];
                        // Exercise the real medium non-abandoning full queue as
                        // well as ordinary small-page retirement before exit.
                        if request > crate::config::SMALL_MAX_OBJ_SIZE {
                            for _ in 1..reserved {
                                clients.push(unsafe { crate::source_heap_api::heap_malloc(heap, request) }.value.unwrap());
                            }
                        }
                        for client in clients {
                            released.push(client.as_ptr() as usize);
                            assert_eq!(unsafe { free(client.as_ptr()) }, FreeOutcome::Freed);
                        }
                    }
                    #[cfg(feature = "mi-debug-3")]
                    let finish = unsafe { crate::page_validity::with_live_page_validity_observer_for_test(
                        observe_exit, core::ptr::addr_of_mut!(exit_observation).cast(),
                        runtime::finish_current_thread_native_after_user_destructors,
                    ) };
                    #[cfg(not(feature = "mi-debug-3"))]
                    let finish = runtime::finish_current_thread_native_after_user_destructors();
                    assert_eq!(finish, runtime::ThreadFinishResult::Finished);
                    #[cfg(feature = "mi-debug-3")]
                    assert!(exit_observation.seen, "actual source Page observation preceded release");
                    (heap as usize, released)
                }).join().unwrap());
                // These are address identities of consumed clients. Observe
                // only PageMap registration after every old issuer projection
                // ended; no former Page or allocation is dereferenced.
                let selected = crate::compiler_tls::default_theap();
                unsafe { runtime::with_native_allocation_owner(selected, |owner| {
                    for address in addresses {
                        assert!(owner.page_map().unwrap().lookup_registered_page(address as *mut u8).unwrap().is_none());
                    }
                }) }.unwrap();
                if let Some(child) = child {
                    assert_eq!(unsafe { crate::subproc::lifecycle::native_subproc_destroy(child) }, Ok(()));
                } else {
                    // The parent retains the actual Heap block across worker
                    // exit; source destruction consumes that exact live image.
                    assert!(unsafe { crate::source_heap_api::heap_release(heap as *mut Heap as *mut _, true) });
                }
                super::collect(true);
            }
        },
    );
}
