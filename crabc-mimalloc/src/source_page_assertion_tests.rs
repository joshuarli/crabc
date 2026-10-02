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
        if unsafe { (*context).observed || (*context).page != snapshot.page } { return None; }
        unsafe { (*context).observed = true; }
        Some(usize::from(snapshot.capacity) + 1)
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

    if std::env::var_os(CHILD).is_some() {
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
        let mut context = Context { page: snapshot.page, client, theap, heap, request, observed: false, entered: false };
        let argument = core::ptr::addr_of_mut!(context).cast();
        // SAFETY: this child serializes callback registration and retains
        // the context, original client and original issuer through abort.
        unsafe {
            crate::source_options_api::register_output(Some(output), argument);
            crate::source_options_api::register_error(Some(error), core::ptr::null_mut());
            let result = crate::page_validity::with_live_page_validity_observer_for_test(
                observe, argument, || malloc(request),
            );
            std::eprintln!("ordinary-return: client={}, errno={:?}, observed={}", result.value.is_some(), result.errno, context.observed);
            crate::source_options_api::register_output(None, core::ptr::null_mut());
            crate::source_options_api::register_error(None, core::ptr::null_mut());
        }
        return;
    }
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", "source_api::source_page_assertion_tests::source_malloc_live_validity_assertion_reenters_after_original_owner_projections_end",
        "--nocapture", "--test-threads=1"]).env(CHILD, "1");
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("mimalloc_") { command.env_remove(name); }
    }
    let result = command.output().unwrap();
    let stderr = std::string::String::from_utf8_lossy(&result.stderr);
    assert_eq!(result.status.signal(), Some(6), "{stderr}");
    assert!(stderr.contains("assertion: \"page->used <= page->capacity\""), "{stderr}");
    assert!(stderr.contains("original-owner-and-page=retained\n"), "{stderr}");
    assert!(stderr.contains("nested-page=distinct\n"), "{stderr}");
    assert!(stderr.contains("nested-client=freed\n"), "{stderr}");
    assert!(!stderr.contains("ordinary-return:"), "{stderr}");
    assert!(!stderr.contains("unexpected-error-handler"), "{stderr}");
}
