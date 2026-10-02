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
