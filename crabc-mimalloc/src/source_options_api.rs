// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/options.c:214-337,347-608`
// (`mi_options_print_out`, the `mi_option_*` accessors and mutators,
// `mi_register_output`, `mi_register_error`), `src/page.c:999-1003`
// (`mi_register_deferred_free`), `src/stats.c:640-653` (`mi_stats_get`),
// and `src/init.c:17-19` (`mi_version`).

//! Pinned mimalloc option, callback, and statistics public entries over the
//! native runtime's process option table and output owner.
//!
//! Each function is the source entry of the same `mi_` name, with a raw
//! `mi_option_t` value where the source takes one: an out-of-range option
//! reads as zero and ignores mutation, as `mi_option_get`/`mi_option_set`
//! do. Before the process has published its option table (which x86 startup
//! does before any allocation), reads return the pinned release default and
//! mutations are ignored.

use core::ffi::{c_char, c_int, c_long, c_void};

use crate::config::SourceOption;
use crate::diagnostic_output::{OutputOwner, RegularReservationDiagnostic};

/// Delivers only scalar reservation facts, after the caller releases its
/// mapping/publication locks and mutable owner projections.
pub(crate) fn regular_reservation_verbose(diagnostic: Option<RegularReservationDiagnostic>) {
    let (Some(owner), Some(diagnostic)) = (owner(), diagnostic) else { return };
    // SAFETY: publication installed the table; runtime reservation admission
    // retains callback lifetimes and ends owner projections before this call.
    unsafe { owner.regular_reservation_verbose(diagnostic) };
}

/// `mi_output_fun`.
pub type OutputFunction = unsafe extern "C" fn(*const c_char, *mut c_void);
/// `mi_error_fun`.
pub type ErrorFunction = unsafe extern "C" fn(c_int, *mut c_void);
/// `mi_deferred_free_fun`.
pub type DeferredFreeFunction = unsafe extern "C" fn(bool, u64, *mut c_void);

/// `MI_MALLOC_VERSION` of the pinned `include/mimalloc.h:11`.
const SOURCE_VERSION: c_int = 30_500;

#[inline]
fn owner() -> Option<&'static OutputOwner> {
    crate::process_init::process_output_owner()
}

/// `mi_version`.
pub fn version() -> c_int {
    SOURCE_VERSION
}

/// `mi_option_get`.
pub fn option_get(option: c_int) -> c_long {
    let Some(option) = SourceOption::from_source_value(option) else { return 0 };
    match owner() {
        // SAFETY: a published owner has an installed table; a lazy retry's
        // warning is delivered through the process output route, as in C.
        Some(owner) => unsafe { owner.option_value(option) },
        None => option.default_value(),
    }
}

/// `mi_option_get_clamp`.
pub fn option_get_clamp(option: c_int, min: c_long, max: c_long) -> c_long {
    let value = option_get(option);
    if value < min { min } else if value > max { max } else { value }
}

/// `mi_option_get_size`.
pub fn option_get_size(option: c_int) -> usize {
    let Some(source) = SourceOption::from_source_value(option) else { return 0 };
    let value = option_get(option);
    let size = if value < 0 { 0 } else { value as usize };
    if source.has_size_in_kib() {
        size.checked_mul(crate::config::KIB).unwrap_or(crate::config::MAX_ALLOC_SIZE)
    } else {
        size
    }
}

/// `mi_option_is_enabled`.
pub fn option_is_enabled(option: c_int) -> bool {
    option_get(option) != 0
}

/// `mi_option_set`.
pub fn option_set(option: c_int, value: c_long) {
    let (Some(option), Some(owner)) = (SourceOption::from_source_value(option), owner()) else { return };
    // SAFETY: a published owner; the lock serializes the store.
    let _ = unsafe { owner.option_set(option, value) };
}

/// `mi_option_set_default`.
pub fn option_set_default(option: c_int, value: c_long) {
    let (Some(option), Some(owner)) = (SourceOption::from_source_value(option), owner()) else { return };
    // SAFETY: as `option_set`.
    let _ = unsafe { owner.option_set_default(option, value) };
}

/// `mi_option_set_enabled`; `mi_option_enable`/`mi_option_disable` are its
/// `true`/`false` forms.
pub fn option_set_enabled(option: c_int, enable: bool) {
    option_set(option, c_long::from(enable));
}

/// `mi_option_set_enabled_default`.
pub fn option_set_enabled_default(option: c_int, enable: bool) {
    option_set_default(option, c_long::from(enable));
}

/// `mi_options_print_out`; a null `output` is the default output route.
///
/// # Safety
/// A non-null `output` and the objects reachable from `argument` stay valid
/// for every printed line.
pub unsafe fn options_print_out(output: Option<OutputFunction>, argument: *mut c_void) {
    let Some(owner) = owner() else { return };
    // SAFETY: forwarded callback contract; the page record size is the
    // source `sizeof(mi_page_t)` its last line prints.
    let _ = unsafe { owner.options_print_out(output, argument, core::mem::size_of::<crate::types::Page>()) };
}

/// `mi_register_output`.
///
/// # Safety
/// The `mi_register_output` contract: `output` and `argument` stay valid
/// until a replacement is registered and in-flight deliveries finish, and
/// registration is serialized with every other output.
pub unsafe fn register_output(output: Option<OutputFunction>, argument: *mut c_void) {
    let Some(owner) = owner() else { return };
    // SAFETY: forwarded.
    unsafe { owner.register_output(output, argument) };
}

/// `mi_register_error`.
///
/// # Safety
/// The `mi_register_error` contract: `handler` and `argument` stay valid for
/// every later report, and registration does not race a report.
pub unsafe fn register_error(handler: Option<ErrorFunction>, argument: *mut c_void) {
    let Some(owner) = owner() else { return };
    // SAFETY: forwarded.
    unsafe { owner.register_error(handler, argument) };
}

/// `mi_register_deferred_free`.
///
/// # Safety
/// As [`crate::runtime_lifecycle::register_native_deferred_free_callback`].
pub unsafe fn register_deferred_free(callback: Option<DeferredFreeFunction>, argument: *mut c_void) {
    // SAFETY: forwarded.
    unsafe { crate::runtime_lifecycle::register_native_deferred_free_callback(callback, argument) };
}

/// `mi_stats_get`.
///
/// # Safety
/// `stats` is null or valid for reads and writes of a source `mi_stats_t`.
pub unsafe fn stats_get(stats: *mut c_void) -> bool {
    // SAFETY: forwarded.
    unsafe { crate::runtime_lifecycle::native_stats_get(stats.cast()) }
}

/// Copies a selected subprocess's own statistics, excluding its Heaps.
///
/// # Safety
/// `id` is null, the main id, or a retained live child. `stats` is null or an
/// exclusively readable/writable complete source statistics image.
pub unsafe fn subproc_stats_get_exclusive(id: *mut c_void, stats: *mut c_void) -> bool {
    // SAFETY: forwarded retained identity and complete output image contracts.
    unsafe { crate::runtime_lifecycle::native_subproc_stats_get(id, stats.cast(), true) }
}

/// Copies subprocess statistics plus its listed Heaps, after each existing
/// calling-thread Theap merge. Metadata-Theap statistics stay excluded.
///
/// # Safety
/// As for the exclusive getter; the calling thread retains its existing
/// Theaps and their owning Heaps through the synchronous traversal.
pub unsafe fn subproc_stats_get(id: *mut c_void, stats: *mut c_void) -> bool {
    // SAFETY: forwarded retained identity, roots and complete image contracts.
    unsafe { crate::runtime_lifecycle::native_subproc_stats_get(id, stats.cast(), false) }
}

/// Renders a selected subprocess aggregate into a fixed or owned JSON buffer.
///
/// # Safety
/// `id` is null, the main id, or a live child retained during the snapshot.
/// `buffer` is null or writable for `size` bytes; free any owned result.
pub unsafe fn subproc_stats_json(id: *mut c_void, size: usize, buffer: *mut c_char) -> *mut c_char {
    // SAFETY: forwarded selected identity and writable buffer contracts.
    unsafe { crate::runtime_lifecycle::native_subproc_stats_json(id, size, buffer.cast()) }.cast()
}

/// Prints a selected subprocess aggregate after releasing its Heap-list lock.
///
/// # Safety
/// `id` is null, the main id, or a child retained through all callbacks.
/// `out` and `argument` stay callable; callbacks may allocate but cannot
/// destroy the selected subprocess during rendering.
pub unsafe fn subproc_stats_print_out(id: *mut c_void, out: Option<OutputFunction>, argument: *mut c_void) {
    // SAFETY: forwarded selected identity and synchronous callback contracts.
    unsafe { crate::runtime_lifecycle::native_subproc_stats_print_out(id, out, argument) };
}

pub use crate::diagnostic_output::SourceProcessInfo;

/// `mi_stats_print_out`; a null `out` is the process default route.
///
/// # Safety
/// A non-null `out` is callable with each message and `argument`.
pub unsafe fn stats_print_out(out: Option<OutputFunction>, argument: *mut c_void) {
    // SAFETY: forwarded.
    unsafe { crate::runtime_lifecycle::native_stats_print_out(out, argument) }
}

/// `mi_subproc_heap_stats_print_out`; null selects no subprocess.
///
/// # Safety
/// `id` is null, the main id, or a live child id retained through the call.
/// `out` and `argument` remain callable for every NUL-terminated message.
/// The callback may allocate, but must not mutate the selected Heap list,
/// destroy the subprocess, or recursively acquire its Heap-list lock.
pub unsafe fn subproc_heap_stats_print_out(id: *mut c_void, out: Option<OutputFunction>, argument: *mut c_void) {
    // SAFETY: forwarded subprocess-lifetime and callback restrictions.
    unsafe { crate::runtime_lifecycle::native_subproc_heap_stats_print_out(id, out, argument) }
}

/// `mi_thread_stats_print_out`.
///
/// # Safety
/// As [`stats_print_out`].
pub unsafe fn thread_stats_print_out(out: Option<OutputFunction>, argument: *mut c_void) {
    // SAFETY: forwarded.
    unsafe { crate::runtime_lifecycle::native_thread_stats_print_out(out, argument) }
}

/// `mi_process_info_print_out`.
///
/// # Safety
/// As [`stats_print_out`].
pub unsafe fn process_info_print_out(out: Option<OutputFunction>, argument: *mut c_void) {
    // SAFETY: forwarded.
    unsafe { crate::runtime_lifecycle::native_process_info_print_out(out, argument) }
}

/// `mi_process_info`'s eight results.
pub fn process_info() -> SourceProcessInfo {
    crate::runtime_lifecycle::native_process_info()
}

/// `mi_stats_get_json` (null `stats`) and `mi_stats_as_json`.
///
/// # Safety
/// As [`crate::runtime_lifecycle::native_stats_json`].
pub unsafe fn stats_json(stats: *const c_void, size: usize, buffer: *mut c_char) -> *mut c_char {
    // SAFETY: forwarded.
    unsafe { crate::runtime_lifecycle::native_stats_json(stats.cast(), size, buffer.cast()) }.cast()
}

/// `mi_stats_get_bin_size`.
pub const fn stats_get_bin_size(bin: usize) -> usize {
    crate::runtime_lifecycle::native_stats_bin_size(bin)
}

/// `mi_stats_reset`.
pub fn stats_reset() {
    crate::runtime_lifecycle::native_stats_reset();
}

#[cfg(all(test, target_arch = "x86_64"))]
mod regular_reservation_output_tests {
    use super::*;
    use core::ffi::CStr;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::vec::Vec;

    struct Capture {
        messages: Mutex<Vec<Vec<u8>>>,
        reenter_on: &'static [u8],
        entered: AtomicBool,
        nested_ok: AtomicBool,
        thread_identity: AtomicUsize,
        disable_verbose_on_failure: AtomicBool,
    }

    unsafe extern "C" fn discard(_: *const c_char) {}

    unsafe extern "C" fn capture(message: *const c_char, argument: *mut c_void) {
        // SAFETY: the fixture retains its serialized capture and every
        // source fragment is a live NUL-terminated string during delivery.
        let state = unsafe { &*argument.cast::<Capture>() };
        let bytes = unsafe { CStr::from_ptr(message) }.to_bytes();
        state.thread_identity.store(crabc_core::thread::thread_pointer_identity(), Ordering::Relaxed);
        state.messages.lock().unwrap().push(bytes.to_vec());
        if bytes.starts_with(b"failed to reserve ") && state.disable_verbose_on_failure.load(Ordering::Relaxed) {
            option_set(SourceOption::Verbose as c_int, 0);
        }
        if !state.reenter_on.is_empty() && bytes.starts_with(state.reenter_on)
            && !state.entered.swap(true, Ordering::AcqRel)
        {
            let mut id = core::ptr::null_mut();
            // SAFETY: this distinct reservation writes only the local ID;
            // the outer callback retains the process arena owner.
            let nested = unsafe { crate::source_heap_api::reserve_os_memory_ex(
                crate::config::ARENA_MIN_SIZE, true, false, false, &mut id) };
            state.nested_ok.store(nested.value == 0 && !id.is_null(), Ordering::Release);
        }
    }

    fn setup(reenter_on: &'static [u8]) -> &'static Capture {
        // SAFETY: the static no-op route stays callable for process lifetime.
        assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(
            4096, unsafe { crate::__crabc_runtime::RuntimeStderrOutput::new(discard) }));
        assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
        option_set(SourceOption::ShowErrors as c_int, 0);
        option_set(SourceOption::MaxWarnings as c_int, 0);
        let state = std::boxed::Box::leak(std::boxed::Box::new(Capture {
            messages: Mutex::new(Vec::new()), reenter_on,
            entered: AtomicBool::new(false), nested_ok: AtomicBool::new(false),
            thread_identity: AtomicUsize::new(0),
            disable_verbose_on_failure: AtomicBool::new(false),
        }));
        // SAFETY: sole registration; this leaked capture remains live through
        // all outer and nested synchronous reservations in the fresh process.
        unsafe { register_output(Some(capture), core::ptr::from_ref(state).cast_mut().cast()) };
        state.messages.lock().unwrap().clear();
        state
    }

    fn reserve(size: usize) -> (c_int, bool) {
        let mut id = core::ptr::null_mut();
        // SAFETY: one local writable ID output.
        let result = unsafe { crate::source_heap_api::reserve_os_memory_ex(
            size, true, false, false, &mut id) };
        (result.value, id.is_null())
    }

    fn print_trace(name: &str, state: &Capture, result: (c_int, bool)) {
        let messages = state.messages.lock().unwrap();
        let fragments: Vec<std::string::String> = messages.iter().map(|message| {
            message.iter().map(|byte| std::format!("{byte:02x}")).collect()
        }).collect();
        std::println!("RESULT {name}={},{},{},{}", result.0, u8::from(result.1),
            u8::from(state.entered.load(Ordering::Acquire)), u8::from(state.nested_ok.load(Ordering::Acquire)));
        std::println!("TRACE {name}={}", fragments.join(":"));
        std::println!("THREAD {name}={:x}", state.thread_identity.load(Ordering::Relaxed));
    }

    #[test]
    fn public_regular_reservation_verbose_success_preserves_fragments_and_signed_gate() {
        crate::test_process::run_in_fresh_process(
            "source_options_api::regular_reservation_output_tests::public_regular_reservation_verbose_success_preserves_fragments_and_signed_gate",
            || {
                let state = setup(b"");
                for verbose in [0, 1, -1] {
                    option_set(SourceOption::Verbose as c_int, verbose);
                    state.messages.lock().unwrap().clear();
                    let result = reserve(crate::config::ARENA_MIN_SIZE + 1);
                    assert_eq!(result, (0, false));
                    let expected = if verbose == 0 { Vec::new() } else {
                        std::vec![b"mimalloc: ".to_vec(), b"reserved 32832 KiB memory\n".to_vec()]
                    };
                    assert_eq!(*state.messages.lock().unwrap(), expected);
                    print_trace(&std::format!("success.{verbose}"), state, result);
                }
            },
        );
    }

    #[test]
    fn public_regular_reservation_manage_failure_emits_verbose_after_warning() {
        crate::test_process::run_in_fresh_process(
            "source_options_api::regular_reservation_output_tests::public_regular_reservation_manage_failure_emits_verbose_after_warning",
            || {
                let state = setup(b"");
                option_set(SourceOption::Verbose as c_int, 1);
                let result = reserve(1);
                assert_eq!(result, (crabc_core::Errno::NOMEM.raw(), true));
                let messages = state.messages.lock().unwrap();
                assert_eq!(messages.len(), 4);
                assert!(messages[0].starts_with(b"mimalloc: warning: thread 0x"));
                assert_eq!(messages[1], b"cannot use OS memory since it is not large enough (size 64 KiB, minimum required is 32768 KiB)");
                assert_eq!(messages[2], b"mimalloc: ");
                assert_eq!(messages[3], b"failed to reserve 64 KiB memory\n");
                drop(messages);
                print_trace("failure.1", state, result);
            },
        );
    }

    fn recursive_reservation(test: &'static str, outer_size: usize, body: &'static [u8], child: bool) {
        crate::test_process::run_in_fresh_process(test, || {
            let state = setup(body);
            let child_id = child.then(|| crate::subproc::lifecycle::native_subproc_new().expect("live child"));
            if !child { option_set(SourceOption::Verbose as c_int, 1); }
            let (sent, received) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                let descriptor = crate::runtime_lifecycle::current_native_allocator_thread_descriptor();
                // SAFETY: this worker retains its exact native TLS descriptor.
                assert!(unsafe { crate::runtime_lifecycle::register_current_native_allocator_worker_descriptor(descriptor) });
                if let Some(id) = child_id {
                    // SAFETY: the parent retains this child through the worker
                    // and the worker owns its compiler-TLS membership roots.
                    assert_eq!(unsafe { crate::subproc::lifecycle::native_subproc_add_current_thread(id) },
                        Ok(crate::subproc::lifecycle::NativeChildThreadAdd::Added));
                    state.messages.lock().unwrap().clear();
                    option_set(SourceOption::Verbose as c_int, 1);
                }
                let main_count = crate::subproc::MainSubprocess::global().arena_backing().registry().count();
                sent.send(reserve(outer_size)).unwrap();
                if child_id.is_some() {
                    assert_eq!(crate::subproc::MainSubprocess::global().arena_backing().registry().count(), main_count);
                    option_set(SourceOption::Verbose as c_int, 0);
                    assert_eq!(crate::subproc::lifecycle::native_child_thread_done(), Some(Ok(())));
                }
            });
            let result = received.recv_timeout(std::time::Duration::from_secs(3))
                .expect("verbose callback permits a distinct regular reservation");
            worker.join().unwrap();
            assert_eq!(result, if outer_size == 1 { (crabc_core::Errno::NOMEM.raw(), true) } else { (0, false) });
            assert!(state.entered.load(Ordering::Acquire));
            assert!(state.nested_ok.load(Ordering::Acquire));
            if let Some(id) = child_id {
                // SAFETY: the sole child worker has completed; no child views
                // or clients survive this final owner release.
                assert_eq!(unsafe { crate::subproc::lifecycle::native_subproc_destroy(id) }, Ok(()));
            }
            let messages = state.messages.lock().unwrap();
            assert_eq!(&messages[messages.len() - 2..], [b"mimalloc: ".to_vec(), b"reserved 32768 KiB memory\n".to_vec()]);
            drop(messages);
            if !child { print_trace(if outer_size == 1 { "recursive.failure" } else { "recursive.success" }, state, result); }
        });
    }

    #[test]
    fn public_regular_reservation_success_verbose_callback_permits_recursive_reservation() {
        recursive_reservation(
            "source_options_api::regular_reservation_output_tests::public_regular_reservation_success_verbose_callback_permits_recursive_reservation",
            crate::config::ARENA_MIN_SIZE, b"reserved ", false);
    }

    #[test]
    fn public_regular_reservation_failure_verbose_callback_permits_recursive_reservation() {
        recursive_reservation(
            "source_options_api::regular_reservation_output_tests::public_regular_reservation_failure_verbose_callback_permits_recursive_reservation",
            1, b"failed to reserve ", false);
    }

    #[test]
    fn child_regular_reservation_success_verbose_callback_permits_recursive_reservation() {
        recursive_reservation(
            "source_options_api::regular_reservation_output_tests::child_regular_reservation_success_verbose_callback_permits_recursive_reservation",
            crate::config::ARENA_MIN_SIZE, b"reserved ", true);
    }

    #[test]
    fn child_regular_reservation_failure_verbose_callback_permits_recursive_reservation() {
        recursive_reservation(
            "source_options_api::regular_reservation_output_tests::child_regular_reservation_failure_verbose_callback_permits_recursive_reservation",
            1, b"failed to reserve ", true);
    }

    #[test]
    fn automatic_regular_reservation_failure_verbose_callback_precedes_fallback_gate() {
        crate::test_process::run_in_fresh_process(
            "source_options_api::regular_reservation_output_tests::automatic_regular_reservation_failure_verbose_callback_precedes_fallback_gate",
            || {
                let state = setup(b"failed to reserve ");
                state.disable_verbose_on_failure.store(true, Ordering::Relaxed);
                option_set(SourceOption::ArenaReserve as c_int, 512 * 1024);
                option_set(SourceOption::ArenaEagerCommit as c_int, 0);
                // SAFETY: the installed process output owner and option table
                // remain live for the process; this isolated issuer retains
                // its own complete arena group through every callback.
                let policy = std::boxed::Box::leak(std::boxed::Box::new(unsafe {
                    crate::os::VmPolicy::from_process_options(owner().unwrap())
                }));
                policy.finish_preloading();
                let subprocess = std::boxed::Box::leak(std::boxed::Box::new(crate::subproc::MainSubprocess::new()));
                let process = crate::os::VmProcess::new_main(policy, subprocess);
                let config = crate::os::MemoryConfig::from_observations(
                    crate::os::PageSize::new(4096).unwrap(), 1 << 20, true, false);
                option_set(SourceOption::Verbose as c_int, 1);
                let _fault = crate::os::fault::install(crate::os::fault::Plan::at(
                    crate::os::fault::Point::Commit, 1, crabc_core::Errno::IO));
                // SAFETY: this issuer owns the live policy, process, backing
                // and every published range; no source random field is borrowed.
                unsafe { subprocess.arena_backing().reserve_first_arena_with_random(
                    process, config, crate::config::ARENA_SLICE_SIZE, false, None) };
                assert!(state.entered.load(Ordering::Acquire));
                assert!(state.nested_ok.load(Ordering::Acquire));
                let arena = unsafe { subprocess.arena_backing().registry().arena_at(0) }.expect("fallback arena");
                assert_eq!(arena.total_size, 4 * crate::config::ARENA_MIN_SIZE);
                let messages = state.messages.lock().unwrap();
                assert_eq!(&messages[messages.len() - 2..],
                    [b"mimalloc: ".to_vec(), b"failed to reserve 524288 KiB memory\n".to_vec()]);
                assert_eq!(option_get(SourceOption::Verbose as c_int), 0);
            },
        );
    }

    #[test]
    fn automatic_regular_reservation_success_verbose_callback_permits_recursive_reservation() {
        crate::test_process::run_in_fresh_process(
            "source_options_api::regular_reservation_output_tests::automatic_regular_reservation_success_verbose_callback_permits_recursive_reservation",
            || {
                let state = setup(b"reserved ");
                option_set(SourceOption::Verbose as c_int, 1);
                let (sent, received) = std::sync::mpsc::channel();
                let worker = std::thread::spawn(move || {
                    let descriptor = crate::runtime_lifecycle::current_native_allocator_thread_descriptor();
                    // SAFETY: this worker retains its exact native TLS roots.
                    assert!(unsafe { crate::runtime_lifecycle::register_current_native_allocator_worker_descriptor(descriptor) });
                    let (binding, _) = crate::process_init::ProcessMainInitializationStorage::global()
                        .ready_child_subprocess_inputs().expect("ready process binding");
                    let backing = crate::subproc::MainSubprocess::global().arena_backing();
                    let config = binding.page_map().memory_config().unwrap();
                    let slices = crate::config::ARENA_MAX_CHUNK_OBJ_SIZE / crate::config::ARENA_SLICE_SIZE;
                    let search = crate::arena::ArenaSearch {
                        heap_sequence: 0, heap_count: 0, thread_sequence: 0, numa_node: -1,
                        requested: crate::arena::ArenaId::none(), allow_pinned: false,
                    };
                    // Consume only existing complete chunks. The later normal
                    // search must reserve without making an oversized bitmap
                    // request or inventing an allocator failure.
                    let mut existing = Vec::new();
                    while let Some(claim) = unsafe { backing.try_find_free(
                        search, slices, crate::config::ARENA_SLICE_SIZE, false) }
                    {
                        existing.push(claim);
                    }
                    // SAFETY: the process backing and policy are retained
                    // through this sole live claim; no teardown can overlap.
                    let claim = unsafe { backing.try_allocate_slices_with_random(
                        binding.process(), config, search, slices,
                        crate::config::ARENA_SLICE_SIZE, false, None) }.expect("automatic arena claim");
                    assert!(claim.release());
                    for claim in existing { assert!(claim.release()); }
                    sent.send(()).unwrap();
                });
                received.recv_timeout(std::time::Duration::from_secs(3))
                    .expect("automatic verbose delivery releases its reserve lock");
                worker.join().unwrap();
                assert!(state.entered.load(Ordering::Acquire));
                assert!(state.nested_ok.load(Ordering::Acquire));
            },
        );
    }
}
