//! x86 native-shadow process and selected-worker lifecycle bridge.
//!
//! Pinned mimalloc v3.5's Unix automatic thread route stores its private
//! default-Theap key with pthread and invokes `_mi_thread_done` from that key's
//! destructor.  The Rust engine instead needs libc to retain its compiler-TLS
//! owner until after user cleanup and pthread TSD destructors. This bridge
//! supplies that real selected-worker boundary; it is not a pthread-key
//! registry. Process initialization and the same-image ELF finalizer below
//! select the source's signed process-done behavior for both owned products.

use core::ffi::{c_char, c_int, c_void};
#[cfg(any(feature = "native-mimalloc-shadow-process-done-exit-test-audit", feature = "x86-owned-allocator-lifecycle-test-audit"))]
use core::sync::atomic::{AtomicU8, Ordering};

use crabc_mimalloc::__crabc_runtime::{
    NativeProcessStartupFacts, RuntimeStderrOutput, NativeProcessDestroyError, NativeProcessDoneAction,
    NativeProcessDoneInvocation, SelectedProcessDoneResult, ThreadAttachResult,
    ThreadFinalProcessExitOwnerResult, ThreadFinishResult,
    attach_current_thread, capture_native_process_destroy_request,
    finish_current_thread_native_after_user_destructors,
    finish_selected_default_release_process_after_user_atexit,
    initialize_process, prepare_native_later_thread_arena,
    publish_native_process_startup_facts,
    native_process_done_action, prepare_native_process_destroy,
    retain_current_thread_native_owner_after_process_done_nonfinal,
    reinitialize_current_thread_native_owner_for_final_process_exit,
    with_native_allocator_diagnostic_callback,
};
#[cfg(feature = "native-mimalloc-shadow-process-done-exit-test-audit")]
use crabc_mimalloc::__crabc_runtime::{
    native_runtime_process_done_terminal_purge_test_audit,
};

/// Child-side native attachment result for the create handshake.
///
/// Only `Rejected` proves that no compiler-TLS allocator owner was installed.
/// A retained, duplicate, or terminal owner cannot be reclaimed as a failed
/// pthread-create transaction because libc is about to release the same TLS
/// image that still contains it.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum SelectedWorkerNativeAttach {
    Attached,
    Rejected,
    Fatal,
}

/// Result retained by libc from the source-ordered worker finish to its
/// locked final-task decision.
///
/// Pinned Unix process shutdown deletes mimalloc's private automatic-done key.
/// A post-done worker therefore cannot run the ordinary Rust source teardown
/// before libc knows whether that same task will execute `atexit`: a nonfinal
/// task discards only its Rust wrapper before ELF TLS release, while a final
/// task keeps this active owner for the callbacks and `_exit` path.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum SelectedWorkerNativeFinish {
    Finished,
    ProcessDoneFinalTaskDecisionPending,
}

/// Send a source diagnostic fragment to the selected permanent `stderr`.
///
/// `stdio_standard`'s permanent stream has static backing and initializes its
/// buffer under its stream lock without allocating. Startup invokes this only
/// after the initial TLS and `environ` owners exist, before constructors can
/// start another selected worker.
unsafe extern "C" fn runtime_stderr_output(message: *const c_char) {
    // Publish the descriptor-local callback marker before acquiring `stderr`'s
    // foreign FILE lock. A terminal writer must observe that marker while it
    // drains ordinary source operations. The admission boundary refuses before
    // invoking this closure, so a rejected or incorrectly nested caller makes
    // no foreign `fputs` call. The terminal diagnostic scope supplied by the
    // transferred process owner uses this same narrow callback route without
    // reopening a native source operation.
    let _ = unsafe {
        with_native_allocator_diagnostic_callback(|| {
            let stream = unsafe { super::stdio_standard::stderr };
            let _ = unsafe { super::stdio_standard::fputs(message, stream) };
        })
    };
}

/// Raw source environment reader handed to the native allocator.
///
/// Pinned `src/prim/unix/prim.c:_mi_prim_getenv` reads the C `environ`
/// spelling directly. libc owns that weak alias of `__environ`, so it, not
/// the allocator engine, performs the read, preserving the exact symbol the
/// source observes. Each call returns the current vector; a later lazy option
/// retry therefore follows a coordinated `setenv` just as the source does.
unsafe fn runtime_source_environment() -> *const *const c_char {
    unsafe extern "C" {
        static mut environ: *mut *mut c_char;
    }
    // SAFETY: a raw word read of libc's own process environment global.
    // Startup installed the validated kernel vector before publication, and
    // later mutation keeps C's ordinary caller-coordination obligation.
    unsafe { core::ptr::read(core::ptr::addr_of!(environ)).cast_const().cast() }
}

/// Start the selected native process owner after x86 startup has installed
/// validated `environ`, `AT_PAGESZ`, initial TLS, and permanent `stderr`.
///
/// libc first publishes those raw facts to the engine, then performs the
/// explicit source startup that a lazy first allocation would otherwise run.
/// A false result makes selected owned startup reject before constructors:
/// process initialization can have published an owner before its later-arena
/// preparation discovers a retained source state. It must not continue with a
/// partially active native lifecycle, substitute C for a native pointer, or
/// admit workers. The same-image `.fini_array` entry below owns logical
/// process finalization; default teardown preserves live allocation backing.
pub(super) unsafe fn initialize_selected_process(page_size: usize) -> bool {
    let stderr_output = unsafe { RuntimeStderrOutput::new(runtime_stderr_output) };
    // SAFETY: `runtime_source_environment` reads libc's own `environ` for the
    // process lifetime, and `runtime_stderr_output` is the permanent
    // `stderr` provider documented above.
    let Some(facts) = (unsafe {
        NativeProcessStartupFacts::new(page_size, runtime_source_environment, stderr_output)
    }) else {
        return false;
    };
    let ready = publish_native_process_startup_facts(facts)
        && initialize_process()
        && prepare_native_later_thread_arena();
    #[cfg(feature = "x86-owned-allocator-lifecycle-test-audit")]
    if ready { ALLOCATOR_LIFECYCLE_PHASE.store(1, Ordering::Release); }
    ready
}

/// Attach one selected child before libc can invoke its user start routine.
///
/// The parent/child handshake in `pthread_create_join` returns ordinary
/// creation failure only for `Rejected`, whose absent owner is proved here.
/// `Fatal` terminates instead of reclaiming the child's mapped TLS/control
/// state because that image may still retain a native owner.
pub(super) fn attach_selected_worker() -> SelectedWorkerNativeAttach {
    match attach_current_thread() {
        ThreadAttachResult::Attached => SelectedWorkerNativeAttach::Attached,
        // Pinned mimalloc initializes a thread at its first allocation, and a
        // failed `_mi_thread_init` fails only that thread's allocations. The
        // runtime deferred this worker's attachment without publishing any
        // owner; the thread runs, its allocations retry the attachment, and
        // its finish completes cleanly.
        ThreadAttachResult::Deferred => SelectedWorkerNativeAttach::Attached,
        // `attach_current_thread` marks the just-published descriptor retired
        // when it observes Inactive. It returns before attachment/admission
        // installation, so this is the sole result whose native TLS owner is
        // proved absent and can enter the rejected-create reclaim path.
        ThreadAttachResult::Inactive => SelectedWorkerNativeAttach::Rejected,
        // A fresh Static Initial TLS v1 child cannot legitimately carry any
        // of these states. In particular Retained may still own a partial
        // attachment/admission, so it must fail-stop before TLS reclamation.
        ThreadAttachResult::AlreadyAttached
        | ThreadAttachResult::Reentrant
        | ThreadAttachResult::Finished
        | ThreadAttachResult::Retained => SelectedWorkerNativeAttach::Fatal,
    }
}

/// Finish the native compiler-TLS owner after user cleanup and selected TSD.
///
/// Reaching this with a nonattached, already-finished, or retained owner
/// contradicts the creation handshake. Do not return toward ELF TLS release
/// with that unresolved state: the runtime's retained native-owner path has
/// already fail-stopped, and every other contradiction terminates here too.
pub(super) unsafe fn finish_selected_worker_after_user_destructors() -> SelectedWorkerNativeFinish {
    match finish_current_thread_native_after_user_destructors() {
        ThreadFinishResult::Finished => SelectedWorkerNativeFinish::Finished,
        ThreadFinishResult::ProcessDoneFinalTaskDecisionPending => {
            SelectedWorkerNativeFinish::ProcessDoneFinalTaskDecisionPending
        }
        ThreadFinishResult::NotAttached
        | ThreadFinishResult::AlreadyFinished
        | ThreadFinishResult::Retained => super::immediate_termination::_Exit(134),
    }
}

/// Retire one post-process-done worker only after libc's final-task decision
/// proved another task remains.
pub(super) unsafe fn retain_selected_nonfinal_worker_after_process_done() {
    if !retain_current_thread_native_owner_after_process_done_nonfinal() {
        super::immediate_termination::_Exit(134);
    }
}

/// Recreate the final selected worker's native owner for ordinary-exit
/// callbacks after its completed source finish.
///
/// The caller has already made the locked final-task decision, restored its
/// application signal mask, and has not yet entered `static_startup::exit`.
/// Any other result preserves a contradictory or retained TLS image and must
/// fail-stop instead of letting a callback reach the native adapter without a
/// source owner.
pub(super) unsafe fn reinitialize_selected_final_worker_for_ordinary_exit() {
    // A deferred result has no owner: as in pinned mimalloc, the callbacks'
    // allocations retry the thread's failed metadata allocation.
    if !matches!(
        reinitialize_current_thread_native_owner_for_final_process_exit(),
        ThreadFinalProcessExitOwnerResult::Reinitialized | ThreadFinalProcessExitOwnerResult::Deferred
    ) {
        super::immediate_termination::_Exit(134);
    }
}

/// Result of the private libc adapter for pinned process-done dispatch.
///
/// This preserves the source's separate automatic and explicit decisions:
/// automatic `destroy_on_exit >= 2` skips process-done entirely, while an
/// explicit process-done call still selects destruction. `Retained` is the
/// existing default-release result, not a physical-destroy fallback.
#[derive(Clone, Copy, Eq, PartialEq)]
enum SelectedNativeProcessDoneResult {
    Completed,
    Destroyed,
    AlreadyCompleted,
    SkippedAutomatic,
    Retained,
}

/// Prepares and, only after dropping libc's existing worker-registry pin,
/// completes one source-selected physical process-destroy request.
///
/// The caller supplies the established finalizer or explicit-process-done
/// boundary after user callbacks. The `DestroyBacking` path snapshots its
/// immutable process witnesses before taking the existing registry pin. The
/// pinned callback performs only the process-owned terminal admission and TLS
/// source-owner transfer; `NativePreparedProcessDestroy` then leaves that
/// scope before its Heap, metadata, arena, PageMap, and OS work begins.
///
/// # Safety
/// The invocation is at the process-owned finalization boundary, after user
/// callbacks and outside every source borrow and outer libc lock. A physical
/// destroy failure is terminal: callers must not substitute the retaining
/// path or C allocator cleanup after this function reports an error.
unsafe fn finish_selected_native_process_after_user_atexit(
    invocation: NativeProcessDoneInvocation,
) -> Result<SelectedNativeProcessDoneResult, NativeProcessDestroyError> {
    match native_process_done_action(invocation)? {
        NativeProcessDoneAction::AlreadyCompleted => {
            Ok(SelectedNativeProcessDoneResult::AlreadyCompleted)
        }
        NativeProcessDoneAction::SkipAutomatic => {
            Ok(SelectedNativeProcessDoneResult::SkippedAutomatic)
        }
        NativeProcessDoneAction::RetainBacking => {
            Ok(match finish_selected_default_release_process_after_user_atexit() {
                SelectedProcessDoneResult::Completed => SelectedNativeProcessDoneResult::Completed,
                SelectedProcessDoneResult::AlreadyCompleted => {
                    SelectedNativeProcessDoneResult::AlreadyCompleted
                }
                SelectedProcessDoneResult::Retained => SelectedNativeProcessDoneResult::Retained,
            })
        }
        NativeProcessDoneAction::DestroyBacking => {
            // The request uses one ordinary source entry and drops it before
            // the existing libc worker-list lock is acquired.
            let request = capture_native_process_destroy_request()?;
            let prepared = unsafe {
                super::pthread_create_join::with_selected_native_allocator_pinned_registry(
                    |registry| unsafe { prepare_native_process_destroy(request, registry) },
                )
            }?;
            // The scoped registry callback above has returned and released
            // its pin. `finish` may now take its process-owned locks, map
            // tracking storage, and perform raw OS teardown without retaining
            // a libc list/control/TLS borrow.
            unsafe { prepared.finish() }?;
            Ok(SelectedNativeProcessDoneResult::Destroyed)
        }
    }
}

/// Runs the source-selected automatic process finalizer from the replacement
/// `.fini_array` entry.
///
/// Pinned mimalloc installs `_mi_auto_process_done` through a compiler
/// destructor. The selected C producer defines
/// `MI_PRIM_HAS_PROCESS_ATTACH=1`, suppressing that exact entry. This bridge
/// retains that same-image ELF transport: the static CRT walks the executable
/// array; the dynamic loader walks libc's array at its real dependency-graph
/// position, after ordinary atexit/main fini and before stdio flush. Independent
/// DSOs can finalize later than libc. The default and automatically suppressed
/// paths keep source backing available for those callbacks. Physical
/// destruction follows the signed source option and permanently denies later
/// native allocator entry.
unsafe extern "C" fn finish_selected_process_in_fini_array() {
    #[cfg(feature = "native-mimalloc-shadow-process-done-exit-test-audit")]
    if unsafe { crabc_x86_64_native_mimalloc_shadow_normal_main_user_atexit_observed() } != 1 {
        super::immediate_termination::_Exit(134);
    }
    match unsafe { finish_selected_native_process_after_user_atexit(NativeProcessDoneInvocation::Automatic) } {
        Ok(SelectedNativeProcessDoneResult::Completed) => {
            #[cfg(feature = "native-mimalloc-shadow-process-done-exit-test-audit")]
            {
                PROCESS_DONE_FINI_ARRAY_TEST_AUDIT.store(1, Ordering::Release);
                unsafe { crabc_x86_64_native_mimalloc_shadow_normal_main_process_done_fini_observed() };
            }
        }
        Ok(SelectedNativeProcessDoneResult::Destroyed) => {
            #[cfg(feature = "native-mimalloc-shadow-process-done-exit-test-audit")]
            {
                PROCESS_DONE_FINI_ARRAY_TEST_AUDIT.store(2, Ordering::Release);
                unsafe { crabc_x86_64_native_mimalloc_shadow_normal_main_process_done_fini_observed() };
            }
        }
        Ok(SelectedNativeProcessDoneResult::SkippedAutomatic) => {
            #[cfg(feature = "native-mimalloc-shadow-process-done-exit-test-audit")]
            PROCESS_DONE_FINI_ARRAY_TEST_AUDIT.store(3, Ordering::Release);
        }
        Ok(SelectedNativeProcessDoneResult::AlreadyCompleted) => {}
        Ok(SelectedNativeProcessDoneResult::Retained) | Err(_) => {
            super::immediate_termination::_Exit(134)
        }
    }
    #[cfg(feature = "x86-owned-allocator-lifecycle-test-audit")]
    ALLOCATOR_LIFECYCLE_PHASE.store(2, Ordering::Release);
}

// Startup and worker calls retain this module in the selected Rust object.
// `#[used]` preserves the private replacement entry for the CRT or loader fini
// walk. The dynamic local symbol permits producer verification; it is not a
// public ABI export. This entry is absent with the default C allocator.
#[used]
#[linkage = "internal"]
#[link_section = ".fini_array"]
#[cfg_attr(crabc_x86_dynamic_runtime, export_name = "__crabc_x86_native_mimalloc_process_finalizer")]
static SELECTED_PROCESS_DONE_FINI_ARRAY: unsafe extern "C" fn() =
    finish_selected_process_in_fini_array;

/// Test-only receipt for the selected `.fini_array` process finalizer.
///
/// The normal-main fixture's application destructor reads only this scalar
/// after it has allocated and freed a block. The feature-gated symbol proves
/// that user `atexit` preceded this bridge and this bridge preceded that
/// later application destructor without publishing allocator state.
#[cfg(feature = "native-mimalloc-shadow-process-done-exit-test-audit")]
static PROCESS_DONE_FINI_ARRAY_TEST_AUDIT: AtomicU8 = AtomicU8::new(0);

#[cfg(feature = "native-mimalloc-shadow-process-done-exit-test-audit")]
unsafe extern "C" {
    fn crabc_x86_64_native_mimalloc_shadow_normal_main_user_atexit_observed() -> c_int;
    fn crabc_x86_64_native_mimalloc_shadow_normal_main_process_done_fini_observed();
}

#[cfg(feature = "native-mimalloc-shadow-process-done-exit-test-audit")]
#[no_mangle]
pub extern "C" fn __crabc_x86_native_mimalloc_process_done_fini_array_test_audit() -> c_int {
    c_int::from(PROCESS_DONE_FINI_ARRAY_TEST_AUDIT.load(Ordering::Acquire))
}

/// Scalar-only selected process-done purge receipt for the normal-main
/// fixture. This is absent from ordinary selected archives and never exposes
/// a mapping or VM owner.
#[cfg(feature = "native-mimalloc-shadow-process-done-exit-test-audit")]
#[repr(C)]
pub struct ProcessDoneTerminalPurgeAudit {
    pub terminal_preloading: usize,
    pub purge_decommits_enabled: usize,
    pub mapping_retained_before_release: usize,
    pub purge_needs_recommit: usize,
    pub purge_calls_delta: usize,
    pub purged_bytes_delta: usize,
    pub reset_calls_delta: usize,
    pub reset_bytes_delta: usize,
    pub release_succeeded: usize,
}

/// Observes the process-done reset-purge consequence through one transient,
/// retained-process mapping.
///
/// # Safety
///
/// `output` must point to writable [`ProcessDoneTerminalPurgeAudit`] storage.
/// The normal-main fixture calls this only after the selected `.fini_array`
/// bridge and with no concurrent allocator statistics writer, so its deltas
/// describe this one audit operation.
#[cfg(feature = "native-mimalloc-shadow-process-done-exit-test-audit")]
#[no_mangle]
pub unsafe extern "C" fn __crabc_x86_native_mimalloc_process_done_terminal_purge_test_audit(
    output: *mut ProcessDoneTerminalPurgeAudit,
) -> c_int {
    let Some(output) = core::ptr::NonNull::new(output) else {
        return -1;
    };
    let audit = match native_runtime_process_done_terminal_purge_test_audit() {
        Ok(audit) => audit,
        Err(error) => return error,
    };
    // SAFETY: the caller's documented writable output contract holds for this
    // scalar-only copy; neither Rust audit structure contains an address or
    // retained source capability.
    unsafe {
        output.as_ptr().write(ProcessDoneTerminalPurgeAudit {
            terminal_preloading: audit.terminal_preloading,
            purge_decommits_enabled: audit.purge_decommits_enabled,
            mapping_retained_before_release: audit.mapping_retained_before_release,
            purge_needs_recommit: audit.purge_needs_recommit,
            purge_calls_delta: audit.purge_calls_delta,
            purged_bytes_delta: audit.purged_bytes_delta,
            reset_calls_delta: audit.reset_calls_delta,
            reset_bytes_delta: audit.reset_bytes_delta,
            release_succeeded: audit.release_succeeded,
        });
    }
    0
}

/// Test-only observation of the engine's active later-worker admission count.
///
/// This is a fixture bridge, not a libc interface. It stays absent from an
/// ordinary native-selected archive and lets the end-to-end worker fixture
/// prove that each post-user-destructor finish returns admission to baseline.
#[cfg(feature = "native-mimalloc-shadow-test-audit")]
#[no_mangle]
pub extern "C" fn __crabc_x86_native_mimalloc_active_later_thread_count_test_audit() -> usize {
    crabc_mimalloc::__crabc_runtime::native_runtime_fork_admission_test_audit()
        .active_later_thread_count
}

/// Fixture-only scalar for the raw same-TP local-free dispatch condition.
#[cfg(feature = "native-mimalloc-shadow-test-audit")]
#[no_mangle]
pub extern "C" fn __crabc_x86_native_mimalloc_process_done_retained_worker_matches_current_thread_test_audit(
) -> i32 {
    i32::from(
        crabc_mimalloc::__crabc_runtime::native_runtime_process_done_retained_worker_matches_current_thread_test_audit(),
    )
}

/// Fixture-only nonmutating retained-source local-free preflight.
///
/// It returns a diagnostic scalar only; the C fixture still calls ordinary
/// `free`, which is the production pointer-first adapter under test.
///
/// # Safety
///
/// `block` must be one exact, still-live native client of the attached worker.
/// The caller must serialize this scalar read with free, allocation,
/// collection, PageMap, queue, and owner mutation.
#[cfg(feature = "native-mimalloc-shadow-test-audit")]
#[no_mangle]
pub unsafe extern "C" fn __crabc_x86_native_mimalloc_process_done_retained_local_preflight_test_audit(
    block: *mut c_void,
) -> i32 {
    let Some(block) = core::ptr::NonNull::new(block.cast::<u8>()) else {
        return -1;
    };
    // SAFETY: the fixture passes one exact still-live native client before
    // its ordinary `free`; the crabc-mimalloc hook observes it without
    // mutating its source PageMap, Theap, queue, or free-list state.
    unsafe {
        crabc_mimalloc::__crabc_runtime::native_runtime_process_done_retained_local_preflight_test_audit(block)
    }
}

/// Fixture-only phase observation for one live retained old-Theap sibling.
///
/// The C layout deliberately contains scalar facts only. It neither exposes
/// the source page, its queue, nor the retained Theap address.
#[cfg(feature = "native-mimalloc-shadow-test-audit")]
#[repr(C)]
pub struct ProcessDoneRetainedLocalPageAudit {
    pub in_full: usize,
    pub has_interior_pointers: usize,
    pub used: usize,
    pub capacity: usize,
    pub reserved: usize,
    pub regular_queue_count: usize,
    pub full_queue_count: usize,
    pub theap_page_count: usize,
    pub member_link_coherent: usize,
}

/// Fixture-only scalar snapshot of the attached worker's current local page.
///
/// It lets the C probe fill the source-reserved count before it retains the
/// worker, so an on-demand capacity extension cannot be mistaken for a full
/// page. The output has the same scalar-only layout as the retained snapshot.
///
/// # Safety
///
/// `block` must be an exact live native client of the attached worker and
/// `output` must name writable `ProcessDoneRetainedLocalPageAudit` storage.
/// The caller must serialize the copy with source page, queue, and owner
/// mutation and must not retain any source-derived state from its scalar fields.
#[cfg(feature = "native-mimalloc-shadow-test-audit")]
#[no_mangle]
pub unsafe extern "C" fn __crabc_x86_native_mimalloc_current_local_page_test_audit(
    block: *mut c_void,
    output: *mut ProcessDoneRetainedLocalPageAudit,
) -> i32 {
    let Some(block) = core::ptr::NonNull::new(block.cast::<u8>()) else {
        return -1;
    };
    let Some(output) = core::ptr::NonNull::new(output) else {
        return -1;
    };
    // SAFETY: the fixture's attached worker owns this exact live client and
    // serializes the scalar read against every source page/queue mutation.
    let audit = match unsafe {
        crabc_mimalloc::__crabc_runtime::native_runtime_current_local_page_test_audit(block)
    } {
        Ok(audit) => audit,
        Err(error) => return error,
    };
    // SAFETY: `output` is the C fixture's writable stack object and this
    // scalar copy retains no Rust projection or source capability.
    unsafe {
        output.as_ptr().write(ProcessDoneRetainedLocalPageAudit {
            in_full: audit.in_full,
            has_interior_pointers: audit.has_interior_pointers,
            used: audit.used,
            capacity: audit.capacity,
            reserved: audit.reserved,
            regular_queue_count: audit.regular_queue_count,
            full_queue_count: audit.full_queue_count,
            theap_page_count: audit.theap_page_count,
            member_link_coherent: audit.member_link_coherent,
        });
    }
    1
}

/// Fixture-only same-page predicate for two current attached-worker clients.
///
/// It returns only a scalar relation: one means the source page is the same,
/// zero means distinct, and negatives reject the exact-live/current-owner
/// preconditions. No page identity or allocator capability crosses this C
/// test boundary.
///
/// # Safety
///
/// Both pointers must be exact, still-live native clients of the current
/// attached worker. The caller must serialize the PageMap/owner relation with
/// frees, allocation, collection, and worker teardown for the whole call.
#[cfg(feature = "native-mimalloc-shadow-test-audit")]
#[no_mangle]
pub unsafe extern "C" fn __crabc_x86_native_mimalloc_current_local_page_same_test_audit(
    first: *mut c_void,
    second: *mut c_void,
) -> i32 {
    let Some(first) = core::ptr::NonNull::new(first.cast::<u8>()) else {
        return -1;
    };
    let Some(second) = core::ptr::NonNull::new(second.cast::<u8>()) else {
        return -1;
    };
    // SAFETY: the fixture passes two exact live current-worker clients and
    // serializes the source PageMap while the relation is copied.
    match unsafe {
        crabc_mimalloc::__crabc_runtime::native_runtime_current_local_page_same_test_audit(
            first, second,
        )
    } {
        Ok(same) => i32::from(same),
        Err(error) => error,
    }
}

/// Fixture-only scalar snapshot for the exact retained local-free page.
///
/// The output pointer is written only after all live-client, retained-owner,
/// and source queue prerequisites were checked. The fixture owns the
/// quiescent boundary and uses the fields only to compare pinned source state.
///
/// # Safety
///
/// `block` must be one exact still-live client of the retained old-Theap page
/// and `output` must name writable scalar-audit storage. The caller must hold
/// the fixture's quiescent boundary against free, allocation, collection,
/// PageMap, queue, and retained-owner mutation for the complete copy.
#[cfg(feature = "native-mimalloc-shadow-test-audit")]
#[no_mangle]
pub unsafe extern "C" fn __crabc_x86_native_mimalloc_process_done_retained_local_page_test_audit(
    block: *mut c_void,
    output: *mut ProcessDoneRetainedLocalPageAudit,
) -> i32 {
    let Some(block) = core::ptr::NonNull::new(block.cast::<u8>()) else {
        return -1;
    };
    let Some(output) = core::ptr::NonNull::new(output) else {
        return -1;
    };
    // SAFETY: the fixture supplies one exact still-live client and serializes
    // this copy against source page/queue mutation. The returned structure is
    // scalar-only and cannot act as a retained source capability.
    let audit = match unsafe {
        crabc_mimalloc::__crabc_runtime::native_runtime_process_done_retained_local_page_test_audit(block)
    } {
        Ok(audit) => audit,
        Err(error) => return error,
    };
    // SAFETY: the nonnull output names the C fixture's writable stack object;
    // no Rust reference escapes this one scalar copy.
    unsafe {
        output.as_ptr().write(ProcessDoneRetainedLocalPageAudit {
            in_full: audit.in_full,
            has_interior_pointers: audit.has_interior_pointers,
            used: audit.used,
            capacity: audit.capacity,
            reserved: audit.reserved,
            regular_queue_count: audit.regular_queue_count,
            full_queue_count: audit.full_queue_count,
            theap_page_count: audit.theap_page_count,
            member_link_coherent: audit.member_link_coherent,
        });
    }
    1
}

/// Fixture-only source-retirement observation after a retained page's final
/// local free.
///
/// # Safety
///
/// `former_client` must be the exact former client from the immediately
/// preceding retained local free. `expected_reserved` must be the pinned-C
/// release geometry: 42 for the normal/256-byte pair or 25 for the interior
/// pair. The caller must exclude allocation, collection, PageMap registration
/// or unregistration, queue/owner mutation, and page reuse until this check
/// completes; the pointer is geometry only and must never be dereferenced.
#[cfg(feature = "native-mimalloc-shadow-test-audit")]
#[no_mangle]
pub unsafe extern "C" fn __crabc_x86_native_mimalloc_process_done_retained_page_retired_test_audit(
    former_client: *mut c_void,
    expected_reserved: usize,
) -> i32 {
    let Some(former_client) = core::ptr::NonNull::new(former_client.cast::<u8>()) else {
        return 0;
    };
    // SAFETY: the fixture uses this former client solely as PageMap geometry
    // immediately after its final local free, before a source collection or
    // allocation can reuse its retired page.
    i32::from(unsafe {
        crabc_mimalloc::__crabc_runtime::native_runtime_process_done_retained_page_retired_test_audit(
            former_client,
            expected_reserved,
        )
    })
}

/// Fixture-only request for the selected logical process-done boundary.
///
/// The native-shadow pthread probe invokes this while its initial task is
/// still alive, then creates sequential workers and observes source-retained
/// page/free behavior. This is absent from ordinary selected archives and is
/// not a public `mi_process_done` replacement.
#[cfg(feature = "native-mimalloc-shadow-test-audit")]
#[no_mangle]
pub extern "C" fn __crabc_x86_native_mimalloc_process_done_test_audit() -> i32 {
    match finish_selected_default_release_process_after_user_atexit() {
        SelectedProcessDoneResult::Completed => 0,
        SelectedProcessDoneResult::AlreadyCompleted => 1,
        SelectedProcessDoneResult::Retained => -1,
    }
}

/// Test-only request for the explicit physical process-destroy adapter.
///
/// This isolated hook is intentionally distinct from the retained-process
/// probe above and from the production automatic `.fini_array` finalizer. It
/// lets the installed native fixture validate the capture -> pinned prepare ->
/// unpinned finish handoff with a fresh selected process and signed nonzero
/// option independently of the automatic finalizer.
#[cfg(feature = "native-mimalloc-shadow-test-audit")]
#[no_mangle]
pub extern "C" fn __crabc_x86_native_mimalloc_process_destroy_test_audit() -> i32 {
    match unsafe {
        finish_selected_native_process_after_user_atexit(NativeProcessDoneInvocation::Explicit)
    } {
        Ok(SelectedNativeProcessDoneResult::Destroyed)
        | Ok(SelectedNativeProcessDoneResult::Completed) => 0,
        Ok(SelectedNativeProcessDoneResult::AlreadyCompleted) => 1,
        Ok(SelectedNativeProcessDoneResult::SkippedAutomatic)
        | Ok(SelectedNativeProcessDoneResult::Retained)
        | Err(_) => -1,
    }
}

/// Fixture-only retained-source observation for the post-process-done worker.
///
/// The C probe supplies its exact still-live native clients after `join`; the
/// Rust audit returns only a pass/fail scalar for the retained TLD/Theap/page
/// relation and pointer-first remote publication. No address or allocator
/// capability crosses this bridge.
///
/// # Safety
///
/// `second`, and `first` when nonnull, must be exact live native clients from
/// the retained worker page. The caller must serialize the audited PageMap,
/// owner, queue, and remote-publication state with frees, allocation,
/// collection, registration, and worker teardown for the complete call.
#[cfg(feature = "native-mimalloc-shadow-test-audit")]
#[no_mangle]
pub unsafe extern "C" fn __crabc_x86_native_mimalloc_process_done_retained_page_test_audit(
    first: *mut c_void,
    second: *mut c_void,
    remote_free_published: i32,
) -> i32 {
    let first = core::ptr::NonNull::new(first.cast::<u8>());
    let Some(second) = core::ptr::NonNull::new(second.cast::<u8>()) else {
        return 0;
    };
    // SAFETY: the fixture documents that `second`, and `first` when present,
    // are exact live native clients at a joined-worker quiescent boundary.
    i32::from(unsafe {
        crabc_mimalloc::__crabc_runtime::native_runtime_process_done_retained_live_page_test_audit(
            first,
            second,
            remote_free_published != 0,
        )
    })
}

// Phase-only development evidence; absent from ordinary allocator products.
#[cfg(feature = "x86-owned-allocator-lifecycle-test-audit")]
static ALLOCATOR_LIFECYCLE_PHASE: AtomicU8 = AtomicU8::new(0);

#[cfg(feature = "x86-owned-allocator-lifecycle-test-audit")]
#[no_mangle]
pub extern "C" fn __crabc_x86_owned_allocator_lifecycle_test_phase() -> c_int {
    c_int::from(ALLOCATOR_LIFECYCLE_PHASE.load(Ordering::Acquire))
}

/// Scalar process-wide allocator state for installed native soak fixtures.
///
/// Each field copies one `NativeRuntimeLifecycleAudit` count: registered
/// PageMap slices and published submaps, registered arenas, live source
/// threads (TLDs), live and high-water metadata capabilities, later-thread
/// Theaps on the shared main Heap, and main-Heap abandoned pages. No address
/// or capability crosses this ABI. The snapshot is meaningful only while no
/// other thread is inside the allocator.
#[cfg(feature = "x86-owned-allocator-lifecycle-test-audit")]
#[repr(C)]
pub struct ProcessAllocatorTestAudit {
    pub page_map_registered_entries: usize,
    pub page_map_published_submaps: usize,
    pub arena_registry_count: usize,
    pub live_thread_count: usize,
    pub metadata_live_capabilities: usize,
    pub metadata_high_water_capabilities: usize,
    pub shared_later_theaps: usize,
    pub main_heap_abandoned_pages: usize,
}

/// Copies [`ProcessAllocatorTestAudit`]; returns -1 when the runtime has no
/// auditable active image.
///
/// # Safety
/// `output` names writable `ProcessAllocatorTestAudit` storage. The call
/// enters one ordinary allocator operation and allocates nothing.
#[cfg(feature = "x86-owned-allocator-lifecycle-test-audit")]
#[no_mangle]
pub unsafe extern "C" fn __crabc_x86_owned_allocator_process_test_audit(
    output: *mut ProcessAllocatorTestAudit,
) -> c_int {
    let Some(output) = core::ptr::NonNull::new(output) else { return -1; };
    let Some(audit) = crabc_mimalloc::__crabc_runtime::native_runtime_lifecycle_test_audit() else {
        return -1;
    };
    // SAFETY: the caller supplies writable storage for this scalar copy.
    unsafe {
        output.as_ptr().write(ProcessAllocatorTestAudit {
            page_map_registered_entries: audit.page_map_registered_entry_count,
            page_map_published_submaps: audit.page_map_published_submap_count,
            arena_registry_count: audit.arena_registry_count,
            live_thread_count: audit.live_thread_count,
            metadata_live_capabilities: audit.metadata_live_capability_count,
            metadata_high_water_capabilities: audit.metadata_high_water_capability_count,
            shared_later_theaps: audit.shared_later_theap_count,
            main_heap_abandoned_pages: audit.main_heap_abandoned_page_count,
        });
    }
    0
}

/// Scalar worker-owner state for installed native lifecycle fixtures.
///
/// `owner_installed` is one while the calling worker's persistent native
/// owner is attached (zero for the initial task, whose owner is separate).
/// `page_engine_active` reports whether that owner has started a page engine,
/// i.e. has allocated. The two counts are process-wide: attached later-worker
/// owners, and descriptor-bearing workers whose TLS, stack and control
/// mappings libc has released. No address or capability crosses this ABI.
#[cfg(feature = "x86-owned-allocator-lifecycle-test-audit")]
#[repr(C)]
pub struct WorkerOwnerLifecycleAudit {
    pub owner_installed: usize,
    pub page_engine_active: usize,
    pub attached_worker_owners: usize,
    pub reclaimed_worker_descriptors: usize,
}

/// Copies [`WorkerOwnerLifecycleAudit`] for the calling thread.
///
/// # Safety
/// `output` names writable `WorkerOwnerLifecycleAudit` storage. The call
/// enters one ordinary allocator operation and allocates nothing.
#[cfg(feature = "x86-owned-allocator-lifecycle-test-audit")]
#[no_mangle]
pub unsafe extern "C" fn __crabc_x86_owned_allocator_worker_owner_test_audit(
    output: *mut WorkerOwnerLifecycleAudit,
) -> c_int {
    let Some(output) = core::ptr::NonNull::new(output) else { return -1; };
    let current = crabc_mimalloc::__crabc_runtime::native_runtime_current_thread_attachment_test_audit();
    let admission = crabc_mimalloc::__crabc_runtime::native_runtime_fork_admission_test_audit();
    // SAFETY: the caller supplies writable storage for this scalar copy.
    unsafe {
        output.as_ptr().write(WorkerOwnerLifecycleAudit {
            owner_installed: current.persistent_owner_installed,
            page_engine_active: current.page_engine_active,
            attached_worker_owners: admission.active_later_thread_count,
            reclaimed_worker_descriptors:
                super::pthread_create_join::native_mimalloc_reclaimed_worker_descriptor_count(),
        });
    }
    0
}
