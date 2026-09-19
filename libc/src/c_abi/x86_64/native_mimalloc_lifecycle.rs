//! x86 native-shadow process and selected-worker lifecycle bridge.
//!
//! Pinned mimalloc v3.5's Unix automatic thread route stores its private
//! default-Theap key with pthread and invokes `_mi_thread_done` from that key's
//! destructor.  The Rust engine instead needs libc to retain its compiler-TLS
//! owner until after user cleanup and pthread TSD destructors.  This bridge
//! supplies that real selected-worker boundary; it is not a pthread-key
//! registry, and it does not touch mimalloc's internal dynamic TLS-key
//! registry or process shutdown.

use core::ffi::c_char;

use crabc_mimalloc::__crabc_runtime::{
    RuntimeStderrOutput, ThreadAttachResult, ThreadFinalProcessExitOwnerResult, ThreadFinishResult,
    attach_current_thread, finish_current_thread_native_after_user_destructors,
    initialize_process, prepare_native_later_thread_arena, process_is_active,
    reinitialize_current_thread_native_owner_for_final_process_exit,
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

/// Send a source diagnostic fragment to the selected permanent `stderr`.
///
/// `stdio_standard`'s permanent stream has static backing and initializes its
/// buffer under its stream lock without allocating. Startup invokes this only
/// after the initial TLS and `environ` owners exist, before constructors can
/// start another selected worker.
unsafe extern "C" fn runtime_stderr_output(message: *const c_char) {
    let stream = unsafe { super::stdio_standard::stderr };
    let _ = unsafe { super::stdio_standard::fputs(message, stream) };
}

/// Start the selected native process owner after x86 startup has installed
/// validated `environ`, `AT_PAGESZ`, initial TLS, and permanent `stderr`.
///
/// A false result makes selected static startup reject before constructors:
/// process initialization can have published an owner before its later-arena
/// preparation discovers a retained source state. It must not continue with a
/// partially active native lifecycle, substitute C for a native pointer, or
/// admit workers. This bridge intentionally installs no process exit callback:
/// upstream process teardown deletes its automatic key, but default teardown
/// does not free live allocations, and this worker slice has no process-
/// shutdown qualification.
pub(super) unsafe fn initialize_selected_process(page_size: usize) -> bool {
    let stderr_output = unsafe { RuntimeStderrOutput::new(runtime_stderr_output) };
    initialize_process(page_size, stderr_output) && prepare_native_later_thread_arena()
}

/// Attach one selected child before libc can invoke its user start routine.
///
/// The parent/child handshake in `pthread_create_join` returns ordinary
/// creation failure only for `Rejected`, whose absent owner is proved here.
/// `Fatal` terminates instead of reclaiming the child's mapped TLS/control
/// state because that image may still retain a native owner.
pub(super) fn attach_selected_worker() -> SelectedWorkerNativeAttach {
    if !process_is_active() {
        return SelectedWorkerNativeAttach::Rejected;
    }
    match attach_current_thread() {
        ThreadAttachResult::Attached => SelectedWorkerNativeAttach::Attached,
        // `Inactive` returns before attachment/admission installation. It is
        // the sole runtime result whose native TLS owner is proved absent.
        ThreadAttachResult::Inactive => SelectedWorkerNativeAttach::Rejected,
        // A fresh Static Initial TLS v1 child cannot legitimately carry any
        // of these states. In particular Retained may still own a partial
        // attachment/admission, so it must fail-stop before TLS reclamation.
        ThreadAttachResult::AlreadyAttached
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
pub(super) unsafe fn finish_selected_worker_after_user_destructors() {
    if finish_current_thread_native_after_user_destructors() != ThreadFinishResult::Finished {
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
    if reinitialize_current_thread_native_owner_for_final_process_exit()
        != ThreadFinalProcessExitOwnerResult::Reinitialized
    {
        super::immediate_termination::_Exit(134);
    }
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
