//! Installed shared-libc process composition over the canonical x86 leaves.
//!
//! This module selects lifecycle ownership, not a second libc implementation.
//! The same errno, allocator, environment, pthread and FILE registries remain
//! siblings in the target root. Loader initial TLS is retained for all workers;
//! runtime module growth and unloading remain separate loader work.

use super::{auxv_observation, environment, errno, immediate_termination, startup_security};
#[path = "process_exit.rs"]
mod process_exit;
#[path = "dynamic_main_thread_runtime_v1_lifecycle.rs"]
mod startup;

pub(super) unsafe fn prepare(argc: core::ffi::c_int, argv: *const *const core::ffi::c_char) -> bool {
    if !unsafe { super::static_tls::attach_initial_thread() } { return false; }
    // SAFETY: the dynamic TLS owner installed this initial task's concrete
    // FS+32 cache word above.  Publish the process-lifetime cancellation
    // state before process globals or executable constructors are visible;
    // the signal handler and delivery transaction remain a separate owner.
    unsafe { super::pthread_create_join::publish_initial_selected_pthread_cancellation_state() };
    unsafe { super::process_globals::install(argc, argv) };
    true
}

pub(super) unsafe fn flush_on_exit() {
    unsafe { super::stdio_standard::flush_all_on_exit() };
}

/// Complete ordinary process exit for the final selected pthread task.
///
/// The shared pthread registry has committed the unique final live task after
/// cleanup/TSD teardown. This startup owner still owns process registrations,
/// executable and loader finalization, and buffered stdio; the loader's main
/// TLS mapping remains process-lifetime storage throughout those callbacks.
pub(super) unsafe fn exit(status: core::ffi::c_int) -> ! {
    unsafe { startup::exit(status) }
}
