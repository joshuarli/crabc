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
    unsafe { super::process_globals::install(argc, argv) };
    true
}

pub(super) unsafe fn flush_on_exit() {
    unsafe { super::stdio_standard::flush_all_on_exit() };
}
