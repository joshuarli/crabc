//! Bounded Linux/x86-64 static `pthread_getconcurrency` artifact.
//!
//! This private static ABI leaf is a source-specific semantic port of pinned
//! musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
//! under musl's MIT license recorded in `COPYRIGHT`:
//!
//! - `src/thread/pthread_getconcurrency.c::pthread_getconcurrency` returns
//!   zero directly.
//!
//! Musl does not retain a concurrency setting for this query. The selected
//! entry therefore consumes no caller input, thread record, scheduler state,
//! or process-global state, and it neither calls nor needs
//! `pthread_setconcurrency`. This entry has no errno/TLS, syscall, allocator,
//! synchronization, cancellation, thread-lifecycle, or runtime dependency.
//! It is a private selected static artifact, not a pthread runtime, scheduler
//! contract, family completion, or public x86 support claim.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread getconcurrency leaf requires little-endian Linux/x86-64");

use core::ffi::c_int;

/// Return musl's fixed no-concurrency-setting status.
///
/// The selected entry is a direct zero result: it reads and writes neither a
/// public record nor a retained setting, and it does not publish through
/// `errno`.
#[no_mangle]
pub extern "C" fn pthread_getconcurrency() -> c_int {
    0
}
