//! Musl-hosted native runtime test input.
//!
//! This support module is compiled only by integration tests. It is not a
//! production allocator transport and does not claim crabc's selected x86 FILE
//! integration. The pinned native harness provides musl's `fputs(message,
//! stderr)` boundary for the explicit private M7 capability.

#[cfg(target_arch = "x86_64")]
use core::ffi::{c_char, c_int, c_void};

#[cfg(target_arch = "x86_64")]
use crabc_mimalloc::__crabc_runtime::{RuntimeStderrOutput, initialize_process};
#[cfg(target_arch = "aarch64")]
use crabc_mimalloc::__crabc_runtime::initialize_process;

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    fn fputs(message: *const c_char, stream: *mut c_void) -> c_int;
    static mut stderr: *mut c_void;
}

#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn musl_fputs_stderr(message: *const c_char) {
    // SAFETY: the capability constructor requires a process-lifetime C FILE
    // provider. The native test harness links musl, keeps `stderr` live, and
    // passes the owner's non-null NUL-terminated source fragment. Pinned
    // `_mi_prim_out_stderr` ignores fputs's integer result.
    unsafe {
        let _ = fputs(message, stderr);
    }
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn stderr_output() -> RuntimeStderrOutput {
    // SAFETY: `musl_fputs_stderr` has the source callback shape and the test
    // process retains its musl stderr object through allocator startup.
    unsafe { RuntimeStderrOutput::new(musl_fputs_stderr) }
}

/// Starts the private runtime using the selected test-only capability shape.
/// AArch64 retains its frozen one-argument initialization surface.
#[cfg(target_arch = "x86_64")]
#[inline]
pub(crate) fn initialize(page_size_bytes: usize) -> bool {
    initialize_process(page_size_bytes, stderr_output())
}

#[cfg(target_arch = "aarch64")]
#[inline]
pub(crate) fn initialize(page_size_bytes: usize) -> bool {
    initialize_process(page_size_bytes)
}
