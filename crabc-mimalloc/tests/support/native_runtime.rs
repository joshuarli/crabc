//! Musl-hosted native runtime test input.
//!
//! This support module is compiled only by integration tests. It is not a
//! production allocator transport and does not claim crabc's selected x86 FILE
//! integration. The pinned native harness provides musl's `fputs(message,
//! stderr)` boundary for the explicit private M7 capability.

#[cfg(target_arch = "x86_64")]
use core::ffi::{c_char, c_int, c_void};

#[cfg(target_arch = "x86_64")]
use crabc_mimalloc::__crabc_runtime::{
    NativeProcessStartupFacts, RuntimeStderrOutput, initialize_process,
    publish_native_process_startup_facts,
};
#[cfg(target_arch = "aarch64")]
use crabc_mimalloc::__crabc_runtime::initialize_process;

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    fn fputs(message: *const c_char, stream: *mut c_void) -> c_int;
    static mut stderr: *mut c_void;
    static mut environ: *mut *mut c_char;
}

/// The musl-hosted test process's own C `environ`, supplied as the runtime's
/// raw source environment reader. The engine itself never names `environ`.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn host_environment() -> *const *const c_char {
    // SAFETY: this reads the fixture process's C global word only. Fixtures
    // that set options do so before startup, as direct C mutation requires.
    unsafe { core::ptr::read(core::ptr::addr_of!(environ)).cast_const().cast() }
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
pub(crate) fn stderr_output() -> RuntimeStderrOutput {
    // SAFETY: `musl_fputs_stderr` has the source callback shape and the test
    // process retains its musl stderr object through allocator startup.
    unsafe { RuntimeStderrOutput::new(musl_fputs_stderr) }
}

/// Starts the private runtime using the selected test-only capability shape:
/// publish the host process's raw startup facts, then start explicitly.
/// A repeated call keeps the first published image and reports whether the
/// already-started process remains usable from this thread. AArch64 retains
/// its frozen one-argument initialization surface.
#[cfg(target_arch = "x86_64")]
#[inline]
pub(crate) fn initialize(page_size_bytes: usize) -> bool {
    // SAFETY: `host_environment` reads this process's live `environ`, and
    // `stderr_output` is the process-lifetime musl FILE fixture.
    let Some(facts) = (unsafe {
        NativeProcessStartupFacts::new(page_size_bytes, host_environment, stderr_output())
    }) else {
        return false;
    };
    let _ = publish_native_process_startup_facts(facts);
    initialize_process()
}

#[cfg(target_arch = "aarch64")]
#[inline]
pub(crate) fn initialize(page_size_bytes: usize) -> bool {
    initialize_process(page_size_bytes)
}

/// Attaches the calling test thread the way libc's x86-64 pthread start does.
///
/// Selected libc publishes and registers the worker's allocator-TLS descriptor
/// before its first allocator entry; an unregistered descriptor is refused by
/// the operation admission and reports `Inactive`. A std test thread has no
/// libc start routine, so this performs that registration first. It is
/// idempotent for an already registered thread, including the initial one.
#[cfg(target_arch = "x86_64")]
pub(crate) fn attach_current_thread() -> crabc_mimalloc::__crabc_runtime::ThreadAttachResult {
    use crabc_mimalloc::__crabc_runtime::{
        current_native_allocator_thread_descriptor,
        register_current_native_allocator_worker_descriptor,
    };
    let descriptor = current_native_allocator_thread_descriptor();
    // SAFETY: the descriptor belongs to this thread's allocator TLS, which
    // stays mapped until the test thread exits. No libc registry visits these
    // test threads, so no terminal or fork scan can observe the record.
    if !unsafe { register_current_native_allocator_worker_descriptor(descriptor) } {
        return crabc_mimalloc::__crabc_runtime::ThreadAttachResult::Inactive;
    }
    crabc_mimalloc::__crabc_runtime::attach_current_thread()
}

#[cfg(target_arch = "aarch64")]
pub(crate) use crabc_mimalloc::__crabc_runtime::attach_current_thread;

/// Counts PageMap registrations held by application pages at one quiescent
/// point, excluding pages of the detached source metadata Theap.
///
/// Pinned `init.c::mi_tld_free` and `theap.c` return a worker's TLD and Theap
/// blocks through `_mi_meta_free`; they never destroy `mi_process_theap_meta`,
/// which `init.c:204` configures with `page_full_retain = 2`. Its reusable
/// pages therefore stay registered after every worker has finished. A test
/// that proves application pages return to baseline must compare this count,
/// not the raw registration total, so a leaked application registration
/// still fails while retained metadata capacity does not.
///
/// # Safety
///
/// Every participating worker must have joined or otherwise stopped entering
/// the allocator; the calling thread performs only this observation, as
/// `native_runtime_metadata_page_map_test_audit` requires.
#[cfg(feature = "native-runtime-test-audit")]
#[allow(dead_code)]
pub(crate) unsafe fn quiescent_application_page_map_entry_count() -> usize {
    let audit = crabc_mimalloc::__crabc_runtime::native_runtime_lifecycle_test_audit()
        .expect("the quiescent runtime is auditable");
    // SAFETY: forwarded from this function's quiescence contract.
    let metadata = unsafe { crabc_mimalloc::__crabc_runtime::native_runtime_metadata_page_map_test_audit() }
        .expect("the quiescent runtime retains its metadata identity");
    audit
        .page_map_registered_entry_count
        .checked_sub(metadata)
        .expect("metadata registrations are a subset of all registrations")
}
