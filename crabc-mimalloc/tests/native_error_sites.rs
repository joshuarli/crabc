// Rust half of the M7 `_mi_error_message` site differential driven by
// `compat/allocator/x86_64_m7_gate.py --error-sites-differential`. The pinned
// C probe `x86_64_m7_error_sites_oracle.c` runs the matching `mi_malloc`,
// `mi_malloc_aligned`, and `mi_malloc_aligned_at` requests under the same
// `mimalloc_show_errors=1` environment and prints the same keys: the
// TID-normalized output fragments, whether the request failed, and the errno
// the source default error policy leaves after starting from zero.
#![cfg(all(target_arch = "x86_64", feature = "native-runtime-test-audit"))]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use core::ffi::{CStr, c_char};
use std::sync::Mutex;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, NativeProcessStartupFacts,
    RuntimeStderrOutput, ThreadAttachResult, ThreadFinishResult,
    finish_current_thread_native_after_user_destructors, initialize_process, native_allocate, native_allocate_aligned,
    native_allocate_aligned_at, native_free, register_native_deferred_free_callback, native_runtime_take_source_error_test_audit,
    publish_native_process_startup_facts,
};

static CAPTURE: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());
/// The force flag of every deferred-free invocation during one request.
static DEFERRED: Mutex<String> = Mutex::new(String::new());

unsafe extern "C" fn record_deferred(force: bool, _heartbeat: u64, _context: *mut core::ffi::c_void) {
    DEFERRED.lock().unwrap().push(if force { '1' } else { '0' });
}

/// The default `_mi_prim_out_stderr` primitive of this process: records each
/// source fragment. It never allocates through the allocator under test,
/// because the test binary's own global allocator is musl's.
unsafe extern "C" fn capture_stderr(message: *const c_char) {
    // SAFETY: the owner passes a non-null NUL-terminated fragment.
    let bytes = unsafe { CStr::from_ptr(message) }.to_bytes().to_vec();
    CAPTURE.lock().unwrap().push(bytes);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn report(name: &str, result: NativePageAllocationResult) {
    let thread = format!("0x{:02X}", crabc_core::thread::thread_pointer_identity());
    let fragments: Vec<String> = CAPTURE
        .lock()
        .unwrap()
        .drain(..)
        .map(|fragment| {
            let text = String::from_utf8(fragment).expect("source messages are ASCII");
            hex(text.replace(&thread, "0xTID").as_bytes())
        })
        .collect();
    println!("error_site.{name}.messages={}", fragments.join(":"));
    println!("error_site.{name}.deferred={}", core::mem::take(&mut *DEFERRED.lock().unwrap()));
    let failed = match result {
        NativePageAllocationResult::Allocated(block) => {
            // SAFETY: the exact live client from this request.
            assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
            0
        }
        NativePageAllocationResult::AllocationFailed => 1,
        NativePageAllocationResult::Unavailable => panic!("{name}: the native runtime is unavailable"),
        NativePageAllocationResult::Retained => panic!("{name}: the native owner was retained"),
    };
    println!("error_site.{name}.null={failed}");
    let errno = native_runtime_take_source_error_test_audit().map_or(0, |report| report.default_errno);
    println!("error_site.{name}.errno={errno}");
}

/// The same requests on one thread, as the C probe's `run_cases`.
fn run_cases(prefix: &str) {
    let too_large = isize::MAX as usize + 1;
    let name = |suffix: &str| format!("{prefix}{suffix}");
    report(&name("malloc_too_large"), native_allocate(too_large, false));
    report(&name("aligned_bad_alignment"), native_allocate_aligned(100, 24, false));
    report(&name("aligned_too_large"), native_allocate_aligned(too_large, 16, false));
    report(&name("aligned_large_alignment_offset"), native_allocate_aligned_at(100, 1 << 20, 8, false));
    report(
        &name("aligned_overallocation_too_large"),
        native_allocate_aligned_at(isize::MAX as usize - 16, 4096, 8, false),
    );
    report(&name("malloc_ordinary"), native_allocate(100, false));
}

#[test]
fn error_sites_match_the_pinned_source() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ");
    // SAFETY: the host environment is stable before startup, and the capture
    // primitive is a process-lifetime function.
    let facts = unsafe {
        NativeProcessStartupFacts::new(
            page_size,
            native_runtime_test_support::host_environment,
            RuntimeStderrOutput::new(capture_stderr),
        )
    }
    .expect("a supported page size");
    assert!(publish_native_process_startup_facts(facts));
    assert!(initialize_process());
    CAPTURE.lock().unwrap().clear();
    let _ = native_runtime_take_source_error_test_audit();
    // SAFETY: a static function with no context, registered for the process.
    unsafe { register_native_deferred_free_callback(Some(record_deferred), core::ptr::null_mut()) };

    println!("CRABC_MI_M7_ERROR_SITES_TRACE_BEGIN");
    run_cases("");
    std::thread::spawn(|| {
        assert_eq!(
            native_runtime_test_support::attach_current_thread(),
            ThreadAttachResult::Attached
        );
        run_cases("worker_");
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    })
    .join()
    .expect("the worker completes");
    println!("CRABC_MI_M7_ERROR_SITES_TRACE_END");
}
