//! Test-only result-allocation failure injection for the private x86 wordexp
//! result owner.
//!
//! This module is compiled only when the eventual C adapter opts into
//! `crabc_owned_wordexp_result_private_test`.  It is deliberately an allocator
//! *handle* for `owned_wordexp_results`, rather than an interposition of the
//! libc `malloc`, `realloc`, or `free` symbols.  Rust test machinery, parser
//! storage, process adapters, and every unrelated C allocation therefore stay
//! outside the injected failure boundary.
//!
//! A finite budget permits that many result-vector or result-string allocation
//! requests, then returns null for the next `malloc` or `realloc`.  `free`
//! always reaches the real selected C allocation domain, including while a
//! zero budget is active, so `wordfree` can release any published prefix.
//! The injected null path performs no allocation and does not write errno.

#![cfg(crabc_owned_wordexp_result_private_test)]

use core::{
    ffi::c_void,
    ptr,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use super::owned_wordexp_results::WordexpResultAllocator;

// The C fixture serializes this private state. Atomics make the narrow
// cross-language control boundary race-free even if an accidental observer is
// present; they are not a promise that concurrent wordexp calls have a useful
// deterministic budget.
static FINITE_BUDGET: AtomicBool = AtomicBool::new(false);
static PERMITTED_REQUESTS: AtomicUsize = AtomicUsize::new(0);
static REQUEST_BUDGET: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" {
    #[link_name = "malloc"]
    fn result_malloc(size: usize) -> *mut c_void;
    #[link_name = "realloc"]
    fn result_realloc(pointer: *mut c_void, size: usize) -> *mut c_void;
    #[link_name = "free"]
    fn result_free(pointer: *mut c_void);
}

/// Return the private result allocator selected by the failure-injection C
/// fixture.
///
/// The returned handle uses the same real C allocation domain as production.
/// Only its allocation and reallocation requests can be refused by the test
/// budget; deallocation is never refused.
pub(super) fn allocator() -> WordexpResultAllocator {
    // SAFETY: these three hooks share the selected C allocation domain. A
    // refused reallocation does not call the real realloc, so its old live
    // allocation remains valid exactly as `WordexpResultAllocator` requires.
    unsafe { WordexpResultAllocator::new(allocate, reallocate, deallocate) }
}

/// Consume one finite-budget request, or permit an unlimited request.
///
/// A real allocator OOM after this succeeds remains a real allocator outcome;
/// the counter describes requests permitted before this module forces null,
/// not a claim that the underlying allocator cannot fail independently.
#[inline]
fn permit_request() -> bool {
    if !FINITE_BUDGET.load(Ordering::SeqCst) {
        return true;
    }

    loop {
        let completed = PERMITTED_REQUESTS.load(Ordering::SeqCst);
        if completed >= REQUEST_BUDGET.load(Ordering::SeqCst) {
            return false;
        }
        if PERMITTED_REQUESTS.compare_exchange_weak(
            completed,
            completed + 1,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ).is_ok() {
            return true;
        }
    }
}

/// Request result-domain storage through the real C allocator unless the
/// finite test budget has reached its forced-null request.
///
/// # Safety
///
/// `size` must satisfy the selected C `malloc` contract. The result owner
/// supplies only checked nonzero sizes. A non-null result belongs to the real
/// C allocation domain and must be released through `deallocate` below.
unsafe fn allocate(size: usize) -> *mut c_void {
    if !permit_request() {
        return ptr::null_mut();
    }
    // SAFETY: the result owner passed one checked C allocation size.
    unsafe { result_malloc(size) }
}

/// Reallocate result-domain storage through the real C allocator unless the
/// finite test budget has reached its forced-null request.
///
/// # Safety
///
/// `pointer` is null or a live allocation from `allocate`/this function in the
/// selected C allocation domain, and `size` satisfies that domain's `realloc`
/// contract. On a forced null this function intentionally does not call the
/// real allocator, so `pointer` remains live and unchanged.
unsafe fn reallocate(pointer: *mut c_void, size: usize) -> *mut c_void {
    if !permit_request() {
        return ptr::null_mut();
    }
    // SAFETY: the result transaction preserves C realloc ownership.
    unsafe { result_realloc(pointer, size) }
}

/// Release result-domain storage through the real C allocator.
///
/// # Safety
///
/// `pointer` is null or one live allocation returned by the selected C
/// allocation domain. This deliberately ignores the finite budget so a
/// `wordfree` call can always retire a completed or partial result.
unsafe fn deallocate(pointer: *mut c_void) {
    // SAFETY: the result transaction passes only its selected-domain storage
    // or null, which C free accepts.
    unsafe { result_free(pointer) }
}

/// Permit exactly `successful_requests` result vector/string allocation
/// requests before forcing the next allocation or reallocation to return null.
///
/// # Safety
///
/// This changes one process-global private test control. The fixture must
/// serialize calls to this setter with every active wordexp result transaction
/// and with `__crabc_test_wordexp_result_unlimited`; it must choose a budget
/// before starting the call whose result allocations it observes. The function
/// itself allocates nothing and does not set errno.
#[no_mangle]
pub unsafe extern "C" fn __crabc_test_wordexp_result_budget(successful_requests: usize) {
    PERMITTED_REQUESTS.store(0, Ordering::SeqCst);
    REQUEST_BUDGET.store(successful_requests, Ordering::SeqCst);
    FINITE_BUDGET.store(true, Ordering::SeqCst);
}

/// Disable result-allocation injection and reset its completed-request count.
///
/// # Safety
///
/// This has the same serialization requirement as
/// `__crabc_test_wordexp_result_budget`: no wordexp result transaction may be
/// active while the fixture changes the process-global control. The function
/// itself allocates nothing and does not set errno.
#[no_mangle]
pub unsafe extern "C" fn __crabc_test_wordexp_result_unlimited() {
    FINITE_BUDGET.store(false, Ordering::SeqCst);
    PERMITTED_REQUESTS.store(0, Ordering::SeqCst);
    REQUEST_BUDGET.store(0, Ordering::SeqCst);
}
