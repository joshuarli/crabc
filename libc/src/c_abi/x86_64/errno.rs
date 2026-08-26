//! Linux/x86-64 C `errno` storage boundary.
//!
//! This source is intentionally not selected by `crabc-libc`: the crate root
//! remains Linux/AArch64-only until the complete x86 C ABI is proven. The
//! source-only native probe compiles this one leaf with static relocation so
//! `ERRNO` uses the executable's initial TLS block (`R_X86_64_TPOFF*`), not a
//! dynamic TLS resolver.

use core::ffi::c_int;

/// Per-thread C `errno` storage for the x86 C ABI.
///
/// The initial zero value and thread-local placement are part of the C
/// contract: each thread starts with an independent zero-initialized `errno`.
#[thread_local]
static mut ERRNO: c_int = 0;

/// Return the calling thread's C `errno` storage.
///
/// C's `errno` macro dereferences this pointer. The source-only x86 evidence
/// links a static C program and proves that its main and pthread instances are
/// distinct, zero-initialized TLS slots.
#[no_mangle]
pub unsafe extern "C" fn __errno_location() -> *mut c_int {
    core::ptr::addr_of_mut!(ERRNO)
}
