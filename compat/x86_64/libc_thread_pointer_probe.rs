#![no_std]

// This source-only probe selects the private x86 `%fs:0` leaf directly. It
// deliberately does not select `crabc-libc`, a public C ABI, or pthread/TLS
// lifecycle code.
#[path = "../../libc/src/c_abi/x86_64/thread_pointer.rs"]
mod thread_pointer;

/// Compatibility-fixture bridge, not a project C ABI export.
///
/// # Safety
///
/// The C fixture must call it only with a native Linux/x86-64 `%fs` base whose
/// zero word is readable, exactly as required by the private source leaf.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn crabc_x86_64_thread_pointer_probe() -> usize {
    // SAFETY: the C fixture establishes the native pinned-musl thread context
    // required by the source-only leaf.
    unsafe { thread_pointer::thread_pointer_identity() as usize }
}
