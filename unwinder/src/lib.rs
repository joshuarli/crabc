//! Build root for the separately linked, allocation-free native x86 unwinder.
//! Rust std owns personality and panic handling; this crate enables neither
//! except the standalone archive's aborting panic handler below.
#![no_std]
#[cfg(not(all(target_arch = "x86_64", target_os = "linux", target_env = "musl", target_endian = "little")))]
compile_error!("the owned unwinder is qualified only for native Linux/x86-64 musl ABI");
extern crate unwinding;

// The source-built cleanup consumer passes this exact provider implementation
// address through `black_box`.  That keeps the approved `_Unwind_RaiseException`
// definition in the same Cargo/LTO graph as source-built `core`; it is neither a
// fallback implementation nor an exception call across an ABI boundary.
#[inline(never)]
pub fn link_anchor() -> unsafe extern "C-unwind" fn(
    *mut unwinding::abi::UnwindException,
) -> unwinding::abi::UnwindReasonCode {
    unwinding::abi::_Unwind_RaiseException
}

// Only the standalone provider archive (`build.py`) compiles this crate as a
// fat-LTO staticlib with its own copy of `core`; there, a bounds or arithmetic
// panic inside the unwinder has no Rust std to report it and aborts through
// the C ABI. The Cargo-dependency form leaves panic handling to consumer std.
#[cfg(crabc_unwinder_standalone)]
#[panic_handler]
fn standalone_panic(_: &core::panic::PanicInfo<'_>) -> ! {
    unsafe extern "C" {
        fn abort() -> !;
    }
    // SAFETY: C `abort` has no preconditions and does not return.
    unsafe { abort() }
}
