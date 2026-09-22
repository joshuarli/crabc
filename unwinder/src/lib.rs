//! Build root for the separately linked, allocation-free native x86 unwinder.
//! Rust std owns personality and panic handling; this crate enables neither.
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
