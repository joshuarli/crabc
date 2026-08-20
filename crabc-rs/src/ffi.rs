//! FFI vocabulary shared with the Rustix-shaped public API.
//!
//! These are type re-exports only. They do not route operations through the C
//! ABI or expose libc's thread-local `errno` protocol.

pub use core::ffi::{
    c_char, c_int, c_long, c_longlong, c_short, c_uint, c_ulong, c_ulonglong, c_ushort, c_void,
    CStr, FromBytesWithNulError,
};

#[cfg(feature = "alloc")]
pub use alloc::ffi::{CString, NulError};
