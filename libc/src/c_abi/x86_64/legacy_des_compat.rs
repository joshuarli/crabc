//! Shared Linux/x86-64 legacy DES ABI compatibility boundary.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` places
//! `src/legacy/encrypt.c::setkey` and `src/legacy/encrypt.c::encrypt` under
//! musl's MIT license. Musl implements the historical DES key schedule and
//! block transformation there. Crabc intentionally diverges: `SCOPE.md`
//! forbids a local cipher implementation, and this interface has no useful
//! modern Rust contract.
//!
//! `static_c_abi.rs` selects this owner through `x86-legacy-des-compat`.
//! `x86-owned-static-runtime` selects that narrow feature for the two
//! link-compatible names required by the pinned OS-test's X/Open calls, while
//! `x86-legacy-misc` depends on it and retains its independent `fmtmsg`
//! provider. With neither feature selected, the frozen default archive has
//! neither export.
//!
//! The two functions are deliberately inert-DES compatibility machinery:
//! they neither read nor write caller storage, retain state, allocate, perform
//! I/O, implement DES, use a PRNG, or select any cryptographic service. Each
//! function does not alter errno. This intentional divergence preserves a
//! linkable ABI boundary under the project's no-hand-rolled-cryptography rule;
//! it is not an implementation of a cipher or a claim of historical DES
//! compatibility.

use core::ffi::{c_char, c_int};

/// Retain the historical `setkey` link spelling as an inert compatibility
/// function.
///
/// The pointer is never observed, so callers may pass a null or otherwise
/// unreadable value and errno remains unchanged. This is intentional inert-DES
/// behavior, not a key-schedule operation.
#[no_mangle]
pub extern "C" fn setkey(_key: *const c_char) {}

/// Retain the historical `encrypt` link spelling as an inert compatibility
/// function.
///
/// Neither argument affects behavior: the block pointer is never read or
/// written, the direction is ignored, and errno remains unchanged. This is
/// intentional inert-DES behavior, not an encryption or decryption operation.
#[no_mangle]
pub extern "C" fn encrypt(_block: *mut c_char, _edflag: c_int) {}
