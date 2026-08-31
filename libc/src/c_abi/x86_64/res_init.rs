//! Selected static Linux/x86-64 legacy resolver-initializer C ABI boundary.
//!
//! This private leaf owns exactly musl's historical `int res_init(void)`
//! spelling. Pinned musl makes it a successful no-op: it has no input,
//! mutable state, errno, TLS, allocation, syscall, file, resolver
//! configuration, DNS, socket, netdb, or network-policy boundary. In
//! particular, it neither reads nor writes `__res_state` or `_res`; it is not
//! an implementation of resolver initialization policy.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.
//! Source-function mapping: musl `src/network/res_init.c::res_init` maps
//! directly to [`res_init`] below. Its complete body is `return 0;`.
//!
//! The System V AMD64 ABI passes no arguments and returns the signed `int` in
//! `eax`. The literal result therefore needs no C ABI translation, runtime
//! seam, or unsafe memory access. This does not select libc.so, a CRT, a
//! loader, a sysroot, resolver-family completion, promotion, or public x86
//! support.

use core::ffi::c_int;

/// Return musl's successful legacy resolver-initializer no-op.
#[no_mangle]
pub extern "C" fn res_init() -> c_int {
    0
}
