//! Selected static Linux/x86-64 `grantpt` C ABI.
//!
//! This is a narrow translation of pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.
//! Source-function mapping: musl `src/unistd/grantpt.c::grantpt` maps to
//! `grantpt` below. On Linux, musl's legacy wrapper returns zero without
//! inspecting the descriptor or issuing a syscall: devpts allocation performs
//! the kernel-side grant before this compatibility spelling is called.
//!
//! This leaf preserves that no-op result only. It neither allocates nor opens a
//! PTY, changes a grant or lock, resolves a slave pathname, observes a terminal,
//! accesses errno or TLS, performs a syscall, or owns any terminal/session
//! policy. PTY allocation and naming, descriptor authority, controlling-terminal
//! setup, generic ioctl, dynamic runtime, CRT, loader, sysroot, family
//! completion, promotion, and public x86 support remain outside this
//! selected-private leaf.

use core::ffi::c_int;

/// Preserve musl's legacy no-op PTY compatibility result.
///
/// # Safety
///
/// This C ABI accepts every `int` bit pattern and does not dereference or retain
/// the descriptor. Callers remain responsible for interpreting this historical
/// compatibility result within any higher-level PTY protocol they select.
#[no_mangle]
pub unsafe extern "C" fn grantpt(_fd: c_int) -> c_int {
    0
}
