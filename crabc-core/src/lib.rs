//! Internal, stateless Linux/AArch64 operations shared by crabc's facades.
//!
//! This crate deliberately owns no process-global runtime state.  It is safe
//! to link into both `libc.so` and a Rust application because its operations
//! cross directly to the kernel and its values have no singleton identity.
//! Stateful libc and dynamic-loader facilities must not be added here without
//! an explicit runtime-owner boundary.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(all(target_os = "linux", target_arch = "aarch64", target_endian = "little")))]
compile_error!("crabc-core supports Linux/AArch64 little-endian only");

mod error;

pub use error::{Errno, RawFd, Result, AT_FDCWD};

/// Direct, typed access to the calling thread's AArch64 floating-point state.
pub mod fenv;
/// Allocation-free character-set conversion shared by the native and C facades.
pub mod iconv;
/// Direct, allocation-free reads of Linux's process auxiliary vector.
pub mod param;
/// Stateless byte-oriented filename pattern matching shared by both facades.
pub mod pattern;
/// Pure byte-string algorithms shared by native text operations.
pub mod text;
/// Linux/AArch64 vDSO discovery and typed time dispatch.
mod vdso;

/// Private, versioned wire contracts for process-singleton crabc runtimes.
///
/// These types are deliberately data-only. They let a native facade reach
/// state owned by `libc.so` or `libldso.so` without mistaking a second linked
/// copy of Rust statics for shared process state. They are not a public C ABI:
/// no installed header names them, and callers must obtain the matching table
/// through the explicitly versioned private entry point.
pub mod runtime;

mod syscall;

/// Direct descriptor I/O operations.
pub mod io;

/// Direct stateless filesystem operations.
pub mod fs;

/// Direct pipe operations.
pub mod pipe;

/// Direct kernel random-source operations.
pub mod rand;

/// Direct stateless clock queries.
pub mod time;

/// Direct event-descriptor and polling operations.
pub mod event;

/// Direct Linux socket operations.
pub mod net;

/// Stateless DNS wire and exchange operations shared by native facades.
///
/// This module deliberately owns no resolver configuration, cache, TLS, or
/// libc state. Callers provide bounded nameserver configuration and buffers;
/// the native facade can therefore own its results while the C facade keeps
/// its historical `_res` state at its own ABI boundary.
pub mod resolver;

/// Direct Linux virtual-memory operations.
pub mod mm;

/// Direct Linux/AArch64 signal operations.
///
/// This module exposes only kernel ABI records and direct syscalls. Policy
/// around reserved libc signals, handler lifetimes, and safe Rust vocabulary
/// belongs to `crabc-rs::signal`; C's public `sigaction` record is likewise a
/// distinct ABI boundary in `libc`.
pub mod signal;

/// Direct process-identity, process-group, and signal operations.
pub mod process;

/// Direct thread-associated Linux operations.
pub mod thread;

/// Direct Linux system-information operations.
pub mod system;

/// Direct Linux POSIX message-queue operations.
pub mod ipc;

/// Direct Linux inotify operations.
pub mod inotify;

/// Direct Linux mount namespace operations.
pub mod mount;

#[cfg(test)]
mod tests;
