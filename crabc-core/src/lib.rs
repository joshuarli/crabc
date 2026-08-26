//! Internal, stateless Linux operations shared by crabc's facades.
//!
//! This crate deliberately owns no process-global runtime state.  It is safe
//! to link into both `libc.so` and a Rust application because its operations
//! cross directly to the kernel and its values have no singleton identity.
//! Stateful libc and dynamic-loader facilities must not be added here without
//! an explicit runtime-owner boundary.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
extern crate std;

// Linux/AArch64 is the current public crabc target. Linux/x86-64 core support
// is a staged native foundation for the separately documented runtime program;
// it does not by itself select libc, loader, CRT, or facade artifacts.
#[cfg(not(all(
    target_os = "linux",
    target_endian = "little",
    any(target_arch = "aarch64", target_arch = "x86_64")
)))]
compile_error!("crabc-core supports little-endian Linux/AArch64 and Linux/x86-64 only");

mod error;

pub use error::{Errno, RawFd, Result, AT_FDCWD};

/// Direct, typed access to the calling thread's AArch64 floating-point state.
#[cfg(target_arch = "aarch64")]
pub mod fenv;
/// Direct, typed access to the calling thread's x87 and SSE floating-point
/// state.
#[cfg(target_arch = "x86_64")]
#[path = "fenv_x86_64.rs"]
pub mod fenv;
/// Allocation-free character-set conversion shared by the native and C facades.
pub mod iconv;
/// Direct, allocation-free reads of Linux's process auxiliary vector.
pub mod param;
/// Stateless byte-oriented filename pattern matching shared by both facades.
pub mod pattern;
/// Pure byte-string algorithms shared by native text operations.
pub mod text;
/// Linux vDSO discovery and typed time dispatch for the supported targets.
mod vdso;

/// Private, versioned wire contracts for process-singleton crabc runtimes.
///
/// These types are deliberately data-only. They let a native facade reach
/// state owned by `libc.so` or `libldso.so` without mistaking a second linked
/// copy of Rust statics for shared process state. They are not a public C ABI:
/// no installed header names them, and callers must obtain the matching table
/// through the explicitly versioned private entry point.
pub mod runtime;

#[cfg(target_arch = "aarch64")]
#[path = "syscall.rs"]
mod syscall;
#[cfg(target_arch = "x86_64")]
#[path = "syscall_x86_64.rs"]
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
#[cfg(target_arch = "aarch64")]
pub mod time;
/// Deliberately bounded Linux/x86-64 clock queries.
#[cfg(target_arch = "x86_64")]
#[path = "time_x86_64.rs"]
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

/// Direct Linux/AArch64 virtual-memory operations.
#[cfg(target_arch = "aarch64")]
pub mod mm;
/// Deliberately bounded Linux/x86-64 virtual-memory operations.
#[cfg(target_arch = "x86_64")]
#[path = "mm_x86_64.rs"]
pub mod mm;

/// Direct Linux/AArch64 signal operations.
///
/// This module exposes only kernel ABI records and direct syscalls. Policy
/// around reserved libc signals, handler lifetimes, and safe Rust vocabulary
/// belongs to `crabc-rs::signal`; C's public `sigaction` record is likewise a
/// distinct ABI boundary in `libc`.
#[cfg(target_arch = "aarch64")]
pub mod signal;
/// Direct Linux/x86-64 signal operations.
///
/// This raw kernel ABI boundary deliberately requires callers installing a
/// handler to supply the target's `SA_RESTORER` trampoline; choosing the C or
/// Rust runtime owner remains outside shared core.
#[cfg(target_arch = "x86_64")]
#[path = "signal_x86_64.rs"]
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
