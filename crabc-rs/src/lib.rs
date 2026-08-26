//! Native Rust vocabulary for the crabc implementation.
//!
//! This crate is the Rust-facing side of crabc. It is intentionally independent
//! of the public C ABI: the types here do not call C functions, read C
//! `errno`, or translate C sentinel return values. Operations will be added
//! behind this vocabulary as their shared implementation seams are extracted.
//!
//! The crate is `no_std` at its core. The default `std` feature enables
//! standard-library integration points as they are added, while the separate
//! `alloc` feature is reserved for APIs that need owned allocation.
#![no_std]

// `crabc-rs` is a public facade, unlike the fixed-mimalloc engine's narrowly
// scoped native x86-64 evidence lane. Linux/x86-64 admission here is the
// explicit staged direct-facade foundation from `x86-64.md`; it does not make
// the facade or platform publicly supported, and runtime-owned features stay
// separately gated until their own native boundaries exist.
#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "aarch64", target_arch = "x86_64"),
    target_endian = "little"
)))]
compile_error!("crabc-rs supports little-endian Linux/AArch64 and staged Linux/x86-64 only");

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(any(feature = "std", test))]
extern crate std;

pub mod buffer;
#[cfg(all(feature = "runtime-stdio", target_arch = "aarch64"))]
pub mod cfile;
pub mod collections;
// The staged x86-64 facade exposes only `buffer`, `collections`, `event`
// (eventfd counters only), `fd`, `fenv`, `ffi`, `io`, `ioctl`, `memory`,
// `numeric`, `param`, `pipe`, `rand`, `signal`, `stdio`, and `text`, plus the
// root descriptor/error types. These are the target-record-independent
// families or have an explicit x86 ABI proof. Every other public module owns
// an AArch64 kernel-record contract and stays absent until its record family
// has its own x86 proof; admission must not silently make an AArch64 layout
// usable on x86-64.
mod eventfd;
#[cfg(target_arch = "aarch64")]
pub mod event;
#[cfg(target_arch = "x86_64")]
#[path = "event_x86_64.rs"]
pub mod event;
#[cfg(feature = "runtime-loader")]
#[cfg(target_arch = "aarch64")]
pub mod dl;
pub mod fd;
pub mod fenv;
pub mod ffi;
#[cfg(target_arch = "aarch64")]
pub mod fs;
pub mod io;
pub mod ioctl;
#[cfg(target_arch = "aarch64")]
pub mod ipc;
pub mod memory;
#[cfg(target_arch = "aarch64")]
pub mod mm;
#[cfg(target_arch = "x86_64")]
#[path = "mm_x86_64.rs"]
pub mod mm;
#[cfg(target_arch = "aarch64")]
pub mod mount;
#[cfg(target_arch = "aarch64")]
pub mod net;
#[cfg(all(feature = "alloc", target_arch = "aarch64"))]
pub mod netdb;
pub mod numeric;
pub mod param;
#[cfg(target_arch = "aarch64")]
pub mod path;
#[cfg(target_arch = "aarch64")]
pub mod pattern;
pub mod pipe;
#[cfg(target_arch = "aarch64")]
pub mod process;
#[cfg(target_arch = "aarch64")]
pub mod pty;
pub mod rand;
#[cfg(target_arch = "aarch64")]
mod raw_dir;
#[cfg(all(feature = "alloc", target_arch = "aarch64"))]
pub mod resolver;
#[cfg(all(feature = "runtime-thread", target_arch = "aarch64"))]
pub mod runtime_thread;
#[cfg(target_arch = "aarch64")]
pub mod shm;
pub mod signal;
pub mod stdio;
#[cfg(target_arch = "aarch64")]
pub mod sync;
#[cfg(target_arch = "aarch64")]
pub mod system;
#[cfg(target_arch = "aarch64")]
pub mod termios;
pub mod text;
#[cfg(target_arch = "aarch64")]
pub mod thread;
#[cfg(target_arch = "aarch64")]
pub mod time;
#[cfg(all(feature = "alloc", target_arch = "aarch64"))]
pub mod timezone;
#[cfg(all(feature = "alloc", target_arch = "aarch64"))]
pub mod users;

pub use crabc_core::{Errno, Result};
pub use fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
#[cfg(target_arch = "x86_64")]
pub use signal::Pid;
#[cfg(target_arch = "aarch64")]
pub use raw_dir::{RawDir, RawDirEntry};

#[cfg(test)]
mod tests {
    use super::{AsFd, BorrowedFd, Errno};

    #[test]
    fn errno_round_trips_a_linux_error_number() {
        let error = Errno::from_raw(9).expect("9 is a valid Linux errno");

        assert_eq!(error.raw(), 9);
        assert_eq!(error, Errno::from_raw(9).expect("9 is a valid Linux errno"));
    }

    #[test]
    fn borrowed_fd_preserves_the_raw_descriptor() {
        // SAFETY: `3` is a non-negative descriptor value. This test only
        // exercises the type boundary; it does not claim that descriptor 3 is
        // open in the test process.
        let descriptor = unsafe { BorrowedFd::borrow_raw(3) };

        assert_eq!(descriptor.as_raw_fd(), 3);
        assert_eq!(descriptor.as_fd().as_raw_fd(), 3);
    }
}
