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
// scoped native x86-64 evidence lane. Keep its platform boundary explicit so
// Cargo feature unification with that private engine cannot turn an internal
// `crabc-core` evidence feature into an x86 facade build.
#[cfg(not(all(
    target_os = "linux",
    target_arch = "aarch64",
    target_endian = "little"
)))]
compile_error!("crabc-rs supports Linux/AArch64 little-endian only");

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(any(feature = "std", test))]
extern crate std;

pub mod buffer;
#[cfg(feature = "runtime-stdio")]
pub mod cfile;
pub mod collections;
#[cfg(feature = "runtime-loader")]
pub mod dl;
pub mod event;
pub mod fd;
pub mod fenv;
pub mod ffi;
pub mod fs;
pub mod io;
pub mod ioctl;
pub mod ipc;
pub mod memory;
pub mod mm;
pub mod mount;
pub mod net;
#[cfg(feature = "alloc")]
pub mod netdb;
pub mod numeric;
pub mod param;
pub mod path;
pub mod pattern;
pub mod pipe;
pub mod process;
pub mod pty;
pub mod rand;
mod raw_dir;
#[cfg(feature = "alloc")]
pub mod resolver;
#[cfg(feature = "runtime-thread")]
pub mod runtime_thread;
pub mod shm;
pub mod signal;
pub mod stdio;
pub mod sync;
pub mod system;
pub mod termios;
pub mod text;
pub mod thread;
pub mod time;
#[cfg(feature = "alloc")]
pub mod timezone;
#[cfg(feature = "alloc")]
pub mod users;

pub use crabc_core::{Errno, Result};
pub use fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
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
