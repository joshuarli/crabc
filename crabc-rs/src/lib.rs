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

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(any(feature = "std", test))]
extern crate std;

pub mod buffer;
pub mod event;
pub mod fd;
pub mod ffi;
pub mod fs;
pub mod io;
pub mod ioctl;
pub mod mm;
pub mod mount;
pub mod net;
pub mod param;
pub mod path;
pub mod pipe;
pub mod process;
pub mod pty;
pub mod rand;
pub mod time;
pub mod termios;
pub mod thread;
pub mod shm;
pub mod signal;
pub mod stdio;
pub mod system;
mod raw_dir;

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
