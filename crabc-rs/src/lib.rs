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

// Runtime-owned features stay behind their own features until their native
// boundaries exist.
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
// Pure Unix-time, Gregorian-calendar, and explicit immutable-timezone-rule
// algorithms are shared by the AArch64 facade and the private
// x86-64 civil-time module. They define no C time ABI or process timezone
// state.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
mod civil_time;
// The three private RuntimeV1 consumers (`cfile`, `dl`, `runtime_thread`)
// are target-neutral. Each opt-in feature needs a crabc process whose loaded
// libc exports `__crabc_runtime_v1`; on x86-64 that is the installed owned
// dynamic product.
#[cfg(feature = "runtime-stdio")]
pub mod cfile;
pub mod collections;
mod eventfd;
pub mod event;
#[cfg(feature = "runtime-loader")]
pub mod dl;
pub mod fd;
pub mod fenv;
pub mod ffi;
pub mod fs;
pub mod io;
pub mod ioctl;
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub mod ipc;
pub mod memory;
pub mod mm;
pub mod mount;
// Socket transport, allocation-free address/message values, bounded
// network-device ioctl/rtnetlink snapshots, and the caller-owned resolver plus
// conventional hosts/service/protocol snapshots use the Linux LP64 layouts
// shared by both architectures.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub mod net;
#[cfg(all(feature = "alloc", any(target_arch = "aarch64", target_arch = "x86_64")))]
pub mod netdb;
pub mod numeric;
pub mod param;
// Path arguments and borrowed component extraction use byte/C-string values,
// with no architecture-specific kernel records or process state.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub mod path;
pub mod pattern;
pub mod pipe;
pub mod process;
pub mod pty;
pub mod rand;
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
mod raw_dir;
#[cfg(all(feature = "alloc", any(target_arch = "aarch64", target_arch = "x86_64")))]
pub mod resolver;
#[cfg(feature = "runtime-thread")]
pub mod runtime_thread;
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub mod shm;
pub mod signal;
pub mod stdio;
// Rust-owned process-private synchronization uses only atomics and the direct
// futex seam. Both admitted targets use the same 64-bit relative timespec.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub mod sync;
pub mod system;
pub mod termios;
pub mod text;
pub mod thread;
pub mod time;
#[cfg(all(
    feature = "alloc",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub mod timezone;
#[cfg(all(
    feature = "alloc",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub mod users;

pub use crabc_core::{Errno, Result};
pub use fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
pub use signal::Pid;
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
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
        // exercises the type boundary; descriptor 3 need not be open in the
        // test process.
        let descriptor = unsafe { BorrowedFd::borrow_raw(3) };

        assert_eq!(descriptor.as_raw_fd(), 3);
        assert_eq!(descriptor.as_fd().as_raw_fd(), 3);
    }
}
