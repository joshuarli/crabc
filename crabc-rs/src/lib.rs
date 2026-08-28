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
// (eventfd counters plus bounded poll/ppoll/pause, select/pselect, and packed
// epoll readiness with temporary signal masks), the staged typed `fs`
// pathname-lifecycle and namespace batch (metadata, open/create,
// directories/nodes/removal, permission/ownership, links, caller-buffer
// readlink, and ordinary/no-replace/exchange rename), descriptor `fs::fstat`,
// and typed filesystem-capacity observation through
// `fs::{StatFs, StatVfs, StatVfsMountFlags, statfs, fstatfs, statvfs,
// fstatvfs}`,
// direct `fs::{memfd_create, fcntl_get_seals, fcntl_add_seals}` and direct
// `fs::{OFlags, fcntl_getfl, fcntl_setfl}` status flags, and the named
// timestamp-mutation family: `fs::{Timespec, Timestamps, UTIME_NOW,
// UTIME_OMIT, futimens}` plus `utimensat`, `futimes`, `futimesat`, `lutimes`,
// `utimes`, and `utime` for bounded directory-relative, current-directory,
// final-symlink, and whole-second forms, plus direct caller-buffer and
// alloc-gated `process::getcwd` observations,
// `fd`, `fenv`, `ffi`, direct `fs::flock` whole-file advisory locking, direct
// `fs::sendfile` descriptor transfer, direct `fs::copy_file_range`
// descriptor-range copying, direct `fs::posix_fallocate` mode-zero
// descriptor-range allocation, direct `fs::{FallocateFlags, fallocate}`
// closed-mode descriptor-range allocation, and direct `fs::{sync, syncfs}`
// system-wide and descriptor-associated filesystem
// synchronization, and direct
// `io::{sync_file_range, SyncFileRangeFlags}` range-writeback
// requests, remaining `io`, `ioctl`, bounded `mm`
// mapping/remapping,
// `memory`, `numeric`, `param`, `pipe`, bounded `process` identity/session
// and supplementary-group query/fill plus pidfd creation and resource-limit
// query/mutation, `rand`, `signal`,
// `stdio`, bounded
// `system::{uname, sysinfo, load_average}`, `text`, bounded
// `thread::{gettid, sched_getcpu, sched_yield, set_thread_res_uid,
// set_thread_res_gid}` plus borrowed `AtomicU32` futex wait/wake and direct
// read-only `sched_rr_get_interval`, direct bounded typed CPU-affinity
// observation/mutation, and bounded `time`
// clock-query, whole-second, and observation APIs plus direct interval-timer
// query/control with bounded real-timer aliases, direct clock-sleep, and
// complete timerfd-descriptor slices,
// and the root descriptor/error types. These
// are the target-record-independent families or have an explicit x86 ABI
// proof. Every other public module owns an AArch64 kernel-record contract and
// stays absent until its record family has its own x86 proof; admission must
// not silently make an AArch64 layout usable on x86-64. The direct credential
// setters retain Linux calling-task scope; they are not musl-style process-wide
// credential transitions.
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
#[cfg(target_arch = "x86_64")]
#[path = "fs_x86_64.rs"]
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
// Socket transport and allocation-free address/message values have a native
// Linux LP64 record proof on both admitted architectures. Network-device
// ioctl records remain AArch64-only inside `net::netdevice` until their x86
// interface ABI receives a separate evidence slice.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
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
#[cfg(target_arch = "x86_64")]
#[path = "process_x86_64.rs"]
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
#[cfg(target_arch = "x86_64")]
#[path = "system_x86_64.rs"]
pub mod system;
#[cfg(target_arch = "aarch64")]
pub mod termios;
pub mod text;
#[cfg(target_arch = "aarch64")]
pub mod thread;
#[cfg(target_arch = "x86_64")]
#[path = "thread_x86_64.rs"]
pub mod thread;
#[cfg(target_arch = "aarch64")]
pub mod time;
#[cfg(target_arch = "x86_64")]
#[path = "time_x86_64.rs"]
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
