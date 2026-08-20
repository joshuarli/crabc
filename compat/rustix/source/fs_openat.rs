//! Source-compatibility anchor for the M0 stateless `openat` slice.
//!
//! The dual-backend runner compiles this source once with `api` aliased to the
//! pinned Rustix package and once with `api` aliased to `crabc-rs`. It uses the
//! common `&CStr` path subset; broader Rustix `Arg` path compatibility belongs
//! to the filesystem milestone.

use core::ffi::CStr;

use api::fs::{openat, Mode, OFlags, CWD};

fn main() {
    let path = CStr::from_bytes_with_nul(b"/proc/self/cmdline\0")
        .expect("the fixed fixture path is NUL terminated");
    let descriptor = openat(CWD, path, OFlags::RDONLY, Mode::empty())
        .expect("the running Linux process has /proc/self/cmdline");
    drop(descriptor);
}
