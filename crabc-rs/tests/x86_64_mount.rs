#![cfg(target_arch = "x86_64")]

//! Native x86-64 contract for the narrow direct mount error boundary.
//!
//! These tests deliberately never grant mount authority or attempt namespace
//! mutation. They prove only byte-path validation and direct errors for a
//! unique nonexistent target.

use core::ffi::CStr;

use crabc_rs::{mount, process, Errno};

#[test]
fn x86_64_mount_basic_checks_paths_and_preserves_direct_missing_target_errors() {
    let missing = format!(
        "/crabc-rs-x86-mount-missing-{}",
        process::getpid().as_raw_pid()
    );

    assert_eq!(
        mount::mount(
            &b"none\0invalid"[..],
            missing.as_str(),
            "tmpfs",
            mount::MountFlags::empty(),
            None::<&CStr>,
        ),
        Err(Errno::INVAL),
    );
    assert_eq!(
        mount::unmount(&b"/crabc-rs-x86-mount\0invalid"[..], mount::UnmountFlags::empty()),
        Err(Errno::INVAL),
    );

    assert!(
        mount::mount(
            "none",
            missing.as_str(),
            "tmpfs",
            mount::MountFlags::empty(),
            None::<&CStr>,
        )
        .is_err(),
        "a unique nonexistent target must not mount successfully"
    );
    assert!(
        mount::unmount(missing.as_str(), mount::UnmountFlags::empty()).is_err(),
        "a unique nonexistent target must not unmount successfully"
    );
}
