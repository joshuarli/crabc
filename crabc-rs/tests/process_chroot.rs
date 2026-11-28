use crabc_rs::{process, Errno};

#[test]
fn chroot_reports_missing_path_without_mutating_process_root() {
    // Never attempt a successful chroot in a shared test process: unlike CWD,
    // root has no portable restoration operation. This path is intentionally
    // outside the repository and is not created by the test.
    #[cfg(target_os = "linux")]
    assert_eq!(
        process::chroot("/crabc-rs-native-chroot-does-not-exist"),
        Err(Errno::NOENT),
    );
    // XNU checks the caller's privilege before it looks up the path.
    #[cfg(target_os = "macos")]
    assert_eq!(
        process::chroot("/crabc-rs-native-chroot-does-not-exist"),
        Err(if process::geteuid().is_root() { Errno::NOENT } else { Errno::PERM }),
    );
}
