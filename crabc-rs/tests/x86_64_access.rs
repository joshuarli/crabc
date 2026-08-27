#![cfg(target_arch = "x86_64")]

use std::fs::{self as std_fs, File};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
use std::process::Command;

use crabc_rs::{fs, process, thread, BorrowedFd, Errno};

const CREDENTIAL_CHILD: &str = "CRABC_RS_X86_64_ACCESS_CREDENTIAL_CHILD";

struct RemoveDirectoryOnDrop(PathBuf);

impl Drop for RemoveDirectoryOnDrop {
    fn drop(&mut self) {
        let _ = std_fs::remove_dir_all(&self.0);
    }
}

fn fixture_root() -> (RemoveDirectoryOnDrop, PathBuf, File) {
    let mut root = std::env::temp_dir();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    root.push(format!("crabc-x86-access-{}-{nonce}", std::process::id()));
    std_fs::create_dir(&root).expect("create access fixture directory");
    let cleanup = RemoveDirectoryOnDrop(root.clone());

    std_fs::write(root.join("record"), b"access").expect("create access fixture file");
    std_fs::set_permissions(root.join("record"), std_fs::Permissions::from_mode(0o400))
        .expect("make the access fixture root-readable only");
    symlink("missing-target", root.join("dangling")).expect("create dangling access symlink");
    let directory = File::open(&root).expect("open access fixture directory");
    (cleanup, root, directory)
}

fn borrow(file: &File) -> BorrowedFd<'_> {
    // SAFETY: The fixture retains the descriptor owner for every immediate
    // access/accessat operation using this borrow.
    unsafe { BorrowedFd::borrow_raw(file.as_raw_fd()) }
}

#[test]
fn x86_64_access_checks_existing_and_missing_paths() {
    let (_cleanup, root, _directory) = fixture_root();
    let record = root.join("record");
    let missing = root.join("missing");

    fs::access(record.as_os_str().as_bytes(), fs::Access::EXISTS)
        .expect("access existing fixture path");
    assert_eq!(
        fs::access(missing.as_os_str().as_bytes(), fs::Access::EXISTS).unwrap_err(),
        Errno::NOENT,
    );
}

#[test]
fn x86_64_accessat_is_descriptor_relative_and_handles_dangling_symlinks() {
    let (_cleanup, _root, directory) = fixture_root();
    let directory = borrow(&directory);

    fs::accessat(
        directory,
        "record",
        fs::Access::EXISTS,
        fs::AccessAtFlags::empty(),
    )
    .expect("accessat existing descriptor-relative path");
    assert_eq!(
        fs::accessat(
            directory,
            "missing",
            fs::Access::EXISTS,
            fs::AccessAtFlags::empty(),
        )
        .unwrap_err(),
        Errno::NOENT,
    );

    fs::accessat(
        directory,
        "dangling",
        fs::Access::EXISTS,
        fs::AccessAtFlags::SYMLINK_NOFOLLOW,
    )
    .expect("faccessat2 checks a dangling final symlink itself");
    assert_eq!(
        fs::accessat(
            directory,
            "dangling",
            fs::Access::EXISTS,
            fs::AccessAtFlags::empty(),
        )
        .unwrap_err(),
        Errno::NOENT,
    );
    fs::accessat(
        directory,
        "record",
        fs::Access::EXISTS,
        fs::AccessAtFlags::EACCESS,
    )
    .expect("faccessat2 accepts effective-credential checks");
}

#[test]
fn x86_64_accessat_distinguishes_real_and_effective_credentials_child_contained() {
    if std::env::var_os(CREDENTIAL_CHILD).is_some() {
        // This exact credential split must run in a child: setresuid changes
        // the calling kernel task, and the native x86 runner deliberately
        // supplies a root test process for this evidence.
        assert_eq!(process::geteuid(), process::Uid::ROOT);
        let (_cleanup, _root, directory) = fixture_root();
        let directory = borrow(&directory);

        thread::set_thread_res_uid(
            Some(process::Uid::from_raw(1000)),
            Some(process::Uid::ROOT),
            Some(process::Uid::ROOT),
        )
        .expect("make real UID differ from effective root UID");
        let ids = process::getresuid().expect("read split user IDs");
        assert_eq!(ids.real, process::Uid::from_raw(1000));
        assert_eq!(ids.effective, process::Uid::ROOT);

        assert_eq!(
            fs::accessat(
                directory,
                "record",
                fs::Access::READ_OK,
                fs::AccessAtFlags::empty(),
            ),
            Err(Errno::ACCESS),
            "ordinary accessat must use the real UID",
        );
        fs::accessat(
            directory,
            "record",
            fs::Access::READ_OK,
            fs::AccessAtFlags::EACCESS,
        )
        .expect("AT_EACCESS must use effective root credentials");
        return;
    }

    let output = Command::new(std::env::current_exe().expect("locate test binary"))
        .args([
            "--exact",
            "x86_64_accessat_distinguishes_real_and_effective_credentials_child_contained",
            "--nocapture",
        ])
        .env(CREDENTIAL_CHILD, "1")
        .output()
        .expect("run isolated credential child");
    assert!(
        output.status.success(),
        "isolated credential child failed with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn x86_64_access_rejects_unknown_modes_flags_and_invalid_paths() {
    let (_cleanup, _root, directory) = fixture_root();
    let directory = borrow(&directory);

    assert!(
        fs::Access::from_bits(0x8).is_none(),
        "unknown access mode bits must not enter the safe API",
    );
    assert_eq!(
        fs::access("record", fs::Access::from_bits_retain(0x8)).unwrap_err(),
        Errno::INVAL,
    );
    assert_eq!(
        fs::accessat(
            directory,
            "record",
            fs::Access::EXISTS,
            fs::AccessAtFlags::from_bits_retain(0x400),
        )
        .unwrap_err(),
        Errno::INVAL,
    );
    assert_eq!(
        fs::access(
            b"record\0suffix".as_slice(),
            fs::Access::EXISTS,
        )
        .unwrap_err(),
        Errno::INVAL,
    );
    let overlong = [b'x'; fs::SMALL_PATH_BUFFER_SIZE];
    assert_eq!(
        fs::access(&overlong, fs::Access::EXISTS).unwrap_err(),
        Errno::NAMETOOLONG,
    );
}
