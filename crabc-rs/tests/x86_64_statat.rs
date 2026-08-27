#![cfg(target_arch = "x86_64")]

use core::ffi::CStr;
use std::fs::{self as std_fs, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;

use crabc_rs::{fs, BorrowedFd, Errno};

struct RemoveDirectoryOnDrop(PathBuf);

impl Drop for RemoveDirectoryOnDrop {
    fn drop(&mut self) {
        let _ = std_fs::remove_dir_all(&self.0);
    }
}

struct RestoreCurrentDirectoryOnDrop(PathBuf);

impl RestoreCurrentDirectoryOnDrop {
    fn enter(directory: &PathBuf) -> Self {
        let original = std::env::current_dir().expect("capture original current directory");
        // The native runner uses one test thread, so this process-global test
        // change cannot race another test while it proves `AT_FDCWD` semantics.
        std::env::set_current_dir(directory).expect("enter statat fixture directory");
        Self(original)
    }
}

impl Drop for RestoreCurrentDirectoryOnDrop {
    fn drop(&mut self) {
        std::env::set_current_dir(&self.0).expect("restore original current directory");
    }
}

fn fixture_root() -> (RemoveDirectoryOnDrop, PathBuf, File, File) {
    let mut root = std::env::temp_dir();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    root.push(format!("crabc-x86-statat-{}-{nonce}", std::process::id()));
    std_fs::create_dir(&root).expect("create private statat fixture directory");
    let cleanup = RemoveDirectoryOnDrop(root.clone());

    let record_path = root.join("record");
    let mut record = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&record_path)
        .expect("create statat fixture file");
    record.write_all(b"statat").expect("write statat fixture file");
    record.sync_all().expect("flush statat fixture file");
    std_fs::set_permissions(&record_path, std_fs::Permissions::from_mode(0o640))
        .expect("set statat fixture mode");
    symlink("record", root.join("link")).expect("create relative symlink");

    let directory = File::open(&root).expect("open fixture directory");
    (cleanup, root, directory, record)
}

fn borrow(file: &File) -> BorrowedFd<'_> {
    // SAFETY: The fixture retains the descriptor's owner for every immediate
    // statat/fstat observation using this borrow.
    unsafe { BorrowedFd::borrow_raw(file.as_raw_fd()) }
}

#[test]
fn x86_64_statat_observes_descriptor_relative_and_cwd_metadata() {
    let (_cleanup, root, directory, record) = fixture_root();
    let directory = borrow(&directory);
    let by_fd = fs::fstat(borrow(&record)).expect("fstat fixture file");

    let by_relative = fs::statat(directory, "record", fs::AtFlags::empty())
        .expect("statat relative fixture path");
    assert_eq!(by_relative.st_ino, by_fd.st_ino);
    assert_eq!(by_relative.st_dev, by_fd.st_dev);
    assert_eq!(by_relative.st_size, 6);
    assert_eq!(by_relative.st_mode & 0o170000, 0o100000);
    assert_eq!(by_relative.st_mode & 0o777, 0o640);
    assert_eq!(
        fs::statat(borrow(&record), "record", fs::AtFlags::empty()).unwrap_err(),
        Errno::NOTDIR,
    );

    let from_c_str = CStr::from_bytes_with_nul(b"record\0").expect("literal C path");
    assert_eq!(
        fs::statat(directory, from_c_str, fs::AtFlags::empty())
            .expect("statat C-string fixture path")
            .st_ino,
        by_fd.st_ino,
    );

    {
        let _restore_cwd = RestoreCurrentDirectoryOnDrop::enter(&root);
        assert_eq!(
            fs::statat(fs::CWD, "record", fs::AtFlags::empty())
                .expect("statat current-directory relative path")
                .st_ino,
            by_fd.st_ino,
        );
        assert_eq!(
            fs::stat("record")
                .expect("stat current-directory relative path")
                .st_ino,
            by_fd.st_ino,
        );
    }
}

#[test]
fn x86_64_statat_distinguishes_symlink_following_and_missing_paths() {
    let (_cleanup, _root, directory, record) = fixture_root();
    let directory = borrow(&directory);
    let record = fs::fstat(borrow(&record)).expect("fstat fixture file");

    let followed = fs::statat(directory, "link", fs::AtFlags::empty())
        .expect("follow fixture symlink");
    assert_eq!(followed.st_ino, record.st_ino);
    assert_eq!(followed.st_mode & 0o170000, 0o100000);

    let link = fs::statat(directory, "link", fs::AtFlags::SYMLINK_NOFOLLOW)
        .expect("observe fixture symlink itself");
    assert_eq!(link.st_mode & 0o170000, 0o120000);
    assert_eq!(link.st_size, 6);

    assert_eq!(
        fs::statat(directory, "missing", fs::AtFlags::empty()).unwrap_err(),
        Errno::NOENT,
    );
}

#[test]
fn x86_64_statat_rejects_interior_nuls_overlong_no_alloc_paths_and_unknown_flags() {
    let (_cleanup, _root, directory, _record) = fixture_root();
    let directory = borrow(&directory);

    assert_eq!(
        fs::statat(directory, &b"record\0suffix"[..], fs::AtFlags::empty()).unwrap_err(),
        Errno::INVAL,
    );
    let overlong = [b'x'; 256];
    assert_eq!(
        fs::statat(directory, &overlong, fs::AtFlags::empty()).unwrap_err(),
        Errno::NAMETOOLONG,
    );
    assert_eq!(
        fs::statat(
            directory,
            "record",
            fs::AtFlags::from_bits_retain(0x0000_1000),
        )
        .unwrap_err(),
        Errno::INVAL,
    );
    assert_eq!(
        fs::statat(
            directory,
            "record",
            fs::AtFlags::from_bits_retain(0x4000_0000),
        )
        .unwrap_err(),
        Errno::INVAL,
    );
}

#[test]
fn x86_64_statat_accepts_non_utf8_byte_pathnames() {
    let mut root = std::env::temp_dir();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    root.push(format!("crabc-x86-statat-bytes-{}-{nonce}", std::process::id()));
    std_fs::create_dir(&root).expect("create byte-path fixture directory");
    let _cleanup = RemoveDirectoryOnDrop(root.clone());
    let name = b"record-\xff";
    let path = root.join(std::ffi::OsStr::from_bytes(name));
    std_fs::write(&path, b"bytes").expect("create non-UTF-8 fixture file");
    let directory = File::open(&root).expect("open byte-path fixture directory");

    let observed = fs::statat(borrow(&directory), &name[..], fs::AtFlags::empty())
        .expect("stat non-UTF-8 byte path");
    assert_eq!(observed.st_size, 5);
    assert_eq!(observed.st_mode & 0o170000, 0o100000);
}
