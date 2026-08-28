#![cfg(target_arch = "x86_64")]

use std::os::fd::AsRawFd;

use crabc_rs::fs::{self as cfs, AtFlags, ChownFlags, FileType, Mode, OFlags, UnlinkAtFlags};
use crabc_rs::{process::Uid, BorrowedFd};

fn mode(bits: u32) -> Mode {
    Mode::from_bits(bits).expect("valid mode bits")
}

#[test]
fn x86_64_path_lifecycle_is_descriptor_relative_and_typed() {
    let root = format!(
        "/tmp/crabc-x86-path-lifecycle-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("wall-clock fixture suffix")
            .as_nanos(),
    );
    std::fs::create_dir(&root).expect("fixture root");
    let root_fd = std::fs::File::open(&root).expect("root descriptor");
    let root_borrow = || unsafe { BorrowedFd::borrow_raw(root_fd.as_raw_fd()) };

    cfs::mkdirat(root_borrow(), "nested", mode(0o755)).expect("mkdirat");
    let nested = cfs::openat(root_borrow(), "nested", OFlags::DIRECTORY | OFlags::RDONLY, mode(0))
        .expect("openat directory");
    let nested_borrow = || unsafe { BorrowedFd::borrow_raw(nested.as_raw_fd()) };
    let nested_value = format!("{root}/nested/value");
    let nested_pipe2 = format!("{root}/nested/pipe2");
    let nested_link = format!("{root}/nested/link");
    let nested_directory = format!("{root}/nested");
    let root_pipe = format!("{root}/pipe");

    let file = cfs::openat(
        nested_borrow(),
        "value",
        OFlags::CREATE | OFlags::RDWR,
        mode(0o640),
    )
    .expect("openat create");
    assert_eq!(cfs::statat(nested_borrow(), "value", AtFlags::empty()).unwrap().file_type(), FileType::RegularFile);
    assert_eq!(cfs::lstat(nested_value.as_str()).unwrap().file_type(), FileType::RegularFile);
    cfs::fchmod(&file, mode(0o600)).expect("fchmod");
    cfs::chmodat(nested_borrow(), "value", mode(0o640), AtFlags::empty()).expect("chmodat");
    cfs::fchown(&file, None, None).expect("fchown no-change");
    cfs::chownat(nested_borrow(), "value", None, None, ChownFlags::empty()).expect("chownat no-change");
    cfs::chown(nested_value.as_str(), None, None).expect("chown no-change");
    cfs::lchown(nested_value.as_str(), None, None).expect("lchown no-change");
    assert_eq!(
        cfs::chownat(
            nested_borrow(),
            "value",
            Some(Uid::from_raw(u32::MAX)),
            None,
            ChownFlags::empty(),
        )
        .unwrap_err(),
        crabc_rs::Errno::INVAL
    );
    cfs::truncate(nested_value.as_str(), 17).expect("truncate");
    drop(file);

    cfs::mkfifoat(nested_borrow(), "pipe", mode(0o600)).expect("mkfifoat");
    assert_eq!(cfs::statat(nested_borrow(), "pipe", AtFlags::empty()).unwrap().file_type(), FileType::Fifo);
    cfs::mknodat(nested_borrow(), "pipe2", FileType::Fifo, mode(0o600), cfs::FIFO_DEVICE).expect("mknodat fifo");
    cfs::mkfifo(root_pipe.as_str(), mode(0o600)).expect("mkfifo");

    std::os::unix::fs::symlink("value", format!("{root}/nested/link")).expect("symlink fixture");
    assert_eq!(cfs::statat(nested_borrow(), "link", AtFlags::empty()).unwrap().file_type(), FileType::RegularFile);
    assert_eq!(cfs::statat(nested_borrow(), "link", AtFlags::SYMLINK_NOFOLLOW).unwrap().file_type(), FileType::Symlink);
    assert_eq!(
        cfs::chmodat(
            nested_borrow(),
            "link",
            mode(0o600),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .unwrap_err(),
        crabc_rs::Errno::OPNOTSUPP
    );

    assert_eq!(cfs::openat(nested_borrow(), "missing", OFlags::RDONLY, mode(0)).unwrap_err(), crabc_rs::Errno::NOENT);
    assert_eq!(cfs::mknodat(nested_borrow(), "bad", FileType::Unknown, mode(0), cfs::FIFO_DEVICE).unwrap_err(), crabc_rs::Errno::INVAL);

    cfs::unlinkat(nested_borrow(), "pipe", UnlinkAtFlags::empty()).expect("unlinkat");
    cfs::unlink(nested_pipe2.as_str()).expect("unlink");
    cfs::unlink(nested_link.as_str()).expect("unlink symlink");
    cfs::unlinkat(nested_borrow(), "value", UnlinkAtFlags::empty()).expect("unlink value");
    cfs::rmdir(nested_directory.as_str()).expect("rmdir");
    cfs::unlink(root_pipe.as_str()).expect("unlink root fifo");
    std::fs::remove_dir(&root).expect("remove fixture root");
}
