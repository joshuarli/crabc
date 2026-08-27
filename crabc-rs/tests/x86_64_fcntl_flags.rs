#![cfg(target_arch = "x86_64")]

use crabc_rs::{fs, io, pipe, Errno};

#[test]
fn x86_64_fcntl_status_flags_match_the_native_abi() {
    assert_eq!(fs::OFlags::ACCMODE.bits(), 0x0020_0003);
    assert_eq!(fs::OFlags::RWMODE.bits(), 0x0000_0003);
    assert!((fs::OFlags::PATH & fs::OFlags::RWMODE).is_empty());
    assert_eq!(fs::OFlags::RDONLY.bits(), 0);
    assert_eq!(fs::OFlags::WRONLY.bits(), 0x0000_0001);
    assert_eq!(fs::OFlags::RDWR.bits(), 0x0000_0002);
    assert_eq!(fs::OFlags::CREATE.bits(), 0x0000_0040);
    assert_eq!(fs::OFlags::EXCL.bits(), 0x0000_0080);
    assert_eq!(fs::OFlags::NOCTTY.bits(), 0x0000_0100);
    assert_eq!(fs::OFlags::TRUNC.bits(), 0x0000_0200);
    assert_eq!(fs::OFlags::APPEND.bits(), 0x0000_0400);
    assert_eq!(fs::OFlags::NONBLOCK.bits(), 0x0000_0800);
    assert_eq!(fs::OFlags::DSYNC.bits(), 0x0000_1000);
    assert_eq!(fs::OFlags::ASYNC.bits(), 0x0000_2000);
    assert_eq!(fs::OFlags::DIRECT.bits(), 0x0000_4000);
    assert_eq!(fs::OFlags::LARGEFILE.bits(), 0x0000_8000);
    assert_eq!(fs::OFlags::DIRECTORY.bits(), 0x0001_0000);
    assert_eq!(fs::OFlags::NOFOLLOW.bits(), 0x0002_0000);
    assert_eq!(fs::OFlags::NOATIME.bits(), 0x0004_0000);
    assert_eq!(fs::OFlags::CLOEXEC.bits(), 0x0008_0000);
    assert_eq!(fs::OFlags::SYNC.bits(), 0x0010_1000);
    assert_eq!(fs::OFlags::FSYNC, fs::OFlags::SYNC);
    assert_eq!(fs::OFlags::RSYNC, fs::OFlags::SYNC);
    assert_eq!(fs::OFlags::PATH.bits(), 0x0020_0000);
    assert_eq!(fs::OFlags::TMPFILE.bits(), 0x0041_0000);
}

#[test]
fn x86_64_fcntl_status_flags_share_open_file_description_and_restore() {
    let (reader, _writer) = pipe::pipe().expect("create status-flags pipe");
    let duplicate = io::dup(&reader).expect("duplicate status-flags pipe");
    let initial = fs::fcntl_getfl(&reader).expect("read initial status flags");

    assert_eq!(initial & fs::OFlags::ACCMODE, fs::OFlags::RDONLY);
    assert!(!initial.contains(fs::OFlags::NONBLOCK));
    io::fcntl_setfd(&duplicate, io::FdFlags::CLOEXEC)
        .expect("set descriptor-local close-on-exec");

    fs::fcntl_setfl(
        &reader,
        initial
            | fs::OFlags::WRONLY
            | fs::OFlags::NONBLOCK
            | fs::OFlags::CREATE
            | fs::OFlags::EXCL
            | fs::OFlags::TRUNC
            | fs::OFlags::CLOEXEC,
    )
    .expect("set mutable status flag");

    let changed = fs::fcntl_getfl(&duplicate).expect("read duplicate status flags");
    assert!(changed.contains(fs::OFlags::NONBLOCK));
    assert_eq!(
        changed & fs::OFlags::ACCMODE,
        fs::OFlags::RDONLY,
        "F_SETFL must not change the open access mode",
    );
    assert!(!changed.intersects(
        fs::OFlags::CREATE | fs::OFlags::EXCL | fs::OFlags::TRUNC | fs::OFlags::CLOEXEC
    ));
    assert!(!io::fcntl_getfd(&reader)
        .expect("read descriptor flags")
        .contains(io::FdFlags::CLOEXEC));
    assert!(io::fcntl_getfd(&duplicate)
        .expect("read duplicate descriptor flags")
        .contains(io::FdFlags::CLOEXEC));

    fs::fcntl_setfl(&duplicate, initial).expect("restore status flags through duplicate");
    assert_eq!(
        fs::fcntl_getfl(&reader).expect("read restored status flags"),
        initial,
        "restoring through a duplicate must update the shared open file description",
    );
}

#[test]
fn x86_64_fcntl_status_flags_reject_closed_descriptor() {
    let (reader, _writer) = pipe::pipe().expect("create EBADF fixture");
    let raw = reader.into_raw_fd();
    crabc_core::io::close(raw).expect("close EBADF fixture");

    // A safe `AsFd` input must remain open, so probe the raw core syscall seam
    // after close rather than construct an invalid BorrowedFd.
    assert_eq!(crabc_core::io::fcntl_getfl(raw), Err(Errno::BADF));
    assert_eq!(
        crabc_core::io::fcntl_setfl(raw, fs::OFlags::NONBLOCK.bits()),
        Err(Errno::BADF)
    );
}
