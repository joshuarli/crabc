#![cfg(target_arch = "x86_64")]

use core::cell::Cell;

use crabc_rs::{fs, io, pipe, AsFd, BorrowedFd, Errno, OwnedFd};
use fs::SeekFrom;

fn anonymous_regular_file() -> OwnedFd {
    fs::memfd_create(
        "crabc-x86-64-file-position",
        fs::MemfdFlags::CLOEXEC | fs::MemfdFlags::ALLOW_SEALING,
    )
    .expect("create anonymous regular file")
}

struct TrackingFd<'fd> {
    fd: BorrowedFd<'fd>,
    borrowed: &'fd Cell<bool>,
}

impl AsFd for TrackingFd<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.borrowed.set(true);
        self.fd
    }
}

#[test]
fn x86_64_file_position_observes_seek_tell_truncate_and_sync_on_memfd() {
    let file = anonymous_regular_file();
    assert_eq!(io::write(&file, b"0123456789").expect("seed memory file"), 10);
    assert_eq!(fs::tell(&file).expect("tell after write"), 10);

    assert_eq!(
        fs::seek(&file, SeekFrom::Start(3)).expect("seek from start"),
        3
    );
    assert_eq!(
        fs::seek(&file, SeekFrom::Current(2)).expect("seek from current"),
        5
    );
    assert_eq!(
        fs::seek(&file, SeekFrom::End(-2)).expect("seek from end"),
        8
    );
    assert_eq!(fs::tell(&file).expect("tell after seeks"), 8);

    fs::ftruncate(&file, 5).expect("truncate memory file");
    assert_eq!(
        fs::tell(&file).expect("tell after truncate"),
        8,
        "ftruncate must not change the shared file position",
    );
    assert_eq!(
        fs::seek(&file, SeekFrom::End(0)).expect("seek to truncated end"),
        5
    );

    fs::fsync(&file).expect("flush memory-file data and metadata");
    fs::fdatasync(&file).expect("flush memory-file data");
}

#[test]
fn x86_64_file_position_finds_sparse_memfd_data_and_holes() {
    let file = anonymous_regular_file();

    assert_eq!(
        fs::seek(&file, SeekFrom::Start(4096)).expect("seek to sparse tail"),
        4096,
    );
    assert_eq!(io::write(&file, b"tail").expect("write sparse tail"), 4);
    assert_eq!(
        fs::seek(&file, SeekFrom::Data(0)).expect("find sparse data"),
        4096,
    );
    assert_eq!(
        fs::seek(&file, SeekFrom::Hole(0)).expect("find sparse hole"),
        0,
    );
}

#[test]
fn x86_64_file_position_forwards_unrepresentable_absolute_offsets_to_linux() {
    let file = anonymous_regular_file();
    let too_large = i64::MAX as u64 + 1;

    for (position, expected) in [
        (SeekFrom::Start(too_large), Errno::INVAL),
        (SeekFrom::Data(too_large), Errno::NXIO),
        (SeekFrom::Hole(too_large), Errno::NXIO),
    ] {
        let borrowed = Cell::new(false);
        let tracked = TrackingFd {
            fd: file.as_fd(),
            borrowed: &borrowed,
        };
        assert_eq!(
            fs::seek(tracked, position),
            Err(expected),
            "an unsigned seek origin outside Linux off_t must preserve Linux's direct error",
        );
        assert!(
            borrowed.get(),
            "the direct x86 boundary must borrow the descriptor before Linux rejects the offset",
        );
    }
}

#[test]
fn x86_64_file_position_keeps_non_seekable_descriptor_errors_direct() {
    let (reader, _writer) = pipe::pipe().expect("create a pipe");
    assert_eq!(
        fs::tell(&reader),
        Err(Errno::SPIPE),
        "lseek on a pipe must remain Linux's direct ESPIPE error",
    );
}
