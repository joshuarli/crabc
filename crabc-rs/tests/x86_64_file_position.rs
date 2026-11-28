
use core::cell::Cell;

use crabc_rs::{fs, io, pipe, AsFd, BorrowedFd, Errno, OwnedFd};
use fs::SeekFrom;

#[cfg(target_os = "linux")]
fn anonymous_regular_file() -> OwnedFd {
    fs::memfd_create(
        "crabc-x86-64-file-position",
        fs::MemfdFlags::CLOEXEC | fs::MemfdFlags::ALLOW_SEALING,
    )
    .expect("create anonymous regular file")
}

// Darwin has no memory files; an unlinked temporary file is the closest
// anonymous regular file.
#[cfg(target_os = "macos")]
fn anonymous_regular_file() -> OwnedFd {
    use core::sync::atomic::{AtomicUsize, Ordering};

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
    let path = format!(
        "/tmp/crabc-x86-64-file-position-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed),
    );
    let file = fs::open(
        path.as_str(),
        fs::OFlags::RDWR | fs::OFlags::CREATE | fs::OFlags::EXCL | fs::OFlags::CLOEXEC,
        fs::Mode::RUSR | fs::Mode::WUSR,
    )
    .expect("create anonymous regular file");
    fs::unlink(path.as_str()).expect("unlink anonymous regular file");
    file
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
    #[cfg(target_os = "linux")]
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
    #[cfg(target_os = "linux")]
    let sparse_error = Errno::NXIO;
    // XNU rejects a negative sparse-seek origin as invalid rather than as
    // beyond the end of the file.
    #[cfg(target_os = "macos")]
    let sparse_error = Errno::INVAL;

    for (position, expected) in [
        (SeekFrom::Start(too_large), Errno::INVAL),
        (SeekFrom::Data(too_large), sparse_error),
        (SeekFrom::Hole(too_large), sparse_error),
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
