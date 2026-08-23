use core::cell::Cell;
use core::sync::atomic::{AtomicUsize, Ordering};

use crabc_rs::fs::{self, Mode, OFlags, SeekFrom};
use crabc_rs::io;
use crabc_rs::{AsFd, BorrowedFd, Errno};

static SCRATCH_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

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
fn seek_tell_sync_and_truncate_use_the_direct_file_descriptor_seams() {
    let path = format!(
        "/tmp/crabc-rs-descriptor-fs-io-{}-{}",
        std::process::id(),
        SCRATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed),
    );
    let _ = fs::unlink(&path);
    let file = fs::open(
        &path,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create file through the direct kernel seam");

    assert_eq!(io::write(&file, b"0123456789").expect("write fixture"), 10);
    assert_eq!(fs::tell(&file).expect("tell after write"), 10);
    assert_eq!(fs::seek(&file, SeekFrom::Start(3)).expect("seek from start"), 3);
    assert_eq!(fs::seek(&file, SeekFrom::Current(2)).expect("seek from current"), 5);
    assert_eq!(fs::seek(&file, SeekFrom::End(-2)).expect("seek from end"), 8);
    assert_eq!(fs::tell(&file).expect("tell after seeks"), 8);

    fs::ftruncate(&file, 5).expect("truncate fixture");
    assert_eq!(fs::seek(&file, SeekFrom::End(0)).expect("seek to truncated end"), 5);
    fs::fsync(&file).expect("flush file data and metadata");
    fs::fdatasync(&file).expect("flush file data");

    drop(file);
    fs::unlink(&path).expect("remove file fixture");
}

#[test]
fn truncate_rejects_unrepresentable_length_without_changing_file_size() {
    let borrow_called = Cell::new(false);
    let path = format!(
        "/tmp/crabc-rs-descriptor-fs-io-range-{}-{}",
        std::process::id(),
        SCRATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed),
    );
    let _ = fs::unlink(&path);
    let file = fs::open(
        &path,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create ftruncate range fixture");

    io::write(&file, b"0123456789").expect("seed ftruncate range fixture");
    let tracked = TrackingFd {
        fd: file.as_fd(),
        borrowed: &borrow_called,
    };
    assert_eq!(
        fs::ftruncate(tracked, i64::MAX as u64 + 1),
        Err(Errno::INVAL),
        "a length outside signed Linux loff_t must be rejected",
    );
    assert!(!borrow_called.get(), "invalid length must be rejected before the syscall");
    assert_eq!(
        fs::seek(&file, SeekFrom::End(0)).expect("read size after rejected truncate"),
        10,
        "a rejected length must not change the file size",
    );

    drop(file);
    fs::unlink(&path).expect("remove ftruncate range fixture");
}

#[test]
fn sparse_file_seek_variants_preserve_rustix_offsets() {
    let path = format!(
        "/tmp/crabc-rs-descriptor-sparse-{}-{}",
        std::process::id(),
        SCRATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed),
    );
    let _ = fs::unlink(&path);
    let file = fs::open(
        &path,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create sparse file");

    assert_eq!(fs::seek(&file, SeekFrom::Start(4096)).expect("seek past end"), 4096);
    io::write(&file, b"tail").expect("write sparse tail");
    assert_eq!(fs::seek(&file, SeekFrom::Data(0)).expect("find sparse data"), 4096);
    assert_eq!(fs::seek(&file, SeekFrom::Hole(0)).expect("find initial sparse hole"), 0);

    drop(file);
    fs::unlink(&path).expect("remove sparse file fixture");
}
