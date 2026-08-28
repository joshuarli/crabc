#![cfg(target_arch = "x86_64")]

use core::cell::Cell;

use crabc_rs::{fs, io};
use crabc_rs::{AsFd, BorrowedFd, Errno, OwnedFd};

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

fn allocation_fixture() -> OwnedFd {
    fs::memfd_create("crabc-x86-64-posix-fallocate", fs::MemfdFlags::CLOEXEC)
        .expect("create a mode-zero allocation fixture")
}

#[test]
fn x86_64_posix_fallocate_extends_without_moving_position() {
    let file = allocation_fixture();
    assert_eq!(io::write(&file, b"crabc-x8").expect("seed allocation fixture"), 8);

    assert_eq!(fs::seek(&file, fs::SeekFrom::Start(17)).expect("set file position"), 17);
    fs::posix_fallocate(&file, 4096, 4096).expect("allocate a mode-zero range");

    assert_eq!(
        fs::tell(&file).expect("read position after allocation"),
        17,
        "posix_fallocate must not change the descriptor's shared position",
    );
    assert_eq!(
        fs::fstat(&file).expect("read file metadata after allocation").st_size,
        8192,
        "allocation beyond EOF extends the memfd",
    );

    let mut retained = [0_u8; 8];
    assert_eq!(
        io::pread(&file, &mut retained, 0).expect("read retained prefix"),
        retained.len(),
    );
    assert_eq!(retained, *b"crabc-x8");

    let mut allocated = [0xff_u8; 8];
    assert_eq!(
        io::pread(&file, &mut allocated, 4096).expect("read allocated range"),
        allocated.len(),
    );
    assert_eq!(
        allocated, [0; 8],
        "Linux must expose a newly allocated unwritten regular-file range as zeroes",
    );
}

#[test]
fn x86_64_posix_fallocate_rejects_unrepresentable_ranges_before_borrowing_fd() {
    let file = allocation_fixture();
    let borrowed = Cell::new(false);

    let tracking = TrackingFd {
        fd: file.as_fd(),
        borrowed: &borrowed,
    };
    assert_eq!(
        fs::posix_fallocate(tracking, i64::MAX as u64 + 1, 0),
        Err(Errno::INVAL),
        "an unrepresentable offset is rejected before AsFd conversion",
    );
    assert!(!borrowed.get());

    borrowed.set(false);
    let tracking = TrackingFd {
        fd: file.as_fd(),
        borrowed: &borrowed,
    };
    assert_eq!(
        fs::posix_fallocate(tracking, 0, i64::MAX as u64 + 1),
        Err(Errno::INVAL),
        "an unrepresentable length is rejected before AsFd conversion",
    );
    assert!(!borrowed.get());

    borrowed.set(false);
    let tracking = TrackingFd {
        fd: file.as_fd(),
        borrowed: &borrowed,
    };
    assert_eq!(
        fs::posix_fallocate(tracking, i64::MAX as u64, 1),
        Err(Errno::INVAL),
        "an overflowing offset-plus-length is rejected before AsFd conversion",
    );
    assert!(!borrowed.get());
}

#[test]
fn x86_64_posix_fallocate_forwards_zero_length_to_linux() {
    let file = allocation_fixture();

    // Linux's direct fallocate mode-zero syscall rejects length zero. The
    // native facade preserves that kernel result instead of adopting the C
    // wrapper's separate error-convention or emulating a no-op.
    assert_eq!(fs::posix_fallocate(&file, 0, 0), Err(Errno::INVAL));
}

#[test]
fn x86_64_posix_fallocate_raw_closed_descriptor_reports_ebadf() {
    let file = allocation_fixture();
    let raw = file.into_raw_fd();
    crabc_core::io::close(raw).expect("close posix_fallocate EBADF fixture");

    // A safe `AsFd` input cannot describe a closed descriptor. Exercise the
    // shared raw core seam after close rather than construct an invalid borrow.
    assert_eq!(crabc_core::fs::fallocate(raw, 0, 0, 1), Err(Errno::BADF));
}
