#![cfg(target_arch = "x86_64")]

use core::cell::Cell;

use crabc_rs::fs::{self, FallocateFlags, SeekFrom};
use crabc_rs::{io, AsFd, BorrowedFd, Errno, OwnedFd};

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
    fs::memfd_create("crabc-x86-64-fallocate", fs::MemfdFlags::CLOEXEC)
        .expect("create a fallocate fixture")
}

fn seed(file: &OwnedFd) {
    assert_eq!(io::write(file, b"abcdefghijklmnop").expect("seed fixture"), 16);
    assert_eq!(
        fs::seek(file, SeekFrom::Start(7)).expect("set fixture position"),
        7
    );
}

#[test]
fn x86_64_fallocate_allocate_and_keep_size_preserve_data_and_position() {
    let file = allocation_fixture();
    seed(&file);

    fs::fallocate(&file, FallocateFlags::ALLOCATE, 4096, 4096)
        .expect("allocate a range beyond the file end");
    assert_eq!(fs::tell(&file).expect("position after allocation"), 7);
    assert_eq!(fs::fstat(&file).expect("stat after allocation").st_size, 8192);

    let mut retained = [0_u8; 16];
    assert_eq!(io::pread(&file, &mut retained, 0).expect("read retained bytes"), 16);
    assert_eq!(retained, *b"abcdefghijklmnop");
    let mut allocated = [0xff_u8; 16];
    assert_eq!(
        io::pread(&file, &mut allocated, 4096).expect("read allocated bytes"),
        16
    );
    assert_eq!(allocated, [0; 16]);

    fs::ftruncate(&file, 16).expect("reset fixture length");
    fs::fallocate(&file, FallocateFlags::KEEP_SIZE, 4096, 4096)
        .expect("allocate without extending file length");
    assert_eq!(fs::tell(&file).expect("position after keep-size allocation"), 7);
    assert_eq!(fs::fstat(&file).expect("stat after keep-size allocation").st_size, 16);
}

#[test]
fn x86_64_fallocate_punch_hole_keep_size_zeroes_data() {
    let file = allocation_fixture();
    seed(&file);

    match fs::fallocate(
        &file,
        FallocateFlags::PUNCH_HOLE | FallocateFlags::KEEP_SIZE,
        4,
        4,
    ) {
        Ok(()) => {}
        Err(Errno::OPNOTSUPP) => return,
        Err(error) => panic!("unexpected PUNCH_HOLE result: {error:?}"),
    }
    assert_eq!(fs::tell(&file).expect("position after hole punch"), 7);
    assert_eq!(fs::fstat(&file).expect("stat after hole punch").st_size, 16);

    let mut contents = [0_u8; 16];
    assert_eq!(io::pread(&file, &mut contents, 0).expect("read punched fixture"), 16);
    assert_eq!(contents, [b'a', b'b', b'c', b'd', 0, 0, 0, 0, b'i', b'j', b'k', b'l', b'm', b'n', b'o', b'p']);
}

#[test]
fn x86_64_fallocate_zero_range_preserves_position_and_size_modes_when_supported() {
    let file = allocation_fixture();
    seed(&file);

    match fs::fallocate(&file, FallocateFlags::ZERO_RANGE, 16, 4) {
        Ok(()) => {}
        Err(Errno::OPNOTSUPP) => return,
        Err(error) => panic!("unexpected ZERO_RANGE result: {error:?}"),
    }
    assert_eq!(fs::tell(&file).expect("position after zero range"), 7);
    assert_eq!(fs::fstat(&file).expect("stat after zero range").st_size, 20);
    let mut extended = [0xff_u8; 4];
    assert_eq!(io::pread(&file, &mut extended, 16).expect("read zero range"), 4);
    assert_eq!(extended, [0; 4]);

    fs::ftruncate(&file, 16).expect("reset fixture length after zero range");
    io::pwrite(&file, b"abcdefghijklmnop", 0).expect("restore fixture data");
    match fs::fallocate(
        &file,
        FallocateFlags::ZERO_RANGE | FallocateFlags::KEEP_SIZE,
        4,
        4,
    ) {
        Ok(()) => {}
        Err(Errno::OPNOTSUPP) => return,
        Err(error) => panic!("unexpected ZERO_RANGE|KEEP_SIZE result: {error:?}"),
    }
    assert_eq!(fs::tell(&file).expect("position after keep-size zero range"), 7);
    assert_eq!(fs::fstat(&file).expect("stat after keep-size zero range").st_size, 16);
    let mut contents = [0_u8; 16];
    assert_eq!(io::pread(&file, &mut contents, 0).expect("read keep-size zero range"), 16);
    assert_eq!(contents, [b'a', b'b', b'c', b'd', 0, 0, 0, 0, b'i', b'j', b'k', b'l', b'm', b'n', b'o', b'p']);
}

#[test]
fn x86_64_fallocate_rejects_unknown_modes_and_bad_combinations_before_borrowing() {
    let file = allocation_fixture();
    for flags in [
        FallocateFlags::from_bits_retain(0x04),
        FallocateFlags::PUNCH_HOLE,
        FallocateFlags::PUNCH_HOLE | FallocateFlags::KEEP_SIZE | FallocateFlags::ZERO_RANGE,
    ] {
        let borrowed = Cell::new(false);
        let tracking = TrackingFd {
            fd: file.as_fd(),
            borrowed: &borrowed,
        };
        assert_eq!(
            fs::fallocate(tracking, flags, 0, 1),
            Err(Errno::INVAL),
            "invalid fallocate mode must be rejected locally",
        );
        assert!(!borrowed.get(), "invalid mode must fail before AsFd conversion");
    }

    let borrowed = Cell::new(false);
    let tracking = TrackingFd {
        fd: file.as_fd(),
        borrowed: &borrowed,
    };
    assert_eq!(
        fs::fallocate(tracking, FallocateFlags::ALLOCATE, i64::MAX as u64, 1),
        Err(Errno::INVAL),
    );
    assert!(!borrowed.get(), "overflow must fail before AsFd conversion");
}

#[test]
fn x86_64_fallocate_raw_closed_descriptor_reports_ebadf() {
    let file = allocation_fixture();
    let raw = file.into_raw_fd();
    crabc_core::io::close(raw).expect("close fallocate EBADF fixture");

    // A safe `AsFd` input cannot describe a closed descriptor. Exercise the
    // shared raw core seam after close rather than construct an invalid borrow.
    assert_eq!(
        crabc_core::fs::fallocate(raw, 0, 0, 1),
        Err(Errno::BADF)
    );
}
