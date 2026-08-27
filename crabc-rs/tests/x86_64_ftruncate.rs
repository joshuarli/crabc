#![cfg(target_arch = "x86_64")]

use core::cell::Cell;

use crabc_rs::{fs, io, pipe, AsFd, BorrowedFd, Errno, OwnedFd};

fn anonymous_regular_file() -> OwnedFd {
    fs::memfd_create(
        "crabc-x86-64-ftruncate",
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
fn x86_64_ftruncate_extends_with_zeroes_and_truncates_memfd_size() {
    let file = anonymous_regular_file();
    assert_eq!(io::write(&file, b"ABCD").expect("seed memory file"), 4);
    assert_eq!(fs::fstat(&file).expect("stat seeded memory file").st_size, 4);

    fs::ftruncate(&file, 12).expect("extend memory file");
    assert_eq!(fs::fstat(&file).expect("stat extended memory file").st_size, 12);

    let mut extension = [0xff_u8; 8];
    assert_eq!(
        io::pread(&file, &mut extension, 4).expect("read extended range"),
        extension.len(),
    );
    assert_eq!(
        extension, [0; 8],
        "Linux must expose newly extended regular-file bytes as zeroes",
    );

    fs::ftruncate(&file, 2).expect("truncate memory file");
    assert_eq!(fs::fstat(&file).expect("stat truncated memory file").st_size, 2);
    let mut retained = [0_u8; 2];
    assert_eq!(
        io::pread(&file, &mut retained, 0).expect("read retained prefix"),
        retained.len(),
    );
    assert_eq!(retained, *b"AB");
}

#[test]
fn x86_64_ftruncate_rejects_lengths_outside_signed_loff_t_before_borrowing() {
    let file = anonymous_regular_file();
    assert_eq!(io::write(&file, b"ABCD").expect("seed regular file"), 4);

    let borrowed = Cell::new(false);
    let tracked = TrackingFd {
        fd: file.as_fd(),
        borrowed: &borrowed,
    };
    assert_eq!(
        fs::ftruncate(tracked, i64::MAX as u64 + 1),
        Err(Errno::INVAL),
        "an unsigned length beyond Linux loff_t must be rejected",
    );
    assert!(
        !borrowed.get(),
        "the signed-range guard must reject before borrowing the descriptor",
    );
    assert_eq!(
        fs::fstat(&file)
            .expect("stat after rejected signed-range request")
            .st_size,
        4,
        "a locally rejected length must not change the regular-file size",
    );
}

#[test]
fn x86_64_ftruncate_keeps_non_regular_descriptor_errors_direct() {
    let (reader, _writer) = pipe::pipe().expect("create pipe for ftruncate error boundary");
    assert_eq!(
        fs::ftruncate(&reader, 0),
        Err(Errno::INVAL),
        "Linux rejects ftruncate on a pipe rather than treating it as a file",
    );
}
