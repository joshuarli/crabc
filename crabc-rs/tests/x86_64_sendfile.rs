#![cfg(target_arch = "x86_64")]

use core::cell::Cell;
use std::os::fd::{AsRawFd, IntoRawFd};

use crabc_rs::{fs, io, AsFd, BorrowedFd, Errno};

struct RemoveFilesOnDrop([std::path::PathBuf; 2]);

impl Drop for RemoveFilesOnDrop {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn sendfile_fixture() -> (std::fs::File, std::fs::File, RemoveFilesOnDrop) {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    let mut input_path = std::env::temp_dir();
    input_path.push(format!(
        "crabc-x86-sendfile-input-{}-{nonce}",
        std::process::id()
    ));
    let mut output_path = std::env::temp_dir();
    output_path.push(format!(
        "crabc-x86-sendfile-output-{}-{nonce}",
        std::process::id()
    ));

    let input = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&input_path)
        .expect("create unique sendfile input fixture");
    let output = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&output_path)
        .expect("create unique sendfile output fixture");
    (input, output, RemoveFilesOnDrop([input_path, output_path]))
}

fn borrow_file(file: &std::fs::File) -> BorrowedFd<'_> {
    // SAFETY: `file` retains ownership of its descriptor for every immediate
    // direct-facade call using this borrowed view.
    unsafe { BorrowedFd::borrow_raw(file.as_raw_fd()) }
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
fn x86_64_sendfile_preserves_explicit_input_position_and_advances_shared_position() {
    let (input, output, _cleanup) = sendfile_fixture();
    assert_eq!(
        io::write(borrow_file(&input), b"0123456789").expect("seed sendfile input"),
        10,
    );
    assert_eq!(
        fs::seek(borrow_file(&input), fs::SeekFrom::Start(8))
            .expect("position sendfile input"),
        8,
    );

    let mut explicit_offset = 2;
    assert_eq!(
        fs::sendfile(
            borrow_file(&output),
            borrow_file(&input),
            Some(&mut explicit_offset),
            4,
        )
        .expect("send positioned input range"),
        4,
    );
    assert_eq!(
        explicit_offset, 6,
        "explicit input offset advances by copied bytes"
    );
    assert_eq!(
        fs::tell(borrow_file(&input)).expect("observe input after explicit sendfile"),
        8,
        "an explicit sendfile offset must not move the input descriptor",
    );
    assert_eq!(
        fs::tell(borrow_file(&output)).expect("observe output after explicit sendfile"),
        4,
        "the output descriptor advances for an explicit input offset",
    );

    let mut positioned = [0_u8; 4];
    assert_eq!(
        io::pread(borrow_file(&output), &mut positioned, 0)
            .expect("read explicit sendfile output"),
        4,
    );
    assert_eq!(&positioned, b"2345");

    // Starting at input position eight with an eight-byte request reaches EOF
    // after two bytes. The direct result must be the short count, not a retry.
    assert_eq!(
        fs::sendfile(
            borrow_file(&output),
            borrow_file(&input),
            None,
            8,
        )
        .expect("send short current-position range"),
        2,
    );
    assert_eq!(
        fs::tell(borrow_file(&input)).expect("observe input after short sendfile"),
        10,
        "a null input offset advances the shared input position",
    );
    assert_eq!(
        fs::tell(borrow_file(&output)).expect("observe output after short sendfile"),
        6,
        "the output position advances by the short sendfile count",
    );

    let mut complete = [0_u8; 6];
    assert_eq!(
        io::pread(borrow_file(&output), &mut complete, 0)
            .expect("read complete sendfile output"),
        6,
    );
    assert_eq!(&complete, b"234589");

    assert_eq!(
        fs::sendfile(
            borrow_file(&output),
            borrow_file(&input),
            None,
            1,
        )
        .expect("send zero-length EOF transfer"),
        0,
        "sendfile must return zero at EOF without retrying",
    );
    assert_eq!(
        fs::tell(borrow_file(&input)).expect("observe input after EOF sendfile"),
        10,
    );
    assert_eq!(
        fs::tell(borrow_file(&output)).expect("observe output after EOF sendfile"),
        6,
    );
}

#[test]
fn x86_64_sendfile_rejects_unrepresentable_explicit_offsets_before_the_syscall() {
    let (input, output, _cleanup) = sendfile_fixture();
    assert_eq!(
        io::write(borrow_file(&input), b"input").expect("seed sendfile input"),
        5,
    );
    fs::seek(borrow_file(&input), fs::SeekFrom::Start(3))
        .expect("position input fixture");
    fs::seek(borrow_file(&output), fs::SeekFrom::Start(0))
        .expect("position output fixture");

    let input_borrowed = Cell::new(false);
    let output_borrowed = Cell::new(false);
    let mut offset = i64::MAX as u64 + 1;
    assert_eq!(
        fs::sendfile(
            TrackingFd {
                fd: borrow_file(&output),
                borrowed: &output_borrowed,
            },
            TrackingFd {
                fd: borrow_file(&input),
                borrowed: &input_borrowed,
            },
            Some(&mut offset),
            1,
        ),
        Err(Errno::INVAL),
    );
    assert_eq!(
        offset,
        i64::MAX as u64 + 1,
        "a rejected explicit offset must remain untouched",
    );
    assert!(
        !input_borrowed.get() && !output_borrowed.get(),
        "an unrepresentable offset must fail before borrowing either descriptor",
    );
    assert_eq!(
        fs::tell(borrow_file(&input)).expect("observe input after rejected sendfile"),
        3,
    );
    assert_eq!(
        fs::tell(borrow_file(&output)).expect("observe output after rejected sendfile"),
        0,
    );
}

#[test]
fn x86_64_sendfile_closed_input_descriptor_reports_ebadf_at_the_raw_seam() {
    let (input, output, _cleanup) = sendfile_fixture();
    let raw_input = input.into_raw_fd();
    crabc_core::io::close(raw_input).expect("close sendfile EBADF input fixture");

    // A safe `AsFd` input cannot describe a closed descriptor. Exercise the
    // raw core seam after close rather than construct an invalid borrow.
    assert_eq!(
        crabc_core::io::sendfile(output.as_raw_fd(), raw_input, None, 1),
        Err(Errno::BADF),
    );
}
