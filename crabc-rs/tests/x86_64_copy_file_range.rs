#![cfg(target_arch = "x86_64")]

use core::cell::Cell;
use std::os::fd::{AsRawFd, IntoRawFd};

use crabc_rs::{fs, io, AsFd, BorrowedFd, Errno};

struct RemoveFilesOnDrop {
    input: Option<std::path::PathBuf>,
    output: Option<std::path::PathBuf>,
}

impl Drop for RemoveFilesOnDrop {
    fn drop(&mut self) {
        for path in [self.input.take(), self.output.take()].into_iter().flatten() {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn copy_file_range_fixture() -> (std::fs::File, std::fs::File, RemoveFilesOnDrop) {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    let mut input_path = std::env::temp_dir();
    input_path.push(format!(
        "crabc-x86-copy-file-range-input-{}-{nonce}",
        std::process::id()
    ));
    let mut output_path = std::env::temp_dir();
    output_path.push(format!(
        "crabc-x86-copy-file-range-output-{}-{nonce}",
        std::process::id()
    ));

    let input = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&input_path)
        .expect("create unique copy_file_range input fixture");
    let mut cleanup = RemoveFilesOnDrop {
        input: Some(input_path),
        output: None,
    };
    let output = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&output_path)
        .expect("create unique copy_file_range output fixture");
    cleanup.output = Some(output_path);
    (input, output, cleanup)
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
fn x86_64_copy_file_range_stages_offsets_and_preserves_position_modes() {
    let (input, output, _cleanup) = copy_file_range_fixture();
    assert_eq!(
        io::write(borrow_file(&input), b"0123456789")
            .expect("seed copy_file_range input"),
        10,
    );
    assert_eq!(
        fs::seek(borrow_file(&input), fs::SeekFrom::Start(7))
            .expect("position copy_file_range input"),
        7,
    );
    assert_eq!(
        fs::seek(borrow_file(&output), fs::SeekFrom::Start(3))
            .expect("position copy_file_range output"),
        3,
    );

    let mut explicit_input = 1;
    let mut explicit_output = 5;
    assert_eq!(
        fs::copy_file_range(
            borrow_file(&input),
            Some(&mut explicit_input),
            borrow_file(&output),
            Some(&mut explicit_output),
            4,
        )
        .expect("copy explicit range"),
        4,
    );
    assert_eq!(explicit_input, 5, "explicit input offset advances by four");
    assert_eq!(
        explicit_output, 9,
        "explicit output offset advances by four"
    );
    assert_eq!(
        fs::tell(borrow_file(&input)).expect("observe input after explicit copy"),
        7,
        "an explicit input offset must not move the input descriptor",
    );
    assert_eq!(
        fs::tell(borrow_file(&output)).expect("observe output after explicit copy"),
        3,
        "an explicit output offset must not move the output descriptor",
    );

    let mut positioned = [0_u8; 4];
    assert_eq!(
        io::pread(borrow_file(&output), &mut positioned, 5)
            .expect("read explicit copy output"),
        4,
    );
    assert_eq!(&positioned, b"1234");

    let mut short_input = 8;
    let mut short_output = 0;
    assert_eq!(
        fs::copy_file_range(
            borrow_file(&input),
            Some(&mut short_input),
            borrow_file(&output),
            Some(&mut short_output),
            8,
        )
        .expect("copy short explicit range"),
        2,
        "copy_file_range must return its short count without retrying",
    );
    assert_eq!(short_input, 10, "short input offset advances by two");
    assert_eq!(short_output, 2, "short output offset advances by two");
    assert_eq!(
        fs::tell(borrow_file(&input)).expect("observe input after short copy"),
        7,
    );
    assert_eq!(
        fs::tell(borrow_file(&output)).expect("observe output after short copy"),
        3,
    );

    let mut short_bytes = [0_u8; 2];
    assert_eq!(
        io::pread(borrow_file(&output), &mut short_bytes, 0)
            .expect("read short copy output"),
        2,
    );
    assert_eq!(&short_bytes, b"89");

    assert_eq!(
        fs::copy_file_range(
            borrow_file(&input),
            Some(&mut short_input),
            borrow_file(&output),
            Some(&mut short_output),
            1,
        )
        .expect("copy explicit EOF range"),
        0,
        "copy_file_range must return zero at EOF without retrying",
    );
    assert_eq!(short_input, 10, "EOF leaves the explicit input offset stable");
    assert_eq!(short_output, 2, "EOF leaves the explicit output offset stable");

    assert_eq!(
        fs::copy_file_range(borrow_file(&input), None, borrow_file(&output), None, 2)
            .expect("copy through shared positions"),
        2,
    );
    assert_eq!(
        fs::tell(borrow_file(&input)).expect("observe input after shared copy"),
        9,
        "a null input offset advances the shared input position",
    );
    assert_eq!(
        fs::tell(borrow_file(&output)).expect("observe output after shared copy"),
        5,
        "a null output offset advances the shared output position",
    );

    let mut shared_bytes = [0_u8; 2];
    assert_eq!(
        io::pread(borrow_file(&output), &mut shared_bytes, 3)
            .expect("read shared-position copy output"),
        2,
    );
    assert_eq!(&shared_bytes, b"78");

    let mut positioned_input = 0;
    assert_eq!(
        fs::copy_file_range(
            borrow_file(&input),
            Some(&mut positioned_input),
            borrow_file(&output),
            None,
            2,
        )
        .expect("copy positioned input through shared output position"),
        2,
    );
    assert_eq!(positioned_input, 2);
    assert_eq!(
        fs::tell(borrow_file(&input)).expect("observe input after mixed copy"),
        9,
        "an explicit input offset must preserve the shared input position",
    );
    assert_eq!(
        fs::tell(borrow_file(&output)).expect("observe output after mixed copy"),
        7,
        "a null output offset advances the shared output position",
    );

    let mut positioned_output = 8;
    assert_eq!(
        fs::copy_file_range(
            borrow_file(&input),
            None,
            borrow_file(&output),
            Some(&mut positioned_output),
            2,
        )
        .expect("copy shared input through positioned output"),
        1,
        "the mixed range must preserve a short direct result",
    );
    assert_eq!(positioned_output, 9);
    assert_eq!(
        fs::tell(borrow_file(&input)).expect("observe input after second mixed copy"),
        10,
        "a null input offset advances the shared input position",
    );
    assert_eq!(
        fs::tell(borrow_file(&output)).expect("observe output after second mixed copy"),
        7,
        "an explicit output offset must preserve the shared output position",
    );
    let mut mixed_bytes = [0_u8; 4];
    assert_eq!(
        io::pread(borrow_file(&output), &mut mixed_bytes, 5)
            .expect("read mixed-position copy output"),
        4,
    );
    assert_eq!(&mixed_bytes, b"0139");
}

#[test]
fn x86_64_copy_file_range_rejects_unrepresentable_ranges_before_as_fd() {
    let (input, output, _cleanup) = copy_file_range_fixture();
    assert_eq!(
        io::write(borrow_file(&input), b"input").expect("seed copy range input"),
        5,
    );
    fs::seek(borrow_file(&input), fs::SeekFrom::Start(3))
        .expect("position copy range input");
    fs::seek(borrow_file(&output), fs::SeekFrom::Start(0))
        .expect("position copy range output");

    let input_borrowed = Cell::new(false);
    let output_borrowed = Cell::new(false);
    let mut input_offset = i64::MAX as u64;
    let mut output_offset = 17;
    assert_eq!(
        fs::copy_file_range(
            TrackingFd {
                fd: borrow_file(&input),
                borrowed: &input_borrowed,
            },
            Some(&mut input_offset),
            TrackingFd {
                fd: borrow_file(&output),
                borrowed: &output_borrowed,
            },
            Some(&mut output_offset),
            1,
        ),
        Err(Errno::INVAL),
    );
    assert_eq!(
        input_offset,
        i64::MAX as u64,
        "a rejected input range must remain untouched",
    );
    assert_eq!(
        output_offset, 17,
        "a rejected input range must not initialize the output offset",
    );
    assert!(
        !input_borrowed.get() && !output_borrowed.get(),
        "an unrepresentable range must fail before either AsFd conversion",
    );
    assert_eq!(
        fs::tell(borrow_file(&input)).expect("observe input after rejected copy"),
        3,
    );
    assert_eq!(
        fs::tell(borrow_file(&output)).expect("observe output after rejected copy"),
        0,
    );

    let mut oversized_input_offset = i64::MAX as u64 + 1;
    let mut second_output_offset = 23;
    assert_eq!(
        fs::copy_file_range(
            TrackingFd {
                fd: borrow_file(&input),
                borrowed: &input_borrowed,
            },
            Some(&mut oversized_input_offset),
            TrackingFd {
                fd: borrow_file(&output),
                borrowed: &output_borrowed,
            },
            Some(&mut second_output_offset),
            0,
        ),
        Err(Errno::INVAL),
    );
    assert_eq!(
        oversized_input_offset,
        i64::MAX as u64 + 1,
        "a signed-loff_t-unrepresentable offset must remain untouched",
    );
    assert_eq!(
        second_output_offset, 23,
        "a rejected input offset must not initialize the output offset",
    );
    assert!(
        !input_borrowed.get() && !output_borrowed.get(),
        "an unrepresentable offset must fail before either AsFd conversion",
    );

    let mut third_input_offset = 11;
    let mut max_output_offset = i64::MAX as u64;
    assert_eq!(
        fs::copy_file_range(
            TrackingFd {
                fd: borrow_file(&input),
                borrowed: &input_borrowed,
            },
            Some(&mut third_input_offset),
            TrackingFd {
                fd: borrow_file(&output),
                borrowed: &output_borrowed,
            },
            Some(&mut max_output_offset),
            1,
        ),
        Err(Errno::INVAL),
    );
    assert_eq!(third_input_offset, 11);
    assert_eq!(max_output_offset, i64::MAX as u64);
    assert!(
        !input_borrowed.get() && !output_borrowed.get(),
        "an unrepresentable output range must fail before either AsFd conversion",
    );

    let mut fourth_input_offset = 13;
    let mut oversized_output_offset = i64::MAX as u64 + 1;
    assert_eq!(
        fs::copy_file_range(
            TrackingFd {
                fd: borrow_file(&input),
                borrowed: &input_borrowed,
            },
            Some(&mut fourth_input_offset),
            TrackingFd {
                fd: borrow_file(&output),
                borrowed: &output_borrowed,
            },
            Some(&mut oversized_output_offset),
            0,
        ),
        Err(Errno::INVAL),
    );
    assert_eq!(fourth_input_offset, 13);
    assert_eq!(oversized_output_offset, i64::MAX as u64 + 1);
    assert!(
        !input_borrowed.get() && !output_borrowed.get(),
        "an oversized output offset must fail before either AsFd conversion",
    );
}

#[test]
fn x86_64_copy_file_range_keeps_offsets_staged_on_kernel_error() {
    let (input, output, _cleanup) = copy_file_range_fixture();
    let directory = std::fs::File::open(std::env::temp_dir())
        .expect("open directory copy_file_range error fixture");
    let mut input_offset = 0;
    let mut output_offset = 17;
    assert_eq!(
        fs::copy_file_range(
            borrow_file(&directory),
            Some(&mut input_offset),
            borrow_file(&output),
            Some(&mut output_offset),
            1,
        ),
        Err(Errno::ISDIR),
    );
    assert_eq!(input_offset, 0, "kernel failure must not commit input offset");
    assert_eq!(
        output_offset, 17,
        "kernel failure must not commit output offset",
    );

    let raw_input = input.into_raw_fd();
    crabc_core::io::close(raw_input).expect("close copy_file_range EBADF input");
    // A safe `AsFd` input cannot describe a closed descriptor. Exercise the
    // raw core seam after close rather than construct an invalid borrow.
    assert_eq!(
        crabc_core::fs::copy_file_range(raw_input, None, output.as_raw_fd(), None, 1),
        Err(Errno::BADF),
    );
}
