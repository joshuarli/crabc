use crabc_rs::fs::{self, Mode, OFlags, SeekFrom};
use crabc_rs::io;
use crabc_rs::{BorrowedFd, Errno};

const INPUT_PATH: &[u8] = b"/tmp/crabc-rs-m10-copy-file-range-input";
const OUTPUT_PATH: &[u8] = b"/tmp/crabc-rs-m10-copy-file-range-output";

fn remove_if_present(path: &[u8]) {
    match fs::unlink(path) {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(error) => panic!("remove stale copy_file_range fixture: {error}"),
    }
}

#[test]
fn copy_file_range_preserves_explicit_positions_and_reports_short_copies() {
    remove_if_present(INPUT_PATH);
    remove_if_present(OUTPUT_PATH);

    let input = fs::open(
        INPUT_PATH,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create copy_file_range input fixture");
    let output = fs::open(
        OUTPUT_PATH,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create copy_file_range output fixture");

    io::write(&input, b"0123456789").expect("write copy_file_range input");
    fs::seek(&input, SeekFrom::Start(7)).expect("position input descriptor");
    fs::seek(&output, SeekFrom::Start(3)).expect("position output descriptor");

    let mut input_offset = 1;
    let mut output_offset = 5;
    assert_eq!(
        fs::copy_file_range(
            &input,
            Some(&mut input_offset),
            &output,
            Some(&mut output_offset),
            4,
        )
        .expect("copy through explicit offsets"),
        4,
    );
    assert_eq!(input_offset, 5, "the input offset advances by the copy");
    assert_eq!(output_offset, 9, "the output offset advances by the copy");
    assert_eq!(fs::tell(&input).expect("input position after explicit copy"), 7);
    assert_eq!(
        fs::tell(&output).expect("output position after explicit copy"),
        3,
    );

    let mut positioned = [0_u8; 4];
    assert_eq!(io::pread(&output, &mut positioned, 5).expect("read explicit output"), 4);
    assert_eq!(&positioned, b"1234");

    let mut short_input_offset = 8;
    let mut short_output_offset = 0;
    assert_eq!(
        fs::copy_file_range(
            &input,
            Some(&mut short_input_offset),
            &output,
            Some(&mut short_output_offset),
            8,
        )
        .expect("copy a short range at end of input"),
        2,
    );
    assert_eq!(short_input_offset, 10, "short input offset advances by two");
    assert_eq!(short_output_offset, 2, "short output offset advances by two");
    assert_eq!(fs::tell(&input).expect("input position after short copy"), 7);
    assert_eq!(fs::tell(&output).expect("output position after short copy"), 3);

    let mut short_output = [0_u8; 2];
    assert_eq!(io::pread(&output, &mut short_output, 0).expect("read short output"), 2);
    assert_eq!(&short_output, b"89");

    assert_eq!(
        fs::copy_file_range(&input, None, &output, None, 2)
            .expect("copy using shared descriptor positions"),
        2,
    );
    assert_eq!(fs::tell(&input).expect("input position after shared copy"), 9);
    assert_eq!(fs::tell(&output).expect("output position after shared copy"), 5);

    let mut shared_output = [0_u8; 2];
    assert_eq!(io::pread(&output, &mut shared_output, 3).expect("read shared output"), 2);
    assert_eq!(&shared_output, b"78");

    let mut invalid_input_offset = i64::MAX as u64 + 1;
    let mut unchanged_output_offset = 17;
    assert_eq!(
        fs::copy_file_range(
            &input,
            Some(&mut invalid_input_offset),
            &output,
            Some(&mut unchanged_output_offset),
            1,
        ),
        Err(Errno::INVAL),
    );
    assert_eq!(invalid_input_offset, i64::MAX as u64 + 1);
    assert_eq!(
        unchanged_output_offset, 17,
        "an invalid request must not initialize or roll back the output offset",
    );
    assert_eq!(fs::tell(&input).expect("input position after rejected copy"), 9);
    assert_eq!(fs::tell(&output).expect("output position after rejected copy"), 5);

    // A syscall error must not expose a partially updated temporary output
    // offset, even when the input offset itself was valid.
    // SAFETY: i32::MAX is not an allocatable Linux file descriptor in this
    // test process; the borrow is used only for the attempted syscall.
    let invalid_input = unsafe { BorrowedFd::borrow_raw(i32::MAX) };
    let mut error_input_offset = 0;
    let mut error_output_offset = 17;
    assert_eq!(
        fs::copy_file_range(
            invalid_input,
            Some(&mut error_input_offset),
            &output,
            Some(&mut error_output_offset),
            1,
        ),
        Err(Errno::BADF),
    );
    assert_eq!(error_input_offset, 0);
    assert_eq!(error_output_offset, 17);

    drop(output);
    drop(input);
    remove_if_present(INPUT_PATH);
    remove_if_present(OUTPUT_PATH);
}
