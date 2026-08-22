use crabc_rs::fs::{self, Mode, OFlags, SeekFrom};
use crabc_rs::io;
use crabc_rs::Errno;

const INPUT_PATH: &[u8] = b"/tmp/crabc-rs-m10-sendfile-input";
const OUTPUT_PATH: &[u8] = b"/tmp/crabc-rs-m10-sendfile-output";
const INVALID_PATH: &[u8] = b"/tmp/crabc-rs-m10-sendfile-invalid";

fn remove_if_present(path: &[u8]) {
    match fs::unlink(path) {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(error) => panic!("remove stale sendfile fixture: {error}"),
    }
}

#[test]
fn sendfile_preserves_or_advances_the_input_position_as_requested() {
    remove_if_present(INPUT_PATH);
    remove_if_present(OUTPUT_PATH);

    let input = fs::open(
        INPUT_PATH,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create sendfile input fixture");
    let output = fs::open(
        OUTPUT_PATH,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create sendfile output fixture");

    io::write(&input, b"0123456789").expect("write sendfile input");
    fs::seek(&input, SeekFrom::Start(8)).expect("position sendfile input");

    let mut offset = 2;
    assert_eq!(
        fs::sendfile(&output, &input, Some(&mut offset), 4)
            .expect("positioned sendfile transfer"),
        4,
    );
    assert_eq!(offset, 6, "sendfile advances its explicit offset");
    assert_eq!(
        fs::tell(&input).expect("input position after explicit offset"),
        8,
        "an explicit sendfile offset must not move the input descriptor",
    );
    assert_eq!(fs::tell(&output).expect("output position after sendfile"), 4);

    fs::seek(&output, SeekFrom::Start(0)).expect("rewind positioned output");
    let mut positioned = [0_u8; 4];
    assert_eq!(
        io::read(&output, &mut positioned).expect("read positioned sendfile output"),
        4,
    );
    assert_eq!(&positioned, b"2345");

    assert_eq!(
        fs::sendfile(&output, &input, None, 2).expect("current-position sendfile transfer"),
        2,
    );
    assert_eq!(fs::tell(&input).expect("input position after null offset"), 10);
    assert_eq!(fs::tell(&output).expect("output position after second transfer"), 6);

    fs::seek(&output, SeekFrom::Start(0)).expect("rewind complete output");
    let mut complete = [0_u8; 6];
    assert_eq!(
        io::read(&output, &mut complete).expect("read complete sendfile output"),
        6,
    );
    assert_eq!(&complete, b"234589");

    drop(output);
    drop(input);
    remove_if_present(INPUT_PATH);
    remove_if_present(OUTPUT_PATH);
}

#[test]
fn sendfile_rejects_offsets_outside_linux_off_t_without_mutating_them() {
    remove_if_present(INVALID_PATH);

    let input = fs::open(
        INVALID_PATH,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create invalid-offset sendfile fixture");
    let output = fs::open(
        INVALID_PATH,
        OFlags::RDWR | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("open second descriptor for invalid-offset sendfile");
    let mut offset = i64::MAX as u64 + 1;

    assert_eq!(
        fs::sendfile(&output, &input, Some(&mut offset), 1),
        Err(Errno::INVAL),
    );
    assert_eq!(offset, i64::MAX as u64 + 1);

    drop(output);
    drop(input);
    remove_if_present(INVALID_PATH);
}
