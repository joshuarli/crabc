use crabc_rs::fs::{self, Mode, OFlags, SeekFrom};
use crabc_rs::io;
use crabc_rs::Errno;

const PATH: &[u8] = b"/tmp/crabc-rs-m10-readahead";

fn remove_fixture() {
    match fs::unlink(PATH) {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(error) => panic!("remove stale readahead fixture: {error}"),
    }
}

#[test]
fn native_readahead_exercises_a_regular_file_without_moving_position() {
    remove_fixture();
    let file = fs::open(
        PATH,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create disposable readahead fixture");
    io::write(&file, &[0x5a; 8192]).expect("seed disposable readahead fixture");
    fs::seek(&file, SeekFrom::Start(19)).expect("position disposable readahead fixture");
    let before = fs::tell(&file).expect("read position before readahead");

    let result = fs::readahead(&file, 0, 8192);
    let after = fs::tell(&file).expect("read position after readahead");

    drop(file);
    remove_fixture();
    result.expect("readahead a real regular file through the direct syscall");
    assert_eq!(after, before, "readahead must not move the file position");
}

#[test]
fn native_readahead_rejects_unrepresentable_signed_ranges() {
    remove_fixture();
    let file = fs::open(
        PATH,
        OFlags::RDONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR,
    )
    .expect("create readahead range-validation fixture");

    assert_eq!(
        fs::readahead(&file, i64::MAX as u64 + 1, 1),
        Err(Errno::INVAL),
        "an offset outside Linux loff_t must not be truncated",
    );
    assert_eq!(
        fs::readahead(&file, i64::MAX as u64, 1),
        Err(Errno::INVAL),
        "the range end must remain representable in Linux loff_t",
    );
    assert_eq!(
        fs::readahead(&file, 0, i64::MAX as u64 + 1),
        Err(Errno::INVAL),
        "a length outside the checked syscall range must be rejected",
    );

    drop(file);
    remove_fixture();
}
