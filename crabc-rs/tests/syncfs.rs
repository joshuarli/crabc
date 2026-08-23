use crabc_rs::{fs, io};
use crabc_rs::fs::{Mode, OFlags};

#[test]
fn native_syncfs_flushes_the_filesystem_for_a_disposable_file() {
    const PATH: &[u8] = b"crabc-rs-native-syncfs";

    match fs::unlink(PATH) {
        Ok(()) | Err(crabc_rs::Errno::NOENT) => {}
        Err(error) => panic!("remove stale syncfs fixture: {error}"),
    }

    let file = fs::open(
        PATH,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create disposable syncfs fixture");
    io::write(&file, b"syncfs").expect("dirty disposable file");

    let result = fs::syncfs(&file);
    drop(file);
    fs::unlink(PATH).expect("remove disposable syncfs fixture");
    result.expect("flush the fixture filesystem through direct syncfs");
}
