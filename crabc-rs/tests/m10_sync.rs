use crabc_rs::{fs, io};
use crabc_rs::fs::{Mode, OFlags};

const PATH: &[u8] = b"/tmp/crabc-rs-m10-sync";

#[test]
fn sync_accepts_dirty_filesystem_state_without_an_error_result() {
    match fs::unlink(PATH) {
        Ok(()) | Err(crabc_rs::Errno::NOENT) => {}
        Err(error) => panic!("remove stale sync fixture: {error}"),
    }

    let file = fs::open(
        PATH,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create disposable sync fixture");
    io::write(&file, b"sync").expect("dirty disposable file");

    // `sync` has global writeback scope and returns unit on Linux. The test
    // deliberately makes no timing or physical-media durability claim.
    fs::sync();

    drop(file);
    fs::unlink(PATH).expect("remove disposable sync fixture");
}
