//! Common Rustix/crabc-rs source fixture for direct descriptor file operations.

use api::fs::{self, Mode, OFlags, SeekFrom, CWD};
use api::io::write;

fn main() {
    let path = format!("/tmp/crabc-rustix-descriptor-fs-io-{}", std::process::id());
    let _ = fs::unlink(&path);
    let file = fs::openat(
        CWD,
        &path,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create fixture");

    assert_eq!(write(&file, b"0123456789").expect("write fixture"), 10);
    assert_eq!(fs::tell(&file).expect("tell after write"), 10);
    assert_eq!(fs::seek(&file, SeekFrom::Start(3)).expect("seek start"), 3);
    assert_eq!(fs::seek(&file, SeekFrom::Current(2)).expect("seek current"), 5);
    assert_eq!(fs::seek(&file, SeekFrom::End(-2)).expect("seek end"), 8);
    fs::ftruncate(&file, 5).expect("truncate fixture");
    assert_eq!(fs::seek(&file, SeekFrom::End(0)).expect("seek truncated end"), 5);
    fs::fsync(&file).expect("fsync fixture");
    fs::fdatasync(&file).expect("fdatasync fixture");

    drop(file);
    fs::unlink(&path).expect("remove fixture");
    println!("descriptor-fs-io ok");
}
