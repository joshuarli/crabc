use core::sync::atomic::{AtomicUsize, Ordering};

use crabc_rs::fs::{self, FileType, Mode};
use crabc_rs::io;
use crabc_rs::Errno;

static SCRATCH_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

struct CreateFixture {
    path: String,
}

impl CreateFixture {
    fn new() -> Self {
        let path = format!(
            "/tmp/crabc-rs-native-create-{}-{}",
            std::process::id(),
            SCRATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed),
        );
        match fs::unlink(&path) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(error) => panic!("remove stale create fixture: {error}"),
        }
        Self { path }
    }
}

impl Drop for CreateFixture {
    fn drop(&mut self) {
        let _ = fs::unlink(&self.path);
    }
}

#[test]
fn create_matches_creat_with_write_only_truncate_and_umask_safe_mode() {
    let fixture = CreateFixture::new();
    let requested_mode =
        Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH;

    let file = fs::create(&fixture.path, requested_mode).expect("create fixture through creat");
    assert_eq!(
        io::fcntl_getfd(&file).expect("read create descriptor flags"),
        io::FdFlags::empty(),
        "creat does not imply O_CLOEXEC",
    );
    let metadata = fs::fstat(&file).expect("stat newly created file");
    assert_eq!(FileType::from_raw_mode(metadata.st_mode), FileType::RegularFile);
    assert_eq!(metadata.st_size, 0, "creat starts a new file empty");
    let observed_mode = Mode::from_raw_mode(metadata.st_mode);
    assert_eq!(
        observed_mode.bits() & !requested_mode.bits(),
        0,
        "the process umask may clear requested bits but cannot add mode bits",
    );

    assert_eq!(io::write(&file, b"seed").expect("write through creat descriptor"), 4);
    assert_eq!(
        io::read(&file, &mut [0_u8; 4]).unwrap_err(),
        Errno::BADF,
        "creat returns a write-only descriptor",
    );
    drop(file);

    let file = fs::create(&fixture.path, Mode::empty()).expect("reopen fixture through creat");
    assert_eq!(
        fs::fstat(&file).expect("stat truncated file").st_size,
        0,
        "creat truncates an existing file",
    );
    assert_eq!(io::write(&file, b"ok").expect("write after truncation"), 2);
}
