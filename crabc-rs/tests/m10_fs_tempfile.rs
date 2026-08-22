use crabc_rs::fs::{self, FileType, Mode, OFlags, TempFile};
use crabc_rs::io;
use crabc_rs::Errno;

fn open_tempfile() -> Result<TempFile, Errno> {
    TempFile::open(
        "/tmp",
        Mode::RUSR | Mode::WUSR,
    )
}

#[test]
fn anonymous_tempfile_owns_cloexec_unlinked_regular_file() {
    let file = match open_tempfile() {
        Ok(file) => file,
        Err(Errno::OPNOTSUPP) => return,
        Err(error) => panic!("open anonymous temporary file: {error}"),
    };

    assert!(
        io::fcntl_getfd(&file)
            .expect("read temporary-file descriptor flags")
            .contains(io::FdFlags::CLOEXEC),
        "anonymous temporary files must be close-on-exec",
    );
    let metadata = fs::fstat(&file).expect("stat anonymous temporary file");
    assert_eq!(FileType::from_raw_mode(metadata.st_mode), FileType::RegularFile);
    assert_eq!(metadata.st_nlink, 0, "O_TMPFILE must not create a directory entry");
    assert_eq!(metadata.st_size, 0);
    assert_eq!(Mode::from_raw_mode(metadata.st_mode).bits() & !0o7777, 0);

    assert_eq!(io::write(&file, b"anonymous").expect("write temporary file"), 9);
    fs::seek(&file, fs::SeekFrom::Start(0)).expect("rewind temporary file");
    let mut content = [0_u8; 9];
    assert_eq!(io::read(&file, &mut content).expect("read temporary file"), 9);
    assert_eq!(&content, b"anonymous");
}

#[test]
fn anonymous_tempfile_supports_descriptor_relative_directory() {
    let directory = fs::open(
        "/tmp",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("open temporary-file parent directory");
    match TempFile::open_at(&directory, ".", Mode::RUSR | Mode::WUSR) {
        Ok(file) => {
            let metadata = fs::fstat(&file).expect("stat descriptor-relative temporary file");
            assert_eq!(FileType::from_raw_mode(metadata.st_mode), FileType::RegularFile);
            assert_eq!(metadata.st_nlink, 0);
        }
        Err(Errno::OPNOTSUPP) => {}
        Err(error) => panic!("open descriptor-relative anonymous temporary file: {error}"),
    }
}

#[test]
fn anonymous_tempfile_does_not_fallback_when_filesystem_lacks_o_tmpfile() {
    assert!(
        matches!(open_tempfile(), Ok(_) | Err(Errno::OPNOTSUPP)),
        "the API either owns an anonymous descriptor or reports EOPNOTSUPP",
    );
}
