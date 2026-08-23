use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crabc_rs::fs::{self as native_fs, Mode, NamedTempFile, OFlags};
use crabc_rs::io;
use crabc_rs::Errno;

fn full_path(file: &NamedTempFile) -> Vec<u8> {
    let mut path = b"/tmp/".to_vec();
    path.extend_from_slice(file.name());
    path
}

#[test]
fn named_tempfile_is_exclusive_private_cloexec_and_drop_unlinks() {
    let path = {
        let file = native_fs::create_temp_file("/tmp", "crabc-rs-native-named-")
            .expect("create named temporary file");
        assert!(file.name().starts_with(b"crabc-rs-native-named-"));
        assert!(io::fcntl_getfd(file.as_fd())
            .expect("read named temporary descriptor flags")
            .contains(io::FdFlags::CLOEXEC));
        let metadata = native_fs::fstat(file.as_fd()).expect("stat named temporary file");
        assert_eq!(
            native_fs::FileType::from_raw_mode(metadata.st_mode),
            native_fs::FileType::RegularFile
        );
        assert_eq!(metadata.st_nlink, 1);
        assert_eq!(
            native_fs::Mode::from_raw_mode(metadata.st_mode).bits() & 0o077,
            0
        );
        full_path(&file)
    };
    assert!(!Path::new(std::ffi::OsStr::from_bytes(&path)).exists());
}

#[test]
fn named_tempfile_parent_descriptor_survives_cwd_changes_and_remove_is_explicit() {
    let parent = native_fs::open(
        "/tmp",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("open named temporary parent directory");
    let file = native_fs::create_temp_file_at(&parent, "crabc-rs-native-at-named-")
        .expect("create descriptor-relative named temporary file");
    let name = file.name().to_vec();
    file.remove().expect("remove named temporary file");
    assert!(matches!(
        native_fs::statat(&parent, name.as_slice(), native_fs::AtFlags::empty()),
        Err(Errno::NOENT)
    ));
}

#[test]
fn named_tempfile_persist_transfers_fd_without_unlinking() {
    let file = native_fs::create_temp_file("/tmp", "crabc-rs-native-persist-")
        .expect("create persistent named temporary file");
    let path = full_path(&file);
    let owned = file.into_owned_fd();
    assert!(Path::new(std::ffi::OsStr::from_bytes(&path)).exists());
    owned.close().expect("close persisted named temporary file");
    fs::remove_file(Path::new(std::ffi::OsStr::from_bytes(&path)))
        .expect("remove persisted named temporary file");
}

#[test]
fn named_tempfile_rejects_ambient_cwd_token_and_invalid_prefixes() {
    assert!(matches!(
        native_fs::create_temp_file_at(native_fs::CWD, "crabc-rs-native-cwd-"),
        Err(Errno::BADF)
    ));
    assert!(matches!(
        native_fs::create_temp_file("/tmp", ""),
        Err(Errno::INVAL)
    ));
    assert!(matches!(
        native_fs::create_temp_file("/tmp", "has/slash"),
        Err(Errno::INVAL)
    ));
    assert!(matches!(
        native_fs::create_temp_file("/tmp", &[b'x'; 256][..]),
        Err(Errno::NAMETOOLONG)
    ));
}
