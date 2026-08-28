//! Native x86-64 regressions for the private temporary-object ownership slice.

use std::env;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use crabc_rs::fs::{self, FileType, Mode, OFlags, TempFile, UnlinkAtFlags};
use crabc_rs::io;
use crabc_rs::Errno;

const NAMED_PREFIX: &[u8] = b"crabc-x86-named-";
const DIRECTORY_PREFIX: &[u8] = b"crabc-x86-dir-";

fn is_lower_hex(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn full_tmp_path(name: &[u8]) -> PathBuf {
    let mut path = b"/tmp/".to_vec();
    path.extend_from_slice(name);
    PathBuf::from(std::ffi::OsString::from_vec(path))
}

struct RestoreCurrentDir(PathBuf);

impl Drop for RestoreCurrentDir {
    fn drop(&mut self) {
        env::set_current_dir(&self.0).expect("restore test current directory");
    }
}

#[test]
fn named_tempfile_is_private_cloexec_and_drop_unlinks() {
    let path = {
        let file = fs::create_temp_file("/tmp", NAMED_PREFIX).expect("create named temp file");
        assert!(file.name().starts_with(NAMED_PREFIX));
        assert_eq!(
            file.name().len(),
            NAMED_PREFIX.len() + fs::TEMP_FILE_RANDOM_BYTES * 2
        );
        assert!(is_lower_hex(&file.name()[NAMED_PREFIX.len()..]));
        assert!(io::fcntl_getfd(file.as_fd())
            .expect("read named temp FD flags")
            .contains(io::FdFlags::CLOEXEC));

        let metadata = fs::fstat(file.as_fd()).expect("stat named temp file");
        assert_eq!(
            FileType::from_raw_mode(metadata.st_mode),
            FileType::RegularFile
        );
        assert_eq!(metadata.st_nlink, 1);
        assert_eq!(Mode::from_raw_mode(metadata.st_mode).bits() & 0o077, 0);
        full_tmp_path(file.name())
    };
    assert!(!path.exists(), "drop must unlink the named entry");
}

#[test]
fn named_tempfile_uses_retained_parent_for_explicit_remove_and_persistence() {
    let parent = fs::open(
        "/tmp",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("open temporary parent");
    let file = fs::create_temp_file_at(&parent, NAMED_PREFIX)
        .expect("create descriptor-relative named temp file");
    let name = file.name().to_vec();

    let restore = RestoreCurrentDir(env::current_dir().expect("read test current directory"));
    env::set_current_dir("/").expect("change test current directory");
    file.remove().expect("remove through retained parent FD");
    drop(restore);
    assert!(matches!(
        fs::statat(&parent, name.as_slice(), fs::AtFlags::empty()),
        Err(Errno::NOENT)
    ));

    let persisted = fs::create_temp_file("/tmp", NAMED_PREFIX)
        .expect("create persistent named temp file");
    let path = full_tmp_path(persisted.name());
    let owned = persisted.into_owned_fd();
    assert!(path.exists(), "into_owned_fd must leave the name linked");
    owned.close().expect("close persisted named temp FD");
    fs::unlink(path.as_os_str().as_encoded_bytes()).expect("remove persisted named temp file");
}

#[test]
fn named_tempfile_rejects_unstable_or_invalid_inputs_before_creation() {
    assert!(matches!(
        fs::create_temp_file_at(fs::CWD, NAMED_PREFIX),
        Err(Errno::BADF)
    ));
    assert!(matches!(fs::create_temp_file("/tmp", ""), Err(Errno::INVAL)));
    assert!(matches!(
        fs::create_temp_file("/tmp", "has/slash"),
        Err(Errno::INVAL)
    ));
    assert!(matches!(
        fs::create_temp_file("/tmp", &[b'x'; 256][..]),
        Err(Errno::NAMETOOLONG)
    ));
}

fn open_anonymous_temp_file() -> Result<TempFile, Errno> {
    TempFile::open("/tmp", Mode::RUSR | Mode::WUSR)
}

#[test]
fn anonymous_tempfile_is_cloexec_unlinked_and_read_write() {
    let file = match open_anonymous_temp_file() {
        Ok(file) => file,
        Err(Errno::OPNOTSUPP) => return,
        Err(error) => panic!("open anonymous temp file: {error}"),
    };
    assert!(io::fcntl_getfd(&file)
        .expect("read anonymous temp FD flags")
        .contains(io::FdFlags::CLOEXEC));
    let metadata = fs::fstat(&file).expect("stat anonymous temp file");
    assert_eq!(
        FileType::from_raw_mode(metadata.st_mode),
        FileType::RegularFile
    );
    assert_eq!(metadata.st_nlink, 0, "O_TMPFILE must not name an entry");
    assert_eq!(metadata.st_size, 0);

    assert_eq!(io::write(&file, b"anonymous").expect("write anonymous temp"), 9);
    fs::seek(&file, fs::SeekFrom::Start(0)).expect("rewind anonymous temp");
    let mut contents = [0_u8; 9];
    assert_eq!(io::read(&file, &mut contents).expect("read anonymous temp"), 9);
    assert_eq!(&contents, b"anonymous");
}

#[test]
fn anonymous_tempfile_accepts_descriptor_relative_directory_or_reports_unsupported() {
    let parent = fs::open(
        "/tmp",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("open anonymous-temp parent");
    match TempFile::open_at(&parent, ".", Mode::RUSR | Mode::WUSR) {
        Ok(file) => {
            let metadata = fs::fstat(file).expect("stat descriptor-relative anonymous temp");
            assert_eq!(
                FileType::from_raw_mode(metadata.st_mode),
                FileType::RegularFile
            );
            assert_eq!(metadata.st_nlink, 0);
        }
        Err(Errno::OPNOTSUPP) => {}
        Err(error) => panic!("open descriptor-relative anonymous temp: {error}"),
    }
}

#[test]
fn temporary_directories_are_private_byte_preserving_and_descriptor_relative() {
    let mut first = [0_u8; 256];
    let first_len = fs::create_temp_dir_into("/tmp", &b"crabc-x86-\xff-"[..], &mut first)
        .expect("create first temporary directory");
    let mut second = [0_u8; 256];
    let second_len = fs::create_temp_dir_into("/tmp", &b"crabc-x86-\xff-"[..], &mut second)
        .expect("create second temporary directory");
    assert!(first[..first_len].starts_with(b"/tmp/crabc-x86-\xff-"));
    assert_eq!(
        first_len,
        b"/tmp/crabc-x86-\xff-".len() + fs::TEMP_DIR_RANDOM_BYTES * 2
    );
    assert!(is_lower_hex(&first[first_len - fs::TEMP_DIR_RANDOM_BYTES * 2..first_len]));
    assert_ne!(
        &first[..first_len],
        &second[..second_len],
        "independent getrandom candidates must not reuse a temporary directory name"
    );
    let first_metadata = fs::stat(&first[..first_len]).expect("stat temporary directory");
    assert_eq!(
        FileType::from_raw_mode(first_metadata.st_mode),
        FileType::Directory
    );
    assert_eq!(Mode::from_raw_mode(first_metadata.st_mode).bits() & 0o077, 0);
    fs::rmdir(&first[..first_len]).expect("remove temporary directory");
    fs::rmdir(&second[..second_len]).expect("remove second temporary directory");

    let parent = fs::open(
        "/tmp",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("open temporary directory parent");
    let mut basename = [0_u8; 256];
    let basename_len = fs::create_temp_dir_at_into(&parent, DIRECTORY_PREFIX, &mut basename)
        .expect("create descriptor-relative temporary directory");
    assert!(basename[..basename_len].starts_with(DIRECTORY_PREFIX));
    assert!(is_lower_hex(
        &basename[basename_len - fs::TEMP_DIR_RANDOM_BYTES * 2..basename_len]
    ));
    fs::unlinkat(
        &parent,
        &basename[..basename_len],
        UnlinkAtFlags::REMOVEDIR,
    )
    .expect("remove descriptor-relative temporary directory");
}

#[test]
fn temporary_directory_invalid_prefixes_and_small_outputs_fail_before_creation() {
    let mut output = [0_u8; 256];
    assert_eq!(
        fs::create_temp_dir_into("/tmp", "", &mut output),
        Err(Errno::INVAL)
    );
    assert_eq!(
        fs::create_temp_dir_into("/tmp", "has/slash", &mut output),
        Err(Errno::INVAL)
    );
    assert_eq!(
        fs::create_temp_dir_into("/tmp", DIRECTORY_PREFIX, &mut [0_u8; 3]),
        Err(Errno::RANGE)
    );
    assert_eq!(
        fs::create_temp_dir_into("/tmp/no-such-parent", DIRECTORY_PREFIX, &mut output),
        Err(Errno::NOENT)
    );
}

#[cfg(feature = "alloc")]
#[test]
fn allocation_backed_temporary_directory_forms_own_byte_paths() {
    let full = fs::create_temp_dir("/tmp", DIRECTORY_PREFIX)
        .expect("create allocation-backed temporary directory");
    assert!(full.as_bytes().starts_with(b"/tmp/crabc-x86-dir-"));
    fs::rmdir(full.as_bytes()).expect("remove allocation-backed temporary directory");

    let parent = fs::open(
        "/tmp",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("open allocation-backed temporary directory parent");
    let basename = fs::create_temp_dir_at(&parent, DIRECTORY_PREFIX)
        .expect("create allocation-backed descriptor-relative temporary directory");
    assert!(basename.as_bytes().starts_with(DIRECTORY_PREFIX));
    fs::unlinkat(&parent, basename.as_bytes(), UnlinkAtFlags::REMOVEDIR)
        .expect("remove allocation-backed descriptor-relative temporary directory");
}
