use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crabc_rs::fs as native_fs;
use crabc_rs::Errno;

fn remove(path: &[u8]) {
    let _ = fs::remove_dir(Path::new(std::ffi::OsStr::from_bytes(path)));
}

#[test]
fn creates_private_unique_directories_with_random_suffixes() {
    let first = native_fs::create_temp_dir("/tmp", "crabc-rs-native-temp-")
        .expect("create first temporary directory");
    let second = native_fs::create_temp_dir("/tmp", "crabc-rs-native-temp-")
        .expect("create second temporary directory");
    assert_ne!(first.as_bytes(), second.as_bytes());

    let first_metadata = fs::metadata(Path::new(std::ffi::OsStr::from_bytes(first.as_bytes())))
        .expect("stat first temporary directory");
    let second_metadata = fs::metadata(Path::new(std::ffi::OsStr::from_bytes(second.as_bytes())))
        .expect("stat second temporary directory");
    assert!(first_metadata.is_dir());
    assert!(second_metadata.is_dir());
    // `mkdirat(..., 0700)` is still filtered through the inherited umask,
    // which may deliberately remove owner bits too. The durable privacy
    // invariant is that the API never grants group or other permissions.
    assert_eq!(first_metadata.permissions().mode() & 0o077, 0);
    assert_eq!(second_metadata.permissions().mode() & 0o077, 0);

    remove(first.as_bytes());
    remove(second.as_bytes());
}

#[test]
fn caller_owned_and_descriptor_relative_forms_preserve_byte_prefixes() {
    let mut full = [0u8; 256];
    let length = native_fs::create_temp_dir_into("/tmp", &b"crabc-\xff-"[..], &mut full)
        .expect("create non-UTF8 temporary directory");
    assert!(full[..length].starts_with(b"/tmp/crabc-\xff-"));
    remove(&full[..length]);

    let parent = native_fs::open(
        "/tmp",
        native_fs::OFlags::PATH | native_fs::OFlags::DIRECTORY,
        native_fs::Mode::empty(),
    )
    .expect("open temporary parent");
    let mut basename = [0u8; 256];
    let length = native_fs::create_temp_dir_at_into(&parent, "crabc-rs-native-at-", &mut basename)
        .expect("create descriptor-relative temporary directory");
    assert!(basename[..length].starts_with(b"crabc-rs-native-at-"));
    let mut full_path = b"/tmp/".to_vec();
    full_path.extend_from_slice(&basename[..length]);
    remove(&full_path);
}

#[test]
fn invalid_prefixes_and_small_outputs_fail_before_creation() {
    let mut output = [0u8; 256];
    assert_eq!(
        native_fs::create_temp_dir_into("/tmp", "", &mut output),
        Err(Errno::INVAL)
    );
    assert_eq!(
        native_fs::create_temp_dir_into("/tmp", "has/slash", &mut output),
        Err(Errno::INVAL)
    );
    assert_eq!(
        native_fs::create_temp_dir_into("/tmp", "prefix", &mut [0u8; 3]),
        Err(Errno::RANGE)
    );
    assert_eq!(
        native_fs::create_temp_dir_into("/tmp/no-such-parent", "prefix", &mut output),
        Err(Errno::NOENT)
    );
}
