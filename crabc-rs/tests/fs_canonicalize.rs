use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use crabc_rs::fs as native_fs;
use crabc_rs::Errno;

fn fixture_root() -> PathBuf {
    let root = PathBuf::from(format!(
        "/tmp/crabc-rs-native-canonicalize-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("real/child")).expect("create canonicalize fixture");
    fs::write(root.join("real/child/file"), b"fixture").expect("write canonicalize fixture");
    root
}

fn cleanup(root: &PathBuf) {
    let _ = fs::remove_dir_all(root);
}

fn canonical(path: &[u8]) -> Vec<u8> {
    native_fs::canonicalize(path)
        .expect("canonicalize fixture path")
        .into_bytes()
}

#[test]
fn canonicalize_lexically_normalizes_and_physically_resolves_relative_links() {
    let root = fixture_root();
    fs::create_dir(root.join("alias")).expect("create alias parent");
    std::os::unix::fs::symlink("../real", root.join("alias/to-real"))
        .expect("create relative symlink");

    let path = root.join("alias/to-real/./child/../child/file");
    let expected = root.join("real/child/file");
    assert_eq!(canonical(path.as_os_str().as_bytes()), expected.as_os_str().as_bytes());
    assert_eq!(
        canonical(root.join("real/child/../").as_os_str().as_bytes()),
        root.join("real").as_os_str().as_bytes()
    );
    assert_eq!(
        native_fs::canonicalize(root.join("real/child/file/..").as_os_str().as_bytes()),
        Err(Errno::NOTDIR)
    );
    cleanup(&root);
}

#[test]
fn canonicalize_relative_paths_are_anchored_to_the_physical_current_directory() {
    let cwd = std::env::current_dir().expect("read test current directory");
    assert_eq!(canonical(b"."), cwd.as_os_str().as_bytes());
    assert_eq!(
        canonical(b".."),
        cwd.parent().expect("test directory has a parent").as_os_str().as_bytes()
    );
}

#[test]
fn canonicalize_preserves_non_utf8_path_bytes_and_absolute_links() {
    let root = fixture_root();
    let raw_name = b"raw-\xff";
    let raw_path = root.join(std::ffi::OsStr::from_bytes(raw_name));
    fs::write(&raw_path, b"raw").expect("write non-UTF8 fixture");
    std::os::unix::fs::symlink(&raw_path, root.join("absolute-link"))
        .expect("create absolute symlink");

    let canonical_path = canonical(root.join("absolute-link").as_os_str().as_bytes());
    assert_eq!(canonical_path, raw_path.as_os_str().as_bytes());
    cleanup(&root);
}

#[test]
fn canonicalize_reports_missing_dangling_and_cyclic_paths() {
    let root = fixture_root();
    assert_eq!(
        native_fs::canonicalize(root.join("missing").as_os_str().as_bytes()),
        Err(Errno::NOENT)
    );
    std::os::unix::fs::symlink("missing", root.join("dangling"))
        .expect("create dangling symlink");
    assert_eq!(
        native_fs::canonicalize(root.join("dangling").as_os_str().as_bytes()),
        Err(Errno::NOENT)
    );

    for index in 0..40 {
        let next = format!("link{}", (index + 1) % 40);
        std::os::unix::fs::symlink(next, root.join(format!("link{}", index)))
            .expect("create symlink cycle");
    }
    assert_eq!(
        native_fs::canonicalize(root.join("link0").as_os_str().as_bytes()),
        Err(Errno::LOOP)
    );
    cleanup(&root);
}

#[test]
fn canonicalize_rejects_nul_and_reports_caller_buffer_capacity() {
    assert_eq!(
        native_fs::canonicalize(&b"/tmp/\0bad"[..]),
        Err(Errno::INVAL)
    );

    let mut output = [0u8; 1];
    assert_eq!(
        native_fs::canonicalize_into("/tmp", &mut output),
        Err(Errno::RANGE)
    );

    let empty = CString::new("").expect("empty CString");
    assert_eq!(native_fs::canonicalize(empty), Err(Errno::NOENT));
}
