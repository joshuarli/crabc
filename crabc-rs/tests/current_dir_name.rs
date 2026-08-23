use core::ffi::CStr;
use core::mem::MaybeUninit;

use crabc_rs::fs;
use crabc_rs::process;
use crabc_rs::{Errno, OwnedFd};
use std::ffi::{CString, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

struct CwdGuard(OwnedFd);

impl Drop for CwdGuard {
    fn drop(&mut self) {
        // The descriptor is an owned snapshot of the original CWD, so this
        // remains valid even when a test changes into a symlink or non-UTF-8
        // fixture directory.
        let _ = process::fchdir(&self.0);
    }
}

fn logical_fixture() -> (CwdGuard, PathBuf, CString) {
    let root = PathBuf::from(format!(
        "/tmp/crabc-rs-native-current-dir-name-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("real")).expect("create current-dir fixture");
    std::fs::create_dir(root.join("other")).expect("create mismatched fixture");
    std::os::unix::fs::symlink("real", root.join("logical")).expect("create logical symlink");

    let saved = fs::open(
        ".",
        fs::OFlags::RDONLY | fs::OFlags::DIRECTORY | fs::OFlags::CLOEXEC,
        fs::Mode::empty(),
    )
    .expect("save CWD in an owned descriptor");
    let logical = root.join("logical");
    process::chdir(&logical).expect("enter logical symlink");
    let logical_c = CString::new(logical.as_os_str().as_bytes()).expect("logical path has no NUL");
    (CwdGuard(saved), root, logical_c)
}

fn current_physical_bytes() -> Vec<u8> {
    process::getcwd_alloc(Vec::new())
        .expect("read physical CWD")
        .into_bytes_with_nul()
}

fn read_logical(pwd: Option<&CStr>) -> Vec<u8> {
    let mut storage = [MaybeUninit::<u8>::uninit(); 4096];
    let (initialized, _) =
        process::get_current_dir_name(pwd, &mut storage).expect("read current directory name");
    CStr::from_bytes_with_nul(initialized)
        .expect("result includes one trailing NUL")
        .to_bytes_with_nul()
        .to_vec()
}

#[test]
fn valid_pwd_preserves_logical_symlink_spelling() {
    let (guard, root, logical) = logical_fixture();
    let expected = logical.as_bytes_with_nul().to_vec();

    assert_eq!(read_logical(Some(logical.as_c_str())), expected);

    drop(guard);
    std::fs::remove_dir_all(root).expect("remove current-dir fixture");
}

#[test]
fn mismatched_relative_empty_and_missing_pwd_fall_back_to_getcwd() {
    let (guard, root, logical) = logical_fixture();
    let expected = current_physical_bytes();

    let mismatch = CString::new(root.join("other").as_os_str().as_bytes())
        .expect("mismatched path has no NUL");
    for pwd in [
        Some(mismatch.as_c_str()),
        Some(CStr::from_bytes_with_nul(b"relative\0").expect("relative C string")),
        Some(CStr::from_bytes_with_nul(b"\0").expect("empty C string")),
        None,
    ] {
        assert_eq!(read_logical(pwd), expected);
    }

    drop(guard);
    std::fs::remove_dir_all(root).expect("remove current-dir fixture");
    drop(logical);
}

#[test]
fn validated_pwd_preserves_non_utf8_bytes() {
    let (guard, root, _) = logical_fixture();
    let non_utf8_real = root.join(OsString::from_vec(b"real-\xff".to_vec()));
    let non_utf8_logical = root.join(OsString::from_vec(b"logical-\xfe".to_vec()));
    std::fs::create_dir(&non_utf8_real).expect("create non-UTF-8 directory");
    std::os::unix::fs::symlink(&non_utf8_real, &non_utf8_logical)
        .expect("create non-UTF-8 logical symlink");
    process::chdir(&non_utf8_logical).expect("enter non-UTF-8 symlink");
    let pwd =
        CString::new(non_utf8_logical.as_os_str().as_bytes()).expect("non-UTF-8 path has no NUL");

    assert_eq!(read_logical(Some(pwd.as_c_str())), pwd.as_bytes_with_nul());

    drop(guard);
    std::fs::remove_dir_all(root).expect("remove current-dir fixture");
}

#[test]
fn validated_pwd_reports_range_without_falling_back() {
    let (guard, root, logical) = logical_fixture();
    let mut storage = [MaybeUninit::<u8>::uninit(); 1];

    let error = process::get_current_dir_name(Some(logical.as_c_str()), &mut storage)
        .expect_err("one byte cannot hold a logical pathname");
    assert_eq!(error, Errno::RANGE);

    drop(guard);
    std::fs::remove_dir_all(root).expect("remove current-dir fixture");
}

#[test]
fn alloc_convenience_reuses_owned_buffer_for_logical_and_physical_results() {
    let (guard, root, logical) = logical_fixture();
    let logical_result = process::get_current_dir_name_alloc(Some(logical.as_c_str()), vec![0; 2])
        .expect("allocate logical current directory name");
    assert_eq!(
        logical_result.as_bytes_with_nul(),
        logical.as_bytes_with_nul()
    );

    let physical =
        process::get_current_dir_name_alloc(None, Vec::new()).expect("allocate physical fallback");
    assert_eq!(physical.as_bytes_with_nul(), current_physical_bytes());

    drop(guard);
    std::fs::remove_dir_all(root).expect("remove current-dir fixture");
}
