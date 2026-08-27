#![cfg(target_arch = "x86_64")]

use core::ffi::CStr;
use core::mem::MaybeUninit;

use crabc_rs::process;
use crabc_rs::Errno;
use std::ffi::{CString, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

const BUFFER_CAPACITY: usize = 4096;

/// Owns a private logical-CWD fixture and restores the process-wide CWD before
/// removing it. The native runner uses one test thread, so this explicit
/// fixture transition cannot race another x86 integration test.
struct LogicalCwdFixture {
    original_cwd: PathBuf,
    root: PathBuf,
    logical: CString,
}

impl LogicalCwdFixture {
    fn new() -> Self {
        let root = fresh_fixture_root();
        std::fs::create_dir(root.join("real")).expect("create physical fixture directory");
        std::fs::create_dir(root.join("other")).expect("create mismatched fixture directory");
        std::os::unix::fs::symlink("real", root.join("logical"))
            .expect("create logical current-directory symlink");

        let original_cwd = std::env::current_dir().expect("capture original current directory");
        let logical_path = root.join("logical");
        std::env::set_current_dir(&logical_path).expect("enter logical current-directory fixture");
        let logical = CString::new(logical_path.as_os_str().as_bytes())
            .expect("logical fixture pathname has no NUL");

        Self {
            original_cwd,
            root,
            logical,
        }
    }

    fn logical_pwd(&self) -> &CStr {
        self.logical.as_c_str()
    }

    fn root(&self) -> &Path {
        &self.root
    }
}

impl Drop for LogicalCwdFixture {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.original_cwd);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn fresh_fixture_root() -> PathBuf {
    let process_id = std::process::id();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();

    for serial in 0_u32..1024 {
        let root = std::env::temp_dir().join(format!(
            "crabc-x86-current-dir-name-{process_id}-{nonce}-{serial}"
        ));
        match std::fs::create_dir(&root) {
            Ok(()) => return root,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("create current-directory fixture root: {error}"),
        }
    }

    panic!("find an unused current-directory fixture root")
}

fn physical_cwd_bytes() -> Vec<u8> {
    let mut storage = [MaybeUninit::<u8>::uninit(); BUFFER_CAPACITY];
    let (initialized, _) = process::getcwd(&mut storage).expect("read physical current directory");
    CStr::from_bytes_with_nul(initialized)
        .expect("getcwd result includes one trailing NUL")
        .to_bytes_with_nul()
        .to_vec()
}

fn read_current_dir_name(pwd: Option<&CStr>) -> Vec<u8> {
    let mut storage = [MaybeUninit::<u8>::uninit(); BUFFER_CAPACITY];
    let (initialized, _) = process::get_current_dir_name(pwd, &mut storage)
        .expect("read current-directory name");
    CStr::from_bytes_with_nul(initialized)
        .expect("current-directory-name result includes one trailing NUL")
        .to_bytes_with_nul()
        .to_vec()
}

#[test]
fn x86_64_current_dir_name_preserves_valid_logical_pwd_spelling() {
    let fixture = LogicalCwdFixture::new();

    assert_eq!(
        read_current_dir_name(Some(fixture.logical_pwd())),
        fixture.logical_pwd().to_bytes_with_nul(),
    );
}

#[test]
fn x86_64_current_dir_name_falls_back_for_invalid_pwd_snapshots() {
    let fixture = LogicalCwdFixture::new();
    let expected = physical_cwd_bytes();
    let mismatch = CString::new(fixture.root().join("other").as_os_str().as_bytes())
        .expect("mismatched fixture pathname has no NUL");

    for pwd in [
        Some(mismatch.as_c_str()),
        Some(CStr::from_bytes_with_nul(b"relative\0").expect("relative C string")),
        Some(CStr::from_bytes_with_nul(b"\0").expect("empty C string")),
        None,
    ] {
        assert_eq!(read_current_dir_name(pwd), expected);
    }
}

#[test]
fn x86_64_current_dir_name_preserves_validated_non_utf8_pwd_bytes() {
    let fixture = LogicalCwdFixture::new();
    let physical = fixture
        .root()
        .join(OsString::from_vec(b"physical-\xff".to_vec()));
    let logical = fixture
        .root()
        .join(OsString::from_vec(b"logical-\xfe".to_vec()));
    std::fs::create_dir(&physical).expect("create non-UTF-8 physical fixture directory");
    std::os::unix::fs::symlink(&physical, &logical)
        .expect("create non-UTF-8 logical current-directory symlink");
    std::env::set_current_dir(&logical).expect("enter non-UTF-8 logical fixture directory");
    let pwd = CString::new(logical.as_os_str().as_bytes())
        .expect("non-UTF-8 logical fixture pathname has no NUL");

    assert_eq!(
        read_current_dir_name(Some(pwd.as_c_str())),
        pwd.as_bytes_with_nul(),
    );
}

#[test]
fn x86_64_current_dir_name_reports_range_without_falling_back() {
    let fixture = LogicalCwdFixture::new();
    let mut storage = [MaybeUninit::<u8>::uninit(); 1];

    let error = process::get_current_dir_name(Some(fixture.logical_pwd()), &mut storage)
        .expect_err("one byte cannot hold a validated logical pathname");
    assert_eq!(error, Errno::RANGE);
}

#[cfg(feature = "alloc")]
#[test]
fn x86_64_current_dir_name_alloc_returns_logical_and_physical_results() {
    let fixture = LogicalCwdFixture::new();

    let logical = process::get_current_dir_name_alloc(Some(fixture.logical_pwd()), vec![0; 2])
        .expect("allocate validated logical current-directory name");
    assert_eq!(logical.as_bytes_with_nul(), fixture.logical_pwd().to_bytes_with_nul());

    let physical = process::get_current_dir_name_alloc(None, Vec::new())
        .expect("allocate physical current-directory fallback");
    assert_eq!(physical.as_bytes_with_nul(), physical_cwd_bytes());
}
