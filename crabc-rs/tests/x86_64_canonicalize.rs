#![cfg(target_arch = "x86_64")]

use core::ffi::CStr;
use core::mem::MaybeUninit;

use std::ffi::{CString, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use crabc_rs::fs as native_fs;
use crabc_rs::Errno;

const UNTOUCHED: u8 = 0xa5;

/// A filesystem fixture whose spelling is deliberately unique to this test
/// process. Canonicalization itself does not mutate the CWD, so it can use a
/// normal RAII fixture rather than a child process.
struct CanonicalFixture {
    root: PathBuf,
}

impl CanonicalFixture {
    fn new() -> Self {
        let root = fresh_fixture_root();
        std::fs::create_dir_all(root.join("real/child"))
            .expect("create canonicalization fixture hierarchy");
        std::fs::write(root.join("real/child/file"), b"fixture")
            .expect("write canonicalization fixture file");
        std::fs::create_dir(root.join("alias")).expect("create symlink parent");
        std::os::unix::fs::symlink("../real", root.join("alias/to-real"))
            .expect("create relative symlink");
        Self { root }
    }

    fn root(&self) -> &Path {
        &self.root
    }
}

impl Drop for CanonicalFixture {
    fn drop(&mut self) {
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
        let candidate = std::env::temp_dir().join(format!(
            "crabc-x86-canonicalize-{process_id}-{nonce}-{serial}"
        ));
        match std::fs::create_dir(&candidate) {
            Ok(()) => return candidate,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("create canonicalization fixture root: {error}"),
        }
    }

    panic!("find an unused canonicalization fixture root")
}

fn canonical_into(path: &[u8]) -> Vec<u8> {
    let mut output = [MaybeUninit::new(UNTOUCHED); native_fs::CANONICAL_PATH_MAX];
    let (initialized, untouched) = native_fs::canonicalize_into(path, &mut output)
        .expect("canonicalize fixture pathname into caller buffer");
    assert!(untouched
        .iter()
        .all(|byte| unsafe { byte.assume_init() } == UNTOUCHED));
    initialized.to_vec()
}

#[test]
fn x86_64_canonicalize_into_is_physical_byte_preserving_and_noalloc() {
    let fixture = CanonicalFixture::new();
    let alias_path = fixture.root().join("alias/to-real/./child/../child/file");
    let expected = fixture.root().join("real/child/file");

    assert_eq!(
        canonical_into(alias_path.as_os_str().as_bytes()),
        expected.as_os_str().as_bytes(),
    );
    assert_eq!(
        canonical_into(fixture.root().join("real/child/../").as_os_str().as_bytes()),
        fixture.root().join("real").as_os_str().as_bytes(),
    );
    assert_eq!(
        native_fs::canonicalize_into(
            fixture.root().join("real/child/file/..").as_os_str().as_bytes(),
            &mut [0_u8; native_fs::CANONICAL_PATH_MAX],
        ),
        Err(Errno::NOTDIR),
    );

    let raw_name = OsString::from_vec(b"raw-\xff".to_vec());
    let raw_path = fixture.root().join("real/child").join(raw_name);
    std::fs::write(&raw_path, b"raw non-UTF-8 fixture")
        .expect("write non-UTF-8 canonicalization fixture");
    std::os::unix::fs::symlink(&raw_path, fixture.root().join("absolute-link"))
        .expect("create absolute non-UTF-8 symlink");
    assert_eq!(
        canonical_into(fixture.root().join("absolute-link").as_os_str().as_bytes()),
        raw_path.as_os_str().as_bytes(),
    );
}

#[test]
fn x86_64_canonicalize_into_anchors_relative_paths_to_physical_cwd() {
    let cwd = std::env::current_dir().expect("read physical test current directory");
    assert_eq!(canonical_into(b"."), cwd.as_os_str().as_bytes());
    assert_eq!(
        canonical_into(b".."),
        cwd.parent()
            .expect("test current directory has a parent")
            .as_os_str()
            .as_bytes(),
    );
}

#[test]
fn x86_64_canonicalize_into_reports_kernel_and_boundary_errors() {
    let fixture = CanonicalFixture::new();
    let mut output = [MaybeUninit::new(UNTOUCHED); native_fs::CANONICAL_PATH_MAX];

    assert_eq!(
        native_fs::canonicalize_into(fixture.root().join("missing").as_os_str().as_bytes(), &mut output).err(),
        Some(Errno::NOENT),
    );
    std::os::unix::fs::symlink("missing", fixture.root().join("dangling"))
        .expect("create dangling symlink");
    assert_eq!(
        native_fs::canonicalize_into(fixture.root().join("dangling").as_os_str().as_bytes(), &mut output).err(),
        Some(Errno::NOENT),
    );
    for index in 0..40 {
        let next = format!("link{}", (index + 1) % 40);
        std::os::unix::fs::symlink(next, fixture.root().join(format!("link{index}")))
            .expect("create canonicalization symlink cycle");
    }
    assert_eq!(
        native_fs::canonicalize_into(fixture.root().join("link0").as_os_str().as_bytes(), &mut output).err(),
        Some(Errno::LOOP),
    );

    assert_eq!(
        native_fs::canonicalize_into(&b"/tmp/\0bad"[..], &mut output).err(),
        Some(Errno::INVAL),
    );
    assert_eq!(
        native_fs::canonicalize_into(&b""[..], &mut output).err(),
        Some(Errno::NOENT),
    );
    assert_eq!(
        native_fs::canonicalize_into(
            fixture.root().as_os_str().as_bytes(),
            &mut [MaybeUninit::<u8>::uninit(); 1],
        )
        .err(),
        Some(Errno::RANGE),
    );

    let too_long = CString::new(vec![b'x'; native_fs::CANONICAL_PATH_MAX])
        .expect("construct NUL-free oversized pathname");
    assert_eq!(
        native_fs::canonicalize_into(too_long.as_c_str(), &mut output).err(),
        Some(Errno::NAMETOOLONG),
    );

    #[cfg(not(feature = "alloc"))]
    {
        let too_large_for_noalloc_path_boundary = [b'x'; native_fs::SMALL_PATH_BUFFER_SIZE];
        assert_eq!(
            native_fs::canonicalize_into(&too_large_for_noalloc_path_boundary, &mut output).err(),
            Some(Errno::NAMETOOLONG),
        );
    }
}

#[cfg(feature = "alloc")]
#[test]
fn x86_64_canonicalize_returns_owned_nul_terminated_byte_path() {
    let fixture = CanonicalFixture::new();
    let expected = fixture.root().join("real/child/file");
    let actual = native_fs::canonicalize(
        fixture
            .root()
            .join("alias/to-real/child/file")
            .as_os_str()
            .as_bytes(),
    )
    .expect("allocate canonical physical path");
    assert_eq!(actual.as_bytes(), expected.as_os_str().as_bytes());
    assert_eq!(actual.as_bytes_with_nul().last(), Some(&0));
}

#[test]
fn x86_64_canonicalize_accepts_an_existing_c_string_input() {
    let path = CStr::from_bytes_with_nul(b"/tmp\0").expect("static pathname is NUL-terminated");
    let mut output = [MaybeUninit::uninit(); native_fs::CANONICAL_PATH_MAX];
    let (initialized, _) = native_fs::canonicalize_into(path, &mut output)
        .expect("canonicalize direct C string input");
    assert_eq!(initialized, b"/tmp");
}
