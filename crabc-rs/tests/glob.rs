use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crabc_rs::fs as native_fs;
use crabc_rs::pattern::{glob, glob_at, GlobPath};
use crabc_rs::Errno;

fn fixture_root() -> PathBuf {
    let root = PathBuf::from(format!("/tmp/crabc-rs-compat-glob-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("nested")).expect("create glob fixture directories");
    fs::write(root.join("z.txt"), b"z").expect("write z fixture");
    fs::write(root.join("a.txt"), b"a").expect("write a fixture");
    fs::write(root.join(".hidden.txt"), b"hidden").expect("write hidden fixture");
    fs::write(root.join("nested/note.txt"), b"note").expect("write nested fixture");
    fs::write(
        root.join(Path::new(std::ffi::OsStr::from_bytes(b"nested/raw-\xff"))),
        b"raw",
    )
    .expect("write non-UTF8 fixture");
    root
}

fn cleanup(root: &Path) {
    let _ = fs::remove_dir_all(root);
}

fn bytes(paths: Vec<GlobPath>) -> Vec<Vec<u8>> {
    paths.into_iter().map(GlobPath::into_bytes).collect()
}

#[test]
fn glob_returns_sorted_owned_paths_and_preserves_non_utf8_names() {
    let root = fixture_root();
    let root_bytes = root.as_os_str().as_bytes();

    let mut expected = root_bytes.to_vec();
    expected.extend_from_slice(b"/a.txt");
    let mut second = root_bytes.to_vec();
    second.extend_from_slice(b"/z.txt");
    assert_eq!(
        bytes(glob(root_bytes, b"*.txt").expect("expand txt files")),
        vec![expected, second]
    );

    let directory = native_fs::open(
        root_bytes,
        native_fs::OFlags::RDONLY | native_fs::OFlags::DIRECTORY | native_fs::OFlags::CLOEXEC,
        native_fs::Mode::empty(),
    )
    .expect("open glob fixture descriptor");
    assert_eq!(
        bytes(glob_at(&directory, b"nested/*").expect("expand nested names")),
        vec![b"nested/note.txt".to_vec(), b"nested/raw-\xff".to_vec()]
    );
    assert_eq!(
        bytes(glob_at(&directory, b".*").expect("expand hidden names")),
        vec![b".hidden.txt".to_vec()]
    );

    cleanup(&root);
}

#[test]
fn glob_has_explicit_root_and_no_match_policy() {
    let root = fixture_root();
    let root_bytes = root.as_os_str().as_bytes();

    assert!(glob(root_bytes, b"missing/*.txt")
        .expect("missing branch is a no-match")
        .is_empty());
    assert_eq!(
        glob(&b"/tmp/crabc-rs-compat-glob-no-such-root"[..], b"*"),
        Err(Errno::NOENT)
    );
    assert_eq!(glob(root_bytes, b""), Err(Errno::INVAL));
    assert_eq!(glob(root_bytes, b"/absolute"), Err(Errno::INVAL));
    assert_eq!(glob(root_bytes, b"../outside"), Err(Errno::INVAL));
    assert_eq!(glob(root_bytes, b"bad\0pattern"), Err(Errno::INVAL));

    cleanup(&root);
}
