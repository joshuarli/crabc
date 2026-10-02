#![cfg(all(target_arch = "x86_64", feature = "alloc"))]

use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;

use crabc_rs::{fs as native_fs, pattern::glob_at, RawDir};

#[test]
fn glob_at_preserves_directory_position_and_owns_paths_across_root_rename() {
    let temporary = std::env::var_os("TMPDIR").expect("owning checkout temporary directory");
    let root = std::path::PathBuf::from(temporary)
        .join(format!("pattern110-glob-{}", std::process::id()));
    let renamed = root.with_extension("renamed");
    fs::create_dir(&root).expect("create explicit root");
    fs::create_dir(root.join("nested")).expect("create nested directory");
    fs::write(root.join("nested/note.txt"), b"note").expect("write ordinary entry");
    symlink("nested", root.join("link")).expect("create intermediate symlink");

    let directory = native_fs::open(
        root.as_os_str().as_bytes(),
        native_fs::OFlags::RDONLY | native_fs::OFlags::DIRECTORY | native_fs::OFlags::CLOEXEC,
        native_fs::Mode::empty(),
    ).expect("open explicit directory descriptor");
    let mut storage = [std::mem::MaybeUninit::uninit(); 4096];
    let mut entries = RawDir::new(&directory, &mut storage);
    entries.next().expect("first directory entry").expect("valid directory record");
    let position = crabc_core::fs::lseek(directory.as_raw_fd(), 0, crabc_core::fs::SEEK_CUR)
        .expect("read borrowed directory position");

    fs::rename(&root, &renamed).expect("rename root while descriptor remains open");
    let matches = glob_at(&directory, b"link/*.txt").expect("follow ordinary intermediate symlink");
    let dotted = glob_at(&directory, b"./nested/*.txt").expect("retain literal dot component");
    assert_eq!(
        crabc_core::fs::lseek(directory.as_raw_fd(), 0, crabc_core::fs::SEEK_CUR)
            .expect("read unchanged directory position"),
        position,
    );
    drop(directory);
    fs::remove_dir_all(&renamed).expect("remove fixture after traversal");

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].as_bytes(), b"link/note.txt");
    assert_eq!(dotted.len(), 1);
    assert_eq!(dotted[0].as_bytes(), b"./nested/note.txt");
}
