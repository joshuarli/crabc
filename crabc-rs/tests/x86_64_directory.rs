#![cfg(target_arch = "x86_64")]

use core::mem::MaybeUninit;
use std::ffi::OsString;
use std::fs::{self as std_fs, File};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use crabc_rs::fs::{self, Dir, Mode, OFlags, CWD};
use crabc_rs::{io, BorrowedFd, Errno};

struct RemoveDirectoryOnDrop(PathBuf);

impl Drop for RemoveDirectoryOnDrop {
    fn drop(&mut self) {
        let _ = std_fs::remove_dir_all(&self.0);
    }
}

fn fixture() -> (RemoveDirectoryOnDrop, String, File, Vec<u8>) {
    let mut root = std::env::temp_dir();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    root.push(format!(
        "crabc-x86-directory-{}-{nonce}",
        std::process::id()
    ));
    std_fs::create_dir(&root).expect("create directory-stream fixture directory");
    let cleanup = RemoveDirectoryOnDrop(root.clone());
    let byte_name = b"entry-\xff".to_vec();
    std_fs::write(root.join(OsString::from_vec(byte_name.clone())), b"entry")
        .expect("create non-UTF-8 fixture entry");
    let directory = File::open(&root).expect("open directory-stream fixture");
    let root = root
        .into_os_string()
        .into_string()
        .expect("generated fixture pathname is UTF-8");
    (cleanup, root, directory, byte_name)
}

fn borrowed(file: &File) -> BorrowedFd<'_> {
    // SAFETY: The fixture retains the descriptor owner through each immediate
    // directory-relative operation using this borrow.
    unsafe { BorrowedFd::borrow_raw(file.as_raw_fd()) }
}

#[test]
fn x86_64_dir_owns_close_on_exec_descriptor_and_preserves_byte_names() {
    let (_cleanup, root, directory, byte_name) = fixture();

    let mut storage = [MaybeUninit::uninit(); 4096];
    let mut stream = Dir::open(root.as_str(), &mut storage).expect("open owned directory stream");
    assert!(
        io::fcntl_getfd(stream.as_fd())
            .expect("read directory stream descriptor flags")
            .contains(io::FdFlags::CLOEXEC),
        "Dir::open must set close-on-exec",
    );

    let mut found = false;
    while let Some(entry) = stream.next() {
        let entry = entry.expect("validated getdents64 record");
        if entry.name_bytes() == byte_name {
            found = true;
        }
    }
    assert!(found, "directory entry names must remain byte-oriented");
    assert!(stream.next().is_none(), "end-of-directory is represented by None");
    drop(stream);

    let mut storage = [MaybeUninit::uninit(); 4096];
    let mut relative = Dir::openat(borrowed(&directory), ".", &mut storage)
        .expect("open directory stream relative to a borrowed descriptor");
    assert!(
        relative.next().is_some(),
        "Dir::openat must produce a stream over the supplied directory"
    );
    drop(relative);

    let owned = fs::openat(
        CWD,
        root.as_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("open descriptor for ownership transfer");
    let mut storage = [MaybeUninit::uninit(); 4096];
    let mut transferred = Dir::from_owned_fd(owned, &mut storage);
    assert!(
        transferred.next().is_some(),
        "Dir::from_owned_fd must consume and iterate its descriptor"
    );
}

#[test]
fn x86_64_dir_reports_small_buffer_error_once_and_then_stops() {
    let (_cleanup, root, _directory, _byte_name) = fixture();
    let mut storage = [MaybeUninit::uninit(); 1];
    let mut stream = Dir::open(root.as_str(), &mut storage).expect("open owned directory stream");

    assert_eq!(
        stream
            .next()
            .expect("small buffer must report an error")
            .unwrap_err(),
        Errno::INVAL,
    );
    assert!(
        stream.next().is_none(),
        "a failed directory stream must not silently continue"
    );
}

#[test]
fn x86_64_dirfd_stream_and_open_file_survive_rename_and_unlink() {
    let (_cleanup, root, _host_directory, byte_name) = fixture();
    let parent = fs::open(root.as_str(), OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty()).unwrap();
    fs::mkdirat(&parent, "before", Mode::RWXU).unwrap();
    let original = fs::openat(&parent, "before",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty()).unwrap();
    let file = fs::openat(&original, byte_name.as_slice(),
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR).unwrap();
    io::write(&file, b"retained").unwrap();
    let file_identity = fs::fstat(&file).unwrap();
    for number in 0..12 {
        drop(fs::openat(&original, format!("extra-{number}"),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
            Mode::RUSR | Mode::WUSR).unwrap());
    }
    let directory_identity = fs::fstat(&original).unwrap();
    let mut buffer = [MaybeUninit::uninit(); 96];
    let mut stream = Dir::openat(&original, ".", &mut buffer).unwrap();
    fs::renameat(&parent, "before", &parent, "after").unwrap();
    fs::mkdirat(&parent, "before", Mode::RWXU).unwrap();
    let replacement = fs::openat(&parent, "before",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty()).unwrap();
    assert_ne!(fs::fstat(&replacement).unwrap().st_ino, directory_identity.st_ino);
    assert_eq!(fs::fstat(stream.as_fd()).unwrap().st_ino, directory_identity.st_ino);
    drop(original);

    // Copy each borrowed name before the small stream buffer is refilled.
    // The descriptor follows the renamed directory, independently of its old path.
    let mut snapshots = Vec::new();
    while let Some(entry) = stream.next() {
        let entry = entry.unwrap();
        snapshots.push((entry.name_bytes().to_vec(), entry.ino()));
    }
    assert_eq!(snapshots.len(), 15);
    assert!(snapshots.iter().any(|(name, inode)|
        name == &byte_name && *inode == file_identity.st_ino));
    let copied_names = snapshots.clone();
    fs::renameat(stream.as_fd(), byte_name.as_slice(), &replacement, "moved").unwrap();
    assert_eq!(fs::statat(&replacement, "moved", fs::AtFlags::empty()).unwrap().st_ino,
        file_identity.st_ino);
    assert_eq!(fs::fstat(&file).unwrap().st_nlink, 1);
    fs::unlinkat(&replacement, "moved", fs::UnlinkAtFlags::empty()).unwrap();
    let unlinked = fs::fstat(&file).unwrap();
    assert_eq!(unlinked.st_ino, file_identity.st_ino);
    assert_eq!(unlinked.st_nlink, 0);
    let mut bytes = [0_u8; 8];
    assert_eq!(io::pread(&file, &mut bytes, 0).unwrap(), 8);
    assert_eq!(&bytes, b"retained");
    drop(stream);
    assert_eq!(snapshots, copied_names);
    assert!(snapshots.iter().any(|(name, _)| name == &byte_name));
    assert!(io::fcntl_getfd(&parent).unwrap().contains(io::FdFlags::CLOEXEC));
    assert!(io::fcntl_getfd(&replacement).unwrap().contains(io::FdFlags::CLOEXEC));
}
