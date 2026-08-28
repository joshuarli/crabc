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
