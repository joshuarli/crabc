#![cfg(target_arch = "x86_64")]

use core::mem::MaybeUninit;
use std::ffi::OsString;
use std::fs::{self as std_fs, File};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use crabc_rs::fs::RawDir;
use crabc_rs::{BorrowedFd, Errno};

struct RemoveDirectoryOnDrop(PathBuf);

impl Drop for RemoveDirectoryOnDrop {
    fn drop(&mut self) {
        let _ = std_fs::remove_dir_all(&self.0);
    }
}

fn fixture() -> (RemoveDirectoryOnDrop, File, Vec<u8>) {
    let mut root = std::env::temp_dir();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    root.push(format!(
        "crabc-x86-raw-directory-{}-{nonce}",
        std::process::id()
    ));
    std_fs::create_dir(&root).expect("create raw-directory fixture directory");
    let cleanup = RemoveDirectoryOnDrop(root.clone());
    std_fs::write(root.join("short"), b"short").expect("create short fixture entry");
    let long_name = vec![b'n'; 255];
    std_fs::write(
        root.join(OsString::from_vec(long_name.clone())),
        b"long",
    )
    .expect("create maximum-length fixture entry");
    let directory = File::open(&root).expect("open raw-directory fixture");
    (cleanup, directory, long_name)
}

fn borrowed(file: &File) -> BorrowedFd<'_> {
    // SAFETY: The fixture retains the descriptor owner through each immediate
    // getdents64 observation using this borrow.
    unsafe { BorrowedFd::borrow_raw(file.as_raw_fd()) }
}

#[test]
fn x86_64_raw_dir_preserves_unaligned_buffer_borrowed_names_and_small_buffer_error() {
    let (cleanup, directory, long_name) = fixture();

    let mut unaligned = [MaybeUninit::uninit(); 4097];
    let mut entries = RawDir::new(borrowed(&directory), &mut unaligned[1..]);
    let mut names = Vec::new();
    while let Some(entry) = entries.next() {
        let entry = entry.expect("validated x86-64 linux_dirent64 record");
        names.push(entry.file_name().to_bytes().to_vec());
    }
    assert!(entries.is_buffer_empty());
    assert!(
        names.iter().any(|name| name == b"short"),
        "entries: {names:?}"
    );
    assert!(
        names.iter().any(|name| name == &long_name),
        "entries: {names:?}"
    );
    drop(entries);

    let small_directory = File::open(&cleanup.0).expect("reopen raw-directory fixture");
    let mut too_small = [MaybeUninit::uninit(); 1];
    let mut entries = RawDir::new(borrowed(&small_directory), &mut too_small);
    assert_eq!(
        entries
            .next()
            .expect("undersized getdents64 buffer reports an error")
            .unwrap_err(),
        Errno::INVAL,
    );
}
