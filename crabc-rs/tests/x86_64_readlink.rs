#![cfg(target_arch = "x86_64")]

use core::mem::MaybeUninit;
use std::fs::{self as std_fs, File};
use std::os::fd::AsRawFd;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use crabc_rs::{fs, BorrowedFd, Errno};

const UNTOUCHED: u8 = 0xa5;

struct RemoveDirectoryOnDrop(PathBuf);

impl Drop for RemoveDirectoryOnDrop {
    fn drop(&mut self) {
        let _ = std_fs::remove_dir_all(&self.0);
    }
}

fn fixture_root() -> (RemoveDirectoryOnDrop, File) {
    let mut root = std::env::temp_dir();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    root.push(format!("crabc-x86-readlink-{}-{nonce}", std::process::id()));
    std_fs::create_dir(&root).expect("create readlink fixture directory");
    let cleanup = RemoveDirectoryOnDrop(root.clone());
    std_fs::write(root.join("record"), b"readlink").expect("create non-symlink fixture");
    symlink("record", root.join("symbolic")).expect("create symbolic-link fixture");
    let directory = File::open(&root).expect("open readlink fixture directory");
    (cleanup, directory)
}

fn borrow(file: &File) -> BorrowedFd<'_> {
    // SAFETY: The fixture retains the descriptor owner for every immediate
    // readlinkat observation using this borrow.
    unsafe { BorrowedFd::borrow_raw(file.as_raw_fd()) }
}

#[test]
fn x86_64_readlinkat_returns_exact_non_nul_target_and_preserves_suffix() {
    let (_cleanup, directory) = fixture_root();
    let mut storage = [MaybeUninit::new(UNTOUCHED); 16];
    let (target, untouched) = fs::readlinkat_raw(borrow(&directory), "symbolic", &mut storage)
        .expect("read symbolic-link target");

    assert_eq!(target, b"record");
    assert!(!target.contains(&0), "readlinkat must not append a NUL");
    assert!(untouched
        .iter()
        .all(|byte| unsafe { byte.assume_init() } == UNTOUCHED));
}

#[test]
fn x86_64_readlinkat_truncates_a_short_output_buffer() {
    let (_cleanup, directory) = fixture_root();
    let mut storage = [MaybeUninit::new(UNTOUCHED); 3];
    let (target, untouched) = fs::readlinkat_raw(borrow(&directory), "symbolic", &mut storage)
        .expect("read truncated symbolic-link target");

    assert_eq!(target, b"rec");
    assert!(!target.contains(&0), "truncated readlinkat output is not NUL-terminated");
    assert!(untouched.is_empty());
}

#[test]
fn x86_64_readlinkat_rejects_a_zero_length_output_buffer() {
    let (_cleanup, directory) = fixture_root();
    let mut storage = [MaybeUninit::<u8>::uninit(); 0];

    match fs::readlinkat_raw(borrow(&directory), "symbolic", &mut storage) {
        Ok(_) => panic!("a zero-length readlinkat buffer must be rejected"),
        Err(error) => assert_eq!(error, Errno::INVAL),
    }
}

#[test]
fn x86_64_readlinkat_propagates_kernel_errors_and_path_validation() {
    let (_cleanup, directory) = fixture_root();
    let directory = borrow(&directory);
    let mut storage = [MaybeUninit::<u8>::uninit(); 16];

    assert_eq!(
        fs::readlinkat_raw(directory, "missing", &mut storage).unwrap_err(),
        Errno::NOENT,
    );
    assert_eq!(
        fs::readlinkat_raw(directory, "record", &mut storage).unwrap_err(),
        Errno::INVAL,
    );
    assert_eq!(
        fs::readlinkat_raw(directory, &b"symbolic\0suffix"[..], &mut storage).unwrap_err(),
        Errno::INVAL,
    );
    let overlong = [b'x'; 256];
    assert_eq!(
        fs::readlinkat_raw(directory, &overlong[..], &mut storage).unwrap_err(),
        Errno::NAMETOOLONG,
    );
}
