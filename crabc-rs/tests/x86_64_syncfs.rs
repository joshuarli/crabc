#![cfg(target_arch = "x86_64")]

use std::io::Write;
use std::os::fd::{AsRawFd, IntoRawFd};

use crabc_rs::{fs, BorrowedFd, Errno};

struct RemoveFileOnDrop(std::path::PathBuf);

impl Drop for RemoveFileOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn regular_file_fixture() -> (std::fs::File, RemoveFileOnDrop) {
    let mut path = std::env::temp_dir();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    path.push(format!("crabc-x86-syncfs-{}-{nonce}", std::process::id()));

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .expect("create unique syncfs fixture");
    (file, RemoveFileOnDrop(path))
}

fn borrow_file(file: &std::fs::File) -> BorrowedFd<'_> {
    // SAFETY: `file` retains sole ownership of its open descriptor for every
    // immediate direct-facade call using this borrow.
    unsafe { BorrowedFd::borrow_raw(file.as_raw_fd()) }
}

#[test]
fn x86_64_syncfs_requests_descriptor_associated_filesystem_writeback_for_a_live_regular_file() {
    let (mut file, _cleanup) = regular_file_fixture();
    file.write_all(b"syncfs")
        .expect("dirty regular-file syncfs fixture");
    assert_eq!(
        fs::seek(borrow_file(&file), fs::SeekFrom::Start(3))
            .expect("position syncfs fixture"),
        3,
    );

    // `std::fs::File` remains the live descriptor owner for this safe facade
    // call. The staged x86 facade intentionally has no pathname-opening API.
    fs::syncfs(borrow_file(&file)).expect("request the fixture's filesystem sync");
    assert_eq!(
        fs::tell(borrow_file(&file)).expect("observe position after syncfs"),
        3,
        "syncfs must not change the shared file position",
    );
}

#[test]
fn x86_64_syncfs_accepts_a_live_pipe_descriptor() {
    let (reader, _writer) = crabc_rs::pipe::pipe().expect("create pipefs syncfs fixture");

    // Linux associates pipe descriptors with pipefs, so this is a successful
    // filesystem synchronization request rather than an invalid-file
    // error. Both pipe owners remain live for the safe facade call.
    fs::syncfs(&reader).expect("accept the live pipefs descriptor");
}

#[test]
fn x86_64_syncfs_raw_seam_reports_ebadf_after_descriptor_close() {
    let (file, _cleanup) = regular_file_fixture();
    let raw = file.into_raw_fd();
    crabc_core::io::close(raw).expect("close syncfs EBADF fixture");

    // A safe `AsFd` input cannot outlive an open descriptor. Exercise the
    // direct core seam after closing its owned raw descriptor rather than
    // constructing an invalid `BorrowedFd` for the facade.
    assert_eq!(crabc_core::fs::syncfs(raw), Err(Errno::BADF));
}
