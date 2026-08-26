#![cfg(target_arch = "x86_64")]

use core::num::NonZeroU64;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;

use crabc_rs::fs::{self, Advice};
use crabc_rs::Errno;

struct RemoveFileOnDrop(std::path::PathBuf);

impl Drop for RemoveFileOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn fixture() -> (std::fs::File, RemoveFileOnDrop) {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "crabc-x86-fs-advice-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_nanos()
    ));
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .expect("create filesystem-advice fixture");
    file.write_all(&[0x5a; 8192])
        .expect("seed filesystem-advice fixture");
    (file, RemoveFileOnDrop(path))
}

fn file_position(file: &std::fs::File) -> u64 {
    crabc_core::fs::lseek(file.as_raw_fd(), 0, crabc_core::fs::SEEK_CUR)
        .expect("query descriptor position") as u64
}

fn borrow_file(file: &std::fs::File) -> crabc_rs::BorrowedFd<'_> {
    // SAFETY: the test fixture retains sole ownership of the open descriptor
    // for every immediate direct-facade call using this borrow.
    unsafe { crabc_rs::BorrowedFd::borrow_raw(file.as_raw_fd()) }
}

#[test]
fn x86_64_filesystem_advice_uses_linux_values_and_preserves_position() {
    assert_eq!(Advice::Normal as u32, 0);
    assert_eq!(Advice::Random as u32, 1);
    assert_eq!(Advice::Sequential as u32, 2);
    assert_eq!(Advice::WillNeed as u32, 3);
    assert_eq!(Advice::DontNeed as u32, 4);
    assert_eq!(Advice::NoReuse as u32, 5);

    let (mut file, _cleanup) = fixture();
    file.seek(SeekFrom::Start(19))
        .expect("position advice fixture");
    let before = file_position(&file);
    let bounded = NonZeroU64::new(8192).expect("non-zero advice length");
    for (index, advice) in [
        Advice::Normal,
        Advice::Random,
        Advice::Sequential,
        Advice::WillNeed,
        Advice::DontNeed,
        Advice::NoReuse,
    ]
    .into_iter()
    .enumerate()
    {
        fs::fadvise(borrow_file(&file), 0, (index != 0).then_some(bounded), advice)
            .expect("apply direct x86-64 file-access advice");
    }
    assert_eq!(file_position(&file), before);
}

#[test]
fn x86_64_readahead_preserves_position_and_reports_kernel_errors() {
    let (mut file, _cleanup) = fixture();
    file.seek(SeekFrom::Start(23))
        .expect("position readahead fixture");
    let before = file_position(&file);
    fs::readahead(borrow_file(&file), 0, 8192).expect("readahead regular file");
    assert_eq!(file_position(&file), before);

    // Linux rejects readahead on a pipe as an invalid operation. This keeps
    // the assertion at the direct syscall boundary instead of using errno.
    let (reader, _writer) = crabc_rs::pipe::pipe().expect("create readahead pipe");
    assert_eq!(fs::readahead(&reader, 0, 0), Err(Errno::INVAL));
}

#[test]
fn x86_64_filesystem_advice_rejects_signed_range_overflow() {
    let (file, _cleanup) = fixture();
    let too_large = i64::MAX as u64 + 1;
    assert_eq!(
        fs::fadvise(borrow_file(&file), too_large, None, Advice::Normal),
        Err(Errno::INVAL)
    );
    assert_eq!(
        fs::fadvise(
            borrow_file(&file),
            0,
            NonZeroU64::new(too_large),
            Advice::Normal
        ),
        Err(Errno::INVAL)
    );
    assert_eq!(
        fs::readahead(borrow_file(&file), i64::MAX as u64, 1),
        Err(Errno::INVAL)
    );
    assert_eq!(
        fs::readahead(borrow_file(&file), 0, too_large),
        Err(Errno::INVAL)
    );
}
