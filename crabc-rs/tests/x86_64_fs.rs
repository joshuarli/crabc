#![cfg(target_arch = "x86_64")]

use core::mem::{align_of, offset_of, size_of};

use crabc_rs::fs;

struct RemoveFileOnDrop(std::path::PathBuf);

impl Drop for RemoveFileOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn x86_64_stat_matches_the_kernel_record() {
    assert_eq!(size_of::<fs::Stat>(), 144);
    assert_eq!(align_of::<fs::Stat>(), 8);
    assert_eq!(offset_of!(fs::Stat, st_dev), 0);
    assert_eq!(offset_of!(fs::Stat, st_ino), 8);
    assert_eq!(offset_of!(fs::Stat, st_nlink), 16);
    assert_eq!(offset_of!(fs::Stat, st_mode), 24);
    assert_eq!(offset_of!(fs::Stat, st_uid), 28);
    assert_eq!(offset_of!(fs::Stat, st_gid), 32);
    assert_eq!(offset_of!(fs::Stat, st_rdev), 40);
    assert_eq!(offset_of!(fs::Stat, st_size), 48);
    assert_eq!(offset_of!(fs::Stat, st_blksize), 56);
    assert_eq!(offset_of!(fs::Stat, st_blocks), 64);
    assert_eq!(offset_of!(fs::Stat, st_atime), 72);
    assert_eq!(offset_of!(fs::Stat, st_mtime), 88);
    assert_eq!(offset_of!(fs::Stat, st_ctime), 104);
}

#[test]
fn x86_64_fstat_reads_regular_file_metadata() {
    use std::io::Write;

    let mut path = std::env::temp_dir();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    path.push(format!("crabc-x86-fstat-{}-{nonce}", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .expect("create unique metadata fixture");
    let _cleanup = RemoveFileOnDrop(path.clone());
    std::fs::set_permissions(
        &path,
        std::os::unix::fs::PermissionsExt::from_mode(0o640),
    )
    .expect("set metadata fixture mode");
    file.write_all(b"crabc-fstat").expect("write metadata fixture");
    file.sync_all().expect("flush metadata fixture");

    use std::os::fd::AsRawFd;

    // SAFETY: `file` remains open and is not closed through another alias for
    // the duration of this immediate borrowed descriptor observation.
    let file_fd = unsafe { crabc_rs::BorrowedFd::borrow_raw(file.as_raw_fd()) };
    let observed = fs::fstat(file_fd).expect("fstat regular file");
    let expected = std::fs::metadata(&path).expect("read host metadata");
    assert_eq!(observed.st_size, expected.len() as i64);
    assert_eq!(observed.st_ino, std::os::unix::fs::MetadataExt::ino(&expected));
    assert_eq!(observed.st_dev, std::os::unix::fs::MetadataExt::dev(&expected));
    assert_eq!(observed.st_nlink, std::os::unix::fs::MetadataExt::nlink(&expected));
    assert_eq!(observed.st_mode & 0o170000, 0o100000);
    assert_eq!(observed.st_mode & 0o777, 0o640);
    assert!((0..1_000_000_000).contains(&observed.st_atime_nsec));
    assert!((0..1_000_000_000).contains(&observed.st_mtime_nsec));
    assert!((0..1_000_000_000).contains(&observed.st_ctime_nsec));
}
