#![cfg(target_arch = "x86_64")]

use core::mem::{align_of, offset_of, size_of};
use std::ffi::OsStr;
use std::fs::{self as std_fs, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;

use crabc_rs::fs::{self, Mode, OFlags, Statx, StatxAtFlags, StatxAttributes, StatxFlags, StatxTimestamp};
use crabc_rs::{BorrowedFd, Errno};

struct RemoveDirectoryOnDrop(PathBuf);

impl Drop for RemoveDirectoryOnDrop {
    fn drop(&mut self) {
        let _ = std_fs::remove_dir_all(&self.0);
    }
}

fn fixture() -> (RemoveDirectoryOnDrop, PathBuf, File, File) {
    let mut root = std::env::temp_dir();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    root.push(format!("crabc-x86-statx-{}-{nonce}", std::process::id()));
    std_fs::create_dir(&root).expect("create private statx fixture directory");
    let cleanup = RemoveDirectoryOnDrop(root.clone());

    let record_path = root.join("record");
    let mut record = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&record_path)
        .expect("create statx fixture file");
    record.write_all(b"statx").expect("write statx fixture file");
    record.sync_all().expect("flush statx fixture file");
    std_fs::set_permissions(&record_path, std_fs::Permissions::from_mode(0o640))
        .expect("set statx fixture mode");
    symlink("record", root.join("link")).expect("create relative statx symlink");
    std_fs::write(root.join(OsStr::from_bytes(b"record-\xff")), b"bytes")
        .expect("create non-UTF-8 statx fixture file");

    let directory = File::open(&root).expect("open statx fixture directory");
    (cleanup, root, directory, record)
}

fn borrowed(file: &File) -> BorrowedFd<'_> {
    // SAFETY: The fixture retains the descriptor owner through every immediate
    // descriptor-relative observation using this borrow.
    unsafe { BorrowedFd::borrow_raw(file.as_raw_fd()) }
}

fn has(mask: u32, field: StatxFlags) -> bool {
    mask & field.bits() == field.bits()
}

#[test]
fn x86_64_statx_record_uses_the_linux_256_byte_abi() {
    assert_eq!(size_of::<StatxTimestamp>(), 16);
    assert_eq!(align_of::<StatxTimestamp>(), 8);
    assert_eq!(offset_of!(StatxTimestamp, tv_sec), 0);
    assert_eq!(offset_of!(StatxTimestamp, tv_nsec), 8);

    assert_eq!(size_of::<Statx>(), 256);
    assert_eq!(align_of::<Statx>(), 8);
    assert_eq!(size_of::<StatxFlags>(), 4);
    assert_eq!(align_of::<StatxAttributes>(), 8);
    assert_eq!(size_of::<StatxAttributes>(), 8);
    assert_eq!(size_of::<StatxAtFlags>(), 4);
    assert_eq!(offset_of!(Statx, stx_mask), 0);
    assert_eq!(offset_of!(Statx, stx_blksize), 4);
    assert_eq!(offset_of!(Statx, stx_attributes), 8);
    assert_eq!(offset_of!(Statx, stx_nlink), 16);
    assert_eq!(offset_of!(Statx, stx_uid), 20);
    assert_eq!(offset_of!(Statx, stx_gid), 24);
    assert_eq!(offset_of!(Statx, stx_mode), 28);
    assert_eq!(offset_of!(Statx, stx_ino), 32);
    assert_eq!(offset_of!(Statx, stx_size), 40);
    assert_eq!(offset_of!(Statx, stx_blocks), 48);
    assert_eq!(offset_of!(Statx, stx_attributes_mask), 56);
    assert_eq!(offset_of!(Statx, stx_atime), 64);
    assert_eq!(offset_of!(Statx, stx_btime), 80);
    assert_eq!(offset_of!(Statx, stx_ctime), 96);
    assert_eq!(offset_of!(Statx, stx_mtime), 112);
    assert_eq!(offset_of!(Statx, stx_rdev_major), 128);
    assert_eq!(offset_of!(Statx, stx_rdev_minor), 132);
    assert_eq!(offset_of!(Statx, stx_dev_major), 136);
    assert_eq!(offset_of!(Statx, stx_dev_minor), 140);
    assert_eq!(offset_of!(Statx, stx_mnt_id), 144);
    assert_eq!(offset_of!(Statx, stx_dio_mem_align), 152);
    assert_eq!(offset_of!(Statx, stx_dio_offset_align), 156);
}

#[test]
fn x86_64_statx_observes_descriptor_relative_metadata_only_when_masked_in() {
    let (_cleanup, _root, directory, record) = fixture();
    let legacy = fs::fstat(borrowed(&record)).expect("fstat statx fixture file");
    let observed = fs::statx(
        borrowed(&directory),
        "record",
        StatxAtFlags::empty(),
        StatxFlags::BASIC_STATS,
    )
    .expect("descriptor-relative statx fixture file");

    assert_ne!(observed.stx_mask & StatxFlags::BASIC_STATS.bits(), 0);
    if has(observed.stx_mask, StatxFlags::INO) {
        assert_eq!(observed.stx_ino, legacy.st_ino);
    }
    if has(observed.stx_mask, StatxFlags::SIZE) {
        assert_eq!(observed.stx_size, legacy.st_size as u64);
    }
    if has(observed.stx_mask, StatxFlags::MODE) {
        assert_eq!(observed.stx_mode as u32, legacy.st_mode & 0xffff);
        assert_eq!(observed.stx_mode as u32 & 0o170000, 0o100000);
        assert_eq!(observed.stx_mode as u32 & 0o777, 0o640);
    }
    if has(observed.stx_mask, StatxFlags::NLINK) {
        assert_eq!(observed.stx_nlink as u64, legacy.st_nlink);
    }
    if has(observed.stx_mask, StatxFlags::UID) {
        assert_eq!(observed.stx_uid, legacy.st_uid);
    }
    if has(observed.stx_mask, StatxFlags::GID) {
        assert_eq!(observed.stx_gid, legacy.st_gid);
    }
    if has(observed.stx_mask, StatxFlags::BLOCKS) {
        assert_eq!(observed.stx_blocks, legacy.st_blocks as u64);
    }
    if has(observed.stx_mask, StatxFlags::ATIME) {
        assert!(observed.stx_atime.tv_nsec < 1_000_000_000);
    }
    if has(observed.stx_mask, StatxFlags::MTIME) {
        assert!(observed.stx_mtime.tv_nsec < 1_000_000_000);
    }
    if has(observed.stx_mask, StatxFlags::CTIME) {
        assert!(observed.stx_ctime.tv_nsec < 1_000_000_000);
    }

    let bytes = fs::statx(
        borrowed(&directory),
        &b"record-\xff"[..],
        StatxAtFlags::empty(),
        StatxFlags::TYPE | StatxFlags::SIZE,
    )
    .expect("statx non-UTF-8 fixture path");
    if has(bytes.stx_mask, StatxFlags::SIZE) {
        assert_eq!(bytes.stx_size, 5);
    }
}

#[test]
fn x86_64_statx_keeps_operation_specific_nofollow_and_empty_path_semantics() {
    let (_cleanup, root, directory, _record) = fixture();

    let followed = fs::statx(
        borrowed(&directory),
        "link",
        StatxAtFlags::empty(),
        StatxFlags::TYPE | StatxFlags::INO,
    )
    .expect("follow statx fixture symlink");
    let link = fs::statx(
        borrowed(&directory),
        "link",
        StatxAtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::TYPE | StatxFlags::SIZE,
    )
    .expect("observe statx fixture symlink itself");
    assert!(has(followed.stx_mask, StatxFlags::TYPE));
    assert!(has(link.stx_mask, StatxFlags::TYPE));
    assert_eq!(followed.stx_mode as u32 & 0o170000, 0o100000);
    assert_eq!(link.stx_mode as u32 & 0o170000, 0o120000);
    if has(link.stx_mask, StatxFlags::SIZE) {
        assert_eq!(link.stx_size, 6);
    }

    let root = root.as_os_str().as_bytes();
    let descriptor = fs::open(
        root,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("open statx fixture directory as O_PATH descriptor");
    let by_empty_path = fs::statx(
        &descriptor,
        "",
        StatxAtFlags::EMPTY_PATH,
        StatxFlags::TYPE | StatxFlags::INO,
    )
    .expect("statx O_PATH descriptor using AT_EMPTY_PATH");
    assert!(has(by_empty_path.stx_mask, StatxFlags::TYPE));
    assert_eq!(by_empty_path.stx_mode as u32 & 0o170000, 0o040000);
}

#[test]
fn x86_64_statx_preserves_direct_validation_and_bounded_path_contracts() {
    let (_cleanup, _root, directory, _record) = fixture();
    let directory = borrowed(&directory);

    assert_eq!(
        fs::statx(
            directory,
            "record",
            StatxAtFlags::empty(),
            StatxFlags::from_bits_retain(StatxFlags::RESERVED_MASK),
        )
        .unwrap_err(),
        Errno::INVAL,
    );
    // `STATX_MNT_ID_UNIQUE` follows this facade's pinned 0x3fff request
    // vocabulary, so the shared core seam deliberately clips it before Linux.
    let future_mask = StatxFlags::from_bits_retain(0x0000_4000);
    fs::statx(directory, "record", StatxAtFlags::empty(), future_mask)
        .expect("future statx mask bits are masked before direct syscall entry");
    assert_eq!(
        fs::statx(
            directory,
            "record",
            StatxAtFlags::FORCE_SYNC | StatxAtFlags::DONT_SYNC,
            StatxFlags::BASIC_STATS,
        )
        .unwrap_err(),
        Errno::INVAL,
    );
    assert_eq!(
        fs::statx(
            directory,
            "record",
            StatxAtFlags::from_bits_retain(0x8000_0000),
            StatxFlags::BASIC_STATS,
        )
        .unwrap_err(),
        Errno::INVAL,
    );
    assert_eq!(
        fs::statx(directory, "missing", StatxAtFlags::empty(), StatxFlags::BASIC_STATS)
            .unwrap_err(),
        Errno::NOENT,
    );
    assert_eq!(
        fs::statx(
            directory,
            &b"record\0suffix"[..],
            StatxAtFlags::empty(),
            StatxFlags::BASIC_STATS,
        )
        .unwrap_err(),
        Errno::INVAL,
    );
    let overlong = [b'x'; 256];
    assert_eq!(
        fs::statx(
            directory,
            &overlong,
            StatxAtFlags::empty(),
            StatxFlags::BASIC_STATS,
        )
        .unwrap_err(),
        Errno::NAMETOOLONG,
    );
}
