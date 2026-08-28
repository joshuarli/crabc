#![cfg(target_arch = "x86_64")]

use std::fs::File;
use std::mem::{align_of, offset_of, size_of};
use std::os::fd::AsRawFd;

use crabc_rs::{fs, BorrowedFd, Errno};

fn borrow(file: &File) -> BorrowedFd<'_> {
    // SAFETY: `file` keeps the descriptor open for the returned borrow.
    unsafe { BorrowedFd::borrow_raw(file.as_raw_fd()) }
}

#[test]
fn x86_64_statfs_has_the_native_abi_layout() {
    assert_eq!(size_of::<fs::StatFs>(), 120);
    assert_eq!(align_of::<fs::StatFs>(), 8);
    assert_eq!(offset_of!(fs::StatFs, f_type), 0);
    assert_eq!(offset_of!(fs::StatFs, f_bsize), 8);
    assert_eq!(offset_of!(fs::StatFs, f_blocks), 16);
    assert_eq!(offset_of!(fs::StatFs, f_fsid), 56);
    assert_eq!(offset_of!(fs::StatFs, f_namelen), 64);
    assert_eq!(offset_of!(fs::StatFs, f_frsize), 72);
    assert_eq!(offset_of!(fs::StatFs, f_flags), 80);
    assert_eq!(size_of::<fs::StatVfs>(), 88);
    assert_eq!(align_of::<fs::StatVfs>(), 8);
    assert_eq!(fs::StatVfsMountFlags::NOATIME.bits(), 0x0400);
    assert_eq!(fs::StatVfsMountFlags::NODIRATIME.bits(), 0x0800);
    assert_eq!(fs::StatVfsMountFlags::RELATIME.bits(), 0x1000);
}

#[test]
fn x86_64_path_and_fd_capacity_queries_agree() {
    let by_path = fs::statfs("/tmp").expect("statfs path query");
    let directory = File::open("/tmp").expect("open /tmp");
    let by_fd = fs::fstatfs(borrow(&directory)).expect("fstatfs descriptor query");

    assert_eq!(by_path.f_type, by_fd.f_type);
    assert_eq!(by_path.f_bsize, by_fd.f_bsize);
    assert_eq!(by_path.f_fsid, by_fd.f_fsid);
    assert_eq!(by_path.f_namelen, by_fd.f_namelen);
    assert!(by_path.f_bsize > 0);
    assert!(by_path.f_blocks > 0);

    let vfs_path = fs::statvfs("/tmp").expect("statvfs path query");
    let vfs_fd = fs::fstatvfs(borrow(&directory)).expect("fstatvfs descriptor query");
    assert_eq!(vfs_path.f_bsize, vfs_fd.f_bsize);
    assert_eq!(vfs_path.f_frsize, vfs_fd.f_frsize);
    assert_eq!(vfs_path.f_fsid, vfs_fd.f_fsid);
    assert_eq!(vfs_path.f_flag, vfs_fd.f_flag);
}

#[test]
fn x86_64_statvfs_mapping_invariants_hold() {
    let stats = fs::statfs("/tmp").expect("statfs query");
    let mapped = fs::statvfs("/tmp").expect("statvfs query");
    assert_eq!(mapped.f_bsize, stats.f_bsize as u64);
    assert_eq!(mapped.f_frsize, if stats.f_frsize != 0 { stats.f_frsize as u64 } else { mapped.f_bsize });
    assert_eq!(mapped.f_favail, mapped.f_ffree);
    assert_eq!(mapped.f_fsid, stats.f_fsid[0] as u64);
    assert_eq!(mapped.f_flag.bits(), stats.f_flags as u64);
}

#[test]
fn x86_64_statvfs_uses_only_the_first_linux_fsid_word() {
    let mut stats = fs::statfs("/tmp").expect("statfs query");
    stats.f_fsid = [0x1234_5678, -1];
    assert_eq!(fs::StatVfs::from(stats).f_fsid, 0x1234_5678);

    stats.f_fsid = [-1, 0x1234_5678];
    assert_eq!(fs::StatVfs::from(stats).f_fsid, u64::MAX);
}

#[test]
fn x86_64_capacity_queries_preserve_path_and_descriptor_errors() {
    assert_eq!(
        fs::statfs("/definitely/missing/crabc-capacity").unwrap_err(),
        Errno::NOENT
    );
    assert_eq!(
        fs::statvfs("/definitely/missing/crabc-capacity").unwrap_err(),
        Errno::NOENT
    );

    // SAFETY: this deliberately invalid descriptor is used only to prove the
    // direct kernel EBADF result and is never closed or treated as owned.
    let invalid = unsafe { BorrowedFd::borrow_raw(0x7fff_ff00) };
    assert_eq!(fs::fstatfs(invalid).unwrap_err(), Errno::BADF);
    assert_eq!(fs::fstatvfs(invalid).unwrap_err(), Errno::BADF);
}

#[test]
fn x86_64_capacity_path_preflight_rejects_invalid_fixed_stack_inputs() {
    assert_eq!(fs::statfs(&b"tmp\0suffix"[..]).unwrap_err(), Errno::INVAL);
    assert_eq!(fs::statvfs(&[b'x'; 256][..]).unwrap_err(), Errno::NAMETOOLONG);
}
