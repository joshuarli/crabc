use crabc_rs::fs::{self, Mode, OFlags};

#[test]
fn statfs_and_fstatfs_report_the_same_filesystem() {
    let by_path = fs::statfs("/tmp").expect("statfs direct path query");
    let directory = fs::open(
        "/tmp",
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .expect("open /tmp for fstatfs");
    let by_fd = fs::fstatfs(&directory).expect("fstatfs direct descriptor query");

    assert_eq!(by_path.f_type, by_fd.f_type);
    assert_eq!(by_path.f_bsize, by_fd.f_bsize);
    assert_eq!(by_path.f_fsid, by_fd.f_fsid);
    assert!(by_path.f_bsize > 0);
    assert!(by_path.f_namelen > 0);
    assert!(by_path.f_blocks > 0);
}

#[test]
fn statvfs_maps_linux_statfs_without_process_state() {
    let stats = fs::statvfs("/tmp").expect("statvfs direct path query");

    assert!(stats.f_bsize > 0);
    assert!(stats.f_frsize > 0);
    assert!(stats.f_blocks > 0);
    assert_eq!(stats.f_favail, stats.f_ffree);
    assert!(stats.f_namemax > 0);
}

#[test]
fn fstatvfs_uses_the_same_typed_mapping_as_statvfs() {
    let directory = fs::open(
        "/tmp",
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .expect("open /tmp for fstatvfs");
    let by_fd = fs::fstatvfs(&directory).expect("fstatvfs direct descriptor query");
    let by_path = fs::statvfs("/tmp").expect("statvfs direct path query");

    assert_eq!(by_fd.f_bsize, by_path.f_bsize);
    assert_eq!(by_fd.f_frsize, by_path.f_frsize);
    assert_eq!(by_fd.f_fsid, by_path.f_fsid);
    assert_eq!(by_fd.f_favail, by_fd.f_ffree);
}
