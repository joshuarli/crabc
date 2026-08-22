use crabc_rs::fs::{self, AtFlags, StatxFlags, CWD};
use crabc_rs::Errno;

#[test]
fn statx_basic_metadata_matches_stat_and_reports_valid_mask() {
    let extended = fs::statx(CWD, "/tmp", AtFlags::empty(), StatxFlags::BASIC_STATS)
        .expect("statx direct metadata query");
    let legacy = fs::stat("/tmp").expect("stat direct metadata query");

    let mask = extended.stx_mask;
    assert_ne!(mask & StatxFlags::BASIC_STATS.bits(), 0);

    if mask & StatxFlags::MODE.bits() != 0 {
        assert_eq!(u32::from(extended.stx_mode), legacy.st_mode);
    }
    if mask & StatxFlags::NLINK.bits() != 0 {
        assert_eq!(extended.stx_nlink, legacy.st_nlink);
    }
    if mask & StatxFlags::UID.bits() != 0 {
        assert_eq!(extended.stx_uid, legacy.st_uid);
    }
    if mask & StatxFlags::GID.bits() != 0 {
        assert_eq!(extended.stx_gid, legacy.st_gid);
    }
    if mask & StatxFlags::INO.bits() != 0 {
        assert_eq!(extended.stx_ino, legacy.st_ino);
    }
    if mask & StatxFlags::SIZE.bits() != 0 {
        assert!(legacy.st_size >= 0);
        assert_eq!(extended.stx_size, legacy.st_size as u64);
    }
    if mask & StatxFlags::BLOCKS.bits() != 0 {
        assert!(legacy.st_blocks >= 0);
        assert_eq!(extended.stx_blocks, legacy.st_blocks as u64);
    }
    if mask & StatxFlags::ATIME.bits() != 0 {
        assert!(extended.stx_atime.tv_nsec < 1_000_000_000);
    }
    if mask & StatxFlags::MTIME.bits() != 0 {
        assert!(extended.stx_mtime.tv_nsec < 1_000_000_000);
    }
    if mask & StatxFlags::CTIME.bits() != 0 {
        assert!(extended.stx_ctime.tv_nsec < 1_000_000_000);
    }
}

#[test]
fn statx_rejects_reserved_mask_before_kernel_entry() {
    let mask = StatxFlags::from_bits_retain(
        StatxFlags::BASIC_STATS.bits() | StatxFlags::RESERVED_MASK,
    );
    let error = fs::statx(CWD, "/tmp", AtFlags::empty(), mask)
        .expect_err("STATX__RESERVED must be rejected");
    assert_eq!(error, Errno::INVAL);
}
