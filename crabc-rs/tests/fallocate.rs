use core::sync::atomic::{AtomicUsize, Ordering};

use crabc_rs::fs::{self, FallocateFlags, Mode, OFlags, SeekFrom};
use crabc_rs::Errno;

static SCRATCH_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

fn scratch_path(prefix: &str) -> String {
    format!(
        "/tmp/crabc-rs-native-fallocate-{}-{}-{}",
        prefix,
        std::process::id(),
        SCRATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed),
    )
}

#[test]
fn fallocate_extends_without_moving_position_and_keep_size_preserves_length() {
    let path = scratch_path("extension");
    let _ = fs::unlink(&path);
    let file = fs::open(
        &path,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create fallocate fixture");

    assert_eq!(fs::tell(&file).expect("initial file position"), 0);
    fs::fallocate(&file, FallocateFlags::ALLOCATE, 4096, 4096)
        .expect("allocate a range beyond the file end");
    assert_eq!(
        fs::tell(&file).expect("position after fallocate"),
        0,
        "fallocate must not change the descriptor position",
    );
    assert_eq!(
        fs::seek(&file, SeekFrom::End(0)).expect("size after extending allocation"),
        8192,
    );

    fs::ftruncate(&file, 0).expect("reset fallocate fixture");
    fs::fallocate(&file, FallocateFlags::KEEP_SIZE, 4096, 4096)
        .expect("allocate without extending the file");
    assert_eq!(
        fs::seek(&file, SeekFrom::End(0)).expect("size after keep-size allocation"),
        0,
    );

    drop(file);
    fs::unlink(&path).expect("remove fallocate fixture");
}

#[test]
fn fallocate_rejects_unsupported_modes_and_unrepresentable_ranges() {
    let path = scratch_path("validation");
    let _ = fs::unlink(&path);
    let file = fs::open(
        &path,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create fallocate validation fixture");

    assert!(
        FallocateFlags::from_bits(0x04).is_none(),
        "reserved NO_HIDE_STALE must not enter the safe mode set",
    );
    assert_eq!(
        fs::fallocate(&file, FallocateFlags::PUNCH_HOLE, 0, 1).unwrap_err(),
        Errno::INVAL,
        "Linux requires PUNCH_HOLE to include KEEP_SIZE",
    );
    assert_eq!(
        fs::fallocate(&file, FallocateFlags::ALLOCATE, u64::MAX, 1).unwrap_err(),
        Errno::INVAL,
    );
    assert_eq!(
        fs::fallocate(&file, FallocateFlags::ALLOCATE, i64::MAX as u64, 1).unwrap_err(),
        Errno::INVAL,
        "offset plus length must fit signed Linux loff_t",
    );

    drop(file);
    fs::unlink(&path).expect("remove fallocate validation fixture");
}

#[test]
fn posix_fallocate_uses_mode_zero_without_moving_position() {
    let path = scratch_path("posix");
    let _ = fs::unlink(&path);
    let file = fs::open(
        &path,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create posix_fallocate fixture");

    assert_eq!(fs::tell(&file).expect("initial file position"), 0);
    fs::posix_fallocate(&file, 4096, 4096).expect("allocate a mode-zero range");
    assert_eq!(
        fs::tell(&file).expect("position after posix_fallocate"),
        0,
        "posix_fallocate must not change the descriptor position",
    );
    assert_eq!(
        fs::seek(&file, SeekFrom::End(0)).expect("size after posix_fallocate"),
        8192,
    );

    assert_eq!(
        fs::posix_fallocate(&file, i64::MAX as u64, 1).unwrap_err(),
        Errno::INVAL,
        "offset plus length must fit signed Linux loff_t",
    );

    drop(file);
    fs::unlink(&path).expect("remove posix_fallocate fixture");
}
