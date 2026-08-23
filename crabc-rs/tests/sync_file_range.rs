use crabc_rs::fs::{self, Mode, OFlags};
use crabc_rs::io::{self, SyncFileRangeFlags};
use crabc_rs::{AsFd, Errno};

const PATH: &[u8] = b"/tmp/crabc-rs-native-sync-file-range";

fn remove_fixture() {
    match fs::unlink(PATH) {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(error) => panic!("remove stale sync_file_range fixture: {error}"),
    }
}

#[test]
fn sync_file_range_flushes_a_regular_file_and_supports_zero_length_to_eof() {
    remove_fixture();
    let file = fs::open(
        PATH,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create sync_file_range fixture");
    io::write(&file, &[0x5a; 8192]).expect("dirty sync_file_range fixture");
    let before = fs::tell(&file).expect("read position before sync_file_range");

    io::sync_file_range(
        file.as_fd(),
        0,
        0,
        SyncFileRangeFlags::WAIT_BEFORE
            | SyncFileRangeFlags::WRITE
            | SyncFileRangeFlags::WAIT_AFTER,
    )
    .expect("sync regular file from offset through EOF");
    let after = fs::tell(&file).expect("read position after sync_file_range");

    drop(file);
    remove_fixture();
    assert_eq!(after, before, "sync_file_range must not move file position");
}

#[test]
fn sync_file_range_rejects_unknown_flags_and_unrepresentable_ranges() {
    remove_fixture();
    let file = fs::open(
        PATH,
        OFlags::RDONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR,
    )
    .expect("create sync_file_range validation fixture");

    let unknown_flags = SyncFileRangeFlags::from_bits_retain(0x08);
    assert!(
        SyncFileRangeFlags::from_bits(0x08).is_none(),
        "reserved sync_file_range flag bits must remain outside the safe set",
    );
    assert_eq!(
        io::sync_file_range(file.as_fd(), 0, 0, unknown_flags),
        Err(Errno::INVAL),
        "unknown flags must be rejected before the syscall",
    );
    assert_eq!(
        io::sync_file_range(file.as_fd(), i64::MAX as u64 + 1, 0, SyncFileRangeFlags::empty()),
        Err(Errno::INVAL),
        "an offset outside signed Linux loff_t must be rejected",
    );
    assert_eq!(
        io::sync_file_range(file.as_fd(), i64::MAX as u64, 1, SyncFileRangeFlags::empty()),
        Err(Errno::INVAL),
        "offset plus length must fit signed Linux loff_t",
    );
    assert_eq!(
        io::sync_file_range(
            file.as_fd(),
            0,
            i64::MAX as u64 + 1,
            SyncFileRangeFlags::empty(),
        ),
        Err(Errno::INVAL),
        "a length outside signed Linux loff_t must be rejected",
    );

    drop(file);
    remove_fixture();
}
