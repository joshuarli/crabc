use crabc_rs::fs::{self, Mode, OFlags, Utimbuf};

const TARGET_PATH: &[u8] = b"/tmp/crabc-rs-native-utime-target";
const LINK_PATH: &[u8] = b"/tmp/crabc-rs-native-utime-link";

fn remove_stale(path: &[u8]) {
    match fs::unlink(path) {
        Ok(()) | Err(crabc_rs::Errno::NOENT) => {}
        Err(error) => panic!("remove stale utime fixture: {error}"),
    }
}

#[test]
fn utime_follows_a_final_symlink_at_second_precision() {
    remove_stale(LINK_PATH);
    remove_stale(TARGET_PATH);
    let target = fs::open(
        TARGET_PATH,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create utime target");
    fs::symlink(TARGET_PATH, LINK_PATH).expect("create utime symbolic link");

    let explicit = Utimbuf {
        actime: 41,
        modtime: 42,
    };
    fs::utime(LINK_PATH, Some(&explicit)).expect("set target through final symlink");
    let target_stat = fs::fstat(&target).expect("observe target timestamps");
    assert_eq!(target_stat.st_atime, 41);
    assert_eq!(target_stat.st_atime_nsec, 0);
    assert_eq!(target_stat.st_mtime, 42);
    assert_eq!(target_stat.st_mtime_nsec, 0);

    fs::utime(LINK_PATH, None).expect("set target timestamps to current time");
    let current = fs::fstat(&target).expect("observe current target timestamps");
    assert!(
        current.st_atime > 41
            || current.st_atime == 41 && current.st_atime_nsec > 0
    );
    assert!(
        current.st_mtime > 42
            || current.st_mtime == 42 && current.st_mtime_nsec > 0
    );

    drop(target);
    remove_stale(LINK_PATH);
    remove_stale(TARGET_PATH);
}
