use crabc_rs::fs::{self, Mode, OFlags, Timeval};

const TARGET_PATH: &[u8] = b"/tmp/crabc-rs-native-utimes-target";
const LINK_PATH: &[u8] = b"/tmp/crabc-rs-native-utimes-link";

fn remove_stale(path: &[u8]) {
    match fs::unlink(path) {
        Ok(()) | Err(crabc_rs::Errno::NOENT) => {}
        Err(error) => panic!("remove stale utimes fixture: {error}"),
    }
}

#[test]
fn utimes_follows_a_final_symlink_and_updates_the_target() {
    remove_stale(LINK_PATH);
    remove_stale(TARGET_PATH);
    let target = fs::open(
        TARGET_PATH,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create utimes target");
    fs::symlink(TARGET_PATH, LINK_PATH).expect("create utimes symbolic link");

    let target_times = [
        Timeval {
            tv_sec: 11,
            tv_usec: 111_111,
        },
        Timeval {
            tv_sec: 12,
            tv_usec: 222_222,
        },
    ];
    fs::utimes(LINK_PATH, Some(&target_times)).expect("set target through final symlink");
    let target_stat = fs::fstat(&target).expect("observe target timestamps");
    assert_eq!(target_stat.st_atime, 11);
    assert_eq!(target_stat.st_atime_nsec, 111_111_000);
    assert_eq!(target_stat.st_mtime, 12);
    assert_eq!(target_stat.st_mtime_nsec, 222_222_000);

    let invalid = [
        Timeval {
            tv_sec: 11,
            tv_usec: -1,
        },
        Timeval {
            tv_sec: 12,
            tv_usec: 1_000_000,
        },
    ];
    assert_eq!(
        fs::utimes(LINK_PATH, Some(&invalid)),
        Err(crabc_rs::Errno::INVAL)
    );
    let unchanged = fs::fstat(&target).expect("observe target after rejected input");
    assert_eq!(unchanged.st_atime, target_stat.st_atime);
    assert_eq!(unchanged.st_atime_nsec, target_stat.st_atime_nsec);
    assert_eq!(unchanged.st_mtime, target_stat.st_mtime);
    assert_eq!(unchanged.st_mtime_nsec, target_stat.st_mtime_nsec);

    fs::utimes(LINK_PATH, None).expect("set target timestamps to current time");
    let current = fs::fstat(&target).expect("observe current target timestamps");
    assert!(
        current.st_atime > 12
            || current.st_atime == 12 && current.st_atime_nsec > 222_222_000
    );
    assert!(
        current.st_mtime > 12
            || current.st_mtime == 12 && current.st_mtime_nsec > 222_222_000
    );

    drop(target);
    remove_stale(LINK_PATH);
    remove_stale(TARGET_PATH);
}
