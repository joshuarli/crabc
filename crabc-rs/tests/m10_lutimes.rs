use crabc_rs::fs::{self, AtFlags, Mode, OFlags, Timeval, CWD};

const TARGET_PATH: &[u8] = b"/tmp/crabc-rs-m10-lutimes-target";
const LINK_PATH: &[u8] = b"/tmp/crabc-rs-m10-lutimes-link";

fn remove_stale(path: &[u8]) {
    match fs::unlink(path) {
        Ok(()) | Err(crabc_rs::Errno::NOENT) => {}
        Err(error) => panic!("remove stale lutimes fixture: {error}"),
    }
}

#[test]
fn lutimes_updates_the_link_without_touching_its_target() {
    remove_stale(LINK_PATH);
    remove_stale(TARGET_PATH);
    let target = fs::open(
        TARGET_PATH,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create lutimes target");
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
    fs::futimes(&target, Some(&target_times)).expect("set target timestamps");
    let target_before = fs::fstat(&target).expect("observe target before lutimes");
    fs::symlink(TARGET_PATH, LINK_PATH).expect("create lutimes symbolic link");

    let link_times = [
        Timeval {
            tv_sec: 31,
            tv_usec: 333_333,
        },
        Timeval {
            tv_sec: 32,
            tv_usec: 444_444,
        },
    ];
    fs::lutimes(LINK_PATH, Some(&link_times)).expect("set symbolic-link timestamps");
    let link = fs::statat(CWD, LINK_PATH, AtFlags::SYMLINK_NOFOLLOW)
        .expect("observe symbolic-link timestamps");
    assert_eq!(link.st_atime, 31);
    assert_eq!(link.st_atime_nsec, 333_333_000);
    assert_eq!(link.st_mtime, 32);
    assert_eq!(link.st_mtime_nsec, 444_444_000);

    let target_after = fs::fstat(&target).expect("observe target after lutimes");
    assert_eq!(target_after.st_atime, target_before.st_atime);
    assert_eq!(target_after.st_atime_nsec, target_before.st_atime_nsec);
    assert_eq!(target_after.st_mtime, target_before.st_mtime);
    assert_eq!(target_after.st_mtime_nsec, target_before.st_mtime_nsec);

    let invalid = [
        Timeval {
            tv_sec: 31,
            tv_usec: -1,
        },
        Timeval {
            tv_sec: 32,
            tv_usec: 1_000_000,
        },
    ];
    assert_eq!(
        fs::lutimes(LINK_PATH, Some(&invalid)),
        Err(crabc_rs::Errno::INVAL)
    );
    let unchanged = fs::lstat(LINK_PATH).expect("observe link after rejected input");
    assert_eq!(unchanged.st_atime, link.st_atime);
    assert_eq!(unchanged.st_atime_nsec, link.st_atime_nsec);
    assert_eq!(unchanged.st_mtime, link.st_mtime);
    assert_eq!(unchanged.st_mtime_nsec, link.st_mtime_nsec);

    fs::lutimes(LINK_PATH, None).expect("set symbolic-link timestamps to current time");
    let current = fs::lstat(LINK_PATH).expect("observe current link timestamps");
    assert!(
        current.st_atime > 32
            || current.st_atime == 32 && current.st_atime_nsec > 444_444_000
    );
    assert!(
        current.st_mtime > 32
            || current.st_mtime == 32 && current.st_mtime_nsec > 444_444_000
    );

    drop(target);
    remove_stale(LINK_PATH);
    remove_stale(TARGET_PATH);
}
