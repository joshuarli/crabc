use crabc_rs::fs::{self, Mode, OFlags, Timeval};

const PATH: &[u8] = b"/tmp/crabc-rs-native-futimes";

fn remove_stale_fixture() {
    match fs::unlink(PATH) {
        Ok(()) | Err(crabc_rs::Errno::NOENT) => {}
        Err(error) => panic!("remove stale futimes fixture: {error}"),
    }
}

#[test]
fn futimes_converts_microseconds_and_supports_current_time() {
    remove_stale_fixture();
    let file = fs::open(
        PATH,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create disposable futimes fixture");

    let explicit = [
        Timeval {
            tv_sec: 41,
            tv_usec: 123_456,
        },
        Timeval {
            tv_sec: 42,
            tv_usec: 654_321,
        },
    ];
    fs::futimes(&file, Some(&explicit)).expect("set explicit microsecond timestamps");
    let stat = fs::fstat(&file).expect("observe explicit futimes timestamps");
    assert_eq!(stat.st_atime, 41);
    assert_eq!(stat.st_atime_nsec, 123_456_000);
    assert_eq!(stat.st_mtime, 42);
    assert_eq!(stat.st_mtime_nsec, 654_321_000);

    let invalid = [
        Timeval {
            tv_sec: 41,
            tv_usec: -1,
        },
        Timeval {
            tv_sec: 42,
            tv_usec: 1_000_000,
        },
    ];
    assert_eq!(
        fs::futimes(&file, Some(&invalid)),
        Err(crabc_rs::Errno::INVAL)
    );
    let unchanged = fs::fstat(&file).expect("observe timestamps after rejected input");
    assert_eq!(unchanged.st_atime, stat.st_atime);
    assert_eq!(unchanged.st_atime_nsec, stat.st_atime_nsec);
    assert_eq!(unchanged.st_mtime, stat.st_mtime);
    assert_eq!(unchanged.st_mtime_nsec, stat.st_mtime_nsec);

    fs::futimes(&file, None).expect("set both timestamps to current time");
    let current = fs::fstat(&file).expect("observe current-time futimes timestamps");
    assert!(
        current.st_atime > 42
            || current.st_atime == 42 && current.st_atime_nsec > 654_321_000
    );
    assert!(
        current.st_mtime > 42
            || current.st_mtime == 42 && current.st_mtime_nsec > 654_321_000
    );

    drop(file);
    fs::unlink(PATH).expect("remove disposable futimes fixture");
}
